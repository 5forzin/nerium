"""Rebuild the pinned emulator system partition's AVB metadata with its public AOSP test key."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile


PARTITION_SIZE = 871968768
DATA_SIZE = 858124288
PUBLIC_KEY_SHA1 = "cdbb77177f731920bbe0a0f94f84d9038ae0617d"
SALT = "c4df1fbfebc34c7a9642231c386a227d3caed607424879591ca81a9742f6f743"
FINGERPRINT = "google/sdk_gphone64_x86_64/emu64xa:14/UE1A.230829.036.A4/12096271:user/release-keys"


def digest(path, size=None):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        remaining = path.stat().st_size if size is None else size
        while remaining:
            data = stream.read(min(8 << 20, remaining))
            if not data:
                raise ValueError("Truncated image")
            result.update(data)
            remaining -= len(data)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--avbtool", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--fec-directory", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.name != "system.img":
        raise ValueError("Use a new output named system.img for descriptor verification")
    if args.source.stat().st_size != PARTITION_SIZE:
        raise ValueError("Unexpected pinned system partition size")
    with args.source.open("rb") as stream:
        stream.seek(-64, os.SEEK_END)
        footer = stream.read(64)
    if footer[:4] != b"AVBf" or struct.unpack_from(">Q", footer, 12)[0] != DATA_SIZE:
        raise ValueError("Unexpected pinned AVB footer")

    environment = os.environ.copy()
    environment["PATH"] = str(args.fec_directory.resolve()) + os.pathsep + environment.get("PATH", "")
    tool = [sys.executable, str(args.avbtool.resolve())]

    def run(*arguments):
        try:
            return subprocess.run(tool + list(map(str, arguments)), env=environment,
                                  text=True, capture_output=True, check=True).stdout
        except subprocess.CalledProcessError as error:
            raise RuntimeError((error.stdout + error.stderr).strip()) from error

    info = run("info_image", "--image", args.source)
    required = (PUBLIC_KEY_SHA1, "SHA256_RSA2048", SALT, FINGERPRINT)
    if any(value not in info for value in required):
        raise ValueError("The source AVB metadata differs from the pinned Google Play image")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        public_key = Path(temporary) / "testkey.avbpubkey"
        run("extract_public_key", "--key", args.key, "--output", public_key)
        if hashlib.sha1(public_key.read_bytes()).hexdigest() != PUBLIC_KEY_SHA1:
            raise ValueError("The key is not the pinned public AOSP emulator test key")

    data_hash = digest(args.source, DATA_SIZE)
    shutil.copyfile(args.source, args.output)
    run("erase_footer", "--image", args.output)
    print("Rebuilding system hashtree and two-root FEC", flush=True)
    run("add_hashtree_footer", "--image", args.output,
        "--partition_size", PARTITION_SIZE, "--partition_name", "system",
        "--hash_algorithm", "sha256", "--salt", SALT, "--block_size", 4096,
        "--fec_num_roots", 2, "--algorithm", "SHA256_RSA2048", "--key", args.key,
        "--rollback_index", 1693872000, "--rollback_index_location", 0, "--flags", 0,
        "--prop", "com.android.build.system.os_version:14",
        "--prop", "com.android.build.system.fingerprint:" + FINGERPRINT,
        "--prop", "com.android.build.system.security_patch:2023-09-05")
    verification = run("verify_image", "--image", args.output, "--key", args.key)
    if args.output.stat().st_size != PARTITION_SIZE or digest(args.output, DATA_SIZE) != data_hash:
        raise ValueError("Rebuilding AVB changed filesystem data or partition size")
    after_info = run("info_image", "--image", args.output)
    fec_offset = int(re.search(r"FEC offset:\s+(\d+)", after_info).group(1))
    fec_size = int(re.search(r"FEC size:\s+(\d+)", after_info).group(1))
    print("Comparing stored FEC parity with a fresh encoding", flush=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        prefix = Path(temporary) / "prefix.img"
        parity = Path(temporary) / "parity.bin"
        with args.output.open("rb") as source, prefix.open("xb") as target:
            remaining = fec_offset
            while remaining:
                data = source.read(min(8 << 20, remaining))
                if not data:
                    raise ValueError("Truncated FEC input")
                target.write(data)
                remaining -= len(data)
        subprocess.run([str(args.fec_directory.resolve() / "fec"), "--encode", "--roots", "2",
                        str(prefix), str(parity)], env=environment, check=True, capture_output=True)
        with args.output.open("rb") as image:
            image.seek(fec_offset)
            stored = image.read(fec_size)
        if stored != parity.read_bytes()[:fec_size]:
            raise ValueError("Stored FEC parity differs from the fresh encoding")
    report = {"source": str(args.source), "output": str(args.output),
              "source_sha256": digest(args.source), "output_sha256": digest(args.output),
              "filesystem_data_sha256": data_hash, "filesystem_data_unchanged": True,
              "public_key_sha1": PUBLIC_KEY_SHA1, "trust_scope": "public AOSP emulator test key",
              "flags": 0, "fec_roots": 2, "fec_parity_matches": True,
              "fec_comparison_bytes": fec_size, "verification": verification.strip()}
    args.output.with_suffix(".avb-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(verification.strip())


if __name__ == "__main__":
    main()

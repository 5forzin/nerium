"""Replace matching Google partitions in an isolated Android Emulator disk."""

import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path


SOURCE_SHA256 = "4806fbc745cd9abbfacc358496508f0ce420010e0ddaccef11e52e5da8e92f0a"
PARTITIONS = {
    "system_ext": {
        "sector": 1_751_040,
        "extent_size": 163_110_912,
        "source_sha256": "a3513070268dcf69553d63629d4559afb3b0bd835ecd82c95ee54eefa691cfe7",
        "replacement_sha256": "e5cdefcfdd0b18bd32b9ff7c59cd21e3e326682ed300ac5d1755f0dee944d1e4",
    },
    "product": {
        "sector": 2_070_528,
        "extent_size": 1_938_083_840,
        "source_sha256": "e091157520e9f7e892021dd49af10f6a31c84e0b6fad014686ddc9afc58b1415",
        "replacement_sha256": "568cba0cc0c9f51f032b12c94db6b29b68002b1502c140225b6e81755a098a38",
    },
}
SUPER_OFFSET = 2_097_152


def digest(path, offset=0, size=None):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = path.stat().st_size - offset if size is None else size
        while remaining:
            chunk = stream.read(min(4 * 1024 * 1024, remaining))
            if not chunk:
                raise ValueError("Truncated image extent")
            result.update(chunk)
            remaining -= len(chunk)
    return result.hexdigest()


def filesystem_size(path):
    with path.open("rb") as stream:
        stream.seek(1024)
        superblock = stream.read(1024)
    if superblock[56:58] != b"\x53\xef":
        raise ValueError(f"Not an ext4 image: {path}")
    if struct.unpack_from("<I", superblock, 24)[0] != 2:
        raise ValueError(f"Expected a 4096-byte block size: {path}")
    return struct.unpack_from("<I", superblock, 4)[0] * 4096


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("system_ext", type=Path)
    parser.add_argument("product", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if digest(args.source) != SOURCE_SHA256:
        raise ValueError("Unexpected platform disk image")

    replacements = {}
    for name, spec in PARTITIONS.items():
        replacement = getattr(args, name)
        offset = SUPER_OFFSET + spec["sector"] * 512
        if digest(args.source, offset, spec["extent_size"]) != spec["source_sha256"]:
            raise ValueError(f"Unexpected original {name} extent")
        if digest(replacement) != spec["replacement_sha256"]:
            raise ValueError(f"Unexpected replacement {name} image")
        size = filesystem_size(replacement)
        if size > spec["extent_size"] or size > replacement.stat().st_size:
            raise ValueError(f"Replacement {name} exceeds its destination extent")
        replacements[name] = (replacement, offset, size, spec["extent_size"])

    with args.source.open("rb") as source, args.output.open("xb") as output:
        shutil.copyfileobj(source, output, 4 * 1024 * 1024)
    with args.output.open("r+b") as output:
        for name, (replacement, offset, size, extent_size) in replacements.items():
            with replacement.open("rb") as source:
                output.seek(offset)
                remaining = size
                while remaining:
                    chunk = source.read(min(4 * 1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError(f"Truncated {name} replacement")
                    output.write(chunk)
                    remaining -= len(chunk)
                output.write(b"\0" * (extent_size - size))
            if digest(args.output, offset, size) != digest(replacement, 0, size):
                raise ValueError(f"Written {name} extent differs from its replacement")

    print(json.dumps({"output": str(args.output), "output_sha256": digest(args.output),
                      "partitions": {name: {"offset": entry[1], "filesystem_size": entry[2]}
                                     for name, entry in replacements.items()}}))


if __name__ == "__main__":
    main()

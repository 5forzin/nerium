"""Build an isolated API 34 Google Play system image with NUMA kernel modules."""

import hashlib
import json
import shutil
from pathlib import Path


SDK_IMAGE = (
    Path.home()
    / "AppData/Local/Android/Sdk/system-images/android-34/google_apis_playstore/x86_64/system.img"
)
NUMA_ROOT = Path.home() / "AppData/Local/android-device-lab/numa-kernel"
WORK = Path.home() / "AppData/Local/android-device-lab/playstore-numa-hybrid"
OUTPUT = WORK / "system-playstore-numa.img"
EXPECTED_SOURCE_SHA256 = "4c0231879770f9ef3a4f33ef317ccf6a123b16e198ecab0e9ce76b9efc1f7da0"
PARTITIONS = (
    ("vendor", WORK / "vendor-numa-partition.img", 875560960, 95346688, 1080, b"\x53\xef"),
    ("system_dlkm", NUMA_ROOT / "system_dlkm-numa.img", 3090153472, 4222976, 1024, b"\xe2\xe1\xf5\xe0"),
)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def marker(path, offset):
    with path.open("rb") as source:
        source.seek(offset)
        return source.read(4)


def write_partition(output, source, offset, extent_size):
    with source.open("rb") as payload, output.open("r+b") as image:
        image.seek(offset)
        remaining = source.stat().st_size
        while remaining:
            chunk = payload.read(min(4 * 1024 * 1024, remaining))
            if not chunk:
                raise EOFError(source)
            image.write(chunk)
            remaining -= len(chunk)
        image.write(b"\0" * (extent_size - source.stat().st_size))


def main():
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    source_hash = digest(SDK_IMAGE)
    if source_hash != EXPECTED_SOURCE_SHA256:
        raise ValueError("Unsupported Google Play system image revision")
    for name, payload, offset, extent_size, marker_offset, expected_magic in PARTITIONS:
        if payload.stat().st_size > extent_size:
            raise ValueError(f"{name} image exceeds its partition")
        if offset + extent_size > SDK_IMAGE.stat().st_size:
            raise ValueError(f"{name} partition exceeds the system image")
        if marker(payload, marker_offset)[: len(expected_magic)] != expected_magic:
            raise ValueError(f"Invalid {name} filesystem image")
        if marker(SDK_IMAGE, offset + marker_offset)[: len(expected_magic)] != expected_magic:
            raise ValueError(f"Unexpected {name} partition offset")

    shutil.copyfile(SDK_IMAGE, OUTPUT)
    for _, payload, offset, extent_size, _, _ in PARTITIONS:
        write_partition(OUTPUT, payload, offset, extent_size)
    report = {
        "source_sha256": source_hash,
        "output_sha256": digest(OUTPUT),
        "partitions": [
            {"name": name, "offset": offset, "extent_size": size, "payload_sha256": digest(payload)}
            for name, payload, offset, size, _, _ in PARTITIONS
        ],
    }
    (WORK / "system-patch-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

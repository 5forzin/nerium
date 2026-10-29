"""Extract the super partition from an Android Emulator GPT disk image."""

import argparse
import hashlib
import json
import struct
from pathlib import Path


def super_extent(image):
    image.seek(0, 2)
    image_size = image.tell()
    image.seek(512)
    header = image.read(92)
    if len(header) != 92 or header[:8] != b"EFI PART":
        raise ValueError("Expected a GPT disk image")
    entries_lba, count, entry_size = struct.unpack_from("<QII", header, 72)
    if entry_size < 128 or count > 1024:
        raise ValueError("Unexpected GPT partition table")
    for index in range(count):
        image.seek(entries_lba * 512 + index * entry_size)
        entry = image.read(entry_size)
        if len(entry) != entry_size:
            raise ValueError("Truncated GPT partition table")
        name = entry[56:128].decode("utf-16le").rstrip("\0")
        if name == "super":
            first, last = struct.unpack_from("<QQ", entry, 32)
            if last < first or (last + 1) * 512 > image_size:
                raise ValueError("Invalid super partition extent")
            return first * 512, (last - first + 1) * 512
    raise ValueError("No super partition in GPT")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    digest = hashlib.sha256()
    with args.source.open("rb") as source:
        offset, size = super_extent(source)
        source.seek(offset)
        with args.output.open("xb") as output:
            remaining = size
            while remaining:
                chunk = source.read(min(4 * 1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("Truncated super partition")
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
    print(json.dumps({"source": str(args.source), "output": str(args.output), "offset": offset,
                      "size": size, "sha256": digest.hexdigest()}))


if __name__ == "__main__":
    main()

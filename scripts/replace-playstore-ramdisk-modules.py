"""Replace only the first-stage modules in the pinned Google Play ramdisk."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import lz4.block


SOURCE_SHA256 = "e154035a28ba927ec18d74f199b7bfc60ea55935e92d52ee2909436d1b682800"
MAGIC = b"\x02\x21\x4c\x18"
MODULES = (
    "virtio-rng.ko",
    "virtio_blk.ko",
    "virtio_console.ko",
    "virtio_dma_buf.ko",
    "virtio_pci.ko",
    "virtio_pci_legacy_dev.ko",
    "virtio_pci_modern_dev.ko",
    "vmw_vsock_virtio_transport.ko",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def frames(data):
    position = 0
    result = []
    while position < len(data):
        if data[position:position + 4] != MAGIC:
            raise ValueError("Unexpected legacy LZ4 frame")
        size = struct.unpack_from("<I", data, position + 4)[0]
        end = position + 8 + size
        if size == 0 or end > len(data):
            raise ValueError("Invalid compressed block size")
        compressed = data[position + 8:end]
        result.append((data[position:end], lz4.block.decompress(compressed, uncompressed_size=8 * 1024 * 1024)))
        position = end
    if len(result) != 2:
        raise ValueError("Expected exactly two ramdisk archives")
    return result


def align(value, boundary=4):
    return (value + boundary - 1) // boundary * boundary


def replace_cpio(data, replacements):
    position = 0
    output = bytearray()
    seen = set()
    names = []
    while True:
        header = data[position:position + 110]
        if len(header) != 110 or header[:6] != b"070701":
            raise ValueError("Expected a newc CPIO entry")
        fields = [int(header[6 + index * 8:14 + index * 8], 16) for index in range(13)]
        size = fields[6]
        name_size = fields[11]
        name_start = position + 110
        name_bytes = data[name_start:name_start + name_size]
        if not name_bytes.endswith(b"\0"):
            raise ValueError("Unterminated CPIO entry name")
        name = name_bytes[:-1].decode("utf-8")
        data_start = align(name_start + name_size)
        payload = data[data_start:data_start + size]
        if len(payload) != size:
            raise ValueError("Truncated CPIO entry")
        next_position = align(data_start + size)
        replacement = replacements.get(name)
        if replacement is not None:
            payload = replacement
            seen.add(name)
        updated = bytearray(header)
        updated[54:62] = f"{len(payload):08X}".encode("ascii")
        output.extend(updated)
        output.extend(name_bytes)
        output.extend(b"\0" * (align(len(output)) - len(output)))
        output.extend(payload)
        output.extend(b"\0" * (align(len(output)) - len(output)))
        names.append(name)
        position = next_position
        if name == "TRAILER!!!":
            if any(data[position:]):
                raise ValueError("Unexpected data after CPIO trailer")
            output.extend(b"\0" * (align(len(output), 512) - len(output)))
            break
    if seen != set(replacements):
        raise ValueError(f"Missing module entries: {set(replacements) - seen}")
    return bytes(output), names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("modules", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    original = args.source.read_bytes()
    if sha(original) != SOURCE_SHA256:
        raise ValueError("Unexpected Google Play ramdisk image")
    first, second = frames(original)
    module_bytes = {f"lib/modules/{name}": (args.modules / name).read_bytes() for name in MODULES}
    archive, names = replace_cpio(second[1], module_bytes)
    if any("magisk" in name.lower() for name in names):
        raise ValueError("The stock module archive contains Magisk files")
    compressed = lz4.block.compress(archive, mode="high_compression", compression=9, store_size=False)
    result = first[0] + MAGIC + struct.pack("<I", len(compressed)) + compressed
    verified = frames(result)
    if verified[0][0] != first[0] or verified[1][1] != archive:
        raise ValueError("Ramdisk verification failed")
    with args.output.open("xb") as output:
        output.write(result)
    print(json.dumps({"source_sha256": SOURCE_SHA256, "output_sha256": sha(result),
                      "first_archive_unchanged": True, "replaced_modules": {
                          name: sha(module_bytes[f"lib/modules/{name}"]) for name in MODULES
                      }, "magisk_files": 0}))


if __name__ == "__main__":
    main()

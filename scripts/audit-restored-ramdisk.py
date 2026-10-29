"""Verify restored init and unchanged kernel module bytes in newc ramdisk archives."""

import argparse
import hashlib
import json
import lzma
from pathlib import Path


def entries(path):
    data = path.read_bytes()
    offset, result = 0, {}
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        if header[:6] not in (b"070701", b"070702"):
            raise ValueError("Unsupported or malformed newc header")
        fields = [int(header[index:index + 8], 16) for index in range(6, 110, 8)]
        size, name_size = fields[6], fields[11]
        if not name_size or offset + 110 + name_size > len(data):
            raise ValueError("Truncated archive name")
        name = data[offset + 110:offset + 110 + name_size - 1].decode("utf-8")
        start = (offset + 110 + name_size + 3) & ~3
        if start + size > len(data):
            raise ValueError("Truncated archive payload")
        payload = data[start:start + size]
        offset = (start + size + 3) & ~3
        if name == "TRAILER!!!":
            return result
        if name in result:
            raise ValueError("Duplicate archive entry")
        result[name] = (fields, payload)
    raise ValueError("Missing archive trailer")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before, after = entries(args.before), entries(args.after)
    modules = [name for name in before if name.startswith("lib/modules/") and name.endswith(".ko")]
    if len(modules) != 8:
        raise ValueError("Expected the eight pinned NUMA-compatible ramdisk modules")
    for name in modules:
        if name not in after or before[name][1] != after[name][1] or before[name][0][1:5] != after[name][0][1:5]:
            raise ValueError(f"Kernel module bytes or metadata changed: {name}")
        # MagiskBoot's newc writer normalizes timestamps when serializing an archive.
        if after[name][0][5] not in (0, before[name][0][5]):
            raise ValueError(f"Unexpected module timestamp change: {name}")
    if after["init"][1] != lzma.decompress(before[".backup/init.xz"][1]):
        raise ValueError("Restored init differs from its preserved original")
    if any(name.startswith((".backup", "overlay.d")) for name in after):
        raise ValueError("Magisk backup or overlay entries remain")
    result = {
        "original_init_restored": True,
        "stock_init_sha256": hashlib.sha256(after["init"][1]).hexdigest(),
        "preserved_kernel_modules": {name: hashlib.sha256(after[name][1]).hexdigest() for name in modules},
        "module_modes_owners_and_groups_preserved": True,
        "module_mtimes_normalized_to_zero": [name for name in modules if before[name][0][5] != after[name][0][5]],
        "removed_entries": sorted(set(before) - set(after)),
        "before_archive_sha256": hashlib.sha256(args.before.read_bytes()).hexdigest(),
        "after_archive_sha256": hashlib.sha256(args.after.read_bytes()).hexdigest(),
        "runtime_verified": False,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"original_init_restored": True, "preserved_kernel_modules": len(modules)}))


if __name__ == "__main__":
    main()

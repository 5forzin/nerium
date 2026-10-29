"""Align copied emulator VINTF metadata with the independently queried AIDL v3 HALs.

Run in the cached image-tools container with /artifacts pointing to research-v12.
Only copied images are opened for writing.
"""
import hashlib
import json
import re
import struct
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path("/artifacts")
MANIFEST = "/etc/vintf/manifest/android.hardware.security.keymint-service.xml"


def debugfs(image, command):
    result = subprocess.run(["debugfs", "-R", command, str(image)], check=True, capture_output=True, text=True)
    return result.stdout


def region_hash(path, offset, length):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        while length:
            data = stream.read(min(length, 1024 * 1024))
            if not data:
                raise ValueError("Truncated image extent")
            result.update(data)
            length -= len(data)
    return result.hexdigest()


def main():
    for name in ("keymint-interface-version.txt", "rkp-interface-version.txt"):
        if not re.search(r"00000000\s+00000003", (ROOT / name).read_text(encoding="utf-8-sig")):
            raise ValueError("Both HAL interfaces must first be independently measured as v3")
    image = ROOT / "vendor-v3-partition.img"
    original = ROOT / "keymint-manifest-extracted.xml"
    debugfs(image, f"dump {MANIFEST} {original}")
    before = original.read_bytes()
    tree = ET.fromstring(before)
    declarations = {(hal.findtext("name"), hal.findtext("fqname")): hal.findtext("version") for hal in tree.findall("hal")}
    expected = {("android.hardware.security.keymint", interface): "2" for interface in ("IKeyMintDevice/default", "IRemotelyProvisionedComponent/default")}
    if declarations != expected or before.count(b"<version>2</version>") != 2:
        raise ValueError("Unexpected source KeyMint manifest")
    after = before.replace(b"<version>2</version>", b"<version>3</version>")
    blocks = [int(item) for item in debugfs(image, f"blocks {MANIFEST}").split()]
    with image.open("rb") as stream:
        stream.seek(1024 + 24)
        block_size = 1024 << struct.unpack("<I", stream.read(4))[0]
    if len(blocks) != 1 or len(before) > block_size:
        raise ValueError("Expected a single data block for the manifest")
    original_hash = region_hash(image, 0, image.stat().st_size)
    vendor_disk = ROOT / "system-images-v3/vendor.img"
    with vendor_disk.open("rb") as stream:
        stream.seek(1024 + 32)
        first, last = struct.unpack("<QQ", stream.read(16))
    vendor_offset, vendor_length = first * 512, (last - first + 1) * 512
    system_offset, system_length = map(int, (ROOT / "vendor-logical-extents.txt").read_text().split())
    if image.stat().st_size > min(vendor_length, system_length):
        raise ValueError("Vendor payload exceeds its original extents")
    targets = [(image, 0), (vendor_disk, vendor_offset), (ROOT / "system-images-v3/system.img", system_offset)]
    for target, offset in targets:
        if region_hash(target, offset, image.stat().st_size) != original_hash:
            raise ValueError(f"Vendor extent does not match the preserved baseline: {target}")
    relative = blocks[0] * block_size
    for target, offset in targets:
        with target.open("r+b") as stream:
            stream.seek(offset + relative)
            if stream.read(len(before)) != before:
                raise ValueError("Manifest data block differs from the extracted file")
            stream.seek(offset + relative)
            stream.write(after)
    verified = ROOT / "keymint-manifest-verified.xml"
    debugfs(image, f"dump {MANIFEST} {verified}")
    if verified.read_bytes() != after:
        raise ValueError("Patched manifest extraction differs")
    subprocess.run(["e2fsck", "-fn", str(image)], check=True, capture_output=True, text=True)
    patched_hash = region_hash(image, 0, image.stat().st_size)
    for target, offset in targets:
        if region_hash(target, offset, image.stat().st_size) != patched_hash:
            raise ValueError("Patched vendor extents differ")
    report = {
        "source_manifest_version": 2,
        "measured_interface_versions": {"keymint": 3, "remote_provisioning": 3},
        "updated_manifest_version": 3,
        "modified_bytes_per_image": sum(a != b for a, b in zip(before, after)),
        "manifest_size": len(before),
        "manifest_inode_and_xattrs_preserved": True,
        "vendor_extent_before_sha256": original_hash,
        "vendor_extent_after_sha256": patched_hash,
        "fsck": "clean",
        "modified_images": [str(target) for target, _ in targets],
        "manufacturer_attestation_or_security_level_modified": False,
    }
    (ROOT / "keymint-image-patch.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

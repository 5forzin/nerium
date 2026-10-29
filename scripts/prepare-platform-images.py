"""Add platform init services to independent copies of the validated vendor images."""

import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path("/artifacts")
SOURCE = Path("/source")
SERVICE = "/etc/init/device-lab-platform.rc"


def run(*arguments):
    completed = subprocess.run(arguments, check=True, capture_output=True, text=True)
    return completed.stdout


def debugfs(image, command, write=False):
    arguments = ["debugfs"] + (["-w"] if write else [])
    return run(*arguments, "-R", command, str(image))


def sha(path, offset=0, length=None):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = path.stat().st_size - offset if length is None else length
        while remaining:
            data = stream.read(min(remaining, 1024 * 1024))
            if not data:
                raise ValueError("Truncated image extent")
            result.update(data)
            remaining -= len(data)
    return result.hexdigest()


def main():
    output = ROOT / "system-images-platform"
    if output.exists():
        raise ValueError("Do not overwrite a previous image experiment")
    output.mkdir()
    source_images = SOURCE / "system-images-v3"
    original = SOURCE / "vendor-v3-partition.img"
    vendor = ROOT / "vendor-platform-partition.img"
    expected = json.loads((SOURCE / "keymint-image-patch.json").read_text(encoding="utf-8-sig"))["vendor_extent_after_sha256"]
    original_hash = sha(original)
    if original_hash != expected:
        raise ValueError("The source vendor partition differs from the accepted v3 image")
    shutil.copyfile(original, vendor)
    listing = debugfs(vendor, "ls -p /etc/init")
    references = [line.split("/")[5] for line in listing.splitlines()
                  if line.startswith("/") and len(line.split("/")) > 6 and line.split("/")[5].endswith(".rc")]
    if not references or "device-lab-platform.rc" in references:
        raise ValueError("Unexpected initial vendor init directory")
    reference = "/etc/init/" + sorted(references)[0]
    label = ROOT / "vendor-init-label.bin"
    debugfs(vendor, f"ea_get -f {label} {reference} security.selinux")
    if not re.fullmatch(rb"u:object_r:vendor_[a-z_]+:s0\x00?", label.read_bytes()):
        raise ValueError("Unexpected reference init-file label")
    with tempfile.TemporaryDirectory(prefix="device-lab-policy-") as temporary:
        temporary = Path(temporary)
        for name in ("before", "after"):
            folder = temporary / name
            folder.mkdir()
            if name == "after":
                debugfs(vendor, f"write {ROOT / 'device-lab-platform.rc'} {SERVICE}", write=True)
                for field, value in (("mode", "0100644"), ("uid", "0"), ("gid", "0")):
                    debugfs(vendor, f"set_inode_field {SERVICE} {field} {value}", write=True)
                debugfs(vendor, f"ea_set -f {label} {SERVICE} security.selinux", write=True)
            debugfs(vendor, f"rdump /etc/selinux {folder}")
        policy_before = {str(path.relative_to(temporary / "before")): sha(path)
                         for path in (temporary / "before").rglob("*") if path.is_file()}
        policy_after = {str(path.relative_to(temporary / "after")): sha(path)
                        for path in (temporary / "after").rglob("*") if path.is_file()}
        if not policy_before or policy_before != policy_after:
            raise ValueError("Existing vendor SELinux policy files changed")
    verified = ROOT / "vendor-init-verified.rc"
    verified_label = ROOT / "vendor-init-verified-label.bin"
    debugfs(vendor, f"dump {SERVICE} {verified}")
    debugfs(vendor, f"ea_get -f {verified_label} {SERVICE} security.selinux")
    if verified.read_bytes() != (ROOT / "device-lab-platform.rc").read_bytes() or verified_label.read_bytes() != label.read_bytes():
        raise ValueError("New service file or label differs from the staged artifact")
    run("e2fsck", "-fn", str(vendor))
    for path in source_images.iterdir():
        if path.is_file() and path.name not in ("kernel-ranchu", "ramdisk.img"):
            shutil.copyfile(path, output / path.name)
    shutil.copyfile(ROOT / "kernel-platform-source", output / "kernel-ranchu")
    shutil.copyfile(ROOT / "ramdisk-platform.img", output / "ramdisk.img")
    disk = output / "vendor.img"
    with disk.open("rb") as stream:
        stream.seek(1024 + 32)
        first, last = struct.unpack("<QQ", stream.read(16))
    offset, length = map(int, (SOURCE / "vendor-logical-extents.txt").read_text().split())
    targets = [(disk, first * 512, (last - first + 1) * 512), (output / "system.img", offset, length)]
    for path, position, maximum in targets:
        if vendor.stat().st_size > maximum or sha(path, position, original.stat().st_size) != original_hash:
            raise ValueError("The original vendor extent does not match its independent partition copy")
        with path.open("r+b") as stream, vendor.open("rb") as payload:
            stream.seek(position)
            shutil.copyfileobj(payload, stream, 1024 * 1024)
    updated_hash = sha(vendor)
    if any(sha(path, position, vendor.stat().st_size) != updated_hash for path, position, _ in targets):
        raise ValueError("Patched vendor extents disagree")
    report = {
        "source_vendor_sha256": original_hash,
        "updated_vendor_sha256": updated_hash,
        "added_file": SERVICE,
        "added_file_sha256": sha(verified),
        "init_file_label": label.read_bytes().rstrip(b"\0").decode("ascii"),
        "vendor_selinux_policy_files_unchanged": policy_before,
        "kernel_sha256": sha(output / "kernel-ranchu"),
        "ramdisk_sha256": sha(output / "ramdisk.img"),
        "fsck": "clean",
        "matching_vendor_extents": True,
        "runtime_verified": False,
    }
    (ROOT / "platform-images-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

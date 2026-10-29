"""Prepare isolated emulator images from the cached stock images and rebuilt modules.

Run inside the kernel build container after build-numa-modules.sh. The SDK images
are never opened for writing. system-numa.img must be a separate copy of system.img.
"""
import json
import shutil
import struct
import subprocess
from pathlib import Path

ROOT = Path("/artifacts")
WORK = Path("/work")
MODULES = ROOT / "modules"


def run(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def replace_modules(directory):
    names = []
    for path in sorted(directory.glob("*.ko")):
        source = MODULES / path.name
        if not source.is_file():
            raise FileNotFoundError(f"Missing rebuilt module: {path.name}")
        shutil.copyfile(source, path)
        names.append(path.name)
    if not names:
        raise ValueError(f"No modules found in {directory}")
    return names


def overwrite_extent(image, payload, offset, length):
    data = payload.read_bytes()
    if len(data) > length:
        raise ValueError(f"{payload.name} exceeds its original partition")
    with image.open("r+b") as target:
        if offset + length > target.seek(0, 2):
            raise ValueError("Extent exceeds image bounds")
        target.seek(offset)
        target.write(data)
        target.write(b"\0" * (length - len(data)))


def main():
    if not (ROOT / "vendor-build.status").read_text().strip() == "completed":
        raise ValueError("Module build is incomplete")
    report = {}

    ramdisk = WORK / "ramdisk"
    report["ramdisk_modules"] = replace_modules(ramdisk / "lib/modules")
    subprocess.run(["bash", "-o", "pipefail", "-c",
                    "find . -print0 | cpio --null -o -H newc --quiet | lz4 -f -l -9 - /artifacts/ramdisk-numa.img"],
                   cwd=ramdisk, check=True)

    vendor = ROOT / "vendor-numa-partition.img"
    shutil.copyfile(ROOT / "vendor-logical-partition.img", vendor)
    original = WORK / "vendor-original"
    original.mkdir(exist_ok=True)
    run("debugfs", "-R", f"rdump /lib/modules {original}", str(vendor))
    names = sorted(path.name for path in (original / "modules").glob("*.ko"))
    if not names:
        raise ValueError("Vendor module directory is empty")
    commands = []
    label = ROOT / "vendor-selinux-label"
    label.write_bytes(b"u:object_r:vendor_file:s0\0")
    for name in names:
        source = MODULES / name
        if not source.is_file():
            raise FileNotFoundError(f"Missing rebuilt vendor module: {name}")
        destination = f"/lib/modules/{name}"
        commands.extend([f"rm {destination}", f"write {source} {destination}",
                         f"set_inode_field {destination} mode 0100644",
                         f"ea_set -f {label} {destination} security.selinux"])
    command_file = ROOT / "vendor-debugfs.commands"
    command_file.write_text("\n".join(commands) + "\n")
    run("debugfs", "-w", "-f", str(command_file), str(vendor))
    # debugfs does not propagate individual command failures through its exit code.
    for name in names:
        extracted = WORK / "verify-vendor.ko"
        run("debugfs", "-R", f"dump /lib/modules/{name} {extracted}", str(vendor))
        if extracted.read_bytes() != (MODULES / name).read_bytes():
            raise ValueError(f"Vendor replacement differs: {name}")
        attributes = run("debugfs", "-R", f"ea_list /lib/modules/{name}", str(vendor))
        if 'security.selinux (26) = "u:object_r:vendor_file:s0' not in attributes:
            raise ValueError(f"Vendor SELinux label differs: {name}")
    run("e2fsck", "-fn", str(vendor))
    report["vendor_modules"] = names
    disk = ROOT / "vendor-numa.img"
    shutil.copyfile(ROOT / "vendor-original.img", disk)
    with disk.open("rb") as image:
        image.seek(1024 + 32)
        first, last = struct.unpack("<QQ", image.read(16))
    overwrite_extent(disk, vendor, first * 512, (last - first + 1) * 512)
    offset, length = map(int, (ROOT / "vendor-logical-extents.txt").read_text().split())
    overwrite_extent(ROOT / "system-numa.img", vendor, offset, length)

    dlkm = WORK / "system-dlkm"
    report["system_dlkm_modules"] = replace_modules(dlkm / "lib/modules")
    contexts = ROOT / "system-dlkm-file-contexts"
    contexts.write_text("/.* u:object_r:system_dlkm_file:s0\n")
    erofs = ROOT / "system_dlkm-numa.img"
    run("mkfs.erofs", "-zlz4hc,9", "-T1720722833", "-U16f0a303-2549-4c63-9ee0-8537127129d4",
        f"--file-contexts={contexts}", str(erofs), str(dlkm))
    run("fsck.erofs", "--extract", str(erofs))
    offset, length = map(int, (ROOT / "system_dlkm-extents.txt").read_text().split())
    overwrite_extent(ROOT / "system-numa.img", erofs, offset, length)
    report["images"] = {}
    for name in ("kernel-numa", "ramdisk-numa.img", "vendor-numa.img", "system-numa.img"):
        path = ROOT / name
        report["images"][name] = {"size": path.stat().st_size}
    (ROOT / "images.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: len(value) for key, value in report.items() if key.endswith("modules")}))


if __name__ == "__main__":
    main()

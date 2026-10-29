"""Replace the stock Google Play vendor modules in an isolated partition image.

Run inside android-device-lab-tools:v12 with /work writable and /modules read-only.
Extract the stock partition with extract-playstore-numa-vendor.py first.
"""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


WORK = Path("/work")
MODULES = Path("/modules")
SOURCE = WORK / "vendor-stock-partition.img"
OUTPUT = WORK / "vendor-numa-partition.img"


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main():
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    shutil.copyfile(SOURCE, OUTPUT)
    extracted = WORK / "vendor-stock-extracted"
    extracted.mkdir(exist_ok=False)
    run("debugfs", "-R", f"rdump /lib/modules {extracted}", str(SOURCE))
    names = sorted(path.name for path in (extracted / "modules").glob("*.ko"))
    if len(names) != 37:
        raise ValueError(f"Unexpected vendor module count: {len(names)}")

    label = WORK / "vendor-selinux-label"
    label.write_bytes(b"u:object_r:vendor_file:s0\0")
    commands = []
    for name in names:
        source = MODULES / name
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = f"/lib/modules/{name}"
        commands.extend(
            [
                f"rm {destination}",
                f"write {source} {destination}",
                f"set_inode_field {destination} mode 0100644",
                f"ea_set -f {label} {destination} security.selinux",
            ]
        )
    command_file = WORK / "vendor-debugfs.commands"
    command_file.write_text("\n".join(commands) + "\n")
    run("debugfs", "-w", "-f", str(command_file), str(OUTPUT))

    for name in names:
        dumped = WORK / "verify-vendor.ko"
        run("debugfs", "-R", f"dump /lib/modules/{name} {dumped}", str(OUTPUT))
        if dumped.read_bytes() != (MODULES / name).read_bytes():
            raise ValueError(f"Vendor module differs: {name}")
        attributes = run("debugfs", "-R", f"ea_list /lib/modules/{name}", str(OUTPUT))
        if 'security.selinux (26) = "u:object_r:vendor_file:s0' not in attributes:
            raise ValueError(f"Vendor label differs: {name}")
        dumped.unlink()

    run("e2fsck", "-fn", str(OUTPUT))
    with OUTPUT.open("rb") as image:
        output_hash = hashlib.file_digest(image, "sha256").hexdigest()
    report = {
        "module_count": len(names),
        "vendor_image_size": OUTPUT.stat().st_size,
        "vendor_image_sha256": output_hash,
    }
    (WORK / "vendor-patch-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

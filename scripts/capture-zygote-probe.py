"""Capture early zygote events and independently identify the running lab image."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-vbmeta-digest", required=True)
    parser.add_argument("--expected-library-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"emulator-\d+", args.serial):
        raise ValueError("This capture is restricted to the emulator lab")

    def command(*values):
        result = subprocess.run([str(args.adb), "-s", args.serial, *values],
                                capture_output=True, timeout=20, check=True)
        return result.stdout.decode().strip()

    def prop(name):
        return command("shell", "-T", "getprop", name)

    boot_id = command("shell", "-T", "cat", "/proc/sys/kernel/random/boot_id")
    digest = prop("ro.boot.vbmeta.digest")
    library_hash = command("shell", "-T", "sha256sum", "/system/lib64/libdevice_lab_boot_probe.so").split()[0]
    if digest != args.expected_vbmeta_digest or library_hash != args.expected_library_sha256:
        raise ValueError("Runtime image does not match the prepared candidate")
    zygote = command("shell", "-T", "pidof", "zygote64")
    server = command("shell", "-T", "pidof", "system_server")
    if not zygote.isdigit() or not server.isdigit():
        raise ValueError("Expected one live zygote and system_server")
    log = command("logcat", "-d", "-v", "raw", "-s", "DeviceLabExecProbe:I")
    events = [json.loads(line) for line in log.splitlines() if line.startswith('{"stage":')]
    report = {
        "captured_at": datetime.now(timezone.utc).isoformat(), "serial": args.serial, "boot_id": boot_id,
        "selinux": command("shell", "-T", "getenforce"), "verity_mode": prop("ro.boot.veritymode"),
        "vbmeta_digest": digest, "library_sha256": library_hash,
        "boot_completed": prop("sys.boot_completed"), "zygote_pid": int(zygote),
        "system_server_pid": int(server), "zygote_service": prop("init.svc.zygote"),
        "build_type": prop("ro.build.type"), "debuggable": prop("ro.debuggable"), "events": events,
    }
    if command("shell", "-T", "cat", "/proc/sys/kernel/random/boot_id") != boot_id or \
            command("shell", "-T", "pidof", "zygote64") != zygote or \
            command("shell", "-T", "pidof", "system_server") != server:
        raise ValueError("Runtime process instance changed during collection")
    args.output.with_suffix(".log").write_text(log + "\n")
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

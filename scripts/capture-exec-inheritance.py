"""Read loader inheritance from the unchanged debuggable diagnostic applications."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess


PACKAGES = ("dev.androidlab.probe", "dev.androidlab.rawprobe", "dev.androidlab.procprobe")
LIBRARY = "/system/lib64/libdevice_lab_boot_probe.so"


def process_start(result, pid):
    if result.returncode or not result.stdout.startswith(f"{pid} (".encode()):
        return None
    fields = result.stdout.rsplit(b") ", 1)[-1].split()
    return int(fields[19]) if len(fields) > 19 and fields[19].isdigit() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"emulator-\d+", args.serial):
        raise ValueError("This capture is restricted to the emulator lab")

    def command(*values):
        return subprocess.run([str(args.adb), "-s", args.serial, *values],
                              capture_output=True, timeout=15)

    boot = command("shell", "-T", "cat", "/proc/sys/kernel/random/boot_id")
    boot_id = boot.stdout.decode().strip()
    if boot.returncode or not re.fullmatch(r"[a-f0-9-]{36}", boot_id):
        raise ValueError("Could not identify the current emulator boot")
    observations = []
    for package in PACKAGES:
        process = command("shell", "pidof", package)
        value = process.stdout.decode().strip()
        if process.returncode or not value.isdigit():
            raise ValueError(f"Expected one running diagnostic process: {package}")
        pid = int(value)

        def read(name):
            return command("shell", "-T", "run-as", package, "cat", f"/proc/{pid}/{name}")

        stat_before = read("stat")
        maps, environment, status = (read(name) for name in ("maps", "environ", "status"))
        context = command("shell", "-T", "ps", "-p", str(pid), "-o", "LABEL,PID,NAME")
        context_rows = [line.split() for line in context.stdout.decode(errors="replace").splitlines()[1:]]
        context_valid = context.returncode == 0 and len(context_rows) == 1 and \
            len(context_rows[0]) == 3 and context_rows[0][1:] == [str(pid), package] and \
            re.fullmatch(r"u:r:untrusted_app(?:_\d+)?:s0(?::c\d+(?:,c\d+)*)?", context_rows[0][0]) is not None
        matches = [line for line in maps.stdout.decode(errors="replace").splitlines()
                   if len(line.split(maxsplit=5)) == 6 and line.split(maxsplit=5)[5] == LIBRARY]
        entries = [value for value in environment.stdout.split(b"\0") if value]
        preload = [value for value in entries if value.startswith(b"LD_PRELOAD=")]
        other = [value for value in entries if not value.startswith(b"LD_PRELOAD=")]
        normalized = b"\0".join(other) + b"\0"
        cleaned_environment = bytearray(environment.stdout)
        offset = 0
        for entry in environment.stdout.split(b"\0"):
            if entry.startswith(b"LD_PRELOAD="):
                cleaned_environment[offset:offset + len(entry)] = b"\0" * len(entry)
            offset += len(entry) + 1
        fields = {}
        keys = {"Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "TracerPid", "Seccomp", "Seccomp_filters"}
        if status.returncode == 0:
            fields = {key: value.strip() for line in status.stdout.decode().splitlines() if ":" in line
                      for key, value in [line.split(":", 1)] if key in keys}
        path_result = command("shell", "pm", "path", package)
        path = path_result.stdout.decode().strip().removeprefix("package:")
        if path_result.returncode or not re.fullmatch(r"/data/app/[A-Za-z0-9_~=/+.-]+/base\.apk", path):
            raise ValueError(f"Unexpected APK path: {package}")
        checksum = command("shell", "sha256sum", path)
        apk_hash = checksum.stdout.decode().split()[0] if checksum.stdout else ""
        if checksum.returncode or not re.fullmatch("[a-f0-9]{64}", apk_hash):
            raise ValueError(f"Could not identify installed diagnostic APK: {package}")
        stat_after = read("stat")
        process_after = command("shell", "pidof", package)
        start = process_start(stat_before, pid)
        stable = start is not None and process_start(stat_after, pid) == start and \
            process_after.returncode == 0 and process_after.stdout.decode().strip() == str(pid)
        observations.append({
            "package": package, "pid": pid, "apk_sha256": apk_hash,
            "process_start_ticks": start, "process_instance_stable": stable,
            "maps_read_success": maps.returncode == 0,
            "library_mapping_visible": bool(matches) if maps.returncode == 0 else None,
            "library_executable_mapping_visible": any(line.split()[1] == "r-xp" for line in matches) if maps.returncode == 0 else None,
            "library_mapping_lines": matches if maps.returncode == 0 else None,
            "initial_environment_read_success": environment.returncode == 0,
            "initial_environment_size": len(environment.stdout) if environment.returncode == 0 else None,
            "initial_environment_sha256": hashlib.sha256(environment.stdout).hexdigest() if environment.returncode == 0 else None,
            "expected_cleaned_environment_sha256": hashlib.sha256(cleaned_environment).hexdigest() if environment.returncode == 0 else None,
            "initial_environment_preload_entries": [value.decode(errors="replace") for value in preload] if environment.returncode == 0 else None,
            "non_preload_environment_sha256": hashlib.sha256(normalized).hexdigest() if environment.returncode == 0 else None,
            "non_preload_environment_entries": len(other) if environment.returncode == 0 else None,
            "status_read_success": status.returncode == 0, "status": fields,
            "context_read_success": context_valid,
            "context_source": "shell ps LABEL,PID,NAME matched to the diagnostic process",
            "context": context_rows[0][0] if context_valid else None,
        })
    boot_after = command("shell", "-T", "cat", "/proc/sys/kernel/random/boot_id")
    if boot_after.returncode or boot_after.stdout.decode().strip() != boot_id:
        raise ValueError("Emulator boot changed during collection")
    report = {"schema_version": 2, "captured_at": datetime.now(timezone.utc).isoformat(), "boot_id": boot_id,
              "source": "read-only run-as observations of unchanged diagnostic APKs",
              "other_environment_values_exported": False, "applications": observations}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    for value in observations:
        print(f"{value['package']}: mapping={value['library_mapping_visible']}; "
              f"initial_preload={value['initial_environment_preload_entries']}; "
              f"effective_capabilities={value['status'].get('CapEff')}")


if __name__ == "__main__":
    main()

"""Verify early constructor transport in the pinned real zygote service."""

import argparse
import json
from pathlib import Path
import re


ARGUMENTS = ["-Xzygote", "/system/bin", "--zygote", "--start-system-server", "--socket-name=zygote"]


def command_line(executable):
    values = [executable] + ARGUMENTS
    data = b"".join(value.encode() + b"\0" for value in values)
    digest = 14695981039346656037
    for value in data:
        digest = ((digest ^ value) * 1099511628211) & ((1 << 64) - 1)
    return len(data), f"{digest:016x}", len(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-cleanup", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    events = report.get("events", [])
    names = [value.get("stage") for value in events]
    unique = {"wrapper", "constructor"}.issubset(names) and \
        set(names).issubset({"wrapper", "constructor", "constructor_cleanup"}) and len(names) == len(set(names))
    found = {value.get("stage"): value for value in events}
    wrapper, constructor = found.get("wrapper", {}), found.get("constructor", {})
    cleanup = found.get("constructor_cleanup", {})
    states = (wrapper, constructor)
    caps = ("effective_capabilities", "permitted_capabilities", "inheritable_capabilities",
            "bounding_capabilities", "ambient_capabilities")
    checks = {
        "enforcing": report.get("selinux") == "Enforcing",
        "verity_enforcing": report.get("verity_mode") == "enforcing",
        "boot_complete": report.get("boot_completed") == "1",
        "system_server_running": report.get("system_server_pid", 0) > 0,
        "all_stages_once": unique,
        "real_zygote_pid": unique and wrapper.get("pid") == constructor.get("pid") == report.get("zygote_pid", 0)
            and report.get("zygote_pid", 0) > 0,
        "root_credentials": unique and all(value.get(key) == 0 for value in states for key in ("uid", "euid", "gid", "egid")),
        "zygote_domain": unique and all(value.get("context") == "u:r:zygote:s0" for value in states),
        "groups_preserved": unique and wrapper.get("groups") == constructor.get("groups") and
            all(isinstance(value.get("groups"), list) and value.get("group_count", -1) >= 0 and
                value.get("group_count") == len(value["groups"]) for value in states),
        "all_capabilities_preserved": unique and all(wrapper.get(key) == constructor.get(key) and
            re.fullmatch("[0-9a-f]{16}", wrapper.get(key, "")) for key in caps) and
            all(value.get("capget_result") == 0 and value.get("capability_query_errors") == 0 for value in states),
        "no_new_privs_preserved": unique and all(value.get("no_new_privs") == 0 for value in states),
        "first_exec_secure": wrapper.get("at_secure") == 1,
        "second_exec_not_secure": constructor.get("at_secure") == 0,
        "preload_configured_at_second_exec": wrapper.get("preload_present") is False and constructor.get("preload_present") is True,
        "android_runtime_visible": constructor.get("runtime_library_visible") is True,
    }
    for stage, executable in (("wrapper", "/system/bin/device-lab-exec-wrapper"),
                              ("constructor", "/system/bin/app_process64")):
        value = found.get(stage, {})
        size, digest, count = command_line(executable)
        checks[f"{stage}_arguments_exact"] = value.get("command_line_size") == size and \
            value.get("command_line_hash_fnv1a") == digest and value.get("argument_count") == count
    cleaned = bool(cleanup) and cleanup.get("pid") == wrapper.get("pid") and \
        cleanup.get("preload_entry_count") == 1 and cleanup.get("unsetenv_result") == 0 and \
        cleanup.get("zeroed_bytes") == len("LD_PRELOAD=/system/lib64/libdevice_lab_boot_probe.so") and \
        cleanup.get("libc_preload_present") is False and cleanup.get("passed") is True
    if args.require_cleanup:
        checks["constructor_environment_cleanup"] = cleaned
    verification = {"source_report": args.report.name, "scope": "early real-zygote constructor transport",
                    "passed": all(checks.values()), "checks": checks,
                    "runtime_hooks_verified": False, "environment_cleanup_observed": cleaned}
    if args.output:
        args.output.write_text(json.dumps(verification, indent=2) + "\n")
    print(json.dumps(verification, indent=2))
    raise SystemExit(0 if verification["passed"] else 1)


if __name__ == "__main__":
    main()

"""Validate the helper's double-exec transport without treating it as a zygote hook test."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-cleanup", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    events = report.get("events", [])
    stages = ("wrapper", "constructor", "helper", "helper_result")
    names = [event.get("stage") for event in events]
    unique = set(stages).issubset(names) and set(names).issubset(set(stages) | {"constructor_cleanup"}) and \
        len(names) == len(set(names))
    found = {event.get("stage"): event for event in events}
    states = [found.get(stage, {}) for stage in stages[:3]]
    result = found.get("helper_result", {})
    cleanup = found.get("constructor_cleanup", {})
    pids = {event.get("pid") for event in events}
    caps = {event.get("effective_capabilities") for event in states}
    checks = {
        "enforcing": report.get("selinux") == "Enforcing",
        "boot_complete": report.get("boot_completed") == "1",
        "all_stages_once": unique,
        "same_process": unique and len(pids) == 1 and next(iter(pids), 0) > 0,
        "root_credentials": unique and all(event.get("uid") == 0 and event.get("euid") == 0 for event in states),
        "zygote_domain": unique and all(event.get("context") == "u:r:zygote:s0" for event in states),
        "no_new_privs_preserved": unique and all(event.get("no_new_privs") == 0 for event in states),
        "effective_capabilities_preserved": unique and len(caps) == 1 and None not in caps and
            all(event.get("capget_result") == 0 for event in states),
        "first_exec_secure": found.get("wrapper", {}).get("at_secure") == 1,
        "second_exec_not_secure": unique and all(event.get("at_secure") == 0 for event in states[1:]),
        "preload_at_constructor": found.get("constructor", {}).get("preload_present") is True,
        "preload_removed_at_main": found.get("helper", {}).get("preload_present") is False,
        "constructor_marker": result.get("marker") == 0x30504C44,
        "mapping_visible": result.get("mapping_visible") is True,
        "helper_passed": result.get("passed") is True and result.get("preload_cleared") is True,
    }
    cleaned = bool(cleanup) and cleanup.get("pid") == result.get("pid") and \
        cleanup.get("preload_entry_count") == 1 and cleanup.get("unsetenv_result") == 0 and \
        cleanup.get("zeroed_bytes") == len("LD_PRELOAD=/system/lib64/libdevice_lab_boot_probe.so") and \
        cleanup.get("libc_preload_present") is False and cleanup.get("passed") is True
    if args.require_cleanup:
        checks["constructor_environment_cleanup"] = cleaned
    verification = {"source_report": args.report.name, "scope": "helper double-exec transport",
                    "passed": all(checks.values()), "checks": checks,
                    "full_zygote_runtime_verified": False, "environment_cleanup_observed": cleaned}
    if args.output:
        args.output.write_text(json.dumps(verification, indent=2) + "\n")
    print(json.dumps(verification, indent=2))
    raise SystemExit(0 if verification["passed"] else 1)


if __name__ == "__main__":
    main()

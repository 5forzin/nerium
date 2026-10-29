"""Compare initial-environment cleanup while retaining an observable inherited library."""

import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    before = json.loads(args.before.read_text(encoding="utf-8-sig"))
    after = json.loads(args.after.read_text(encoding="utf-8-sig"))
    if before.get("schema_version") != 2 or after.get("schema_version") != 2:
        raise ValueError("Recapture both controls with shell exit status and raw environment hashes")
    old = {value["package"]: value for value in before["applications"]}
    new = {value["package"]: value for value in after["applications"]}
    expected = {"dev.androidlab.probe", "dev.androidlab.rawprobe", "dev.androidlab.procprobe"}
    if old.keys() != expected or new.keys() != expected or len(before["applications"]) != 3 or len(after["applications"]) != 3:
        raise ValueError("The capture must contain the same three diagnostic APKs")
    comparisons = {}
    status_keys = ("Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "TracerPid", "Seccomp", "Seccomp_filters")
    readable = ("maps_read_success", "initial_environment_read_success", "status_read_success", "context_read_success")
    for package in sorted(expected):
        b, a = old[package], new[package]
        uid = a["status"].get("Uid", "").split()
        gid = a["status"].get("Gid", "").split()
        filters = a["status"].get("Seccomp_filters")
        checks = {
            "same_apk": b.get("apk_sha256") == a.get("apk_sha256") and bool(a.get("apk_sha256")),
            "all_reads_available": all(value.get(key) is True for value in (b, a) for key in readable),
            "stable_process_instances": b.get("process_instance_stable") is True and a.get("process_instance_stable") is True,
            "library_remains_visible": b.get("library_mapping_visible") is True and a.get("library_mapping_visible") is True,
            "library_executable_mapping_remains_visible": b.get("library_executable_mapping_visible") is True and
                a.get("library_executable_mapping_visible") is True,
            "before_control_present": b.get("initial_environment_preload_entries") == ["LD_PRELOAD=/system/lib64/libdevice_lab_boot_probe.so"],
            "after_control_absent": a.get("initial_environment_preload_entries") == [],
            "other_environment_unchanged": bool(a.get("non_preload_environment_sha256")) and
                b.get("non_preload_environment_sha256") == a.get("non_preload_environment_sha256") and
                b.get("non_preload_environment_entries") == a.get("non_preload_environment_entries"),
            "initial_environment_size_preserved": b.get("initial_environment_size") == a.get("initial_environment_size"),
            "exact_raw_environment_cleanup": re.fullmatch("[a-f0-9]{64}", a.get("initial_environment_sha256") or "") is not None and
                b.get("expected_cleaned_environment_sha256") == a.get("initial_environment_sha256"),
            "application_identity_preserved": bool(a.get("context")) and b.get("context") == a.get("context") and
                all(b["status"].get(key) == a["status"].get(key) and a["status"].get(key) is not None for key in status_keys),
            "application_capabilities_unprivileged": all(a["status"].get(key) == "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
            "ordinary_application_uid": len(uid) == 4 and len(gid) == 4 and len(set(uid + gid)) == 1 and
                uid[0].isdigit() and int(uid[0]) >= 10000 and
                re.fullmatch(r"u:r:untrusted_app(?:_\d+)?:s0(?::c\d+(?:,c\d+)*)?", a.get("context") or "") is not None,
            "normal_application_process_controls": a["status"].get("TracerPid") == "0" and
                a["status"].get("NoNewPrivs") == "0" and a["status"].get("Seccomp") == "2" and
                isinstance(filters, str) and filters.isdigit() and int(filters) >= 1,
        }
        comparisons[package] = {"passed": all(checks.values()), "checks": checks}
    result = {"before": args.before.name, "after": args.after.name,
              "scope": "initial LD_PRELOAD residue removal in unchanged diagnostic APKs",
              "passed": all(value["passed"] for value in comparisons.values()), "applications": comparisons}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()

"""Validate owned-process permission measurements without treating blocked calls as clean."""

import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    before, after = report["before"], report["after"]
    rows = report["observations"]
    paired = {"self_process_vm_readv", "proc_maps", "proc_mem", "process_vm_readv", "kcmp_files", "pidfd_getfd"}
    expected = {(name, mode) for name in paired for mode in (0, 1)} | {(name, 0) for name in ("seccomp_action_avail", "seccomp_notif_sizes")}
    found = {(value["operation"], value["requested_dumpable"]): value for value in rows}
    mount_fields = report.get("host", {}).get("proc_mount", "").split()
    mount_options = set(mount_fields[3].split(",")) if len(mount_fields) >= 4 else set()

    def normal(identity):
        return isinstance(identity, dict) and identity.get("context_available") is True and \
            re.fullmatch(r"u:r:untrusted_app(?:_\d+)?:s0(?::c\d+(?:,c\d+)*)?", identity.get("context") or "") is not None and \
            identity.get("context") == before["context"] and identity.get("uid", 0) >= 10000 and \
            all(identity.get(k) == before["uid"] for k in ("uid", "euid", "gid", "egid", "fsuid", "fsgid")) and \
            isinstance(identity.get("groups"), list) and identity["groups"] == before["groups"] and 3009 not in identity["groups"] and \
            identity.get("capabilities_available") is True and identity.get("capabilities") == ["0000000000000000"] * 5 and \
            identity.get("no_new_privs") == 0 and identity.get("seccomp") == 2 and identity.get("seccomp_filters", 0) >= 1

    checks = {
        "selinux_enforcing": report.get("host", {}).get("selinux") == "Enforcing",
        "exact_measurement_set": len(rows) == 14 and found.keys() == expected,
        "application_state_unchanged": before == after and normal(before),
        "all_runners_unprivileged": all(normal(value.get("runner")) for value in rows),
        "separate_runner_per_operation": len({value["runner_pid"] for value in rows}) == len(rows) and all(value["runner_pid"] > 0 and value["runner_pid"] != report["process_id"] for value in rows),
        "real_subject_modes": all(normal(value["subject"]) and value["subject"]["dumpable"] == value["requested_dumpable"] and value["subject_pid"] > 0 for value in rows if value["operation"] in paired - {"self_process_vm_readv"}),
        "unused_subjects_are_null": all(value["subject"] is None and value["subject_pid"] == 0 for value in rows if value["operation"] == "self_process_vm_readv" or value["operation"].startswith("seccomp_")),
        "returned_values_are_explicit": all((value["returned"] is True and value["attempted"] is True and isinstance(value["return"], int) and isinstance(value["errno"], int)) or (value["returned"] is False and value["return"] is None and value["errno"] is None) for value in rows),
        "proc_visibility_policy_observed": "gid=3009" in mount_options and bool(mount_options & {"hidepid=invisible", "hidepid=2"}),
        "subjects_alive_during_completed_reads": all(value.get("subject_alive_before") is True and value.get("subject_alive_after") is True for value in rows if value["subject_pid"] > 0 and value["completed"]),
    }
    if found.keys() == expected:
        for mode in (0, 1):
            value = found["self_process_vm_readv", mode]
            checks[f"self_read_dumpable_{mode}"] = value["completed"] and value["returned"] and value["return"] == 8 and value["matched"] and value["runner"]["dumpable"] == mode
        for name in ("proc_maps", "proc_mem"):
            denied, allowed = found[name, 0], found[name, 1]
            checks[f"{name}_permission_control"] = denied["completed"] and denied["open_returned"] and denied["open_return"] == -1 and denied["open_errno"] in (1, 2, 13) and denied["subject_alive_before"] is True and denied["subject_alive_after"] is True and denied["attempted"] is False and allowed["completed"] and allowed["open_returned"] and allowed["open_return"] >= 0 and allowed["returned"] and allowed["matched"]
        for name in ("process_vm_readv", "pidfd_getfd"):
            denied, allowed = found[name, 0], found[name, 1]
            checks[f"{name}_permission_control"] = denied["completed"] and denied["returned"] and denied["return"] == -1 and denied["errno"] == 1 and allowed["completed"] and allowed["returned"] and allowed["return"] >= 0 and allowed["matched"]
        checks["kcmp_interruption_not_counted_as_success"] = all(found["kcmp_files", mode]["completed"] is False and found["kcmp_files", mode]["exit_signal"] == 31 and found["kcmp_files", mode]["last_stage"] == 9 and found["kcmp_files", mode]["attempted"] is True and found["kcmp_files", mode]["returned"] is False for mode in (0, 1))
        checks["query_support_only"] = all(found[name, 0]["completed"] and found[name, 0]["returned"] and found[name, 0]["return"] == 0 for name in ("seccomp_action_avail", "seccomp_notif_sizes")) and found["seccomp_notif_sizes", 0]["notification_sizes"] == [80, 24, 64]
    result = {
        "source_report": args.report.name,
        "scope": "owned-process read-only permission controls, not a broker implementation",
        "measurement_contract_passed": all(checks.values()), "checks": checks,
        "completed_operations": sum(value["completed"] is True for value in rows),
        "interrupted_operations": sum(value["exit_signal"] != 0 for value in rows),
        "kcmp_operational_in_app": all(value["completed"] and value["returned"] and value["return"] >= 0 for value in rows if value["operation"] == "kcmp_files") and sum(value["operation"] == "kcmp_files" for value in rows) == 2,
        "cross_domain_broker_verified": False,
        "filter_installation_or_interception_verified": False,
        "zero_detections_achieved": False,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["measurement_contract_passed"] else 1)


if __name__ == "__main__":
    main()

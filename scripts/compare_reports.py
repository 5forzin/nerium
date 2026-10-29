"""Compare independently collected device reports without claiming physical-device status."""

import argparse
import hashlib
import json
from pathlib import Path


def observation(value):
    text = str(value)
    if len(text) <= 240:
        return text
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    return f"{text[:120]!r}... ({len(text)} characters, sha256 {digest})"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args()
    before = json.loads(args.before.read_text(encoding="utf-8-sig"))
    after = json.loads(args.after.read_text(encoding="utf-8-sig"))
    if "detector" in before and "detector" in after:
        keys = ("detector", "package", "apk_sha256", "installed_abi")
        if any(before[key] != after[key] for key in keys):
            raise SystemExit("Detector identity, APK checksum or ABI changed between measurements")
        print(f"Detector: {before['detector']} (same APK checksum and ABI)")
        print(f"Status: {before['status']} -> {after['status']}")
        print(f"Detected: {before['detected']} -> {after['detected']}")
        for label, report in (("Before", before), ("After", after)):
            print(f"{label}: {report['reason']}")
        if before["detected"] is None or after["detected"] is None:
            print("Incomplete measurements must not be counted as clear.")
        if "duck" in before and "duck" in after:
            for label in ("Danger", "Warning", "Ready", "Pending"):
                old = before["duck"]["scan_statistics"][label]
                new = after["duck"]["scan_statistics"][label]
                print(f"{label} modules: {old} -> {new}")
            old_modules = {m["detector"]: m for m in before["duck"]["module_verdicts"]}
            new_modules = {m["detector"]: m for m in after["duck"]["module_verdicts"]}
            for name in sorted(old_modules.keys() | new_modules.keys()):
                old, new = old_modules.get(name), new_modules.get(name)
                if old != new:
                    print(f"  {name}: {old['severity'] + ': ' + old['verdict'] if old else 'missing'}")
                    print(f"    -> {new['severity'] + ': ' + new['verdict'] if new else 'missing'}")
        return
    if "finding_count" in before and "finding_count" in after:
        if (before["package"], before["apk_sha256"]) != (after["package"], after["apk_sha256"]):
            raise SystemExit("Detector package or APK checksum changed between measurements")
        print(f"Detector: {before['package']} (same APK checksum)")
        print(f"Findings: {before['finding_count']} -> {after['finding_count']}")
        print(f"Detected: {before['detected']} -> {after['detected']}")
        for finding in sorted(set(before["findings"]) - set(after["findings"])):
            print(f"  Removed: {finding}")
        for finding in sorted(set(after["findings"]) - set(before["findings"])):
            print(f"  Added: {finding}")
        return
    if before["schema_version"] != after["schema_version"]:
        raise SystemExit("Report schema versions differ")
    if "apk_sha256" in before and "apk_sha256" in after and before["apk_sha256"] != after["apk_sha256"]:
        raise SystemExit("Probe APK checksum changed between measurements")
    if "installed_abi" in before and "installed_abi" in after and before["installed_abi"] != after["installed_abi"]:
        raise SystemExit("Probe installation ABI changed between measurements")
    old_checks = {item["id"]: item for item in before["checks"]}
    new_checks = {item["id"]: item for item in after["checks"]}
    print("Device identity changes:")
    changes = 0
    old_device, new_device = before.get("device", {}), after.get("device", {})
    for key in sorted(old_device.keys() | new_device.keys()):
        old, new = old_device.get(key), new_device.get(key)
        if old != new:
            changes += 1
            print(f"  {key}: {old!r} -> {new!r}")
    print(f"\nChanged identity fields: {changes}")
    print("\nCheck changes:")
    for check_id in sorted(old_checks.keys() | new_checks.keys()):
        old, new = old_checks.get(check_id), new_checks.get(check_id)
        if old != new:
            old_status = old["status"] if old else "missing"
            new_status = new["status"] if new else "missing"
            print(f"  {check_id}: {old_status} -> {new_status}")
            print(f"    before: {observation(old.get('observed', old.get('detail'))) if old else None}")
            print(f"    after:  {observation(new.get('observed', new.get('detail'))) if new else None}")
    remaining = [item["id"] for item in after["checks"] if item["status"] == "detected"]
    unavailable = [item["id"] for item in after["checks"] if item["status"] == "unavailable"]
    print(f"\nRemaining detected signals ({len(remaining)}):")
    for check_id in remaining:
        print(f"  {check_id}")
    print(f"\nUnavailable checks ({len(unavailable)}):")
    for check_id in unavailable:
        print(f"  {check_id}")
    print("\nThese are heuristic observations, not proof of a physical device or an integrity verdict.")


if __name__ == "__main__":
    main()

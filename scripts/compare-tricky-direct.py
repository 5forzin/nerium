"""Validate the isolated TrickyStoreOSS trial against its fresh-boot baseline."""

import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"


def report(name):
    return json.loads((REPORTS / f"strict-v17-direct-{name}.json").read_text(encoding="utf-8-sig"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    cache = Path(os.environ["LOCALAPPDATA"]) / "android-device-lab" / "research-v17"
    sandbox = json.loads((cache / "sandbox-manifest.json").read_text(encoding="utf-8"))
    for name, expected_hash in sandbox["baseline_file_sha256"].items():
        with (Path(sandbox["accepted_avd"]) / name).open("rb") as source:
            require(hashlib.file_digest(source, "sha256").hexdigest() == expected_hash,
                    f"Accepted baseline changed: {name}")
    manifest = json.loads((cache / "candidate-direct" / "manifest.json").read_text(encoding="utf-8"))
    with (cache / "candidate-direct" / "inject").open("rb") as source:
        require(hashlib.file_digest(source, "sha256").hexdigest() == manifest["files"]["inject"],
                "Adapted injector hash changed")
    before_boot = report("before-boot")
    after_boot = report("after-boot")
    candidate = json.loads((REPORTS / "strict-v17-tricky-direct.json").read_text(encoding="utf-8-sig"))
    before_duck = report("before-duck")
    after_duck = report("after-duck")
    offline_duck = report("after-offline-duck")
    trust = report("after-trust-audit")

    require(before_boot["boot_id"] == after_boot["boot_id"] == candidate["boot_id"], "Boot ID changed")
    policy = before_boot["loaded_selinux_policy_sha256"]
    require(policy == after_boot["loaded_selinux_policy_sha256"] == candidate["loaded_selinux_policy_sha256"],
            "Loaded SELinux policy changed")
    require(candidate["candidate_library_loaded"] and candidate["interceptors_initialized"],
            "Candidate did not initialize")
    require(candidate["keystore_before"] == candidate["keystore_after"] and
            candidate["enforcing"] == "Enforcing" and not candidate["hardware_trust_supplied"],
            "Keystore or policy precondition failed")
    for boot in (before_boot, after_boot):
        require(boot["selinux_controls"]["passed"] == 5 and boot["selinux_controls"]["failed"] == 0,
                "SELinux controls regressed")
        require(boot["platform_contract"]["passed"] == 12 and boot["platform_contract"]["failed"] == 0,
                "Syscall contract regressed")

    probes = {}
    for name, total in (("proc99", 99), ("raw79", 79), ("probe54", 54)):
        before, after = report(f"before-{name}"), report(f"after-{name}")
        require(before["apk_sha256"] == after["apk_sha256"], f"{name} APK changed")
        for item in (before, after):
            require(item["summary"] == {"detected": 0, "unavailable": 0, "total": total},
                    f"{name} detection or availability regressed")
        probes[name] = {"before": before["summary"], "after": after["summary"],
                        "apk_sha256": after["apk_sha256"]}

    before_reveny, after_reveny = report("before-reveny"), report("after-reveny")
    require(before_reveny["apk_sha256"] == after_reveny["apk_sha256"], "Reveny APK changed")
    require(all(not item["detected"] and item["finding_count"] == 0
                for item in (before_reveny, after_reveny)), "Reveny regressed")

    for item in (before_duck, after_duck, offline_duck):
        require(item["status"] == "complete" and item["apk_sha256"] == before_duck["apk_sha256"],
                "Duck scan or APK changed")
    samples = (REPORTS / "strict-v17-direct-after-offline-duck-state" / "samples.jsonl").read_text().splitlines()
    require(len(samples) == 36, "Offline sample count changed")
    require(all(json.loads(line)["adbd"] == "stopped" and json.loads(line)["mdnsd"] == "stopped"
                for line in samples), "ADB was active during an offline sample")

    require(trust["manufacturer_trust"] == "not_established" and
            len(trust["failed_prerequisites"]) == 9, "Independent trust probe changed unexpectedly")
    result = {
        "trial": "TrickyStoreOSS x86_64 target-open transport in the isolated four-vCPU AVD",
        "source_revision": candidate["repository_revision"],
        "boot_id": candidate["boot_id"],
        "selinux_enforcing": True,
        "loaded_selinux_policy_sha256": policy,
        "keystore_pid_unchanged": True,
        "candidate_initialized": True,
        "accepted_baseline_untouched": True,
        "scope": ["com.eltavine.duckdetector"],
        "probes": probes,
        "reveny": {"before": 0, "after": 0, "apk_sha256": after_reveny["apk_sha256"]},
        "duck": {
            "normal_before": before_duck["duck"]["scan_statistics"],
            "normal_after": after_duck["duck"]["scan_statistics"],
            "offline_after": offline_duck["duck"]["scan_statistics"],
            "offline_samples": len(samples),
            "bootloader_before": next(v["verdict"] for v in before_duck["duck"]["module_verdicts"]
                                      if v["detector"] == "Bootloader"),
            "bootloader_after": next(v["verdict"] for v in after_duck["duck"]["module_verdicts"]
                                     if v["detector"] == "Bootloader"),
            "tee_before": next(v["verdict"] for v in before_duck["duck"]["module_verdicts"]
                               if v["detector"] == "TEE"),
            "tee_after": next(v["verdict"] for v in after_duck["duck"]["module_verdicts"]
                              if v["detector"] == "TEE"),
            "remaining": ["AOSP test root", "expired AOSP intermediate", "Binder hook",
                          "unexpected Keystore2 reply", "RSA-OAEP MGF enforcement mismatch"],
        },
        "independent_attestation": {
            "targeted_by_candidate": False,
            "failed_hardware_trust_prerequisites": trust["failed_prerequisites"],
            "manufacturer_trust": trust["manufacturer_trust"],
        },
        "hardware_trust_supplied": False,
        "evidence": ["strict-v17-tricky-direct.json", "strict-v17-direct-before-duck.json",
                     "strict-v17-direct-after-duck.json", "strict-v17-direct-after-offline-duck.json",
                     "strict-v17-direct-after-trust-audit.json"],
    }
    output = REPORTS / "strict-v17-direct-summary.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "duck": result["duck"], "manufacturer_trust":
                      result["independent_attestation"]["manufacturer_trust"]}))


if __name__ == "__main__":
    main()

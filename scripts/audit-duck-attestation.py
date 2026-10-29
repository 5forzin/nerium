"""Correlate the unchanged Duck export with independently verified public evidence."""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

DUCK_REVISION = "b5305070468a497842f54fbe998521fbc9d87ddc"
DUCK_APK_SHA256 = "9d0bbdab9c0b14334c9ec0d319758c5f9085260a09388486482b2ac497c81ffc"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attestation", type=Path)
    parser.add_argument("duck", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-challenge", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="device-lab-duck-attestation-") as directory:
        destination = Path(directory, "verified.json")
        subprocess.run(
            [sys.executable, str(Path(__file__).with_name("verify-attestation.py")),
             str(args.attestation), "--output", str(destination)]
            + (["--expected-challenge", str(args.expected_challenge)] if args.expected_challenge else []),
            check=True, capture_output=True, text=True,
        )
        verified = json.loads(destination.read_text(encoding="utf-8"))
    attestation = json.loads(args.attestation.read_text(encoding="utf-8-sig"))
    duck = json.loads(args.duck.read_text(encoding="utf-8-sig"))
    if duck["apk_sha256"] != DUCK_APK_SHA256:
        raise ValueError("This source interpretation requires the pinned Duck APK")
    export_path = args.duck.parent / duck["duck"]["export_report"]
    export_bytes = export_path.read_bytes()
    if hashlib.sha256(export_bytes).hexdigest() != duck["duck"]["export_sha256"]:
        raise ValueError("Duck export hash mismatch")
    export = export_bytes.decode("utf-8-sig")
    fingerprints = re.findall(r"Root fingerprint:\s*([a-f0-9]{64})", export)
    if not fingerprints:
        raise ValueError("Duck did not export a complete root public-key fingerprint")
    root = x509.load_der_x509_certificate(base64.b64decode(
        attestation["default_keystore"]["certificates"][-1]["der_base64"], validate=True))
    public_key = root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    public_key_hash = hashlib.sha256(public_key).hexdigest()
    if any(value != public_key_hash for value in fingerprints):
        raise ValueError("Duck and the independent probe observed different root public keys")
    boot = verified["signed_claims"]["root_of_trust"]
    evidence = {
        "boot_state": boot["verified_boot_state"],
        "lock_state": boot["device_locked"],
        "attested_boot_state": boot["verified_boot_state"],
        "attested_lock": boot["device_locked"],
        "attested_boot_hash": boot["verified_boot_hash"],
        "attested_boot_key": boot["verified_boot_key"],
    }
    result = {
        "attestation": args.attestation.name,
        "duck": args.duck.name,
        "duck_apk_sha256": duck["apk_sha256"],
        "duck_source_revision": DUCK_REVISION,
        "source": "https://github.com/eltavine/Duck-Detector-Refactoring/blob/"
        + DUCK_REVISION + "/capability/attestation/data/src/main/kotlin/com/eltavine/duckdetector/"
        "capability/attestation/data/CertificateTrustAnalyzer.kt",
        "duck_export_sha256": hashlib.sha256(export_bytes).hexdigest(),
        "independent_root_certificate_sha256": verified["root_sha256"],
        "independent_root_public_key_sha256": public_key_hash,
        "duck_root_public_key_fingerprints": fingerprints,
        "root_public_key_fingerprint_agrees": True,
        "signed_claims": verified["signed_claims"],
        "external_nonce_binding_verified": verified["external_nonce_binding_verified"],
        "external_challenge": verified["external_challenge"],
        "bootloader_signal_inputs": evidence,
        "interpretation": [
            "Duck fingerprints SubjectPublicKeyInfo, whereas the independent root_sha256 fingerprints the entire certificate.",
            "The six Bootloader danger entries reuse four signed boot fields; they are not six independent hardware defects.",
            "In the pinned Duck analyzer, Factory is a fallback label after Google-root matching and AOSP name patterns; it does not establish manufacturer trust.",
        ],
        "scope": "Correlates public-key fingerprints and boot inputs only. Duck does not export its complete certificate chain here. The independent verifier checks its own chain, nonce and possession signature; manufacturer trust remains unestablished.",
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "root_public_key_fingerprint_agrees": True}))


if __name__ == "__main__":
    main()

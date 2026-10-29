"""Compare independently verified attestation claims with an external root snapshot."""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--roots", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-challenge", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="device-lab-attestation-") as temporary:
        verified_path = Path(temporary) / "verified.json"
        subprocess.run(
            [sys.executable, str(Path(__file__).with_name("verify-attestation.py")),
             str(args.report), "--output", str(verified_path)]
            + (["--expected-challenge", str(args.expected_challenge)] if args.expected_challenge else []),
            check=True, capture_output=True, text=True,
        )
        verified = json.loads(verified_path.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    roots = json.loads(args.roots.read_text(encoding="utf-8-sig"))
    if not isinstance(roots, list) or not roots or not all(isinstance(item, str) for item in roots):
        raise ValueError("Expected a nonempty JSON array of PEM root certificates")
    anchors = [x509.load_pem_x509_certificate(item.encode("ascii")) for item in roots]
    certificates = [x509.load_der_x509_certificate(base64.b64decode(
        item["der_base64"], validate=True)) for item in report["default_keystore"]["certificates"]]
    root = certificates[-1]

    def extension_indices(oid):
        return [index for index, certificate in enumerate(certificates)
                if any(extension.oid.dotted_string == oid for extension in certificate.extensions)]

    attestation_indices = extension_indices("1.3.6.1.4.1.11129.2.1.17")
    provisioning_indices = extension_indices("1.3.6.1.4.1.11129.2.1.30")
    provisioning_adjacent = (provisioning_indices[-1] == attestation_indices[-1] + 1
                             if provisioning_indices and attestation_indices else None)

    def public_key(certificate):
        return certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    claims = verified["signed_claims"]
    boot = claims.get("root_of_trust", {})
    checks = {
        "root_certificate_in_external_snapshot": any(
            root.fingerprint(hashes.SHA256()) == anchor.fingerprint(hashes.SHA256())
            for anchor in anchors),
        "root_public_key_in_external_snapshot": any(
            public_key(root) == public_key(anchor) for anchor in anchors),
        "attestation_security_level_is_hardware": claims["attestation_security_level"] in (1, 2),
        "keymaster_security_level_is_hardware": claims["keymaster_security_level"] in (1, 2),
        "root_of_trust_is_hardware_enforced": boot.get("authorization_list") == "hardware",
        "attested_device_is_locked": boot.get("device_locked") is True,
        "attested_boot_is_verified": boot.get("verified_boot_state") == 0,
        "attested_boot_key_is_nonzero": bool(boot.get("verified_boot_key"))
        and any(character != "0" for character in boot["verified_boot_key"]),
        "attested_boot_hash_is_nonzero": bool(boot.get("verified_boot_hash"))
        and any(character != "0" for character in boot["verified_boot_hash"]),
    }
    result = {
        "report": args.report.name,
        "report_sha256": digest(args.report),
        "external_root_snapshot_sha256": digest(args.roots),
        "external_root_count": len(anchors),
        "certificate_signatures_verified": verified["certificate_signatures_verified"],
        "nonce_binding_verified": verified["nonce_binding_verified"],
        "external_nonce_binding_verified": verified["external_nonce_binding_verified"],
        "external_challenge": verified["external_challenge"],
        "key_possession_verified": verified["key_possession_verified"],
        "root_sha256": verified["root_sha256"],
        "root_subject": root.subject.rfc4514_string(),
        "signed_claims": claims,
        "rkp_metadata": {
            "attestation_certificate_indices_zero_based": attestation_indices,
            "provisioning_certificate_indices_zero_based": provisioning_indices,
            "nearest_root_provisioning_adjacent_to_attestation": provisioning_adjacent,
            "root_public_key_matches_external_snapshot": checks["root_public_key_in_external_snapshot"],
            "scope": "Extension placement and root matching only; provisioning contents are not authenticated here.",
        },
        "prerequisites": checks,
        "failed_prerequisites": [name for name, passed in checks.items() if not passed],
        "revocation_checked": False,
        "full_pkix_path_validation_performed": False,
        "manufacturer_trust": "not_established",
        "scope": "Diagnostic prerequisite audit; matching an anchor alone does not establish hardware trust.",
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "failed_prerequisites": result["failed_prerequisites"]}))


if __name__ == "__main__":
    main()

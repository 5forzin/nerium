"""Verify public Android CNG laboratory evidence without trusting APK verdicts."""
import argparse
import base64
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier, SignatureAlgorithmOID

spec = importlib.util.spec_from_file_location("attestation_der", Path(__file__).with_name("verify-attestation.py"))
der = importlib.util.module_from_spec(spec)
spec.loader.exec_module(der)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(value):
    return base64.b64decode(value, validate=True)


def structured(data, tag):
    items = der.values(data)
    require(len(items) == 1 and items[0][:2] == (0, tag), "Unexpected ASN.1 structure")
    return der.values(items[0][2])


def check_certificate_algorithms(encoded, certificate):
    components = structured(encoded, 16)
    require(len(components) == 3 and components[0][:2] == (0, 16), "Malformed certificate structure")
    tbs = der.values(components[0][2])
    signature_index = 2 if tbs and tbs[0][:2] == (2, 0) else 1
    require(len(tbs) > signature_index, "Missing signed certificate algorithm")
    # RFC 5758 requires absent parameters for ecdsa-with-SHA256. Comparing the
    # exact AlgorithmIdentifier body also rejects inner/outer substitutions.
    expected = (0, 16, bytes.fromhex("06082a8648ce3d040302"))
    require(components[1] == expected and tbs[signature_index] == expected, "Certificate signature algorithms differ or are unsupported")
    require(certificate.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256, "Unexpected certificate signature OID")


def verify(report, challenge, roots, package, app_certificate, expected_lab_root_sha256):
    sample = report["default_keystore"]
    require(sample["status"] == "complete", "The APK did not collect attestation")
    require(len(challenge) == 32, "Expected a fresh 32-byte external challenge")
    require(sample["payload_scheme"] == "RSA_PSS_SHA256_SALT32", "Unexpected possession scheme")
    certificates = [x509.load_der_x509_certificate(decode(item["der_base64"])) for item in sample["certificates"]]
    require(len(certificates) == 2, "Expected a leaf and one laboratory issuer")
    now = datetime.now(timezone.utc)
    for index, certificate in enumerate(certificates):
        check_certificate_algorithms(decode(sample["certificates"][index]["der_base64"]), certificate)
        issuer = certificates[min(index + 1, len(certificates) - 1)]
        require(certificate.issuer == issuer.subject, "Issuer name mismatch")
        issuer_key = issuer.public_key()
        require(isinstance(issuer_key, ec.EllipticCurvePublicKey) and isinstance(issuer_key.curve, ec.SECP256R1), "Expected the laboratory P-256 issuer")
        require(isinstance(certificate.signature_hash_algorithm, hashes.SHA256), "Unexpected certificate digest")
        issuer_key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        require(certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc, "Certificate outside validity interval")
    root = certificates[-1]
    require(root.fingerprint(hashes.SHA256()).hex() == expected_lab_root_sha256, "Issuer differs from the root published directly by the host backend")
    common_names = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    require(len(common_names) == 1 and common_names[0].value == "AndroidLab Software Attestation Root", "Unexpected laboratory issuer")
    require(root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, "Issuer is not a CA")
    require(root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign, "Issuer cannot sign certificates")
    public_key = certificates[0].public_key()
    require(isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size == 2048 and public_key.public_numbers().e == 65537, "Unexpected leaf RSA profile")
    canonical = base64.b64encode(challenge).decode("ascii")
    payload = ("AndroidLab CNG attestation control v1\nchallenge_base64=" + canonical).encode("utf-8")
    require(decode(sample["payload_base64"]) == payload, "Possession payload is not bound to the external challenge")
    public_key.verify(decode(sample["signature_base64"]), payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    extension = certificates[0].extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")).value.value
    fields = structured(extension, 16)
    require(len(fields) == 8, "Unexpected attestation field count")
    require([int.from_bytes(fields[i][2], "big") for i in (0, 1, 2, 3)] == [300, 0, 300, 0], "Unexpected version or hardware claims")
    require(fields[4][:2] == (0, 4) and fields[4][2] == challenge, "Signed challenge mismatch")
    software, hardware = der.values(fields[6][2]), der.values(fields[7][2])
    require(not hardware, "Laboratory software attestation must not assert hardware authorizations")
    require(all(not (item[0] == 2 and item[1] == 704) for item in software + hardware), "Unknown boot state must not produce RootOfTrust")
    application_ids = [item for item in software if item[:2] == (2, 709)]
    require(len(application_ids) == 1, "Expected one software application identity")
    wrapped = der.values(application_ids[0][2])
    require(len(wrapped) == 1 and wrapped[0][:2] == (0, 4), "Malformed application identity")
    identity = structured(wrapped[0][2], 16)
    require(len(identity) == 2 and identity[0][:2] == (0, 17) and identity[1][:2] == (0, 17), "Malformed application identity sets")
    package_infos = der.values(identity[0][2])
    require(len(package_infos) == 1 and package_infos[0][:2] == (0, 16), "Unexpected application package set")
    package_fields = der.values(package_infos[0][2])
    require(len(package_fields) == 2 and package_fields[0][:2] == (0, 4) and package_fields[0][2] == package.encode("utf-8"), "Signed package mismatch")
    require(package_fields[1][:2] == (0, 2) and int.from_bytes(package_fields[1][2], "big") == 1, "Unexpected signed application version")
    digests = der.values(identity[1][2])
    require(len(digests) == 1 and digests[0][:2] == (0, 4) and digests[0][2] == app_certificate, "Signed APK certificate mismatch")
    anchors = [x509.load_pem_x509_certificate(item.encode("ascii")) for item in roots]
    root_spki = root.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(all(anchor.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != root_spki for anchor in anchors), "The laboratory issuer unexpectedly matches an external anchor")
    return {
        "certificate_signatures_verified": True,
        "externally_supplied_challenge_verified": True,
        "rsa_pss_key_possession_verified": True,
        "signed_package_and_apk_certificate_verified": True,
        "signed_package": package,
        "attestation_security_level": 0,
        "keymaster_security_level": 0,
        "root_of_trust_present": False,
        "root_subject": root.subject.rfc4514_string(),
        "root_sha256": root.fingerprint(hashes.SHA256()).hex(),
        "root_matches_host_backend": True,
        "root_matches_external_snapshot": False,
        "manufacturer_trust": "not_established",
        "full_pkix_path_validation_performed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-challenge", type=Path, required=True)
    parser.add_argument("--expected-app-certificate-sha256", required=True)
    parser.add_argument("--expected-lab-root-sha256", required=True)
    parser.add_argument("--roots", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    challenge = decode(json.loads(args.expected_challenge.read_text(encoding="utf-8-sig"))["challenge_base64"])
    roots = json.loads(args.roots.read_text(encoding="utf-8-sig"))
    require(isinstance(roots, list) and bool(roots), "Expected an external root snapshot")
    app_certificate = bytes.fromhex(args.expected_app_certificate_sha256)
    require(len(app_certificate) == 32, "Expected a SHA-256 APK signing-certificate digest")
    require(len(bytes.fromhex(args.expected_lab_root_sha256)) == 32, "Expected a SHA-256 host issuer fingerprint")
    result = verify(report, challenge, roots, "dev.androidlab.cngattestationcontrol", app_certificate, args.expected_lab_root_sha256.lower())
    result.update({"schema_version": 1, "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                   "external_root_snapshot_sha256": hashlib.sha256(args.roots.read_bytes()).hexdigest()})
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "public_software_attestation_verified", "manufacturer_trust": "not_established", "output": str(args.output)}))


if __name__ == "__main__":
    main()

"""Verify exported public attestation evidence independently on the host."""
import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ObjectIdentifier


def values(data):
    offset, result = 0, []
    while offset < len(data):
        first = data[offset]
        offset += 1
        tag = first & 31
        if tag == 31:
            tag = 0
            while True:
                item = data[offset]
                offset += 1
                tag = (tag << 7) | (item & 127)
                if not item & 128:
                    break
        length = data[offset]
        offset += 1
        if length & 128:
            count = length & 127
            if count == 0 or count > 4 or offset + count > len(data):
                raise ValueError("Invalid DER length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        if offset + length > len(data):
            raise ValueError("Truncated DER payload")
        result.append((first >> 6, tag, data[offset:offset + length]))
        offset += length
    return result


def verify_signature(key, signature, data, algorithm):
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(algorithm))
    elif isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, data, padding.PKCS1v15(), algorithm)
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key.verify(signature, data)
    else:
        raise ValueError("Unsupported attestation signature algorithm")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-challenge", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    sample = report["default_keystore"]
    if sample["status"] != "complete":
        raise ValueError("The device did not produce a complete attestation")
    certificates = [x509.load_der_x509_certificate(base64.b64decode(item["der_base64"])) for item in sample["certificates"]]
    for index, certificate in enumerate(certificates):
        issuer = certificates[min(index + 1, len(certificates) - 1)]
        if certificate.issuer != issuer.subject:
            raise ValueError("Certificate issuer name mismatch")
        verify_signature(issuer.public_key(), certificate.signature, certificate.tbs_certificate_bytes, certificate.signature_hash_algorithm)
        now = datetime.now(timezone.utc)
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            raise ValueError("Certificate is outside its validity interval")
    verify_signature(certificates[0].public_key(), base64.b64decode(sample["signature_base64"]), base64.b64decode(sample["payload_base64"]), hashes.SHA256())
    extension = certificates[0].extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")).value.value
    fields = values(values(extension)[0][2])
    challenge_matches = fields[4][2] == base64.b64decode(sample["challenge_base64"])
    if not challenge_matches:
        raise ValueError("Attestation nonce mismatch")
    external_nonce_verified = False
    if args.expected_challenge:
        expected = json.loads(args.expected_challenge.read_text(encoding="utf-8-sig"))
        challenge = base64.b64decode(expected["challenge_base64"], validate=True)
        if len(challenge) != 32 or fields[4][2] != challenge:
            raise ValueError("External attestation challenge mismatch")
        external_nonce_verified = True
    signed = {
        "attestation_version": int.from_bytes(fields[0][2], "big"),
        "attestation_security_level": int.from_bytes(fields[1][2], "big"),
        "keymaster_version": int.from_bytes(fields[2][2], "big"),
        "keymaster_security_level": int.from_bytes(fields[3][2], "big"),
    }
    for index in (6, 7):
        for tag_class, tag, payload in values(fields[index][2]):
            if tag_class == 2 and tag == 704:
                boot = values(values(payload)[0][2])
                signed["root_of_trust"] = {
                    "authorization_list": "software" if index == 6 else "hardware",
                    "verified_boot_key": boot[0][2].hex(),
                    "device_locked": boot[1][2] != b"\0",
                    "verified_boot_state": int.from_bytes(boot[2][2], "big"),
                    "verified_boot_hash": boot[3][2].hex() if len(boot) > 3 else None,
                }
    for key, value in signed.items():
        if sample["attestation"][key] != value:
            raise ValueError(f"Device/host attestation decode mismatch: {key}")
    result = {
        "report": args.report.name,
        "certificate_count": len(certificates),
        "certificate_signatures_verified": True,
        "nonce_binding_verified": True,
        "external_nonce_binding_verified": external_nonce_verified,
        "external_challenge": {
            "file": args.expected_challenge.name,
            "sha256": hashlib.sha256(args.expected_challenge.read_bytes()).hexdigest(),
        } if args.expected_challenge else None,
        "key_possession_verified": True,
        "device_host_decode_agrees": True,
        "signed_claims": signed,
        "root_sha256": certificates[-1].fingerprint(hashes.SHA256()).hex(),
        "manufacturer_trust": "not_established",
        "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()

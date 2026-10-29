"""Create an explicitly synthetic attestation keybox for an isolated detector experiment."""

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def certificate(subject, issuer, public_key, signing_key, *, serial, first, last, ca):
    return (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(first)
            .not_valid_after(last)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True)
            .sign(signing_key, hashes.SHA256()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.destination.exists():
        raise FileExistsError(args.destination)
    now = datetime.now(timezone.utc)
    first = now - timedelta(days=30)
    last = now + timedelta(days=730)
    top = ET.Element("AndroidAttestation")
    ET.SubElement(top, "NumberOfKeyboxes").text = "1"
    keybox = ET.SubElement(top, "Keybox", DeviceID="device-lab-experimental")
    entries = []
    for algorithm in ("ecdsa", "rsa"):
        root_key = ec.generate_private_key(ec.SECP256R1()) if algorithm == "ecdsa" else rsa.generate_private_key(65537, 2048)
        signing_key = ec.generate_private_key(ec.SECP256R1()) if algorithm == "ecdsa" else rsa.generate_private_key(65537, 2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Device Lab Test Only"),
                               x509.NameAttribute(NameOID.COMMON_NAME, f"Device Lab {algorithm.upper()} Test Root")])
        signing_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Device Lab Test Only"),
                                  x509.NameAttribute(NameOID.COMMON_NAME, f"Device Lab {algorithm.upper()} Test Intermediate")])
        root = certificate(root_name, root_name, root_key.public_key(), root_key,
                           serial=x509.random_serial_number(), first=first, last=last, ca=True)
        intermediate = certificate(signing_name, root_name, signing_key.public_key(), root_key,
                                   serial=x509.random_serial_number(), first=first, last=last, ca=True)
        intermediate.verify_directly_issued_by(root)
        root.verify_directly_issued_by(root)
        item = ET.SubElement(keybox, "Key", algorithm=algorithm)
        key = ET.SubElement(item, "PrivateKey", format="pem")
        key.text = signing_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()).decode("ascii")
        chain = ET.SubElement(item, "CertificateChain")
        ET.SubElement(chain, "NumberOfCertificates").text = "2"
        for cert in (intermediate, root):
            ET.SubElement(chain, "Certificate", format="pem").text = cert.public_bytes(
                serialization.Encoding.PEM).decode("ascii")
        root_der = root.public_bytes(serialization.Encoding.DER)
        entries.append({
            "algorithm": algorithm,
            "root_subject": root.subject.rfc4514_string(),
            "root_certificate_sha256": sha256(root_der),
            "root_public_key_sha256": sha256(root.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "intermediate_subject": intermediate.subject.rfc4514_string(),
            "valid_from": first.isoformat(),
            "valid_until": last.isoformat(),
        })
    args.destination.mkdir(parents=True)
    xml = ET.tostring(top, encoding="utf-8", xml_declaration=True)
    (args.destination / "keybox.xml").write_bytes(xml)
    (args.destination / "manifest.json").write_text(json.dumps({
        "purpose": "Isolated local detector experiment",
        "synthetic_ca": True,
        "manufacturer_trust": False,
        "hardware_trust": False,
        "target_scope": ["com.eltavine.duckdetector"],
        "keybox_sha256": sha256(xml),
        "entries": entries,
    }, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"destination": str(args.destination), "keybox_sha256": sha256(xml),
                      "manufacturer_trust": False}))


if __name__ == "__main__":
    main()

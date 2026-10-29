"""Stage a pinned x86_64 candidate using only its published software test keybox."""

import argparse
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes


ARCHIVE_SHA256 = "ef356f81c57b010618dcf29500eecdb1b01287e488c7fdba3063273d9ae76ebd"
REVISION = "dda5277d10b948ba6bec362252ec41f8bbbd9f97"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--aosp-source", type=Path, required=True)
    args = parser.parse_args()
    if digest(args.archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("Pinned CI archive hash mismatch")
    aosp_source = args.aosp_source.read_text(encoding="utf-8")
    aosp_roots = set()
    for symbol in ("kEcAttestRootCert", "kRsaAttestRootCert"):
        match = re.search(r"static const uint8_t " + symbol + r"\[\] = \{(.*?)\};", aosp_source, re.S)
        if not match:
            raise ValueError("AOSP software root declaration missing")
        der = bytes(int(value, 16) for value in re.findall(r"0x([a-fA-F0-9]{2})", match[1]))
        aosp_roots.add(x509.load_der_x509_certificate(der).fingerprint(hashes.SHA256()).hex())
    with zipfile.ZipFile(args.archive) as archive:
        files = {
            "classes.dex": archive.read("classes.dex"),
            "inject": archive.read("lib/x86_64/libinject.so"),
            "libTrickyStoreOSS.so": archive.read("lib/x86_64/libTrickyStoreOSS.so"),
            "keybox.xml": archive.read("keybox.xml"),
        }
    roots = []
    for key in ET.fromstring(files["keybox.xml"]).findall(".//Key"):
        chain = key.findall(".//Certificate")
        certificate = x509.load_pem_x509_certificate(chain[-1].text.strip().encode("ascii"))
        subject = certificate.subject.rfc4514_string()
        if certificate.fingerprint(hashes.SHA256()).hex() not in aosp_roots:
            raise ValueError("Only the published AOSP software test fixture is supported")
        roots.append({"algorithm": key.attrib["algorithm"], "subject": subject,
                      "sha256": certificate.fingerprint(hashes.SHA256()).hex()})
    dex = files["classes.dex"]
    if dex[12:32] != hashlib.sha1(dex[32:]).digest():
        raise ValueError("Original DEX signature mismatch")
    if struct.unpack_from("<I", dex, 8)[0] != zlib.adler32(dex[12:]) & 0xffffffff:
        raise ValueError("Original DEX checksum mismatch")
    old = b"/data/adb/tricky_store"
    new = b"/data/misc/tricky_lab1"
    assert len(old) == len(new)
    replacements = dex.count(old)
    if not replacements:
        raise ValueError("The pinned configuration prefix was not found")
    adapted = bytearray(dex.replace(old, new))
    adapted[12:32] = hashlib.sha1(adapted[32:]).digest()
    struct.pack_into("<I", adapted, 8, zlib.adler32(adapted[12:]) & 0xffffffff)
    files["classes.dex"] = adapted
    for name in ("inject", "libTrickyStoreOSS.so"):
        elf = files[name]
        if elf[:4] != b"\x7fELF" or elf[4] != 2 or struct.unpack_from("<H", elf, 18)[0] != 62:
            raise ValueError("Expected an x86_64 ELF candidate")
    files["target.txt"] = b"com.eltavine.duckdetector!\n"
    args.destination.mkdir()
    for name, data in files.items():
        (args.destination / name).write_bytes(data)
    manifest = {
        "repository": "https://github.com/beakthoven/TrickyStoreOSS",
        "revision": REVISION,
        "workflow_run": "https://github.com/beakthoven/TrickyStoreOSS/actions/runs/38476533465",
        "archive_sha256": ARCHIVE_SHA256,
        "aosp_software_certificate_source_sha256": digest(args.aosp_source.read_bytes()),
        "private_configuration_path": new.decode(),
        "configuration_prefix_replacements": replacements,
        "original_dex_sha256": digest(dex),
        "adapted_dex_sha256": digest(adapted),
        "dex_magic": dex[:8].decode("ascii"),
        "software_fixture_roots": roots,
        "scope": ["com.eltavine.duckdetector"],
        "hardware_trust_supplied": False,
        "installer_and_sepolicy_rules_used": False,
        "files": {name: digest(data) for name, data in files.items()},
    }
    (args.destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"destination": str(args.destination), "configuration_prefix_replacements": replacements,
                      "software_fixture_roots": roots, "hardware_trust_supplied": False}))


if __name__ == "__main__":
    main()

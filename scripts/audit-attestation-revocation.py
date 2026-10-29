"""Check captured attestation chains against a saved Google status snapshot."""

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509


STATUS_URL = "https://android.googleapis.com/attestation/status"
SERIAL_PATTERN = re.compile(r"^[a-f1-9][a-f0-9]*$")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    data = path.read_bytes()
    return json.loads(data.decode("utf-8-sig")), digest(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--status", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    status_file, status_hash = read_json(args.status)
    entries = status_file.get("entries")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("Status snapshot has no entries")
    for serial, entry in entries.items():
        if (not isinstance(serial, str) or not SERIAL_PATTERN.fullmatch(serial)
                or not isinstance(entry, dict)
                or entry.get("status") not in ("REVOKED", "SUSPENDED")):
            raise ValueError("Invalid status snapshot entry")

    checked = []
    for report_path in args.reports:
        report, report_hash = read_json(report_path)
        samples = {}
        for name in ("default_keystore", "strongbox"):
            sample = report[name]
            if sample["status"] != "complete":
                samples[name] = {"status": sample["status"], "checked": False}
                continue
            certificates = [
                x509.load_der_x509_certificate(
                    base64.b64decode(item["der_base64"], validate=True))
                for item in sample["certificates"]
            ]
            if not certificates:
                raise ValueError(f"Empty certificate chain in {report_path}: {name}")
            listed = [
                {"certificate_index": index, "serial_hex": format(cert.serial_number, "x"),
                 "status": entries[format(cert.serial_number, "x")]["status"]}
                for index, cert in enumerate(certificates)
                if format(cert.serial_number, "x") in entries
            ]
            samples[name] = {
                "status": "complete",
                "checked": True,
                "certificate_count": len(certificates),
                "listed": listed,
                "clear": not listed,
            }
        checked.append({"report": report_path.name, "report_sha256": report_hash,
                        "samples": samples})

    result = {
        "schema_version": 1,
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status_source": STATUS_URL,
        "status_snapshot_sha256": status_hash,
        "status_snapshot_entries": len(entries),
        "reports": checked,
        "all_completed_chains_clear": all(
            sample["clear"] for item in checked for sample in item["samples"].values()
            if sample["checked"]),
        "scope": "Serial-number status only. A clear result does not establish a trusted root, "
                 "valid path, nonce binding, hardware security level, or boot integrity.",
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Checked {sum(sample['checked'] for item in checked for sample in item['samples'].values())} "
          f"chains; all clear: {result['all_completed_chains_clear']}")


if __name__ == "__main__":
    main()

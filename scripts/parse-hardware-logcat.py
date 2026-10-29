"""Rebuild a hardware snapshot JSON from a Firebase Test Lab logcat capture.

SnapshotRunner (hardwareprobe androidTest) streams the report through logcat
in 3000-character chunks between BEGIN_JSON/END_JSON markers. This tool
rejoins the chunks, validates the JSON, and writes a snapshot file with the
same schema capture-hardware.ps1 produces, minus the adb-only shell section.

Usage:
    python parse-hardware-logcat.py LOGCAT.txt --model shiba --version 36 \
        --output reports/physical-shiba-api36.json [--apk-sha256 SHA256]
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TAG_LINE = re.compile(
    r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+[IWE]\s+"
    r"HardwareSnapshotReport\s*:\s?(.*)$")


def extract_chunks(logcat_text):
    """Return the joined JSON payload between the markers."""
    lines = []
    inside = False
    for raw in logcat_text.splitlines():
        match = TAG_LINE.match(raw)
        message = match.group(1) if match else (raw if inside else "")
        if match and message.strip() == "BEGIN_JSON":
            inside = True
            continue
        if match and message.strip() == "END_JSON":
            if not inside:
                raise SystemExit("END_JSON appeared before BEGIN_JSON.")
            return "\n".join(lines)
        if inside:
            lines.append(message)
    raise SystemExit("No END_JSON marker found; the snapshot did not complete.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logcat", help="logcat text file captured by Test Lab")
    parser.add_argument("--model", required=True, help="Firebase model id, e.g. shiba")
    parser.add_argument("--version", required=True, help="API level as a string, e.g. 36")
    parser.add_argument("--output", required=True, help="destination snapshot JSON")
    parser.add_argument("--apk-sha256", help="installed app APK SHA-256, when known")
    args = parser.parse_args()

    payload = extract_chunks(Path(args.logcat).read_text(encoding="utf-8", errors="replace"))
    report = json.loads(payload)
    if report.get("kind") != "hardware-snapshot" or report.get("schema_version") != 1:
        raise SystemExit("Recovered JSON is not a hardware snapshot.")

    snapshot = {
        "schema_version": 1,
        "kind": "hardware-snapshot",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "type": "firebase-test-lab-instrumentation",
            "model": args.model,
            "android_version": args.version,
        },
        "identity": report.get("identity"),
        "apk_sha256": args.apk_sha256
                      or hashlib.sha256(Path(args.logcat).read_bytes()).hexdigest(),
        "app": report,
        "shell": {"note": "not collected: instrumentation runs have no adb shell channel"},
    }
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    identity = report.get("identity", {})
    print(f"wrote {destination}")
    print(f"model={identity.get('model')} device={identity.get('device')} "
          f"sdk={identity.get('sdk')} fingerprint={identity.get('fingerprint')}")
    print(f"sensors={report.get('sensors', {}).get('count')} "
          f"cameras={report.get('cameras', {}).get('count')} "
          f"codecs={report.get('codecs', {}).get('count')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

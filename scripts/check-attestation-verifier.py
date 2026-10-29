"""Exercise the host verifier against an accepted capture and corrupted copies."""
import argparse
import base64
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-challenge", type=Path)
    args = parser.parse_args()
    original = json.loads(args.report.read_text(encoding="utf-8-sig"))
    verifier = Path(__file__).with_name("verify-attestation.py")
    cases = [("original", original, None)]

    nonce = copy.deepcopy(original)
    value = bytearray(base64.b64decode(nonce["default_keystore"]["challenge_base64"]))
    value[0] ^= 1
    nonce["default_keystore"]["challenge_base64"] = base64.b64encode(value).decode()
    cases.append(("changed_nonce", nonce, "Attestation nonce mismatch"))

    claim = copy.deepcopy(original)
    claim["default_keystore"]["attestation"]["attestation_security_level"] += 1
    cases.append(("changed_unsigned_claim", claim, "Device/host attestation decode mismatch"))

    signature = copy.deepcopy(original)
    value = bytearray(base64.b64decode(signature["default_keystore"]["signature_base64"]))
    value[-1] ^= 1
    signature["default_keystore"]["signature_base64"] = base64.b64encode(value).decode()
    cases.append(("changed_possession_signature", signature, "InvalidSignature"))

    chain = copy.deepcopy(original)
    chain["default_keystore"]["certificates"][1] = chain["default_keystore"]["certificates"][-1]
    cases.append(("replaced_issuer", chain, "Certificate issuer name mismatch"))

    results = []
    with tempfile.TemporaryDirectory(prefix="device-lab-attestation-") as directory:
        for name, report, expected in cases:
            source = Path(directory, name + ".json")
            destination = Path(directory, name + "-verified.json")
            source.write_text(json.dumps(report), encoding="utf-8")
            command = [sys.executable, str(verifier), str(source), "--output", str(destination)]
            if args.expected_challenge:
                command += ["--expected-challenge", str(args.expected_challenge)]
            completed = subprocess.run(command, capture_output=True, text=True)
            if expected is None:
                if completed.returncode != 0:
                    raise RuntimeError(completed.stderr)
                result = json.loads(destination.read_text(encoding="utf-8"))
                if result["manufacturer_trust"] != "not_established":
                    raise AssertionError("A valid software chain must not establish manufacturer trust")
            elif completed.returncode == 0 or expected not in completed.stderr or destination.exists():
                raise AssertionError(f"Corrupted evidence was not rejected correctly: {name}")
            results.append({"case": name, "passed": True, "expected": "accepted_without_manufacturer_trust" if expected is None else "rejected"})
        if args.expected_challenge:
            source = Path(directory, "replayed-report.json")
            source.write_text(json.dumps(original), encoding="utf-8")
            challenge = json.loads(args.expected_challenge.read_text(encoding="utf-8-sig"))
            value = bytearray(base64.b64decode(challenge["challenge_base64"], validate=True))
            value[0] ^= 1
            challenge["challenge_base64"] = base64.b64encode(value).decode()
            expected_path = Path(directory, "new-challenge.json")
            expected_path.write_text(json.dumps(challenge), encoding="utf-8")
            destination = Path(directory, "replayed-verified.json")
            completed = subprocess.run(
                [sys.executable, str(verifier), str(source), "--output", str(destination),
                 "--expected-challenge", str(expected_path)], capture_output=True, text=True,
            )
            if completed.returncode == 0 or "External attestation challenge mismatch" not in completed.stderr or destination.exists():
                raise AssertionError("A replayed valid report was not rejected against the new challenge")
            results.append({"case": "replayed_report_with_new_host_challenge", "passed": True, "expected": "rejected"})
    print(json.dumps({"cases": results, "passed": len(results), "failed": 0}, indent=2))


if __name__ == "__main__":
    main()

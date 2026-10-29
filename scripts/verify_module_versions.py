"""Check ELF64 module import CRCs against the matching kernel and module exports."""
import argparse
import json
import struct
from pathlib import Path


def sections(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"Expected little-endian ELF64: {path}")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    names = data[headers[strings][4]:headers[strings][4] + headers[strings][5]]
    return {names[h[0]:].split(b"\0", 1)[0].decode(): data[h[4]:h[4] + h[5]] for h in headers}


def versions(path):
    data = sections(path)["__versions"]
    if len(data) % 64:
        raise ValueError(f"Unexpected module version record size: {path}")
    return {data[i + 8:i + 64].split(b"\0", 1)[0].decode(): struct.unpack_from("<Q", data, i)[0]
            for i in range(0, len(data), 64)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modules", type=Path)
    parser.add_argument("symvers", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    exports = {}
    for path in args.symvers:
        for line in path.read_text().splitlines():
            fields = line.split()
            crc, name = int(fields[0], 16), fields[1]
            if name in exports and exports[name] != crc:
                raise ValueError(f"Conflicting export CRC: {name}")
            exports[name] = crc
    results = []
    for path in sorted(args.modules.glob("*.ko")):
        imports = versions(path)
        mismatches = {name: {"module": hex(crc), "export": hex(exports[name]) if name in exports else None}
                      for name, crc in imports.items() if exports.get(name) != crc}
        results.append({"module": path.name, "imports": len(imports), "mismatches": mismatches})
    report = {"modules": len(results), "imports": sum(r["imports"] for r in results),
              "mismatched_modules": sum(bool(r["mismatches"]) for r in results), "results": results}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "results"}))
    if not results or report["mismatched_modules"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

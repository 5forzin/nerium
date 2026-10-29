"""Compare the captured Android policy with the scoped openat2 policy prefix."""
import argparse
import json
import struct
from pathlib import Path


def evaluate(code, architecture, number):
    pc, accumulator = 0, 0
    while pc < len(code):
        op, yes, no, value = code[pc]
        if op == 0x20:
            accumulator = {0: number & 0xffffffff, 4: architecture}[value]
        elif op == 0x15:
            pc += yes if accumulator == value else no
        elif op == 0x35:
            pc += yes if accumulator >= value else no
        elif op == 0x06:
            return value
        else:
            raise ValueError(f"Unsupported BPF instruction: {op:#x}")
        pc += 1
    raise ValueError("BPF program did not return")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original, patched = args.before.read_bytes(), args.after.read_bytes()
    if patched[40:] != original:
        raise ValueError("The original BPF suffix changed")
    programs = [list(struct.iter_unpack("<HBBI", data)) for data in (original, patched)]
    differences, cases = set(), 0
    for architecture in (0xc000003e, 0x40000003, 0xc00000b7, 0):
        for number in (*range(65536), -1, 0x40000000, 0x400001b5, 0x7fffffff):
            before, after = (evaluate(program, architecture, number) for program in programs)
            cases += 1
            if before != after:
                differences.add((architecture, number, before, after))
    if differences != {(0xc000003e, 437, 0x30000, 0x7fff0000)}:
        raise ValueError(f"Unexpected policy difference: {differences}")
    if programs[0][0] != (0x20, 0, 0, 4):
        raise ValueError("The original policy must reload architecture at entry")
    report = {"original_instructions": len(programs[0]), "patched_instructions": len(programs[1]),
              "original_suffix_byte_identical": True, "evaluated_cases": cases,
              "structural_preservation": "The unchanged original program reloads arch before using the accumulator. The prefix changes no scratch registers or memory.",
              "differences": [dict(zip(("arch", "syscall", "before", "after"), row)) for row in sorted(differences)]}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

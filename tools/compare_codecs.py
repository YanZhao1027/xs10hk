#!/usr/bin/env python3
"""Compare probable codec regions in two *local* extracted Fujifilm payloads.

No device communication. No firmware bytes or copyright-protected blobs are printed.
"""
import argparse
import hashlib
from pathlib import Path

# Areas immediately surrounding the module descriptors observed in both images.
MODULES = [
    ("H.265 encoder", 0x2C40000, 0x2CA8000),
    ("H.264 encoder", 0x2CA8000, 0x2CE1000),
    ("H.264 decoder (candidate)", 0x2CE1000, 0x2CF5000),
]

def compare(left, right, start, stop, delta):
    lbytes = left[start:stop]
    rbytes = right[start + delta:stop + delta]
    if len(lbytes) != len(rbytes):
        raise ValueError("Region exceeds a file")
    first = next((i for i, (a, b) in enumerate(zip(lbytes, rbytes)) if a != b), None)
    unequal = sum(a != b for a, b in zip(lbytes, rbytes))
    return {
        "length": len(lbytes),
        "mismatch_bytes": unequal,
        "equal_pct": round(100 * (1 - unequal / len(lbytes)), 5),
        "first_diff": hex(start + first) if first is not None else None,
        "sha256_xt4": hashlib.sha256(lbytes).hexdigest(),
        "sha256_xs10": hashlib.sha256(rbytes).hexdigest(),
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xt4", type=Path)
    p.add_argument("xs10", type=Path)
    p.add_argument("--delta", type=lambda s: int(s, 0), default=0x160000)
    args = p.parse_args()
    left, right = args.xt4.read_bytes(), args.xs10.read_bytes()
    print("Comparative blocks (file offsets, not runtime addresses):")
    for name, start, stop in MODULES:
        result = compare(left, right, start, stop, args.delta)
        print(name, hex(start), hex(stop), result)
    print("Neighboring 64 KiB windows:")
    for start in range(0x2C00000, 0x2F00000, 0x10000):
        stop = start + 0x10000
        if stop + args.delta > len(right) or stop > len(left):
            break
        result = compare(left, right, start, stop, args.delta)
        print(f"0x{start:08x}: {result['equal_pct']}% equal")

if __name__ == "__main__":
    main()

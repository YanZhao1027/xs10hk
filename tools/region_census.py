#!/usr/bin/env python3
"""Offline census of large nontrivial data extents in a firmware payload.

Classifies coarse blocks as FF fill, zero fill, or data. This does NOT parse
compressed-segment headers and does NOT establish runtime memory mapping.
"""
import argparse
from pathlib import Path


def classify(chunk, threshold=0.98):
    if chunk.count(255) / len(chunk) >= threshold:
        return "ff"
    if chunk.count(0) / len(chunk) >= threshold:
        return "zero"
    return "data"


def regions(data, blocksize=4096):
    if blocksize <= 0:
        raise ValueError("blocksize must be positive")
    if not data:
        return []
    groups = []
    first = 0
    last = classify(data[:blocksize])
    for start in range(blocksize, len(data), blocksize):
        kind = classify(data[start:start + blocksize])
        if kind != last:
            groups.append((last, first, start))
            first, last = start, kind
    groups.append((last, first, len(data)))
    return groups


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("payload", type=Path)
    ap.add_argument("--blocksize", type=int, default=4096)
    ap.add_argument("--min-data-bytes", type=int, default=131072)
    args = ap.parse_args()
    d = args.payload.read_bytes()
    for kind, start, stop in regions(d, args.blocksize):
        if kind != "data" or stop - start < args.min_data_bytes:
            continue
        print(f"DATA (not necessarily compressed) 0x{start:08x}..0x{stop:08x}  size={stop - start:,} bytes")
    print("WARNING: These are statistical extents, not verified compression or RAM sections.")


if __name__ == "__main__":
    main()

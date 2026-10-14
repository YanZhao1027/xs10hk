#!/usr/bin/env python3
"""Match non-trivial equal blocks between two offline Fujifilm payloads.

Produces only file offsets and lengths. It does not derive virtual addresses,
identify executable code, or publish proprietary firmware data.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
from pathlib import Path


def interesting(block):
    if len(block) < 16:
        return False
    hist = Counter(block)
    return max(hist.values()) / len(block) < 0.80


def find_matches(left, right, blocksize=4096, min_length=65536):
    """Return maximal block-aligned identical runs, avoiding fill/padding."""
    if blocksize <= 0 or min_length <= 0:
        raise ValueError("blocksize and min_length must be positive")
    index = defaultdict(list)
    for b in range(0, len(right) - blocksize + 1, blocksize):
        data = right[b:b + blocksize]
        if interesting(data):
            index[hashlib.sha256(data).digest()].append(b)
    pairs = set()
    for a in range(0, len(left) - blocksize + 1, blocksize):
        data = left[a:a + blocksize]
        if not interesting(data):
            continue
        for b in index.get(hashlib.sha256(data).digest(), []):
            if data == right[b:b + blocksize]:
                pairs.add((a, b))
    runs = []
    for a, b in sorted(pairs):
        if (a - blocksize, b - blocksize) in pairs:
            continue
        n = 0
        while (a + n, b + n) in pairs:
            n += blocksize
        if n >= min_length:
            runs.append({"left_offset": a, "right_offset": b,
                         "delta": b - a, "length": n,
                         "block_count": n // blocksize})
    return sorted(runs, key=lambda r: -r["length"])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("left", type=Path)
    ap.add_argument("right", type=Path)
    ap.add_argument("--blocksize", type=int, default=4096)
    ap.add_argument("--min-length", type=int, default=65536)
    ap.add_argument("--top", type=int, default=30)
    args = ap.parse_args()
    result = find_matches(args.left.read_bytes(), args.right.read_bytes(),
                          args.blocksize, args.min_length)
    print("All values below are FILE OFFSETS (not runtime addresses).")
    for run in result[:args.top]:
        print("left=%#010x right=%#010x delta=%+#x identical=%d bytes (%d blocks)" %
              (run["left_offset"], run["right_offset"],run["delta"],run["length"],run["block_count"]))
    print("runs>=%d bytes: %d; trivial fill blocks excluded" % (args.min_length,len(result)))


if __name__ == "__main__":
    main()

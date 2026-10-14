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
    left_index = defaultdict(list)
    for a in range(0, len(left) - blocksize + 1, blocksize):
        data = left[a:a + blocksize]
        if interesting(data):
            left_index[hashlib.sha256(data).digest()].append(a)

    pairs = set()
    for digest, a_positions in left_index.items():
        b_positions = index.get(digest, [])
        # Unique anchors prevent repeated UI resources or microcode padding from
        # generating dozens of deceptive alternative alignments.
        if len(a_positions) != 1 or len(b_positions) != 1:
            continue
        a, b = a_positions[0], b_positions[0]
        if left[a:a + blocksize] == right[b:b + blocksize]:
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

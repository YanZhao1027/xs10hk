#!/usr/bin/env python3
"""Find selected video markers in an already extracted local firmware payload.

Host-only, read-only scanning. Matches indicate strings, NOT enabled features.
Original firmware and decoded payload must stay off public GitHub.
"""
import argparse
import json
from pathlib import Path

# Short marker names: intentionally does not publish any firmware binary/content.
MARKERS = [
    "HEVCENC", "H.265 MP Encoder", "Encoder=HEVC",
    "set-opt encode stream bitdepth: unsupported value",
    "Firmware version does not match hardware!",
    "H264", "H265", "H.264", "H.265", "H.265(HEVC)",
    "4:2:0 10bit", "4:2:2 10bit",
    "4K_59_94P_400M_16", "4K_59_94P", "_4K30FP",
    "FHD60FPS", "MOVIECROP_X110", "59.94P",
    "MOVIE MODE BIT RATE", "MOVIE MODE FRAME RATE",
    "MOVIE MODE RESOLUTION/ASPECT RATIO",
    "RAW RECORDING", "4K MOVIE OUTPUT",
]


def offsets(data, needle, limit=32):
    found = []
    pos = 0
    while len(found) < limit:
        index = data.find(needle, pos)
        if index < 0:
            break
        found.append(index)
        pos = index + len(needle)
    return found


def scan(data, markers=MARKERS):
    results = []
    for marker in markers:
        for codec in ("ascii", "utf-16-le"):
            needle = marker.encode(codec)
            matches = offsets(data, needle)
            total = data.count(needle)
            if total:
                results.append({"marker": marker, "encoding": codec,
                                "total_count": total,
                                "offsets": [hex(n) for n in matches],
                                "truncated_at": 32 if total > 32 else None})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path, help="Local decoded payload")
    parser.add_argument("--json", type=Path, help="Optional local results file")
    args = parser.parse_args()
    results = scan(args.payload.read_bytes())
    for item in results:
        print(f"{item['marker']!r} [{item['encoding']}] count={item['total_count']} "
              f"at {', '.join(item['offsets'])}")
    print(f"{len(results)} marker/encoding matches; no functionality implied")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        with args.json.open("x", encoding="utf-8") as file:
            json.dump(results, file, indent=2, ensure_ascii=False)
        print(f"Local report: {args.json}")


if __name__ == "__main__":
    main()

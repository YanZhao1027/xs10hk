#!/usr/bin/env python3
"""Compare FIVE paired movie-setting permission lists, allowing duplicate IDs.

Off-line static study, not a firmware patcher. Uses the independently
recovered X6 section-1 permission lists for X-T4 2.12 and X-S10 3.11.

Pairs determined from actual setting-read call patterns and local table IDs:
  xt4 0x3DD -> xs10 0x3F4
  xt4 0x3DF -> xs10 0x3F6
  xt4 0x3E2 -> xs10 0x3F9
  xt4 0x3E4 -> xs10 0x3FB (movie file format setting)
  xt4 0x3E5 -> xs10 0x3FC (eModeMovieCodec)
One setting may contain DUPLICATE numeric options with different flags,
so records are compared as an ORDERED sequence, preserving duplicates.
The numeric meaning of the FIRST THREE setting IDs is not yet established.
No data is modified; results prove only *generic* setting constraints.
"""
from argparse import ArgumentParser
from pathlib import Path
import struct
from codec_setting_permissions import (
    LAYOUTS, SENTINEL, parse_categories,
    parse_group_index, read_bytes, allowed,
)

PAIRS = (
    (0x3DD, 0x3F4),
    (0x3DF, 0x3F6),
    (0x3E2, 0x3F9),
    (0x3E4, 0x3FB),
    (0x3E5, 0x3FC),
)


def ordered_mode_options(blob: bytes, model: str, setting_id: int):
    layout = LAYOUTS[model]
    cats = parse_categories(blob, layout)
    catidx = cats.index(0x2D)
    index = parse_group_index(blob, layout)
    if setting_id not in index:
        raise ValueError("Setting ID absent")
    addr, meta = index[setting_id]
    if meta:
        raise ValueError("Range-format table unsupported")
    stride = 4 + ((len(cats)+3)//4)*4
    values = []
    for i in range(256):
        item = read_bytes(blob, base=layout.base,
                          addr=addr+i*stride, count=stride)
        num = struct.unpack_from("<I", item)[0]
        if num == SENTINEL:
            return values
        flag = item[4+catidx]
        values.append((num, flag))
    raise ValueError("Setting list has no terminator")


def compare(xt4: bytes, xs10: bytes):
    pairs = []
    for xtid, xsid in PAIRS:
        xt = ordered_mode_options(xt4, "xt4", xtid)
        xs = ordered_mode_options(xs10, "xs10", xsid)
        pairs.append({
            "xt4_id": xtid,
            "xs10_id": xsid,
            "xt4_rows": xt,
            "xs10_rows": xs,
            "row_count": len(xt),
            "equal": xt == xs,
        })
    return {
        "pairs": pairs,
        "all_equal": all(p["equal"] for p in pairs),
        "total_checked_rows": sum(p["row_count"] for p in pairs),
    }


def main():
    ap = ArgumentParser(description=__doc__)
    ap.add_argument("--xt4-section1", type=Path, required=True)
    ap.add_argument("--xs10-section1", type=Path, required=True)
    args = ap.parse_args()
    result = compare(args.xt4_section1.read_bytes(),
                     args.xs10_section1.read_bytes())
    for p in result["pairs"]:
        print(f"X-T4 {p['xt4_id']:#x} vs X-S10 {p['xs10_id']:#x}: "
              f"{p['row_count']} ordered values, equal={p['equal']}")
        print(" movie flag and validity per value:", [
            (value, flag, allowed(flag))
            for value, flag in p["xs10_rows"]
        ])
    print("ALL FIVE LISTS EQUAL:", result["all_equal"])
    print("TOTAL ORDERED RECORDS:", result["total_checked_rows"])
    print("Do NOT infer that an allowed menu value activates HEVC Main10 "
          "or 4K60. Meaning of three setting keys remains unknown.")


if __name__ == "__main__":
    main()

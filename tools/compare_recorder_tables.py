#!/usr/bin/env python3
"""Reconstruct X-T4 2.12 and X-S10 3.11 X6 recorder initialization LUTs.

Static read-only firmware research, NOT a video feature unlocker.
The 64-byte table at section2 provides *candidate* format parameters.
The caller filters (byte0, uint16@1, fps_enum@3, qualifier@4) and
derives width, height, bitrate and code/bit-depth-related option values.
Rows that are present in this table may be unreachable to the user UI,
rejected by the sensor/ISP, or rejected by actual VPU/recording pipeline.

These addresses are candidate Ghidra VIRTUAL ADDRESSES for the EXACT
studied public X-S10 3.11 and X-T4 2.12 firmware releases; they are
NOT the firmware file offsets, not camera-live addresses, and are not
suitable for the user's differently versioned camera.

For model-specific table entries, frame-rate enum 1..6 corresponds to
23.98, 24, 25, 29.97, 50, and 59.94 fps (verified independently in
the actual HEVC recorder code). Dimensions were recovered via actual
lookup functions: row[1] and row[2] are indices into the width and
height 5-column grids; row[2] >= 4 uses column 4.
"""
import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import struct

ROW_BYTES = 64
MAX_ENTRIES = 512
FPS_ENUM = {
    1: 23.98, 2: 24.00, 3: 25.00, 4: 29.97,
    5: 50.00, 6: 59.94,
}


@dataclass(frozen=True)
class ModelLayout:
    segment1_base: int
    segment2_base: int
    matrix_width: int
    matrix_height: int
    recorder_table: int


LAYOUTS = {
    "xt4": ModelLayout(
        0x01021000, 0x01E0F000, 0x0168BAE4, 0x0168BDC8, 0x026FDE5C,
    ),
    "xs10": ModelLayout(
        0x01021000, 0x01EAF000, 0x0171BF0C, 0x0171C1F0, 0x027A0DBC,
    ),
}


def read_at_virt(blob: bytes, base: int, addr: int, length: int) -> bytes:
    """Read only when [addr, addr + length) lies in mapped segment."""
    offset = addr - base
    if length < 0 or offset < 0 or offset + length > len(blob):
        raise ValueError(f"Out-of-range segment address 0x{addr:x}")
    return blob[offset:offset + length]


def parse_rows(section2: bytes, layout: ModelLayout):
    """Read 64-byte records, stop at explicit first-byte FF sentinel."""
    offset = layout.recorder_table - layout.segment2_base
    records = []
    keys = set()
    for i in range(MAX_ENTRIES):
        pos = offset + i * ROW_BYTES
        if pos < 0 or pos + ROW_BYTES > len(section2):
            raise ValueError("LUT missing sentinel before section boundary")
        row = section2[pos:pos + ROW_BYTES]
        if row[0] == 0xFF:
            return records, b"".join(records)
        key = (row[0], struct.unpack_from("<H", row, 1)[0],
               row[3], row[4])
        if key in keys:
            raise ValueError("Duplicate four-field recorder LUT key")
        keys.add(key)
        records.append(row)
    raise ValueError("LUT has no sentinel before record safety limit")


def derive_dimensions(section1: bytes, layout: ModelLayout, row: bytes):
    """Follow two verified 5-column 32-bit dimension lookup functions."""
    family = row[1]
    submode = min(row[2], 4)
    index = (family * 5 + submode) * 4
    w_bytes = read_at_virt(
        section1, layout.segment1_base, layout.matrix_width + index, 4)
    h_bytes = read_at_virt(
        section1, layout.segment1_base, layout.matrix_height + index, 4)
    width = struct.unpack("<I", w_bytes)[0]
    height = struct.unpack("<I", h_bytes)[0]
    if width <= 0 or height <= 0 or width > 8192 or height > 8192:
        raise ValueError("Dimension lookup did not return plausible pixels")
    return width, height


def audit_one(model: str, section1: bytes, section2: bytes,
              layouts=LAYOUTS):
    if model not in layouts:
        raise ValueError(f"Unknown model: {model}")
    layout = layouts[model]
    rows, all_bytes = parse_rows(section2, layout)
    combos = Counter()
    keys_by_dimensions = {}
    for row in rows:
        res = derive_dimensions(section1, layout, row)
        fps_enum = row[3]
        if fps_enum not in FPS_ENUM:
            raise ValueError(f"Undocumented fps enum: {fps_enum}")
        combo = (*res, fps_enum)
        combos[combo] += 1
        keys_by_dimensions.setdefault(res, set()).add(fps_enum)
    return {
        "model": model,
        "table_address": f"0x{layout.recorder_table:08x}",
        "rows": len(rows),
        "sha256_table_rows": sha256(all_bytes).hexdigest(),
        "all_rows": all_bytes,
        "fps_enum_counts": dict(sorted(Counter(r[3] for r in rows).items())),
        "dimension_counts": dict(sorted(Counter(
            derive_dimensions(section1, layout, row) for row in rows
        ).items())),
        "4k_5994_record_count": sum(count for (w, h, f), count in
                                    combos.items() if w >= 3840 and
                                    h >= 2160 and f == 6),
        "combinations": combos,
        "all_observed_dimension_fps": {
            dim: sorted(fs) for dim, fs in keys_by_dimensions.items()},
    }


def compare_models(xt4_seg1, xt4_seg2, xs10_seg1, xs10_seg2):
    xt = audit_one("xt4", xt4_seg1, xt4_seg2)
    xs = audit_one("xs10", xs10_seg1, xs10_seg2)
    return {
        "xt4": xt, "xs10": xs,
        "table_rows_identical": xt["all_rows"] == xs["all_rows"],
        "different_row_bytes": sum(a != b for a, b in zip(
            xt["all_rows"], xs["all_rows"])),
        "same_combination_counts": xt["combinations"] == xs["combinations"],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for m in ("xt4", "xs10"):
        for i in (1, 2):
            p.add_argument(f"--{m}-section{i}", required=True, type=Path)
    args = p.parse_args()
    get = lambda m, i: getattr(args, f"{m}_section{i}").read_bytes()
    result = compare_models(get("xt4", 1), get("xt4", 2),
                            get("xs10", 1), get("xs10", 2))
    for m in ("xt4", "xs10"):
        x = result[m]
        print(f"{m}: {x['rows']} rows / 64 bytes each at {x['table_address']}")
        print(f"  rows SHA256: {x['sha256_table_rows']}")
        print("  fps counts:", x["fps_enum_counts"])
        print("  dimension counts:", dict(x["dimension_counts"]))
        print("  3840/4096 x 2160 + 59.94 candidate rows:",
              x["4k_5994_record_count"])
        print("  dimension to fps codes:", x["all_observed_dimension_fps"])
    print("all rows identical:", result["table_rows_identical"])
    print("mismatching bytes:", result["different_row_bytes"])
    print("same resolution/fps key counts:", result["same_combination_counts"])
    print("CRITICAL: STATIC TABLE ENTRIES ARE NOT PROOF OF ENABLED 4K60,")
    print("H.265 MAIN10, LIVE HARDWARE CAPACITY, OR SAFE FIRMWARE PATCHES.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Decode Fujifilm movie-codec *generic setting validation* tables, offline.

This is deliberately NOT a firmware patcher.

Observed for the exact original 2.12 X-T4 and 3.11 X-S10 X6 decoded
section-1.bin main program. Ghidra recovered real setting-validity routines:
- X-T4  FUN_011222DC (+ getter FUN_011224C8), movie codec key 0x3E5
- X-S10 FUN_0114DFAC (+ getter FUN_0114E198), movie codec key 0x3FC

Each routine finds its current category in a BYTE array terminated by 0x2E,
then a configuration item in an 8-byte (setting_id, options_pointer) table,
then the proposed setting value in an array. Each value has a DWORD numeric
ID and one BYTE flag per category, padded to 4-byte alignment. A flag in
the range 1..4 passes the observed simple validity check, while flag 0
does not. The generic fallback getter privileges flags 2/4.
For the eModeMovieCodec enumeration in BOTH builds, separate Ghidra code
shows 0=H.264 and 1=H.265 (not UI resource IDs).

All addresses below are offline decoded section-1 virtual addresses for
specified firmware releases, NOT the user's camera-live addresses.
A "valid" static *generic setting value* is NOT proof that the UI exposes
it, that the recording pipeline selects it, that it will initialize, or
that HEVC Main10/4K60 is achievable. No camera I/O. No binary writing.
"""
import argparse
from dataclasses import dataclass
from pathlib import Path
import struct


@dataclass(frozen=True)
class ModelLayout:
    base: int
    categories_addr: int
    setting_index_addr: int
    codec_setting_id: int
    movie_format_id: int


LAYOUTS = {
    "xt4": ModelLayout(0x01021000, 0x014090A0, 0x014090AC,
                       0x3E5, 0x3E4),
    "xs10": ModelLayout(0x01021000, 0x0141AE54, 0x0141AE70,
                        0x3FC, 0x3FB),
}
SENTINEL = 0x7FFFFFFE


def read_bytes(blob: bytes, *, base: int, addr: int, count: int) -> bytes:
    off = addr - base
    if off < 0 or count < 0 or off + count > len(blob):
        raise ValueError(f"Missing memory at decoded address 0x{addr:08x}")
    return blob[off:off + count]


def parse_categories(blob: bytes, layout: ModelLayout) -> tuple[int, ...]:
    raw = read_bytes(blob, base=layout.base,
                     addr=layout.categories_addr, count=46)
    categories = []
    for cat in raw:
        if cat == 0x2E:
            if not categories or len(set(categories)) != len(categories):
                raise ValueError("Invalid or duplicate movie category IDs")
            return tuple(categories)
        categories.append(cat)
    raise ValueError("Movie category sentinel 0x2E absent")


def parse_group_index(blob: bytes, layout: ModelLayout) -> dict[int, tuple[int, int]]:
    """Return (setting ID -> (value-array address, high16 metadata))."""
    result = {}
    for i in range(512):
        raw = read_bytes(blob, base=layout.base,
                         addr=layout.setting_index_addr + i*8, count=8)
        item, ptr = struct.unpack("<II", raw)
        if ptr == 0:
            return result
        if item in result:
            raise ValueError(f"Duplicate setting ID {item:#x}")
        if not layout.base <= ptr < layout.base + len(blob):
            raise ValueError(f"Setting table pointer is out of range: {ptr:#x}")
        result[item] = (ptr, (item >> 16) & 0xFF)
    raise ValueError("Setting index termination missing")


def parse_options(blob: bytes, layout: ModelLayout, key: int):
    cats = parse_categories(blob, layout)
    index = parse_group_index(blob, layout)
    if key not in index:
        raise ValueError(f"Setting {key:#x} not in index")
    addr, meta = index[key]
    if meta != 0:
        raise ValueError("Range-style groups are not handled here")
    stride = 4 + ((len(cats) + 3) // 4)*4
    options = {}
    for i in range(256):
        raw = read_bytes(blob, base=layout.base,
                         addr=addr+i*stride, count=stride)
        value = struct.unpack_from("<I", raw, 0)[0]
        if value == SENTINEL:
            if not options:
                raise ValueError("Empty setting options")
            return cats, options, stride, addr
        if value in options:
            raise ValueError("Duplicate numeric option")
        options[value] = tuple(raw[4:4 + len(cats)])
    raise ValueError("Option list termination missing")


def allowed(flag: int) -> bool:
    if not 0 <= flag <= 255:
        raise ValueError("Option flag out of byte range")
    return ((flag - 1) & 0xFF) < 4


def preferred(flag: int) -> bool:
    """Observed generic getter accepts 2 or 4 as preferred/fallback."""
    if not 0 <= flag <= 255:
        raise ValueError("Option flag out of byte range")
    return ((flag - 2) & 0xFD) == 0


def analyze(blob: bytes, model: str):
    if model not in LAYOUTS:
        raise ValueError(f"Unsupported model/version: {model}")
    layout = LAYOUTS[model]
    cats, options, stride, address = parse_options(
        blob, layout, layout.codec_setting_id)
    if 0x2D not in cats or 0 not in options or 1 not in options:
        raise ValueError("Required movie category/codec value absent")
    idx = cats.index(0x2D)
    return {
        "model": model,
        "setting_key": layout.codec_setting_id,
        "options_virtual_address": address,
        "number_of_categories": len(cats),
        "movie_category": 0x2D,
        "movie_category_index": idx,
        "option_stride": stride,
        "option_flags": {
            num: {
                "movie_mode_flag": flags[idx],
                "passes_generic_validation": allowed(flags[idx]),
                "is_generic_fallback": preferred(flags[idx]),
                "other_category_nonzero_flags": sum(
                    f != 0 for i, f in enumerate(flags) if i != idx),
            }
            for num, flags in sorted(options.items())
        },
        "caveat": (
            "A true generic validation result does NOT demonstrate that "
            "the model can internally record H.265 Main10 or 4K60."
        ),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--xt4-section1", type=Path, required=True)
    p.add_argument("--xs10-section1", type=Path, required=True)
    opt = p.parse_args()
    for model, path in (("xt4", opt.xt4_section1), ("xs10", opt.xs10_section1)):
        info = analyze(path.read_bytes(), model)
        print(f"{model} {info['setting_key']:#x}: categories="
              f"{info['number_of_categories']} movie_cat_idx="
              f"{info['movie_category_index']} option_stride="
              f"{info['option_stride']} table={info['options_virtual_address']:#x}")
        for value, flags in info["option_flags"].items():
            name = {0: "H.264", 1: "H.265"}.get(value, "UNKNOWN")
            print(" ", name, value, flags)
    print("Static generic setting validation is NOT proof of HEVC Main10 "
          "activation, 4K60 capability, or a safe firmware patch.")


if __name__ == "__main__":
    main()

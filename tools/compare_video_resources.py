#!/usr/bin/env python3
"""Offline X-S10/X-T4 video-resource comparison on DECOMPRESSED X6 sections.

Use with X-S10 3.11 and X-T4 2.12 section-1/section-2 files. For these
specific releases the candidate memory bases are independently supported by
four ARM entrypoint checks:
    X-S10 seg2 = 0x01EAF000; X-T4 seg2 = 0x01E0F000.

The UI resource registry is a lookup from option *names* to numeric IDs.
Presence of a name/ID DOES NOT prove an option is enabled or usable.
Only reports summary metadata; never includes or modifies whole firmware.
"""
import argparse
from pathlib import Path
import re
import struct

XS10_SECTION2_BASE = 0x01EAF000
XT4_SECTION2_BASE = 0x01E0F000
MODE_NAME_RE = re.compile(rb"UI_MOVIE_MODE_[A-Z0-9_]+(?=\x00)")
CODEC_NAMES = (
    b"UI_MOVIE_CODEC_H265", b"UI_MOVIE_CODEC_H264",
    b"UI_MOVIE_MOV_H265", b"UI_MOVIE_MOV_H264",
    b"UI_MOVIE_MP4_H265", b"UI_MOVIE_MP4_H264",
)


class ResourceFormatError(ValueError):
    pass


def locate_exact_pointer(data: bytes, address: int):
    """Return all offsets of 32-bit little-endian absolute pointer values."""
    if not 0 <= address <= 0xFFFFFFFF:
        raise ResourceFormatError("32-bit absolute address out of range")
    needle = struct.pack("<I", address)
    hits = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        hits.append(pos)
        pos += 1
    return hits


def parse_registry(data: bytes, base: int):
    """Return mode + codec IDs from string pointer pairs in X6 segment 2."""
    results = {}
    entries = [(match.group(), match.start()) for match in
               MODE_NAME_RE.finditer(data)]
    for token in CODEC_NAMES:
        pos = data.find(token + b"\x00")
        if pos >= 0:
            entries.append((token, pos))

    for raw_name, string_offset in entries:
        name = raw_name.decode("ascii")
        if name in results:
            raise ResourceFormatError("Duplicate movie resource name: " + name)
        pointers = locate_exact_pointer(data, base + string_offset)
        if len(pointers) != 1:
            raise ResourceFormatError(
                f"{name}: expected one table pointer, found {len(pointers)}"
            )
        pointer_offset = pointers[0]
        if pointer_offset & 3 or pointer_offset + 8 > len(data):
            raise ResourceFormatError(f"{name}: misaligned/truncated table pair")
        numeric_id = struct.unpack_from("<I", data, pointer_offset + 4)[0]
        if numeric_id > 0xFFFF:
            raise ResourceFormatError(f"{name}: unreasonable ID {numeric_id}")
        results[name] = numeric_id
    return results


def fileformat_resource_ids(section1: bytes):
    """Collect filename/codec menu resource names, not ordinary prose."""
    output = set()
    for part in section1.split(b"\x00"):
        if (part.startswith(b"MSG_") and b"FILEFORMAT" in part
                and (b"H265" in part or b"H264" in part)
                and re.fullmatch(rb"[A-Z0-9_]+", part)):
            output.add(part.decode("ascii"))
    return output


def compare(xs10_1: bytes, xs10_2: bytes, xt4_1: bytes, xt4_2: bytes):
    xs_ui = parse_registry(xs10_2, XS10_SECTION2_BASE)
    xt_ui = parse_registry(xt4_2, XT4_SECTION2_BASE)
    xs_fileformat = fileformat_resource_ids(xs10_1)
    xt_fileformat = fileformat_resource_ids(xt4_1)
    only_xs = sorted(xs_fileformat - xt_fileformat)
    only_xt = sorted(xt_fileformat - xs_fileformat)
    common = sorted(set(xs_ui) & set(xt_ui))
    differing = {key: (xs_ui[key], xt_ui[key]) for key in common
                 if xs_ui[key] != xt_ui[key]}
    return {
        "xs_mode_count": sum(k.startswith("UI_MOVIE_MODE_") for k in xs_ui),
        "xt_mode_count": sum(k.startswith("UI_MOVIE_MODE_") for k in xt_ui),
        "mode_id_mismatches": {
            key: pair for key, pair in differing.items()
            if key.startswith("UI_MOVIE_MODE_")
        },
        "mode_names_only_xs": sorted(
            key for key in xs_ui.keys() - xt_ui.keys()
            if key.startswith("UI_MOVIE_MODE_")
        ),
        "mode_names_only_xt": sorted(
            key for key in xt_ui.keys() - xs_ui.keys()
            if key.startswith("UI_MOVIE_MODE_")
        ),
        "mode_4k5994_counts": (
            sum("4K_59_94P" in k for k in xs_ui),
            sum("4K_59_94P" in k for k in xt_ui)
        ),
        "mode_4k5000_counts": (
            sum("4K_50_00P" in k for k in xs_ui),
            sum("4K_50_00P" in k for k in xt_ui)
        ),
        "codec_registry_xs": {k: xs_ui[k] for k in sorted(xs_ui)
                              if k in {v.decode() for v in CODEC_NAMES}},
        "codec_registry_xt": {k: xt_ui[k] for k in sorted(xt_ui)
                              if k in {v.decode() for v in CODEC_NAMES}},
        "fileformat_common": sorted(xs_fileformat & xt_fileformat),
        "fileformat_xs_only": only_xs,
        "fileformat_xt_only": only_xt,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--xs10-dir", type=Path, required=True,
                   help="Private directory with decoded section-1.bin / section-2.bin")
    p.add_argument("--xt4-dir", type=Path, required=True)
    args = p.parse_args()
    result = compare(
        (args.xs10_dir / "section-1.bin").read_bytes(),
        (args.xs10_dir / "section-2.bin").read_bytes(),
        (args.xt4_dir / "section-1.bin").read_bytes(),
        (args.xt4_dir / "section-2.bin").read_bytes(),
    )
    print("Movie mode registry: X-S10", result["xs_mode_count"],
          "X-T4", result["xt_mode_count"])
    print("4K59.94 names (not usable-mode counts):", result["mode_4k5994_counts"])
    print("4K50.00 names (not usable-mode counts):", result["mode_4k5000_counts"])
    print("Mode names only X-S10:", result["mode_names_only_xs"])
    print("Mode names only X-T4:", result["mode_names_only_xt"])
    print("Mode ID mismatches:", result["mode_id_mismatches"])
    print("Codec UI IDs X-S10:", result["codec_registry_xs"])
    print("Codec UI IDs X-T4:", result["codec_registry_xt"])
    print("H.264/265 FILEFORMAT strings only X-S10:",
          result["fileformat_xs_only"])
    print("H.264/265 FILEFORMAT strings only X-T4:",
          result["fileformat_xt_only"])
    print("Only compares resources: available recording formats and 10-bit")
    print("codec initialization must be established by separate code analysis.")


if __name__ == "__main__":
    main()

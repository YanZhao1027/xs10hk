#!/usr/bin/env python3
"""Offline proof of X6 ARM cross-segment BL calls to HEVC parameter wrapper.

On X-T3 5.11, X-T4 2.12, X-S10 3.11, the recording task is in decoded X6
section 2, while the H.265 driver wrapper is in section 1. Importing these
into SEPARATE Ghidra databases hides their direct BL cross references.

This scanner independently decodes ARM32 A32 BL (branch-with-link) immediates
to find direct calls to a *specific known target*. Result was then confirmed
by Ghidra ARM disassembly. It makes no claims about runtime call reachability,
effective HEVC profile or firmware safety; performs zero writes or USB I/O.

Usage: python3 tools/x6_cross_segment_calls.py --model xs10 \\
  --section1 output/x6-xs10/section-1.bin \\
  --section2 output/x6-xs10/section-2.bin
"""
import argparse
from pathlib import Path
import struct

MODEL_BASES = {
    "xt3": (0x00F21000, 0x01B4E000, 0x01096B44),
    "xt4": (0x01021000, 0x01E0F000, 0x011CAB08),
    "xs10": (0x01021000, 0x01EAF000, 0x011F745C),
}


def a32_bl_target(word: int, pc: int):
    """Return A32 BL target if 32-bit instruction has non-1111 condition."""
    if not 0 <= word <= 0xFFFFFFFF or not 0 <= pc <= 0xFFFFFFFF:
        raise ValueError("ARM instruction word/PC outside 32-bit range")
    if word & 0x0F000000 != 0x0B000000 or word >> 28 == 0xF:
        return None
    imm24 = word & 0x00FFFFFF
    if imm24 & 0x800000:
        imm24 -= 0x1000000
    return (pc + 8 + imm24 * 4) & 0xFFFFFFFF


def find_direct_bl_calls(section2: bytes, *, section2_base: int,
                         target: int):
    """Find A32 BL opcodes that directly branch to a given virtual address."""
    results = []
    length = len(section2) & ~3
    for offset, (word,) in enumerate(
        struct.iter_unpack("<I", section2[:length])
    ):
        pc = section2_base + offset * 4
        if a32_bl_target(word, pc) == target:
            results.append(pc)
    return results


def check_x6_load_base(section: bytes, expected_base: int):
    """Validate the observed little-endian candidate X6 loader header."""
    if len(section) < 32:
        raise ValueError("Truncated decoded X6 segment")
    blank, base, _, _, _, _, _, mark = struct.unpack_from("<8I", section)
    if blank != 0 or base != expected_base or mark != 0xAAAAFFFF:
        raise ValueError("Unexpected decoded X6 loader base/marker")


def analyze_model(model: str, section1: bytes, section2: bytes):
    if model not in MODEL_BASES:
        raise ValueError("Unsupported fixed research build")
    base1, base2, wrapper = MODEL_BASES[model]
    check_x6_load_base(section1, base1)
    check_x6_load_base(section2, base2)
    if not base1 <= wrapper < base1 + len(section1):
        raise ValueError("HEVC wrapper address outside section 1")
    sites = find_direct_bl_calls(
        section2, section2_base=base2, target=wrapper)
    return {"model": model,
            "hevc_driver_wrapper": f"0x{wrapper:08x}",
            "recorder_call_sites": [f"0x{addr:08x}" for addr in sites],
            "number_of_matching_bl": len(sites)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", choices=MODEL_BASES, required=True)
    p.add_argument("--section1", type=Path, required=True)
    p.add_argument("--section2", type=Path, required=True)
    args = p.parse_args()
    result = analyze_model(
        args.model, args.section1.read_bytes(), args.section2.read_bytes())
    print(result)
    print("Observed ARM calls are STATIC evidence, not proof a particular")
    print("movie mode is enabled or any camera has been modified.")


if __name__ == "__main__":
    main()

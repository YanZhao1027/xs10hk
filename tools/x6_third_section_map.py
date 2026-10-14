#!/usr/bin/env python3
"""Validate the extra executable X6 section-3 in X-T4 and X-S10 (offline).

These two vendor decompressed images have an unusual 8-byte preamble:
    +0x00: little-endian first ARM function address, a *candidate* entry
    +0x04: zero
    +0x08: ARM function prologue
Therefore, a candidate Ghidra flat loader base is entry - 8.
The first function at +8 includes an A32 BL at +0x80 (for these exact
firmwares); following that branch must land on a further ARM prologue
inside the same decoded image. This checks more than an arbitrary pointer
looking plausible but does NOT establish complete runtime mapping, overlays,
device-level reachability, bit depth or video capability.

NEVER run on a camera. Only local, private decoded section-3 files.
"""
from argparse import ArgumentParser
from hashlib import sha256
from pathlib import Path
import struct


def decode_arm_bl(word: int, pc: int) -> int:
    if word & 0x0F000000 != 0x0B000000 or word >> 28 == 0xF:
        raise ValueError("Not an A32 branch-with-link instruction")
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return (pc + 8 + (imm << 2)) & 0xFFFFFFFF


def is_arm_push(word: int) -> bool:
    return word & 0xFFFF0000 == 0xE92D0000


def analyze(blob: bytes):
    if len(blob) < 0x100 or len(blob) % 4 != 0:
        raise ValueError("Too short or unaligned for observed third section")
    first, zero, prologue, frame = struct.unpack_from("<4I", blob)
    if zero != 0 or not is_arm_push(prologue) or frame != 0xE28DB004:
        raise ValueError("Unexpected section-3 entry metadata/prologue")
    base = first - 8
    if base < 0 or base % 4 != 0:
        raise ValueError("Cannot derive aligned candidate base")
    pc = base + 0x80
    call = struct.unpack_from("<I", blob, 0x80)[0]
    target = decode_arm_bl(call, pc)
    offset = target - base
    if offset < 8 or offset > len(blob) - 8 or offset % 4:
        raise ValueError("Internal BL target outside third-section bounds")
    target_code = struct.unpack_from("<I", blob, offset)[0]
    if not is_arm_push(target_code):
        raise ValueError("Internal BL does not land on ARM push prologue")
    return {
        "candidate_load_base": base,
        "candidate_entry": first,
        "entry_prologue": f"0x{prologue:08x}",
        "inner_call_site": pc,
        "inner_call_target": target,
        "inner_target_prologue": f"0x{target_code:08x}",
        "section_bytes": len(blob),
        "sha256": sha256(blob).hexdigest(),
        "warning": (
            "A correct local map does NOT prove later sections are contiguous "
            "or all addresses contain runtime code; data/overlays are present."
        )
    }


def main():
    ap = ArgumentParser(description=__doc__)
    ap.add_argument("section3", type=Path,
                    help="Local, private, X6 LZ77 decoded section-3.bin")
    a = ap.parse_args()
    result = analyze(a.section3.read_bytes())
    for k, v in result.items():
        print(f"{k}: {hex(v) if k.endswith('base') or k.endswith('entry') or k in ('inner_call_site','inner_call_target') else v}")


if __name__ == "__main__":
    main()

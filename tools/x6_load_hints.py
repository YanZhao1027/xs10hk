#!/usr/bin/env python3
"""Inspect likely loader metadata in decoded X6 sections 1 and 2.

Observed for X-S10 v3.11 and X-T4 v2.12:
  +0x00: uint32 = 0
  +0x04: uint32 = probable RAM load base
  +0x08: uint32 = unpacked size rounded up to 4096
  +0x0c: uint32 = probable entry function address
  +0x10/+0x14/+0x18: uint32 = 0
  +0x1c: uint32 = 0xAAAAFFFF

Four independent images have an entry pointer which lands exactly on
a conventional ARM push + frame-pointer setup in the matching decoded blob.
This is evidence for a probable layout, not direct proof of runtime mapping.

No USB/firmware updater access and no firmware modification.
"""
import argparse
from pathlib import Path
import struct

HEADER_WORDS = 8
PAGE_ALIGN = 0x1000
SENTINEL = 0xAAAAFFFF


def interpret_loader_header(decoded: bytes):
    if len(decoded) < 32:
        raise ValueError("Too short for candidate X6 loader header")
    words = struct.unpack_from("<8I", decoded)
    blank, base, rounded, entry, r4, r5, r6, sentinel = words
    actual_rounded = (len(decoded) + PAGE_ALIGN - 1) // PAGE_ALIGN * PAGE_ALIGN
    if (blank, r4, r5, r6, sentinel) != (0, 0, 0, 0, SENTINEL):
        raise ValueError("Expected candidate X6 loader header signature absent")
    if base % PAGE_ALIGN or rounded != actual_rounded or entry % 4:
        raise ValueError("Bad alignment or unpacked extent; cannot infer mapping")
    if not base <= entry <= base + len(decoded) - 8:
        raise ValueError("Candidate entry address outside mapped section")
    entry_offset = entry - base
    prologue, frame = struct.unpack_from("<2I", decoded, entry_offset)
    # 0xE92D4... = ARM STMDB SP!, {..., LR}; 0xE28DB0... = ADD FP, SP, #...
    looks_like_arm_function = (
        prologue & 0xFFFF0000 == 0xE92D0000
        and frame & 0xFFFFF000 == 0xE28DB000
    )
    return {
        "base_candidate": base,
        "mapped_size_candidate": rounded,
        "entry_candidate": entry,
        "entry_file_offset": entry_offset,
        "arm_prologue_at_entry": looks_like_arm_function,
        "arm_words": (prologue, frame),
    }


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("decoded", nargs="+", type=Path,
                     help="Private uncompressed section-1/section-2 binaries")
    opts = arg.parse_args()
    for path in opts.decoded:
        try:
            info = interpret_loader_header(path.read_bytes())
        except ValueError as exc:
            print(f"{path.name}: no validated candidate ({exc})")
            continue
        print(f"{path.name}: base=0x{info['base_candidate']:08x} "
              f"memory_size=0x{info['mapped_size_candidate']:x} "
              f"entry=0x{info['entry_candidate']:08x} "
              f"file_offset=0x{info['entry_file_offset']:x} "
              f"ARM_prologue={info['arm_prologue_at_entry']}")
    print("These are evidence-backed candidates, not verified live RAM addresses.")


if __name__ == "__main__":
    main()

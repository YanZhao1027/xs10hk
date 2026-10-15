#!/usr/bin/env python3
"""Conservative offline A32 candidate scanner for Fuji Recorder profile headers.

It finds *static candidates* to write descriptor pointer fields (+0x0c,
+0x10, +0x14), including some register-computed addresses and copy-like
calls. It does not resolve heap aliases or other processors and does not
prove runtime execution. It never communicates with a camera or modifies
any firmware file. Original binaries stay in a private, ignored directory.

Expected layout on the authorized Ubuntu (per the completed Phase27 audit):
    output/x6-xs10/section-{1,2}.bin
    output/x6-xt4/section-{1,2}.bin

Usage:
    python3 tools/scan_profile_header_writes_stage28.py --output output
    python3 tools/scan_profile_header_writes_stage28.py --output output \
        --json-report output/stage28_header_candidates.json

This scanner deliberately has a narrow instruction vocabulary and no CFG:
its results require independent Ghidra function and raw-A32 review. Absence
of candidates NEVER proves an address lacks a writer (memcpy/alias/DMA).
"""
from __future__ import annotations

from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json
import struct
from typing import Iterator, Optional, Sequence

SECTION1_BASE = 0x01021000
MAX_SPAN = 0x100000


@dataclass(frozen=True)
class Spec:
    model: str
    section2_base: int
    descriptor: int
    primary_slot: int
    secondary_slot: int
    slot_control_site: int
    known_copy_helper: int


SPECS = (
    Spec("xs10", 0x01eaf000, 0x02d987e8, 0x02d9c2ac,
         0x02d9c2b0, 0x0221477c, 0x012a9148),
    Spec("xt4", 0x01e0f000, 0x02d0bf48, 0x02d0fa0c,
         0x02d0fa10, 0x02180d50, 0x01281848),
)


@dataclass(frozen=True)
class Region:
    label: str
    address: int
    width: int = 4


@dataclass(frozen=True)
class Event:
    model: str
    section: str
    instruction: int
    kind: str
    target: int
    width: int
    overlaps: tuple[str, ...]
    source_class: str
    callee: Optional[int] = None
    input_value_proven: bool = False
    runtime_executed: bool = False

    def serializable(self):
        return {
            "model": self.model,
            "section": self.section,
            "instruction": f"0x{self.instruction:08x}",
            "kind": self.kind,
            "target": f"0x{self.target:08x}",
            "width": self.width,
            "overlaps": list(self.overlaps),
            "source_class": self.source_class,
            "callee": None if self.callee is None else f"0x{self.callee:08x}",
            "input_value_proven": self.input_value_proven,
            "runtime_executed": self.runtime_executed,
        }


def regions(spec: Spec) -> tuple[Region, ...]:
    return (
        Region("descriptor_object_pointer", spec.descriptor + 0x0c),
        Region("descriptor_primary_buffer_pointer", spec.descriptor + 0x10),
        Region("descriptor_secondary_buffer_pointer", spec.descriptor + 0x14),
        Region("runtime_primary_pointer_slot", spec.primary_slot),
        Region("runtime_secondary_pointer_slot", spec.secondary_slot),
    )


def overlap_labels(regs: Sequence[Region], addr: int, length: int):
    if length <= 0:
        return ()
    return tuple(r.label for r in regs if addr < r.address+r.width
                 and r.address < addr+length)


def rotate_imm12(word: int) -> int:
    imm = word & 0xff
    rot = ((word >> 8) & 0xf) * 2
    if rot == 0:
        return imm
    return ((imm >> rot) | (imm << (32 - rot))) & 0xffffffff


def decode_mov_half(word: int):
    if (word >> 28) != 14:
        return None
    opcode = word & 0x0ff00000
    if opcode not in (0x03000000, 0x03400000):
        return None
    high = opcode == 0x03400000
    reg = (word >> 12) & 15
    imm = (((word >> 16) & 15) << 12) | (word & 0xfff)
    return high, reg, imm


def decode_branch(word: int, at: int):
    if ((word >> 25) & 7) != 5:
        return None
    signed = word & 0xffffff
    if signed & 0x800000:
        signed -= 0x1000000
    target = (at + 8 + (signed << 2)) & 0xffffffff
    return (word >> 28, bool((word >> 24) & 1), target)


def decode_single_memory(word: int):
    """ARM immediate pre-indexed positive/negative LDR/STR or byte variant.

    Returns (load, base_register, data_register, signed_offset, width).
    Other modes (register offset, writeback, post-index) are NOT covered.
    """
    if ((word >> 26) & 3) != 1 or ((word >> 25) & 1) or not ((word >> 24) & 1):
        return None
    if (word >> 21) & 1:
        return None
    offset = word & 0xfff
    if not ((word >> 23) & 1):
        offset = -offset
    return (bool((word >> 20) & 1), (word >> 16) & 15,
            (word >> 12) & 15, offset, 1 if ((word >> 22) & 1) else 4)


def decode_halfword_store(word: int):
    """Subset: preindexed immediate ARM STRH, without writeback."""
    if ((word >> 25) & 7) != 0 or not ((word >> 24) & 1) or (word >> 21) & 1:
        return None
    if not ((word >> 22) & 1) or (word >> 20) & 1:
        return None
    if (word & 0xf0) != 0xb0:
        return None
    offset = (((word >> 8) & 0xf) << 4) | (word & 0xf)
    if not ((word >> 23) & 1):
        offset = -offset
    return ((word >> 16) & 15, (word >> 12) & 15, offset)


def decode_dp(word: int):
    """Subset of A32 integer data processing; effects on destination reg."""
    if ((word >> 26) & 3) != 0:
        return None
    op = (word >> 21) & 15
    reg = (word >> 12) & 15
    rn = (word >> 16) & 15
    has_imm = bool((word >> 25) & 1)
    # CMP/TST/TEQ/CMN do not write a GPR. Exclude unusual opcodes by caller.
    if op in (8, 9, 10, 11):
        return ("test", None, None, None)
    if not has_imm and (word & 0xff0) != 0:
        return ("unknown", reg, None, None)
    value = rotate_imm12(word) if has_imm else (word & 15)
    if op in (13, 4, 2, 0, 1, 12, 14):
        return (op, reg, rn, (has_imm, value))
    return ("unknown", reg, None, None)


def memory_word(sections: Sequence[tuple[str, int, bytes]], addr: int):
    for _, base, data in sections:
        idx = addr - base
        if idx >= 0 and idx + 4 <= len(data) and idx % 4 == 0:
            return struct.unpack_from("<I", data, idx)[0]
    return None


class State:
    def __init__(self):
        self.reg: list[Optional[int]] = [None]*16
        self.low: list[Optional[int]] = [None]*16
        self.origin: list[str] = ["unknown"]*16

    def clear(self):
        self.reg = [None]*16
        self.low = [None]*16
        self.origin = ["unknown"]*16

    def put(self, r: int, value: Optional[int], origin="unknown"):
        self.reg[r] = None if value is None else value & 0xffffffff
        self.low[r] = None if value is None else (value & 0xffff)
        self.origin[r] = origin if value is not None else "unknown"

    def invalidate_unknown_instruction(self, word: int):
        # When unsure which registers an instruction changes, clear *all*
        # provenance. Conservative = lost findings rather than false links.
        self.clear()


def scan_section(spec: Spec, section_name: str, base: int, data: bytes,
                 image: Sequence[tuple[str, int, bytes]]) -> list[Event]:
    regs = regions(spec)
    state = State()
    events = []
    for off in range(0, len(data)-3, 4):
        word = struct.unpack_from("<I", data, off)[0]
        at = base + off
        cond = word >> 28
        if cond != 14:
            # Conditional writes and branches require a CFG/path split;
            # resetting avoids spuriously carrying constants across paths.
            state.clear()
            continue
        half = decode_mov_half(word)
        if half is not None:
            high, r, value = half
            if high:
                lo = state.low[r]
                state.put(r, ((value << 16) | lo) if lo is not None else None,
                          "MOVW/MOVT" if lo is not None else "unknown")
            else:
                state.put(r, value, "MOVW")
            continue

        branch = decode_branch(word, at)
        if branch is not None:
            _, link, callee = branch
            if link and state.reg[0] is not None:
                dest = state.reg[0]
                n = state.reg[2]
                labels = overlap_labels(regs, dest, n) if n is not None and 0 < n <= MAX_SPAN else ()
                if labels:
                    kind = ("known_copy_helper_call" if callee == spec.known_copy_helper
                            else "unverified_copy_like_call")
                    events.append(Event(spec.model, section_name, at, kind, dest, n,
                                        labels, state.origin[0], callee))
            state.clear()
            continue

        mem = decode_single_memory(word)
        if mem is not None:
            load, rn, rd, imm, width = mem
            if rn == 15:
                target = (at+8+imm) & 0xffffffff
            elif state.reg[rn] is not None:
                target = (state.reg[rn]+imm)&0xffffffff
            else:
                target = None
            if target is not None:
                labels = overlap_labels(regs, target, width)
                if labels:
                    events.append(Event(spec.model, section_name, at,
                                        ("LDRB" if load and width == 1 else
                                         "LDR" if load else
                                         "STRB" if width == 1 else "STR"),
                                        target, width, labels,
                                        "PC" if rn == 15 else state.origin[rn]))
            if load:
                # Only literal LDR from original read-only firmware has a
                # fully known contents. Loads from RAM are never assumed.
                if width == 4 and rn == 15 and target is not None:
                    value = memory_word(image, target)
                    state.put(rd, value, "PC_LITERAL" if value is not None else "unknown")
                else:
                    state.put(rd, None)
            continue

        half_store = decode_halfword_store(word)
        if half_store is not None:
            rn, rd, imm = half_store
            if state.reg[rn] is not None:
                target = (state.reg[rn]+imm)&0xffffffff
                labels = overlap_labels(regs, target, 2)
                if labels:
                    events.append(Event(spec.model, section_name, at,
                                        "STRH", target, 2, labels, state.origin[rn]))
            continue

        dp = decode_dp(word)
        if dp is not None:
            op, rd, rn, val_tuple = dp
            if op == "test":
                continue
            if op == "unknown":
                state.put(rd, None)
                continue
            immediate, val = val_tuple
            rhs = val if immediate else state.reg[val]
            lhs = (at + 8) if rn == 15 else state.reg[rn]
            if op == 13:  # MOV
                state.put(rd, rhs, "MOV_imm_or_reg")
            elif lhs is not None and rhs is not None:
                operation = {4:lambda a,b:a+b, 2:lambda a,b:a-b,
                             0:lambda a,b:a&b, 1:lambda a,b:a^b,
                             12:lambda a,b:a|b, 14:lambda a,b:a&~b}[op]
                state.put(rd, operation(lhs,rhs), "computed_A32")
            else:
                state.put(rd, None)
            continue
        state.invalidate_unknown_instruction(word)
    return events


def scan_model(spec: Spec, output: Path):
    image = []
    for label, base in (("section-1", SECTION1_BASE),
                        ("section-2", spec.section2_base)):
        path = output / f"x6-{spec.model}/{label}.bin"
        image.append((label, base, path.read_bytes()))
    events = []
    for label, base, data in image:
        events.extend(scan_section(spec, label, base, data, image))
    control = [e for e in events if e.instruction == spec.slot_control_site
               and e.kind == "STR" and
               "runtime_primary_pointer_slot" in e.overlaps]
    if not control:
        raise RuntimeError(f"{spec.model}: known Phase27 pointer-slot STR control missing; "
                           "scanner cannot be trusted on this image/version")
    descriptor_writes = [e for e in events if e.kind in
                         ("STR", "STRB", "STRH", "known_copy_helper_call",
                          "unverified_copy_like_call") and
                         any(x.startswith("descriptor_") for x in e.overlaps)]
    result = {
        "model": spec.model,
        "phase27_primary_slot_positive_control": True,
        "source_descriptor": f"0x{spec.descriptor:08x}",
        "descriptor_header_write_candidates": [e.serializable() for e in descriptor_writes],
        "descriptor_header_candidate_count": len(descriptor_writes),
        "all_static_target_events_count": len(events),
        "status": "CANDIDATES_ONLY_NOT_EXECUTION_PROOF",
        "static_scan_exhaustive_for_indirect_writes": False,
        "dynamic_primary_buffer_address_known": False,
        "current_buffer_codec_value_known": False,
        "gui_to_recorder_config_link_proven": False,
        "main10_internal_recording_proven": False,
        "4k60_internal_recording_proven": False,
        "camera_modified": False,
    }
    return result


def main():
    p = ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("output"))
    p.add_argument("--json-report", type=Path, default=None)
    args = p.parse_args()
    result = {"stage": 28,
              "evidence_class": "static_candidate_scan_only",
              "models": [scan_model(s,args.output) for s in SPECS]}
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.json_report is not None:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(text + "\n", encoding="utf-8")
    print("OFFLINE ONLY: descriptor candidate scan, not codec-source proof.")


if __name__ == "__main__":
    main()

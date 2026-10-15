#!/usr/bin/env python3
"""Offline Fujifilm X-S10 vs X-T4 MOVIE codec/menu mapper comparison.

Uses PRIVATE, locally extracted X6 Section 1 and 2 binaries, NEVER camera
I/O, EEPROM, FF80, image writing, or a firmware patch.

The 336-byte ARM mapper
  X-S10 FUN_0114DC2C / X-T4 FUN_01121F5C
uses a per-setting pointer-indexed array of (uint32, uint32, uint32,
uint32) records, terminated by four 0xFFFF values. When called with
r2=0 and r3=3, it converts selected row index r1 to field 3 (word[2]).
The returned 8-bit value is passed to eModeMovieCodec setter.

The UI dispatch code in X-S10 and X-T4 has a real ARM A32
   MOV r3,#3; MOV r2,#0; MOV r1,r5; MOV(W) r0,#codec_setting
   BL value_converter; UXTB r0,r0; BL eModeMovieCodec_setter
sequence, also independently checked below.

The ROWS are NOT evidence that those options are *visible* or reachable
in an X-S10 normal menu, nor that the separate recorder's snapshot
+0x5B0 field can receive value 1. Main10/4K60 recording is unverified.
All address constants refer ONLY to X-S10 3.11 / X-T4 2.12 firmware.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import hashlib
import struct


@dataclass(frozen=True)
class ROMLayout:
    name: str
    section1_base: int
    section2_base: int
    pointer_index_base: int
    codec_id: int
    converter_bl_site: int
    converter_entry: int
    setter_entry: int


LAYOUTS = {
    "xt4": ROMLayout("xt4", 0x01021000, 0x01E0F000, 0x01700694,
                     0x3E5, 0x02057E74, 0x01022F7C, 0x0112FD80),
    "xs10": ROMLayout("xs10", 0x01021000, 0x01EAF000, 0x01788E80,
                      0x3FC, 0x02103A30, 0x0102300C, 0x0115B578),
}
ID_PAIRS = (
    (0x3DD, 0x3F4), (0x3DF, 0x3F6), (0x3E0, 0x3F7),
    (0x3E2, 0x3F9), (0x3E3, 0x3FA), (0x3E4, 0x3FB),
    (0x3E5, 0x3FC),
)
END_RECORD = (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)


def read_u32(blob: bytes, *, base: int, addr: int) -> int:
    off = addr - base
    if off < 0 or off + 4 > len(blob) or off % 4 != 0:
        raise ValueError(f"Not a valid aligned section address: {addr:#x}")
    return struct.unpack_from("<I", blob, off)[0]


def load_menu_rows(blob: bytes, model: ROMLayout, setting_id: int):
    """Read original FOUR DWORD records, preserve duplicates and ordering."""
    slot = model.pointer_index_base + setting_id*4
    ptr = read_u32(blob, base=model.section1_base, addr=slot)
    if not (model.section1_base <= ptr < model.section1_base+len(blob)):
        raise ValueError(f"{model.name} setting {setting_id:#x} invalid pointer {ptr:#x}")
    if ptr % 4:
        raise ValueError("Unaligned menu mapper row address")
    rows = []
    for i in range(256):
        off = ptr + i*16 - model.section1_base
        if off < 0 or off + 16 > len(blob):
            raise ValueError("Mapper list extends beyond decoded section")
        record = struct.unpack_from("<4I", blob, off)
        if record == END_RECORD:
            if not rows:
                raise ValueError("Empty menu conversion mapping")
            return tuple(rows), ptr
        rows.append(record)
    raise ValueError("Menu conversion table missing sentinel")


def decode_a32_bl(inst: int, pc: int) -> int:
    if inst & 0x0F000000 != 0x0B000000 or inst >> 28 == 0xF:
        raise ValueError(f"Not conditional A32 BL: {inst:#x}")
    imm24 = inst & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 0x1000000
    return (pc+8 + (imm24<<2)) & 0xFFFFFFFF


def decode_mov_r0_imm(inst: int):
    if (inst >> 28) == 0xF or (inst >> 12) & 0xF:
        raise ValueError("Expected MOV immediate into R0")
    if inst & 0x0FF00000 == 0x03000000:
        return ((inst >> 16) & 0xF)<<12 | (inst & 0xFFF)
    if inst & 0x0FE00000 == 0x03A00000:
        v = inst & 0xFF
        rotation = 2*((inst >> 8) & 0xF)
        return ((v >> rotation) | (v << (32-rotation))) & 0xFFFFFFFF if rotation else v
    raise ValueError("Expected ARM MOV/MOVW immediate")


def audit_calls(section2: bytes, model: ROMLayout):
    """Validate the actual Section2 menu-converter -> codec setter BL chain."""
    pc = model.converter_bl_site
    def w(offset):
        return read_u32(section2, base=model.section2_base, addr=pc+offset)
    if w(-16) != 0xE3A03003 or w(-12) != 0xE3A02000 or w(-8) != 0xE1A01005:
        raise ValueError("Unexpected menu mapper register arguments")
    if decode_mov_r0_imm(w(-4)) != model.codec_id:
        raise ValueError("Menu event is not for codec setting ID")
    if decode_a32_bl(w(0),pc) != model.converter_entry:
        raise ValueError("Wrong menu index converter target")
    if w(4) != 0xE6EF0070:
        raise ValueError("Converter output not reduced to uint8 in R0")
    if decode_a32_bl(w(8), pc+8) != model.setter_entry:
        raise ValueError("Wrong eModeMovieCodec setter target")
    return {
        "menu_setting_id": f"0x{model.codec_id:03x}",
        "converter_call_site": f"0x{pc:08x}",
        "converter_entry": f"0x{model.converter_entry:08x}",
        "setter_call_site": f"0x{pc+8:08x}",
        "setter_entry": f"0x{model.setter_entry:08x}",
        "observable_effect": "menu row -> 8-bit enum setter call; UI reachability unknown",
    }


def compare(xt4_s1: bytes, xs10_s1: bytes, xt4_s2: bytes, xs10_s2: bytes):
    data = {"xt4":xt4_s1, "xs10":xs10_s1}
    mappings = []
    for xt_id, xs_id in ID_PAIRS:
        xt, xtptr = load_menu_rows(data["xt4"],LAYOUTS["xt4"],xt_id)
        xs, xsptr = load_menu_rows(data["xs10"],LAYOUTS["xs10"],xs_id)
        mappings.append({
            "xt4_id": f"0x{xt_id:03x}",
            "xs10_id": f"0x{xs_id:03x}",
            "xt4_ptr":hex(xtptr),
            "xs10_ptr":hex(xsptr),
            "xt4_rows":len(xt),
            "xs10_rows":len(xs),
            "identical":xt==xs,
            "xs10_result_column3":[rec[2] for rec in xs],
            "normalized_sha256":hashlib.sha256(
                b"".join(struct.pack("<4I",*row) for row in xt)
            ).hexdigest(),
        })
    codec_rows = load_menu_rows(data["xs10"],LAYOUTS["xs10"],0x3FC)[0]
    codec_values = [row[2] for row in codec_rows]
    return {
        "pairs":mappings,
        "all_equal":all(row["identical"] for row in mappings),
        "total_xt4_rows":sum(row["xt4_rows"] for row in mappings),
        "total_xs10_rows":sum(row["xs10_rows"] for row in mappings),
        "xs10_codec_row_to_enum":codec_values,
        "codec_mapping_has_0_and_1":set(codec_values)=={0,1},
        "xt4_call_chain":audit_calls(xt4_s2,LAYOUTS["xt4"]),
        "xs10_call_chain":audit_calls(xs10_s2,LAYOUTS["xs10"]),
        "normal_xs10_menu_displays_HEVC": "UNVERIFIED",
        "runtime_snapshot_codec_byte_from_UI": "UNVERIFIED",
        "main10_4k60_supported": "UNVERIFIED",
    }


def main():
    p=ArgumentParser(description=__doc__)
    for m in ("xt4","xs10"):
        for section in (1,2):
            p.add_argument(f"--{m}-section{section}",required=True,type=Path)
    args=p.parse_args()
    result=compare(
        args.xt4_section1.read_bytes(), args.xs10_section1.read_bytes(),
        args.xt4_section2.read_bytes(), args.xs10_section2.read_bytes()
    )
    for pair in result["pairs"]:
        print(f"{pair['xt4_id']} -> {pair['xs10_id']} "
              f"rows={pair['xt4_rows']}/{pair['xs10_rows']} "
              f"identical={pair['identical']} "
              f"mapped={pair['xs10_result_column3']}")
    for name in (
        "all_equal","total_xt4_rows","total_xs10_rows",
        "xs10_codec_row_to_enum","codec_mapping_has_0_and_1",
        "xt4_call_chain","xs10_call_chain","normal_xs10_menu_displays_HEVC",
        "runtime_snapshot_codec_byte_from_UI","main10_4k60_supported"
    ):
        print(f"{name}: {result[name]}")
    print("STATIC TABLES AND BL VERIFIED, UI REACHABILITY STILL UNKNOWN. "
          "No camera I/O or firmware changes.")


if __name__=="__main__":
    main()

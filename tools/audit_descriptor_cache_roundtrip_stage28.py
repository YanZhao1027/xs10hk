#!/usr/bin/env python3
"""Phase 28: offline audit of profile-descriptor save/restore cache.

Crosschecks original A32 BL instruction targets and key register instructions
with private Ghidra decompilation. This proves *code paths*, not execution,
runtime copy lengths, pointer payload values, camera capability or a patch.
Only uses preexisting private X6 sections and logs; no camera I/O.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json
import re
import struct


@dataclass(frozen=True)
class Spec:
    model: str
    s2base: int
    descriptor: int
    table: int
    copy_helper: int
    save_fn: int
    restore_fn: int
    reset_fn: int
    save_caller: int
    restore_caller: int
    save_hook: int
    restore_hook: int
    save_payload_bl: int
    save_header_bl: int
    restore_header_bl: int
    restore_payload_bl: int
    save_dynamic_len_insn: int
    restore_dynamic_len_insn: int
    restore_mov_len_insn: int
    save_mov_len_insn: int
    restore_dest_insn: int
    restore_movw: int
    restore_movt: int
    index_mov: int
    index_mul: int


SPECS = {
    "xs10": Spec(
        "xs10",0x01eaf000,0x02d987e8,0x02d9bd0c,0x012a9148,
        0x021f9338,0x021f93d8,0x021f92f8,0x021fc530,0x021fc9d8,
        0x021fc608,0x021fca78,
        0x021f9388,0x021f93d0,0x021f9404,0x021f9424,
        0x021f937c,0x021f9418,0x021f93f8,0x021f93c4,
        0x021f9420,0x021f93f0,0x021f93f4,
        0x021f93e0,0x021f93e4),
    "xt4": Spec(
        "xt4",0x01e0f000,0x02d0bf48,0x02d0f46c,0x01281848,
        0x021653b4,0x02165454,0x02165374,0x02168604,0x02168aa8,
        0x021686dc,0x02168b48,
        0x02165404,0x0216544c,0x02165480,0x021654a0,
        0x021653f8,0x02165494,0x02165474,0x02165440,
        0x0216549c,0x0216546c,0x02165470,
        0x0216545c,0x02165460),
}


def require(ok: bool, desc: str):
    if not ok:
        raise ValueError("phase28 descriptor cache audit: " + desc)


def word(data: bytes, base: int, at: int) -> int:
    off = at - base
    if off < 0 or off % 4 or off + 4 > len(data):
        raise ValueError("unaligned/outside original X6 section")
    return struct.unpack_from("<I",data,off)[0]


def decode_bl(insn: int, at: int) -> int:
    if insn >> 28 != 14 or (insn >> 25) & 7 != 5 or not (insn >> 24) & 1:
        raise ValueError("not A32 unconditional BL")
    off = insn & 0xffffff
    if off & 0x800000:
        off -= 0x1000000
    return (at + 8 + (off << 2)) & 0xffffffff


def half(insn: int, high: bool, reg: int) -> int:
    opcode = insn & 0x0ff00000
    require(insn >> 28 == 14 and
            opcode == (0x03400000 if high else 0x03000000)
            and ((insn >> 12) & 15) == reg,
            "MOVW/MOVT wrong opcode or register")
    return (((insn >> 16) & 15) << 12) | (insn & 0xfff)


def function_c(log: str, entry: int) -> str:
    fname = "FUN_%08x" % entry
    for segment in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        body = segment.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|char|byte)"
                     r"\s+(?:\*\s*)?" + fname + r"\s*\(",body):
            return body
    raise ValueError("Ghidra decompilation missing "+fname)


def payload_covers_primary_pointer(copy_size: int) -> bool:
    """The 4-byte pointer at descriptor+0x10 lies 4B into +0x0C payload."""
    if copy_size < 0:
        raise ValueError("negative memcpy size")
    return copy_size >= 8


def verify_c(spec: Spec, save: str, restore: str, reset: str,
             caller_save: str, caller_restore: str) -> dict:
    fmt = lambda v: "0x%x" % v
    sf = "FUN_%08x" % spec.copy_helper
    db, tb = spec.descriptor, spec.table
    require(("iVar1 = param_1 * 0x54;") in save,
            "save index stride is not 0x54")
    require(("param_1 = param_1 * 0x54;") in restore,
            "restore index stride is not 0x54")
    require((f"{sf}(&DAT_{db:08x},&DAT_{tb:08x} + param_1,0xc);") in restore,
            "restore fixed 12-byte header from selected record missing")
    require((f"{sf}(&DAT_{db+0xc:08x},param_1 + {fmt(tb+0xc)},"
             f"*(undefined4 *)(param_1 + {fmt(tb+4)}));") in restore,
            "restore variable-size payload path/length source missing")
    require((f"{sf}(&DAT_{tb:08x} + iVar1,&DAT_{db:08x},0xc);") in save,
            "save fixed 12-byte header to selected record missing")
    require((f"{sf}(iVar1 + {fmt(tb+0xc)},&DAT_{db+0xc:08x},"
             f"_DAT_{db+4:08x});") in save,
            "save variable-size payload path/length source missing")
    require("0x540" in reset and "0x54" in reset,
            "profile cache reset does not cover 16 records of 0x54 each")
    require("0x50" in reset,
            "profile cache clear routine unexpected span")
    require(f"FUN_{spec.save_fn:08x}();" in caller_save,
            "save event caller missing")
    require(f"FUN_{spec.restore_fn:08x}(uVar3 & 0xff);" in caller_restore,
            "restore event caller missing")
    require("uVar3 != 0x10" in caller_restore,
            "restore selector does not iterate over sixteen slots")
    return {"record_stride_bytes":0x54,
            "record_count_in_callers":16,
            "cache_span_bytes":0x540,
            "header_copy_bytes":0xc,
            "payload_dynamic_copy_size":True,
            "pointer_inside_payload_offset_bytes":4,
            "minimum_payload_length_to_include_pointer":8}


def check_original(spec: Spec, data: bytes, decomp_save: str,
                   decomp_restore: str, decomp_reset: str,
                   decomp_save_caller: str, decomp_restore_caller: str,
                   xref_text: str) -> dict:
    w = lambda at:word(data,spec.s2base,at)
    checks = [
        (spec.save_payload_bl,spec.copy_helper),
        (spec.save_header_bl,spec.copy_helper),
        (spec.restore_header_bl,spec.copy_helper),
        (spec.restore_payload_bl,spec.copy_helper),
        (spec.save_hook,spec.save_fn),
        (spec.restore_hook,spec.restore_fn),
    ]
    for site,target in checks:
        require(decode_bl(w(site),site)==target,
                "raw BL target mismatch at %08x" % site)
    # Header copy length is fixed 0xC, while payload gets len from RAM.
    for site in (spec.save_mov_len_insn,spec.restore_mov_len_insn):
        require(w(site)==0xe3a0200c,
                "header length must be immediate 0x0c")
    require(w(spec.save_dynamic_len_insn)==0xe5942004,
            "save payload size must load from descriptor header+4")
    require(w(spec.restore_dynamic_len_insn)==0xe7922003,
            "restore payload size must read selected cache entry+4")
    require(w(spec.restore_dest_insn)==0xe285000c,
            "restore variable payload must start at descriptor+0x0c")
    require(w(spec.index_mov)==0xe3a04054
            and w(spec.index_mul)==0xe0040094,
            "restore 0x54-byte index register instructions changed")
    base = (half(w(spec.restore_movw),False,5)
            | (half(w(spec.restore_movt),True,5)<<16))
    require(base==spec.descriptor,"restore descriptor-base constant changed")
    for address,target in ((spec.save_hook,spec.save_fn),
                           (spec.restore_hook,spec.restore_fn)):
        pattern=(r"PROBE_REF from=%08x to=%08x "
                 r"type=UNCONDITIONAL_CALL" %(address,target))
        require(re.search(pattern,xref_text) is not None,
                "Ghidra caller xrefs missing %08x" % address)
    details = verify_c(spec,decomp_save,decomp_restore,
                       decomp_reset,decomp_save_caller,decomp_restore_caller)
    # A fixed 12-byte header memcpy cannot reach descriptor+0x10; a
    # separately sized payload copy may, if its runtime size is >=8.
    require(not payload_covers_primary_pointer(0) and
            payload_covers_primary_pointer(8) and
            not payload_covers_primary_pointer(7),
            "symbolic copy-size boundary invalid")
    return {
        "model":spec.model,
        "descriptor_base":"0x%08x" % spec.descriptor,
        "descriptor_primary_pointer_field":"0x%08x" %(spec.descriptor+0x10),
        "cache_entry_base":"0x%08x" % spec.table,
        "cache_length_field_offset":"0x4",
        "cache_payload_field_offset":"0xc",
        "save_function":"0x%08x" % spec.save_fn,
        "restore_function":"0x%08x" % spec.restore_fn,
        "raw_BL_targets_verified":len(checks),
        "cache_backup_and_restore_paths_proven_statically":True,
        "primary_pointer_restore_if_payload_len_at_least_8":True,
        "runtime_payload_length_verified":False,
        "buffer_pointer_initial_producer_found":False,
        "input_buffer_codec_value_verified":False,
        "GUI_to_recorder_codec_assignment_proven":False,
        "HEVC_Main10_bitstream_proven":False,
        "internal_4K60_proven":False,
        "camera_modified":False,
        **details,
    }


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    root=p.parse_args().output
    info=[]
    for spec in SPECS.values():
        model=spec.model
        def local(name):
            return (root/name).read_text(encoding="utf-8")
        decomp=local(f"{model}_stage28_descriptor_copy_family.log")
        caller=local(f"{model}_stage28_profile_save_restore_callers.log")
        refs=local(f"{model}_stage28_profile_save_restore_refs.log")
        src=(root/f"x6-{model}/section-2.bin").read_bytes()
        info.append(check_original(
            spec,src,
            function_c(decomp,spec.save_fn),
            function_c(decomp,spec.restore_fn),
            function_c(caller,spec.reset_fn),
            function_c(caller,spec.save_caller),
            function_c(caller,spec.restore_caller),
            refs))
    print(json.dumps(info,ensure_ascii=False,indent=2))
    print("OFFLINE ONLY: conditional cache restores, no proved runtime codec or Main10/4K60.")


if __name__=="__main__":
    main()

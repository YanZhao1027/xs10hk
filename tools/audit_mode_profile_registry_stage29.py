#!/usr/bin/env python3
"""Phase29: offline ARM/Ghidra proof of profile registry -> descriptor ingress.

This audits structural metadata and A32 instructions in locally held ORIGINAL
X-S10 3.11 / X-T4 2.12 X6 sections. It does NOT read live runtime memory,
communicate with any camera, modify ROM or prove HEVC Main10 or 4K60.
"""
from dataclasses import dataclass
from argparse import ArgumentParser
from pathlib import Path
import json
import re
import struct


@dataclass(frozen=True)
class Spec:
    model: str
    section_base: int
    destination_header: int
    destination_payload: int
    installer: int
    header_lookup: int
    payload_lookup: int
    memcpy: int
    header_lookup_bl: int
    payload_lookup_bl: int
    header_copy_bl: int
    payload_copy_bl: int
    header_base_movw: int
    header_base_movt: int
    payload_dest_ldr: int
    payload_dest_literal: int
    dynamic_copy_len_ldr: int
    header_copy_len_mov: int
    mode_call_sites: tuple[int, ...]
    mode_caller_functions: tuple[int, ...]
    mode_selected_buffer_loads: tuple[int, ...]
    mode_selector_byte_loads: tuple[int, ...]
    registry_206_header_literal: int
    registry_207_header_literal: int
    registry_207_payload_literal: int
    registry_200_header_literal: int
    registry_200_payload_literal: int
    mode_206_counter_slot: int
    mode_206_payload_base: int


SPECS={
    "xs10":Spec(
        "xs10",0x01eaf000,0x02d987e8,0x02d987f4,
        0x021f9194,0x021f893c,0x021f8d64,0x012a9148,
        0x021f91a8,0x021f91bc,0x021f91dc,0x021f91f4,
        0x021f91d4,0x021f91d8,0x021f91f0,0x021f9218,
        0x021f91e8,0x021f91cc,
        (0x021e6e60,0x021e7060,0x021e71dc),
        (0x021e6d48,0x021e6ea8,0x021e7138),
        (0x021e702c,0x021e7194),
        (0x021e7030,0x021e7198),
        0x021f8d08,0x021f8cc8,0x021f90f8,
        0x021f8ccc,0x021f90fc,0x02d9c2a4,0x02d98a74
    ),
    "xt4":Spec(
        "xt4",0x01e0f000,0x02d0bf48,0x02d0bf54,
        0x02165210,0x021649b8,0x02164de0,0x01281848,
        0x02165224,0x02165238,0x02165258,0x02165270,
        0x02165250,0x02165254,0x0216526c,0x02165294,
        0x02165264,0x02165248,
        (0x021513ec,0x021515ec,0x02151768),
        (0x021512d4,0x02151434,0x021516c4),
        (0x021515b8,0x02151720),
        (0x021515bc,0x02151724),
        0x02164d84,0x02164d44,0x02165174,
        0x02164d48,0x02165178,0x02d0fa04,0x02d0c1d4
    ),
}


def ensure(cond: bool,msg: str):
    if not cond:
        raise ValueError("phase29 registry-to-descriptor audit: "+msg)


def word(raw:bytes,base:int,addr:int)->int:
    loc=addr-base
    if loc<0 or loc%4 or loc+4>len(raw):
        raise ValueError("outside original section or unaligned address")
    return struct.unpack_from("<I",raw,loc)[0]


def bl_target(instruction:int,addr:int)->int:
    if instruction>>28!=14 or ((instruction>>25)&7)!=5 or not ((instruction>>24)&1):
        raise ValueError("not an unconditional A32 BL")
    d=instruction&0xffffff
    if d&0x800000:d-=0x1000000
    return (addr+8+(d<<2))&0xffffffff


def half(insn:int,high:bool,reg:int)->int:
    opcode=insn&0x0ff00000
    ensure(insn>>28==14 and opcode==(0x03400000 if high else 0x03000000)
           and ((insn>>12)&15)==reg,"MOVW/MOVT opcode or Rd mismatch")
    return (((insn>>16)&15)<<12)|(insn&0xfff)


def positive_pc_ldr(insn:int,addr:int,expected:int,rd:int)->None:
    imm=expected-(addr+8)
    ensure(0<=imm<=4095 and
           insn==(0xe59f0000 | (rd<<12) | imm),
           "positive PC-relative LDR points to wrong destination literal")


def function_c(log:str,addr:int)->str:
    name="FUN_%08x"%addr
    for chunk in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=chunk.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|char|byte)"
                     r"\s+(?:\*\s*)?"+name+r"\s*\(",c):
            return c
    raise ValueError("missing Ghidra decompile definition "+name)


def decode_registry_literals(s:Spec,w)->dict:
    h206=w(s.registry_206_header_literal)
    h207=w(s.registry_207_header_literal)
    p207=w(s.registry_207_payload_literal)
    h200=w(s.registry_200_header_literal)
    p200=w(s.registry_200_payload_literal)
    ensure(h206+0xc==s.mode_206_payload_base,
           "dynamic mode 0x206 header/payload base mismatch")
    ensure(h207+0xc==p207,"mode 0x207 header+0xC payload mismatch")
    ensure(h200+0xc==p200,"mode 0x200 static fallback header mismatch")
    return {"mode_206_dynamic_header_base":"0x%08x"%h206,
            "mode_206_dynamic_payload_base":"0x%08x"%s.mode_206_payload_base,
            "mode_206_index_counter_slot":"0x%08x"%s.mode_206_counter_slot,
            "mode_206_index_expression":"(counter-1)*0x50",
            "mode_207_static_header":"0x%08x"%h207,
            "mode_207_static_payload":"0x%08x"%p207,
            "registered_type_200_header_not_seen_called":"0x%08x"%h200,
            "registered_type_200_payload_not_seen_called":"0x%08x"%p200}


def audit(s:Spec,raw:bytes,ghidra_install:str,ghidra_lookup:str,
          ghidra_refs:str,ghidra_mode_callers:str)->dict:
    w=lambda a:word(raw,s.section_base,a)
    for call,target in [
        (s.header_lookup_bl,s.header_lookup),
        (s.payload_lookup_bl,s.payload_lookup),
        (s.header_copy_bl,s.memcpy),
        (s.payload_copy_bl,s.memcpy),
        *zip(s.mode_call_sites,(s.installer,)*len(s.mode_call_sites)),
    ]:
        ensure(bl_target(w(call),call)==target,
               "original A32 BL mismatch at 0x%08x"%call)
        pattern=(r"PROBE_REF from=%08x to=%08x "
                 r"type=UNCONDITIONAL_CALL"%(call,target))
        if call in s.mode_call_sites:
            ensure(re.search(pattern,ghidra_refs) is not None,
                   "Ghidra installer call reference not found")
    hb=half(w(s.header_base_movw),False,0)|(
        half(w(s.header_base_movt),True,0)<<16)
    ensure(hb==s.destination_header,"header destination base not literal")
    positive_pc_ldr(w(s.payload_dest_ldr),s.payload_dest_ldr,
                    s.payload_dest_literal,0)
    ensure(w(s.payload_dest_literal)==s.destination_payload,
           "payload destination literal not descriptor +0xC")
    ensure(s.destination_payload==s.destination_header+0xc,
           "payload target offset should be +0xC")
    ensure(w(s.dynamic_copy_len_ldr)==0xe5942004,
           "payload copy size must read source header +0x4")
    ensure(w(s.header_copy_len_mov)==0xe3a0200c,
           "12-byte header copy size instruction changed")

    c=function_c(ghidra_install,s.installer)
    hc="FUN_%08x"%s.header_lookup
    pc="FUN_%08x"%s.payload_lookup
    cp="FUN_%08x"%s.memcpy
    ensure(f"{hc}(param_1,param_2,1)" in c and
           f"{pc}(param_1,param_2,1)" in c,
           "installer header and payload lookup chain not decompiled")
    ensure((f"{cp}(&DAT_{s.destination_header:08x},iVar1,0xc)") in c,
           "installer fixed 0xC header write missing")
    ensure((f"{cp}(DAT_{s.payload_dest_literal:08x},iVar2,"
            f"*(undefined4 *)(iVar1 + 4))") in c,
           "installer dynamic payload write missing")
    reg=decode_registry_literals(s,w)
    hdr=function_c(ghidra_lookup,s.header_lookup)
    pay=function_c(ghidra_lookup,s.payload_lookup)
    ensure("param_1 != 0x206" in hdr and "param_1 == 0x207" in hdr
           and "param_1 != 0x200" in hdr,
           "header registry type routing changed")
    ensure("param_1 == 0x206" in pay and "param_1 == 0x207" in pay
           and "param_1 == 0x200" in pay,
           "payload registry type routing changed")
    ensure("0x50" in hdr and "0x50" in pay and
           ("0x%x"%s.mode_206_payload_base) in pay and
           ("_DAT_%08x"%s.mode_206_counter_slot) in pay,
           "dynamic 0x206 entry counter or stride changed")

    mode_functions=[]
    for idx,(caller,site) in enumerate(zip(s.mode_caller_functions,s.mode_call_sites)):
        ci=function_c(ghidra_mode_callers,caller)
        ensure(re.search(r"FUN_%08x\([^\\n]*,0x8c\)"%s.installer,ci) is not None,
               "mode caller missing installer with selector 0x8c")
        ensure("0x206" in ci and "0x207" in ci and
               re.search(r"\*\(char \*\)\(\*\(int \*\)\(DAT_[0-9a-f]+ \+ 0xac4\) \+ 4\)",ci),
               "mode switch not based on primary buffer byte+4")
        ensure(w(site-8)==0xe3a0108c and w(site-4)==0xe1a00004,
               "mode caller lacks literal 0x8C and R4 mode argument")
        mode_functions.append("0x%08x"%caller)

    for ptr_load,byte_load in zip(s.mode_selected_buffer_loads,s.mode_selector_byte_loads):
        ensure(w(ptr_load)==0xe5933ac4,
               "mode selector must deref primary buffer pointer +0xAC4")
        ensure(w(byte_load)==0xe5d33004,
               "mode selector must load primary buffer byte +0x4")

    return {
        "model":s.model,
        "descriptor_header":"0x%08x"%s.destination_header,
        "descriptor_current_pointer_field":"0x%08x"%(s.destination_header+0x10),
        "payload_destination":"0x%08x"%s.destination_payload,
        "selected_registry_type_values":["0x206","0x207"],
        "actual_installer_callers_verified":mode_functions,
        "original_7_A32_BL_edges_verified":7,
        "primary_input_flag_byte_offset":"0x4",
        "profile_selector_constant":"0x8c",
        "descriptor_header_copy_bytes":12,
        "descriptor_payload_copy_length_source":"selected_header+0x4",
        "primary_pointer_relative_to_payload_start":4,
        "entire_pointer_overwritten_iff_payload_length_at_least_8":True,
        "runtime_length_and_pointer_value_known":False,
        "GUI_MovieCodec_to_Recorder_buffer_proven":False,
        "HEVC_Main10_internal_bitstream_proven":False,
        "4K60_sensor_pipeline_proven":False,
        "firmware_or_camera_modified":False,
        **reg,
    }


def main():
    a=ArgumentParser(description=__doc__)
    a.add_argument("--output",type=Path,default=Path("output"))
    root=a.parse_args().output
    vals=[]
    for s in SPECS.values():
        read=lambda name:(root/name).read_text(encoding="utf-8")
        binary=(root/f"x6-{s.model}/section-2.bin").read_bytes()
        vals.append(audit(
            s,binary,
            read(f"{s.model}_stage29_registry_install_callsite.log"),
            read(f"{s.model}_stage28_profile_descriptor_registry.log"),
            read(f"{s.model}_stage29_registry_origins_xrefs.log"),
            read(f"{s.model}_stage29_registry_install_callsite.log")
        ))
    print(json.dumps(vals,indent=2,ensure_ascii=False))
    print("OFFLINE: profile *descriptor* producer identified; 10-bit / 4K60 unproven.")


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Offline Phase31: prove Recorder input/output pointer COPY and Codec writeback.

X-S10 3.11 and X-T4 2.12 original Section1+Section2, private Ghidra logs.
The code first copies current-config pointer VALUE into export pointer slot,
and later (on a gated path in same caller) serializes active Codec/Format via
that export pointer. Does NOT prove the pointer value at runtime remains
unchanged, GUI settings feed Recorder, HEVC Main10, 4K60 or any unlock.
No USB, camera operations, writes to ROM/DAT, or private binaries uploaded.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json
import re
import struct


@dataclass(frozen=True)
class Spec:
    name: str
    sec2_base: int
    descriptor: int
    current_slot: int
    export_slot: int
    alias_init: int
    caller: int
    call_alias: int
    call_serializer: int
    serializer: int
    call_exporter: int
    exporter: int
    byte_instructions: tuple[int,int,int,int]
    codec_offset: int
    active_codec: int
    active_format: int
    gui_byte: int
    gui_setter: int
    gui_store: int
    gui_loader: int
    gui_loader_call: int
    setting_id: int
    former_input_slot_writer: int


SPECS = {
    "xs10":Spec(
        "xs10",0x01eaf000,0x02d987e8,0x02d9c2ac,0x035bd868,
        0x0221c934,0x021cdf80,0x021cdf8c,0x021ce0f4,
        0x0221d1bc,0x0221d298,0x012be684,
        (0x012beb8c,0x012beb90,0x012beb94,0x012beb98),
        0x430,0x01c25208,0x01c25209,
        0x01b88650,0x0115b578,0x0115b5d4,0x01179dc0,
        0x01179e54,0x3fc,0x0221477c),
    "xt4":Spec(
        "xt4",0x01e0f000,0x02d0bf48,0x02d0fa0c,0x03672078,
        0x02189348,0x0213754c,0x02137558,0x021376c0,
        0x02189bd4,0x02189cb0,0x01296d38,
        (0x01297250,0x01297254,0x01297258,0x0129725c),
        0x434,0x01b83974,0x01b83975,
        0x01af2db8,0x0112fd80,0x0112fddc,0x0114dab4,
        0x0114db48,0x3e5,0x02180d50),
}


def require(ok:bool,why:str):
    if not ok:raise ValueError("Phase31 pointer-alias audit: "+why)


def word(rom:bytes,base:int,addr:int)->int:
    delta=addr-base
    if delta<0 or delta%4 or delta+4>len(rom):
        raise ValueError("not aligned or outside loaded original X6 section")
    return struct.unpack_from("<I",rom,delta)[0]


def mov_half(insn:int,high:bool,rd:int)->int:
    req=0x03400000 if high else 0x03000000
    require((insn>>28)==14 and (insn&0x0ff00000)==req and
            ((insn>>12)&15)==rd,"MOVW/MOVT operation/register changed")
    return (((insn>>16)&15)<<12)|(insn&0xfff)


def branch_target(insn:int,addr:int)->int:
    require(insn>>28==14 and ((insn>>25)&7)==5 and ((insn>>24)&1)==1,
            "not an unconditional A32 BL")
    displacement=insn&0xffffff
    if displacement&0x800000:displacement-=0x1000000
    return (addr+8+(displacement<<2))&0xffffffff


def function_c(log:str,addr:int)->str:
    target="FUN_%08x"%addr
    for seg in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        body=seg.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|uint|int|undefined\d+|byte|char)"
                     r"\s+(?:\*\s*)?"+target+r"\s*\(",body):
            return body
    raise ValueError("Ghidra function definition absent "+target)


def direct_writer_refs(text:str,slot:int,at:int,owner:int)->dict:
    slotstr="%08x"%slot
    found=re.search(r"SLOT_SUMMARY addr="+slotstr+
                    r" refs=(\d+) functions=(\d+) types=\{([^}]*)\}",text)
    require(found is not None,"Ghidra slot reference summary absent")
    counts={k:int(v) for k,v in re.findall(r"([A-Z]+)=(\d+)",found.group(3))}
    require(sum(counts.values())==int(found.group(1)),
            "Ghidra xref type counter mismatch")
    require(counts.get("WRITE")==1,
            "more than one direct write to pointer slot; re-audit")
    require(("SLOT_WRITE_CAND addr=%08x from=%08x type=WRITE func=%08x" %
             (slot,at,owner)) in text,
            "expected original slot writer not present in xrefs")
    return {"total_Ghidra_xrefs":int(found.group(1)),
            "direct_Ghidra_writer_xrefs":counts["WRITE"],
            "all_indirect_or_alias_writes_ruled_out":False}


def audit(s:Spec,section1:bytes,section2:bytes,
          init_log:str,parent_log:str,exporter_log:str,
          serializer_log:str,gui_setter_log:str,gui_caller_log:str,
          pointer_xrefs:str,ram_map_log:str)->dict:
    w=lambda addr:word(section2,s.sec2_base,addr)
    s1=lambda addr:word(section1,0x01021000,addr)
    # In both models the init function has the same seven A32 instructions:
    # R2 = export-slot - 8; R3 = descriptor header;
    # R1 = *(uint32 *)(R3 + 0x3000 + 0xAC4); *(R2+8) = R1.
    base=s.alias_init
    output_base=(mov_half(w(base+8),False,2) |
                 mov_half(w(base+12),True,2)<<16)
    descriptor=(mov_half(w(base+16),False,3) |
                mov_half(w(base+20),True,3)<<16)
    require(descriptor==s.descriptor,"source descriptor constant wrong")
    require(output_base+8==s.export_slot,"output pointer slot constant wrong")
    require(descriptor+0x3000+0xac4==s.current_slot,
            "input pointer slot computed address mismatch")
    for at,expected in ((base+24,0xe2831a03),
                        (base+28,0xe5911ac4),
                        (base+32,0xe5821008)):
        require(w(at)==expected,"ADD/LDR/STR value-copy instruction mismatch")
    assert_seq=function_c(init_log,s.alias_init)
    require(("_DAT_%08x = _DAT_%08x;"%
             (s.export_slot,s.current_slot)) in assert_seq,
            "Ghidra does not confirm alias assignment direction")

    # SAME higher-level function calls alias setup first; serialization is
    # conditional on four successful comparisons. This is code ordering only.
    require(s.call_alias<s.call_serializer,
            "alias initiation must precede serializer call address")
    for at,target in (
            (s.call_alias,s.alias_init),
            (s.call_serializer,s.serializer),
            (s.call_exporter,s.exporter),
            (s.gui_loader_call,s.gui_setter)):
        block=section1 if at<0x01800000 else section2
        base_rom=0x01021000 if at<0x01800000 else s.sec2_base
        require(branch_target(word(block,base_rom,at),at)==target,
                "callsite original BL target wrong at %08x"%at)
    caller=function_c(parent_log,s.caller)
    alias_label="FUN_%08x();"%s.alias_init
    serialize_label="FUN_%08x();"%s.serializer
    require(alias_label in caller and serialize_label in caller and
            caller.index(alias_label)<caller.index(serialize_label),
            "parent decompile ordering changed")
    require(caller.count("if (iVar2 == 0)")>=4,
            "serializer gated success path changed")

    serializer=function_c(serializer_log,s.serializer)
    exporter_name="FUN_%08x"%s.exporter
    require(("_DAT_%08x"%s.export_slot) in serializer and
            exporter_name+"(" in serializer,
            "serializer not reading export-pointer slot")
    load_match=re.search(r"\b(iVar\d+)\s*=\s*_DAT_%08x;"%s.export_slot,
                         serializer)
    require(load_match is not None,
            "cannot identify exported pointer variable")
    variable=load_match.group(1)
    require((exporter_name+"("+variable+")") in serializer,
            "serializer exporter not using aliased buffer variable")
    require(branch_target(w(s.call_exporter),s.call_exporter)==s.exporter,
            "serializer raw BL target invalid")

    # Original Section1 two byte transfers from active Codec/Format config.
    p=s.byte_instructions
    ops=[0xe5d53000|s.codec_offset,0xe5c435b0,
         0xe5d53000|(s.codec_offset+1),0xe5c435b1]
    for addr,expected in zip(p,ops):
        require(s1(addr)==expected,
                "Recorder active->buffer LDRB/STRB four A32 words differ")
    exporter=function_c(exporter_log,s.exporter)
    for idx,address in enumerate((s.active_codec,s.active_format)):
        require(("param_1[0x%x] = DAT_%08x;"%(0x5b0+idx,address)) in exporter,
                "active config to output Codec/Format decompile absent")

    # GUI setting ID populates a distinct UI-cache field. Direct setters
    # themselves do NOT prove a GUI -> Recorder current pointer data edge.
    require(s1(s.gui_store)==0xe5c345b0,
            "GUI codec byte cache direct STRB changed")
    gui_setter=function_c(gui_setter_log,s.gui_setter)
    gui_loader=function_c(gui_caller_log,s.gui_loader)
    require(("DAT_%08x = (char)param_1;"%s.gui_byte) in gui_setter,
            "GUI cache setter actual assignment absent")
    require(("FUN_%08x(uVar2 & 0xff);"%s.gui_setter) in gui_loader and
            ("0x%x"%s.setting_id) in gui_loader and
            "0x7fffffff" in gui_loader,
            "GUI settings-service ID/value -> cache assignment absent")

    outrefs=direct_writer_refs(pointer_xrefs,s.export_slot,
                               s.alias_init+32,s.alias_init)
    srcwrite=direct_writer_refs(
        pointer_xrefs,s.current_slot,s.former_input_slot_writer,
        0x02214738 if s.name=="xs10" else 0x02180d0c)

    # These are runtime RAM addresses, outside the two main loaded X6 code
    # memory blocks. A static Ghidra image cannot tell us pointer *contents*.
    for target in (s.export_slot,s.current_slot,s.descriptor+0x10,s.gui_byte):
        key="MEMORY_TARGET %08x block=UNMAPPED"%target
        require(key in ram_map_log,
                "target now mapped; investigate ROM data before concluding unknown")
    return {
       "model":s.name,
       "input_pointer_slot":"0x%08x"%s.current_slot,
       "export_pointer_slot":"0x%08x"%s.export_slot,
       "pointer_slots_are_different":s.current_slot!=s.export_slot,
       "original_A32_R0_R1_pointer_copy_verified":True,
       "pointer_value_equality_immediately_after_alias_instruction":True,
       "initialization_function":"0x%08x"%s.alias_init,
       "success_gated_caller":"0x%08x"%s.caller,
       "same_caller_calls_initializer_before_serializer":True,
       "original_ARM_BL_edges_verified":4,
       "raw_active_codec_format_load_store_words_verified":4,
       "codec_active_config":"0x%08x"%s.active_codec,
       "format_active_config":"0x%08x"%s.active_format,
       "export_codec_field_offset":"0x5b0",
       "export_format_field_offset":"0x5b1",
       "GUI_setting_ID":"0x%x"%s.setting_id,
       "GUI_cache_byte":"0x%08x"%s.gui_byte,
       "gui_settings_service_to_cache_assignment_proven":True,
       "original_GUI_cache_STRB_verified":True,
       "input_pointer_slot_static_refs":srcwrite,
       "export_pointer_slot_static_refs":outrefs,
       "runtime_current_buffer_pointer_numeric_value":"UNKNOWN",
       "runtime_pointer_equality_at_serializer_time_proven":False,
       "conditional_active_to_input_buffer_codec_feedback_possible":True,
       "actual_GUI_codec_to_Recorder_input_initial_value_proven":False,
       "HEVC_Main10_internal_bitstream_proven":False,
       "4K60_sensor_ISP_pipeline_proven":False,
       "camera_or_firmware_modified":False,
    }


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    root=p.parse_args().output
    out=[]
    for spec in SPECS.values():
        m=spec.name
        log=lambda fname:(root/fname).read_text(encoding="utf-8")
        out.append(audit(spec,
          (root/f"x6-{m}/section-1.bin").read_bytes(),
          (root/f"x6-{m}/section-2.bin").read_bytes(),
          log(f"{m}_stage31_export_pointer_slot_initializer.log"),
          log(f"{m}_stage31_alias_producer_order_callers.log"),
          log(f"{m}_stage25_snapshot_populate_pipeline.log"),
          log(f"{m}_stage25_snapshot_producer_candidates.log"),
          log(f"{m}_stage31_gui_codec_setter_pipeline.log"),
          log(f"{m}_stage31_gui_setter_caller_context.log"),
          log(f"{m}_stage31_export_pointer_slot_refs.log"),
          log(f"{m}_stage31_dynamic_ram_mapping.log")))
    print(json.dumps(out,ensure_ascii=False,indent=2))
    print("OFFLINE only: pointer-equality ASSIGNMENT + gated active->export.")
    print("NO proof of runtime pointer equality, GUI->Recorder or 10-bit/4K60.")


if __name__=="__main__":main()

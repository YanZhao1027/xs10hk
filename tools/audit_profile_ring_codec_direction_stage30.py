#!/usr/bin/env python3
"""Phase30 evidence audit: profile ring pointer provenance and Codec serializing.

Offline ONLY. Requires user's original locally extracted X6 sections and
private Ghidra logs. No camera I/O, firmware patch or codec-unlock assertion.
Verifies two different data-flow edges:
    descriptor -> type 0x206/0x207 registry and conditional reverse load;
    active Recorder Codec/Format -> independent output buffer.
The actual Recorder input buffer's +0x5B0 content remains UNKNOWN.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json
import re
import struct


@dataclass(frozen=True)
class Model:
    name: str
    sec2base: int
    descriptor: int
    save_fn: int
    restore_fn: int
    memcpy: int
    header_copy: int
    payload_copy: int
    header_movw: int
    header_movt: int
    payload_movw: int
    payload_movt: int
    counter_store: int
    counter_addr: int
    counter_owner_literal: int
    ring_header: int
    ring_payload: int
    ring_header_literal: int
    ring_payload_literal: int
    ordinary_206_payload_literal: int
    ordinary_206_payload: int
    ordinary_206_fallback_symbol: str
    type207_write_payload_literal: int
    type207_read_header_literal: int
    type207_read_payload_literal: int
    type207_header: int
    type207_payload: int
    original_gui_byte: int
    current_ptr_slot: int
    active_codec: int
    active_format: int
    active_export_function: int
    serializer_caller_function: int
    serializer_caller_bl: int
    serializer_global: int
    raw_export_codec_load: int
    raw_export_codec_store: int
    raw_export_format_load: int
    raw_export_format_store: int
    raw_export_codec_baseoffset: int
    counter_mutator_functions: tuple[int,...]


SPECS={
  "xs10":Model(
    "xs10",0x01eaf000,0x02d987e8,
    0x021f8100,0x021f9194,0x012a9148,
    0x021f81cc,0x021f81ec,
    0x021f81c0,0x021f81c4,
    0x021f81d8,0x021f81dc,
    0x021f8474,0x02d9c2a4,0x021f8cc0,
    0x02d98a68,0x02d98a74,0x021f8d08,0x021f9190,
    0x021f85b8,0x02d9b314,"DAT_021f85b8",
    0x021f857c,0x021f8cc8,0x021f90f8,0x02d9b358,0x02d9b364,
    0x01b88650,0x02d9c2ac,0x01c25208,0x01c25209,
    0x012be684,0x0221d1bc,0x0221d298,0x035bd868,
    0x012beb8c,0x012beb90,0x012beb94,0x012beb98,0x430,
    (0x021f921c,0x021fb3f8,0x021fb77c)),
  "xt4":Model(
    "xt4",0x01e0f000,0x02d0bf48,
    0x0216417c,0x02165210,0x01281848,
    0x02164248,0x02164268,
    0x0216423c,0x02164240,
    0x02164254,0x02164258,
    0x021644f0,0x02d0fa04,0x02164d3c,
    0x02d0c1c8,0x02d0c1d4,0x02164d84,0x0216520c,
    0x02164634,0x02d0ea74,"DAT_02164634",
    0x021645f8,0x02164d44,0x02165174,0x02d0eab8,0x02d0eac4,
    0x01af2db8,0x02d0fa0c,0x01b83974,0x01b83975,
    0x01296d38,0x02189bd4,0x02189cb0,0x03672078,
    0x01297250,0x01297254,0x01297258,0x0129725c,0x434,
    (0x02165298,0x021674c8,0x0216784c)),
}


def req(condition,why):
    if not condition:raise ValueError("phase30 evidence audit: "+why)


def rom_word(blob,base,addr):
    off=addr-base
    if off<0 or off%4 or off+4>len(blob):raise ValueError("unaligned/outside original section")
    return struct.unpack_from("<I",blob,off)[0]


def decode_bl(insn,at):
    if insn>>28!=14 or (insn>>25)&7!=5 or not (insn>>24)&1:
        raise ValueError("not an unconditional ARM BL")
    d=insn&0xffffff
    if d&0x800000:d-=0x1000000
    return (at+8+(d<<2))&0xffffffff


def movhalf(insn,top,reg):
    op=0x03400000 if top else 0x03000000
    req(insn>>28==14 and (insn&0x0ff00000)==op and
        ((insn>>12)&15)==reg,"MOVW/MOVT register or operation mismatch")
    return (((insn>>16)&15)<<12)|(insn&0xfff)


def function_c(log,addr):
    label="FUN_%08x"%addr
    for part in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=part.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|char|byte)"
                     r"\s+(?:\*\s*)?"+label+r"\s*\(",c):
            return c
    raise ValueError("missing Ghidra decompile "+label)


def includes_full_pointer(payload_bytes):
    if payload_bytes<0:raise ValueError("negative payload size")
    # Descriptor+0x10 is 4B into source/destination payload+0x0C.
    return payload_bytes>=8


def counter_xrefs(log,model):
    line=re.search(
      r"SLOT_SUMMARY addr=%08x refs=(\d+) functions=(\d+) "
      r"types=\{([^}]*)\}"%model.counter_addr,log)
    req(line is not None,"missing Ghidra counter-reference summary")
    types={k:int(v) for k,v in re.findall(r"([A-Z]+)=(\d+)",line.group(3))}
    req(sum(types.values())==int(line.group(1)) and types.get("WRITE")==5,
        "counter direct Ghidra WRITE count changed; reinvestigate")
    req(("SLOT_WRITE_CAND addr=%08x from=%08x type=WRITE" %
         (model.counter_addr,model.counter_store)) in log,
        "original counter increment writer not in Ghidra xrefs")
    return {"total_direct_xrefs":int(line.group(1)),
            "static_Ghidra_direct_Writes":types["WRITE"],
            "all_write_implementations_enumerated":False}


def triad(log):
    r=[]
    for a,b in (("gui","active"),("gui","current_ptr_slot"),
                ("active","current_ptr_slot")):
        m=re.search(r"TRIAD_PAIR a=%s b=%s functions=(\d+)"%(a,b),log)
        req(m is not None,"missing triad xref audit")
        r.append(int(m.group(1)))
    req(r==[0,0,0],"new same-function static xref overlap needs analysis")
    return {"direct_function_xref_overlap_for_three_pairs":r,
            "indirect_call_or_pointer_transfer_excluded":False}


def audit(s,raw_s1,raw_s2,registry_c,registry_reader_c,counter_c,
          serializer_c,serializer_caller_c,counter_refs,triad_refs):
    w=lambda at:rom_word(raw_s2,s.sec2base,at)
    sr=lambda at:rom_word(raw_s1,0x01021000,at)
    for at in (s.header_copy,s.payload_copy):
        req(decode_bl(w(at),at)==s.memcpy,"profile-ring copy BL target")
    req(decode_bl(w(s.serializer_caller_bl),s.serializer_caller_bl)==
        s.active_export_function,"active-export call BL target")
    head=(movhalf(w(s.header_movw),False,1) |
          (movhalf(w(s.header_movt),True,1)<<16))
    pay=(movhalf(w(s.payload_movw),False,1) |
         (movhalf(w(s.payload_movt),True,1)<<16))
    req(head==s.descriptor and pay==s.descriptor,
        "profile ring save source is not current descriptor")
    req(w(s.header_copy-16)==0xe3a0200c,
        "profile ring header copy length is not 0xc")
    req(w(s.header_copy-4)==0xe1a00005 and
        w(s.payload_copy-4)==0xe1a00004,
        "profile save memcpy destination registers changed")
    req(w(s.payload_copy-12)==0xe5912004 and
        w(s.payload_copy-8)==0xe281100c,
        "payload source descriptor+0xc / size header+4 mismatch")
    req(w(s.counter_store)==0xe5812abc,
        "profile ring increment is not expected STR [R1,#0xABC]")

    # Independently read actual little-endian pointer constants from ROM
    # instead of deriving values from Ghidra symbol names.
    req(w(s.ring_header_literal)==s.ring_header,
        "ring header table pointer ROM constant")
    req(w(s.ring_payload_literal)==s.ring_payload,
        "ring payload table pointer ROM constant")
    req(s.ring_header+0xc==s.ring_payload,
        "ring header/payload structural offset")
    req(w(s.ordinary_206_payload_literal)==s.ordinary_206_payload,
        "0x206/0x8C ordinary-write path ROM constant")
    req(s.ordinary_206_payload!=s.ring_payload,
        "ordinary 0x206/0x8C save falsely equals dynamic ring payload")
    req(w(s.type207_write_payload_literal)==s.type207_payload and
        w(s.type207_read_payload_literal)==s.type207_payload and
        w(s.type207_read_header_literal)==s.type207_header,
        "0x207 static reader/writer source identity mismatch")
    req(s.type207_header+0xc==s.type207_payload,
        "0x207 static header/payload offset")
    owner=w(s.counter_owner_literal)
    req(owner+0xabc==s.counter_addr,
        "reader's last-entry counter not same writer counter")

    writer=function_c(registry_c,s.save_fn)
    lookup_hdr=function_c(registry_reader_c,
                          0x021f893c if s.name=="xs10" else 0x021649b8)
    lookup_pay=function_c(registry_reader_c,
                          0x021f8d64 if s.name=="xs10" else 0x02164de0)
    req("0x11b" in writer and "0x11e" in writer and
        ("_DAT_%08x"%s.counter_addr+" * 0x50") in writer and
        ("_DAT_%08x = _DAT_%08x + 1"%(s.counter_addr,s.counter_addr)) in writer,
        "conditional type206 special-subtype ring insertion absent")
    req(("_DAT_%08x == 0x206"%s.descriptor) in writer and
        ("_DAT_%08x != 0x207"%s.descriptor) in writer and
        (s.ordinary_206_fallback_symbol+" + -0xc") in writer,
        "ordinary type206 or type207 route changed")
    req(("FUN_%08x(puVar3,&DAT_%08x,0xc)"%
         (s.memcpy,s.descriptor)) in writer and
        ("FUN_%08x(puVar2,&DAT_%08x,_DAT_%08x)"%
         (s.memcpy,s.descriptor+0xc,s.descriptor+4)) in writer,
        "ring cache save direction/length source missing")
    req(("_DAT_%08x + -1"%s.counter_addr) in lookup_pay and
        ("0x%x"%s.ring_payload) in lookup_pay and
        "0x50" in lookup_hdr and "+ 0xabc" in lookup_hdr,
        "dynamic registry reader does not use latest ring index")
    req(("&DAT_%08x"%s.ring_header) in writer and
        ("0x%x"%s.ring_payload) in writer,
        "ring-save target address does not match reader")
    # Verify multiple independent decrement/compaction functions exist;
    # the counter is NOT an always-increasing append-only value.
    clear_func=function_c(counter_c,s.counter_mutator_functions[0])
    collapse_func=function_c(counter_c,s.counter_mutator_functions[1])
    drop_func=function_c(counter_c,s.counter_mutator_functions[2])
    req("0x44" in clear_func and
        " + -1" in clear_func and "0x206" in clear_func,
        "record-clear and counter-decrement mechanism changed")
    req("0x50" in collapse_func and "0x18" in collapse_func and
        "0x206" in collapse_func and " + -1" in collapse_func,
        "record compaction/decrement missing")
    req("0x50" in drop_func and "0x44" in drop_func and
        ("_DAT_%08x"%s.counter_addr) in drop_func,
        "indexed record deletion missing")
    counter=counter_xrefs(counter_refs,s)

    # A separate confirmed assignment: active Codec byte -> exported buffer.
    # This is NOT evidence of the GUI -> recorder-input assignment.
    src_byte=0xe5d53000|s.raw_export_codec_baseoffset
    next_src=src_byte+1
    req(sr(s.raw_export_codec_load)==src_byte and
        sr(s.raw_export_codec_store)==0xe5c435b0 and
        sr(s.raw_export_format_load)==next_src and
        sr(s.raw_export_format_store)==0xe5c435b1,
        "raw LDRB->STRB active Codec/Format export pair changed")
    export=function_c(serializer_c,s.active_export_function)
    caller=function_c(serializer_caller_c,s.serializer_caller_function)
    req(("param_1[0x5b0] = DAT_%08x;"%s.active_codec) in export and
        ("param_1[0x5b1] = DAT_%08x;"%s.active_format) in export,
        "active Codec/Format -> export buffer direction not decompiled")
    out_var="iVar3" if s.name=="xs10" else "iVar4"
    req(("%s = _DAT_%08x;"%(out_var,s.serializer_global)) in caller and
        ("FUN_%08x(%s);"%(s.active_export_function,out_var)) in caller,
        "serializer output pointer origin not independently found")
    # The export destination is a separate RAM pointer *slot*, without
    # any proof that the pointer value is the current Recorder buffer.
    req(s.serializer_global!=s.current_ptr_slot,
        "export and input pointer slots unexpectedly share exact address")
    from_rom=triad(triad_refs)
    return {
        "model":s.name,
        "descriptor_base":"0x%08x"%s.descriptor,
        "pointer_offset_in_descriptor":"0x10",
        "current_input_pointer_slot":"0x%08x"%s.current_ptr_slot,
        "ring_counter_slot":"0x%08x"%s.counter_addr,
        "ring_header_base":"0x%08x"%s.ring_header,
        "ring_payload_base":"0x%08x"%s.ring_payload,
        "type206_special_save_suboptions":["0x11b","0x11e"],
        "ring_entry_byte_stride":0x50,
        "nominal_ring_header_bytes":0xc,
        "nominal_ring_payload_bytes":0x44,
        "type206_selector_8c_normal_save_payload":"0x%08x"%
                                                   s.ordinary_206_payload,
        "type206_selector_8c_normal_save_is_same_as_latest_ring":False,
        "type206_last_entry_read_formula":"(count-1)*0x50+ring_base",
        "type207_static_save_and_read_payload":"0x%08x"%s.type207_payload,
        "copy_contains_full_descriptor_pointer_if_payload_size_at_least":8,
        "original_ARM_memcpy_and_serializer_BLs_checked":3,
        "original_ARM_four_export_load_store_words_checked":4,
        "ring_counter_reference_audit":counter,
        "static_cross_xref_screen":from_rom,
        "active_Codec_byte":"0x%08x"%s.active_codec,
        "active_Format_byte":"0x%08x"%s.active_format,
        "export_output_pointer_global":"0x%08x"%s.serializer_global,
        "verified_active_codec_to_export_buffer_byte_0x5b0":True,
        "verified_active_format_to_export_buffer_byte_0x5b1":True,
        "output_pointer_same_value_as_current_input_proven":False,
        "GUI_codec_to_recorder_input_buffer_assignment_proven":False,
        "runtime_ring_entry_pointer_value_known":False,
        "runtime_ring_count_or_copy_length_known":False,
        "HEVC_Main10_internal_10bit_proven":False,
        "4K60_internal_sensor_pipeline_proven":False,
        "camera_or_firmware_modified":False,
    }


def main():
    parser=ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=Path("output"))
    root=parser.parse_args().output
    values=[]
    for s in SPECS.values():
        def log(name):return (root/name).read_text(encoding="utf-8")
        values.append(audit(
          s,
          (root/f"x6-{s.name}/section-1.bin").read_bytes(),
          (root/f"x6-{s.name}/section-2.bin").read_bytes(),
          log(f"{s.name}_stage28_profile_descriptor_registry.log"),
          log(f"{s.name}_stage28_profile_descriptor_registry.log"),
          log(f"{s.name}_stage30_dynamic_ring_counter_writers.log"),
          log(f"{s.name}_stage29_primary_buffer_init_api.log"),
          log(f"{s.name}_stage30_serializer_entrycallers.log"),
          log(f"{s.name}_stage30_registry_ring_counter_xrefs.log"),
          log(f"{s.name}_stage30_codec_triad_xrefs.log"),
        ))
    print(json.dumps(values,indent=2,ensure_ascii=False))
    print("OFFLINE: cache pointer provenance and outbound Codec export proven; "
          "inbound Codec assignment STILL UNKNOWN.")


if __name__=="__main__":
    main()
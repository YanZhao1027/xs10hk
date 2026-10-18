#!/usr/bin/env python3
"""Stage34 original-ROM audit: register constructed movie codec control struct.

Scopes: original Fujifilm X-S10 3.11 / X-T4 2.12 X6 sections and private
Ghidra READ-ONLY logs on authorized Ubuntu. NEVER touches any camera, never
modifies firmware/DAT, never identifies unverified Main10 or 4K60 unlock.

Proves this static intended propagation when the guarded movie setup path
executes:
  active Codec -> context+0x9d8 / +0x9dc (Stage33)
  movie builder -> *(main+0x37f8+0x220) = 0x10004 / 0x10005
  movie caller -> *(ctx+0x5ff4) = main+0x37f8
  backend_register -> *(backend+0x3d00) = main+0x37f8
where main=*(ctx+0x601c), backend=*(main+0x124a8).
This does NOT prove backend dereference/encoder acceptance/profile or bitdepth.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
import struct

@dataclass(frozen=True)
class Spec:
    model: str
    sec2base: int
    caller: int
    builder: int
    builder_bl: int
    registrar: int
    registrar_bl: int
    codec_offset: int
    packet_codec_ldr: int

SPECS={
 "xs10":Spec("xs10",0x01eaf000,0x022df9ec,0x022b6230,0x022dfaa8,
             0x022e3d5c,0x022dfaf8,0x9d8,0x022b6784),
 "xt4":Spec("xt4",0x01e0f000,0x0224c14c,0x02222a00,0x0224c208,
            0x02250634,0x0224c258,0x9dc,0x02222f44),
}
REGISTER_BODY_NBYTES=152

# Encoded instructions from the owner-relative caller context and backend
# registration function, matching original ARM A32 in BOTH models. These
# literals are hand-readable instruction *assertions*, not firmware images.
REG_A32_WORDS={
    0x08:0xe280ca06,     # ADD r12,r0,#0x6000 (ctx+0x601c via LDR)
    0x0c:0xe59c201c,     # LDR r2,[r12,#0x1c] -> main
    0x10:0xe2823a12,     # ADD r3,r2,#0x12000
    0x14:0xe59334a8,     # LDR r3,[r3,#0x4a8] -> backend
    0x18:0xe2831a03,     # ADD r1,r3,#0x3000
    0x1c:0xe5812cf8,     # STR main,[backend+0x3cf8]
    0x20:0xe59c201c,     # LDR main again
    0x24:0xe2822dd2,     # ADD r2,main,#0x3480
    0x28:0xe2822014,     # ADD r2,r2,#0x14 => +0x3494
    0x2c:0xe5812cfc,     # STR [backend+0x3cfc] = main+0x3494
    0x30:0xe59c201c,     # LDR main again
    0x34:0xe2822ddf,     # ADD r2,main,#0x37c0
    0x38:0xe2822038,     # ADD r2,r2,#0x38 => main+0x37f8
    0x3c:0xe5812d00,     # STR [backend+0x3d00] = main+0x37f8
}

def must(cond,why):
    if not cond:raise ValueError("Stage34 original-ROM proof failed: "+why)

def rom_word(raw,base,addr):
    k=addr-base
    if k%4 or k<0 or k+4>len(raw):raise ValueError("bad ROM word offset")
    return struct.unpack_from("<I",raw,k)[0]

def rom_function_bytes(raw,base,addr,n):
    k=addr-base
    if n<=0 or k<0 or k+n>len(raw):raise ValueError("bad ROM function slice")
    return raw[k:k+n]

def bl_target(word,at):
    must(word>>28==14 and word>>25&7==5 and word>>24&1==1,
         "instruction is not unconditional ARM BL")
    delta=word&0xffffff
    if delta&0x800000:delta-=0x1000000
    return (at+8+(delta<<2))&0xffffffff

def decomp(log,at):
    marker="FUN_%08x"%at
    for p in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        b=p.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|byte|char|bool|undefined\d+)"
                     r"\s+(?:\*\s*)?"+marker+r"\s*\(",b):
            return b
    raise ValueError("missing Ghidra read-only function "+marker)

def audit_model(s,word_fn,body,parent_c,registrar_c,builder_c,stage33):
    must(stage33["model"]==s.model and
         stage33["movie_context_codec_offset"]=="0x%x"%s.codec_offset and
         stage33["codec_control_if_byte_equals_1"]=="0x10004" and
         stage33["codec_control_otherwise"]=="0x10005" and
         stage33["movie_context_plus_0x5b0_is_Recorder_Codec"] is False,
         "incorrect Stage33 upstream evidence")
    must(s.codec_offset in (0x9d8,0x9dc),"wrong movie context codec location")
    must(s.builder_bl<s.registrar_bl,
         "registration call must follow constructor in movie setup")
    for site,target in ((s.builder_bl,s.builder),(s.registrar_bl,s.registrar)):
        must(bl_target(word_fn(site),site)==target,
             "ROM parent BL does not target movie function")

    name="FUN_%08x"%s.builder
    caller="FUN_%08x"%s.registrar
    arg="iVar4" if s.model=="xs10" else "iVar6"
    expected_build=("%s(param_1,%s,%s + 0x3494,%s + 0x37f8,%s + 0x120d4);"%
                    (name,arg,arg,arg,arg))
    pointer_store=("*(int *)(param_1 + 0x5ff4) = %s + 0x37f8;"%arg)
    expected_reg=caller+"(param_1);"
    for phrase in (expected_build,pointer_store,expected_reg,
                   "*(int *)(param_1 + 0x601c)"):
        must(phrase in parent_c,
             "movie setup caller expected pointer chain missing: "+phrase)
    must(parent_c.index(expected_build)<parent_c.index(pointer_store)<
         parent_c.index(expected_reg),
         "movie constructor / ctx pointer / registrar order changed")
    must(("if (*(char *)(%s + 0x122a0) == '\\0')"%arg) in parent_c,
         "movie setup alternate branch guard missing")

    for phrase in (
         "iVar2 = *(int *)(*(int *)(param_1 + 0x601c) + 0x124a8);",
         "*(int *)(iVar2 + 0x3cf8) = *(int *)(param_1 + 0x601c);",
         "*(int *)(iVar2 + 0x3cfc) = *(int *)(param_1 + 0x601c) + 0x3494;",
         "*(int *)(iVar2 + 0x3d00) = *(int *)(param_1 + 0x601c) + 0x37f8;",
        ):
        must(phrase in registrar_c,
             "backend pointer source, index or slot mismatch: "+phrase)
    must(("*(int *)(param_1 + 0x3118) == 0") in registrar_c and
         "*(int *)(iVar2 + 0x3d04) = iVar1;" in registrar_c,
         "adjacent optional stream pointer context changed")

    must(("*(char *)(param_1 + 0x%x) == '\\x01'"%s.codec_offset) in builder_c,
         "movie builder not reading Stage33 Codec byte")
    must("*(uint *)(param_4 + 0x220) = uVar8 | 0x10000;" in builder_c,
         "movie builder missing 0x10004/5 output field")
    must(word_fn(s.packet_codec_ldr)==(0xe5d43000|s.codec_offset),
         "builder raw LDRB Codec field offset changed")

    for rel,expected in REG_A32_WORDS.items():
        must(word_fn(s.registrar+rel)==expected,
             "registration original ARM word changed at +0x%x"%rel)
    must(len(body)==REGISTER_BODY_NBYTES,
         "original registrar function fingerprint length differs")

    return {
      "model":s.model,
      "parent_movie_setup_function":"FUN_%08x"%s.caller,
      "original_ARM_registrar_word_checks":len(REG_A32_WORDS),
      "original_ARM_movie_builder_ldr_checks":1,
      "original_ARM_parent_BLs_checked":2,
      "register_function_length_bytes":len(body),
      "register_function_sha256":hashlib.sha256(body).hexdigest(),
      "record_path_conditional_on_submode":True,
      "main_ptr_source":"*(ctx + 0x601c)",
      "codec_constructor_function":"FUN_%08x"%s.builder,
      "codec_constructor_output":"main + 0x37f8",
      "codec_constructor_select_field_offset":"0x220",
      "codec_constructor_field_absolute_offset_from_main":"0x3a18",
      "movie_caller_secondary_pointer_slot":"ctx + 0x5ff4",
      "backend_ptr_source":"*(main + 0x124a8)",
      "backend_parameter_set_ptr_slot":"backend + 0x3d00",
      "backend_parameter_ptr_equals":"main + 0x37f8",
      "other_backend_pointers":{
        "backend + 0x3cf8":"main",
        "backend + 0x3cfc":"main + 0x3494",
        "backend + 0x3d04":"main + 0x120d4 or NULL, conditional"
      },
      "static_struct_pointer_registration_proven":True,
      "backend_slot_dereference_or_VPU_command_proven":False,
      "numeric_0x10004_means_what_codec_or_profile":"UNKNOWN",
      "GUI_to_Recorder_INPUT_0x5b0_initial_assignment_proven":False,
      "HEVC_Main10_recording_proven":False,
      "4K60_sustained_recording_proven":False,
      "camera_or_firmware_modified":False
    }

def audit_pair(xs,xt):
    must(xs["model"]=="xs10" and xt["model"]=="xt4",
         "cross-model fingerprint IDs wrong")
    must(xs["register_function_sha256"]==xt["register_function_sha256"],
         "cross-model fingerprint: 152B ARM registration body must match byte-for-byte")
    for k in ("codec_constructor_select_field_offset",
              "codec_constructor_field_absolute_offset_from_main",
              "backend_ptr_source","backend_parameter_set_ptr_slot",
              "backend_parameter_ptr_equals"):
        must(xs[k]==xt[k],"cross-model pointer ABIs differ for "+k)
    return {
      "cross_model_registration_function_byte_identical":True,
      "common_registration_function_sha256":xs["register_function_sha256"],
      "common_registration_function_size":REGISTER_BODY_NBYTES,
      "common_parameter_struct_main_offset":"0x37f8",
      "common_field_offset_within_that_struct":"0x220",
      "actual_encoder_consumer_or_final_device_bits_seen":False
    }

def main():
    ap=ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    o=ap.parse_args().output
    prior_text=(o/"stage33_movie_context_audit_result.jsonlog").read_text()
    prior=json.loads(prior_text.split("\nStage33 is READ-ONLY")[0])
    results=[]
    for spec in SPECS.values():
        raw=(o/f"x6-{spec.model}/section-2.bin").read_bytes()
        def g(name):return (o/name).read_text()
        trace=g(f"{spec.model}_stage34_post_builder_pipeline.log")
        prior_model=next(p for p in prior if p["model"]==spec.model)
        results.append(audit_model(spec,
            lambda address:rom_word(raw,spec.sec2base,address),
            rom_function_bytes(raw,spec.sec2base,spec.registrar,
                               REGISTER_BODY_NBYTES),
            decomp(trace,spec.caller),
            decomp(trace,spec.registrar),
            decomp(g(f"{spec.model}_stage33_movie_context_fields_consumers.log"),
                   spec.builder),
            prior_model))
    result={"models":results,"cross_model":audit_pair(*results)}
    print(json.dumps(result,ensure_ascii=False,indent=2))
    print("STAGE34 OFFLINE: backend received a pointer to parameter STRUCT, not verified codec bytes.")
    print("UNKNOWN: backend consumer, HEVC Main10/10-bit, 4K60, GUI initial input assignment.")

if __name__=="__main__":
    main()

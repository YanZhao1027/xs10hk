#!/usr/bin/env python3
"""Stage38: audit third X6 ARM sections and bounded VPU command candidates.

Strictly OFFLINE and READ-ONLY input. All proprietary sections, payloads,
codec modules, and private Ghidra logs stay in gitignored output/. No camera
USB/PTP/FF80 operations, firmware edits, flash images, or hardware claims.

The superficial XT4 section-3 MOVW #0xBB9 pattern is part of a MOVW/MOVT
pair representing *0xFF000BB9*, the third argument of a different
application-side function; it is NOT evidence of VPU queue consumption.
A bounded MOVW scan is not exhaustive for instructions or alternate cores.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct

SEC1_BASE=0x01021000
COMMAND=0xBB9
EXPECTED_HEVC_SHA="9d986c77d71a57ceefbd6b0bde2668f1a057f6892daff3be0fb4a4a3c5f4441c"
HEVC_LENGTH=0x68000
HEVC_LABEL=b"H.265 MP Encoder"
HEVC_MAGIC=b"\x5e\xeb\x00\x00\x04\x02\x00\x00"+b"56610002"

@dataclass(frozen=True)
class Model:
    model:str
    sec2_base:int
    sec3_base:int
    sec3_entry:int
    sec3_size:int
    sec3_sha:str
    app_function:int
    app_movw_sites:tuple
    app_bl_sites:tuple
    full_arg:int
    arg_caller:int
    arg_wrapper:int
    arg_inner:int
    ui_draw:int
    error_code1:int
    error_code2:int
    other_sec1_movw:tuple
    hevc_file_offset:int
    sec3_log:str
    arg_sink_log:str
    ui_sink_log:str

MODELS={
 "xs10":Model(
  "xs10",0x01eaf000,0x038f7de8,0x038f7df0,0x990000,
  "2625666839fd2fdb7ec92bc4486a5c5d6193441afd6f833f29cf0cf13524c5d7",
  0x0390f03c,(0x0390f0a4,0x0390f124),(0x0390f0b4,0x0390f134),
  0xff000c91,0x0390f03c,0x03928e84,0x03928cb4,0x038f9dac,
  0x1b3,0x1b4,
  (0x01085f8c,0x0109ee44,0x011fad74,0x011faf20),0x02da0000,
  "xs10_stage38_sec3_region_ghidra.log",
  "xs10_stage38_sec3_event_parameter_consumer.log",
  "xs10_stage38_sec3_event_sink_internal.log"),
 "xt4":Model(
  "xt4",0x01e0f000,0x0398a118,0x0398a120,0x9c4000,
  "6c8d7b8b0a37df8c2b636c504c07a80318243b313d5bf435e2c39ef3f56e9f80",
  0x039a16d0,(0x039a1738,0x039a17b8),(0x039a1748,0x039a17c8),
  0xff000bb9,0x039a16d0,0x039bb34c,0x039bb17c,0x0398c0dc,
  0x19d,0x19e,
  (0x01084cb4,0x0109d310,0x011ce420,0x011ce5cc),0x02c40000,
  "xt4_stage38_sec3_misleading_bbb9_ghidra.log",
  "xt4_stage38_sec3_event_parameter_consumer.log",
  "xt4_stage38_sec3_event_sink_internal.log"),
}
HEVC_OFFSETS={"xt3":0x02c60000,"xt4":0x02c40000,"xs10":0x02da0000}

def require(ok,reason):
    if not ok:raise ValueError("Stage38 original-only third section audit: "+reason)

def word(data,base,addr):
    off=addr-base
    require(off>=0 and off%4==0 and off+4<=len(data),
            "A32 read outside section or unaligned")
    return struct.unpack_from("<I",data,off)[0]

def decode_movw(w,reg,top=False):
    mask=0x03400000 if top else 0x03000000
    require((w>>28)==14 and (w&0x0ff00000)==mask and
            ((w>>12)&15)==reg,"MOVW/MOVT wrong variant, condition, or register")
    return (((w>>16)&15)<<12)|(w&0xfff)

def decode_bl(w,pc):
    require((w>>28)==14 and (w&0x0f000000)==0x0b000000,
            "not unconditional A32 BL")
    disp=w&0xffffff
    if disp&0x800000:disp-=0x1000000
    return (pc+8+4*disp)&0xffffffff

def scan_unconditional_movw(data,base,imm):
    """Only aligned, unconditional A32 MOVW words, not reachable-code proof."""
    matches=[]
    for off in range(0,len(data)-3,4):
        w=struct.unpack_from("<I",data,off)[0]
        if (w>>28)==14 and (w&0x0ff00000)==0x03000000:
            val=(((w>>16)&15)<<12)|(w&0xfff)
            if val==imm:matches.append(base+off)
    return tuple(matches)

def ghidra_c(log,pc):
    start=f"STAGE38_C_BEGIN {pc:08x}"
    require(start in log,"missing read-only section3 Ghidra decomp "+start)
    section=log.split(start,1)[1].split("STAGE38_C_END ",1)[0]
    require(section.count("Stage38_probe_")>=1,
            "third-section decomp should be a bounded valid Ghidra function")
    return section

def stage37_baseline(prev,m):
    require(prev["model"]==m.model and
            prev["frame_sender_0xBB9_payload_bytes"]==72 and
            prev["primary_tx_packet_location"]=="W+0x92010" and
            prev["primary_rx_packet_location"]=="W+0x93010" and
            prev["0xBB9_paired_to_0x7D5"]=="UNPROVEN" and
            prev["0xBB9_direct_VPU_hardware_consumer_observed"]==False,
            "stage37 CPU message ring evidence changed")

def validate_third_arm(m,sec1,sec2,sec3,gh,prev):
    stage37_baseline(prev,m)
    require(len(sec3)==m.sec3_size and
            hashlib.sha256(sec3).hexdigest()==m.sec3_sha,
            "third original section SHA256 and expected extent mismatched")
    require(m.sec3_entry==m.sec3_base+8 and
            (word(sec3,m.sec3_base,m.sec3_base)==m.sec3_entry) and
            word(sec3,m.sec3_base,m.sec3_base+4)==0 and
            word(sec3,m.sec3_base,m.sec3_entry)==0xe92d4800 and
            word(sec3,m.sec3_base,m.sec3_entry+4)==0xe28db004,
            "section3 third executable candidate preamble and prologue mismatch")
    target=decode_bl(word(sec3,m.sec3_base,m.sec3_base+0x80),
                     m.sec3_base+0x80)
    require(m.sec3_entry<=target<=m.sec3_base+len(sec3)-4 and
            word(sec3,m.sec3_base,target)&0xffff0000==0xe92d0000,
            "third-section local ARM BL/prologue cross-check invalid")
    out={}
    counts=(scan_unconditional_movw(sec1,SEC1_BASE,COMMAND),
            scan_unconditional_movw(sec2,m.sec2_base,COMMAND),
            scan_unconditional_movw(sec3,m.sec3_base,COMMAND))
    require(counts[0]==m.other_sec1_movw and not counts[1],
            "bounded section1/2 0xBB9 MOVW scan baseline differs")
    require(counts[2]==(m.app_movw_sites if m.model=="xt4" else ()),
            "third-section 0xBB9 candidate count/address differs")

    # Decompile known section3 routines using fresh temporary local Ghidra
    # ARM project, *not* raw linear instruction guessing alone.
    app=ghidra_c(gh["app"],m.app_function)
    outer=ghidra_c(gh["wrapper"],m.arg_wrapper)
    inner=ghidra_c(gh["inner"],m.arg_inner)
    drawing=ghidra_c(gh["drawing"],m.ui_draw)
    for number in (m.error_code1,m.error_code2):
        expect=f"func_0x{m.arg_wrapper:08x}(0x{number:x},0x29,0x{m.full_arg:08x},7);"
        require(expect in app,
                "actual section3 call does not pass full 32-bit argument "+expect)

    for at,blsite in zip(m.app_movw_sites,m.app_bl_sites):
        low=decode_movw(word(sec3,m.sec3_base,at),2)
        high=decode_movw(word(sec3,m.sec3_base,at+4),2,True)
        require(((high<<16)|low)==m.full_arg,
                "false positive MOVW low16 must combine with true MOVT high16")
        require(decode_bl(word(sec3,m.sec3_base,blsite),blsite)==m.arg_wrapper,
                "section3 original BL target does not match Ghidra caller")

    require(f"func_0x{m.arg_inner:08x}();" in outer,
            "third section parameter wrapper does not call service")
    # Nontrivial evidence that the argument flows into an application
    # display/event service with x/y grid operations, NOT into VPU TX reader.
    require("param_3 != 0" in inner and "func_0x" in inner,
            "application side inner dispatch shape mismatch")
    require("(param_1 + -1) * 0x14" in drawing and
            "(param_2 + -1) * 0x18" in drawing,
            "outer parameter flows toward coordinate-scaled display-like routine")
    require("VPU_H265_RSP_CODE_INPUT" not in app and
            "0xbb9,0x48" not in app,
            "third section application service unexpectedly resembles VPU queue")

    return {
      "model":m.model,
      "third_section_size":len(sec3),
      "third_section_candidate_load_base":"0x%08x"%m.sec3_base,
      "third_section_entry_prologue":"ARM STMDB SP!,[register list]",
      "third_section_sha256":m.sec3_sha,
      "third_section_internal_BL_to_ARM_prologue":True,
      "third_section_Ghidra_independent_import_and_decomp":True,
      "aligned_unconditional_MOVW_0xBB9_by_section_1_2_3":
          [len(x) for x in counts],
      "third_section_bare_MOVW_0xBB9_sites":
          ["0x%08x"%v for v in counts[2]],
      "app_function":"0x%08x"%m.app_function,
      "app_function_full_32bit_constant":"0x%08x"%m.full_arg,
      "app_function_full_32bit_parameter_callee":
          "0x%08x"%m.arg_wrapper,
      "app_function_validated_original_ARM_BL_sites":
          ["0x%08x"%v for v in m.app_bl_sites],
      "app_constant_true_VPU_frame_queue_command":False,
      "app_function_calls_coordinate_scaled_event_or_display_like_helpers":True,
      "physical_10bit_or_4K60_inferred":False,
      "hardware_receiver_0xBB9_confirmed":False,
    }

def compare_hevc_modules(payloads):
    """Stage13 three-camera positive-control payload identity and bounded grep."""
    result={}
    digests=[]
    for model in ("xt3","xt4","xs10"):
        raw=payloads[model]
        offset=HEVC_OFFSETS[model]
        require(0<=offset and offset+HEVC_LENGTH<=len(raw),
                "private decoded HEVC payload out of bounds")
        b=raw[offset:offset+HEVC_LENGTH]
        require(b[0x60:0x60+len(HEVC_MAGIC)]==HEVC_MAGIC and
                b[0x70:0x70+len(HEVC_LABEL)]==HEVC_LABEL,
                "HEVC encoder vendor module descriptor signature missing")
        dg=hashlib.sha256(b).hexdigest()
        require(dg==EXPECTED_HEVC_SHA,"HEVC encoder module SHA256 changed")
        digests.append(dg)
        c16=b.count(b"\xb9\x0b")
        c32=b.count(COMMAND.to_bytes(4,"little"))
        hdr=b.count(((72<<16)|COMMAND).to_bytes(4,"little"))
        require((c16,c32,hdr)==(17,0,0),
                "bounded literal scan of known HEVC encoder image changed")
        result[model]={
            "vendor_module_payload_file_offset":"0x%x"%offset,
            "vendor_module_size":len(b),
            "sha256":dg,
            "nonaligned_raw_b9_0b_substring_occurrences":c16,
            "little_endian_exact_u32_0x00000bb9_occurrences":c32,
            "little_endian_exact_u32_0x00480bb9_occurrences":hdr,
        }
    require(len(set(digests))==1,"three-camera module bytes differ")
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    out=ap.parse_args().output
    stage37=json.loads((out/"stage37_vpu_ring_memory_audit.jsonlog").read_text().split(
      "\nSTAGE37 OFFLINE ORIGINAL ARM:")[0])
    results=[]
    for m in MODELS.values():
        gh={
         "app":(out/m.sec3_log).read_text(),
         "wrapper":(out/m.arg_sink_log).read_text(),
         "inner":(out/m.ui_sink_log).read_text(),
         "drawing":(out/m.ui_sink_log).read_text(),
        }
        sec1=(out/f"x6-{m.model}/section-1.bin").read_bytes()
        sec2=(out/f"x6-{m.model}/section-2.bin").read_bytes()
        sec3=(out/f"x6-{m.model}/section-3.bin").read_bytes()
        prev=next(x for x in stage37 if x["model"]==m.model)
        results.append(validate_third_arm(m,sec1,sec2,sec3,gh,prev))
    b={model:(out/f"{model}-payload.bin").read_bytes()
       for model in ("xt3","xt4","xs10")}
    modules=compare_hevc_modules(b)
    print(json.dumps({"third_sections":results,"positive_control_HEVC_encoder_images":modules,
       "boundary":{
        "direct_0xBB9_VPU_coprocessor_receiver_confirmed":False,
        "Main10_SPS_hvcC_or_physical_pixel_depth_identified":False,
        "x_s10_internal_10bit_recording_proven":False,
        "x_s10_internal_4K60_recording_proven":False,
        "camera_contacted_or_firmware_modified":False,
        "other_core_opaque_opcode_decoder_recovered":False,
       }},indent=2,ensure_ascii=False))
    print("STAGE38 OFFLINE ORIGINAL X6 + Ghidra: 3 camera HEVC modules, 2 section3 ARM decomp PASS.")
    print("NO hardware command receiver or physical bitdepth mapping identified.")
if __name__=="__main__":
    main()

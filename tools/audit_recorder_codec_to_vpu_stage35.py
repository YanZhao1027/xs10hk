#!/usr/bin/env python3
"""Stage35 offline X6 audit: ACTIVE Recorder Codec -> movie context -> VPU init.

Original firmware sections and Ghidra logs are PRIVATE to the owner's Ubuntu.
This tool only reads existing files, emits evidence and checks ARM A32 words.
It neither communicates with cameras nor patches firmware.

The key unknowns remain: runtime execution/value and codec/bitdepth enum
mapping, GUI MovieCodec -> Recorder input initial setter, HEVC Main10 SPS,
4K60 readout/ISP/VPU/card bandwidth. Never treat these as unlocked.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct

@dataclass(frozen=True)
class Model:
    name: str
    s2base: int
    active_base: int
    active_codec: int
    active_off: int
    getter: int
    getter_movw: int
    ctor: int
    copy_func: int
    copy_bl: int
    ctor_ctx_add: int
    ctor_getter_bl: int
    ctor_ctx_store: int
    movie_vpu_parent: int
    param_base: int
    param_gate_start: int
    branch_zero: int
    zero_block: int
    wrapper_init: int
    wrapper_init_bl: int
    driver_init: int
    wrapper_inner_init_bl: int
    driver_gate: int
    wrapper_encoder: int
    wrapper_encoder_bl: int
    driver_encoder: int
    wrapper_inner_encoder_bl: int
    enc_src: int
    enc_dest: int
    drv_copy_dest: int
    driver_copy_engine: int
    init_bitdepth_error: int
    init_codec_error: int
    ctor_log: str
    driver_log: str
    bridge_log: str
    getter_log: str
    wrapper_log: str

MODELS={
 "xs10":Model(
  "xs10",0x01eaf000,0x01c24dd8,0x01c25208,0x430,
  0x012c048c,0x012c0494,0x022d5fec,0x012bd150,0x022d61ac,
  0x022d6298,0x022d62a4,0x022d62a8,
  0x022dee64,0x02945a08,0x022def44,0x022df154,0x022df154,
  0x011f7190,0x022df0f8,0x011f97dc,0x011f7330,0x011f97fc,
  0x011f745c,0x022df508,0x011f9b84,0x011f7464,
  0x029459cc,0x019fb67c,0x01c25970,0x00059328,
  0x015b62a8,0x015b6478,
  "xs10_stage35_video_codec_context_writer.log",
  "xs10_stage35_h265_vpu_init_decomp.log",
  "xs10_stage35_h265_vpu_parent_callers.log",
  "xs10_stage35_context_codec_getter.log",
  "xs10_stage35_h265_api_wrapper.log"),
 "xt4":Model(
  "xt4",0x01e0f000,0x01b83540,0x01b83974,0x434,
  0x01298c18,0x01298c20,0x022425bc,0x012957c0,0x0224277c,
  0x02242868,0x02242874,0x02242878,
  0x0224b65c,0x028a5150,0x0224b73c,0x0224b94c,0x0224b94c,
  0x011ca83c,0x0224b8f0,0x011cce88,0x011ca9dc,0x011ccea8,
  0x011cab08,0x0224bc90,0x011cd230,0x011cab10,
  0x028a5114,0x0196b6d0,0x01b840d8,0x00059108,
  0x0158db68,0x0158dd38,
  "xt4_stage35_video_codec_context_writer.log",
  "xt4_stage35_h265_vpu_init_decomp.log",
  "xt4_stage35_h265_vpu_parent_callers.log",
  "xt4_stage35_context_codec_getter.log",
  "xt4_stage35_h265_api_wrapper.log")
}

VALIDATION_7_WORDS=(
  0xe5913188, # LDR  r3,[r1,#0x188] ; init video_codec byte/word enum
  0xe3530000, # CMP  r3,#0
  0x1a000002, # BNE  skip first bit_depth check
  0xe591200c, # LDR  r2,[r1,#0x0c] ; init bit_depth enum
  0xe3520001, # CMP  r2,#1
  0x8a000067, # BHI  bit_depth error
  0xe1c141d0, # LDRD r4,r5,[r1,#0x10] ; next init buffer checks
)

def must(ok,why):
    if not ok:raise ValueError("Stage35 offline VPU audit: "+why)

def word(buf,base,address):
    off=address-base
    if off<0 or off%4 or off+4>len(buf):raise ValueError("bad firmware word address")
    return struct.unpack_from("<I",buf,off)[0]

def rom_ascii(buf,base,address,length):
    k=address-base
    if k<0 or length<=0 or k+length>len(buf):
        raise ValueError("bad original ROM ASCII address")
    return buf[k:k+length]

def movpart(v,reg,upper=False):
    must(v>>28==14 and v&0x0ff00000==(0x03400000 if upper else 0x03000000)
         and v>>12&15==reg,"bad MOVW/MOVT register/variant")
    return ((v>>16&15)<<12)|(v&0xfff)

def decode_bl(v,site):
    must(v>>28==14 and (v>>25)&7==5 and (v>>24)&1==1,
         "expected unconditional A32 BL")
    disp=v&0xffffff
    if disp&0x800000:disp-=0x1000000
    return (site+8+(disp<<2))&0xffffffff

def decode_cond_b(v,site,cond):
    must(v>>28==cond and (v>>25)&7==5 and (v>>24)&1==0,
         "expected correct conditional ARM branch")
    disp=v&0xffffff
    if disp&0x800000:disp-=0x1000000
    return (site+8+(disp<<2))&0xffffffff

def c_function(log,addr):
    marker="FUN_%08x"%addr
    for p in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        body=p.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|byte|char|bool|undefined\d+)"
                     r"\s+(?:\*\s*)?"+marker+r"\s*\(",body):
            return body
    raise ValueError("Ghidra C function missing "+marker)

def audit(s,raw1,raw2,logs,phase32,phase33,phase34):
    w1=lambda at:word(raw1,0x01021000,at)
    w2=lambda at:word(raw2,s.s2base,at)
    must(phase32["model"]==s.name and
         phase32["input_to_active_static_data_flow_edges_proven"] is True and
         phase32["active_Recorder_Codec_byte"]=="0x%08x"%s.active_codec,
         "prior Phase32 input->active baseline invalid")
    must(phase33["model"]==s.name and
         phase33["movie_context_codec_offset"]==
            ("0x9d8" if s.name=="xs10" else "0x9dc") and
         phase33["codec_control_if_byte_equals_1"]=="0x10004" and
         phase33["codec_control_otherwise"]=="0x10005",
         "Phase33 independent movie context control path baseline invalid")
    must(phase34["model"]==s.name and
         phase34["static_struct_pointer_registration_proven"] is True,
         "Phase34 backend pointer registration baseline invalid")
    must(s.active_base+s.active_off==s.active_codec,"active Codec arithmetic differs")

    getter=c_function(logs["getter"],s.getter)
    must(("return DAT_%08x;"%s.active_codec) in getter,
         "active Codec getter target identity differs")
    start=s.getter_movw
    got_base=movpart(w1(start),3)|(movpart(w1(start+4),3,True)<<16)
    must(got_base==s.active_base and
         w1(start+8)==(0xe5d30000|s.active_off),
         "original A32 active Codec MOVW/MOVT/LDRB mismatch")
    ctx=c_function(logs["context"],s.ctor)
    copy_text="FUN_%08x(iVar8);"%s.copy_func
    getter_text="FUN_%08x();"%s.getter
    must(copy_text in ctx and getter_text in ctx and
         "*(undefined1 *)(iVar8 + 0xadda) = uVar4;" in ctx,
         "movie context copy and direct Codec byte STORE absent")
    must(ctx.index(copy_text)<ctx.index(getter_text)<
         ctx.index("*(undefined1 *)(iVar8 + 0xadda) = uVar4;"),
         "context copy / active getter / context write order differs")
    must(decode_bl(w2(s.copy_bl),s.copy_bl)==s.copy_func,
         "movie context active-template copy BL mismatch")
    must(w2(s.ctor_ctx_add)==0xe2845a0a and
         w2(s.ctor_ctx_store)==0xe5c50dda and
         decode_bl(w2(s.ctor_getter_bl),s.ctor_getter_bl)==s.getter,
         "A32 ctx+0xADDA active Codec store and getter call mismatch")

    parent=c_function(logs["parent"],s.movie_vpu_parent)
    must("*(char *)(param_1 + 0xadda) == '\\x01'" in parent and
         "bVar9 =" in parent,
         "movie application Codec comparison not found")
    for text in ("_DAT_%08x = 1;"%(s.param_base+0xc),
                 "_DAT_%08x = (uint)!bVar9;"%(s.param_base+0x188),
                 "FUN_%08x(0,&DAT_%08x,"%(s.wrapper_init,s.param_base),
                 "FUN_%08x(&DAT_%08x,"%(s.wrapper_encoder,s.enc_src)):
        must(text in parent,"VPU init/enc parameters not linked in movie setup: "+text)
    must(parent.index("_DAT_%08x = 1;"%(s.param_base+0xc)) <
         parent.index("FUN_%08x(0,&DAT_%08x,"%(s.wrapper_init,s.param_base)),
         "bitdepth constant not written before driver init")
    must(parent.index("_DAT_%08x = (uint)!bVar9;"%(s.param_base+0x188)) <
         parent.index("FUN_%08x(0,&DAT_%08x,"%(s.wrapper_init,s.param_base)),
         "video_codec enum not written before driver init")
    must(parent.index("FUN_%08x(0,&DAT_%08x,"%(s.wrapper_init,s.param_base)) <
         parent.index("FUN_%08x(&DAT_%08x,"%(s.wrapper_encoder,s.enc_src)),
         "VPU init and encoder-param setup order inconsistent")

    # Both main code paths: codec byte 1 is normalized to VPU enum zero;
    # other Codec byte values normalize to one. The bitdepth field is
    # explicitly initialized with one in BOTH models (not known as 10-bit).
    p=s.param_gate_start
    expected_base=movpart(w2(p),3)|(movpart(w2(p+4),3,True)<<16)
    must(expected_base==s.param_base,"VPU parameter struct base MOVW/MOVT")
    expected={
      8:0xe3a02001, 12:0xe583200c, 16:0xe2853a0a,20:0xe5d33dda,
      24:0xe1530002,32:None,36:None,40:0xe3a02001,
      44:0xe5832188
    }
    for off,expected_word in expected.items():
        if expected_word is not None:
            must(w2(p+off)==expected_word,
                 "VPU parent A32 Codec/bitdepth assignment +0x%x"%off)
    must(decode_cond_b(w2(p+28),p+28,0)==s.branch_zero,
         "VPU enum zero branch not gated by active Codec ==1")
    zero=s.zero_block
    must((movpart(w2(zero),3)|(movpart(w2(zero+4),3,True)<<16))==s.param_base,
         "video_codec zero block points at different VPU parameter")
    must(w2(zero+8)==0xe3a02000 and w2(zero+12)==0xe5832188,
         "video_codec zero branch does not STR zero to +0x188")

    for call,target in (
       (s.wrapper_init_bl,s.wrapper_init),
       (s.wrapper_encoder_bl,s.wrapper_encoder),
       (s.wrapper_inner_init_bl,s.driver_init),
       (s.wrapper_inner_encoder_bl,s.driver_encoder)):
        block=w2 if call>=s.s2base else w1
        must(decode_bl(block(call),call)==target,
             "original movie driver / API BL destination mismatch")
    wrapper1=c_function(logs["wrapper"],s.wrapper_init)
    wrapper2=c_function(logs["wrapper"],s.wrapper_encoder)
    must("FUN_%08x();"%s.driver_init in wrapper1 and
         "FUN_%08x();"%s.driver_encoder in wrapper2,
         "driver wrapper no longer invokes expected driver implementation")

    drv=c_function(logs["driver"],s.driver_init)
    must("(*(uint *)(param_2 + 0x188) == 0) && (1 < *(uint *)(param_2 + 0xc))"
         in drv and
         "if (1 < *(uint *)(param_2 + 0x188))" in drv,
         "bit_depth/video_codec driver C validation no longer matched")
    must(("func_0x%08x(&DAT_%08x,param_2,400);"%
         (s.driver_copy_engine,s.drv_copy_dest)) in drv,
         "VPU driver does not copy 400-byte init structure")
    for i,v in enumerate(VALIDATION_7_WORDS):
        must(w1(s.driver_gate+4*i)==v,
             "seven original A32 bit_depth/codec branch words changed")
    for addr,needle in ((s.init_bitdepth_error,b"#init bit_depth ERROR"),
                        (s.init_codec_error,b"#init video_codec ERROR")):
        must(rom_ascii(raw1,0x01021000,addr,len(needle))==needle,
             "VPU original diagnostic string bytes missing")

    enc=c_function(logs["driver"],s.driver_encoder)
    must("if (param_2 == 0)" in enc and
         "*(int" not in enc[:5] and
         ("_DAT_%08x = *param_1;"%s.enc_dest) in enc and
         ("_DAT_%08x = param_1[0xe];"%(s.enc_dest+0x38)) in enc,
         "encoder parameter driver 15-word input struct unexpected")
    must(s.enc_src+0x38==s.param_base-0x04,
         "encoder parameter source field layout invalid")

    return {
        "model":s.name,
        "active_Recorder_Codec_byte":"0x%08x"%s.active_codec,
        "active_byte_getter":"FUN_%08x"%s.getter,
        "movie_context_active_codec_offset":"0xADDA",
        "movie_context_constructor":"FUN_%08x"%s.ctor,
        "movie_context_active_template_copy_and_getter_in_order":True,
        "VPU_movie_setup_function":"FUN_%08x"%s.movie_vpu_parent,
        "VPU_init_parameter_struct":"0x%08x"%s.param_base,
        "VPU_bit_depth_field_offset":"0x0C",
        "VPU_bit_depth_enum_written_by_movie_setup":1,
        "VPU_video_codec_field_offset":"0x188",
        "VPU_video_codec_when_active_Codec_byte_is_1":0,
        "VPU_video_codec_when_active_Codec_byte_is_not_1":1,
        "VPU_init_wrapper":"FUN_%08x"%s.wrapper_init,
        "VPU_driver_init":"FUN_%08x"%s.driver_init,
        "VPU_driver_conditional_reject_bitdepth_gt1_if_codec0":True,
        "VPU_driver_reject_video_codec_enum_gt1":True,
        "VPU_original_validation_ARM_words":len(VALIDATION_7_WORDS),
        "original_subroutine_BL_targets_checked":6,
        "VPU_driver_init_copy_bytes":400,
        "VPU_encoder_param_setup_function":"FUN_%08x"%s.driver_encoder,
        "encoder_param_words_written_to_internal_RAM":15,
        "independent_movie_param_0x10004_0x10005_path_from_same_active_codec":True,
        "both_context_fields_equal_in_unobserved_runtime":False,
        "actual_bitdepth_enum_1_means_10bit": "UNKNOWN",
        "actual_0_1_VPU_codec_enum_to_H264_H265_mapping":"UNKNOWN",
        "VPU_driver_runtime_executed_or_bitstream_captured":False,
        "GUI_to_Recorder_input_initial_assignment_proven":False,
        "HEVC_Main10_SPS_bitdepth_proven":False,
        "internal_4K60_proven":False,
        "camera_touched":False,
    }

def main():
    arg=argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--output",type=Path,default=Path("output"))
    o=arg.parse_args().output
    p32=json.loads((o/"stage32_codec_forward_audit_result.jsonlog").read_text().split(
        "\nORIGINAL OFFLINE ARM:")[0])
    p33=json.loads((o/"stage33_movie_context_audit_result.jsonlog").read_text().split(
        "\nStage33 is READ-ONLY")[0])
    p34=json.loads((o/"stage34_backend_pointer_audit_result.jsonlog").read_text().split(
        "\nSTAGE34 OFFLINE:")[0])["models"]
    results=[]
    for m in MODELS.values():
        logs={
          "context":(o/m.ctor_log).read_text(),
          "driver":(o/m.driver_log).read_text(),
          "parent":(o/m.bridge_log).read_text(),
          "getter":(o/m.getter_log).read_text(),
          "wrapper":(o/m.wrapper_log).read_text(),
        }
        results.append(audit(
          m,(o/f"x6-{m.name}/section-1.bin").read_bytes(),
          (o/f"x6-{m.name}/section-2.bin").read_bytes(),
          logs,
          next(p for p in p32 if p["model"]==m.name),
          next(p for p in p33 if p["model"]==m.name),
          next(p for p in p34 if p["model"]==m.name)
        ))
    must(all(x["VPU_bit_depth_enum_written_by_movie_setup"]==1 for x in results),
         "cross-model bit_depth enum value differs")
    must(all(x["VPU_video_codec_when_active_Codec_byte_is_1"]==0 for x in results),
         "cross-model active Codec inversion differs")
    print(json.dumps(results,indent=2,ensure_ascii=False))
    print("STAGE35 OFFLINE: ACTIVE Codec -> movie ctx -> VPU codec enum static path proved.")
    print("UNKNOWN: internal enum physical bitdepth/profile, runtime use, Main10, 4K60.")

if __name__=="__main__":main()

#!/usr/bin/env python3
"""Phase36 original-ROM A32 evidence audit, strictly read-only and offline.

Trace Recorder Codec -> VPU initialization: cached bit_depth / video_codec
-> VPU initialization packet +0x0c/+0x190 -> frame descriptor format choice
0x201 or 0x121 -> frame buffer message queue 0xbb9.

This does NOT map enum values to physical bit depth (8/10-bit), observe an
actual camera, capture HEVC Main10 SPS, or prove internal 4K60 recording.
No USB or firmware writes. ROMs and private Ghidra logs remain in output/.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct

ROM_SECTION1_BASE = 0x01021000
NORMAL_WORDS = (
    0xe5943188,  # LDR r3,[r4,#0x188] codec enum
    0xe3530000,  # CMP r3,#0
    None,        # MOVWEQ r3,#cached init-structure low half (model specific)
    0x01a03004,  # CPYEQ r3,r4
    0x0593300c,  # LDREQ r3,[r3,#0x0c] bit depth enum
    0x13a03001,  # MOVNE r3,#1
    0xe582300c,  # STR r3,[r2,#0x0c] VPU init packet
)
CODEC_FORWARD_WORDS = (0xe5942188, 0xe5832190)
FORMAT_0_WORDS = (0xe3001201, 0xe1c211b8)  # MOVW #0x201; STRH +0x18
FORMAT_NONZERO_WORDS = (0xe3001121, 0xe1c211b8)  # MOVW #0x121; STRH
STRIDE_0_WORDS = (0xe5931008, 0xe5821034, 0xe5933008, 0xe5823038)
STRIDE_NONZERO_WORDS = (0xe5933008, 0xe1a03103, 0xe5823034)

@dataclass(frozen=True)
class Model:
    name: str
    cached_init: int
    packet_ptr_slot: int
    frame_packet_ptr_slot: int
    state_global: int
    assembler: int
    assemble_bitdepth_site: int
    assemble_codec_site: int
    state_dispatcher: int
    state_assembly_bl: int
    frame_builder: int
    frame_branch_base: int
    format_zero_site: int
    format_nonzero_site: int
    stride_zero_site: int
    stride_nonzero_site: int
    encoder_param_state: int
    decoder_param_state: int
    encoder_frame_builder_bl: int
    decoder_frame_builder_bl: int
    send_frame: int
    frame_send_enc: int
    frame_send_dec: int
    ring_send_enc_bl: int
    ring_send_dec_bl: int
    packet_ring_encoder: int
    packet_ring_decoder: int
    init_field_refs: str
    bitdepth_ptr_refs: str
    assembler_log: str
    dispatcher_log: str
    frame_builder_log: str
    encoder_decoder_log: str

MODELS = {
  "xs10":Model(
    "xs10",0x01c25970,0x01c8573c,0x01b8809c,0x0182197c,
    0x011f8460,0x011f8598,0x011f87a4,
    0x011f93dc,0x011f944c,0x011fab58,
    0x011fab78,0x011fab9c,0x011fabfc,
    0x011fabb4,0x011fac14,0x011f8914,0x011f89f0,
    0x011f898c,0x011f8a50,0x011fac24,
    0x011fa714,0x011fa844,
    0x011fad78,0x011faf28,0x011fa714,0x011fa844,
    "xs10_stage36_vpu_init_fields_xrefs.log",
    "xs10_stage36_vpu_bitdepth_packet_consumers.log",
    "xs10_stage36_vpu_field_consumers_trace.log",
    "xs10_stage36_vpu_event_init_and_packet_transport.log",
    "xs10_stage36_frame_packet_bitdepth_branch.log",
    "xs10_stage36_vpu_frame_desc_send_callsite.log"
  ),
  "xt4":Model(
    "xt4",0x01b840d8,0x01be5808,0x01af2804,0x01790d8c,
    0x011cbb0c,0x011cbc44,0x011cbe50,
    0x011cca88,0x011ccaf8,0x011ce204,
    0x011ce224,0x011ce248,0x011ce2a8,
    0x011ce260,0x011ce2c0,0x011cbfc0,0x011cc09c,
    0x011cc038,0x011cc0fc,0x011ce2d0,
    0x011cddc0,0x011cdef0,
    0x011ce424,0x011ce5d4,0x011cddc0,0x011cdef0,
    "xt4_stage36_vpu_init_fields_xrefs.log",
    "xt4_stage36_vpu_bitdepth_packet_consumers.log",
    "xt4_stage36_vpu_field_consumers_trace.log",
    "xt4_stage36_vpu_event_init_and_packet_transport.log",
    "xt4_stage36_frame_packet_bitdepth_branch.log",
    "xt4_stage36_vpu_frame_desc_send_callsite.log"
  ),
}

def require(condition, reason):
    if not condition:
        raise ValueError("Stage36 VPU enum packet audit: " + reason)

def read_word(rom, addr):
    offset = addr-ROM_SECTION1_BASE
    require(offset>=0 and offset%4==0 and offset+4<=len(rom),
            "out-of-range original ROM instruction")
    return struct.unpack_from("<I", rom, offset)[0]

def decode_bl(inst, address):
    require(inst>>28==14 and inst&0x0f000000==0x0b000000,
            "expected unconditional A32 BL")
    relative=inst&0xffffff
    if relative & 0x800000:relative-=0x1000000
    return (address+8+relative*4)&0xffffffff

def decode_branch(inst, address, condition):
    require(inst>>28==condition and inst&0x0f000000==0x0a000000,
            "wrong A32 branch condition or opcode")
    relative=inst&0xffffff
    if relative & 0x800000:relative-=0x1000000
    return (address+8+relative*4)&0xffffffff

def decode_movw(inst, dst_register=3,condition=14):
    require(inst>>28==condition and inst&0x0ff00000==0x03000000
            and (inst>>12)&15==dst_register,
            "A32 MOVW condition/target mismatch")
    return ((inst>>16)&15)<<12 | (inst&0xfff)

def decode_movt(inst, dst_register=3,condition=14):
    require(inst>>28==condition and inst&0x0ff00000==0x03400000
            and (inst>>12)&15==dst_register,
            "A32 MOVT condition/target mismatch")
    return ((inst>>16)&15)<<12 | (inst&0xfff)

def extract_c(log, address):
    name="FUN_%08x"%address
    for chunk in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=chunk.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|bool)\s+"+
                     re.escape(name)+r"\s*\(", c):
            return c
    raise ValueError("Missing Ghidra C for "+name)

def static_effective_depth(video_codec_enum,bit_depth_enum):
    """A32-derived normalization for any VALID codec enum (0 or 1)."""
    require(video_codec_enum in (0,1),"video_codec enum outside verified domain")
    return bit_depth_enum if video_codec_enum==0 else 1

def static_frame_code(effective_depth):
    """A32-derived conditional frame descriptor code, *not* 8/10-bit mapping."""
    return 0x201 if effective_depth==0 else 0x121

def audit_model(m, read, c, refs, prev):
    require(prev["model"]==m.name and
            prev["VPU_bit_depth_enum_written_by_movie_setup"]==1 and
            prev["VPU_video_codec_when_active_Codec_byte_is_1"]==0 and
            prev["VPU_video_codec_when_active_Codec_byte_is_not_1"]==1 and
            prev["VPU_driver_init_copy_bytes"]==400 and
            not prev["HEVC_Main10_SPS_bitdepth_proven"],
            "prior stage35 original bitdepth / codec assignment invalid")
    depth=m.cached_init+0x0c
    codec=m.cached_init+0x188
    rs=refs["global"]
    require("PROBE_TARGET addr=%08x refs=1"%depth in rs and
            "PROBE_TARGET addr=%08x refs=3"%codec in rs,
            "cached bitdepth/codec xref ground truth missing")
    ptr=refs["pointer"]
    require("VPU_PTR_TARGET %08x refs=55 funcs=17"%m.packet_ptr_slot in ptr,
            "VPU packet pointer xref baseline differs")
    require("VPU_BITDEPTH_CONTEXT %08x"%m.frame_builder in ptr and
            "VPU_BITDEPTH_CONTEXT %08x"%m.send_frame in ptr,
            "both VPU frame descriptor consumers not confirmed")

    # The init state handler calls the 0x298-byte shared packet builder.
    dispatch=c["state"]
    for label,num,fn in (("init",1,m.assembler),
                         ("encoder",2,m.encoder_param_state),
                         ("decoder",3,m.decoder_param_state)):
        txt="FUN_%08x();"%fn
        require(("== %d"%num) in dispatch and txt in dispatch,
                "VPU %s state dispatcher mismatched"%label)
    require(decode_bl(read(m.state_assembly_bl),m.state_assembly_bl)==m.assembler,
            "VPU state=1 packet-assembly BL target")

    asm=c["assemble"]
    checks=[
        "FUN_%08x(_DAT_%08x,0,0x298);"%
            (0x011fcb5c if m.name=="xs10" else 0x011d0208,m.packet_ptr_slot),
        "uVar2 = _DAT_%08x;"%depth,
        "if (_DAT_%08x != 0) {"%codec,
        "uVar2 = 1;",
        "puVar3[3] = uVar2;",
        "puVar3[100] = _DAT_%08x;"%codec,
    ]
    for k in checks:
        require(k in asm,"VPU packet bitdepth normalization C mismatch: "+k)
    require(asm.index("uVar2 = _DAT_%08x;"%depth) <
            asm.index("if (_DAT_%08x != 0) {"%codec) <
            asm.index("puVar3[3] = uVar2;") <
            asm.index("puVar3[100] = _DAT_%08x;"%codec),
            "VPU packet bitdepth normalized/codec exported in wrong order")
    w=[read(m.assemble_bitdepth_site+4*i) for i in range(7)]
    for i,expected in enumerate(NORMAL_WORDS):
        if expected is not None:
            require(w[i]==expected,
                    "A32 normalize bitdepth: instruction %d changed"%i)
    require(decode_movw(w[2],3,0)==m.cached_init&0xffff,
            "A32 conditional MOVWEQ cached bitdepth pointer mismatch")
    for i,val in enumerate(CODEC_FORWARD_WORDS):
        require(read(m.assemble_codec_site+i*4)==val,
                "A32 VPU payload codec forward +0x190 mismatch")

    builder=c["frame"]
    form="FUN_%08x(_DAT_%08x,0,0x48);"%(0x011fcb5c if m.name=="xs10"
                                            else 0x011d0208,m.frame_packet_ptr_slot)
    require(form in builder and
            "if (_DAT_%08x[3] == 0) {"%m.packet_ptr_slot in builder,
            "frame descriptor constructor, size and condition unknown")
    for value in (0x201,0x121):
        require("= 0x%x;"%value in builder,
                "frame descriptor branch code 0x%x missing"%value)
    require("*(undefined4 *)(iVar1 + 0x34) = puVar2[2];" in builder and
            "*(undefined4 *)(iVar1 + 0x38) = puVar2[2];" in builder and
            "*(undefined4 *)(iVar1 + 0x34) = puVar2[2] << 2;" in builder,
            "0 vs nonzero frame stride/header structure mismatch")
    p=m.frame_branch_base
    frameptr=(decode_movw(read(p),3)|(decode_movt(read(p+4),3)<<16))
    require(frameptr==m.packet_ptr_slot and
            read(p+8)==0xe5933000 and read(p+12)==0xe593200c and
            read(p+16)==0xe3520000,
            "A32 frame descriptor reads same VPU packet +0xc")
    require(decode_branch(read(p+20),p+20,1)==m.format_nonzero_site-0x0c,
            "A32 BNE must select nonzero depth frame builder branch")
    for site,words,label in ((m.format_zero_site,FORMAT_0_WORDS,"0x201"),
                             (m.format_nonzero_site,FORMAT_NONZERO_WORDS,"0x121"),
                             (m.stride_zero_site,STRIDE_0_WORDS,"zero stride"),
                             (m.stride_nonzero_site,STRIDE_NONZERO_WORDS,
                              "nonzero stride")):
        for i,expected in enumerate(words):
            require(read(site+4*i)==expected,
                    "A32 frame %s instruction %d changed"%(label,i))

    for site,parent in ((m.encoder_frame_builder_bl,m.encoder_param_state),
                        (m.decoder_frame_builder_bl,m.decoder_param_state)):
        require(decode_bl(read(site),site)==m.frame_builder,
                "original A32 encoder/decoder frame-builder call target changed")
    require("if (iVar2 == 0)" in c["encode"] and
            "FUN_%08x();"%m.frame_builder in c["encode"] and
            "FUN_%08x();"%m.frame_builder in c["decode"],
            "encoded/decoded driver state branches or packet preparation absent")
    # This describes the *static* message-buildup and send mechanism, not an
    # observation of a real VPU response nor proof any specific bit depth.
    sender=c["send"]
    for fn in (m.packet_ring_encoder,m.packet_ring_decoder):
        require("FUN_%08x"%fn in sender,
                "frame ring sender call absent: FUN_%08x"%fn)
    require(sender.count("0xbb9,0x48")>=2 and
            ("_DAT_%08x"%m.frame_packet_ptr_slot) in sender,
            "same 0x48 frame descriptor used in 0xBB9 ring messages unproven")
    for site,target in ((m.ring_send_enc_bl,m.packet_ring_encoder),
                        (m.ring_send_dec_bl,m.packet_ring_decoder)):
        require(decode_bl(read(site),site)==target,
                "VPU frame packet queue ARM BL mismatch")
    # For Stage35 movie setup, both codec enums normalize depth=1. Thus the
    # 0x201 branch exists in generic driver, but is NOT selected by this
    # unchanged movie-init path. Concurrency/other branches not investigated.
    effective_by_codec=[static_effective_depth(codec_enum,1) for codec_enum in (0,1)]
    require(effective_by_codec==[1,1] and static_frame_code(1)==0x121,
            "derived guarded movie-setup depth/format invariant changed")
    return {
      "model":m.name,
      "VPU_driver_cached_bitdepth_global":"0x%08x"%depth,
      "VPU_driver_cached_video_codec_global":"0x%08x"%codec,
      "VPU_init_packet_ptr_slot":"0x%08x"%m.packet_ptr_slot,
      "VPU_init_packet_builder":"FUN_%08x"%m.assembler,
      "VPU_init_packet_bytes_cleared":0x298,
      "VPU_init_packet_effective_bitdepth_word_offset":"0x0c",
      "VPU_init_packet_codec_word_offset":"0x190",
      "effective_bitdepth_when_video_codec_0":"saved_bit_depth",
      "effective_bitdepth_when_video_codec_1":1,
      "VPU_frame_descriptor_builder":"FUN_%08x"%m.frame_builder,
      "VPU_frame_descriptor_ptr_slot":"0x%08x"%m.frame_packet_ptr_slot,
      "VPU_frame_descriptor_bytes_cleared":0x48,
      "frame_format_code_if_effective_depth_0":"0x201",
      "frame_format_code_if_effective_depth_nonzero":"0x121",
      "frame_depth0_stride_from_VPU_init_word2":"direct into +0x34 and +0x38",
      "frame_nonzero_stride_from_VPU_init_word2":"shift left 2 into +0x34",
      "VPU_frame_descriptor_consumed_by_both_encoder_decoder_param_branches":True,
      "frame_send_command":"0x0bb9",
      "frame_send_payload_bytes":0x48,
      "VPU_static_movie_path_bitdepth_init_enum":1,
      "VPU_static_movie_path_effective_depth_by_codec_enum_0_1":effective_by_codec,
      "VPU_static_movie_path_frame_code_if_no_intervening_writes":"0x121",
      "VPU_state1_builder_direct_BL_verified":True,
      "frame_packet_encoder_decoder_BL_verified":True,
      "frame_message_ring_BL_verified":True,
      "A32_normalization_words_checked":len(NORMAL_WORDS),
      "A32_frame_format_and_stride_words_checked":sum(map(len,(
          FORMAT_0_WORDS,FORMAT_NONZERO_WORDS,STRIDE_0_WORDS,STRIDE_NONZERO_WORDS))),
      "Ghidra_packet_ptr_refs":55,
      "Ghidra_packet_ptr_referencing_functions":17,
      "physical_bitdepth_enum_0_1_mapping":"UNKNOWN",
      "descriptor_0x201_0x121_pixel_format_mapping":"UNKNOWN",
      "VPU_hardware_acceptance_or_SPS_proven":False,
      "HEVC_Main10_internal_recording_unlocked":False,
      "internal_4K60_unlocked":False,
      "GUI_to_Recorder_input_initial_assignment_proven":False,
      "camera_touched":False,
    }

def compare_full_frame_builders(rom_xs,rom_xt,xs,xt):
    """Compare complete 204-byte original ROM frame descriptor builder bodies.

    Of 51 four-byte words, 12 model-dependent words must ONLY be the
    MOVW/MOVT literals constructing packet-pointer/descriptor-pointer slots.
    No physical 8/10-bit mapping is inferred from identical branch logic.
    """
    expected_diff=(0x08,0x0c,0x20,0x24,0x38,0x3c,
                   0x6c,0x70,0x78,0x7c,0x98,0x9c)
    n=204//4
    x=[read_word(rom_xs,xs.frame_builder+4*i) for i in range(n)]
    y=[read_word(rom_xt,xt.frame_builder+4*i) for i in range(n)]
    actual_diff=tuple(4*i for i,(u,v) in enumerate(zip(x,y)) if u!=v)
    require(actual_diff==expected_diff,
            "original 204-byte complete frame descriptor fingerprint changed")
    # All differing instructions must be a 32-bit address literal pair;
    # explicitly verify destination register and both low/high halves.
    pairs=((0x08,3,"frame_packet_ptr_slot"),
           (0x20,3,"packet_ptr_slot"),
           (0x38,2,"frame_packet_ptr_slot"),
           (0x6c,3,"packet_ptr_slot"),
           (0x78,3,"frame_packet_ptr_slot"),
           (0x98,2,"frame_packet_ptr_slot"))
    for offset,reg,field in pairs:
        i=offset//4
        for model,words in ((xs,x),(xt,y)):
            val=getattr(model,field)
            require(decode_movw(words[i],reg)==(val&0xffff) and
                    decode_movt(words[i+1],reg)==(val>>16),
                    "model-specific frame function differences are not just"
                    " address-literal MOVW/MOVT register pairs")
    return {"full_frame_builder_ARM_word_count":n,
            "cross_model_identical_ARM_words":n-len(actual_diff),
            "cross_model_MOVW_MOVT_address_only_differences":len(actual_diff),
            "frame_function_byte_count":204}


def read_private_decomp(o,m):
    logs={
      "assemble":(o/m.assembler_log).read_text(),
      "state":(o/m.dispatcher_log).read_text(),
      "frame":(o/m.frame_builder_log).read_text(),
      "encode":(o/m.encoder_decoder_log).read_text(),
    }
    return {
      "assemble":extract_c(logs["assemble"],m.assembler),
      "state":extract_c(logs["state"],m.state_dispatcher),
      "frame":extract_c(logs["frame"],m.frame_builder),
      "encode":extract_c(logs["encode"],m.encoder_param_state),
      "decode":extract_c(logs["encode"],m.decoder_param_state),
      "send":extract_c(logs["frame"],m.send_frame),
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    o=p.parse_args().output
    stage35=json.loads((o/"stage35_codec_to_vpu_audit_result.jsonlog").read_text().split(
       "\nSTAGE35 OFFLINE:")[0])
    items=[]
    for m in MODELS.values():
        original=(o/f"x6-{m.name}/section-1.bin").read_bytes()
        c=read_private_decomp(o,m)
        refs={"global":(o/m.init_field_refs).read_text(),
              "pointer":(o/m.bitdepth_ptr_refs).read_text()}
        baseline=next(x for x in stage35 if x["model"]==m.name)
        result=audit_model(m,lambda a:read_word(original,a),c,refs,baseline)
        items.append(result)
    fingerprint=compare_full_frame_builders(
       (o/"x6-xs10/section-1.bin").read_bytes(),
       (o/"x6-xt4/section-1.bin").read_bytes(),
       MODELS["xs10"],MODELS["xt4"])
    for x in items:x.update(fingerprint)
    require(items[0]["VPU_static_movie_path_effective_depth_by_codec_enum_0_1"] ==
            items[1]["VPU_static_movie_path_effective_depth_by_codec_enum_0_1"] ==
            [1,1],"cross-model normalization invariant mismatch")
    require(items[0]["frame_format_code_if_effective_depth_0"]==
            items[1]["frame_format_code_if_effective_depth_0"]=="0x201",
            "cross-model zero-format code mismatch")
    print(json.dumps(items,indent=2,ensure_ascii=False))
    print("STAGE36 ORIGINAL READ-ONLY ARM: both models PASS.")
    print("NO mapping to physical bit-depth, HEVC Main10 SPS or 4K60; no camera.")
if __name__=="__main__":
    main()

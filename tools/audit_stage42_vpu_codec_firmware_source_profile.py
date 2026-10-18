#!/usr/bin/env python3
"""Stage42 read-only original ARM audit: HEVC-vs-H264 firmware source identity.

Compare X-S10 3.11 and X-T4 2.12 original X6 ARM section1+2 with the
independently hashed V61 HEVC/H264 encoder *image boundaries* from Stage40,
Stage41 public MVE protocol ABI and original 11 direct send-message caller refs.

No private Fuji ROM bytes/images/Ghidra log contents are shipped here. Original
files remain only in the authorized Ubuntu gitignored output/ directory.
No camera connection, no USB/FF80, no physical RAM/flash read or write,
no firmware modification, patch, bypass or Main10/4K60 unlock claim.

Important: calls to FUN_012A8514 / FUN_01280C14 with size 0x39000 use a
low-level system service func_00058600; do NOT call it verified memcpy.
The static selection sets the VPU init packet firmware *source pointer*.
Correlating runtime source pointers with decoded payload file offsets via the
same constant difference for HEVC and H264 is strong *layout correlation*,
NOT an independently proven global file-to-runtime loader mapping.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import argparse
import json
import re
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage40_v61_hevc_image_boundaries as st40
import audit_stage41_mve_v61_protocol_abi as st41

ROM1_BASE=0x01021000
FUJI_HEVC_ENCODER_FW_ADDR=0x00CA0000
FUJI_H264_ENCODER_FW_ADDR=0x00D08000
MVE_FW_REGION_BYTES=0x39000
MVE_FRAME_BITSTREAM=3002
PUBLIC_PROFILE_LEVEL_INDEX=3
PUBLIC_HEVC_MAIN10_PROFILE_ENUM=4
# Encoded public ABI features are independent of actual camera acceptance.
EXPECTED_SET_OPTION_INDICES=(1,16,38,1,5)
UNPROVEN={
 "V61_proprietary_microcode_disassembled":False,
 "V61_0xBB9_receiver_verified":False,
 "runtime_camera_codec_selection_observed":False,
 "MVE_PROFILE_LEVEL_option3_ever_sent_proven":False,
 "Fuji_HEVC_Main10_profile_enum4_sent_proven":False,
 "Fuji_Main10_SPS_or_hvcC_recording_proven":False,
 "X_S10_4K60_recording_proven":False,
 "camera_connected_or_USB_FF80_or_flash_modified":False,
 "all_indirect_or_alternate_VPU_message_paths_excluded":False,
}

@dataclass(frozen=True)
class Camera:
    name:str
    section2_base:int
    section2_sha256:str
    movie_func:int
    movie_rom_codec_load:int
    movie_rom_codec_cmp:int
    movie_rom_beq:int
    h264_codec_store:int
    h264_ptr_low:int
    h264_ptr_high:int
    h264_ptr_store:int
    hevc_branch:int
    hevc_codec_store:int
    hevc_ptr_low:int
    hevc_ptr_high:int
    hevc_ptr_store:int
    fw_address_api_bl:int
    fw_address_api:int
    vpu_params_base:int
    vpu_option_sender:int
    option_caller_log:str
    option_function:int
    option_function_log:str
    header_sender:int
    header_c_log:str
    header_codecload:int
    header_codec_cmp:int
    header_count2:int
    header_count3:int
    header2_codecload:int
    header2_codec_cmp:int
    header2_count2:int
    header2_count3:int
    header_bitstream_mov:int
    header_bitstream_bl:int
    header_ring_write:int
    job_sender:int
    job_bl:int
    movie_loader_log:str

CAMERAS={
 "xs10":Camera(
   "xs10",0x01eaf000,
   "f0c4db782031a81c620d764317ebf0219d10bb4b52eb4fd5998b9ce39c3afb8c",
   0x022dee64,0x022def58,0x022def5c,0x022def60,
   0x022def70,0x022def74,0x022def78,0x022def7c,
   0x022df154,0x022df160,0x022df164,0x022df168,0x022df16c,
   0x022df078,0x012a8514,0x02945a08,
   0x011fa530,"xs10_stage42_mve_sender_refs.log",
   0x011fb758,"xs10_vpu_setoptions.log",
   0x011fb3b8,"xs10_stage42_profile_module_selection_decomp.log",
   0x011fb448,0x011fb44c,0x011fb450,0x011fb454,
   0x011fb4f4,0x011fb4f8,0x011fb4fc,0x011fb500,
   0x011fb490,0x011fb494,0x011fa844,
   0x011fb590,0x011fb5b8,
   "xs10_stage35_h265_vpu_parent_callers.log"),
 "xt4":Camera(
   "xt4",0x01e0f000,
   "e1ef8b30903d3078fde103cdd134fca7bfc4337d67bcaf55c3080ffd5fd93b13",
   0x0224b65c,0x0224b750,0x0224b754,0x0224b758,
   0x0224b768,0x0224b76c,0x0224b770,0x0224b774,
   0x0224b94c,0x0224b958,0x0224b95c,0x0224b960,0x0224b964,
   0x0224b870,0x01280c14,0x028a5150,
   0x011cdbdc,"xt4_stage42_mve_sender_refs.log",
   0x011cee04,"xt4_vpu_setoptions.log",
   0x011cea64,"xt4_stage42_profile_module_selection_decomp.log",
   0x011ceaf4,0x011ceaf8,0x011ceafc,0x011ceb00,
   0x011ceba0,0x011ceba4,0x011ceba8,0x011cebac,
   0x011ceb3c,0x011ceb40,0x011cdef0,
   0x011cec3c,0x011cec64,
   "xt4_stage35_h265_vpu_parent_callers.log"),
}

EXPECTED_SEND_CALLS={
 "xs10":(
  0x011fd8c0,0x011fb614,0x011fb668,0x011fb718,0x011fb7b4,
  0x011fb7e4,0x011fb82c,0x011fb86c,0x011fb89c,0x011fb5b8,
  0x011fb8fc),
 "xt4":(
  0x011d0f6c,0x011cecc0,0x011ced14,0x011cedc4,0x011cee60,
  0x011cee90,0x011ceed8,0x011cef18,0x011cef48,0x011cec64,
  0x011cefa8),
}

def need(b,message):
    if not b: raise ValueError("Stage42 VPU HEVC source/index3 audit: "+message)

def from_rom(buf,base,addr):
    off=addr-base
    need(off>=0 and off%4==0 and off+4<=len(buf),
         "out-of-bounds/misaligned unmodified ROM A32 "+hex(addr))
    return struct.unpack_from("<I",buf,off)[0]

def decode_arm_bl(word,addr):
    need(word>>28==14 and word&0x0f000000==0x0b000000,
         "expected original unconditional A32 BL")
    off=word&0xffffff
    if off&0x800000:off-=0x1000000
    return (addr+8+4*off)&0xffffffff

def decode_arm_beq(word,addr):
    need(word>>28==0 and word&0x0f000000==0x0a000000,
         "expected original A32 BEQ")
    off=word&0xffffff
    if off&0x800000:off-=0x1000000
    return (addr+8+4*off)&0xffffffff

def movw16(word,rd,opcode):
    need((word>>28)==14 and (word&0x0ff00000)==opcode and
         (word>>12)&15==rd,"wrong MOVW/MOVT opcode or register")
    return ((word>>16)&15)<<12 | (word&0xfff)

def extract_c(log,fn):
    key="void FUN_%08x(void)"%fn
    need(key in log,"original Ghidra function absent "+hex(fn))
    return log.split(key,1)[1].split("TRACE_DECOMP_END",1)[0]

def validate_firmware_image_order(container,image_defs=st40.IMAGES):
    """Read-only independent *image* identity, not global memory map proof."""
    need(len(container)==st40.BUNDLE_BYTES,
         "private original decoded V61 image set wrong size")
    found=st40.check_four_images(container,images=image_defs,require_hash=True)
    enc=found["hevc_encoder"]
    h264=found["h264_encoder"]
    need(enc["slot_file_offset"]=="0x0" and
         h264["slot_file_offset"]=="0x68000" and
         enc["bytes"]==MVE_FW_REGION_BYTES and
         h264["bytes"]==MVE_FW_REGION_BYTES and
         enc["descriptor"]=="H.265 MP Encoder" and
         h264["descriptor"]=="H.264 BP/MP/HP Encoder",
         "two proposed source-address targets do not align to exact HEVC/H264 names, boundaries, hashes")
    need((FUJI_H264_ENCODER_FW_ADDR-FUJI_HEVC_ENCODER_FW_ADDR)==0x68000,
         "original source address pair not separated by HEVC encoder+decoder region")
    return found

def correlate_payload_source_offsets(cases,by_name=CAMERAS):
    """Same per-sample translation for two independent *named* images.
    This is a bounded correlation, not a loader relocation algorithm proof.
    """
    reports={}
    for camera in st40.CAMERAS:
        name=camera.name
        first=camera.module_region_payload_offset
        second=first+st40.HEVC_BUNDLE_BYTES
        mapping_from_hevc=first-FUJI_HEVC_ENCODER_FW_ADDR
        mapping_from_h264=second-FUJI_H264_ENCODER_FW_ADDR
        need(mapping_from_hevc==mapping_from_h264,
             "HEVC/H264 decoded payload relative layout disagrees with original source pointers")
        need(camera.name in cases,
             "model X-T3/4/X-S10 payload image not inspected")
        original=cases[name]
        need(original["images"]["hevc_encoder"]["bytes"]==MVE_FW_REGION_BYTES and
             original["images"]["h264_encoder"]["bytes"]==MVE_FW_REGION_BYTES,
             "Stage40 original standalone image sizes changed")
        reports[name]={
           "HEVC_encoder_payload_file_offset":"0x%x"%first,
           "HEVC_encoder_VPU_init_addr_candidate":"0x%x"%FUJI_HEVC_ENCODER_FW_ADDR,
           "H264_encoder_payload_file_offset":"0x%x"%second,
           "H264_encoder_VPU_init_addr_candidate":"0x%x"%FUJI_H264_ENCODER_FW_ADDR,
           "constant_difference_for_both":"0x%x"%mapping_from_hevc,
           "same_translation_for_both_named_images":True,
           "global_payload_runtime_address_mapping_proven":False,
        }
    return reports

def verify_movie_selection(m,rom1,rom2,ghidra_movie):
    need(sha256(rom2).hexdigest()==m.section2_sha256,
         "original Section2 SHA does not match, reject cross-sample code offsets")
    w=lambda a:from_rom(rom2,m.section2_base,a)
    need(w(m.movie_rom_codec_load)==0xe5d33dda and
         w(m.movie_rom_codec_cmp)==0xe1530002,
         "MovieCodec byte+0xADDA original LDRB+CMP1 not verified")
    need(decode_arm_beq(w(m.movie_rom_beq),m.movie_rom_beq)==m.hevc_branch,
         "original BEQ MovieCodec==1 must choose HEVC branch")
    # MovieCodec==1 is HEVC. It writes video_codec=0 and firmware addr 0xCA0000
    need(w(m.hevc_codec_store)==0xe5832188 and
         w(m.hevc_codec_store-4)==0xe3a02000 and
         movw16(w(m.hevc_ptr_low),0,0x03000000)==0 and
         movw16(w(m.hevc_ptr_high),0,0x03400000)==0x00ca and
         w(m.hevc_ptr_store)==0xe5830010,
         "original HEVC branch must write codec0 and selected firmware source +0x10")
    # Codec!=1 chooses H264: codec1 and firmware addr 0xD08000
    need(w(m.h264_codec_store)==0xe5832188 and
         w(m.h264_codec_store-4)==0xe3a02001 and
         movw16(w(m.h264_ptr_low),0,0x03000000)==0x8000 and
         movw16(w(m.h264_ptr_high),0,0x03400000)==0x00d0 and
         w(m.h264_ptr_store)==0xe5830010,
         "original H264 branch must write codec1 and selected firmware source +0x10")
    need(decode_arm_bl(w(m.fw_address_api_bl),m.fw_address_api_bl)==m.fw_address_api,
         "original MovieSetup firmware-region helper call BL changed")

    # Third independent check: Ghidra C verifies both paths fill same VPU
    # parameter struct and the selected source is then passed to service
    # with byte count 0x39000. The service function is NOT proven memcpy.
    c=ghidra_movie
    base=m.vpu_params_base
    need("FUN_%08x("%m.movie_func in c,
         "original Ghidra MovieSetup function identity absent")
    txt=(
      "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';",
      "uVar2 = 0xca0000;",
      "_DAT_%08x = 0xca0000;"%(base+0x10),
      "uVar2 = 0xd08000;",
      "_DAT_%08x = 0xd08000;"%(base+0x10),
      "_DAT_%08x = (uint)!bVar9;"%(base+0x188),
      "FUN_%08x(uVar2,0x39000,9);"%m.fw_address_api,
    )
    need(all(q in c for q in txt),
         "Ghidra parent ROM must show exact firmware pointer branches, shared VPU codec field and 0x39000 region service")
    return {
        "original_MovieSetup":"FUN_%08x"%m.movie_func,
        "context_active_codec_byte_offset":"0xADDA",
        "MovieCodec_byte_eq1_branch_site":"0x%08x"%m.movie_rom_beq,
        "MovieCodec_byte_eq1_A32_branch_target":"0x%08x"%m.hevc_branch,
        "MovieCodec_byte_eq1_VPU_video_codec_enum":0,
        "MovieCodec_byte_eq1_VPU_FW_addr":"0x00ca0000",
        "MovieCodec_byte_ne1_VPU_video_codec_enum":1,
        "MovieCodec_byte_ne1_VPU_FW_addr":"0x00d08000",
        "VPU_Init_codec_field_offset":"0x188",
        "VPU_Init_firmware_address_field_offset":"0x10",
        "firmware_region_service_BL":"0x%08x"%m.fw_address_api_bl,
        "firmware_region_service":"FUN_%08x"%m.fw_address_api,
        "region_service_byte_length":"0x39000",
        "region_service_verified_as_memcpy":False,
        "selected_Fuji_codec0_HEVC_static_support":True,
        "selected_Fuji_codec1_H264_static_support":True,
    }

def verify_header_split(m,rom1,log):
    """Second independent codec identity consistency: 2 vs 3 bitstream headers."""
    w=lambda a:from_rom(rom1,ROM1_BASE,a)
    expected={
      m.header_codecload:0xe5933190,
      m.header_codec_cmp:0xe3530001,
      m.header_count2:0x03a08002,  # MOVEQ r8,#2
      m.header_count3:0x13a08003,  # MOVNE r8,#3
      m.header2_codecload:0xe5933190,
      m.header2_codec_cmp:0xe3530001,
      m.header2_count2:0x03a09002, # MOVEQ r9,#2
      m.header2_count3:0x13a09003, # MOVNE r9,#3
      m.header_bitstream_mov:0xe3001bba,
    }
    for addr,raw in expected.items():
        need(w(addr)==raw,
             "original ARM bitstream-header codec1=>2 codec0=>3 branch differs at "+hex(addr))
    need(decode_arm_bl(w(m.header_bitstream_bl),m.header_bitstream_bl)==m.header_ring_write,
         "bitstream header 0xBBA/0x28 software ring destination changed")
    c=extract_c(log,m.header_sender)
    required=(
       "FUN_%08x"%m.header_sender if False else "s_h265_SndBitStreamHeader",
       "if (*(int *)(iVar2 + 400) == 1)",
       "uVar7 = 2;",
       "uVar7 = 3;",
       "0xbba,0x28",
    )
    need(all(s in c for s in required),
         "bitstream header producer decompile lacks codec selector and 0xBBA 40B descriptor")
    return {
      "header_builder":"FUN_%08x"%m.header_sender,
      "MVE_BUFFER_CODE_BITSTREAM":"0xBBA/3002",
      "input_video_codec_enum_1_header_record_count_if_split":2,
      "input_video_codec_enum_0_header_record_count_if_split":3,
      "record_length_each":"0x28",
      "bitstream_header_count_branch_original_A32":"0x%08x"%m.header_codec_cmp,
      "ring_forward_BL":"0x%08x"%m.header_bitstream_bl,
      "header_count_alone_not_proof_of_actual_VPS_SPS_PPS_bytes":True,
      "SPS_PPS_for_H264_VPS_SPS_PPS_for_HEVC_consistent_with_count":True,
    }

def read_direct_call_refs(log,target):
    """Direct Ghidra original xrefs bounded to ONE analyzed function."""
    key="ST42_TARGET=%08x"%target
    need(key in log,"VPU send-message function target not in read-only Ghidra log")
    rest=log.split(key,1)[1].split("ST42_TARGET=",1)[0]
    count=re.search(r"^.*?\bREFS=(\d+)",rest.splitlines()[0])
    need(count is not None,"static direct xref count absent")
    rows=re.findall(r"ST42_REF=\d+ source=([0-9a-f]{8}) kind=UNCONDITIONAL_CALL",
                    rest)
    need(len(rows)==int(count.group(1)),"xref not all unconditional direct BLs")
    return tuple(int(x,16) for x in rows)

def verify_direct_option_senders(m,rom1,c_log,refs_log,job_log):
    direct=read_direct_call_refs(refs_log,m.vpu_option_sender)
    need(direct==EXPECTED_SEND_CALLS[m.name],
         "original Ghidra compiled send-message direct caller set changed")
    for source in direct:
        need(decode_arm_bl(from_rom(rom1,ROM1_BASE,source),source)==m.vpu_option_sender,
             "Ghidra direct send ref source BL does not match original Section1")
    c=extract_c(c_log,m.option_function)
    ids=tuple(int(s,0) for s in re.findall(r"\blocal_58\s*=\s*(0x[0-9a-f]+|\d+);",c))
    need(ids==EXPECTED_SET_OPTION_INDICES,
         "five direct SET_OPTION indices changed or profile3 newly sent")
    send="FUN_%08x(0x3f2,8,&local_58);"%m.vpu_option_sender
    need(c.count(send)==5 and
         "local_54 = 0x80008;" in c and
         c.count("local_58 = 0x26;")==1,
         "Ghidra all direct SET_OPTION payload sites not verified")
    need(PUBLIC_PROFILE_LEVEL_INDEX not in ids,
         "public Profile-Level index 3 does appear in known static sender")

    # The other prominent '4' is NOT Main10 profile4. Public mve_request_job:
    # uint16 cores; uint16 frames; uint32 flags, here 0x00000004, 0.
    job=extract_c(job_log,m.job_sender)
    need("local_10 = 4;" in job and "local_c = 0;" in job and
         ("FUN_%08x(0x3f1,8,&local_10);"%m.vpu_option_sender) in job,
         "job request was mistaken for HEVC profile")
    need(decode_arm_bl(from_rom(rom1,ROM1_BASE,m.job_bl),m.job_bl)==m.vpu_option_sender and
         from_rom(rom1,ROM1_BASE,m.job_bl-4)==0xe30003f1,
         "job code0x3F1 A32 MOVW + BL changed")
    return {
        "direct_Ghidra_xrefs_to_VPU_send_message":len(direct),
        "all_11_direct_A32_BL_sites_rechecked":True,
        "SndSetOption_function":"FUN_%08x"%m.option_function,
        "SndSetOption_direct_CALL_count":5,
        "SndSetOption_fixed_indices_order":list(ids),
        "SndSetOption_direct_profile_level_index3_occurrences":0,
        "SndSetOption_conditional_H264_stream_bitdepth_index38":True,
        "SndSetOption_conditional_HEVC_stream_bitdepth_index38":False,
        "JOB_request_code_0x3F1_public_mve_request_job":True,
        "JOB_four_in_code_is_core_count_not_HEVC_Main10_profile":True,
        "all_other_indirect_or_other_queue_messages_excluded":False,
        "Main10_profile_config_sent_somewhere_else":"UNKNOWN",
    }

def parse_prior(path,marker):
    return json.loads(path.read_text().split("\n"+marker,1)[0])

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    output=ap.parse_args().output
    # Link to Stage41 ABI proofs and to Stage40 3-camera independently
    # hashed image quartet, both in the prior stacked-Draft PRs.
    public=st41.validate_mve_frame_abi()
    need(public["set_option_ids"]["MVE_SET_OPT_INDEX_PROFILE_LEVEL"]==3 and
         public["set_option_ids"]["MVE_OPT_PROFILE_H265_MAIN_10"]==4 and
         public["set_option_ids"]["MVE_SET_OPT_INDEX_ENC_STREAM_BITDEPTH"]==38 and
         st41.MVE_FRAME==0xbb9 and MVE_FRAME_BITSTREAM==0xbba,
         "Stage41 independently reconstructed public protocol field baseline differs")
    prior41=parse_prior(output/"stage41_mve_v61_protocol_abi_audit.jsonlog","STAGE41")
    prior40=parse_prior(output/"stage40_v61_hevc_image_boundaries_audit.jsonlog","STAGE40")
    image_samples={}
    for info in st40.CAMERAS:
        payload=(output/f"{info.name}-payload.bin").read_bytes()
        off=info.module_region_payload_offset
        need(off>=0 and off+st40.BUNDLE_BYTES<=len(payload),
             "original private payload V61 image quartet outside file")
        original=payload[off:off+st40.BUNDLE_BYTES]
        images=validate_firmware_image_order(original)
        old=next(x for x in prior40["cameras"] if x["camera"]==info.name)
        need(images==old["images"],
             "Stage40 3-camera V61 image SHA and boundaries changed")
        image_samples[info.name]=old
    mappings=correlate_payload_source_offsets(image_samples)
    model_rows=[]
    for name,m in CAMERAS.items():
        rom1=(output/f"x6-{name}/section-1.bin").read_bytes()
        rom2=(output/f"x6-{name}/section-2.bin").read_bytes()
        p41=next(x for x in prior41["fuji_original_ARM_results"] if x["model"]==name)
        need(sha256(rom1).hexdigest()==p41["original_rom1_sha256"] and
             p41["encoder_stream_bitdepth_setting"]["output_luma_depth_u16"]==8 and
             p41["encoder_stream_bitdepth_setting"]["output_chroma_depth_u16"]==8 and
             p41["encoder_stream_bitdepth_setting"]["camera_codec_enum1_standard_assignment"]=="UNVERIFIED" and
             p41["encoder_stream_bitdepth_setting"]["function"]=="FUN_%08x"%m.option_function and
             p41["encoder_stream_bitdepth_setting"]["set_option_message_code"]=="0x3f2" and
             p41["encoder_stream_bitdepth_setting"]["option_index_38_A32_store"]=="0x%08x"%(m.option_function+0xb8) and
             "ROM_guard_0x194_eq0" in p41["encoder_stream_bitdepth_setting"] and
             "ROM_codec_eq1_guard" in p41["encoder_stream_bitdepth_setting"],
             "old Stage41 source ROM or conditional 8/8 bitdepth output observation differs")
        parent=(output/m.movie_loader_log).read_text()
        sender=(output/m.option_function_log).read_text()
        header=(output/m.header_c_log).read_text()
        refs=(output/m.option_caller_log).read_text()
        # Job + SndSetOption functions contained in the same short original Ghidra log.
        model_rows.append({
          "model":name,
          "original_Section2_sha256":m.section2_sha256,
          "movie_codec_to_encoder_firmware_pointer":verify_movie_selection(m,rom1,rom2,parent),
          "independent_header_count_consistency":verify_header_split(m,rom1,header),
          "direct_MVE_option3_and_job_site_inventory":verify_direct_option_senders(
               m,rom1,sender,refs,job_log=(output/
               (name+"_stage42_sender_dispatch_decomp.log")).read_text()),
        })
    need(all(row["movie_codec_to_encoder_firmware_pointer"]
             ["MovieCodec_byte_eq1_VPU_video_codec_enum"]==0 for row in model_rows)
         and all(row["movie_codec_to_encoder_firmware_pointer"]
             ["MovieCodec_byte_ne1_VPU_video_codec_enum"]==1 for row in model_rows)
         and all(row["direct_MVE_option3_and_job_site_inventory"]
             ["SndSetOption_direct_profile_level_index3_occurrences"]==0
                 for row in model_rows),
         "two-camera VPU firmware source/option3 comparison fails")
    print(json.dumps({
       "public_MVE_protocol_frame_bitdepth_profile_source":"Kendryte v2/v3 and CIX v2",
       "original_three_camera_V61_encoder_image_layout_matches":mappings,
       "two_camera_original_ROM_A32_assignment_and_sender_inventory":model_rows,
       "observed_static_assignment":{
           "MovieCodecByte1":"HEVC encoder 0xca0000 / VPU enum0 / 10bit Y0L2 frame if effective_depth nonzero",
           "MovieCodecByteOther":"H264 encoder 0xd08000 / VPU enum1 / conditional SET_OPTION index38, luma8 chroma8",
           "no_fuji_profile_level_index3_in_known_five_option_messages":True,
           "HEVC_main10_profile4_or_hardware_acceptance_proven":False,
       },
       "evidence_limits":UNPROVEN,
    },ensure_ascii=False,indent=2))
    print("STAGE42 HEVC FW SELECTOR / H264 ONLY 8/8 OPTION / DIRECT PROFILE3 BOUNDED AUDIT PASS")
    print("No Ghidra firmware-image machine code uploaded, no physical camera touched, no Main10 or 4K60 claim.")
if __name__=="__main__":
    main()

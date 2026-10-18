#!/usr/bin/env python3
"""Stage41: independently reconcile Fujifilm original ARM with open MVE ABI.

OFFLINE/read-only. No Sony/Fuji binary is included here. Inputs are the
already obtained unmodified X-S10 3.11 / X-T4 2.12 Section1 ROM and private
Stage36/37/39/40 Ghidra-based audit logs under gitignored output/.
No camera, USB/FF80, flash, firmware patch or 10-bit Main10 claim.

Upstream public Linux MVE ABI evidence (independently inspected 2026-10-18):
  Kendryte K230 v2: github.com/kendryte/k230_sdk/blob/main/src/little/linux/
                    drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h
    pinned Git blob 7888514a3ba4ace1ea62da324a9ced5534e3c45e
  Kendryte K230 v3: .../mve_protocol_def_v3.h
    pinned Git blob 9c79991f0c43e27cc78642a73bd8c98aa87d573f
  CIX official VPU v2: github.com/cixtech/cix_opensource__vpu_driver/
                         blob/cix_p1_k6.6_master/driver/external/fw_v2/
                         mve_protocol_def.h
    pinned Git blob f5c7eddebcf97fa9dcd992a316c675b7fec5f904
The public sources agree on the protocol values, field layout and option
indices used here. This derived standalone code is NOT an ISA disassembler.
Upstream source must still be checked independently before claiming identity
of *all* versions of Fuji's V61 firmware ABI.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import argparse
import ctypes
import json
import re
import struct

ROM1=0x01021000
HEVC_MAIN10_PROFILE_ID=4          # public MVE_OPT_PROFILE_H265_MAIN_10
MVE_PROFILE_LEVEL_INDEX=3         # public MVE_SET_OPT_INDEX_PROFILE_LEVEL
MVE_ENC_STREAM_BITDEPTH_INDEX=38  # public MVE_SET_OPT_INDEX_ENC_STREAM_BITDEPTH
MVE_REQUEST_SET_OPTION=1010       # public MVE_REQUEST_CODE_SET_OPTION
MVE_FRAME=3001                    # public MVE_BUFFER_CODE_FRAME
MVE_INPUT=2005                    # public MVE_RESPONSE_CODE_INPUT
MVE_OUTPUT=2006                   # public MVE_RESPONSE_CODE_OUTPUT
MVE_INPUT_FLUSHED=2007            # public MVE_RESPONSE_CODE_INPUT_FLUSHED
MVE_OUTPUT_FLUSHED=2008           # public MVE_RESPONSE_CODE_OUTPUT_FLUSHED
CHROMA_420=1
FORMAT_SHIFT_CHROMA=0
FORMAT_SHIFT_MAX_BITDEPTH_MINUS8=4
FORMAT_SHIFT_PLANES=8
FORMAT_SHIFT_VARIANT=12
FORMAT_SHIFT_AFBC=15
PUBLIC_HEADER_BLOBS={
 "kendryte_v2":"7888514a3ba4ace1ea62da324a9ced5534e3c45e",
 "kendryte_v3":"9c79991f0c43e27cc78642a73bd8c98aa87d573f",
 "cixtech_v2":"f5c7eddebcf97fa9dcd992a316c675b7fec5f904",
}

class Planar(ctypes.Structure):
    _fields_=[("plane_top",ctypes.c_uint32*3),
              ("plane_bot",ctypes.c_uint32*3),
              ("stride",ctypes.c_int32*3),
              ("max_frame_width",ctypes.c_uint16),
              ("max_frame_height",ctypes.c_uint16)]

class AFBC(ctypes.Structure):
    _fields_=[("plane",ctypes.c_uint32*2),
              ("alloc_bytes",ctypes.c_uint32*2),
              ("cropx",ctypes.c_uint16),
              ("cropy",ctypes.c_uint16),
              ("afbc_width_in_superblocks",ctypes.c_uint16*2),
              ("afbc_params",ctypes.c_uint32)]

class FrameData(ctypes.Union):
    _fields_=[("planar",Planar),("afbc",AFBC)]

class MVEFrame(ctypes.Structure):
    _fields_=[("host_handle",ctypes.c_uint64),
              ("user_data_tag",ctypes.c_uint64),
              ("frame_flags",ctypes.c_uint32),
              ("visible_frame_height",ctypes.c_uint16),
              ("visible_frame_width",ctypes.c_uint16),
              ("format",ctypes.c_uint16),
              ("frame_type",ctypes.c_uint8),
              ("frame_flags_ext",ctypes.c_uint8),
              ("data",FrameData),
              ("mini_frame_y_start",ctypes.c_uint16),
              ("mini_frame_y_end",ctypes.c_uint16)]

class OptionStreamDepth(ctypes.Structure):
    _fields_=[("luma_bitdepth",ctypes.c_uint16),
              ("chroma_bitdepth",ctypes.c_uint16)]

class StreamDepthOption(ctypes.Structure):
    _fields_=[("index",ctypes.c_uint32),
              ("data",OptionStreamDepth)]

@dataclass(frozen=True)
class Model:
    name:str
    rom1_sha:str
    zero_format:int
    nonzero_format:int
    send_option:int
    packet_global:int
    codec_1_ldr:int
    protocol_option_mov:int
    first_depth_halfstore:int
    second_depth_halfstore:int
    option_send_bl:int
    ring_writer:int
    string_log:str

MODELS={
 "xs10": Model(
   "xs10","c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff",
   0x011fab9c,0x011fabfc,0x011fb758,0x01c8573c,
   0x011fb804,0x011fb810,0x011fb81c,0x011fb820,
   0x011fb82c,0x011fa530,"xs10_vpu_setoptions.log"),
 "xt4": Model(
   "xt4","0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb",
   0x011ce248,0x011ce2a8,0x011cee04,0x01be5808,
   0x011ceeB0,0x011ceeBC,0x011ceeC8,0x011ceeCC,
   0x011ceeD8,0x011cdbdc,"xt4_vpu_setoptions.log"),
}

def must(b,reason):
    if not b:raise ValueError("Stage41 MVE protocol ABI: "+reason)

def format_u16(chroma,storage_bits,planes,variant=0,afbc=False):
    """Encode published MVE format bitfield, not the HEVC SPS profile."""
    must(chroma in range(8),"format chroma out of 3bit range")
    must(storage_bits in range(8,24),"format storage max depth outside 4bit")
    must(planes in range(0,4),"format plane count outside 2bit")
    must(variant in range(4),"format variant outside 2bit")
    return ((chroma<<FORMAT_SHIFT_CHROMA) |
            ((storage_bits-8)<<FORMAT_SHIFT_MAX_BITDEPTH_MINUS8) |
            (planes<<FORMAT_SHIFT_PLANES) |
            (variant<<FORMAT_SHIFT_VARIANT) |
            (int(bool(afbc))<<FORMAT_SHIFT_AFBC))

def decode_format(value):
    must(isinstance(value,int) and 0<=value<=0xffff,"format not u16")
    return {
      "chroma_format":(value>>FORMAT_SHIFT_CHROMA)&7,
      "format_storage_depth":8+((value>>FORMAT_SHIFT_MAX_BITDEPTH_MINUS8)&15),
      "planes":(value>>FORMAT_SHIFT_PLANES)&3,
      "variant":(value>>FORMAT_SHIFT_VARIANT)&3,
      "afbc":bool((value>>FORMAT_SHIFT_AFBC)&1)
    }

FORMAT_NAMES={
 "NV12_8bit":(0x201,(1,8,2,0,False),"MVE_FORMAT_YUV420_NV12"),
 "Y0L2_10bit":(0x121,(1,10,1,0,False),"MVE_FORMAT_YUV420_Y0L2"),
 "P010_16bit_storage":(0x281,(1,16,2,0,False),"MVE_FORMAT_YUV420_P010"),
 "2P_10bit":(0x221,(1,10,2,0,False),"MVE_FORMAT_YUV420_2P_10"),
}

def validate_mve_frame_abi():
    offsets={
      "header_code":0,
      "header_size":2,
      "frame.format":MVEFrame.format.offset,
      "frame.data":MVEFrame.data.offset,
      "frame.data.planar.stride[0]":
          MVEFrame.data.offset+Planar.stride.offset,
      "frame.data.planar.stride[1]":
          MVEFrame.data.offset+Planar.stride.offset+4,
      "frame.data.planar.stride[2]":
          MVEFrame.data.offset+Planar.stride.offset+8,
      "frame.mini_frame_y_start":MVEFrame.mini_frame_y_start.offset,
    }
    must((ctypes.sizeof(MVEFrame),ctypes.sizeof(Planar),
          ctypes.sizeof(AFBC),ctypes.sizeof(FrameData))==(72,40,28,40),
         "public-frame self-contained ABI model size changed")
    must((offsets["frame.format"],offsets["frame.data"],
          offsets["frame.data.planar.stride[0]"],
          offsets["frame.data.planar.stride[1]"],
          offsets["frame.mini_frame_y_start"])==(0x18,0x1c,0x34,0x38,0x44),
         "public frame+0x18/stride field offsets mismatch")
    must(ctypes.sizeof(StreamDepthOption)==8 and
         StreamDepthOption.data.offset==4 and
         OptionStreamDepth.luma_bitdepth.offset==0 and
         OptionStreamDepth.chroma_bitdepth.offset==2,
         "public MVE set-option bitdepth payload is not 8B/index+u16+u16")
    must(struct.calcsize("<QQIHHHBB40sHH")==72,
         "cross-check of frame size from manually specified little-endian layout")
    for name,(number,args,label) in FORMAT_NAMES.items():
        must(format_u16(*args)==number and
             decode_format(number)=={
                 "chroma_format":args[0],
                 "format_storage_depth":args[1],
                 "planes":args[2],
                 "variant":args[3],
                 "afbc":args[4],
             },"public MVE named-format bitfield mismatch "+name)
    must(MVE_FRAME==0xbb9 and MVE_REQUEST_SET_OPTION==0x3f2 and
         MVE_INPUT==0x7d5 and MVE_OUTPUT_FLUSHED==0x7d8 and
         MVE_OUTPUT==0x7d6 and MVE_INPUT_FLUSHED==0x7d7,
         "published MVE request/response code ID mapping differs")
    must(HEVC_MAIN10_PROFILE_ID==4 and MVE_PROFILE_LEVEL_INDEX==3 and
         MVE_ENC_STREAM_BITDEPTH_INDEX==0x26,
         "published MVE profile/bitdepth option ID mapping differs")
    # The MVE packet's original on-ring 32bit little-endian (size<<16)|code
    must(struct.pack("<HH",MVE_FRAME,72)==struct.pack("<I",0x00480bb9),
         "original 0xBB9 72B buffer message header not ABI-compatible")
    return {
      "frame_payload_size":ctypes.sizeof(MVEFrame),
      "protocol_header_size":4,
      "fields":{k:("0x%x"%v) for k,v in offsets.items()},
      "format_ids":{
         label:{
           "value":"0x%x"%number,
           "depth_field_storage_bits":args[1],
           "plane_count":args[2],
         }
         for _,(number,args,label) in FORMAT_NAMES.items()
      },
      "mve_codes":{
        "MVE_BUFFER_CODE_FRAME":"0x%x"%MVE_FRAME,
        "MVE_RESPONSE_CODE_INPUT":"0x%x"%MVE_INPUT,
        "MVE_RESPONSE_CODE_OUTPUT":"0x%x"%MVE_OUTPUT,
        "MVE_RESPONSE_CODE_INPUT_FLUSHED":"0x%x"%MVE_INPUT_FLUSHED,
        "MVE_RESPONSE_CODE_OUTPUT_FLUSHED":"0x%x"%MVE_OUTPUT_FLUSHED,
        "MVE_REQUEST_CODE_SET_OPTION":"0x%x"%MVE_REQUEST_SET_OPTION,
      },
      "set_option_ids":{
        "MVE_SET_OPT_INDEX_PROFILE_LEVEL":MVE_PROFILE_LEVEL_INDEX,
        "MVE_OPT_PROFILE_H265_MAIN_10":HEVC_MAIN10_PROFILE_ID,
        "MVE_SET_OPT_INDEX_ENC_STREAM_BITDEPTH":MVE_ENC_STREAM_BITDEPTH_INDEX,
      },
      "published_source_git_blob_ids":PUBLIC_HEADER_BLOBS,
    }

def read32(rom,addr):
    off=addr-ROM1
    must(off>=0 and off%4==0 and off+4<=len(rom),
         "unaligned/out-of-image A32 source address")
    return struct.unpack_from("<I",rom,off)[0]

def decode_bl(inst,addr):
    must(inst>>28==14 and inst&0x0f000000==0x0b000000,
         "not an unconditional A32 BL")
    rel=inst&0xffffff
    if rel&0x800000:rel-=0x1000000
    return (addr+8+rel*4)&0xffffffff

def confirm_option_sender(m,word,c):
    """Original A32 + read-only Ghidra C, never execute original machine code."""
    # Two conditional gates:
    # packet+0x194 == 0 (encoder setup), then packet+0x190 == 1
    # within that block opt.index=38, opt.bitdepth=(8,8), length=8,
    # sends MVE_REQUEST_CODE_SET_OPTION 0x3F2.
    instructions={
       m.send_option+0x28:0xe5933194,
       m.send_option+0x2c:0xe3530000,
       m.send_option+0x30:0x1a00002d,
       m.codec_1_ldr:0xe5933190,
       m.codec_1_ldr+4:0xe3530001,
       m.codec_1_ldr+8:0x1a00001b,
       m.protocol_option_mov:0xe3a03026,
       m.protocol_option_mov+4:0xe50b3054,
       m.protocol_option_mov+8:0xe3a01008,
       m.first_depth_halfstore:0xe14b15b0,
       m.second_depth_halfstore:0xe14b14be,
       m.option_send_bl-4:0xe30003f2,
    }
    for site,machine in instructions.items():
        must(word(site)==machine,
             "original A32 predicate/marshaled option38/8bit bitdepth differs at "+
             hex(site))
    must(decode_bl(word(m.option_send_bl),m.option_send_bl)==m.ring_writer,
         "original A32 SEND_OPTION packet call target changed")
    begin="void FUN_%08x(void)"%m.send_option
    must(begin in c,"Ghidra original set-options function missing")
    source=c.split(begin,1)[1].split("TRACE_DECOMP_END",1)[0]
    required=[
      "if (*(int *)(_DAT_%08x + 0x194) == 0)"%m.packet_global,
      "if (*(int *)(_DAT_%08x + 400) == 1)"%m.packet_global,
      "local_58 = 0x26;",
      "local_54 = 0x80008;",
      "FUN_%08x(0x3f2,8,&local_58);"%m.ring_writer,
    ]
    positions=[]
    at=0
    for needle in required:
        pos=source.find(needle,at)
        positions.append(pos)
        if pos>=0:at=pos+len(needle)
    must(all(k>=0 for k in positions) and positions==sorted(positions),
         "Ghidra option38 after guards, 8/8 payload and 0x3f2 send unverified")
    # In this particular function profile-level index=3 is *not* asserted
    # to have been sent. Do NOT equate an input Y0L2 buffer with a Main10 SPS.
    return {
      "function":"FUN_%08x"%m.send_option,
      "ROM_guard_0x194_eq0":"0x%08x"%(m.send_option+0x28),
      "ROM_codec_eq1_guard":"0x%08x"%(m.codec_1_ldr+4),
      "option_index_38_A32_store":"0x%08x"%m.protocol_option_mov,
      "output_luma_depth_u16":8,
      "output_chroma_depth_u16":8,
      "set_option_message_code":"0x3f2",
      "set_option_buffer_bytes":8,
      "set_option_BL":"0x%08x"%m.option_send_bl,
      "option_profile_level_3_sent_by_this_branch":False,
      "camera_codec_enum1_standard_assignment":"UNVERIFIED",
      "runtime_branch_observed_on_camera":False,
    }

def verify_model(m,rom,prior36,prior37,prior39,prior40,log):
    must(sha256(rom).hexdigest()==m.rom1_sha,
         "unmodified original Fuji ARM Section1 SHA differs")
    must(prior36["model"]==m.name and
         prior37["model"]==m.name and
         prior39["model"]==m.name,
         "prior original ARM model provenance differs")
    must(prior36["frame_format_code_if_effective_depth_0"]=="0x201" and
         prior36["frame_format_code_if_effective_depth_nonzero"]=="0x121" and
         prior36["VPU_frame_descriptor_bytes_cleared"]==72 and
         prior36["frame_send_command"]=="0x0bb9" and
         prior36["frame_send_payload_bytes"]==72 and
         prior36["frame_depth0_stride_from_VPU_init_word2"]==
               "direct into +0x34 and +0x38" and
         prior36["frame_nonzero_stride_from_VPU_init_word2"]==
               "shift left 2 into +0x34" and
         prior36["VPU_static_movie_path_frame_code_if_no_intervening_writes"]=="0x121",
         "Stage36 original ARM frame+0x18/stride/72B format baseline mismatch")
    must(prior37["frame_sender_0xBB9_payload_bytes"]==72 and
         prior37["0xBB9_direct_VPU_hardware_consumer_observed"]==False and
         prior37["0xBB9_paired_to_0x7D5"]=="UNPROVEN",
         "Stage37 software-only ring direction/unknown VPU endpoint altered")
    must(prior39["software_rsp_0x7D8_may_submit_next_0xBB9_frame"][
             "request_response_pair_0xBB9_to_0x7D8_proven"]==False and
         prior39["hardware_side_0xBB9_receiver_known"]==False,
         "Stage39 CPU notification chain promoted to hardware causality")
    must(prior40["camera"]==m.name and
         prior40["images"]["hevc_encoder"]["descriptor"]=="H.265 MP Encoder" and
         prior40["images"]["hevc_decoder"]["descriptor"]=="HEVC Decoder",
         "Stage40 original V61 decoder-vs-encoder separation changed")

    words=lambda addr:read32(rom,addr)
    must(words(m.zero_format)==0xe3001201 and
         words(m.zero_format+4)==0xe1c211b8 and
         words(m.nonzero_format)==0xe3001121 and
         words(m.nonzero_format+4)==0xe1c211b8,
         "original A32 MOVW plus STRH [r2,+0x18] format writes mismatch")
    sender=confirm_option_sender(m,words,log)
    return {
       "model":m.name,
       "original_rom1_sha256":m.rom1_sha,
       "confirmed_original_A32_zero_format_store_site":"0x%08x"%m.zero_format,
       "zero_depth_mode_writes_frame_format":"MVE_FORMAT_YUV420_NV12 (0x201/8bit)",
       "confirmed_original_A32_nonzero_format_store_site":"0x%08x"%m.nonzero_format,
       "nonzero_depth_mode_writes_frame_format":"MVE_FORMAT_YUV420_Y0L2 (0x121/10bit)",
       "original_72B_frame_matches_public_mve_buffer_frame":True,
       "original_stride0_0x34_and_stride1_0x38_match_public_ABI":True,
       "original_sender_0xbb9":"MVE_BUFFER_CODE_FRAME (3001)",
       "original_response_0x7d5":"MVE_RESPONSE_CODE_INPUT (2005)",
       "original_response_0x7d8":"MVE_RESPONSE_CODE_OUTPUT_FLUSHED (2008)",
       "encoder_stream_bitdepth_setting":sender,
       "actual_fuji_v61_isa_disassembled":False,
       "real_vpu_0xbb9_consumer_identified":False,
       "hevc_Main10_SPS_profile4_emitted_proven":False,
       "all_xs10_movies_are_10bit_proven":False,
       "XS10_4K60_supported_or_unlocked":False,
       "camera_firmware_written_or_physical_camera_access":False,
    }

def read_prior(output,name,marker):
    return json.loads((output/name).read_text().split(marker,1)[0])

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    output=ap.parse_args().output
    abi=validate_mve_frame_abi()
    p36=read_prior(output,"stage36_vpu_bitdepth_packet_audit.jsonlog","\nSTAGE36")
    p37=read_prior(output,"stage37_vpu_ring_memory_audit.jsonlog","\nSTAGE37")
    p39=read_prior(output,"stage39_h265_irq_callback_original_audit.jsonlog","\nSTAGE39")
    p40=read_prior(output,"stage40_v61_hevc_image_boundaries_audit.jsonlog","\nSTAGE40")
    rows=[]
    for name,m in MODELS.items():
        rom=(output/f"x6-{name}/section-1.bin").read_bytes()
        rows.append(verify_model(m,rom,
          next(x for x in p36 if x["model"]==name),
          next(x for x in p37 if x["model"]==name),
          next(x for x in p39 if x["model"]==name),
          next(x for x in p40["cameras"] if x["camera"]==name),
          (output/m.string_log).read_text()))
    must(rows[0]["zero_depth_mode_writes_frame_format"]==
         rows[1]["zero_depth_mode_writes_frame_format"] and
         rows[0]["nonzero_depth_mode_writes_frame_format"]==
         rows[1]["nonzero_depth_mode_writes_frame_format"] and
         rows[0]["encoder_stream_bitdepth_setting"]["output_luma_depth_u16"]==
         rows[1]["encoder_stream_bitdepth_setting"]["output_luma_depth_u16"],
         "cross-camera MVE+ARM byte/protocol equivalence failed")
    print(json.dumps({"protocol_abi_from_three_public_headers":abi,
                       "fuji_original_ARM_results":rows,
                       "hardware_main10_proven":False,
                       "actual_v61_microcode_disassembly_proven":False,
                       "camera_contacted_or_modified":False,
                       },indent=2,ensure_ascii=False))
    print("STAGE41 PUBLIC MVE ABI x ORIGINAL FUJI A32 OPTION/FRAME FIELD AUDIT: 2 CAMERAS PASS")
    print("Protocol mapping proven; V61 core ISA, actual hardware execution/Main10/4K60 NOT proven.")
if __name__=="__main__":
    main()

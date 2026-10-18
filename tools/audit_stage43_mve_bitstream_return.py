#!/usr/bin/env python3
"""Stage43: OFFLINE V61/MVE bitstream CODECCONFIG CPU receive provenance.

This audit reads only the authorized user's original X-S10 3.11 / X-T4
2.12 Section1 ROM and private read-only Ghidra logs in ignored output/.
It compares original A32+Ghidra CPU software to published MVE v2/v3 ABI.
It NEVER executes Fuji firmware, touches physical cameras/USB/FF80/flash,
reads user camera RAM, or claims Main10/4K60 is unlocked.

Public ABI citations:
 - https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/
   drivers/media/platform/canaan-vpu/mve_protocol_def_v2.h
 - https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/
   drivers/media/platform/canaan-vpu/mve_protocol_def_v3.h
 - https://github.com/kendryte/k230_sdk/blob/main/src/little/linux/
   drivers/media/platform/canaan-vpu/mvx_firmware_v2.c
 - https://github.com/cixtech/cix_opensource__vpu_driver/
   blob/cix_p1_k6.6_master/driver/external/fw_v2/mve_protocol_def.h
"""
from dataclasses import dataclass
import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage41_mve_v61_protocol_abi as st41

BASE=0x01021000
CODE_BITSTREAM=0xBBA
RSP_OUTPUT=0x7D6
RSP_OPTION_CONFIRM=0x7D3
RSP_OPTION_FAIL=0x7E1
RSP_SEQUENCE_PARAMS=0x7DF
REQUEST_OUTPUT_FLUSH=0x3EC
CODECCONFIG_MASK=0x80
EOFRAME_MASK=0x10
EOS_MASK=0x1

class MveBitstream(ctypes.Structure):
    _fields_=[
      ("host_handle",ctypes.c_uint64),
      ("user_data_tag",ctypes.c_uint64),
      ("bitstream_flags",ctypes.c_uint32),
      ("bitstream_alloc_bytes",ctypes.c_uint32),
      ("bitstream_offset",ctypes.c_uint32),
      ("bitstream_filled_len",ctypes.c_uint32),
      ("bitstream_buf_addr",ctypes.c_uint32),
      ("frame_type",ctypes.c_uint8),
      ("src_transform",ctypes.c_uint8),
    ]

class MveSequenceParams(ctypes.Structure):
    _fields_=[
      ("interlace",ctypes.c_uint8),
      ("chroma_format",ctypes.c_uint8),
      ("bitdepth_luma",ctypes.c_uint8),
      ("bitdepth_chroma",ctypes.c_uint8),
      ("num_buffers_planar",ctypes.c_uint8),
      ("num_buffers_afbc",ctypes.c_uint8),
      ("range_mapping_enabled",ctypes.c_uint8),
      ("reserved0",ctypes.c_uint8),
    ]

@dataclass(frozen=True)
class Model:
    name:str
    sha:str
    header_builder:int
    header_global:int
    header_flag_store:int
    header_offset_store:int
    header_alloc_mov:int
    header_alloc_store:int
    header_filled_store:int
    header_ptr_store:int
    header_code_mov:int
    header_send_bl:int
    header_send_api:int
    header_code2_mov:int
    header_send2_bl:int
    header_send2_api:int
    response_fn:int
    response_flag_test:int
    response_flag_test2:int
    response_bufaddr_load:int
    response_offset_load:int
    response_filled_load:int
    response_ring_unpack:int
    response_bitstream_global:int
    response_event:int
    response_msg_sender:int
    status_confirm_mov:int
    status_sequence_mov:int
    status_fail_mov:int
    response_flush_mov:int
    response_flush_bl:int
    output_resolve_fn:int
    output_resolve_table_global:int
    assembler_log:str
    resp_c_log:str
    handler_refs_log:str
    ring_c_log:str

MODELS={
 "xs10":Model(
  "xs10","c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff",
  0x011fb3b8,0x019fb7e0,
  0x011fb414,0x011fb424,0x011fb428,0x011fb42c,0x011fb484,0x011fb488,
  0x011fb490,0x011fb494,0x011fa844,0x011fb564,0x011fb568,0x011fa714,
  0x011fcbc4,0x011fd234,0x011fd404,0x011fd414,0x011fd418,0x011fd45c,
  0x011faa68,0x019e55f8,0x011fc614,0x011fa530,
  0x011fcc44,0x011fcfc4,0x011fd014,0x011fd8bc,0x011fd8c0,
  0x011fc2e4,0x01821988,
  "xs10_stage43_mve_response_a32_sites.log",
  "xs10_stage39_mmio_status_router_c.log",
  "xs10_stage42_profile_module_selection_decomp.log",
  "xs10_stage43_mve_output_bitstream_consumer.log",
 ),
 "xt4":Model(
  "xt4","0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb",
  0x011cea64,0x0196b834,
  0x011ceac0,0x011cead0,0x011cead4,0x011cead8,0x011ceb30,0x011ceb34,
  0x011ceb3c,0x011ceb40,0x011cdef0,0x011cec10,0x011cec14,0x011cddc0,
  0x011d0270,0x011d08e0,0x011d0ab0,0x011d0ac0,0x011d0ac4,0x011d0b08,
  0x011ce114,0x01955538,0x011cfcc0,0x011cdbdc,
  0x011d02f0,0x011d0670,0x011d06c0,0x011d0f68,0x011d0f6c,
  0x011cf990,0x01790d98,
  "xt4_stage43_mve_response_a32_sites.log",
  "xt4_stage39_mmio_status_router_c.log",
  "xt4_stage42_profile_module_selection_decomp.log",
  "xt4_stage43_mve_output_bitstream_consumer.log",
 )
}

def need(flag,why):
    if not flag:raise ValueError("Stage43 MVE output/SPS provenance: "+why)

def original_word(rom,addr):
    i=addr-BASE
    need(i>=0 and i%4==0 and i+4<=len(rom),
         "original A32 word OOB or unaligned "+hex(addr))
    return struct.unpack_from("<I",rom,i)[0]

def a32_bl(word,addr):
    need(word>>28==14 and word&0x0f000000==0x0b000000,
         "original ARM BL opcode/condition invalid")
    signed=word&0xffffff
    if signed&0x800000:signed-=0x1000000
    return (addr+8+signed*4)&0xffffffff

def decomp(log,fn):
    pat=r"(?m)^\s*(?:void|int|uint|undefined\d+)\s+FUN_%08x\("%fn
    for block in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        code=block.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(pat,code):
            return code
    raise ValueError("original read-only Ghidra function missing "+hex(fn))

def public_abi():
    need(ctypes.sizeof(MveBitstream)==40,
         "published MVE bitstream buffer sizeof mismatch")
    f={name:getattr(MveBitstream,name).offset for name,_ in
       MveBitstream._fields_}
    need((f["bitstream_flags"],f["bitstream_alloc_bytes"],
          f["bitstream_offset"],f["bitstream_filled_len"],
          f["bitstream_buf_addr"],f["frame_type"])==
         (0x10,0x14,0x18,0x1c,0x20,0x24),
         "published MVE bitstream buffer field offsets differ")
    need(ctypes.sizeof(MveSequenceParams)==8 and
         MveSequenceParams.bitdepth_luma.offset==2 and
         MveSequenceParams.bitdepth_chroma.offset==3,
         "published MVE SEQUENCE_PARAMETERS is not 8B metadata with u8 bitdepth")
    need(CODE_BITSTREAM==3002 and RSP_OUTPUT==2006 and
         RSP_OPTION_CONFIRM==2003 and RSP_OPTION_FAIL==2017 and
         RSP_SEQUENCE_PARAMS==2015 and
         REQUEST_OUTPUT_FLUSH==1004 and
         CODECCONFIG_MASK==0x80 and EOFRAME_MASK==0x10 and EOS_MASK==1,
         "published MVE response/bitstream/flag code mapping changed")
    need(struct.pack("<HH",CODE_BITSTREAM,40)==
         struct.pack("<I",0x00280bba),
         "original 40B bitstream buffer packet header mismatch")
    return {
      "mve_buffer_bitstream_bytes":40,
      "bitstream_fields":{k:"0x%x"%v for k,v in f.items()},
      "sequence_parameters_bytes":ctypes.sizeof(MveSequenceParams),
      "sequence_parameters_bitdepth_luma_offset":2,
      "sequence_parameters_bitdepth_chroma_offset":3,
      "CODECCONFIG_flag":"0x80",
      "EOS_flag":"0x1",
      "ENDOFFRAME_flag":"0x10",
      "responses":{
       "OUTPUT":"0x7d6",
       "SET_OPTION_CONFIRM":"0x7d3",
       "SET_OPTION_FAIL":"0x7e1",
       "SEQUENCE_PARAMETERS":"0x7df",
      },
      "OUTPUT_FLUSH_request":"0x3ec",
      "SEQUENCE_PARAMETERS_is_coded_HEVC_SPS_or_VPS":False,
      "output_bitstream_data_must_be_captured_to_verify_SPS":True,
    }

def validate_stage42(prev,name):
    rows=prev["two_camera_original_ROM_A32_assignment_and_sender_inventory"]
    need(len(rows)==2 and {x["model"] for x in rows}=={"xs10","xt4"},
         "Stage42 bounded codec selector comparison sample set altered")
    old=next(x for x in rows if x["model"]==name)
    s=old["movie_codec_to_encoder_firmware_pointer"]
    o=old["direct_MVE_option3_and_job_site_inventory"]
    h=old["independent_header_count_consistency"]
    need(s["MovieCodec_byte_eq1_VPU_video_codec_enum"]==0 and
         s["MovieCodec_byte_ne1_VPU_video_codec_enum"]==1 and
         s["selected_Fuji_codec0_HEVC_static_support"]==True and
         o["SndSetOption_fixed_indices_order"]==[1,16,38,1,5] and
         o["SndSetOption_direct_profile_level_index3_occurrences"]==0 and
         o["SndSetOption_conditional_HEVC_stream_bitdepth_index38"]==False and
         o["all_other_indirect_or_other_queue_messages_excluded"]==False and
         h["input_video_codec_enum_0_header_record_count_if_split"]==3 and
         h["input_video_codec_enum_1_header_record_count_if_split"]==2,
         "Stage42 HEVC/H264 source, bounded direct Profile index3 or 3/2 headers changed")
    return old

def expected_sites(m):
    return {
     m.header_flag_store:0xe5821010,
     m.header_offset_store:0xe5821018,
     m.header_alloc_mov:0xe3a01a01,
     m.header_alloc_store:0xe5821014,
     m.header_filled_store:0xe580701c,
     m.header_ptr_store:0xe5805020,
     m.header_code_mov:0xe3001bba,
     m.header_code2_mov:0xe3001bba,
     m.response_flag_test:0xe3130080,
     m.response_flag_test2:0xe3130080,
     m.response_bufaddr_load:0xe5992020,
     m.response_offset_load:0xe5993018,
     m.response_filled_load:0xe599e01c,
     m.status_confirm_mov:0xe30037d3,
     m.status_sequence_mov:0xe30037df,
     m.status_fail_mov:0xe30037e1,
     m.response_flush_mov:0xe3a00ffb, # ARM MOV #1004 / 0x3EC
    }

def require_site_trace(text,fn,at,mnemonic,imm):
    expected=("ST43_SITE fn=FUN_%08x at=%08x mnemonic=%s imm=%x"%
              (fn,at,mnemonic,imm))
    need(expected in text,"read-only Ghidra instruction scalar-site missing "+expected)

def verify_model(m,rom,logs,prior):
    need(sha256(rom).hexdigest()==m.sha,
         "unmodified original ROM Section1 SHA256 not accepted")
    validate_stage42(prior,m.name)
    rd=lambda addr:original_word(rom,addr)
    for at,inst in expected_sites(m).items():
        need(rd(at)==inst,
             "original ARM bitstream descriptor/flags/response opcode changed at "+hex(at))
    for source,target in (
      (m.header_send_bl,m.header_send_api),
      (m.header_send2_bl,m.header_send2_api),
      (m.response_flush_bl,m.response_msg_sender)
    ):
        need(a32_bl(rd(source),source)==target,
             "original bitstream or output-flush ARM BL target differs "+hex(source))
    for at,mnem,imm in (
       (m.header_alloc_mov,"mov",0x1000),
       (m.header_code_mov,"movw",0xBBA),
       (m.header_code2_mov,"movw",0xBBA),
       (m.response_flag_test,"tst",0x80),
       (m.response_flag_test2,"tst",0x80),
       (m.response_bufaddr_load,"ldr",0x20),
       (m.response_offset_load,"ldr",0x18),
       (m.response_filled_load,"ldr",0x1c),
       (m.status_confirm_mov,"movw",0x7d3),
       (m.status_sequence_mov,"movw",0x7df),
       (m.status_fail_mov,"movw",0x7e1),
       (m.response_flush_mov,"mov",0x3ec),
    ):
        fn=m.header_builder if at in (
            m.header_alloc_mov,m.header_code_mov,m.header_code2_mov
        ) else m.response_fn
        require_site_trace(logs["a32sites"],fn,at,mnem,imm)
    head=decomp(logs["header"],m.header_builder)
    ptr="_DAT_%08x"%m.header_global
    need(("FUN_%08x("%m.header_builder) in head and
         "FUN_%08x("%m.header_send_api in head and
         "FUN_%08x("%m.header_send2_api in head and
         head.count("0xbba,0x28")==2 and
         head.count("puVar5[5] = 0x1000;")==2 and
         head.count("puVar5[6] = 0;")==2 and
         head.count("puVar5[2] = 0;")==2 and
         head.count("puVar5[3] = 0;")==2 and
         "puVar5[8] = uVar4;" in head and
         "puVar1[8] = (0x20000000 - " in head and
         "*%s = uVar3 + 0x4b0da000;"%ptr in head and
         "if (*(int *)(iVar2 + 400) == 1)" in head and
         "uVar7 = 2;" in head and "uVar7 = 3;" in head,
         "Ghidra bitstream header producer layout, count or CODE_BBA missing")
    rx=decomp(logs["ring"],m.response_ring_unpack)
    need("0x3fc" in rx and
         ">> 0x10" in rx and
         "*param_1 = *(undefined4 *)" in rx,
         "CPU software response ring payload unpack is not verified")
    handler=decomp(logs["handler"],m.response_fn)
    slot=m.response_bitstream_global
    names={
      "flags":"_DAT_%08x"%(slot+0x10),
      "offset":"_DAT_%08x"%(slot+0x18),
      "filled":"_DAT_%08x"%(slot+0x1c),
      "address":"_DAT_%08x"%(slot+0x20),
    }
    need(("FUN_%08x(&DAT_%08x);"%(m.response_ring_unpack,slot)) in handler,
         "OUTPUT receive path does not populate expected bitstream descriptor")
    need(("_DAT_%08x & 0x80"% (slot+0x10)) in handler or
         ("(%s & 0x80)"%names["flags"]) in handler,
         "OUTPUT CODECCONFIG 0x80 test not found")
    need(("%s + %s;"%(names["address"],names["offset"])) in handler and
         names["filled"] in handler and
         ("FUN_%08x(iVar7)"%m.output_resolve_fn) in handler and
         "if ((_DAT_%08x & 0x11) == 0)"%(slot+0x10) in handler,
         "OUTPUT received addr+offset and filled_len handling not verified")
    resolver=decomp(logs["ring"],m.output_resolve_fn)
    need(("_DAT_%08x"%m.output_resolve_table_global) in resolver and
         "(param_1 >> 0xc) * 4" in resolver and
         "param_1 & 0xfff" in resolver,
         "OUTPUT return data address involves runtime translation, not a file address")
    need(("if (uVar4 == 0x7d3)" in handler and
          "if (uVar4 == 0x7df)" in handler and
          "if (uVar4 == 0x7e1)" in handler and
          "if (uVar4 == 0x7d7)" in handler and
          "if (uVar4 < 0x7d7)" in handler and
          ("FUN_%08x(0x3ec,0);"%m.response_msg_sender) in handler and
          ("FUN_%08x(0x10);"%m.response_event) in handler and
          ("FUN_%08x(0x20000);"%m.response_event) in handler),
         "Ghidra explicit MVE response confirm/fail/SEQ_PARAMS/OUTPUT_FLUSH branches absent")
    return {
      "model":m.name,
      "original_rom1_sha256":m.sha,
      "CPU_bitstream_header_builder":"FUN_%08x"%m.header_builder,
      "CPU_header_descriptor_block_bytes":40,
      "bitstream_header_buffer_alloc_bytes":0x1000,
      "CPU_0xBBA_send_original_BLs":["0x%08x"%m.header_send_bl,
                                    "0x%08x"%m.header_send2_bl],
      "HEVC_header_record_count_if_known_codec0":3,
      "H264_header_record_count_if_known_codec1":2,
      "CPU_MVE_OUTPUT_response_function":"FUN_%08x"%m.response_fn,
      "CPU_OUTPUT_ring_reader":"FUN_%08x"%m.response_ring_unpack,
      "CPU_OUTPUT_bitstream_descriptor_global":"0x%08x"%slot,
      "OUTPUT_CODECCONFIG_test_mask":"0x80",
      "OUTPUT_buf_addr_plus_offset_read_from_descriptor":True,
      "OUTPUT_filled_len_read_from_descriptor":True,
      "OUTPUT_runtime_buffer_address_translation_function":
        "FUN_%08x"%m.output_resolve_fn,
      "SET_OPTION_CONFIRM_response":"0x7d3",
      "SET_OPTION_FAIL_response":"0x7e1",
      "SEQUENCE_PARAMETERS_response":"0x7df",
      "SEQUENCE_PARAMETERS_branch_statically_sends_OUTPUT_FLUSH":"0x3ec",
      "SEQUENCE_PARAMS_response_is_not_coded_HEVC_VPS_SPS_PPS":True,
      "Main10_SPS_or_hvcC_extracted":False,
      "successful_VPU_HEVC_Main10_encoder_execution_observed":False,
      "unknown_V61_microcode_receiver_disassembled":False,
      "hardware_camera_or_flash_accessed":False,
    }

def read_previous(path,marker):
    return json.loads(path.read_text().split("\n"+marker,1)[0])

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    out=ap.parse_args().output
    abi=public_abi()
    orig42=read_previous(out/"stage42_vpu_fw_codec_profile_audit.jsonlog","STAGE42")
    rows=[]
    for m in MODELS.values():
        logs={
         "a32sites":(out/m.assembler_log).read_text(),
         "handler":(out/m.resp_c_log).read_text(),
         "header":(out/m.handler_refs_log).read_text(),
         "ring":(out/m.ring_c_log).read_text(),
        }
        rom=(out/f"x6-{m.name}/section-1.bin").read_bytes()
        rows.append(verify_model(m,rom,logs,orig42))
    need(rows[0]["CPU_header_descriptor_block_bytes"]==
         rows[1]["CPU_header_descriptor_block_bytes"]==
         ctypes.sizeof(MveBitstream) and
         rows[0]["OUTPUT_CODECCONFIG_test_mask"]==
         rows[1]["OUTPUT_CODECCONFIG_test_mask"],
         "cross-model MVE bitstream output/CPU return path mismatched")
    print(json.dumps({
      "independently_rebuilt_public_MVE_abi":abi,
      "fuji_original_ARM_and_readonly_Ghidra":rows,
      "original_ROM_and_all_video_data_kept_local":True,
      "actual_HEVC_Main10_SPS_or_10bit_video_sample_observed":False,
      "X_S10_4K60_claimed":False
    },ensure_ascii=False,indent=2))
    print("STAGE43 ORIGINAL CPU MVE OUTPUT CODECCONFIG / SEQUENCE-ALERT PATH PASS")
    print("Main10 SPS, hardware receipt and 4K60 still UNPROVEN; no camera access.")
if __name__=="__main__":main()

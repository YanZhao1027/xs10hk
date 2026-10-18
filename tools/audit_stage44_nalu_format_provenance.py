#!/usr/bin/env python3
"""Stage44 read-only original-ARM NALU format provenance.

Follow caller 48-byte parameter block -> NALU enum RAM first word ->
init object +0x18 -> SET_OPTION NALU_FORMAT index1 -> CPU OUTPUT buffer
4-byte big-endian NAL length rewrite if runtime mode==16.

The source function uses a dec_param diagnostic; no proof the camera's
movie HEVC path ever invokes it or selects mode16. No HEVC SPS captured.
No camera, USB/FF80, hardware RAM, ROM patch, Flash write or unlock.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import argparse, json, re, struct, sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage43_mve_bitstream_return as st43
import inspect_hevc_sps_stage44 as sps

BASE=0x01021000
NALU_OPTION_INDEX=1
NALU_FORMATS=(1,2,4,8,16)

@dataclass(frozen=True)
class Model:
    name:str
    source_fn:int
    adapter_fn:int
    adapter_bl:int
    source_ram:int
    stm_a:int
    stm_b:int
    stm_c:int
    compare16:int
    reader_fn:int
    reader_ldr:int
    reader_str:int
    snd_bl:int
    hdr_bl:int
    snd_fn:int
    hdr_fn:int
    msg_sender:int
    config_ptr:int
    response_fn:int
    received_filled:int
    source_log:str
    refs_log:str
    adapter_log:str
    opts_log:str
    response_log:str

MODELS={
 "xs10":Model(
  "xs10",0x011f9cf4,0x011f7494,0x011f749c,0x01b55de0,
  0x011f9e10,0x011f9e18,0x011f9e20,0x011f9e28,
  0x011f89f0,0x011f8a28,0x011f8a2c,0x011f8a44,0x011f8a54,
  0x011fb758,0x011fb3b8,0x011fa530,0x01c09b68,0x011fcbc4,0x019e5614,
  "xs10_stage44_nalu_mode_writer_and_reader.log",
  "xs10_stage44_nalu_global_refs.log",
  "xs10_stage44_decparam_api_chain.log",
  "xs10_vpu_setoptions.log",
  "xs10_stage39_mmio_status_router_c.log"),
 "xt4":Model(
  "xt4",0x011cd3a0,0x011cab40,0x011cab48,0x01abfd58,
  0x011cd4bc,0x011cd4c4,0x011cd4cc,0x011cd4d4,
  0x011cc09c,0x011cc0d4,0x011cc0d8,0x011cc0f0,0x011cc100,
  0x011cee04,0x011cea64,0x011cdbdc,0x01b682a8,0x011d0270,0x01955554,
  "xt4_stage44_nalu_mode_writer_and_reader.log",
  "xt4_stage44_nalu_global_refs.log",
  "xt4_stage44_decparam_api_chain.log",
  "xt4_vpu_setoptions.log",
  "xt4_stage39_mmio_status_router_c.log")
}

def need(value,why):
    if not value:raise ValueError("Stage44 NALU source: "+why)

def arm_word(rom,addr):
    off=addr-BASE
    need(off>=0 and off%4==0 and off+4<=len(rom),
         "original A32 offset absent or unaligned")
    return struct.unpack_from("<I",rom,off)[0]

def bl_target(word,site):
    need(word>>28==14 and (word&0x0f000000)==0x0b000000,
         "original A32 BL opcode unexpected")
    off=word&0xffffff
    if off&0x800000:off-=0x1000000
    return (site+8+off*4)&0xffffffff

def source_words(m):
    return {
      m.stm_a:0xe8ac000f, m.stm_b:0xe8ac000f,
      m.stm_c:0xe88c000f, m.compare16:0xe3530010,
      m.reader_ldr:0xe5933000, m.reader_str:0xe5823018,
    }

def c_function(log,address):
    pattern=r"(?m)^\s*(?:void|int|uint|undefined\d+)\s+FUN_%08x\("%address
    for seg in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        text=seg.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(pattern,text):return text
    raise ValueError("Ghidra original function missing "+hex(address))

def public_nalu_abi():
    need(NALU_OPTION_INDEX==1 and NALU_FORMATS==(1,2,4,8,16) and
         st43.public_abi()["mve_buffer_bitstream_bytes"]==40 and
         st43.CODECCONFIG_MASK==0x80 and
         sps.MVE_MAIN10_OPTION_PROFILE_VALUE==4 and
         sps.HEVC_MAIN10_PROFILE_IDC==2,
         "public MVE NALU vs actual coded HEVC Main10 values differ")
    return {
      "MVE_SET_OPT_INDEX_NALU_FORMAT":1,
      "START_CODES":1,
      "ONE_NALU_PER_BUFFER":2,
      "ONE_BYTE_LENGTH_FIELD":4,
      "TWO_BYTE_LENGTH_FIELD":8,
      "FOUR_BYTE_LENGTH_FIELD":16,
      "public_MVE_Main10_profile_option_enum":4,
      "coded_HEVC_SPS_Main10_general_profile_idc":2,
      "a_NALU_length_format_is_not_an_HEVC_Main10_profile":True,
    }

def fourbyte_nalu_prefix(total_bytes):
    need(isinstance(total_bytes,int) and 4<total_bytes<=0xffffffff,
         "filled_len must be at least five bytes and fit uint32")
    return (total_bytes-4).to_bytes(4,"big")

def check_prior43(data,m):
    rows=data["fuji_original_ARM_and_readonly_Ghidra"]
    need(len(rows)==2 and {x["model"] for x in rows}=={"xs10","xt4"},
         "prior Phase43 model coverage changed")
    row=next(x for x in rows if x["model"]==m.name)
    need(row["original_rom1_sha256"]==st43.MODELS[m.name].sha and
         row["CPU_OUTPUT_bitstream_descriptor_global"]==
         "0x%08x"%st43.MODELS[m.name].response_bitstream_global and
         row["OUTPUT_CODECCONFIG_test_mask"]=="0x80" and
         row["Main10_SPS_or_hvcC_extracted"] is False,
         "prior original ROM/output or SPS evidence changed")

def check_xrefs(m,text):
    target="PROBE_TARGET addr=%08x refs=2"%m.source_ram
    w="PROBE_REF from=%08x to=%08x type=WRITE"%(m.stm_a,m.source_ram)
    r="PROBE_REF from=%08x to=%08x type=READ"%(m.reader_ldr,m.source_ram)
    need(target in text and w in text and r in text,
         "Ghidra direct source RAM writer and reader xrefs missing")
    block=text.split(target,1)[1].split("PROBE_TARGET",1)[0]
    need(block.count("PROBE_REF from=")==2,
         "direct static RAM reference inventory changed")

def verify_model(m,rom,log,old):
    need(sha256(rom).hexdigest()==st43.MODELS[m.name].sha,
         "unmodified original Section1 SHA wrong")
    check_prior43(old,m)
    a=lambda x:arm_word(rom,x)
    for at,w in source_words(m).items():
        need(a(at)==w,"original 48B ARM copy or 0x10 conditional differs "+hex(at))
    for at,target in ((m.adapter_bl,m.source_fn),
                      (m.snd_bl,m.snd_fn),(m.hdr_bl,m.hdr_fn)):
        need(bl_target(a(at),at)==target,"original direct BL target differs "+hex(at))
    check_xrefs(m,log["refs"])
    writer=c_function(log["source"],m.source_fn)
    reader=c_function(log["source"],m.reader_fn)
    adapter=c_function(log["adapter"],m.adapter_fn)
    options=c_function(log["opts"],m.snd_fn)
    response=c_function(log["response"],m.response_fn)
    source="_DAT_%08x"%m.source_ram
    setting="_DAT_%08x"%m.config_ptr
    fill="_DAT_%08x"%m.received_filled
    must_writer=(
      "dec_param",
      "%s = *param_1;"%source,
      "_DAT_%08x = param_1[0xb];"%(m.source_ram+0x2c),
      "if (*param_1 == 0x10)",
      "if (*param_1 == 1)",
      "bVar1 = *pbVar10;",
      "*pbVar10 = bVar4;",
      "pbVar10[1] = bVar3;",
      "pbVar10[2] = bVar2;",
      "pbVar10[3] = bVar1;",
      "uVar12 = 2;",
      "uVar12 = 3;",
    )
    need(all(t in writer for t in must_writer),
         "Ghidra original decoder-parameter source and 16-format byte swap changed")
    need(("%s[6] = %s;"%(setting,source)) in reader and
         ("FUN_%08x();"%m.snd_fn) in reader and
         ("FUN_%08x();"%m.hdr_fn) in reader,
         "CPU init does not copy actual saved NALU mode to dynamic setup+0x18 then send option")
    need(("FUN_%08x();"%m.source_fn) in adapter,
         "original decoder-param API adapter chain missing")
    need(options.count("local_58 = 1;")==2 and
         options.count("local_54 = %s[6];"%setting)==2 and
         options.count("FUN_%08x(0x3f2,8,&local_58);"%m.msg_sender)==5 and
         "local_58 = 0x10;" in options and
         "local_58 = 0x26;" in options,
         "SndSetOption does not send NALU_FORMAT index1 using saved setting in both cases")
    need(response.count("if (%s[6] == 0x10)"%setting)>=2 and
         response.count("iVar9 = %s + -4;"%fill)==2 and
         response.count("*puVar5 = (char)((uint)iVar9 >> 0x18);")==2 and
         response.count("puVar5[1] = (char)((uint)iVar9 >> 0x10);")==2 and
         response.count("puVar5[2] = (char)((uint)iVar9 >> 8);")==2 and
         response.count("puVar5[3] = (char)iVar9;")==2,
         "CODECCONFIG/bitstream CPU return four-byte big-endian rewrite unverified")
    return {
      "model":m.name,
      "source_decoder_param_function":"FUN_%08x"%m.source_fn,
      "param_block_bytes":"0x30",
      "source_12_words_written_to_RAM_start":"0x%08x"%m.source_ram,
      "source_3_original_STMIA_sites":[hex(m.stm_a),hex(m.stm_b),hex(m.stm_c)],
      "source_0x10_A32_cmp_site":hex(m.compare16),
      "source_writer_one_direct_Ghidra_WRITE_at":hex(m.stm_a),
      "setup_source_reader":"FUN_%08x"%m.reader_fn,
      "setup_mode_u32_from_RAM":"0x%08x"%m.reader_ldr,
      "setup_object_plus_0x18_store":"0x%08x"%m.reader_str,
      "option1_NALU_FORMAT_uses_saved_value_in_two_branches":True,
      "output_mode16_converts_filled_len_minus4_to_be32":True,
      "direct_Ghidra_refs_to_source_RAM":2,
      "aliases_indirect_writers_excluded":False,
      "runtime_param_1_value_or_movie_encoder_invocation_proven":False,
      "real_main10_SPS_captured":False,
      "physical_camera_modified":False,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    out=ap.parse_args().output
    abi=public_nalu_abi()
    prior=json.loads((out/"stage43_mve_output_original_audit.jsonlog").read_text().split("\nSTAGE43",1)[0])
    models=[]
    for m in MODELS.values():
        logs={slot:(out/getattr(m,key)).read_text() for slot,key in (
          ("source","source_log"),("refs","refs_log"),("adapter","adapter_log"),
          ("opts","opts_log"),("response","response_log"))}
        source=(out/f"x6-{m.name}/section-1.bin").read_bytes()
        models.append(verify_model(m,source,logs,prior))
    print(json.dumps({
      "published_MVE_NALU_enumerations":abi,
      "two_original_camera_models_static_assignment":models,
      "physical_runtime_main10_or_nalu_format_observed":False,
      "ROM_camera_USB_FF80_or_flash_modified":False,
    },ensure_ascii=False,indent=2))
    print("STAGE44 NALU-FORMAT SOURCE-TO-SETOPTION-TO-OUTPUT A32 AUDIT PASS")
    print("Real movie mode16 selection, Main10 SPS/4K60 unknown; no physical access.")
if __name__=="__main__":main()

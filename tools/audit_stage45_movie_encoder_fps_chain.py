#!/usr/bin/env python3
"""Stage45 offline original X-S10/X-T4 encoder param source and 23.98..59.94fps.

Two firmware ROM sections + local read-only Ghidra logs only. This audits:
MovieSetup Section2 -> 60B encoder param block with mode=0x10 and six
Q16 fps values -> original Section2 BL -> Section1 encoder entry adapter ->
15-word A32 encoder parameter saver -> 5 cached config fields -> distinct
MVE SET_OPTION(index1 NALU, index16 P_FRAMES) and MVE_BUFFER_CODE_PARAM
(type9 FRAMERATE, type10 RATE_CONTROL, others 23/15/21).

Physical camera (previously 2.10), USB/FF80, RAM/flash, source ROM, patch
and V61 bytecode NEVER touched or altered. No real Main10 SPS or 4K60 claim.
"""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage44_nalu_format_provenance as st44

Q16=65536
FPS_TABLE={
    1:0x17FAE1,  # 23.979995728
    2:0x180000,  # 24
    3:0x190000,  # 25
    4:0x1DF851,  # 29.969985962
    5:0x320000,  # 50
    6:0x3BF0A3,  # 59.939987183
}
PUBLIC_MVE={
  "MVE_SET_OPT_INDEX_NALU_FORMAT":1,
  "MVE_SET_OPT_INDEX_ENC_P_FRAMES":16,
  "MVE_BUFFER_PARAM_TYPE_FRAME_RATE":9,
  "MVE_BUFFER_PARAM_TYPE_RATE_CONTROL":10,
  "MVE_BUFFER_PARAM_TYPE_RATE_CONTROL_HRD_BUF_SIZE":23,
  "MVE_BUFFER_PARAM_TYPE_COLOUR_DESCRIPTION":15,
  "MVE_BUFFER_PARAM_TYPE_RATE_CONTROL_QP_RANGE":21,
  "MVE_BUFFER_CODE_PARAM":3003,
  "MVE_REQUEST_CODE_SET_OPTION":1010,
}
SECTION1_BASE=0x01021000
FILENAME_1="section-1.bin"
FILENAME_2="section-2.bin"

@dataclass(frozen=True)
class Model:
    name:str
    sha2:str
    section2_base:int
    movie_fn:int
    movie_wrapper_bl:int
    movie_param_ram:int
    movie_mode_store:int
    fps_ram_store_sites:tuple
    source_fn:int
    source_fn_bl:int
    saved_ram:int
    source_stmia:int
    source_stmia2:int
    init_fn:int
    init_bl:int
    cache:int
    cached_codecreg:int
    cached_nalreg:int
    cached_fpsreg:int
    cached_rcmode_reg:int
    cached_rcbitrate_reg:int
    option_fn:int
    option_bl:int
    option_generic:int
    bufferparam_fn:int
    bufferparam_bl:int
    bufferparam_generic:int
    movie_log:str
    source_log:str
    option_log:str
    other_log:str
    xrefs_log:str
    moviexref_log:str

MODELS={
 "xs10":Model(
  "xs10",
  "f0c4db782031a81c620d764317ebf0219d10bb4b52eb4fd5998b9ce39c3afb8c",
  0x01EAF000,
  0x022dee64,0x022df508,0x029459cc,0x022df1c4,
  (0x022df224,0x022df2e8,0x022df300,0x022df314,0x022df328,0x022df340),
  0x011f9b84,0x011f7464,0x019fb67c,0x011f9c20,0x011f9c28,
  0x011f8914,0x011f946c,0x01c09b68,
  0x011f8964,0x011f896c,0x011f895c,0x011f894c,0x011f8954,
  0x011fb758,0x011f89b8,0x011fa530,
  0x011fafb0,0x011f89c0,0x011fa714,
  "xs10_stage45_movie_encoder_param_callsite.log",
  "xs10_stage45_encoder_param_calls.log",
  "xs10_stage45_enc_params_option_consumers.log",
  "xs10_stage45_encoder_entry_xrefs.log",
  "xs10_stage45_encoder_param_xrefs.log",
  "xs10_stage45_movie_fps_ram_xrefs.log",
 ),
 "xt4":Model(
  "xt4",
  "e1ef8b30903d3078fde103cdd134fca7bfc4337d67bcaf55c3080ffd5fd93b13",
  0x01E0F000,
  0x0224b65c,0x0224bc90,0x028a5114,0x0224b9bc,
  (0x0224ba1c,0x0224baa0,0x0224bab8,0x0224bacc,0x0224bae0,0x0224baf8),
  0x011cd230,0x011cab10,0x0196b6d0,0x011cd2cc,0x011cd2d4,
  0x011cbfc0,0x011ccb18,0x01b682a8,
  0x011cc010,0x011cc018,0x011cc008,0x011cbff8,0x011cc000,
  0x011cee04,0x011cc064,0x011cdbdc,
  0x011ce65c,0x011cc06c,0x011cddc0,
  "xt4_stage45_movie_encoder_param_callsite.log",
  "xt4_stage45_encoder_param_calls.log",
  "xt4_stage45_enc_params_option_consumers.log",
  "xt4_stage45_encoder_entry_xrefs.log",
  "xt4_stage45_encoder_param_xrefs.log",
  "xt4_stage45_movie_fps_ram_xrefs.log",
 ),
}

# One dataclass field is the encoder adapter rather than parameter block addr.
ENCODER_ADAPTER={"xs10":0x011f745c,"xt4":0x011cab08}
ROM1_SHA={
 "xs10":"c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff",
 "xt4":"0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb",
}
# Original A32 stores that write all six distinct Q16 values to MovieSetup param[2].
# Each separate case has its own immediate-form source value and same offset +8.
FPS_STORE_ORIGINAL={"xs10":0xe581e008,"xt4":0xe582c008}

def require(value,why):
    if not value:raise ValueError("Stage45 original encoder fps audit: "+why)

def u32(rom,site,base):
    i=site-base
    require(i>=0 and i%4==0 and i+4<=len(rom),"A32 ROM instruction OOB "+hex(site))
    return struct.unpack_from("<I",rom,i)[0]

def a32_bl_target(word,site):
    require(word>>28==14 and word&0x0f000000==0x0b000000,
            "not original unconditional A32 BL at "+hex(site))
    rel=word&0xffffff
    if rel&0x800000:rel-=0x1000000
    return (site+8+rel*4)&0xffffffff

def decomp(log,fn):
    pat=r"(?m)^\s*(?:void|int|uint|undefined\d+)\s+FUN_%08x\("%fn
    for blob in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=blob.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(pat,c):return c
    raise ValueError("Ghidra decomp not found for "+hex(fn))

def to_fps(fixed):
    require(isinstance(fixed,int) and 0<fixed<2**32,"not valid Q16 fps")
    return fixed/Q16

def check_public_abi():
    required=st44.public_nalu_abi()
    require(required["MVE_SET_OPT_INDEX_NALU_FORMAT"]==1 and
            required["FOUR_BYTE_LENGTH_FIELD"]==16 and
            tuple(FPS_TABLE)==(1,2,3,4,5,6) and
            all(0 < v < (1<<32) for v in FPS_TABLE.values()) and
            PUBLIC_MVE["MVE_BUFFER_CODE_PARAM"]==0xbbb and
            PUBLIC_MVE["MVE_REQUEST_CODE_SET_OPTION"]==0x3f2 and
            PUBLIC_MVE["MVE_BUFFER_PARAM_TYPE_FRAME_RATE"]==9 and
            PUBLIC_MVE["MVE_SET_OPT_INDEX_ENC_P_FRAMES"]==16,
            "public MVE v2/v3 parameter and Q16 meanings do not match")
    return {
      "public_MVE_abi_values":PUBLIC_MVE,
      "public_MVE_framerate_Q16_values_by_Fuji_enum":{
        str(k):{"q16_hex":hex(v),"fps":round(to_fps(v),9)} for k,v in FPS_TABLE.items()
      },
      "MVE_Main10_profile_option_index_3_seen_in_this_encoder_path":False,
      "V61_default_Main10_profile_proven":False,
    }

def check_raw_rom(m,rom1,rom2):
    require(sha256(rom1).hexdigest()==ROM1_SHA[m.name],
            "original Section1 SHA mismatched")
    require(sha256(rom2).hexdigest()==m.sha2,
            "original Section2 SHA mismatched")
    a=lambda x:u32(rom1,x,SECTION1_BASE)
    b=lambda x:u32(rom2,x,m.section2_base)
    for site,target,r in (
      (m.movie_wrapper_bl,ENCODER_ADAPTER[m.name],b),
      (m.source_fn_bl,m.source_fn,a),
      (m.init_bl,m.init_fn,a),
      (m.option_bl,m.option_fn,a),
      (m.bufferparam_bl,m.bufferparam_fn,a),
    ):
        require(a32_bl_target(r(site),site)==target,
                "original Section1/Section2 direct call target diverged "+hex(site))
    require(a(m.source_stmia)==0xe8ae000f and
            a(m.source_stmia2)==0xe8ae000f,
            "original encoder 60-byte source writer initial STMIA differed")
    sites_and_words={
      m.cached_codecreg:0xe5930000,
      m.cached_nalreg:0xe5933004,
      m.cached_fpsreg:0xe5930008,
      m.cached_rcmode_reg:0xe593000c,
      m.cached_rcbitrate_reg:0xe5930010,
      m.movie_mode_store:0xe5832004,
    }
    for site,word in sites_and_words.items():
        reader=b if site==m.movie_mode_store else a
        require(reader(site)==word,
                "original encoder source word/offset A32 differed "+hex(site))
    require(len(m.fps_ram_store_sites)==6,
            "six original enum cases missing")
    for site in m.fps_ram_store_sites:
        require(b(site)==FPS_STORE_ORIGINAL[m.name],
                "original six Q16 fps stores at +8 differ "+hex(site))
    return {
      "section1_sha256":ROM1_SHA[m.name],
      "section2_sha256":m.sha2,
      "movie_to_encoder_adapter_BL":hex(m.movie_wrapper_bl),
      "original_param1_mode16_A32_STR_at":hex(m.movie_mode_store),
      "six_original_fps_writer_A32_STR_sites":
          [hex(a) for a in m.fps_ram_store_sites],
      "original_encoder_param_saver_A32_STMIA":hex(m.source_stmia),
      "original_cached_5_inputs_A32_LDR":list(map(hex,(
         m.cached_codecreg,m.cached_nalreg,m.cached_fpsreg,
         m.cached_rcmode_reg,m.cached_rcbitrate_reg))),
    }

def validate_ghidra(m,logs):
    movie=decomp(logs["movie"],m.movie_fn)
    enc=decomp(logs["source"],m.source_fn)
    loader=decomp(logs["source"],m.init_fn)
    opt=decomp(logs["consumers"],m.option_fn)
    bp=decomp(logs["consumers"],m.bufferparam_fn)
    block="_DAT_%08x"%m.movie_param_ram
    saved="_DAT_%08x"%m.saved_ram
    cached="_DAT_%08x"%m.cache

    must_movie=[
       # MovieSetup derives each of the six encoder Q16 frame rate choices
       "FUN_%08x(&DAT_%08x,"%(ENCODER_ADAPTER[m.name],m.movie_param_ram),
       "FUN_",
       "0,0x3c);",
       "_DAT_%08x = 0x10;"%(m.movie_param_ram+4),
       "(param_1 + 0x5c6)",
       "(param_1 + 0x5c7)",
       "(iVar7 + 0x5f5)",
       "(iVar7 + 0x600)",
       "(iVar7 + 0x602)",
       "(param_1 + 0xadda)",
       "0xca0000",
       "0xd08000",
    ]
    require(all(x in movie for x in must_movie),
            "Ghidra MovieSetup param and codec selects are missing")
    # Require each enum maps to its own explicit Q16 value (not a random
    # presence of constants elsewhere in that C function).
    for enum,value in FPS_TABLE.items():
        pattern=r"case %d:\s*_DAT_%08x = 0x%x;\s*break;"%(
            enum,m.movie_param_ram+8,value)
        require(re.search(pattern,movie) is not None,
                "original MovieSetup Q16 case/provenance differs for enum "+str(enum))
    require(("*param_1" in enc and
             "%s = *param_1;"%saved in enc and
             "_DAT_%08x = param_1[0xe];"%(m.saved_ram+0x38) in enc and
             "enc_param" in enc and
             "_DAT_0" in enc and "FUN_" in enc),
            "Ghidra 15-word true encoding setter missing")
    required_assign=[
      "%s[2] = _DAT_%08x;"%(cached,m.saved_ram+12),
      "piVar1[3] = _DAT_%08x;"%(m.saved_ram+16),
      "piVar1[4] = _DAT_%08x;"%(m.saved_ram+8),
      "piVar1[5] = %s;"%saved,
      "piVar1[6] = _DAT_%08x;"%(m.saved_ram+4),
      ("FUN_%08x();"%m.option_fn),
      ("FUN_%08x();"%m.bufferparam_fn),
    ]
    require(all(x in loader for x in required_assign),
            "Ghidra encoder param0-4 -> config Pframes/NALU/fps/rate fields broken")
    need_option=(
      "local_58 = 1;",
      "local_54 = %s[6];"%cached,
      "local_58 = 0x10;",
      "local_54 = piVar1[5];",
      ("FUN_%08x(0x3f2,8,&local_58);"%m.option_generic),
    )
    require(all(x in opt for x in need_option) and
            opt.count("local_58 = 1;")==2 and
            "local_58 = 3;" not in opt,
            "Ghidra index1 and index16 actual SetOption sender changed")
    need_buffer=(
      "*_DAT_",
      " = 9;",
      "(%s + 0x10)"%cached,
      ",0xbbb,8);",
      " = 10;",
      "(%s + 8)"%cached,
      "iVar1 + 0xc",
      ",0xbbb,0xc);",
      " = 0x17;",
      " = 0xf;",
      " = 0x15;",
    )
    require(all(s in bp for s in need_buffer),
            "Ghidra MVE BUFFER_PARAM type9 FPS/10 RC/23 HRD/15 colour/21 QP changed")
    # Exact evidence to distinguish encoder and decoder data sources:
    require("%s[6] = "%cached not in loader and
            "V61_drv_set_enc_param_start" in loader and
            "V61_drv_set_dec_param_start" not in loader,
            "encoder path accidentally conflated with decoder")
    need_xref=[
       "PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL"%(
            m.movie_wrapper_bl,ENCODER_ADAPTER[m.name]),
    ]
    require(all(x in logs["entry_xrefs"] for x in need_xref),
            "MovieSetup Section2 -> true encoder wrapper Ghidra BL xref missing")
    for idx,readsite in enumerate((
        m.cached_codecreg,m.cached_nalreg,m.cached_fpsreg,
        m.cached_rcmode_reg,m.cached_rcbitrate_reg)):
        addr=m.saved_ram+4*idx
        expected_w=m.source_stmia if idx<4 else m.source_stmia2
        refs=logs["source_xrefs"]
        require(("PROBE_TARGET addr=%08x refs=2"%addr) in refs and
                ("PROBE_REF from=%08x to=%08x type=WRITE"%(expected_w,addr))
                    in refs and
                ("PROBE_REF from=%08x to=%08x type=READ"%(readsite,addr))
                    in refs,
                "encoder param[%d] original Ghidra RAM writer/reader xref changed"%idx)
    # Separate state2 encoder and state3 decoder must never be conflated.
    router_fn={"xs10":0x011f93dc,"xt4":0x011cca88}[m.name]
    router=decomp(logs["source"],router_fn)
    setter_state={"xs10":"_DAT_0182197c","xt4":"_DAT_01790d8c"}[m.name]
    require((setter_state+" = 2;") in enc and
            ("if (%s == 2)"%setter_state) in router and
            ("if (%s == 3)"%setter_state) in router and
            ("FUN_%08x();"%m.init_fn) in router and
            ("FUN_%08x();"%{"xs10":0x011f89f0,
                             "xt4":0x011cc09c}[m.name]) in router,
            "encoder state2 to cache loader vs decoder state3 dispatch not verified")

    r="PROBE_TARGET addr=%08x refs=6"%(m.movie_param_ram+8)
    require(r in logs["fps_xrefs"] and
            logs["fps_xrefs"].count("to=%08x type=WRITE"%(m.movie_param_ram+8))==6,
            "six real original fps enum RAM writers Ghidra xref count differ")
    require("PROBE_TARGET addr=%08x refs=1"%(m.movie_param_ram+4)
            in logs["fps_xrefs"],
            "MovieSetup sets fixed encoder NALU value in exactly one direct site")

    return {
      "MovieSetup_function":"FUN_%08x"%m.movie_fn,
      "encoder_60B_RAM_args":"0x%08x"%m.movie_param_ram,
      "encoder_param_count_u32":15,
      "MovieSetup_statically_sets_param1_NALU_to":"0x10",
      "MovieSetup_fps_enum1_to_6_Q16":{str(k):hex(v) for k,v in FPS_TABLE.items()},
      "MovieSetup_width_from_mode_source_offset":"0x602",
      "MovieSetup_height_from_mode_source_offset":"0x600",
      "MovieSetup_framerate_selection_offsets":["0x5c6","0x5c7"],
      "MovieSetup_H265_vs_H264_section_pointer_by_codec":[
        "0xCA0000","0xD08000"],
      "encoder_driver_setter":"FUN_%08x"%m.source_fn,
      "encoder_cache_loader":"FUN_%08x"%m.init_fn,
      "field_provenance":[
        {"encoder_arg":"param[0]","MVE_option":"index16 ENC_P_FRAMES"},
        {"encoder_arg":"param[1]","MVE_option":"index1 NALU_FORMAT, value0x10"},
        {"encoder_arg":"param[2]","MVE_buffer_param":"type9 FRAME_RATE Q16"},
        {"encoder_arg":"param[3..4]","MVE_buffer_param":"type10 RATE_CONTROL"},
      ],
      "other_buffer_param_types_from_encoder_params":[23,15,21],
      "direct_SndSetOption_index3_profile_level_found_here":False,
      "entire_Fuji_firmware_excludes_indirect_profile_override":False,
      "HEVC_V61_default_profile_known":False,
      "recorded_HEVC_Main10_SPS_observed":False,
      "X_S10_physical_4K60_supported_proven":False,
      "physical_camera_or_original_ROM_modified":False,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    out=ap.parse_args().output
    abi=check_public_abi()
    results=[]
    for m in MODELS.values():
        rom1=(out/f"x6-{m.name}"/FILENAME_1).read_bytes()
        rom2=(out/f"x6-{m.name}"/FILENAME_2).read_bytes()
        raw=check_raw_rom(m,rom1,rom2)
        keys={
          "movie":m.movie_log,"source":m.source_log,"consumers":m.option_log,
          "entry_xrefs":m.other_log,"fps_xrefs":m.moviexref_log,
          "source_xrefs":m.xrefs_log,
        }
        logs={k:(out/p).read_text() for k,p in keys.items()}
        provenance=validate_ghidra(m,logs)
        results.append({"model":m.name,**raw,**provenance})
    require([x["MovieSetup_statically_sets_param1_NALU_to"] for x in results]
            ==["0x10","0x10"],"X-S10/X-T4 movie NALU mode16 assignment differs")
    print(json.dumps({
      "MVE_public_ABI_evidence":abi,
      "two_original_vendor_ROM_readonly_results":results,
      "main10_profile_configuration_or_encoded_SPS_observed":False,
      "4K59_94_mode_viability_on_XS10_observed":False,
      "physical_camera_or_ROM_ever_touched":False,
    },indent=2,ensure_ascii=False))
    print("STAGE45 ORIGINAL MOVIE FPS/ENCODER PARAM/NALU/BITSTREAM A32 AUDIT PASS")
    print("59.94 enum path is NOT evidence of 4K59.94 sensor/ISP/hardware runtime.")
if __name__=="__main__":main()

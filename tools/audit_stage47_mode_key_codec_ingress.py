#!/usr/bin/env python3
"""Stage47 strictly offline, cross-model Movie mode-key and codec ingress.

Finds original Movie/Recorder input mode u16 LE (+ADD8..+ADD9) write:
4K movie type and runtime flag +A8E==1 => low key forced to 6, otherwise
from +5BD; high key copied from +5BE. Codec +ADDA comes via explicit BL
getter returning active Recorder codec global, independent of the LUT match.
A 4K movie fps enum6 is locally handled, but no GUI/sensor/ISP/VPU approval
or Main10 SPS can be inferred. Original ROMs are SHA pinned and read only.
Never operate live camera, FF80, USB, RAM, Flash, or patch firmware.
"""
from dataclasses import dataclass
from pathlib import Path
from hashlib import sha256
import argparse
import json
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage46_joint_movie_mode_matrix as st46
import audit_stage45_movie_encoder_fps_chain as st45

@dataclass(frozen=True)
class Model:
    name:str
    writer_fn:int
    classifier:int
    getter_fn:int
    codec_global:int
    mode_global:int
    low_cond:int
    low_src:int
    high_src:int
    codec_store:int
    classifier_bl:int
    getter_bl:int
    branch_flag_cmp:int
    mode_log:str
    lookup_log:str
    asm_log:str
    setup_log:str

MODELS={
 "xs10":Model("xs10",
  0x022d5fec,0x022d1674,0x012c048c,
  0x01c25208,0x02eda0b4,
  0x022d6284,0x022d6294,0x022d62a0,0x022d62a8,
  0x022d625c,0x022d62a4,0x022d6278,
  "xs10_stage47_modekey_codec_writers_trace.log",
  "xs10_stage46_table_dimension_decoder_and_mode_enum.log",
  "xs10_stage47_modekey_codec_A32_provenance.log",
  "xs10_stage45_movie_encoder_param_callsite.log"),
 "xt4":Model("xt4",
  0x022425bc,0x0223dc04,0x01298c18,
  0x01b83974,0x02e57934,
  0x02242854,0x02242864,0x02242870,0x02242878,
  0x0224282c,0x02242874,0x02242848,
  "xt4_stage47_modekey_codec_writers_trace.log",
  "xt4_stage46_table_dimension_decoder_and_mode_enum.log",
  "xt4_stage47_modekey_codec_A32_provenance.log",
  "xt4_stage45_movie_encoder_param_callsite.log")
}

# Original A32 words at mode classification, +ADD8 low-key writes,
# +ADD9 high-key copy, and active codec getter/copy into +ADDA.
COMMON_WORDS={
  "test_classified":0xe3500000,
  "flag_eq_one":0xe3530001,
  "force_six":0x03a02006,       # MOVEQ r2,#6
  "store_six":0x05c32dd8,       # STRBEQ r2,[r3,#0xDD8]
  "load_low":0xe5d425bd,       # LDRB r2,[r4,#0x5BD]
  "store_low":0xe5c32dd8,      # STRB r2,[r3,#0xDD8]
  "load_high":0xe5d435be,      # LDRB r3,[r4,#0x5BE]
  "store_high":0xe5c53dd9,     # STRB r3,[r5,#0xDD9]
  "store_codec":0xe5c50dda,    # STRB r0,[r5,#0xDDA]
}
GETTER_WORDS={
 "xs10":{
  0x012c0494:0xe3043dd8,
  0x012c0498:0xe34031c2,
  0x012c049c:0xe5d30430,
 },
 "xt4":{
  0x01298c20:0xe3033540,
  0x01298c24:0xe34031b8,
  0x01298c28:0xe5d30434,
 }
}
MORE_SITES={
 "xs10":{
  "test_classified":0x022d6260,
  "flag_eq_one":0x022d6278,
  "force_six":0x022d6280,
  "load_low":0x022d6290,
  "load_high":0x022d629c,
 },
 "xt4":{
  "test_classified":0x02242830,
  "flag_eq_one":0x02242848,
  "force_six":0x02242850,
  "load_low":0x02242860,
  "load_high":0x0224286c,
 }
}

def need(v,why):
    if not v:raise ValueError("Stage47 mode ingress: "+why)

def compute_key(klass_is_4k:bool, runtime_a8e:int, low:int, high:int)->int:
    """Mirror original conditional low-byte override, NOT a physical mode grant."""
    need(isinstance(runtime_a8e,int) and 0<=runtime_a8e<=255 and
         isinstance(low,int) and 0<=low<=255 and
         isinstance(high,int) and 0<=high<=255,
         "invalid runtime mode-identifier byte")
    resolved_low=6 if klass_is_4k and runtime_a8e==1 else low
    return resolved_low|(high<<8)

def read_arm_word(s1,s2,model,at):
    if at < 0x01d00000:
        return st45.u32(s1,at,0x01021000)
    return st45.u32(s2,at,st45.MODELS[model.name].section2_base)

def check_a32(m,at_word):
    common_sites={
       "store_six":m.low_cond,
       "store_low":m.low_src,
       "store_high":m.high_src,
       "store_codec":m.codec_store,
       **MORE_SITES[m.name],
    }
    for typ,site in common_sites.items():
        need(at_word(site)==COMMON_WORDS[typ],
             "original A32 "+typ+" opcode differs at "+hex(site))
    for at,val in GETTER_WORDS[m.name].items():
        need(at_word(at)==val,"original active codec getter A32 changed "+hex(at))
    for site,target in (
        (m.classifier_bl,m.classifier),(m.getter_bl,m.getter_fn)):
        need(st45.a32_bl_target(at_word(site),site)==target,
             "original A32 BL target differs at "+hex(site))
    return {
       "classifier_BL_original_site":hex(m.classifier_bl),
       "conditional_force_low_mode_id_six_store_site":hex(m.low_cond),
       "original_low_mode_copy_store_site":hex(m.low_src),
       "original_high_mode_copy_store_site":hex(m.high_src),
       "original_active_codec_getter_BL_site":hex(m.getter_bl),
       "original_active_codec_store_site":hex(m.codec_store),
       "codec_getter_3_A32_source_words_verified":True,
    }

def validate_ghidra(m,logs):
    w=st46.decomp(logs["mode"],m.writer_fn)
    classf=st46.decomp(logs["lookup"],m.classifier)
    get=st46.decomp(logs["mode"],m.getter_fn)
    setup=st46.decomp(logs["setup"],st45.MODELS[m.name].movie_fn)
    mode_src="_DAT_%08x"%m.mode_global
    codec="DAT_%08x"%m.codec_global
    need(("iVar6 = FUN_%08x(*(undefined1 *)(%s + 0xa8c));"%(
        m.classifier,mode_src)) in w,
        "4K movie-class detector not called with current type +A8C")
    needed=[
      "%s + 0xa8e) != '\\x01'"%mode_src,
      "if ((iVar6 == 0) ||",
      "*(undefined1 *)(iVar8 + 0xadd8) = *(undefined1 *)(iVar8 + 0x5bd);",
      "*(undefined1 *)(iVar8 + 0xadd8) = 6;",
      "*(undefined1 *)(iVar8 + 0xadd9) = *(undefined1 *)(iVar8 + 0x5be);",
      "uVar4 = FUN_%08x();"%m.getter_fn,
      "*(undefined1 *)(iVar8 + 0xadda) = uVar4;",
      "case '\\x06':",
      "uVar7 = 0x3c;",
    ]
    need(all(t in w for t in needed),
         "Ghidra actual source/conditional mode-id and 60fps branch changed")
    need(all(t in classf for t in (
          "case 1:","case 2:","case 3:",
          "case 4:","case 5:","case 6:","case 7:",
          "return 0;","return 1;")),
         "Ghidra 4K movie-class partition changed")
    need(("return %s;"%codec) in get,
         "active recorder codec getter no longer returns expected RAM byte")
    need("(param_1 + 0xadda)" in setup and
         "0xca0000" in setup and "0xd08000" in setup,
         "downstream MovieSetup H265/H264 firmware selection differs")
    asm=logs["asm"]
    # Match only original instruction text, both sites of each root.
    items=(
      (m.low_cond,"strbeq r2,[r3,#0xdd8]"),
      (m.low_src,"strb r2,[r3,#0xdd8]"),
      (m.high_src,"strb r3,[r5,#0xdd9]"),
      (m.getter_bl,"bl 0x%08x"%m.getter_fn),
      (m.codec_store,"strb r0,[r5,#0xdda]"))
    for site,text in items:
        need(("TRACE_INSN %08x %s"%(site,text)) in asm,
             "Ghidra read-only instruction at "+hex(site)+" absent")
    return {
      "model":m.name,
      "Movie_mode_4K_classifier":"FUN_%08x"%m.classifier,
      "Movie_runtime_flag_address_base":"0x%08x"%m.mode_global,
      "runtime_flag_offset":"0xA8E",
      "mode_source_original_bytes":["movie+0x5BD","movie+0x5BE"],
      "mode_key_u16_little_endian_written_to":"movie+0xADD8",
      "4K_type_and_flag1_forces_low_mode_key_6":True,
      "codec_source_getter":"FUN_%08x"%m.getter_fn,
      "active_recorder_codec_byte":"0x%08x"%m.codec_global,
      "codec_writes_into":"movie+0xADDA",
      "MovieSetup_software_60fps_case_present_for_4K_types":True,
      "mode_flag_A8E_hardware_or_menu_semantics_resolved":False,
      "X_S10_GUI_4K60_or_HEVC_joint_access_proven":False,
      "real_Main10_SPS_observed":False,
      "camera_or_ROM_modified":False,
    }

def check_table_crossing(m,rom1,rom2):
    old=st46.MODELS[m.name]
    mod=st45.MODELS[m.name]
    table=st46.section_slice(rom2,mod.section2_base,
                             old.movie_table,st46.STRIDE*st46.RECORDS+1)
    rows=st46.read_records(table)
    need(sha256(table[:st46.STRIDE*st46.RECORDS]).hexdigest()==st46.BODY_SHA,
         "original 96 mode records SHA differs")
    wa=st46.section_slice(rom1,0x01021000,old.widths,st46.DIM_BYTES)
    ha=st46.section_slice(rom1,0x01021000,old.heights,st46.DIM_BYTES)
    need(sha256(wa).hexdigest()==st46.WIDTH_SHA and
         sha256(ha).hexdigest()==st46.HEIGHT_SHA,"original width/height lookups differ")
    out={}
    for high in (2,7):
      normal=compute_key(True,0,7,high)
      forced=compute_key(True,1,7,high)
      need(normal==((high<<8)|7) and forced==((high<<8)|6),
           "mode key override arithmetic wrong")
      ids_normal=st46.match_record(rows,0,normal,6,1)
      ids_forced=st46.match_record(rows,0,forced,6,1)
      need(len(ids_normal)==len(ids_forced)==1,"normal/forced mode row absent")
      size_normal=st46.lookup_width_height(rows[ids_normal[0]],wa,ha)
      size_forced=st46.lookup_width_height(rows[ids_forced[0]],wa,ha)
      need(size_normal==(3840,2160) if high==2 else
           size_normal==(4096,2160),"original 4K lookup expected size missing")
      need(size_forced==(1920,1080) if high==2 else
           size_forced==(2048,1080),"mode-key forced-to-6 decoder must map 1080")
      out["high_key_%d"%high]={
        "preserve_low7": {"record":ids_normal[0],"size":list(size_normal)},
        "flag1_force_low6":{"record":ids_forced[0],"size":list(size_forced)},
      }
    return out

def audit(m,rom1,rom2,logs):
    need(sha256(rom1).hexdigest()==st45.ROM1_SHA[m.name] and
         sha256(rom2).hexdigest()==st45.MODELS[m.name].sha2,
         "original Section1/2 SHA identity differs")
    source=check_a32(m,lambda at:read_arm_word(rom1,rom2,m,at))
    c=validate_ghidra(m,logs)
    out=check_table_crossing(m,rom1,rom2)
    return {"model":m.name,**source,**c,
            "4K59_94_record_key_branch_resolution_pairs":out}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",default=Path("output"),type=Path)
    folder=ap.parse_args().output
    results=[]
    for m in MODELS.values():
      logs={
       "mode":(folder/m.mode_log).read_text(),
       "lookup":(folder/m.lookup_log).read_text(),
       "asm":(folder/m.asm_log).read_text(),
       "setup":(folder/m.setup_log).read_text()}
      sec1=(folder/f"x6-{m.name}"/"section-1.bin").read_bytes()
      sec2=(folder/f"x6-{m.name}"/"section-2.bin").read_bytes()
      results.append(audit(m,sec1,sec2,logs))
    need(results[0]["4K59_94_record_key_branch_resolution_pairs"]==
         results[1]["4K59_94_record_key_branch_resolution_pairs"],
         "actual X-S10/X-T4 record branch mapping divergence")
    print(json.dumps({
       "two_original_ROMs_original_ARM_and_readonly_Ghidra":results,
       "critical_rule":"for 4K film type and flag+0xA8E=1, low key is 6 not 7",
       "model_specific_4K60_restriction_proven":False,
       "Main10_or_HEVC_4K60_real_output_proven":False,
       "device_USB_FF80_RAM_Flash_ROM_changed":False,
    },ensure_ascii=False,indent=2))
    print("STAGE47 ORIGINAL MODE-ID OVERRIDE / CODEC INGRESS A32 AUDIT PASS")
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Stage46 offline cross-camera joint mode LUT audit (X-S10 3.11, X-T4 2.12).

A *static* 96x64-byte Movie/Recorder table is matched on frame class,
two-byte movie-size/mode key, fps enum, and a variant byte; width and
height come from separate 37x5 u32 decode LUTs. This must not be used to
claim a real X-S10 4K59.94 HEVC mode, V61 Main10 or working sensor/ISP.
No device, FF80, USB, flash, ROM modifications or patch generation.
Vendor ROM+Ghidra stay in gitignored output/ only.
"""
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import argparse
import json
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage45_movie_encoder_fps_chain as st45

STRIDE=0x40
RECORDS=96
DIM_BYTES=0x2e4
ENDMARKER=0xff
BODY_SHA="43852b4bb7454ad54b1a9d018432250829abb334dec9961fb54e4862407199bc"
WIDTH_SHA="1487b8f22ce79a2255416db3c5610be42aa33305695b65944bb0bb63f57e395d"
HEIGHT_SHA="fc69ac54361cb78b51cae67a42bdd49d3f22d726fef6e4e49f9a496f5ef3949a"
EXPECTED_DIM_COUNTS={(1920,1080):42,(2048,1080):18,(3840,2160):18,(4096,2160):18}

@dataclass(frozen=True)
class Model:
    name:str
    movie_table:int
    widths:int
    heights:int
    frame_matcher:int
    width_lookup:int
    height_lookup:int
    resolver_caller:int
    resolver_caller_bl:int
    movie_setup:int
    mode_initializer:int
    highspeed_classifier:int
    movie4k_classifier:int
    source_mode_global:int
    fps_variant_offset:int
    movie_setup_log:str
    candidate_log:str
    decoder_log:str
    xref_log:str

MODELS={
 "xs10":Model("xs10",0x027a0dbc,0x0171bf0c,0x0171c1f0,
  0x022e123c,0x012c9354,0x012c941c,
  0x022d5fec,0x022d6978,0x022dee64,
  0x022d5fec,0x022d171c,0x022d1674,
  0x02eda0b4,0x9b8,
  "xs10_stage45_movie_encoder_param_callsite.log",
  "xs10_stage46_mode_joint_candidate_decomp.log",
  "xs10_stage46_table_dimension_decoder_and_mode_enum.log",
  "xs10_stage46_joint_mode_table_provenance_xrefs.log"),
 "xt4":Model("xt4",0x026fde5c,0x0168bae4,0x0168bdc8,
  0x0224db10,0x012a2f90,0x012a3058,
  0x022425bc,0x02242f48,0x0224b65c,
  0x022425bc,0x0223dcac,0x0223dc04,
  0x02e57934,0x9bc,
  "xt4_stage45_movie_encoder_param_callsite.log",
  "xt4_stage46_mode_joint_candidate_decomp.log",
  "xt4_stage46_table_dimension_decoder_and_mode_enum.log",
  "xt4_stage46_joint_mode_table_provenance_xrefs.log")
}

def need(test,detail):
    if not test:raise ValueError("Stage46 offline joint-mode LUT: "+detail)

def section_slice(binary,virtual_base,addr,size):
    off=addr-virtual_base
    need(off>=0 and off+size<=len(binary),"out-of-bounds original ROM span "+hex(addr))
    return binary[off:off+size]

def lookup_width_height(record,wide,height):
    """Decode the same two-byte key indexed by the original width/height funcs.

    Original decoder: for key2=0..3 use key2, otherwise column4.
    The first key byte is a 0..36 row index. The 0x40 record's class and
    fps fields DO NOT select the width/height decoder column.
    """
    need(len(record)>=5 and len(wide)==DIM_BYTES and len(height)==DIM_BYTES,
         "dimension lookup source size wrong")
    category=record[1]
    aspect=record[2]
    column=aspect if aspect<=3 else 4
    idx=(category*5+column)*4
    need(idx+4<=len(wide),"encoded resolution key beyond lookup LUT")
    w=struct.unpack_from("<I",wide,idx)[0]
    h=struct.unpack_from("<I",height,idx)[0]
    need(0<w<=0xffff and 0<h<=0xffff,"dimension LUT entry invalid/zero")
    return (w,h)

def read_records(data,count=RECORDS,require_terminal=True):
    need(count>=1 and count<=1024,"record count bad")
    need(len(data)>=count*STRIDE+(1 if require_terminal else 0),
         "short record table")
    out=[]
    for i in range(count):
        r=data[i*STRIDE:(i+1)*STRIDE]
        need(r[0]!=ENDMARKER,"early terminal entry")
        need(0<=r[3]<=0xff and 0<=r[4]<=0xff,"invalid byte record")
        out.append(r)
    if require_terminal:
        need(data[count*STRIDE]==ENDMARKER,"missing exact next-record sentinel")
    return out

def match_record(rows,frame_class,mode_key_le,fps_enum,variant):
    """Mirror ONLY the 4 comparisons in original lookup, NOT upstream gating."""
    need(0<=frame_class<=255 and 0<=mode_key_le<=0xffff and
         0<=fps_enum<=255 and 0<=variant<=255,"invalid mock mode key")
    result=[]
    for i,row in enumerate(rows):
        key=row[1]|(row[2]<<8)
        if (row[0],key,row[3],row[4])==(
            frame_class,mode_key_le,fps_enum,variant):
            result.append(i)
    return result

def decomp(log,entry):
    needle=r"(?m)^\s*(?:void|int|uint|undefined\d+)\s+FUN_%08x\("%entry
    for blk in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=blk.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(needle,c):return c
    raise ValueError("Ghidra function not found at "+hex(entry))

def audit_ghidra(m,logs):
    f=decomp(logs["candidates"],m.frame_matcher)
    raw_table="DAT_%08x"%m.movie_table
    need(("if (%s != -1)"%raw_table) in f and
         ("pcVar10 = &%s;"%raw_table) in f and
         ("pcVar10 = pcVar10 + 0x40;") in f,
         "original constant-64-stride sentinel lookup missing")
    need("(param_1 + 0x6018) + 0x5f5" in f and
         "(byte)(cVar1 - 1U) < 2" in f and
         "(param_1 + 0x5c7)" in f and
         "(param_1 + 0x5c6)" in f,
         "frame class and alternative fps source selectors changed")
    need(("*(short *)(param_1 + 0xadd8) == *(short *)(pcVar10 + 1)") in f
         and "(pcVar10[3] == cVar2)" in f
         and ("*(char *)(param_1 + 0x%x) == pcVar10[4]"%m.fps_variant_offset) in f
         and "(cVar1 == cVar9)" in f,
         "not all four independent table match predicates are present")
    for func,offset,source in (
       (m.width_lookup,0x600,logs["lookups"]),
       (m.height_lookup,0x602,logs["lookups"])):
        fn="FUN_%08x"%func
        need(("uVar4 = %s(pcVar10[1],pcVar10[2]);"%fn) in f and
             ("+ 0x%x) = uVar4;"%offset) in f,
             "selected LUT key not copied to runtime resolved width/height")
        look=decomp(source,func)
        addr=m.widths if offset==0x600 else m.heights
        need(("&DAT_%08x + (param_1 * 5 + iVar1) * 4"%addr) in look and
             "iVar1 = 4;" in look and
             "param_2 == 3" in look,
             "distinct ROM width/height 37x5 32-bit decoder changed")
    need("(param_1 + 0xadda)" not in f and "PROFILE_LEVEL" not in f,
         "codec or profile unexpectedly appears in table matcher")
    init=decomp(logs["candidates"],m.mode_initializer)
    need(("FUN_%08x(iVar8);"%m.frame_matcher) in init and
         ("FUN_%08x(cVar1);"%m.highspeed_classifier) in init and
         "+ 0x5f5) = 0;" in init and
         "+ 0x5f5) = uVar4;" in init and
         ("+ 0x6018) = _DAT_%08x + 8;"%m.source_mode_global) in init,
         "movie mode provider does not set runtime +0x6018 / class / call lookup")
    high=decomp(logs["lookups"],m.highspeed_classifier)
    classify=decomp(logs["lookups"],m.movie4k_classifier)
    need("case 2:" in high and "case 3:" in high and
         "case 4:" in high and "case 7:" in high and
         "case 1:" in classify and "case 4:" in classify and
         "case 5:" in classify and "case 6:" in classify and
         "case 7:" in classify,
         "4K-vs-highspeed movie-type classifier shape changed")
    setup=decomp(logs["movie"],m.movie_setup)
    need("(iVar7 + 0x600)" in setup and "(iVar7 + 0x602)" in setup and
         "(param_1 + 0xadda)" in setup and
         "0xca0000" in setup and "0xd08000" in setup and
         "(param_1 + 0x5c6)" in setup and
         "(param_1 + 0x5c7)" in setup,
         "downstream movie encoder still consumes resolution, fps, codec separately")
    ref="PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL"%(m.resolver_caller_bl,m.frame_matcher)
    need(ref in logs["xref"],"original direct caller of table lookup missing")
    addr_hit="PROBE_TARGET addr=%08x refs=4"%m.movie_table
    need(addr_hit in logs["xref"],
         "original static reference to table base missing in Ghidra")
    need(("PROBE_TARGET addr=%08x"%m.widths) in logs["xref"] and
         ("PROBE_TARGET addr=%08x"%m.heights) in logs["xref"],
         "two distinct dimension decoder ROM arrays absent in Ghidra xrefs")
    return {
      "matcher_function":"FUN_%08x"%m.frame_matcher,
      "ROM_match_table_base":"0x%08x"%m.movie_table,
      "runtime_config_mode_ptr_offset":"0x6018",
      "runtime_resolved_width_and_height_offsets":["0x600","0x602"],
      "four_match_fields":[
          "frame_class_from_0x5F5",
          "u16_LE_mode_key_from_movie_context_0xADD8",
          "fps_enum_from_movie_context_0x5C6_or_0x5C7",
          "variant_byte_from_movie_context_0x%x"%m.fps_variant_offset],
      "movie_HEVC_selector_0xADDA_not_a_direct_table_match_key":True,
      "movie_init_resolver_bl":"0x%08x"%m.resolver_caller_bl,
      "4k_classifier_function":"FUN_%08x"%m.movie4k_classifier,
      "highspeed_class_classifier":"FUN_%08x"%m.highspeed_classifier,
      "upstream_GUI_or_sensor_gate_excluded":False,
    }

def audit_model(m,sec1,sec2,logs):
    rom2=st45.MODELS[m.name]
    need(sha256(sec1).hexdigest()==st45.ROM1_SHA[m.name] and
         sha256(sec2).hexdigest()==rom2.sha2,
         "unaltered official ROM Section1/2 SHA256 identity mismatch")
    table=section_slice(sec2,rom2.section2_base,m.movie_table,STRIDE*RECORDS+1)
    widths=section_slice(sec1,0x01021000,m.widths,DIM_BYTES)
    heights=section_slice(sec1,0x01021000,m.heights,DIM_BYTES)
    rows=read_records(table)
    need(sha256(table[:STRIDE*RECORDS]).hexdigest()==BODY_SHA,
         "official 96-row ROM table hash changed")
    need(sha256(widths).hexdigest()==WIDTH_SHA and
         sha256(heights).hexdigest()==HEIGHT_SHA,
         "original lookup mapping-table hash changed")
    w=st45.u32(sec2,m.resolver_caller_bl,rom2.section2_base)
    need(st45.a32_bl_target(w,m.resolver_caller_bl)==m.frame_matcher,
         "original 32-bit A32 BL does not call ROM record matcher")
    checks=audit_ghidra(m,logs)
    counts=Counter()
    frame_counter=Counter()
    variant=Counter()
    records=[]
    for i,r in enumerate(rows):
        dims=lookup_width_height(r,widths,heights)
        counts[dims]+=1
        frame_counter[r[3]]+=1
        variant[r[4]]+=1
        records.append({
         "index":i,"class":r[0],
         "mode_key_u16_le":r[1]|r[2]<<8,
         "fps_enum":r[3],"variant":r[4],
         "width":dims[0],"height":dims[1]})
    need(dict(counts)==EXPECTED_DIM_COUNTS and
         dict(frame_counter)=={i:16 for i in range(1,7)} and
         dict(Counter(t["class"] for t in records))=={0:72,1:18,2:6},
         "identical ROM mode matrix cardinalities changed")
    fps6=[r for r in records if r["fps_enum"]==6]
    fps6_4k=[r for r in fps6 if r["height"]==2160]
    need(len(fps6)==16 and len(fps6_4k)==6,
         "4K59.94 mode record count changed")
    need([(r["index"],r["width"],r["height"]) for r in fps6_4k]==[
       (15,4096,2160),(16,4096,2160),(17,4096,2160),
       (33,3840,2160),(34,3840,2160),(35,3840,2160)],
       "mode record decoder does not resolve expected six 4K fps6 records")
    need(all(r["class"]==0 and r["variant"] in (1,2,3)
             for r in fps6_4k),
         "actual 4K59.94 header match keys unexpected")
    need(match_record(rows,0,0x0207,6,1)==[33] and
         match_record(rows,0,0x0707,6,2)==[16] and
         match_record(rows,1,0x0207,6,1)==[],
         "row comparisons cannot be reproduced from exactly four keys")

    return {"model":m.name,
      "original_section1_sha256":st45.ROM1_SHA[m.name],
      "original_section2_sha256":rom2.sha2,
      **checks,
      "table_record_stride_hex":"0x40",
      "table_count":len(records),
      "byte_identical_cross_model_matrix_sha256":BODY_SHA,
      "width_table_sha256":WIDTH_SHA,
      "height_table_sha256":HEIGHT_SHA,
      "all_fps_enum6_records":len(fps6),
      "all_resolved_dimensions_counts":{
       f"{w}x{h}":count for (w,h),count in sorted(counts.items())},
      "4K_59_94_static_mode_records":[{
          "row":r["index"],
          "class":r["class"],"mode_key_le_hex":"0x%04x"%r["mode_key_u16_le"],
          "fps_enum":r["fps_enum"],"variant":r["variant"],
          "size":f"{r['width']}x{r['height']}"} for r in fps6_4k],
      "X_S10_4K59_94_mode_exposed_in_GUI_or_reachable":False,
      "HEVC_4K59_94_joint_legality_proven":False,
      "Main10_runtime_or_real_SPS_proven":False,
      "physical_hardware_bandwidth_verified":False,
      "physical_camera_touched_or_ROM_modified":False,
      "_raw_record_bytes_private_do_not_publish":True,
    },table,rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",default=Path("output"),type=Path)
    root=ap.parse_args().output
    results=[];table_by_model={}
    for m in MODELS.values():
        s1=(root/f"x6-{m.name}"/"section-1.bin").read_bytes()
        s2=(root/f"x6-{m.name}"/"section-2.bin").read_bytes()
        logs={"movie":(root/m.movie_setup_log).read_text(),
              "candidates":(root/m.candidate_log).read_text(),
              "lookups":(root/m.decoder_log).read_text(),
              "xref":(root/m.xref_log).read_text()}
        res,table,rows=audit_model(m,s1,s2,logs)
        results.append(res);table_by_model[m.name]=table
    need(table_by_model["xs10"]==table_by_model["xt4"],
         "X-S10 and X-T4 entire table including terminal sentinel differs")
    need(results[0]["4K_59_94_static_mode_records"]==
         results[1]["4K_59_94_static_mode_records"],
         "4K59.94 static matrix decoded entry divergence")
    report={
      "source":"offline-original-X6-ROM-and-readOnly-Ghidra-only",
      "two_camera_static_mode_matrix":results,
      "both_original_ROM_96_by_64_records_byte_identical":True,
      "4k_59_94_rows_are_static_configurations_not_hardware_permission":True,
      "any_runnable_camera_combo_and_Main10_unproven":True,
      "hardware_RAM_USB_FF80_flash_ROM_written":False,
    }
    print(json.dumps(report,indent=2,ensure_ascii=False))
    print("STAGE46 ORIGINAL 96x64 JOINT MODE MATRIX / 4K59.94 ROWS AUDIT PASS")
    print("Static table != GUI/sensor/ISP/VPU/storage execution permission.")
if __name__=="__main__":main()

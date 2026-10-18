#!/usr/bin/env python3
"""Offline HEVC SPS verifier for raw Annex-B or four-byte-length NALU streams.

Accepts only existing LOCAL raw HEVC elementary-stream bytes, NOT an MP4/MOV
container, a camera connection, memory dump, or Fuji firmware image.
All bit decoding is independently authored using documented HEVC SPS syntax.
No device I/O, hardware commands, patch creation, or HEVC unlock.

Important numeric distinction: public Arm MVE *option* profile enum
MVE_OPT_PROFILE_H265_MAIN_10 == 4; actual HEVC SPS general_profile_idc
for Main10 == 2. They are different namespaces.
"""
import argparse
import json
from pathlib import Path
import re

HEVC_SPS_NAL_TYPE=33
HEVC_MAIN_PROFILE_IDC=1
HEVC_MAIN10_PROFILE_IDC=2
MVE_MAIN10_OPTION_PROFILE_VALUE=4
MAX_FILE_BYTES=128*1024*1024
MAX_NAL_BYTES=8*1024*1024

class ParseError(ValueError): pass

def require(cond,why):
    if not cond:raise ParseError(why)

class Bits:
    def __init__(self,data):
        self.data=bytes(data)
        self.pos=0
    def bits(self,n):
        require(0<=n<=64,"bad field bit count")
        require(self.pos+n<=len(self.data)*8,"truncated HEVC SPS RBSP")
        x=0
        for _ in range(n):
            x=(x<<1)|((self.data[self.pos//8]>>(7-self.pos%8))&1)
            self.pos+=1
        return x
    def flag(self):return self.bits(1)
    def ue(self):
        zeros=0
        while self.flag()==0:
            zeros+=1
            require(zeros<=31,"invalid oversized SPS exponential Golomb code")
        return ((1<<zeros)-1)+self.bits(zeros)

def unescape_ebsp(data):
    result=bytearray()
    zero_count=0
    i=0
    while i<len(data):
        b=data[i]
        if zero_count>=2 and b==3:
            require(i+1<len(data),"invalid trailing emulation-prevention byte")
            require(data[i+1]<=3,"invalid HEVC emulation-prevention byte")
            zero_count=0
            i+=1
            continue
        result.append(b)
        zero_count=zero_count+1 if b==0 else 0
        i+=1
    return bytes(result)

def nal_type(nal):
    require(len(nal)>=2,"HEVC NAL header shorter than 2 bytes")
    require(nal[0]&0x80==0,"HEVC forbidden_zero_bit is not zero")
    require((nal[1]&7)!=0,"invalid HEVC temporal_id_plus1=0")
    return (nal[0]>>1)&0x3f

def parse_sps(nal):
    require(nal_type(nal)==HEVC_SPS_NAL_TYPE,
            "not an HEVC SPS NAL unit (type 33)")
    b=Bits(unescape_ebsp(nal[2:]))
    sps_vps_id=b.bits(4)
    max_sub=b.bits(3)
    nesting=b.flag()
    general_profile_space=b.bits(2)
    general_tier_flag=b.flag()
    general_profile_idc=b.bits(5)
    compatibility_flags=b.bits(32)
    constraint_flags=b.bits(48)
    level_idc=b.bits(8)
    profiles=[]
    levels=[]
    for _ in range(max_sub):
        profiles.append(b.flag())
        levels.append(b.flag())
    if max_sub:
        for _ in range(max_sub,8):
            require(b.bits(2)==0,"invalid nonzero reserved_zero_2bits")
    for i in range(max_sub):
        if profiles[i]:
            b.bits(2+1+5+32+48)
        if levels[i]:b.bits(8)
    sps_id=b.ue()
    chroma=b.ue()
    require(chroma<=3,"invalid SPS chroma_format_idc")
    separate_plane=b.flag() if chroma==3 else 0
    width=b.ue()
    height=b.ue()
    require(width>0 and height>0,"SPS dimensions must be nonzero")
    if b.flag():   # conformance_window_flag
        for _ in range(4): b.ue()
    luma=8+b.ue()
    chroma_depth=8+b.ue()
    require(8<=luma<=16 and 8<=chroma_depth<=16,
            "invalid SPS bit depth fields")
    explicit_main10=(general_profile_idc==HEVC_MAIN10_PROFILE_IDC and
                     luma==10 and chroma_depth==10)
    return {
        "nal_type":HEVC_SPS_NAL_TYPE,
        "sps_video_parameter_set_id":sps_vps_id,
        "sps_seq_parameter_set_id":sps_id,
        "max_sub_layers_minus1":max_sub,
        "temporal_id_nesting_flag":nesting,
        "general_profile_space":general_profile_space,
        "general_tier_flag":general_tier_flag,
        "general_profile_idc":general_profile_idc,
        "general_profile_compatibility_flags":"0x%08x"%compatibility_flags,
        "general_constraint_indicator_flags":"0x%012x"%constraint_flags,
        "general_level_idc":level_idc,
        "chroma_format_idc":chroma,
        "separate_colour_plane_flag":separate_plane,
        "pic_width_in_luma_samples":width,
        "pic_height_in_luma_samples":height,
        "bit_depth_luma":luma,
        "bit_depth_chroma":chroma_depth,
        "explicit_main10_profile_and_10bit_depth_signaled":explicit_main10,
        "profile_enum_4_does_not_mean_HEVC_SPS_profile_idc_4":True,
    }

def split_annexb(stream):
    matches=list(re.finditer(b"\x00\x00\x00\x01|\x00\x00\x01",stream))
    require(bool(matches),"no HEVC Annex-B start code")
    require(all(c==0 for c in stream[:matches[0].start()]),
            "nonzero data before first Annex-B start code")
    chunks=[]
    for i,m in enumerate(matches):
        end=matches[i+1].start() if i+1<len(matches) else len(stream)
        nal=stream[m.end():end].rstrip(b"\x00")
        require(bool(nal),"empty Annex-B NAL")
        require(len(nal)<=MAX_NAL_BYTES,"raw NAL exceeds safety size limit")
        chunks.append(nal)
    return chunks

def split_len4(stream):
    chunks=[]
    at=0
    while at<len(stream):
        require(at+4<=len(stream),"truncated four-byte NAL length prefix")
        length=int.from_bytes(stream[at:at+4],"big")
        at+=4
        require(0<length<=MAX_NAL_BYTES,"invalid four-byte NAL payload length")
        require(at+length<=len(stream),"length-prefix exceeds raw stream boundary")
        chunks.append(stream[at:at+length])
        at+=length
    require(bool(chunks),"no NAL units")
    return chunks

def inspect(data,mode="auto",require_all_sps_valid=True):
    data=bytes(data)
    require(len(data)>0,"raw elementary stream empty")
    require(len(data)<=MAX_FILE_BYTES,"input exceeds offline size limit")
    require(mode in ("auto","annexb","len4"),"unknown stream NAL framing mode")
    if mode=="auto":
        mode="annexb" if data.startswith((b"\x00\x00\x01",b"\x00\x00\x00\x01")) else "len4"
    nals=split_annexb(data) if mode=="annexb" else split_len4(data)
    types=[]
    sps=[]
    invalid=[]
    for i,nal in enumerate(nals):
        typ=nal_type(nal)
        types.append(typ)
        if typ!=HEVC_SPS_NAL_TYPE:continue
        try:
            sps.append(parse_sps(nal))
        except ParseError as exc:
            invalid.append({"nal_index":i,"reason":str(exc)})
    if invalid and require_all_sps_valid:
        raise ParseError("unreadable HEVC SPS NAL: "+json.dumps(invalid))
    # Main10 is supported by actual SPS metadata when an SPS exists. We still
    # do NOT infer that a physical X-S10 ever generated this stream.
    verified=bool(sps) and not invalid and all(
        s["explicit_main10_profile_and_10bit_depth_signaled"] for s in sps)
    return {
        "raw_format":mode,
        "nal_count":len(nals),
        "vps_nal_count":types.count(32),
        "sps_nal_count":types.count(33),
        "pps_nal_count":types.count(34),
        "parsed_sps":sps,
        "invalid_sps":invalid,
        "ALL_SPS_explicit_Main10_10bit":verified,
        "sample_provenance_not_attested":True,
        "XS10_Main10_runtime_success_not_proven_by_parser_alone":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input",type=Path,required=True,
                    help="local raw H.265 elementary stream ONLY (.h265, .hevc), NOT .MOV/.MP4")
    ap.add_argument("--mode",choices=("auto","annexb","len4"),default="auto")
    args=ap.parse_args()
    require(args.input.suffix.lower() in (".h265",".hevc",".265"),
            "not a raw .h265/.hevc/.265 elementary stream; extract from MOV first")
    require(args.input.stat().st_size<=MAX_FILE_BYTES,"input too large")
    result=inspect(args.input.read_bytes(),args.mode)
    print(json.dumps(result,indent=2))
    if not result["parsed_sps"]:
        print("UNVERIFIED: raw stream does not contain an HEVC SPS")
        raise SystemExit(2)
    if not result["ALL_SPS_explicit_Main10_10bit"]:
        print("UNVERIFIED: SPS did not jointly confirm HEVC Main10 profile and 10+10-bit")
        raise SystemExit(3)
    print("SPS indicates HEVC Main10/10-bit on this offline file; origin of file unknown")
if __name__=="__main__":main()

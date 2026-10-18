"""Purely synthetic HEVC SPS parsing tests; no original Fujifilm bitstreams.

All SPS NALs are generated in this file by an independent bit writer and
are synthetic format examples only; they cannot prove an actual camera mode.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import inspect_hevc_sps_stage44 as s

class Writer:
    def __init__(self):self.b=[]
    def bits(self,n,value):
        assert 0<=value<1<<n,(n,value)
        for shift in range(n-1,-1,-1):self.b.append((value>>shift)&1)
    def ue(self,v):
        assert 0<=v<0x1000000
        k=(v+1).bit_length()-1
        self.bits(k,0)
        self.bits(k+1,v+1)
    def bytes(self):
        out=self.b[:]
        out.append(1)
        while len(out)%8:out.append(0)
        return bytes(sum(out[i+j]<<(7-j) for j in range(8)) for i in range(0,len(out),8))

def toy_sps(profile=2,luma=10,chroma_depth=10,width=1920,height=1080,
            chroma_fmt=1,max_sub=0,nal_type=33,compat=0,tier=0,
            conf_win=False,invalid_reserved=False):
    w=Writer()
    w.bits(4,0)           # sps_video_parameter_set_id
    w.bits(3,max_sub)
    w.bits(1,1)
    w.bits(2,0)           # profile_space
    w.bits(1,tier)
    w.bits(5,profile)
    w.bits(32,compat)
    w.bits(48,0)          # constraint indicator flags
    w.bits(8,120)         # level_idc / HEVC level4.0, metadata only
    for _ in range(max_sub):w.bits(2,0)
    for _ in range(max_sub,8):
        if max_sub:w.bits(2,1 if invalid_reserved else 0)
    w.ue(0)               # sps_seq_parameter_set_id
    w.ue(chroma_fmt)
    if chroma_fmt==3:w.bits(1,1)
    w.ue(width);w.ue(height)
    w.bits(1,int(conf_win))
    if conf_win:
        for _ in range(4):w.ue(2)
    w.ue(luma-8)
    w.ue(chroma_depth-8)
    # no vendor encoded data; 2B synthetic HEVC NAL header
    return bytes([nal_type<<1,1])+w.bytes()

def toy_nal(nal_type):
    return bytes([nal_type<<1,1,0x80])
def length4(nals):
    return b"".join(len(n).to_bytes(4,"big")+n for n in nals)
def annexb(nals):
    return b"".join(b"\x00\x00\x00\x01"+n for n in nals)

class SPSCodec(unittest.TestCase):
    def test_sps_is_type33(self):
        self.assertEqual(s.nal_type(toy_sps()),33)
    def test_main10_actual_sps_profile_is_2(self):
        self.assertEqual(s.parse_sps(toy_sps())["general_profile_idc"],2)
    def test_mve_option_enum4_not_profile_idc2(self):
        self.assertEqual(s.MVE_MAIN10_OPTION_PROFILE_VALUE,4)
        self.assertEqual(s.HEVC_MAIN10_PROFILE_IDC,2)
        self.assertNotEqual(s.MVE_MAIN10_OPTION_PROFILE_VALUE,s.HEVC_MAIN10_PROFILE_IDC)
    def test_sps10_10_is_main10(self):
        self.assertTrue(s.parse_sps(toy_sps())["explicit_main10_profile_and_10bit_depth_signaled"])
    def test_main8_profile1(self):
        self.assertFalse(s.parse_sps(toy_sps(profile=1,luma=8,chroma_depth=8))["explicit_main10_profile_and_10bit_depth_signaled"])
    def test_profile4_with_10bit_not_explicit_Main10(self):
        self.assertFalse(s.parse_sps(toy_sps(profile=4))["explicit_main10_profile_and_10bit_depth_signaled"])
    def test_profile2_8bit_not_explicit_Main10(self):
        self.assertFalse(s.parse_sps(toy_sps(profile=2,luma=8,chroma_depth=8))["explicit_main10_profile_and_10bit_depth_signaled"])
    def test_luma10_chroma8_fails_main10(self):
        self.assertFalse(s.parse_sps(toy_sps(chroma_depth=8))["explicit_main10_profile_and_10bit_depth_signaled"])
    def test_luma8_chroma10_fails_main10(self):
        self.assertFalse(s.parse_sps(toy_sps(luma=8))["explicit_main10_profile_and_10bit_depth_signaled"])
    def test_profile_fields(self):
        z=s.parse_sps(toy_sps())
        self.assertEqual(z["general_level_idc"],120)
        self.assertEqual(z["pic_width_in_luma_samples"],1920)
        self.assertEqual(z["pic_height_in_luma_samples"],1080)
        self.assertEqual(z["chroma_format_idc"],1)
    def test_profile_tier_high(self):
        self.assertEqual(s.parse_sps(toy_sps(tier=1))["general_tier_flag"],1)
    def test_profile_compatibility(self):
        self.assertEqual(s.parse_sps(toy_sps(compat=0x60000000))["general_profile_compatibility_flags"],"0x60000000")
    def test_sub_layer1_skips_reserved_fields(self):
        self.assertEqual(s.parse_sps(toy_sps(max_sub=1))["max_sub_layers_minus1"],1)
    def test_sub_layer2(self):
        self.assertEqual(s.parse_sps(toy_sps(max_sub=2))["max_sub_layers_minus1"],2)
    def test_sub_layer7(self):
        self.assertEqual(s.parse_sps(toy_sps(max_sub=7))["max_sub_layers_minus1"],7)
    def test_nonzero_reserved_2bits_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"reserved"):
            s.parse_sps(toy_sps(max_sub=1,invalid_reserved=True))
    def test_444_chroma(self):
        self.assertEqual(s.parse_sps(toy_sps(chroma_fmt=3))["separate_colour_plane_flag"],1)
    def test_conformance_window(self):
        self.assertEqual(s.parse_sps(toy_sps(conf_win=True))["pic_width_in_luma_samples"],1920)
    def test_width0_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"dimensions"):
            s.parse_sps(toy_sps(width=0))
    def test_height0_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"dimensions"):
            s.parse_sps(toy_sps(height=0))
    def test_chroma16bit_rejected_when_luma17(self):
        with self.assertRaisesRegex(s.ParseError,"bit depth"):
            s.parse_sps(toy_sps(luma=17))
    def test_bad_non_sps_type(self):
        with self.assertRaisesRegex(s.ParseError,"not an HEVC SPS"):
            s.parse_sps(toy_sps(nal_type=32))
    def test_bad_forbidden_zero_bit(self):
        with self.assertRaisesRegex(s.ParseError,"forbidden_zero_bit"):
            s.nal_type(b"\xC2\x01")
    def test_bad_temporal_id_plus1(self):
        with self.assertRaisesRegex(s.ParseError,"temporal_id"):
            s.nal_type(b"\x42\x00")
    def test_one_byte_header_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"shorter"):
            s.nal_type(b"\x42")
    def test_invalid_ebsp(self):
        with self.assertRaisesRegex(s.ParseError,"trailing"):
            s.unescape_ebsp(b"\x00\x00\x03")
    def test_invalid_escape_next(self):
        with self.assertRaisesRegex(s.ParseError,"emulation-prevention"):
            s.unescape_ebsp(b"\x00\x00\x03\x04")
    def test_unescape_valid_00000301(self):
        self.assertEqual(s.unescape_ebsp(b"\x00\x00\x03\x01"),b"\x00\x00\x01")
    def test_unescape_valid_00000300(self):
        self.assertEqual(s.unescape_ebsp(b"\x00\x00\x03\x00"),b"\x00\x00\x00")
    def test_read_truncated_rbsp(self):
        with self.assertRaisesRegex(s.ParseError,"truncated"):
            s.parse_sps(b"\x42\x01")
    def test_ue_zero(self):
        self.assertEqual(s.Bits(b"\x80").ue(),0)
    def test_ue_one(self):
        self.assertEqual(s.Bits(b"\x40").ue(),1)
    def test_ue_two(self):
        self.assertEqual(s.Bits(b"\x60").ue(),2)
    def test_ue_overlong(self):
        with self.assertRaisesRegex(s.ParseError,"oversized"):
            s.Bits(b"\x00"*5).ue()

class ElementaryStream(unittest.TestCase):
    def test_annexb_sps(self):
        r=s.inspect(annexb([toy_nal(32),toy_sps(),toy_nal(34)]))
        self.assertEqual((r["vps_nal_count"],r["sps_nal_count"],r["pps_nal_count"]),(1,1,1))
        self.assertTrue(r["ALL_SPS_explicit_Main10_10bit"])
    def test_four_byte_length_sps(self):
        r=s.inspect(length4([toy_nal(32),toy_sps(),toy_nal(34)]))
        self.assertEqual(r["raw_format"],"len4")
        self.assertTrue(r["ALL_SPS_explicit_Main10_10bit"])
    def test_three_byte_annexb(self):
        r=s.inspect(b"\x00\x00\x01"+toy_sps())
        self.assertEqual(r["raw_format"],"annexb")
    def test_annexb_explicit(self):
        self.assertEqual(s.inspect(annexb([toy_sps()]),mode="annexb")["sps_nal_count"],1)
    def test_len4_explicit(self):
        self.assertEqual(s.inspect(length4([toy_sps()]),mode="len4")["sps_nal_count"],1)
    def test_unknown_mode_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"framing"):
            s.inspect(b"x",mode="mov")
    def test_nonzero_annexb_preamble_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"nonzero"):
            s.split_annexb(b"\x01\x00\x00\x01"+toy_sps())
    def test_no_start_code_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"start code"):
            s.split_annexb(toy_sps())
    def test_empty_NAL_rejected(self):
        with self.assertRaisesRegex(s.ParseError,"empty Annex-B"):
            s.split_annexb(b"\x00\x00\x01\x00\x00\x01"+toy_sps())
    def test_truncated_prefix(self):
        with self.assertRaisesRegex(s.ParseError,"truncated"):
            s.split_len4(b"\x01\x02")
    def test_zero_len_NAL(self):
        with self.assertRaisesRegex(s.ParseError,"invalid four-byte"):
            s.split_len4(b"\x00\x00\x00\x00")
    def test_too_large_declared_length(self):
        with self.assertRaisesRegex(s.ParseError,"invalid four-byte"):
            s.split_len4((s.MAX_NAL_BYTES+1).to_bytes(4,"big"))
    def test_prefix_past_end(self):
        with self.assertRaisesRegex(s.ParseError,"boundary"):
            s.split_len4(b"\x00\x00\x00\x20"+toy_sps()[:3])
    def test_empty_raw_file(self):
        with self.assertRaisesRegex(s.ParseError,"empty"):
            s.inspect(b"")
    def test_too_large_raw_file(self):
        with patch.object(s,"MAX_FILE_BYTES",4):
            with self.assertRaisesRegex(s.ParseError,"size limit"):
                s.inspect(b"12345")
    def test_empty_header_without_sps(self):
        r=s.inspect(length4([toy_nal(32),toy_nal(34)]))
        self.assertFalse(r["ALL_SPS_explicit_Main10_10bit"])
        self.assertEqual(r["sps_nal_count"],0)
    def test_non_main10_header(self):
        r=s.inspect(length4([toy_sps(profile=1,luma=8,chroma_depth=8)]))
        self.assertFalse(r["ALL_SPS_explicit_Main10_10bit"])
    def test_mixed_main8_main10(self):
        r=s.inspect(length4([toy_sps(),toy_sps(profile=1,luma=8,chroma_depth=8)]))
        self.assertFalse(r["ALL_SPS_explicit_Main10_10bit"])
        self.assertEqual(r["sps_nal_count"],2)
    def test_invalid_sps_fails_closed(self):
        with self.assertRaisesRegex(s.ParseError,"unreadable"):
            s.inspect(length4([b"\x42\x01"]))
    def test_invalid_sps_partial_flag(self):
        r=s.inspect(length4([b"\x42\x01"]),require_all_sps_valid=False)
        self.assertFalse(r["ALL_SPS_explicit_Main10_10bit"])
        self.assertEqual(len(r["invalid_sps"]),1)
    def test_provenance_stays_unattested(self):
        r=s.inspect(length4([toy_sps()]))
        self.assertTrue(r["sample_provenance_not_attested"])
        self.assertTrue(r["XS10_Main10_runtime_success_not_proven_by_parser_alone"])
    def test_oversized_nal_length(self):
        with patch.object(s,"MAX_NAL_BYTES",4):
            with self.assertRaisesRegex(s.ParseError,"invalid"):
                s.split_len4(length4([toy_sps()]))
    def test_length_mode_fails_on_non_matching_boundary(self):
        with self.assertRaises(s.ParseError):
            s.inspect(annexb([toy_sps()]),mode="len4")

def make_sps_case(width,profile,depth):
    def t(self):
        obj=s.parse_sps(toy_sps(profile=profile,luma=depth,
                               chroma_depth=depth,width=width,height=1080))
        self.assertEqual(obj["pic_width_in_luma_samples"],width)
        self.assertEqual(obj["general_profile_idc"],profile)
        self.assertEqual(obj["explicit_main10_profile_and_10bit_depth_signaled"],
                         profile==2 and depth==10)
    return t

# Systematic parameter variation shows we do not infer Main10 from 10-bit
# alone, profile=4 in the wrong namespace, or attractive size numbers.
for width in (32,128,640,1280,1920,3840,4096):
    for profile,depth in ((1,8),(2,10),(2,8),(4,10)):
        setattr(SPSCodec,"test_synthetic_profile_%d_depth_%d_width_%d"%(profile,depth,width),
                make_sps_case(width,profile,depth))

if __name__=="__main__":unittest.main()

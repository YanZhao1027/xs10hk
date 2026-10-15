"""Synthetic-only tests of Fuji movie menu numeric mapping and ARM dispatch."""
import pathlib
import struct
import sys
import unittest
from dataclasses import replace

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from compare_codec_menu_mappings import (
    ID_PAIRS, END_RECORD, ROMLayout, audit_calls, compare,
    decode_a32_bl, decode_mov_r0_imm, load_menu_rows,
)


def encode_bl(site, target):
    delta=target-site-8
    if delta%4:
        raise ValueError("unaligned branch")
    imm=(delta//4) & 0xFFFFFF
    return 0xEB000000|imm


def dummy_layout(model):
    return ROMLayout(model, 0x1000, 0x3000, 0x1200,
                     0x3E5 if model=="xt4" else 0x3FC,
                     0x3400, 0x3800, 0x3840)


def synthetic_model(model):
    spec=dummy_layout(model)
    s1=bytearray(0x8000)
    s2=bytearray(0x1000)
    keys=[p[0] if model=="xt4" else p[1] for p in ID_PAIRS]
    counts=[9,15,11,4,2,4,4]
    for group,(key,n) in enumerate(zip(keys,counts)):
        addr=0x4000+group*0x600
        struct.pack_into("<I",s1,spec.pointer_index_base+key*4-0x1000,addr)
        for row in range(n):
            r=(row,0x7FFFFFFE,row%2,0x7FFFFFFE)
            if group==6:
                rowvalues=[1,0,3,2]
                r=(rowvalues[row],0x7FFFFFFE,rowvalues[row]%2,0x7FFFFFFE)
            struct.pack_into("<4I",s1,addr-0x1000+row*16,*r)
        struct.pack_into("<4I",s1,addr-0x1000+n*16,*END_RECORD)
    off=spec.converter_bl_site-spec.section2_base
    # Both supported immediate forms, just as in the actual firmware.
    for offset,w in [
        (-16,0xE3A03003),(-12,0xE3A02000),(-8,0xE1A01005),
        (-4,(0xE3000000|spec.codec_id)), # MOVW R0,#id
        (0,encode_bl(spec.converter_bl_site,spec.converter_entry)),
        (4,0xE6EF0070),
        (8,encode_bl(spec.converter_bl_site+8,spec.setter_entry)),
    ]:
        struct.pack_into("<I",s2,off+offset,w)
    return s1,s2,spec


class MovieMenuMapTests(unittest.TestCase):
    def test_decode_menu_table_rows_codec(self):
        s1,s2,lay=synthetic_model("xs10")
        rows,ptr=load_menu_rows(bytes(s1),lay,0x3FC)
        self.assertEqual(ptr,0x6400) # six groups from 0x4000
        self.assertEqual(len(rows),4)
        self.assertEqual([r[2] for r in rows],[1,0,1,0])
        self.assertEqual(rows[0][1],0x7FFFFFFE)

    def test_all_seven_paired_mappings_equal_on_synthetic(self):
        xt,xts,_=synthetic_model("xt4")
        xs,xss,_=synthetic_model("xs10")
        # Under test, source code has official address constants. Substitute
        # synthetic model layouts so NO Fujifilm binary is ever test input.
        import compare_codec_menu_mappings as mod
        orig_xt,orig_xs=mod.LAYOUTS["xt4"],mod.LAYOUTS["xs10"]
        try:
            mod.LAYOUTS["xt4"]=dummy_layout("xt4")
            mod.LAYOUTS["xs10"]=dummy_layout("xs10")
            a=compare(bytes(xt),bytes(xs),bytes(xts),bytes(xss))
        finally:
            mod.LAYOUTS["xt4"],mod.LAYOUTS["xs10"]=orig_xt,orig_xs
        self.assertTrue(a["all_equal"])
        self.assertEqual(a["total_xt4_rows"],49)
        self.assertEqual(a["total_xs10_rows"],49)
        self.assertEqual(a["xs10_codec_row_to_enum"],[1,0,1,0])
        self.assertEqual(a["normal_xs10_menu_displays_HEVC"],"UNVERIFIED")

    def test_genuine_menu_dispatch_encoding_patterns(self):
        _,s2,lay=synthetic_model("xs10")
        info=audit_calls(bytes(s2),lay)
        self.assertEqual(info["setter_entry"],"0x00003840")
        self.assertEqual(info["menu_setting_id"],"0x3fc")

    def test_mov_immediate_arm_rotate_0x3fc(self):
        self.assertEqual(decode_mov_r0_imm(0xE3A00FFF),0x3FC)
        self.assertEqual(decode_mov_r0_imm(0xE30003E5),0x3E5)

    def test_branch_forward_backward(self):
        self.assertEqual(decode_a32_bl(encode_bl(0x4000,0x5000),0x4000),
                         0x5000)
        self.assertEqual(decode_a32_bl(encode_bl(0x5000,0x4000),0x5000),
                         0x4000)
        with self.assertRaisesRegex(ValueError,"Not conditional"):
            decode_a32_bl(0xEA000000,0x4000)

    def test_wrong_setting_id_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.converter_bl_site-lay.section2_base-4
        struct.pack_into("<I",s2,off,0xE30003FB)
        with self.assertRaisesRegex(ValueError,"not for codec"):
            audit_calls(bytes(s2),lay)

    def test_wrong_converter_target_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.converter_bl_site-lay.section2_base
        struct.pack_into("<I",s2,off,encode_bl(lay.converter_bl_site,0x3810))
        with self.assertRaisesRegex(ValueError,"Wrong menu index converter"):
            audit_calls(bytes(s2),lay)

    def test_wrong_eMode_setter_target_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.converter_bl_site-lay.section2_base+8
        struct.pack_into("<I",s2,off,encode_bl(lay.converter_bl_site+8,0x3860))
        with self.assertRaisesRegex(ValueError,"Wrong eModeMovieCodec setter"):
            audit_calls(bytes(s2),lay)

    def test_bad_converter_to_u8_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.converter_bl_site-lay.section2_base+4
        struct.pack_into("<I",s2,off,0xE1A00000) # MOV r0,r0 not UXTB
        with self.assertRaisesRegex(ValueError,"not reduced to uint8"):
            audit_calls(bytes(s2),lay)

    def test_missing_key_pointer_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.pointer_index_base+lay.codec_id*4-lay.section1_base
        struct.pack_into("<I",s1,off,0xFFFFFFFF)
        with self.assertRaisesRegex(ValueError,"invalid pointer"):
            load_menu_rows(bytes(s1),lay,lay.codec_id)

    def test_empty_menu_table_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.pointer_index_base+lay.codec_id*4-lay.section1_base
        ptr=struct.unpack_from("<I",s1,off)[0]
        struct.pack_into("<4I",s1,ptr-lay.section1_base,*END_RECORD)
        with self.assertRaisesRegex(ValueError,"Empty menu"):
            load_menu_rows(bytes(s1),lay,lay.codec_id)

    def test_wrong_category_selection_argument_rejected(self):
        s1,s2,lay=synthetic_model("xs10")
        off=lay.converter_bl_site-lay.section2_base-12
        struct.pack_into("<I",s2,off,0xE3A02001)
        with self.assertRaisesRegex(ValueError,"register arguments"):
            audit_calls(bytes(s2),lay)


if __name__=="__main__":
    unittest.main()

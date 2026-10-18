"""Synthetic-only tests for Stage41 MVE ABI + original ARM provenance.

All test "instructions" are fabricated in memory by integers, never read from
a manufacturer firmware blob. Strings are synthetic Ghidra-shaped fixtures,
not vendor decompile output. No network, device, USB, patching or flashing.
"""
from pathlib import Path
import ctypes
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage41_mve_v61_protocol_abi as s

def fake_bl(site,target):
    delta=target-site-8
    assert delta%4==0 and -(1<<25)<=delta<(1<<25)
    return 0xeb000000|((delta//4)&0xffffff)

def fake_word_map(m):
    d={
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
       m.option_send_bl:fake_bl(m.option_send_bl,m.ring_writer),
    }
    return d

def fake_ghidra(m):
    # Synthetic declarations with *multiple* earlier SET_OPTION calls; the
    # 0x26 send must be located AFTER its 0x194 and 0x190 conditions.
    return (
       "TRACE_DECOMP_BEGIN (Synthetic)\n"
       "void FUN_%08x(void)\n{\n"%m.send_option+
       "if (*(int *)(_DAT_%08x + 0x194) == 0) {\n"%m.packet_global+
       "local_58 = 1; local_54 = 123;\n"
       "FUN_%08x(0x3f2,8,&local_58);\n"%m.ring_writer+
       "local_58 = 0x10; local_54 = 123;\n"
       "FUN_%08x(0x3f2,8,&local_58);\n"%m.ring_writer+
       "if (*(int *)(_DAT_%08x + 400) == 1) {\n"%m.packet_global+
       "local_58 = 0x26;\n"
       "local_54 = 0x80008;\n"
       "FUN_%08x(0x3f2,8,&local_58);\n"%m.ring_writer+
       "}\n}\n}\nTRACE_DECOMP_END\n")

def verify_fake(model="xs10",change=None):
    m=s.MODELS[model]
    blob=fake_word_map(m)
    log=fake_ghidra(m)
    if change:
        blob,log=change(m,blob,log)
    return s.confirm_option_sender(m,lambda x:blob[x],log)

class Stage41PublicABI(unittest.TestCase):
    def test_all_abi_validation(self):
        d=s.validate_mve_frame_abi()
        self.assertEqual(d["frame_payload_size"],72)
    def test_frame_format_offset(self):
        self.assertEqual(s.MVEFrame.format.offset,0x18)
    def test_stride0_offset(self):
        self.assertEqual(s.MVEFrame.data.offset+s.Planar.stride.offset,0x34)
    def test_stride1_offset(self):
        self.assertEqual(s.MVEFrame.data.offset+s.Planar.stride.offset+4,0x38)
    def test_frame_size_72(self):
        self.assertEqual(ctypes.sizeof(s.MVEFrame),72)
    def test_header_size_4(self):
        self.assertEqual(struct.calcsize("<HH"),4)
    def test_frame_byte_size_from_manual_struct(self):
        self.assertEqual(struct.calcsize("<QQIHHHBB40sHH"),72)
    def test_option_payload_size(self):
        self.assertEqual(ctypes.sizeof(s.StreamDepthOption),8)
    def test_option_depth_struct_size(self):
        self.assertEqual(ctypes.sizeof(s.OptionStreamDepth),4)
    def test_option_fields_u16(self):
        self.assertEqual(s.OptionStreamDepth.luma_bitdepth.offset,0)
        self.assertEqual(s.OptionStreamDepth.chroma_bitdepth.offset,2)
    def test_option_data_offset(self):
        self.assertEqual(s.StreamDepthOption.data.offset,4)
    def test_option_message_number(self):
        self.assertEqual((s.MVE_REQUEST_SET_OPTION,hex(s.MVE_REQUEST_SET_OPTION)),
                         (1010,"0x3f2"))
    def test_frame_0xBB9(self):
        self.assertEqual(s.MVE_FRAME,3001)
        self.assertEqual(s.MVE_FRAME,0xBB9)
    def test_input_response_0x7D5(self):
        self.assertEqual(s.MVE_INPUT,2005)
    def test_output_response_0x7D6(self):
        self.assertEqual(s.MVE_OUTPUT,2006)
    def test_input_flush_response_0x7D7(self):
        self.assertEqual(s.MVE_INPUT_FLUSHED,2007)
    def test_0x7d8_is_output_flushed_NOT_frame_completion(self):
        self.assertEqual(s.MVE_OUTPUT_FLUSHED,2008)
        self.assertNotEqual(s.MVE_OUTPUT_FLUSHED,s.MVE_OUTPUT)
    def test_mve_frame_packed_header(self):
        self.assertEqual(struct.pack("<HH",s.MVE_FRAME,72),
                         b"\xb9\x0b\x48\x00")
    def test_profile_level_index_3(self):
        self.assertEqual(s.MVE_PROFILE_LEVEL_INDEX,3)
    def test_main10_profile_index_4(self):
        self.assertEqual(s.HEVC_MAIN10_PROFILE_ID,4)
        self.assertNotEqual(s.MVE_PROFILE_LEVEL_INDEX,s.HEVC_MAIN10_PROFILE_ID)
    def test_bitdepth_index_0x26(self):
        self.assertEqual(s.MVE_ENC_STREAM_BITDEPTH_INDEX,0x26)
    def test_8_8_is_two_16bit_values(self):
        self.assertEqual(struct.pack("<HH",8,8),struct.pack("<I",0x00080008))
    def test_no_fuji_rom_published(self):
        self.assertEqual(len(s.PUBLIC_HEADER_BLOBS),3)
        for sha in s.PUBLIC_HEADER_BLOBS.values():self.assertEqual(len(sha),40)
    def test_nV12_8bit_formula(self):
        self.assertEqual(s.format_u16(1,8,2),0x201)
    def test_y0l2_10bit_formula(self):
        self.assertEqual(s.format_u16(1,10,1),0x121)
    def test_P010_formula_storage16(self):
        self.assertEqual(s.format_u16(1,16,2),0x281)
    def test_two_plane_10bit_is_distinct(self):
        self.assertEqual(s.format_u16(1,10,2),0x221)
    def test_10bit_Y0L2_is_NOT_p010(self):
        self.assertNotEqual(s.format_u16(1,10,1),s.format_u16(1,16,2))
    def test_no_10bit_sps_by_encoded_Y0L2(self):
        self.assertEqual(s.decode_format(0x121)["format_storage_depth"],10)
        self.assertNotEqual(s.HEVC_MAIN10_PROFILE_ID,0x121)
    def test_bitfield_decode_nv12(self):
        self.assertEqual(s.decode_format(0x201),dict(
          chroma_format=1,format_storage_depth=8,
          planes=2,variant=0,afbc=False))
    def test_bitfield_decode_y0l2(self):
        self.assertEqual(s.decode_format(0x121),dict(
          chroma_format=1,format_storage_depth=10,
          planes=1,variant=0,afbc=False))
    def test_bitfield_decode_p010(self):
        self.assertEqual(s.decode_format(0x281),dict(
          chroma_format=1,format_storage_depth=16,
          planes=2,variant=0,afbc=False))
    def test_roundtrip_formula_all_named_formats(self):
        for key,(value,args,label) in s.FORMAT_NAMES.items():
            with self.subTest(key=key):
                self.assertEqual(s.format_u16(*args),value)
                self.assertEqual(s.decode_format(value)["planes"],args[2])
    def test_format_afbc_bit(self):
        self.assertEqual(s.format_u16(1,10,1,afbc=True),0x8121)
        self.assertTrue(s.decode_format(0x8121)["afbc"])
    def test_format_variant_bit(self):
        self.assertEqual(s.format_u16(1,8,2,variant=1),0x1201)
        self.assertEqual(s.decode_format(0x1201)["variant"],1)
    def test_invalid_chroma_value(self):
        with self.assertRaisesRegex(ValueError,"chroma"):
            s.format_u16(8,10,1)
    def test_invalid_storage_bits_low(self):
        with self.assertRaisesRegex(ValueError,"storage"):
            s.format_u16(1,7,1)
    def test_invalid_storage_bits_high(self):
        with self.assertRaisesRegex(ValueError,"storage"):
            s.format_u16(1,24,1)
    def test_invalid_planes(self):
        with self.assertRaisesRegex(ValueError,"plane"):
            s.format_u16(1,10,4)
    def test_invalid_variant(self):
        with self.assertRaisesRegex(ValueError,"variant"):
            s.format_u16(1,10,1,4)
    def test_invalid_negative_u16(self):
        with self.assertRaisesRegex(ValueError,"not u16"):
            s.decode_format(-1)
    def test_invalid_large_u16(self):
        with self.assertRaisesRegex(ValueError,"not u16"):
            s.decode_format(65536)
    def test_invalid_rom_address(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            s.read32(b"\x00"*8,s.ROM1+1)
    def test_rom_word_little_endian(self):
        self.assertEqual(s.read32(b"\x78\x56\x34\x12",s.ROM1),0x12345678)
    def test_rom_outside(self):
        with self.assertRaisesRegex(ValueError,"out-of-image"):
            s.read32(b"\x00"*4,s.ROM1+4)
    def test_bl_synthetic_forward(self):
        self.assertEqual(s.decode_bl(fake_bl(0x123000,0x123600),0x123000),0x123600)
    def test_bl_synthetic_backward(self):
        self.assertEqual(s.decode_bl(fake_bl(0x123600,0x123000),0x123600),0x123000)
    def test_bl_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,"not an unconditional"):
            s.decode_bl(0xe3a00000,0x123000)
    def test_bl_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"not an unconditional"):
            s.decode_bl(0x1b000000,0x123000)

class Stage41SoftwareSender(unittest.TestCase):
    def test_positive_synthetic_for_both(self):
        for model in ("xs10","xt4"):
            with self.subTest(model=model):
                result=verify_fake(model)
                self.assertEqual(result["set_option_message_code"],"0x3f2")
                self.assertEqual(result["output_luma_depth_u16"],8)
                self.assertEqual(result["output_chroma_depth_u16"],8)
    def test_passes_multiple_earlier_messages_after_guard(self):
        for model in ("xs10","xt4"):
            with self.subTest(model=model):
                out=verify_fake(model)
                self.assertEqual(out["set_option_buffer_bytes"],8)
    def test_real_Main10_unsolved_by_option_sender(self):
        for model in ("xs10","xt4"):
            result=verify_fake(model)
            self.assertFalse(result["option_profile_level_3_sent_by_this_branch"])
            self.assertFalse(result["runtime_branch_observed_on_camera"])
            self.assertEqual(result["camera_codec_enum1_standard_assignment"],
                             "UNVERIFIED")
    def test_fake_Ghidra_wrong_codec_option(self):
        def change(m,words,c):
            return words,c.replace("local_58 = 0x26;","local_58 = 0x27;")
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake("xs10",change)
    def test_fake_Ghidra_wrong_bitdepth_packed(self):
        def change(m,words,c):
            return words,c.replace("local_54 = 0x80008;","local_54 = 0xa000a;")
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake("xt4",change)
    def test_fake_Ghidra_wrong_coarse_guard(self):
        def change(m,words,c):
            return words,c.replace("+ 0x194) == 0","+ 0x194) == 1")
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake("xs10",change)
    def test_fake_Ghidra_wrong_internal_codec(self):
        def change(m,words,c):
            return words,c.replace("+ 400) == 1","+ 400) == 0")
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake("xt4",change)
    def test_fake_Ghidra_missing_8byte_send(self):
        def change(m,words,c):
            return words,c.replace(
                "FUN_%08x(0x3f2,8,&local_58);"%m.ring_writer,
                "FUN_%08x(0x3f2,4,&local_58);"%m.ring_writer)
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake("xt4",change)
    def test_fake_Ghidra_bad_target(self):
        def change(m,words,c):
            return words,c.replace("FUN_%08x(0x3f2,8,&local_58);"%m.ring_writer,
                      "FUN_ffffffff(0x3f2,8,&local_58);")
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake("xs10",change)
    def test_wrong_BL_target(self):
        def change(m,words,c):
            words[m.option_send_bl]=fake_bl(m.option_send_bl,m.ring_writer+0x40)
            return words,c
        with self.assertRaisesRegex(ValueError,"call target"):
            verify_fake("xt4",change)
    def test_wrong_initial_function_declaration(self):
        def change(m,words,c):
            return words,c.replace("void FUN_%08x(void)"%m.send_option,
                                   "void FUN_00000000(void)")
        with self.assertRaisesRegex(ValueError,"function missing"):
            verify_fake("xs10",change)

def word_flip_test(model,site_index,site_factory):
    def test(self):
        m=s.MODELS[model]
        site=site_factory(m)
        def change(m,words,c):
            words[site]^=1
            return words,c
        with self.assertRaises(ValueError):
            verify_fake(model,change)
    return test

sites=[
    lambda m:m.send_option+0x28,
    lambda m:m.send_option+0x2c,
    lambda m:m.send_option+0x30,
    lambda m:m.codec_1_ldr,
    lambda m:m.codec_1_ldr+4,
    lambda m:m.codec_1_ldr+8,
    lambda m:m.protocol_option_mov,
    lambda m:m.protocol_option_mov+4,
    lambda m:m.protocol_option_mov+8,
    lambda m:m.first_depth_halfstore,
    lambda m:m.second_depth_halfstore,
    lambda m:m.option_send_bl-4,
    lambda m:m.option_send_bl,
]
for i,factory in enumerate(sites):
    for model in ("xs10","xt4"):
        setattr(Stage41SoftwareSender,
                "test_original_A32_mutation_%02d_%s"%(i,model),
                word_flip_test(model,i,factory))

def synthetic_perturb_order(model,which):
    def t(self):
        def change(m,words,c):
            if which=="move_pack_before_guard":
                c=c.replace("local_58 = 0x26;", "local_58 = 0x26; /* index38 misplaced? */")
                # delete actual option event and put it *before* the guard
                c=c.replace("local_54 = 0x80008;","local_54 = 0x00000000;")
                c=c.replace("if (*(int *)(_DAT_%08x + 400) == 1)"%m.packet_global,
                   "local_54 = 0x80008;\nif (*(int *)(_DAT_%08x + 400) == 1)"%m.packet_global)
            elif which=="swap_codec_guard_and_option":
                c=c.replace("local_58 = 0x26;","/* omitted index38 */")
                c=c.replace("if (*(int *)(_DAT_%08x + 400) == 1)"%m.packet_global,
                            "local_58 = 0x26;\nif (*(int *)(_DAT_%08x + 400) == 1)"%m.packet_global)
            return words,c
        with self.assertRaisesRegex(ValueError,"Ghidra option38"):
            verify_fake(model,change)
    return t

for model in ("xs10","xt4"):
    for kind in ("move_pack_before_guard","swap_codec_guard_and_option"):
        setattr(Stage41SoftwareSender,
                "test_option_guard_order_wrong_%s_%s"%(model,kind),
                synthetic_perturb_order(model,kind))

if __name__=="__main__":
    unittest.main()

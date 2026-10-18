"""Synthetic only: Stage35 original ARM evidence checks and uncertainty guards.

Test vectors are constructed from generic ARM instruction encodings and
fictional decompiler strings. No Fujifilm original image, Ghidra database,
runtime camera bytes, USB or patch information occurs in tests.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_recorder_codec_to_vpu_stage35 as a

def mw(reg,imm,high=False):
    return (0xe3400000 if high else 0xe3000000)|(((imm>>12)&15)<<16)|(reg<<12)|(imm&0xfff)

def fake_bl(src,target):
    diff=target-src-8
    if diff%4 or not -(1<<25)<=diff<1<<25:raise ValueError("unencodable synthetic BL")
    return 0xeb000000|((diff>>2)&0xffffff)

def cb(src,target,cond=0):
    diff=target-src-8
    if diff%4 or not -(1<<25)<=diff<1<<25:raise ValueError("unencodable conditional B")
    return (cond<<28)|0x0a000000|((diff>>2)&0xffffff)

def ghidra(at,body,typ="void"):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"+
       ("%s FUN_%08x(void)\n{\n"%(typ,at))+body+
       "\n}\nTRACE_DECOMP_END (GhidraScript)\n")

def fixture(m):
    w={
      m.getter_movw:mw(3,m.active_base&0xffff),
      m.getter_movw+4:mw(3,m.active_base>>16,True),
      m.getter_movw+8:0xe5d30000|m.active_off,
      m.copy_bl:fake_bl(m.copy_bl,m.copy_func),
      m.ctor_ctx_add:0xe2845a0a,
      m.ctor_getter_bl:fake_bl(m.ctor_getter_bl,m.getter),
      m.ctor_ctx_store:0xe5c50dda,
      m.param_gate_start:mw(3,m.param_base&0xffff),
      m.param_gate_start+4:mw(3,m.param_base>>16,True),
      m.param_gate_start+8:0xe3a02001,
      m.param_gate_start+12:0xe583200c,
      m.param_gate_start+16:0xe2853a0a,
      m.param_gate_start+20:0xe5d33dda,
      m.param_gate_start+24:0xe1530002,
      m.param_gate_start+28:cb(m.param_gate_start+28,m.branch_zero),
      m.param_gate_start+40:0xe3a02001,
      m.param_gate_start+44:0xe5832188,
      m.zero_block:mw(3,m.param_base&0xffff),
      m.zero_block+4:mw(3,m.param_base>>16,True),
      m.zero_block+8:0xe3a02000,
      m.zero_block+12:0xe5832188,
      m.wrapper_init_bl:fake_bl(m.wrapper_init_bl,m.wrapper_init),
      m.wrapper_encoder_bl:fake_bl(m.wrapper_encoder_bl,m.wrapper_encoder),
      m.wrapper_inner_init_bl:fake_bl(m.wrapper_inner_init_bl,m.driver_init),
      m.wrapper_inner_encoder_bl:fake_bl(m.wrapper_inner_encoder_bl,m.driver_encoder),
    }
    w.update({m.driver_gate+i*4:word for i,word in enumerate(a.VALIDATION_7_WORDS)})
    getter=ghidra(m.getter,"return DAT_%08x;"%m.active_codec,"undefined1")
    ctx=ghidra(m.ctor,
       "FUN_%08x(iVar8);\n"%m.copy_func+
       "uVar4 = FUN_%08x();\n"%m.getter+
       "*(undefined1 *)(iVar8 + 0xadda) = uVar4;")
    parent=ghidra(m.movie_vpu_parent,
       "_DAT_%08x = 1;\n"%(m.param_base+0xc)+
       "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';\n"+
       "_DAT_%08x = (uint)!bVar9;\n"%(m.param_base+0x188)+
       "iVar7 = FUN_%08x(0,&DAT_%08x,FUN_callback);\n"%(m.wrapper_init,m.param_base)+
       "iVar7 = FUN_%08x(&DAT_%08x,FUN_encoder_callback);"%(m.wrapper_encoder,m.enc_src))
    driver=(
       ghidra(m.driver_init,
          "if ((*(uint *)(param_2 + 0x188) == 0) && (1 < *(uint *)(param_2 + 0xc))) {"
          "return -1;}\nif (1 < *(uint *)(param_2 + 0x188)) {return -1;}\n"+
          "func_0x%08x(&DAT_%08x,param_2,400);"%(m.driver_copy_engine,m.drv_copy_dest),
          "undefined4")+
       ghidra(m.driver_encoder,
          "if (param_2 == 0) {return -1;}\n"+
          "_DAT_%08x = *param_1;\n"%m.enc_dest+
          "_DAT_%08x = param_1[0xe];"%(m.enc_dest+0x38),
          "undefined4"))
    wrapper=(
       ghidra(m.wrapper_init,"iVar1 = FUN_%08x();"%m.driver_init,"undefined4")+
       ghidra(m.wrapper_encoder,"iVar1 = FUN_%08x();"%m.driver_encoder,"undefined4"))
    return {
       "words":w,
       "ascii":{m.init_bitdepth_error:b"#init bit_depth ERROR",
                m.init_codec_error:b"#init video_codec ERROR"},
       "logs":{"getter":getter,"context":ctx,"parent":parent,
               "driver":driver,"wrapper":wrapper},
       "p32":{"model":m.name,"input_to_active_static_data_flow_edges_proven":True,
              "active_Recorder_Codec_byte":"0x%08x"%m.active_codec},
       "p33":{"model":m.name,
              "movie_context_codec_offset":"0x9d8" if m.name=="xs10" else "0x9dc",
              "codec_control_if_byte_equals_1":"0x10004",
              "codec_control_otherwise":"0x10005"},
       "p34":{"model":m.name,"static_struct_pointer_registration_proven":True},
    }

def run(m,mutator=None):
    t=fixture(m)
    if mutator:mutator(t)
    with patch.object(a,"word",side_effect=lambda b,base,at:t["words"][at]):
        with patch.object(a,"rom_ascii",side_effect=lambda b,base,at,length:t["ascii"][at]):
            return a.audit(m,b"",b"",t["logs"],t["p32"],t["p33"],t["p34"])

class A32Syntax(unittest.TestCase):
    def test_movw(self):
        self.assertEqual(a.movpart(mw(3,0xb00d),3),0xb00d)
    def test_movt(self):
        self.assertEqual(a.movpart(mw(3,0x29a,True),3,True),0x29a)
    def test_wrong_mov_reg(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movpart(mw(4,0xabcd),3)
    def test_wrong_mov_variant(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movpart(mw(3,0xabcd,True),3)
    def test_bl_forward(self):
        self.assertEqual(a.decode_bl(fake_bl(0x1010,0x2020),0x1010),0x2020)
    def test_bl_backward(self):
        self.assertEqual(a.decode_bl(fake_bl(0x2020,0x1010),0x2020),0x1010)
    def test_reject_bl_condition(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.decode_bl(0x1b001000,0x1010)
    def test_reject_not_bl(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.decode_bl(0xe3a02001,0x1010)
    def test_conditional_eq_branch_forward(self):
        self.assertEqual(a.decode_cond_b(cb(0x1000,0x1040),0x1000,0),0x1040)
    def test_conditional_eq_branch_backward(self):
        self.assertEqual(a.decode_cond_b(cb(0x1000,0x0f00),0x1000,0),0x0f00)
    def test_reject_wrong_branch_cond(self):
        with self.assertRaisesRegex(ValueError,"conditional"):
            a.decode_cond_b(cb(0x1000,0x1040,1),0x1000,0)
    def test_reject_conditional_bl(self):
        with self.assertRaisesRegex(ValueError,"conditional"):
            a.decode_cond_b(0xeb000000,0x1000,0)
    def test_rom_word_le(self):
        self.assertEqual(a.word(bytes.fromhex("78563412"),0,0),0x12345678)
    def test_rom_word_oob(self):
        with self.assertRaisesRegex(ValueError,"bad firmware"):
            a.word(b"\x00"*4,0,8)
    def test_rom_word_unaligned(self):
        with self.assertRaisesRegex(ValueError,"bad firmware"):
            a.word(b"\x00"*8,0,3)
    def test_rom_ascii_fictional(self):
        self.assertEqual(a.rom_ascii(b"ABCDE123",0x100,0x102,3),b"CDE")
    def test_rom_ascii_bounds(self):
        with self.assertRaisesRegex(ValueError,"ROM ASCII"):
            a.rom_ascii(b"ABCDE",0,3,4)
    def test_find_decompiler(self):
        m=a.MODELS["xs10"]
        self.assertIn("hello",a.c_function(ghidra(m.getter,"hello;"),m.getter))
    def test_no_c_function(self):
        with self.assertRaisesRegex(ValueError,"function missing"):
            a.c_function("",0x2024)

class StaticDataflow(unittest.TestCase):
    def test_original_models_synthetic_positive(self):
        for m in a.MODELS.values():
            with self.subTest(model=m.name):
                x=run(m)
                self.assertTrue(x["movie_context_active_template_copy_and_getter_in_order"])
                self.assertEqual(x["VPU_original_validation_ARM_words"],7)
                self.assertEqual(x["original_subroutine_BL_targets_checked"],6)
                self.assertEqual(x["VPU_bit_depth_enum_written_by_movie_setup"],1)
    def test_distinct_active_codec_addresses(self):
        x,y=(run(m) for m in a.MODELS.values())
        self.assertNotEqual(x["active_Recorder_Codec_byte"],y["active_Recorder_Codec_byte"])
    def test_common_codec_to_vpu_enum(self):
        for m in a.MODELS.values():
            x=run(m)
            self.assertEqual(x["VPU_video_codec_when_active_Codec_byte_is_1"],0)
            self.assertEqual(x["VPU_video_codec_when_active_Codec_byte_is_not_1"],1)
    def test_no_physical_10bit_mapping_claim(self):
        for m in a.MODELS.values():
            x=run(m)
            self.assertEqual(x["actual_bitdepth_enum_1_means_10bit"],"UNKNOWN")
            self.assertEqual(x["actual_0_1_VPU_codec_enum_to_H264_H265_mapping"],"UNKNOWN")
            self.assertFalse(x["HEVC_Main10_SPS_bitdepth_proven"])
    def test_no_camera_or_firmware_mutation(self):
        for m in a.MODELS.values():
            x=run(m)
            self.assertFalse(x["camera_touched"])
            self.assertFalse(x["VPU_driver_runtime_executed_or_bitstream_captured"])
            self.assertFalse(x["internal_4K60_proven"])
    def test_upstream_GUI_remains_unknown(self):
        for m in a.MODELS.values():
            self.assertFalse(run(m)["GUI_to_Recorder_input_initial_assignment_proven"])
    def test_stage32_wrong_active(self):
        m=a.MODELS["xs10"]
        def change(t):t["p32"]["active_Recorder_Codec_byte"]="0x11111111"
        with self.assertRaisesRegex(ValueError,"Phase32"):run(m,change)
    def test_stage32_wrong_model(self):
        m=a.MODELS["xt4"]
        def change(t):t["p32"]["model"]="xs10"
        with self.assertRaisesRegex(ValueError,"Phase32"):run(m,change)
    def test_stage33_wrong_control(self):
        m=a.MODELS["xs10"]
        def change(t):t["p33"]["codec_control_otherwise"]="0x10004"
        with self.assertRaisesRegex(ValueError,"Phase33"):run(m,change)
    def test_stage33_wrong_offset(self):
        m=a.MODELS["xt4"]
        def change(t):t["p33"]["movie_context_codec_offset"]="0x9d8"
        with self.assertRaisesRegex(ValueError,"Phase33"):run(m,change)
    def test_stage34_pointer_unproved(self):
        m=a.MODELS["xs10"]
        def change(t):t["p34"]["static_struct_pointer_registration_proven"]=False
        with self.assertRaisesRegex(ValueError,"Phase34"):run(m,change)
    def test_getter_wrong_codec_var(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["getter"]=t["logs"]["getter"].replace(
                "DAT_%08x"%m.active_codec,"DAT_11111111")
        with self.assertRaisesRegex(ValueError,"getter target"):run(m,change)
    def test_getter_movw_wrong_base(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.getter_movw]=mw(3,(m.active_base&0xffff)+4)
        with self.assertRaisesRegex(ValueError,"A32 active Codec"):run(m,change)
    def test_getter_movt_wrong_base(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.getter_movw+4]=mw(3,(m.active_base>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"A32 active Codec"):run(m,change)
    def test_getter_ldrb_other_field(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.getter_movw+8]=0xe5d30431
        with self.assertRaisesRegex(ValueError,"A32 active Codec"):run(m,change)
    def test_context_copy_missing(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["context"]=t["logs"]["context"].replace(
              "FUN_%08x"%m.copy_func,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"context copy"):run(m,change)
    def test_context_getter_missing(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["context"]=t["logs"]["context"].replace(
              "FUN_%08x"%m.getter,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"context copy"):run(m,change)
    def test_context_store_wrong_offset(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["context"]=t["logs"]["context"].replace(
              "0xadda","0xadd9")
        with self.assertRaisesRegex(ValueError,"context copy"):run(m,change)
    def test_context_bad_order(self):
        m=a.MODELS["xs10"]
        def change(t):
            copy="FUN_%08x(iVar8);\n"%m.copy_func
            getter="uVar4 = FUN_%08x();\n"%m.getter
            t["logs"]["context"]=t["logs"]["context"].replace(copy+getter,getter+copy)
        with self.assertRaisesRegex(ValueError,"context copy /"):run(m,change)
    def test_context_BL_other_target(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.copy_bl]=fake_bl(m.copy_bl,m.copy_func+4)
        with self.assertRaisesRegex(ValueError,"active-template copy BL"):run(m,change)
    def test_context_A32_add_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.ctor_ctx_add]^=1
        with self.assertRaisesRegex(ValueError,"ctx\\+0xADDA"):run(m,change)
    def test_context_A32_store_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.ctor_ctx_store]^=1
        with self.assertRaisesRegex(ValueError,"ctx\\+0xADDA"):run(m,change)
    def test_context_getter_BL_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.ctor_getter_bl]=fake_bl(m.ctor_getter_bl,m.getter+4)
        with self.assertRaisesRegex(ValueError,"ctx\\+0xADDA"):run(m,change)
    def test_parent_wrong_codec_comparison(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["parent"]=t["logs"]["parent"].replace(
                   "param_1 + 0xadda","param_1 + 0x9d8")
        with self.assertRaisesRegex(ValueError,"Codec comparison"):run(m,change)
    def test_parent_missing_bitdepth_constant(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["parent"]=t["logs"]["parent"].replace(
                   "_DAT_%08x = 1;"%(m.param_base+0xc),"_DAT_ffffffff = 1;")
        with self.assertRaisesRegex(ValueError,"VPU init/enc"):run(m,change)
    def test_parent_wrong_inverted_codec(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["parent"]=t["logs"]["parent"].replace(
                   "(uint)!bVar9","(uint)bVar9")
        with self.assertRaisesRegex(ValueError,"VPU init/enc"):run(m,change)
    def test_parent_wrong_init_struct(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["parent"]=t["logs"]["parent"].replace(
                   "&DAT_%08x"%m.param_base,"&DAT_ffffffff")
        with self.assertRaisesRegex(ValueError,"VPU init/enc"):run(m,change)
    def test_parent_wrong_encoder_struct(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["parent"]=t["logs"]["parent"].replace(
                   "&DAT_%08x"%m.enc_src,"&DAT_ffffffff")
        with self.assertRaisesRegex(ValueError,"VPU init/enc"):run(m,change)
    def test_parent_bitdepth_written_after_driver_call(self):
        m=a.MODELS["xs10"]
        def change(t):
            b="_DAT_%08x = 1;\n"%(m.param_base+0xc)
            call="iVar7 = FUN_%08x(0,&DAT_%08x,FUN_callback);\n"%(m.wrapper_init,m.param_base)
            t["logs"]["parent"]=t["logs"]["parent"].replace(b, "").replace(call,call+b)
        with self.assertRaisesRegex(ValueError,"bitdepth constant"):run(m,change)
    def test_parent_video_codec_written_after_driver_call(self):
        m=a.MODELS["xt4"]
        def change(t):
            b="_DAT_%08x = (uint)!bVar9;\n"%(m.param_base+0x188)
            call="iVar7 = FUN_%08x(0,&DAT_%08x,FUN_callback);\n"%(m.wrapper_init,m.param_base)
            t["logs"]["parent"]=t["logs"]["parent"].replace(b,"").replace(call,call+b)
        with self.assertRaisesRegex(ValueError,"video_codec enum"):run(m,change)
    def test_parent_encoder_before_init(self):
        m=a.MODELS["xs10"]
        def change(t):
            a1="iVar7 = FUN_%08x(0,&DAT_%08x,FUN_callback);\n"%(m.wrapper_init,m.param_base)
            a2="iVar7 = FUN_%08x(&DAT_%08x,FUN_encoder_callback);"%(m.wrapper_encoder,m.enc_src)
            t["logs"]["parent"]=t["logs"]["parent"].replace(a1+a2,a2+"\n"+a1)
        with self.assertRaisesRegex(ValueError,"VPU init and encoder"):run(m,change)
    def test_parent_MOVW_bad_param_base(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.param_gate_start]=mw(3,(m.param_base&0xffff)+4)
        with self.assertRaisesRegex(ValueError,"param.*base"):run(m,change)
    def test_parent_MOVT_bad_param_base(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.param_gate_start+4]=mw(3,(m.param_base>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"param.*base"):run(m,change)
    def test_parent_bitdepth_write_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.param_gate_start+12]^=1
        with self.assertRaisesRegex(ValueError,"Codec/bitdepth"):run(m,change)
    def test_parent_get_codec_wrong_offset(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.param_gate_start+20]^=1
        with self.assertRaisesRegex(ValueError,"Codec/bitdepth"):run(m,change)
    def test_parent_compare_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.param_gate_start+24]^=1
        with self.assertRaisesRegex(ValueError,"Codec/bitdepth"):run(m,change)
    def test_parent_branch_wrong_condition(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.param_gate_start+28]=cb(
                                  m.param_gate_start+28,m.branch_zero,1)
        with self.assertRaisesRegex(ValueError,"conditional"):run(m,change)
    def test_parent_branch_wrong_target(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.param_gate_start+28]=cb(
                                  m.param_gate_start+28,m.branch_zero+4)
        with self.assertRaisesRegex(ValueError,"zero branch"):run(m,change)
    def test_parent_non1_codec_field_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.param_gate_start+44]^=4
        with self.assertRaisesRegex(ValueError,"Codec/bitdepth"):run(m,change)
    def test_parent_zero_branch_base_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.zero_block]=mw(3,(m.param_base&0xffff)+8)
        with self.assertRaisesRegex(ValueError,"zero block"):run(m,change)
    def test_parent_zero_branch_value_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.zero_block+8]^=1
        with self.assertRaisesRegex(ValueError,"zero branch does not"):run(m,change)
    def test_parent_zero_branch_store_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.zero_block+12]^=1
        with self.assertRaisesRegex(ValueError,"zero branch does not"):run(m,change)
    def test_wrapper_inner_vpu_init_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.wrapper_inner_init_bl]=fake_bl(
                       m.wrapper_inner_init_bl,m.driver_init+4)
        with self.assertRaisesRegex(ValueError,"driver / API BL"):run(m,change)
    def test_wrapper_inner_encoder_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.wrapper_inner_encoder_bl]=fake_bl(
                       m.wrapper_inner_encoder_bl,m.driver_encoder+4)
        with self.assertRaisesRegex(ValueError,"driver / API BL"):run(m,change)
    def test_wrapper_parent_vpu_init_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.wrapper_init_bl]=fake_bl(
                       m.wrapper_init_bl,m.wrapper_init+4)
        with self.assertRaisesRegex(ValueError,"driver / API BL"):run(m,change)
    def test_wrapper_parent_encoder_wrong(self):
        m=a.MODELS["xs10"]
        def change(t):t["words"][m.wrapper_encoder_bl]=fake_bl(
                       m.wrapper_encoder_bl,m.wrapper_encoder+4)
        with self.assertRaisesRegex(ValueError,"driver / API BL"):run(m,change)
    def test_wrapper_bad_decompiler_target(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["wrapper"]=t["logs"]["wrapper"].replace(
              "FUN_%08x"%m.driver_init,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"driver wrapper"):run(m,change)
    def test_driver_C_wrong_bitdepth_gate(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["driver"]=t["logs"]["driver"].replace(
             "param_2 + 0xc","param_2 + 0x10")
        with self.assertRaisesRegex(ValueError,"C validation"):run(m,change)
    def test_driver_C_wrong_codec_gate(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["driver"]=t["logs"]["driver"].replace(
             "1 < *(uint *)(param_2 + 0x188)","2 < *(uint *)(param_2 + 0x188)")
        with self.assertRaisesRegex(ValueError,"C validation"):run(m,change)
    def test_driver_C_wrong_copy_count(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["driver"]=t["logs"]["driver"].replace(
             "param_2,400)","param_2,396)")
        with self.assertRaisesRegex(ValueError,"copy 400-byte"):run(m,change)
    def test_driver_first_A32_byte_gate_wrong(self):
        m=a.MODELS["xt4"]
        def change(t):t["words"][m.driver_gate]^=1
        with self.assertRaisesRegex(ValueError,"seven original A32"):run(m,change)
    def test_driver_error_string_bad(self):
        m=a.MODELS["xs10"]
        def change(t):t["ascii"][m.init_bitdepth_error]=b"#init bit_deepth ERROR"
        with self.assertRaisesRegex(ValueError,"diagnostic"):run(m,change)
    def test_driver_video_codec_error_string_bad(self):
        m=a.MODELS["xt4"]
        def change(t):t["ascii"][m.init_codec_error]=b"#init video_codec FAIL"
        with self.assertRaisesRegex(ValueError,"diagnostic"):run(m,change)
    def test_driver_encoder_missing_15th_word(self):
        m=a.MODELS["xs10"]
        def change(t):t["logs"]["driver"]=t["logs"]["driver"].replace(
             "param_1[0xe]","param_1[0xd]")
        with self.assertRaisesRegex(ValueError,"15-word"):run(m,change)
    def test_driver_encoder_wrong_output_buffer(self):
        m=a.MODELS["xt4"]
        def change(t):t["logs"]["driver"]=t["logs"]["driver"].replace(
             "_DAT_%08x = *param_1"%m.enc_dest,"_DAT_ffffffff = *param_1")
        with self.assertRaisesRegex(ValueError,"15-word"):run(m,change)

def make_validation_corruption_test(idx):
    def test(self):
        m=a.MODELS["xs10" if idx%2 else "xt4"]
        def change(t):t["words"][m.driver_gate+4*idx]^=1
        with self.assertRaisesRegex(ValueError,"seven original A32"):
            run(m,change)
    test.__name__="test_corrupt_driver_gate_%02d"%idx
    return test

for idx in range(len(a.VALIDATION_7_WORDS)):
    setattr(StaticDataflow,"test_corrupt_driver_gate_%02d"%idx,
            make_validation_corruption_test(idx))

if __name__=="__main__":
    unittest.main()

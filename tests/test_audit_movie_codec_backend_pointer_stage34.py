"""Phase34 synthetic-only ARM pointer provenance and cross-model ABI tests.

NO Fujifilm images, Ghidra databases, FF80, USB or runtime camera data.
All ARM words/objects are fabricated from public instruction forms and
standalone function labels to challenge the read-only audit's assumptions.
"""
import sys
from pathlib import Path
from unittest import TestCase,main
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_movie_codec_backend_pointer_stage34 as v

def fakebl(at,to):
    diff=to-at-8
    if diff%4 or not -(1<<25)<=diff<(1<<25):raise ValueError("bad fake BL")
    return 0xeb000000|(diff>>2 & 0xffffff)

def function(at,c):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\nvoid FUN_%08x(void)\n{\n"%
             at+c+"\n}\nTRACE_DECOMP_END (GhidraScript)")

def case(s):
    arg="iVar4" if s.model=="xs10" else "iVar6"
    parent=function(s.caller,
         "%s = *(int *)(param_1 + 0x601c);\n"%arg+
         "if (*(char *)(%s + 0x122a0) == '\\0') {\n"%arg+
         " fallback();\n} else {\n"+
         "FUN_%08x(param_1,%s,%s + 0x3494,%s + 0x37f8,%s + 0x120d4);\n"%
           (s.builder,arg,arg,arg,arg)+
         "*(int *)(param_1 + 0x5ff4) = %s + 0x37f8;\n"%arg+
         "FUN_%08x(param_1);\n}"%s.registrar)
    registrar=function(s.registrar,
         "iVar2 = *(int *)(*(int *)(param_1 + 0x601c) + 0x124a8);\n"+
         "*(int *)(iVar2 + 0x3cf8) = *(int *)(param_1 + 0x601c);\n"+
         "*(int *)(iVar2 + 0x3cfc) = *(int *)(param_1 + 0x601c) + 0x3494;\n"+
         "*(int *)(iVar2 + 0x3d00) = *(int *)(param_1 + 0x601c) + 0x37f8;\n"+
         "if (*(int *)(param_1 + 0x3118) == 0) {iVar1=0;}\n"+
         "*(int *)(iVar2 + 0x3d04) = iVar1;")
    builder=function(s.builder,
         "if (*(char *)(param_1 + 0x%x) == '\\x01') {\n"%s.codec_offset+
         "uVar8 = 4;\n} else {\nuVar8 = 5;\n}\n"+
         "*(uint *)(param_4 + 0x220) = uVar8 | 0x10000;")
    words=dict((s.registrar+off,w) for off,w in v.REG_A32_WORDS.items())
    words.update({
         s.builder_bl:fakebl(s.builder_bl,s.builder),
         s.registrar_bl:fakebl(s.registrar_bl,s.registrar),
         s.packet_codec_ldr:0xe5d43000|s.codec_offset,
    })
    return {"parent":parent,"registrar":registrar,"builder":builder,
         "words":words,
         "body":b"SYNTHETIC".ljust(v.REGISTER_BODY_NBYTES,b"\x00"),
         "p33":{
          "model":s.model,
          "movie_context_codec_offset":"0x%x"%s.codec_offset,
          "codec_control_if_byte_equals_1":"0x10004",
          "codec_control_otherwise":"0x10005",
          "movie_context_plus_0x5b0_is_Recorder_Codec":False
          }
    }

def evalm(s,change=None):
    t=case(s)
    if change:change(t)
    return v.audit_model(s,lambda address:t["words"][address],t["body"],
                         t["parent"],t["registrar"],t["builder"],t["p33"])

class ARMHelpers(TestCase):
    def test_word_le(self):
        self.assertEqual(v.rom_word(bytes.fromhex("f82d0002"),0,0),0x02002df8)
    def test_word_bad_offset(self):
        with self.assertRaisesRegex(ValueError,"bad ROM word"):
            v.rom_word(b"\0"*4,0,4)
    def test_word_unaligned(self):
        with self.assertRaisesRegex(ValueError,"bad ROM word"):
            v.rom_word(b"\0"*8,0,2)
    def test_bytes_slice(self):
        self.assertEqual(v.rom_function_bytes(b"ABCDE",0,1,3),b"BCD")
    def test_bytes_oob(self):
        with self.assertRaisesRegex(ValueError,"bad ROM function"):
            v.rom_function_bytes(b"ABCD",0,3,2)
    def test_bytes_nosize(self):
        with self.assertRaisesRegex(ValueError,"bad ROM function"):
            v.rom_function_bytes(b"ABCD",0,0,0)
    def test_bl_forward(self):
        self.assertEqual(v.bl_target(fakebl(0x1000,0x2000),0x1000),0x2000)
    def test_bl_backward(self):
        self.assertEqual(v.bl_target(fakebl(0x2000,0x1000),0x2000),0x1000)
    def test_bl_not_conditional(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            v.bl_target(0x0b000000,0x1000)
    def test_bl_not_mov(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            v.bl_target(0xe3a02008,0x1000)
    def test_decomp_finds_fake_function(self):
        s=v.SPECS["xs10"]
        self.assertIn("fallback",v.decomp(function(s.caller,"fallback();"),s.caller))
    def test_decomp_rejects_missing(self):
        with self.assertRaisesRegex(ValueError,"missing Ghidra"):
            v.decomp("",0x1122)

class Flow(TestCase):
    def test_both_original_layouts_with_synthetic_data(self):
        for s in v.SPECS.values():
            with self.subTest(model=s.model):
                r=evalm(s)
                self.assertTrue(r["static_struct_pointer_registration_proven"])
                self.assertEqual(r["original_ARM_registrar_word_checks"],14)
                self.assertEqual(r["original_ARM_parent_BLs_checked"],2)
                self.assertEqual(r["backend_parameter_ptr_equals"],"main + 0x37f8")
    def test_cross_model_fingerprint_match(self):
        a,b=(evalm(s) for s in v.SPECS.values())
        d=v.audit_pair(a,b)
        self.assertTrue(d["cross_model_registration_function_byte_identical"])
    def test_fingerprint_different(self):
        a,b=(evalm(s) for s in v.SPECS.values())
        b["register_function_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"fingerprint"):
            v.audit_pair(a,b)
    def test_fingerprint_length_rejected(self):
        s=v.SPECS["xs10"]
        def ch(t):t["body"]=b"x"*151
        with self.assertRaisesRegex(ValueError,"fingerprint length"):
            evalm(s,ch)
    def test_no_hardware_claim(self):
        for s in v.SPECS.values():
            p=evalm(s)
            self.assertFalse(p["backend_slot_dereference_or_VPU_command_proven"])
            self.assertFalse(p["HEVC_Main10_recording_proven"])
            self.assertFalse(p["4K60_sustained_recording_proven"])
            self.assertFalse(p["camera_or_firmware_modified"])
            self.assertEqual(p["numeric_0x10004_means_what_codec_or_profile"],"UNKNOWN")
    def test_gui_initial_assignment_is_unknown(self):
        for s in v.SPECS.values():
            self.assertFalse(evalm(s)["GUI_to_Recorder_INPUT_0x5b0_initial_assignment_proven"])
    def test_main_plus_field_arithmetic(self):
        p=evalm(v.SPECS["xt4"])
        self.assertEqual(p["codec_constructor_field_absolute_offset_from_main"],"0x3a18")
        self.assertEqual(p["codec_constructor_select_field_offset"],"0x220")
    def test_submode_guard_present(self):
        for s in v.SPECS.values():
            self.assertTrue(evalm(s)["record_path_conditional_on_submode"])
    def test_stage33_wrong_model(self):
        s=v.SPECS["xs10"]
        def ch(t):t["p33"]["model"]="xt4"
        with self.assertRaisesRegex(ValueError,"Stage33"):
            evalm(s,ch)
    def test_stage33_wrong_context_offset(self):
        s=v.SPECS["xt4"]
        def ch(t):t["p33"]["movie_context_codec_offset"]="0x9d8"
        with self.assertRaisesRegex(ValueError,"Stage33"):
            evalm(s,ch)
    def test_stage33_wrong_first_value(self):
        s=v.SPECS["xs10"]
        def ch(t):t["p33"]["codec_control_if_byte_equals_1"]="0x10005"
        with self.assertRaisesRegex(ValueError,"Stage33"):
            evalm(s,ch)
    def test_stage33_wrong_second_value(self):
        s=v.SPECS["xt4"]
        def ch(t):t["p33"]["codec_control_otherwise"]="0x10004"
        with self.assertRaisesRegex(ValueError,"Stage33"):
            evalm(s,ch)
    def test_stage33_conflation(self):
        s=v.SPECS["xt4"]
        def ch(t):t["p33"]["movie_context_plus_0x5b0_is_Recorder_Codec"]=True
        with self.assertRaisesRegex(ValueError,"Stage33"):
            evalm(s,ch)
    def test_main_movie_constructor_BL_wrong(self):
        s=v.SPECS["xs10"]
        def ch(t):t["words"][s.builder_bl]=fakebl(s.builder_bl,s.builder+4)
        with self.assertRaisesRegex(ValueError,"parent BL"):
            evalm(s,ch)
    def test_main_backend_registrar_BL_wrong(self):
        s=v.SPECS["xt4"]
        def ch(t):t["words"][s.registrar_bl]=fakebl(s.registrar_bl,s.registrar+4)
        with self.assertRaisesRegex(ValueError,"parent BL"):
            evalm(s,ch)
    def test_main_movie_constructor_BL_rejected_if_not_call(self):
        s=v.SPECS["xs10"]
        def ch(t):t["words"][s.builder_bl]=0xe3a02008
        with self.assertRaisesRegex(ValueError,"unconditional"):
            evalm(s,ch)
    def test_parent_missing_builder(self):
        s=v.SPECS["xt4"]
        def ch(t):t["parent"]=t["parent"].replace("FUN_%08x"%s.builder,"FUN_deadbeef")
        with self.assertRaisesRegex(ValueError,"movie setup caller"):
            evalm(s,ch)
    def test_parent_wrong_main_video_subobject_offset(self):
        s=v.SPECS["xs10"]
        def ch(t):t["parent"]=t["parent"].replace("iVar4 + 0x37f8","iVar4 + 0x37f4")
        with self.assertRaisesRegex(ValueError,"movie setup caller"):
            evalm(s,ch)
    def test_parent_missing_secondary_pointer_slot(self):
        s=v.SPECS["xt4"]
        def ch(t):t["parent"]=t["parent"].replace("param_1 + 0x5ff4","param_1 + 0x5ff0")
        with self.assertRaisesRegex(ValueError,"movie setup caller"):
            evalm(s,ch)
    def test_parent_wrong_secondary_pointer_target(self):
        s=v.SPECS["xs10"]
        def ch(t):t["parent"]=t["parent"].replace("*(int *)(param_1 + 0x5ff4) = iVar4 + 0x37f8",
                                                 "*(int *)(param_1 + 0x5ff4) = iVar4 + 0x3494")
        with self.assertRaisesRegex(ValueError,"movie setup caller"):
            evalm(s,ch)
    def test_parent_missing_registrar(self):
        s=v.SPECS["xs10"]
        def ch(t):t["parent"]=t["parent"].replace("FUN_%08x(param_1)"%s.registrar,
                                                 "FUN_deadbeef(param_1)")
        with self.assertRaisesRegex(ValueError,"movie setup caller"):
            evalm(s,ch)
    def test_parent_bad_order(self):
        s=v.SPECS["xt4"]
        def ch(t):
            a="*(int *)(param_1 + 0x5ff4) = iVar6 + 0x37f8;\n"
            b="FUN_%08x(param_1);\n"%s.registrar
            t["parent"]=t["parent"].replace(a+b,b+a)
        with self.assertRaisesRegex(ValueError,"order changed"):
            evalm(s,ch)
    def test_parent_missing_guard(self):
        s=v.SPECS["xs10"]
        def ch(t):t["parent"]=t["parent"].replace("iVar4 + 0x122a0","iVar4 + 0x122a1")
        with self.assertRaisesRegex(ValueError,"alternate branch guard"):
            evalm(s,ch)
    def test_registrar_backend_ptr_origin_wrong(self):
        s=v.SPECS["xt4"]
        def ch(t):t["registrar"]=t["registrar"].replace("+ 0x124a8","+ 0x124ac")
        with self.assertRaisesRegex(ValueError,"backend pointer"):
            evalm(s,ch)
    def test_registrar_main_pointer_origin_wrong(self):
        s=v.SPECS["xs10"]
        def ch(t):t["registrar"]=t["registrar"].replace("param_1 + 0x601c","param_1 + 0x6018")
        with self.assertRaisesRegex(ValueError,"backend pointer"):
            evalm(s,ch)
    def test_registrar_wrong_backend_slot(self):
        s=v.SPECS["xt4"]
        def ch(t):t["registrar"]=t["registrar"].replace("iVar2 + 0x3d00","iVar2 + 0x3d08")
        with self.assertRaisesRegex(ValueError,"backend pointer"):
            evalm(s,ch)
    def test_registrar_wrong_backend_source_subobject(self):
        s=v.SPECS["xs10"]
        def ch(t):t["registrar"]=t["registrar"].replace(
            "iVar2 + 0x3d00) = *(int *)(param_1 + 0x601c) + 0x37f8",
            "iVar2 + 0x3d00) = *(int *)(param_1 + 0x601c) + 0x3494")
        with self.assertRaisesRegex(ValueError,"backend pointer"):
            evalm(s,ch)
    def test_registrar_wrong_neighboring_field(self):
        s=v.SPECS["xt4"]
        def ch(t):t["registrar"]=t["registrar"].replace("iVar2 + 0x3cfc","iVar2 + 0x3d04")
        with self.assertRaisesRegex(ValueError,"backend pointer"):
            evalm(s,ch)
    def test_registrar_optional_context_missing(self):
        s=v.SPECS["xs10"]
        def ch(t):t["registrar"]=t["registrar"].replace("param_1 + 0x3118","param_1 + 0x311c")
        with self.assertRaisesRegex(ValueError,"adjacent optional"):
            evalm(s,ch)
    def test_builder_c_wrong_codec_read_offset(self):
        s=v.SPECS["xs10"]
        def ch(t):t["builder"]=t["builder"].replace("0x9d8","0x9dc")
        with self.assertRaisesRegex(ValueError,"Stage33 Codec"):
            evalm(s,ch)
    def test_builder_c_wrong_control_write_location(self):
        s=v.SPECS["xt4"]
        def ch(t):t["builder"]=t["builder"].replace("param_4 + 0x220","param_4 + 0x224")
        with self.assertRaisesRegex(ValueError,"output field"):
            evalm(s,ch)
    def test_builder_A32_ldr_wrong_offset(self):
        s=v.SPECS["xt4"]
        def ch(t):t["words"][s.packet_codec_ldr]=0xe5d439d8
        with self.assertRaisesRegex(ValueError,"raw LDRB"):
            evalm(s,ch)
    def test_registrar_same_binary_original_instructions(self):
        for s in v.SPECS.values():
            self.assertEqual(evalm(s)["original_ARM_registrar_word_checks"],14)
    def test_cross_model_ABI_pointer_source_wrong(self):
        x,y=(evalm(s) for s in v.SPECS.values())
        y["backend_ptr_source"]="*(main + 0x124ac)"
        with self.assertRaisesRegex(ValueError,"ABIs differ"):
            v.audit_pair(x,y)
    def test_cross_model_ABI_slot_wrong(self):
        x,y=(evalm(s) for s in v.SPECS.values())
        y["backend_parameter_set_ptr_slot"]="backend + 0x3d04"
        with self.assertRaisesRegex(ValueError,"ABIs differ"):
            v.audit_pair(x,y)
    def test_cross_model_model_ids_wrong(self):
        x,y=(evalm(s) for s in v.SPECS.values())
        x["model"]="xt4"
        with self.assertRaisesRegex(ValueError,"IDs wrong"):
            v.audit_pair(x,y)
    def test_cross_model_field_location_wrong(self):
        x,y=(evalm(s) for s in v.SPECS.values())
        y["codec_constructor_field_absolute_offset_from_main"]="0x3a14"
        with self.assertRaisesRegex(ValueError,"ABIs differ"):
            v.audit_pair(x,y)
    def test_cross_model_ptr_equality_wrong(self):
        x,y=(evalm(s) for s in v.SPECS.values())
        y["backend_parameter_ptr_equals"]="main + 0x3494"
        with self.assertRaisesRegex(ValueError,"ABIs differ"):
            v.audit_pair(x,y)
    def test_consumer_not_claimed_by_fingerprint_match(self):
        x,y=(evalm(s) for s in v.SPECS.values())
        z=v.audit_pair(x,y)
        self.assertFalse(z["actual_encoder_consumer_or_final_device_bits_seen"])

def _make_individual_corruption(rel):
    def test(self):
        s=v.SPECS["xs10"] if rel%8 else v.SPECS["xt4"]
        def bad(t):t["words"][s.registrar+rel]^=1
        with self.assertRaisesRegex(ValueError,"original ARM word changed"):
            evalm(s,bad)
    test.__name__="test_corrupt_registration_A32_at_offset_%02x"%rel
    return test

# Every original registrar source/offset/store ARM word has an independently
# corrupted negative test, in addition to the source/destination C tests.
for _rel in sorted(v.REG_A32_WORDS):
    setattr(Flow,"test_corrupt_register_A32_%02x"%_rel,
            _make_individual_corruption(_rel))

if __name__=="__main__":
    main()

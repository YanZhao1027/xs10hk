"""Synthetic-only Phase31 tests: prove two pointer values are copied, with
a conditional active Codec->export-buffer write and an unrelated GUI cache.

All A32 words are generated; no proprietary Fujifilm ROM bytes or
camera/device interfaces are used. Does not establish Main10 or 4K60.
"""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_recorder_input_export_alias_stage31 as a


def make_movhalf(rd:int,value:int,high=False):
    return ((0xe3400000 if high else 0xe3000000) |
            (((value>>12)&15)<<16) | (rd<<12) | (value&0xfff))


def make_bl(from_addr:int,to_addr:int):
    diff=to_addr-from_addr-8
    if diff%4 or not -(1<<25)<=diff<(1<<25):
        raise ValueError("unencodable A32 BL")
    return 0xeb000000|((diff>>2)&0xffffff)


def block(c:str)->str:
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"+c+
            "\nTRACE_DECOMP_END (GhidraScript)\n")


def fixture(s:a.Spec):
    rom={}
    init=s.alias_init
    rom[init+8]=make_movhalf(2,(s.export_slot-8)&0xffff)
    rom[init+12]=make_movhalf(2,((s.export_slot-8)>>16)&0xffff,True)
    rom[init+16]=make_movhalf(3,s.descriptor&0xffff)
    rom[init+20]=make_movhalf(3,(s.descriptor>>16)&0xffff,True)
    rom[init+24]=0xe2831a03
    rom[init+28]=0xe5911ac4
    rom[init+32]=0xe5821008
    for call,target in ((s.call_alias,s.alias_init),
                        (s.call_serializer,s.serializer),
                        (s.call_exporter,s.exporter),
                        (s.gui_loader_call,s.gui_setter)):
        rom[call]=make_bl(call,target)
    a1,b1,c1,d1=s.byte_instructions
    for loc,val in ((a1,0xe5d53000|s.codec_offset),
                    (b1,0xe5c435b0),
                    (c1,0xe5d53000|(s.codec_offset+1)),
                    (d1,0xe5c435b1),
                    (s.gui_store,0xe5c345b0)):
        rom[loc]=val

    ini=block("void FUN_%08x(void) { _DAT_%08x = _DAT_%08x; }" %
              (s.alias_init,s.export_slot,s.current_slot))
    parent=("undefined4 FUN_%08x(void){\n"%s.caller+
            "  FUN_%08x();\n"%s.alias_init+
            ("  if (iVar2 == 0) { return 0; }\n"*4)+
            "  FUN_%08x();\n"%s.serializer+
            "  return 1;\n}")
    var="iVar3" if s.name=="xs10" else "iVar4"
    serializer=block("void FUN_%08x(void){\n"%s.serializer+
                     " %s = _DAT_%08x;\n"%(var,s.export_slot)+
                     " FUN_%08x(%s);\n}"%(s.exporter,var))
    codec=block("void FUN_%08x(int *param_1){\n"%s.exporter+
                "param_1[0x5b0] = DAT_%08x;\n"%s.active_codec+
                "param_1[0x5b1] = DAT_%08x;\n}"%s.active_format)
    gui=block("void FUN_%08x(uint param_1){\n"%s.gui_setter+
              "DAT_%08x = (char)param_1;\n}"%s.gui_byte)
    gui_loader=block("void FUN_%08x(void){\n"%s.gui_loader+
                     "uVar2 = GET_SETTING(0x%x);\n"%s.setting_id+
                     "if(uVar2 != 0x7fffffff){ FUN_%08x(uVar2 & 0xff); }\n}"%
                     s.gui_setter)
    ptr_xrefs=""
    for target,at,owner in ((s.current_slot,s.former_input_slot_writer,
                             (0x02214738 if s.name=="xs10" else 0x02180d0c)),
                            (s.export_slot,init+32,init)):
        ptr_xrefs+=(
            "SLOT_WRITE_CAND addr=%08x from=%08x type=WRITE func=%08x\n"
            "SLOT_SUMMARY addr=%08x refs=3 functions=3 types={READ=2, WRITE=1}\n"%
            (target,at,owner,target))
    ramlog="".join("MEMORY_TARGET %08x block=UNMAPPED initialized=N/A\n"%addr
                    for addr in (s.export_slot,s.current_slot,
                                 s.descriptor+0x10,s.gui_byte))
    return {"words":rom,"init":ini,"parent":block(parent),
            "serializer":serializer,"exporter":codec,"gui":gui,
            "gui_loader":gui_loader,"xrefs":ptr_xrefs,
            "ramlog":ramlog}


def audit_fixture(s,modifier=None):
    f=fixture(s)
    if modifier:modifier(f)
    with patch.object(a,"word",side_effect=lambda rom,base,addr:f["words"][addr]):
        return a.audit(s,b"",b"",f["init"],f["parent"],f["exporter"],
                       f["serializer"],f["gui"],f["gui_loader"],
                       f["xrefs"],f["ramlog"])


class DecoderCases(unittest.TestCase):
    def test_movw(self):
        self.assertEqual(a.mov_half(make_movhalf(2,0xd860),False,2),0xd860)
    def test_movt(self):
        self.assertEqual(a.mov_half(make_movhalf(3,0x02d9,True),True,3),0x2d9)
    def test_wrong_mov_register(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.mov_half(make_movhalf(1,0xd860),False,2)
    def test_wrong_mov_type(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.mov_half(make_movhalf(2,0x35b,True),False,2)
    def test_bl_negative(self):
        self.assertEqual(a.branch_target(make_bl(0x3000,0x2000),0x3000),0x2000)
    def test_bl_positive(self):
        self.assertEqual(a.branch_target(make_bl(0x2000,0x3000),0x2000),0x3000)
    def test_bl_wrong_class(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.branch_target(0xe2831a03,0x2000)
    def test_bl_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.branch_target(0x0b000000,0x2000)
    def test_real_little_endian_rom_word(self):
        self.assertEqual(a.word(bytes.fromhex("030a83e2"),0x1000,0x1000),
                         0xe2830a03)
    def test_rom_bounds(self):
        with self.assertRaisesRegex(ValueError,"outside loaded"):
            a.word(b"\0"*4,0x1000,0x1004)
    def test_rom_alignment(self):
        with self.assertRaisesRegex(ValueError,"aligned"):
            a.word(b"\0"*8,0x1000,0x1001)
    def test_function_only_definition(self):
        s=a.SPECS["xs10"]
        content=block("void FUN_0221c934(void){X;}")
        self.assertIn("X;",a.function_c(content,s.alias_init))
    def test_function_absent(self):
        with self.assertRaisesRegex(ValueError,"absent"):
            a.function_c("",0x0221c934)


class AliasProofCases(unittest.TestCase):
    def test_two_models_positive(self):
        for s in a.SPECS.values():
            with self.subTest(model=s.name):
                out=audit_fixture(s)
                self.assertTrue(out["pointer_value_equality_immediately_after_alias_instruction"])
                self.assertTrue(out["same_caller_calls_initializer_before_serializer"])
                self.assertEqual(out["original_ARM_BL_edges_verified"],4)
                self.assertEqual(out["raw_active_codec_format_load_store_words_verified"],4)
                self.assertFalse(out["runtime_pointer_equality_at_serializer_time_proven"])
                self.assertFalse(out["actual_GUI_codec_to_Recorder_input_initial_value_proven"])
                self.assertFalse(out["HEVC_Main10_internal_bitstream_proven"])
                self.assertFalse(out["camera_or_firmware_modified"])

    def test_two_slot_addresses_differ(self):
        for s in a.SPECS.values():
            self.assertNotEqual(s.current_slot,s.export_slot)

    def test_xs10_alias_addresses(self):
        result=audit_fixture(a.SPECS["xs10"])
        self.assertEqual(result["input_pointer_slot"],"0x02d9c2ac")
        self.assertEqual(result["export_pointer_slot"],"0x035bd868")

    def test_xt4_alias_addresses(self):
        result=audit_fixture(a.SPECS["xt4"])
        self.assertEqual(result["input_pointer_slot"],"0x02d0fa0c")
        self.assertEqual(result["export_pointer_slot"],"0x03672078")

    def test_wrong_current_pointer_owner(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.alias_init+16]=make_movhalf(
            3,(s.descriptor+4)&0xffff)
        with self.assertRaisesRegex(ValueError,"descriptor"):
            audit_fixture(s,modify)

    def test_wrong_export_slot_base(self):
        s=a.SPECS["xt4"]
        def modify(f):f["words"][s.alias_init+8]=make_movhalf(
            2,s.export_slot&0xffff)
        with self.assertRaisesRegex(ValueError,"output pointer slot"):
            audit_fixture(s,modify)

    def test_wrong_owner_high_half(self):
        s=a.SPECS["xt4"]
        def modify(f):f["words"][s.alias_init+20]=make_movhalf(
            3,(s.descriptor>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"descriptor"):
            audit_fixture(s,modify)

    def test_wrong_export_slot_high_half(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.alias_init+12]=make_movhalf(
            2,0x366,True)
        with self.assertRaisesRegex(ValueError,"output pointer"):
            audit_fixture(s,modify)

    def test_wrong_add_immediate(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.alias_init+24]=0xe2831a02
        with self.assertRaisesRegex(ValueError,"ADD/LDR/STR"):
            audit_fixture(s,modify)

    def test_wrong_input_slot_ldr_offset(self):
        s=a.SPECS["xt4"]
        def modify(f):f["words"][s.alias_init+28]=0xe5911ac8
        with self.assertRaisesRegex(ValueError,"ADD/LDR/STR"):
            audit_fixture(s,modify)

    def test_wrong_export_store_offset(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.alias_init+32]=0xe582100c
        with self.assertRaisesRegex(ValueError,"ADD/LDR/STR"):
            audit_fixture(s,modify)

    def test_alias_c_direction_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["init"]=f["init"].replace(
            "_DAT_035bd868 = _DAT_02d9c2ac",
            "_DAT_02d9c2ac = _DAT_035bd868")
        with self.assertRaisesRegex(ValueError,"alias assignment direction"):
            audit_fixture(s,modify)

    def test_parent_init_bl_corrupt(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.call_alias]=make_bl(
            s.call_alias,s.alias_init+4)
        with self.assertRaisesRegex(ValueError,"callsite original BL"):
            audit_fixture(s,modify)

    def test_parent_serializer_bl_corrupt(self):
        s=a.SPECS["xt4"]
        def modify(f):f["words"][s.call_serializer]=make_bl(
            s.call_serializer,s.serializer+4)
        with self.assertRaisesRegex(ValueError,"callsite original BL"):
            audit_fixture(s,modify)

    def test_parent_decompile_missing_serializer(self):
        s=a.SPECS["xs10"]
        def modify(f):f["parent"]=f["parent"].replace(
            "FUN_0221d1bc();","FUN_0221d1c0();")
        with self.assertRaisesRegex(ValueError,"ordering changed"):
            audit_fixture(s,modify)

    def test_parent_c_success_guard_missing(self):
        s=a.SPECS["xs10"]
        def modify(f):f["parent"]=f["parent"].replace(
            "if (iVar2 == 0) { return 0; }","if (iVar2 == 1) { return 0; }")
        with self.assertRaisesRegex(ValueError,"gated success"):
            audit_fixture(s,modify)

    def test_serializer_exporter_bl_corrupt(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.call_exporter]=make_bl(
            s.call_exporter,s.exporter+4)
        with self.assertRaisesRegex(ValueError,"callsite original BL"):
            audit_fixture(s,modify)

    def test_wrong_exporter_argument(self):
        s=a.SPECS["xs10"]
        def modify(f):f["serializer"]=f["serializer"].replace(
            "FUN_012be684(iVar3)","FUN_012be684(other)")
        with self.assertRaisesRegex(ValueError,"aliased buffer"):
            audit_fixture(s,modify)

    def test_wrong_exporter_global(self):
        s=a.SPECS["xt4"]
        def modify(f):f["serializer"]=f["serializer"].replace(
            "_DAT_03672078","_DAT_0367207c")
        with self.assertRaisesRegex(ValueError,"export-pointer"):
            audit_fixture(s,modify)

    def test_codec_read_offset_wrong(self):
        s=a.SPECS["xt4"]
        def modify(f):f["words"][s.byte_instructions[0]]=0xe5d53430
        with self.assertRaisesRegex(ValueError,"four A32"):
            audit_fixture(s,modify)

    def test_codec_store_offset_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.byte_instructions[1]]=0xe5c435b1
        with self.assertRaisesRegex(ValueError,"four A32"):
            audit_fixture(s,modify)

    def test_format_read_offset_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.byte_instructions[2]]=0xe5d53432
        with self.assertRaisesRegex(ValueError,"four A32"):
            audit_fixture(s,modify)

    def test_format_store_offset_wrong(self):
        s=a.SPECS["xt4"]
        def modify(f):f["words"][s.byte_instructions[3]]=0xe5c435b2
        with self.assertRaisesRegex(ValueError,"four A32"):
            audit_fixture(s,modify)

    def test_export_codec_source_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["exporter"]=f["exporter"].replace(
            "DAT_01c25208","DAT_01c25209")
        with self.assertRaisesRegex(ValueError,"active config to output"):
            audit_fixture(s,modify)

    def test_gui_is_distinct_cache(self):
        for s in a.SPECS.values():
            r=audit_fixture(s)
            self.assertNotEqual(r["GUI_cache_byte"],r["codec_active_config"])
            self.assertNotEqual(r["GUI_cache_byte"],r["input_pointer_slot"])

    def test_gui_loader_setting_id_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["gui_loader"]=f["gui_loader"].replace(
            "0x3fc","0x3fa")
        with self.assertRaisesRegex(ValueError,"settings-service"):
            audit_fixture(s,modify)

    def test_gui_loader_call_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.gui_loader_call]=make_bl(
            s.gui_loader_call,s.gui_setter+4)
        with self.assertRaisesRegex(ValueError,"callsite original BL"):
            audit_fixture(s,modify)

    def test_gui_cache_assignment_wrong(self):
        s=a.SPECS["xt4"]
        def modify(f):f["gui"]=f["gui"].replace(
            "DAT_01af2db8","DAT_01af2db9")
        with self.assertRaisesRegex(ValueError,"GUI cache setter"):
            audit_fixture(s,modify)

    def test_gui_store_raw_wrong(self):
        s=a.SPECS["xs10"]
        def modify(f):f["words"][s.gui_store]=0xe5c345b1
        with self.assertRaisesRegex(ValueError,"GUI codec byte"):
            audit_fixture(s,modify)

    def test_wrong_export_direct_write_xref(self):
        s=a.SPECS["xs10"]
        def modify(f):f["xrefs"]=f["xrefs"].replace(
            "from=0221c954","from=0221c958")
        with self.assertRaisesRegex(ValueError,"expected original slot"):
            audit_fixture(s,modify)

    def test_wrong_source_direct_write_xref(self):
        s=a.SPECS["xt4"]
        def modify(f):f["xrefs"]=f["xrefs"].replace(
            "from=02180d50","from=02180d54")
        with self.assertRaisesRegex(ValueError,"expected original slot"):
            audit_fixture(s,modify)

    def test_additional_direct_writer_requires_reaudit(self):
        s=a.SPECS["xs10"]
        def modify(f):f["xrefs"]=f["xrefs"].replace(
            "READ=2, WRITE=1","READ=1, WRITE=2")
        with self.assertRaisesRegex(ValueError,"more than one"):
            audit_fixture(s,modify)

    def test_runtime_ram_not_in_rom_map(self):
        for s in a.SPECS.values():
            r=audit_fixture(s)
            self.assertEqual(r["runtime_current_buffer_pointer_numeric_value"],
                             "UNKNOWN")

    def test_new_rom_mapping_for_pointer_requires_research(self):
        s=a.SPECS["xs10"]
        def modify(f):f["ramlog"]=f["ramlog"].replace(
            "MEMORY_TARGET 02d9c2ac block=UNMAPPED",
            "MEMORY_TARGET 02d9c2ac block=ram")
        with self.assertRaisesRegex(ValueError,"now mapped"):
            audit_fixture(s,modify)

    def test_no_unconditional_runtime_alias_claim(self):
        for s in a.SPECS.values():
            r=audit_fixture(s)
            self.assertFalse(r["runtime_pointer_equality_at_serializer_time_proven"])
            self.assertTrue(r["conditional_active_to_input_buffer_codec_feedback_possible"])

    def test_not_a_camera_patch_or_unlock(self):
        for s in a.SPECS.values():
            r=audit_fixture(s)
            self.assertFalse(r["camera_or_firmware_modified"])
            self.assertFalse(r["HEVC_Main10_internal_bitstream_proven"])
            self.assertFalse(r["4K60_sensor_ISP_pipeline_proven"])


if __name__=="__main__":
    unittest.main()

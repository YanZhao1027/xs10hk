"""Synthetic A32 positive and negative tests: Phase29 registry-to-descriptor.

Every instruction below is constructed in memory; no camera firmware, ROM
bytes, crypto materials, or hardware access embedded. Tests do not imply
HEVC Main10 or 4K60 is supported.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_mode_profile_registry_stage29 as a


def bl(at,target):
    delta=target-at-8
    if delta%4 or not -(1<<25)<=delta<(1<<25):
        raise ValueError("BL out of range")
    return 0xeb000000 | ((delta>>2)&0xffffff)


def movhalf(rd,imm,high=False):
    return ((0xe3400000 if high else 0xe3000000)
            | (((imm>>12)&15)<<16) | (rd<<12) | (imm&0xfff))


def wrapped(body):
    return "TRACE_DECOMP_BEGIN (GhidraScript)\n"+body+"\nTRACE_DECOMP_END (GhidraScript)\n"


def fixture(s):
    words={}
    for address,target in (
        (s.header_lookup_bl,s.header_lookup),
        (s.payload_lookup_bl,s.payload_lookup),
        (s.header_copy_bl,s.memcpy),
        (s.payload_copy_bl,s.memcpy),
        *((p,s.installer) for p in s.mode_call_sites)
    ):
        words[address]=bl(address,target)
    words[s.header_base_movw]=movhalf(0,s.destination_header&0xffff)
    words[s.header_base_movt]=movhalf(0,(s.destination_header>>16)&0xffff,True)
    words[s.payload_dest_ldr]=(0xe59f0000|
             (s.payload_dest_literal-(s.payload_dest_ldr+8)))
    words[s.payload_dest_literal]=s.destination_payload
    words[s.dynamic_copy_len_ldr]=0xe5942004
    words[s.header_copy_len_mov]=0xe3a0200c
    for caller in s.mode_call_sites:
        words[caller-8]=0xe3a0108c
        words[caller-4]=0xe1a00004
    for ptr,byte in zip(s.mode_selected_buffer_loads,s.mode_selector_byte_loads):
        words[ptr]=0xe5933ac4
        words[byte]=0xe5d33004
    refs=""
    callerC=""
    for caller,site in zip(s.mode_caller_functions,s.mode_call_sites):
        refs+=("PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n"%
               (site,s.installer))
        callerC+=wrapped(
            "undefined4 FUN_%08x(void){\n"%caller
            +" if (*(char *)(*(int *)(DAT_01001234 + 0xac4) + 4) == 0) {\n"
            +"   uVar2 = 0x206;\n"
            +" } else { uVar2 = 0x207; }\n"
            +" FUN_%08x(uVar2,0x8c);\n"%s.installer
            +"}")

    inst=wrapped(
        "void FUN_%08x(undefined4 param_1,undefined4 param_2){\n"%s.installer
        +" iVar1 = FUN_%08x(param_1,param_2,1);\n"%s.header_lookup
        +" iVar2 = FUN_%08x(param_1,param_2,1);\n"%s.payload_lookup
        +" FUN_%08x(&DAT_%08x,iVar1,0xc);\n"%(s.memcpy,s.destination_header)
        +" FUN_%08x(DAT_%08x,iVar2,*(undefined4 *)(iVar1 + 4));\n"%
           (s.memcpy,s.payload_dest_literal)
        +"}"
    )
    hdr=wrapped(
        "int FUN_%08x(uint param_1,uint param_2,int param_3){\n"%s.header_lookup
        +" if (param_1 != 0x200) goto ABORT;\n"
        +" if (param_1 != 0x206) { ..; }\n"
        +" if (param_1 == 0x207) { ..; }\n"
        +" iVar1 = 0x50 * DAT_1234;\n"
        +" return 1;\n}"
    )
    pay=wrapped(
        "int FUN_%08x(uint param_1,uint param_2,int param_3){\n"%s.payload_lookup
        +" if (param_1 == 0x200) return 0;\n"
        +" if (param_1 == 0x206) { ..; }\n"
        +" else if (param_1 == 0x207) { ..; }\n"
        +" iVar1 = (_DAT_%08x + -1) * 0x50 + 0x%x;\n"%
           (s.mode_206_counter_slot,s.mode_206_payload_base)
        +" return iVar1;\n}"
    )
    for at,val in (
        (s.registry_206_header_literal,s.mode_206_payload_base-0xc),
        (s.registry_207_header_literal,
         (0x02d9b358 if s.model=="xs10" else 0x02d0eab8)),
        (s.registry_207_payload_literal,
         (0x02d9b364 if s.model=="xs10" else 0x02d0eac4)),
        (s.registry_200_header_literal,
         (0x02d98838 if s.model=="xs10" else 0x02d0bf98)),
        (s.registry_200_payload_literal,
         (0x02d98844 if s.model=="xs10" else 0x02d0bfa4)),
    ):words[at]=val
    return dict(words=words,install=inst,lookup=hdr+pay,
                refs=refs,callers=callerC)


def evaluate(s,mutation=None):
    f=fixture(s)
    if mutation:mutation(f)
    with patch.object(a,"word",side_effect=lambda raw,base,address:f["words"][address]):
        return a.audit(s,b"",f["install"],f["lookup"],f["refs"],f["callers"])


class InstructionTests(unittest.TestCase):
    def test_bl_positive(self):
        self.assertEqual(a.bl_target(bl(0x2000,0x1000),0x2000),0x1000)

    def test_bl_forward(self):
        self.assertEqual(a.bl_target(bl(0x1000,0x1100),0x1000),0x1100)

    def test_bl_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.bl_target(0xe3a0108c,0x1000)

    def test_bl_wrong_cond(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.bl_target(0x0b000004,0x1000)

    def test_movw_assembles(self):
        self.assertEqual(a.half(movhalf(0,0x87e8),False,0),0x87e8)

    def test_movt_assembles(self):
        self.assertEqual(a.half(movhalf(0,0x02d9,True),True,0),0x2d9)

    def test_movhalf_wrong_reg(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.half(movhalf(2,0x2d9),False,0)

    def test_movhalf_wrong_kind(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.half(movhalf(0,0x2d9,True),False,0)

    def test_pc_literal_positive(self):
        a.positive_pc_ldr(0xe59f0020,0x1000,0x1028,0)

    def test_pc_literal_wrong_rd(self):
        with self.assertRaisesRegex(ValueError,"PC-relative"):
            a.positive_pc_ldr(0xe59f1020,0x1000,0x1028,0)

    def test_pc_literal_too_far(self):
        with self.assertRaisesRegex(ValueError,"PC-relative"):
            a.positive_pc_ldr(0xe59f0020,0x1000,0x5000,0)

    def test_raw_little_endian_read(self):
        self.assertEqual(a.word(struct.pack("<I",0xe3a0108c),0x1000,0x1000),
                         0xe3a0108c)

    def test_raw_word_out_of_section(self):
        with self.assertRaisesRegex(ValueError,"outside original"):
            a.word(b"\x00"*4,0x1000,0x1004)

    def test_raw_word_unaligned(self):
        with self.assertRaisesRegex(ValueError,"outside original"):
            a.word(b"\x00"*8,0x1000,0x1001)

    def test_missing_decompile(self):
        with self.assertRaisesRegex(ValueError,"missing Ghidra"):
            a.function_c("",0x12345000)

    def test_decompile_not_wrong_name(self):
        source=wrapped("int FUN_11112222(void){return 0;}")+wrapped(
            "int FUN_12345000(void){return 7;}")
        self.assertIn("return 7",a.function_c(source,0x12345000))


class IngressAuditTests(unittest.TestCase):
    def test_both_models_pass(self):
        for s in a.SPECS.values():
            with self.subTest(model=s.model):
                r=evaluate(s)
                self.assertEqual(r["original_7_A32_BL_edges_verified"],7)
                self.assertEqual(len(r["actual_installer_callers_verified"]),3)
                self.assertEqual(r["selected_registry_type_values"],["0x206","0x207"])
                self.assertFalse(r["runtime_length_and_pointer_value_known"])
                self.assertFalse(r["GUI_MovieCodec_to_Recorder_buffer_proven"])
                self.assertFalse(r["HEVC_Main10_internal_bitstream_proven"])
                self.assertFalse(r["4K60_sensor_pipeline_proven"])
                self.assertFalse(r["firmware_or_camera_modified"])

    def test_xs10_selected_registry_table(self):
        r=evaluate(a.SPECS["xs10"])
        self.assertEqual(r["mode_206_dynamic_header_base"],"0x02d98a68")
        self.assertEqual(r["mode_207_static_payload"],"0x02d9b364")
        self.assertEqual(r["descriptor_current_pointer_field"],"0x02d987f8")

    def test_xt4_selected_registry_table(self):
        r=evaluate(a.SPECS["xt4"])
        self.assertEqual(r["mode_206_dynamic_header_base"],"0x02d0c1c8")
        self.assertEqual(r["mode_207_static_payload"],"0x02d0eac4")
        self.assertEqual(r["descriptor_current_pointer_field"],"0x02d0bf58")

    def test_wrong_installer_original_BL(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.mode_call_sites[0]]=bl(
            s.mode_call_sites[0],s.installer+4)
        with self.assertRaisesRegex(ValueError,"A32 BL mismatch"):
            evaluate(s,m)

    def test_wrong_header_lookup_BL(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.header_lookup_bl]=bl(
            s.header_lookup_bl,s.header_lookup+4)
        with self.assertRaisesRegex(ValueError,"A32 BL mismatch"):
            evaluate(s,m)

    def test_wrong_payload_lookup_BL(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.payload_lookup_bl]=bl(
            s.payload_lookup_bl,s.payload_lookup+4)
        with self.assertRaisesRegex(ValueError,"A32 BL mismatch"):
            evaluate(s,m)

    def test_wrong_payload_copy_helper_BL(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.payload_copy_bl]=bl(
            s.payload_copy_bl,s.memcpy+4)
        with self.assertRaisesRegex(ValueError,"A32 BL mismatch"):
            evaluate(s,m)

    def test_github_xref_wrong_call_address(self):
        s=a.SPECS["xs10"]
        def m(f):f["refs"]=f["refs"].replace(
            "from=021e7060","from=021e7064")
        with self.assertRaisesRegex(ValueError,"Ghidra installer"):
            evaluate(s,m)

    def test_header_target_movw_bad(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.header_base_movw]=movhalf(
            0,(s.destination_header+4)&0xffff)
        with self.assertRaisesRegex(ValueError,"base not literal"):
            evaluate(s,m)

    def test_header_target_movt_bad(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.header_base_movt]=movhalf(
            0,(s.destination_header>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"base not literal"):
            evaluate(s,m)

    def test_payload_dest_pc_pointer_bad(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.payload_dest_literal]=s.destination_payload+4
        with self.assertRaisesRegex(ValueError,"payload destination literal"):
            evaluate(s,m)

    def test_payload_dest_ldr_bad(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.payload_dest_ldr]=0xe59f0024
        with self.assertRaisesRegex(ValueError,"PC-relative"):
            evaluate(s,m)

    def test_dynamic_size_read_wrong(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.dynamic_copy_len_ldr]=0xe5942008
        with self.assertRaisesRegex(ValueError,"size must read"):
            evaluate(s,m)

    def test_fixed_header_copy_len_bad(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.header_copy_len_mov]=0xe3a02010
        with self.assertRaisesRegex(ValueError,"12-byte"):
            evaluate(s,m)

    def test_missing_installer_lookup_C(self):
        s=a.SPECS["xs10"]
        def m(f):f["install"]=f["install"].replace(
            "FUN_021f893c(param_1,param_2,1)","FUN_021f893c(param_1,param_2,0)")
        with self.assertRaisesRegex(ValueError,"lookup chain"):
            evaluate(s,m)

    def test_missing_data_copy_C(self):
        s=a.SPECS["xt4"]
        def m(f):f["install"]=f["install"].replace(
            "DAT_02165294,iVar2","DAT_02165290,iVar2")
        with self.assertRaisesRegex(ValueError,"dynamic payload"):
            evaluate(s,m)

    def test_header_registry_missing_206(self):
        s=a.SPECS["xs10"]
        def m(f):f["lookup"]=f["lookup"].replace(
            "param_1 != 0x206","param_1 != 0x204")
        with self.assertRaisesRegex(ValueError,"header registry type"):
            evaluate(s,m)

    def test_payload_registry_missing_207(self):
        s=a.SPECS["xt4"]
        def m(f):f["lookup"]=f["lookup"].replace(
            "else if (param_1 == 0x207)","else if (param_1 == 0x210)")
        with self.assertRaisesRegex(ValueError,"payload registry type"):
            evaluate(s,m)

    def test_dynamic_entry_counter_wrong(self):
        s=a.SPECS["xs10"]
        def m(f):f["lookup"]=f["lookup"].replace(
            "_DAT_02d9c2a4","_DAT_02d9c2a8")
        with self.assertRaisesRegex(ValueError,"dynamic 0x206"):
            evaluate(s,m)

    def test_dynamic_entry_stride_wrong(self):
        s=a.SPECS["xt4"]
        def m(f):f["lookup"]=f["lookup"].replace("0x50","0x54")
        with self.assertRaisesRegex(ValueError,"dynamic 0x206"):
            evaluate(s,m)

    def test_206_static_literal_wrong(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.registry_206_header_literal]+=4
        with self.assertRaisesRegex(ValueError,"dynamic mode 0x206"):
            evaluate(s,m)

    def test_207_static_payload_wrong(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.registry_207_payload_literal]+=4
        with self.assertRaisesRegex(ValueError,"mode 0x207"):
            evaluate(s,m)

    def test_200_registry_payload_wrong(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.registry_200_payload_literal]+=4
        with self.assertRaisesRegex(ValueError,"mode 0x200"):
            evaluate(s,m)

    def test_mode_caller_setting_wrong(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.mode_call_sites[1]-8]=0xe3a01084
        with self.assertRaisesRegex(ValueError,"literal 0x8C"):
            evaluate(s,m)

    def test_mode_caller_register_wrong(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.mode_call_sites[2]-4]=0xe1a00005
        with self.assertRaisesRegex(ValueError,"R4"):
            evaluate(s,m)

    def test_mode_selector_ptr_slot_offset_wrong(self):
        s=a.SPECS["xt4"]
        def m(f):f["words"][s.mode_selected_buffer_loads[0]]=0xe5933ac8
        with self.assertRaisesRegex(ValueError,"buffer pointer"):
            evaluate(s,m)

    def test_mode_selector_byte_offset_wrong(self):
        s=a.SPECS["xs10"]
        def m(f):f["words"][s.mode_selector_byte_loads[1]]=0xe5d33005
        with self.assertRaisesRegex(ValueError,"buffer byte"):
            evaluate(s,m)

    def test_mode_caller_not_primary_buffer(self):
        s=a.SPECS["xt4"]
        def m(f):f["callers"]=f["callers"].replace(
            " + 0xac4) + 4"," + 0xac8) + 4")
        with self.assertRaisesRegex(ValueError,"mode switch not based"):
            evaluate(s,m)

    def test_mode_caller_wrong_choice(self):
        s=a.SPECS["xs10"]
        def m(f):f["callers"]=f["callers"].replace("0x207","0x208")
        with self.assertRaisesRegex(ValueError,"mode switch not based"):
            evaluate(s,m)

    def test_missing_mode_installer_call(self):
        s=a.SPECS["xt4"]
        def m(f):f["callers"]=f["callers"].replace(
            "FUN_02165210(uVar2,0x8c)","FUN_02165210(uVar2,0x84)")
        with self.assertRaisesRegex(ValueError,"installer with selector"):
            evaluate(s,m)

    def test_wrong_data_payload_plus12_alignment(self):
        s=replace(a.SPECS["xs10"],destination_payload=0x02d987f8)
        with self.assertRaisesRegex(ValueError,"literal|offset"):
            evaluate(s)

    def test_different_modes_not_codec_proof(self):
        for s in a.SPECS.values():
            r=evaluate(s)
            self.assertFalse(r["GUI_MovieCodec_to_Recorder_buffer_proven"])
            self.assertFalse(r["runtime_length_and_pointer_value_known"])


if __name__=="__main__":
    unittest.main()

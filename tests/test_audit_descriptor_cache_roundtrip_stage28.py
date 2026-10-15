"""Synthetic-only tests for Phase28 descriptor cache save/restore evidence.

Test ROM instructions are GENERATED in memory, not extracted from Fujifilm.
No camera/device access. Positive synthetic tests are not proof of Main10.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_descriptor_cache_roundtrip_stage28 as aud


def branch(at, target):
    delta=target-at-8
    if delta%4 or not -(1<<25)<=delta<(1<<25):
        raise ValueError("unencodable A32 BL")
    return 0xeb000000 | ((delta>>2)&0xffffff)


def movhalf(reg,n,high=False):
    return ((0xe3400000 if high else 0xe3000000) |
            (((n>>12)&15)<<16) | (reg<<12) | (n&4095))


def fixture(s):
    values={}
    for address,target in (
        (s.save_payload_bl,s.copy_helper),
        (s.save_header_bl,s.copy_helper),
        (s.restore_header_bl,s.copy_helper),
        (s.restore_payload_bl,s.copy_helper),
        (s.save_hook,s.save_fn),(s.restore_hook,s.restore_fn)):
        values[address]=branch(address,target)
    for address in (s.save_mov_len_insn,s.restore_mov_len_insn):
        values[address]=0xe3a0200c
    values[s.save_dynamic_len_insn]=0xe5942004
    values[s.restore_dynamic_len_insn]=0xe7922003
    values[s.restore_dest_insn]=0xe285000c
    values[s.index_mov]=0xe3a04054
    values[s.index_mul]=0xe0040094
    values[s.restore_movw]=movhalf(5,s.descriptor&65535)
    values[s.restore_movt]=movhalf(5,(s.descriptor>>16)&65535,True)

    copier="FUN_%08x"%s.copy_helper
    d=s.descriptor
    t=s.table
    save=(
        "void FUN_%08x(int param_1){\n"
        " iVar1 = param_1 * 0x54;\n"
        " if (condition) { %s(&DAT_%08x + iVar1,&DAT_%08x,0xc); }\n"
        " %s(iVar1 + 0x%x,&DAT_%08x,_DAT_%08x);\n"
        "}\n" %
        (s.save_fn,copier,t,d,copier,t+0xc,d+0xc,d+4)
    )
    restore=(
        "void FUN_%08x(int param_1){\n"
        " param_1 = param_1 * 0x54;\n"
        " %s(&DAT_%08x,&DAT_%08x + param_1,0xc);\n"
        " %s(&DAT_%08x,param_1 + 0x%x,*(undefined4 *)(param_1 + 0x%x));\n"
        "}\n" %
        (s.restore_fn,copier,d,t,copier,d+0xc,t+0xc,t+4)
    )
    reset=("void FUN_%08x(void){ int p=0x540; int stride=0x54;"
           "zero_mem(...,0x50); }" % s.reset_fn)
    savecaller=("void FUN_%08x(void){ FUN_%08x(); }" %
                (s.save_caller,s.save_fn))
    restorecaller=("void FUN_%08x(void){ "
                   "if (uVar3 != 0x10) FUN_%08x(uVar3 & 0xff); }" %
                   (s.restore_caller,s.restore_fn))
    xrefs=("PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n"
           "PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n" %
           (s.save_hook,s.save_fn,s.restore_hook,s.restore_fn))
    return {
        "words":values,"save":save,"restore":restore,"reset":reset,
        "savecaller":savecaller,"restorecaller":restorecaller,
        "xrefs":xrefs
    }


def run(s, mutation=None):
    d=fixture(s)
    if mutation:mutation(d)
    with patch.object(aud,"word",
                      side_effect=lambda blob,base,at:d["words"][at]):
        return aud.check_original(
            s,b"",d["save"],d["restore"],d["reset"],
            d["savecaller"],d["restorecaller"],d["xrefs"])


class A32ParserTests(unittest.TestCase):
    def test_branch_backward(self):
        self.assertEqual(aud.decode_bl(branch(0x2000,0x1000),0x2000),
                         0x1000)

    def test_branch_forward(self):
        self.assertEqual(aud.decode_bl(branch(0x1000,0x2000),0x1000),
                         0x2000)

    def test_wrong_branch_class(self):
        with self.assertRaisesRegex(ValueError,"not A32"):
            aud.decode_bl(0xe3a0200c,0x1000)

    def test_wrong_branch_condition(self):
        with self.assertRaisesRegex(ValueError,"not A32"):
            aud.decode_bl(0x0b000003,0x1000)

    def test_movw_correct(self):
        self.assertEqual(aud.half(movhalf(5,0xbeef),False,5),0xbeef)

    def test_movt_correct(self):
        self.assertEqual(aud.half(movhalf(5,0x2d9,True),True,5),0x2d9)

    def test_half_wrong_register(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            aud.half(movhalf(4,0xbeef),False,5)

    def test_half_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            aud.half(movhalf(5,0xbeef,True),False,5)

    def test_original_arm_read(self):
        self.assertEqual(aud.word(struct.pack("<I",0xe3a0200c),0x1000,0x1000),
                         0xe3a0200c)

    def test_original_read_misalignment(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            aud.word(bytes(12),0x1000,0x1002)

    def test_original_read_outside(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            aud.word(bytes(4),0x1000,0x1004)

    def test_function_only_definition_not_caller(self):
        c=("TRACE_DECOMP_BEGIN (GhidraScript)\n"
           "void FUN_01000000(void){ FUN_021f9338(); }\n"
           "TRACE_DECOMP_END (GhidraScript)\n"
           "TRACE_DECOMP_BEGIN (GhidraScript)\n"
           "void FUN_021f9338(void){ REAL_SAVE(); }\n"
           "TRACE_DECOMP_END (GhidraScript)\n")
        self.assertIn("REAL_SAVE",aud.function_c(c,0x021f9338))

    def test_missing_decompile_rejected(self):
        with self.assertRaisesRegex(ValueError,"missing"):
            aud.function_c("",0x021f9338)

    def test_payload_length_boundary(self):
        for n in range(8):
            with self.subTest(length=n):
                self.assertFalse(aud.payload_covers_primary_pointer(n))
        self.assertTrue(aud.payload_covers_primary_pointer(8))
        self.assertTrue(aud.payload_covers_primary_pointer(80))

    def test_negative_length_rejected(self):
        with self.assertRaisesRegex(ValueError,"negative"):
            aud.payload_covers_primary_pointer(-1)


class StagedAuditTests(unittest.TestCase):
    def test_both_models_positive(self):
        for s in aud.SPECS.values():
            with self.subTest(model=s.model):
                r=run(s)
                self.assertEqual(r["raw_BL_targets_verified"],6)
                self.assertEqual(r["record_count_in_callers"],16)
                self.assertTrue(r["cache_backup_and_restore_paths_proven_statically"])
                self.assertFalse(r["runtime_payload_length_verified"])
                self.assertFalse(r["input_buffer_codec_value_verified"])
                self.assertFalse(r["GUI_to_recorder_codec_assignment_proven"])
                self.assertFalse(r["HEVC_Main10_bitstream_proven"])
                self.assertFalse(r["internal_4K60_proven"])

    def test_restore_header_covers_no_primary_pointer(self):
        for s in aud.SPECS.values():
            with self.subTest(s.model):
                r=run(s)
                self.assertEqual(r["header_copy_bytes"],12)
                self.assertEqual(r["pointer_inside_payload_offset_bytes"],4)
                self.assertEqual(r["minimum_payload_length_to_include_pointer"],8)

    def test_wrong_memcpy_call_target(self):
        s=aud.SPECS["xs10"]
        def m(d):d["words"][s.restore_payload_bl]=branch(
            s.restore_payload_bl,s.copy_helper+4)
        with self.assertRaisesRegex(ValueError,"BL target"):
            run(s,m)

    def test_wrong_upstream_caller_target(self):
        s=aud.SPECS["xt4"]
        def m(d):d["words"][s.restore_hook]=branch(
            s.restore_hook,s.restore_fn+4)
        with self.assertRaisesRegex(ValueError,"BL target"):
            run(s,m)

    def test_changed_header_fixed_len(self):
        s=aud.SPECS["xs10"]
        def m(d):d["words"][s.restore_mov_len_insn]=0xe3a02010
        with self.assertRaisesRegex(ValueError,"header length"):
            run(s,m)

    def test_missing_save_payload_length_read(self):
        s=aud.SPECS["xs10"]
        def m(d):d["words"][s.save_dynamic_len_insn]=0xe5942008
        with self.assertRaisesRegex(ValueError,"save payload size"):
            run(s,m)

    def test_missing_restore_dynamic_size_read(self):
        s=aud.SPECS["xt4"]
        def m(d):d["words"][s.restore_dynamic_len_insn]=0xe7922004
        with self.assertRaisesRegex(ValueError,"restore payload size"):
            run(s,m)

    def test_wrong_restore_destination_offset(self):
        s=aud.SPECS["xt4"]
        def m(d):d["words"][s.restore_dest_insn]=0xe2850010
        with self.assertRaisesRegex(ValueError,"descriptor\\+0x0c"):
            run(s,m)

    def test_wrong_record_stride_mov(self):
        s=aud.SPECS["xs10"]
        def m(d):d["words"][s.index_mov]=0xe3a04058
        with self.assertRaisesRegex(ValueError,"index register"):
            run(s,m)

    def test_wrong_record_stride_mul(self):
        s=aud.SPECS["xs10"]
        def m(d):d["words"][s.index_mul]=0xe0040095
        with self.assertRaisesRegex(ValueError,"index register"):
            run(s,m)

    def test_wrong_descriptor_movw(self):
        s=aud.SPECS["xs10"]
        def m(d):d["words"][s.restore_movw]=movhalf(
            5,(s.descriptor+8)&65535)
        with self.assertRaisesRegex(ValueError,"descriptor-base"):
            run(s,m)

    def test_missing_restore_header_copy_c(self):
        s=aud.SPECS["xs10"]
        def m(d):d["restore"]=d["restore"].replace("0xc);","0x10);")
        with self.assertRaisesRegex(ValueError,"fixed 12-byte"):
            run(s,m)

    def test_missing_restore_payload_length_field(self):
        s=aud.SPECS["xs10"]
        def m(d):d["restore"]=d["restore"].replace(
            "0x2d9bd10","0x2d9bd14")
        with self.assertRaisesRegex(ValueError,"variable-size payload"):
            run(s,m)

    def test_wrong_save_header_copy_destination(self):
        s=aud.SPECS["xt4"]
        def m(d):d["save"]=d["save"].replace(
            "&DAT_02d0f46c + iVar1","&DAT_02d0f46f + iVar1")
        with self.assertRaisesRegex(ValueError,"save fixed 12-byte"):
            run(s,m)

    def test_wrong_save_payload_source(self):
        s=aud.SPECS["xt4"]
        def m(d):d["save"]=d["save"].replace(
            "&DAT_02d0bf54,_DAT_02d0bf4c",
            "&DAT_02d0bf58,_DAT_02d0bf4c")
        with self.assertRaisesRegex(ValueError,"save variable-size"):
            run(s,m)

    def test_header_clear_count_changed(self):
        s=aud.SPECS["xs10"]
        def m(d):d["reset"]=d["reset"].replace("0x540","0x580")
        with self.assertRaisesRegex(ValueError,"16 records"):
            run(s,m)

    def test_restore_caller_not_looping_16_slots(self):
        s=aud.SPECS["xt4"]
        def m(d):d["restorecaller"]=d["restorecaller"].replace(
            "uVar3 != 0x10","uVar3 != 0x11")
        with self.assertRaisesRegex(ValueError,"sixteen slots"):
            run(s,m)

    def test_no_upstream_restore_call(self):
        s=aud.SPECS["xt4"]
        def m(d):d["restorecaller"]=d["restorecaller"].replace(
            f"FUN_{s.restore_fn:08x}","FUN_00000001")
        with self.assertRaisesRegex(ValueError,"restore event caller"):
            run(s,m)

    def test_wrong_ghidra_caller_xref(self):
        s=aud.SPECS["xs10"]
        def m(d):d["xrefs"]=d["xrefs"].replace(
            "from=021fca78","from=021fca7c")
        with self.assertRaisesRegex(ValueError,"caller xrefs"):
            run(s,m)

    def test_second_model_compares_same_layout(self):
        a,b=aud.SPECS["xs10"],aud.SPECS["xt4"]
        ar,br=run(a),run(b)
        self.assertEqual(ar["record_stride_bytes"],br["record_stride_bytes"])
        self.assertNotEqual(ar["descriptor_base"],br["descriptor_base"])


if __name__=="__main__":
    unittest.main()

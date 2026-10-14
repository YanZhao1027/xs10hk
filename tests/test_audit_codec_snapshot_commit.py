"""Synthetic only: audit snapshot -> buffer -> active movie codec runtime byte."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from audit_codec_snapshot_commit import (
    SPECS, audit, c_function, pointer_from_section, wrapper_preserves_r0,
)


def synthetic(spec):
    source=spec.snapshot_ptr_literal
    working=spec.working_ptr_literal
    call={"xt4":0x01299020,"xs10":0x012c0894}[spec.name]
    return {
        "snapshot_ptr":spec.snapshot_expected,
        "working_ptr":spec.working_expected,
        "translator_c":(
            f"void FUN_{spec.translator:08x}(void *param_1, void *param_2) {{"
            f"*(undefined1 *)(param_1 + 0x{spec.destination_offset:x})"
            f" = param_2[0x5b0];}}"
        ),
        "memcpy_c":(
            f"void FUN_{spec.commit:08x}(int param_1) {{"
            f"func_0x{spec.memcpy_stub:08x}"
            f"(0x{spec.active_base:x},param_1,0x{spec.bytes_copied:x});"
            f"func_0x{spec.memcpy_stub:08x}"
            f"(0x{spec.mirror_base:x},param_1,0x{spec.bytes_copied:x});}}"
        ),
        "parent_c": (
            f"void FUN_{spec.parent:08x}(void) {{"
            f"{spec.snapshot_arg} = DAT_{source:08x};"
            f"{spec.work_arg} = DAT_{working:08x};"
            f"FUN_{spec.translator:08x}(DAT_{working:08x},"
            f"{spec.snapshot_arg},1);"
            f"FUN_{spec.wrapper:08x}({spec.work_arg});}}"
        ),
        "wrapper_asm": (
            f"TRACE_INSN {spec.wrapper:08x} stmdb sp!,{{r4,lr}} (GhidraScript)\n"
            f"TRACE_INSN {spec.wrapper+4:08x} movw r4,#0x4321 (GhidraScript)\n"
            f"TRACE_INSN {spec.wrapper+8:08x} ldrb r5,[r4,#0x8] (GhidraScript)\n"
            f"TRACE_INSN {call:08x} bl 0x{spec.commit:08x} (GhidraScript)\n"
        ),
        "reverse_c":(
            f"void FUN_{spec.reverse_export:08x}(void *param_1) {{"
            f"param_1[0x5b0] = DAT_{spec.codec_byte:08x};}}"
        ),
        "getter_c":(
            f"undefined1 FUN_{spec.runtime_getter:08x}(void) {{"
            f"return DAT_{spec.codec_byte:08x};}}"
        )
    }


class BulkCommitTests(unittest.TestCase):
    def test_two_model_positive_path(self):
        for spec in SPECS:
            with self.subTest(model=spec.name):
                r=audit(spec,**synthetic(spec))
                self.assertEqual(r["active_mode_byte"],hex(spec.codec_byte))
                self.assertNotEqual(r["active_mode_byte"],
                                    hex(spec.e_mode_codec_byte))
                self.assertLess(spec.destination_offset,spec.bytes_copied)
                self.assertEqual(int(r["snapshot_mode_byte"],16),
                                 spec.snapshot_expected+0x5b0)
                self.assertFalse(r["HEVC_Main10_recording_verified"])

    def test_reject_source_pointer_not_same(self):
        s=SPECS[1]; data=synthetic(s)
        data["snapshot_ptr"]+=4
        with self.assertRaisesRegex(ValueError,"raw source"):
            audit(s,**data)

    def test_reject_different_working_pointer(self):
        s=SPECS[0]; data=synthetic(s)
        data["working_ptr"]+=0x100
        with self.assertRaisesRegex(ValueError,"intermediate working"):
            audit(s,**data)

    def test_reject_wrong_serialized_codec_field(self):
        s=SPECS[1];data=synthetic(s)
        data["translator_c"]=data["translator_c"].replace(
            "0x430","0x431")
        with self.assertRaisesRegex(ValueError,"snapshot"):
            audit(s,**data)

    def test_reject_wrong_snapshot_field(self):
        s=SPECS[0];data=synthetic(s)
        data["translator_c"]=data["translator_c"].replace(
            "0x5b0","0x5b1")
        with self.assertRaisesRegex(ValueError,"snapshot"):
            audit(s,**data)

    def test_reject_bulk_copy_too_short(self):
        s=SPECS[1];data=synthetic(s)
        data["memcpy_c"]=data["memcpy_c"].replace(
            "0x478","0x400")
        with self.assertRaisesRegex(ValueError,"bulk-copied"):
            audit(s,**data)

    def test_reject_parent_forwards_unrelated_context(self):
        s=SPECS[0];data=synthetic(s)
        data["parent_c"]=data["parent_c"].replace(
            f"FUN_{s.wrapper:08x}(iVar1)",
            f"FUN_{s.wrapper:08x}(iVar2)")
        with self.assertRaisesRegex(ValueError,"same working"):
            audit(s,**data)

    def test_reject_wrapper_that_clobbers_r0(self):
        s=SPECS[1];data=synthetic(s)
        data["wrapper_asm"]=data["wrapper_asm"].replace(
            f"TRACE_INSN {s.wrapper+8:08x} ldrb r5,",
            f"TRACE_INSN {s.wrapper+8:08x} ldrb r0,")
        with self.assertRaisesRegex(ValueError,"forwards original R0"):
            audit(s,**data)

    def test_reject_reverse_export_wrong_field(self):
        s=SPECS[1];data=synthetic(s)
        data["reverse_c"]=data["reverse_c"].replace(
            "param_1[0x5b0]","param_1[0x5b1]")
        with self.assertRaisesRegex(ValueError,"reverse exporter"):
            audit(s,**data)

    def test_reject_getter_reads_unrelated_byte(self):
        s=SPECS[0];data=synthetic(s)
        data["getter_c"]=data["getter_c"].replace(
            "DAT_01b83974","DAT_01b83975")
        with self.assertRaisesRegex(ValueError,"runtime getter"):
            audit(s,**data)

    def test_read_pointer_synthetic(self):
        b=bytearray(0x40)
        struct.pack_into("<I",b,0x20,0x9ABC1234)
        self.assertEqual(pointer_from_section(bytes(b),0x1000,0x1020),
                         0x9ABC1234)
        with self.assertRaisesRegex(ValueError,"not in aligned"):
            pointer_from_section(bytes(b),0x1000,0x1021)
        with self.assertRaisesRegex(ValueError,"not in aligned"):
            pointer_from_section(bytes(b),0x1000,0x2000)

    def test_extract_only_named_decomp_function(self):
        s="TRACE_DECOMP_BEGIN (GhidraScript)\nINFO x\nvoid FUN_012bd110(int p) {}\nTRACE_DECOMP_END (GhidraScript)"
        self.assertIn("FUN_012bd110",c_function(s,0x012bd110))
        with self.assertRaisesRegex(ValueError,"function body missing"):
            c_function(s,0x012bd111)


if __name__=="__main__":
    unittest.main()

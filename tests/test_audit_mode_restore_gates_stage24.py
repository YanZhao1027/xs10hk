"""Synthetic-only tests of stage24 X-S10 / X-T4 mode-restore differences.

No camera, no vendor firmware data. Synthetic ARM instructions + invented
decompiled function stubs model the observed cross-firmware call edges.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_mode_restore_gates_stage24 import (
    SPECS, A32_RESTORE_FINGERPRINT, audit, decode_arm_branch,
    decode_cond_ldrb, find_signature, read_word, get_decomp,
    function_references, check_branch,
)


BASE1 = 0x01021000


def arm_b(address, target, *, condition=14, link=True):
    offset = target - address - 8
    if offset % 4 or not -(1 << 25) <= offset < (1 << 25):
        raise ValueError("target not encodable as A32 B/BL")
    return ((condition << 28) | 0x0a000000 | (int(link) << 24)
            | ((offset >> 2) & 0x00ffffff))


def synthetic_decomp(entry: int, body: str) -> str:
    return ("INFO  TraceX6Function.java> TRACE_DECOMP_BEGIN (GhidraScript)\n"
            "void FUN_%08x(void) {\n%s\n}\n" % (entry, body)
            + "INFO  TraceX6Function.java> TRACE_DECOMP_END (GhidraScript)\n")


def fake_firmware(spec):
    s1 = bytearray(0x0118b79c - BASE1 + 4)
    last = max(spec.signature_addr + 0x1c, 0x02043b14 if spec.name == "xt4"
               else 0x020eb67c, 0x020583ac if spec.name == "xs10" else 0)
    s2 = bytearray(last - spec.section2_base + 4)
    off = spec.signature_addr - spec.section2_base
    s2[off:off+16] = A32_RESTORE_FINGERPRINT

    def pack(address, word):
        buf, base = ((s1, BASE1) if address < spec.section2_base
                     else (s2, spec.section2_base))
        struct.pack_into("<I", buf, address - base, word)

    suffix = (0x832, 0x831) if spec.name == "xt4" else (0x582, 0x581)
    pack(spec.signature_addr + 0x14, 0x05d30000 | suffix[0])
    pack(spec.signature_addr + 0x18, 0x15d30000 | suffix[1])
    if spec.name == "xt4":
        pack(0x0115f2d0, arm_b(0x0115f2d0, 0x0115b234))
        pack(0x02043b14, arm_b(0x02043b14, 0x0115b234))
    else:
        pack(0x020eb658, 0xe30830a0)
        pack(0x020eb668, arm_b(0x020eb668, 0x020eb688,
                               condition=0, link=False))
        pack(0x020eb67c, arm_b(0x020eb67c, 0x02058368))
        pack(0x020583ac, arm_b(0x020583ac, 0x0118b280))
        pack(0x0118b79c, arm_b(0x0118b79c, 0x01179dc0))
    return s1, s2


def fixture(spec):
    a, b = fake_firmware(spec)
    if spec.name == "xt4":
        main = (synthetic_decomp(spec.main_dispatcher,
                "  FUN_0114dab4(param_1);\n"
                "  if (*(char *)(DAT_0115f340 + 0x834) == 1) {\n"
                "     FUN_0115b234();\n  }")
                + synthetic_decomp(0x0115b234,
                "  use_setting(0x3e4);\n  use_setting(0x3e5);\n"
                "  FUN_0112fe18(uVar1 & 0xff);\n"
                "  FUN_0112fd80(uVar1 & 0xff);"))
        restore = synthetic_decomp(spec.restore_addr,
                                   "  FUN_0115b234();")
        helper = restore
        refs = ("PROBE_TARGET addr=0115b234 refs=2\n"
                "PROBE_REF from=0115f2d0 to=0115b234 type=UNCONDITIONAL_CALL\n"
                "PROBE_REF from=02043b14 to=0115b234 type=UNCONDITIONAL_CALL\n")
    else:
        main = synthetic_decomp(spec.main_dispatcher,
                                "  FUN_01179dc0(param_1);")
        restore = synthetic_decomp(spec.restore_addr,
                   "  if (DAT_01b880a0 != '-') {\n"
                   "    FUN_02058368(local_11[0]);\n  }")
        helper = synthetic_decomp(0x02058368,
                  "  FUN_0118b280(DAT_01b880a0,0x23);")
        refs = ("PROBE_TARGET addr=02058368 refs=1\n"
                "PROBE_REF from=020eb67c to=02058368 type=UNCONDITIONAL_CALL\n")
    return [a, b, main, restore, helper, refs]


class RawA32Tests(unittest.TestCase):
    def test_unique_signature(self):
        self.assertEqual(find_signature(A32_RESTORE_FINGERPRINT, 0x1000),
                         [0x1000])

    def test_multiple_signature_locations(self):
        d = A32_RESTORE_FINGERPRINT + bytes(8) + A32_RESTORE_FINGERPRINT
        self.assertEqual(find_signature(d, 0x1000), [0x1000, 0x1018])

    def test_missing_signature(self):
        self.assertEqual(find_signature(bytes(32), 0x1000), [])

    def test_branch_forward(self):
        insn=arm_b(0x1000, 0x2000)
        self.assertEqual(decode_arm_branch(insn, 0x1000), (14, True, 0x2000))

    def test_branch_backward(self):
        insn=arm_b(0x2000, 0x1000)
        self.assertEqual(decode_arm_branch(insn, 0x2000), (14, True, 0x1000))

    def test_conditional_skip(self):
        self.assertEqual(decode_arm_branch(
            arm_b(0x1000, 0x1020, condition=0, link=False), 0x1000),
            (0, False, 0x1020))

    def test_wrong_branch_opcode(self):
        with self.assertRaisesRegex(ValueError, "not A32"):
            decode_arm_branch(0xe3a00000, 0x1000)

    def test_unconditional_encoding_rejected(self):
        with self.assertRaisesRegex(ValueError, "not A32"):
            decode_arm_branch(0xfa000000, 0x1000)

    def test_out_of_range_target(self):
        with self.assertRaisesRegex(ValueError, "encodable"):
            arm_b(0x1000, 0x10000000)

    def test_word_outside_section(self):
        for addr in (0x0, 0x1001, 0x1004):
            with self.subTest(addr=addr), self.assertRaisesRegex(
                    ValueError, "unaligned/outside"):
                read_word(bytes(4), 0x1000, addr)

    def test_correct_conditional_ldrb(self):
        self.assertEqual(decode_cond_ldrb(0x05d30832), (0,3,0,0x832))
        self.assertEqual(decode_cond_ldrb(0x15d30581), (1,3,0,0x581))

    def test_wrong_ldrb_class(self):
        with self.assertRaisesRegex(ValueError, "family"):
            decode_cond_ldrb(0xe3a00000)

    def test_wrong_load_type(self):
        with self.assertRaisesRegex(ValueError, "LDRB"):
            decode_cond_ldrb(0x05c30832)

    def test_wrong_ldrb_writeback(self):
        with self.assertRaisesRegex(ValueError, "writeback"):
            decode_cond_ldrb(0x05f30832)

    def test_decompile_ignores_caller_reference(self):
        junk=synthetic_decomp(0x01000000, "FUN_0115b234();")
        real=synthetic_decomp(0x0115b234, "use_setting(0x3e5);")
        self.assertIn("use_setting", get_decomp(junk + real, 0x0115b234))

    def test_xref_exact_target(self):
        refs=fixture(SPECS["xt4"])[-1]
        self.assertEqual(function_references(refs,0x0115b234),
                         {0x0115f2d0,0x02043b14})


class AuditTests(unittest.TestCase):
    def test_two_synthetic_models_pass(self):
        for s in SPECS.values():
            with self.subTest(model=s.name):
                result=audit(s,*fixture(s))
                self.assertEqual(result["section2_fingerprint_matches"],1)
                self.assertTrue(result["paired_menu_initializer_present"])
                self.assertFalse(result["actual_h265_main10_recording_proven"])
                self.assertFalse(result["actual_4k60_sensor_capture_proven"])
                self.assertFalse(result["generated_firmware_patch"])

    def test_direct_reloader_only_xt4(self):
        self.assertTrue(audit(SPECS["xt4"],*fixture(SPECS["xt4"]))
                        ["direct_extra_codec_format_reload"])
        self.assertFalse(audit(SPECS["xs10"],*fixture(SPECS["xs10"]))
                         ["direct_extra_codec_format_reload"])

    def test_fingerprint_duplicate_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        args[1][200:216]=A32_RESTORE_FINGERPRINT
        with self.assertRaisesRegex(ValueError, "unique section2"):
            audit(spec,*args)

    def test_wrong_selection_byte_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        struct.pack_into("<I",args[1],spec.signature_addr+0x14-spec.section2_base,
                         0x05d30832)
        with self.assertRaisesRegex(ValueError, "movie-mode selection"):
            audit(spec,*args)

    def test_bad_restore_bl_target_fails(self):
        spec=SPECS["xt4"];args=fixture(spec)
        struct.pack_into("<I",args[1],0x02043b14-spec.section2_base,
                         arm_b(0x02043b14,0x0115b238))
        with self.assertRaisesRegex(ValueError, "branch at"):
            audit(spec,*args)

    def test_bad_xt4_extra_main_bl_fails(self):
        spec=SPECS["xt4"];args=fixture(spec)
        struct.pack_into("<I",args[0],0x0115f2d0-BASE1,
                         arm_b(0x0115f2d0,0x0115b238))
        with self.assertRaisesRegex(ValueError, "branch at"):
            audit(spec,*args)

    def test_extra_xt4_missing_setter_fails(self):
        spec=SPECS["xt4"];args=fixture(spec)
        args[2]=args[2].replace("FUN_0112fd80(uVar1 & 0xff)", "NO_CODEC()")
        with self.assertRaisesRegex(ValueError, "both setters"):
            audit(spec,*args)

    def test_missing_xt4_mode_flag_fails(self):
        spec=SPECS["xt4"];args=fixture(spec)
        args[2]=args[2].replace("DAT_0115f340 + 0x834","OTHER_FLAG")
        with self.assertRaisesRegex(ValueError, "reload flag"):
            audit(spec,*args)

    def test_xs10_skip_branch_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        struct.pack_into("<I",args[1],0x020eb668-spec.section2_base,
                         arm_b(0x020eb668,0x020eb688,
                               condition=1,link=False))
        with self.assertRaisesRegex(ValueError, "branch at"):
            audit(spec,*args)

    def test_xs10_helper_call_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        struct.pack_into("<I",args[1],0x020eb67c-spec.section2_base,
                         arm_b(0x020eb67c,0x0205836c))
        with self.assertRaisesRegex(ValueError, "branch at"):
            audit(spec,*args)

    def test_xs10_helper_to_main_missing_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        args[4]=args[4].replace("FUN_0118b280(DAT_01b880a0,0x23)",
                                "OTHER_FUNCTION()")
        with self.assertRaisesRegex(ValueError, "not invoking main"):
            audit(spec,*args)

    def test_xs10_main_menu_initializer_missing_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        args[2]=args[2].replace("FUN_01179dc0(param_1)","OTHER_FUNCTION()")
        with self.assertRaisesRegex(ValueError, "menu initializer"):
            audit(spec,*args)

    def test_xs10_alternative_conditional_missing_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        args[3]=args[3].replace("if (DAT_01b880a0 != '-')",
                                "if (DAT_01b880a0 == '-')")
        with self.assertRaisesRegex(ValueError, "conditional nonmovie"):
            audit(spec,*args)

    def test_missing_verified_xrefs_fails(self):
        spec=SPECS["xs10"];args=fixture(spec)
        args[-1] = args[-1].replace("from=020eb67c","from=020eb680")
        with self.assertRaisesRegex(ValueError, "not Ghidra verified"):
            audit(spec,*args)

    def test_zero_xrefs_fails(self):
        with self.assertRaisesRegex(ValueError, "missing Ghidra xref"):
            function_references("", 0x0115b234)

    def test_output_does_not_claim_missing_all_paths(self):
        result=audit(SPECS["xs10"],*fixture(SPECS["xs10"]))
        self.assertFalse(result["additional_codec_format_reload_elsewhere_ruled_out"])
        self.assertFalse(result["gui_to_recorder_snapshot_proven"])


if __name__ == "__main__":
    unittest.main()

"""Synthetic-only verification of A32 codec/format pair auditing.

No vendor code, USB, camera, fixture ROM, or flash operation.
"""
from dataclasses import replace
from pathlib import Path
from unittest import TestCase, main, mock
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_codec_format_pair_stage23 import (
    SPECS, Site, a32_byte_immediate, audit, check_site,
    decompiled, get_refs, reported_combined_cases,
)


def encode_byte(*, load=True, rn=3, rd=4, offset=0x5b0,
                writeback=False, byte=True, positive=True, pre=True) -> int:
    return (0xe0000000 | 0x04000000 | (int(pre) << 24) |
            (int(positive) << 23) | (int(byte) << 22) |
            (int(writeback) << 21) | (int(load) << 20) |
            (rn << 16) | (rd << 12) | offset)


def wrapped(name, body):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
            "void FUN_%08x(uint param_1) {\n%s\n}\n" %
            (name, body) + "TRACE_DECOMP_END (GhidraScript)\n")


def fixture(spec):
    c, f = spec.settings_base + 0x5b0, spec.settings_base + 0x5b1
    converter = 0x0102300c if spec.model == "xs10" else 0x01022f7c
    low = wrapped(spec.codec_setter,
                  "  eModeMovieCodec;\n  DAT_%08x = (char)param_1;" % c)
    high = wrapped(spec.format_setter,
                   "  eModeMovieFormat;\n  DAT_%08x = (char)param_1;" % f)
    boot = wrapped(spec.boot_pair,
                   "  use_setting(0x%x); use_setting(0x%x);\n"
                   "  FUN_%08x(uVar2 & 0xff);\n  FUN_%08x(uVar2 & 0xff);" %
                   (spec.format_id, spec.codec_id,
                    spec.format_setter, spec.codec_setter))
    cases = (1, 0, 0x101, 0x100)
    mapping = {1: 0, 0: 1, 0x101: 2, 0x100: 3}
    export = ("  uVar1 = FUN_%08x(0x%x,DAT_%08x,3,0);\n"
              "  param_1[0x90] = uVar1;\n" %
              (converter, spec.ui_export_id, c))
    for value in cases:
        export += ("  if (_DAT_%08x == %s) {\n"
                   "    param_1[0xa1] = %d;\n  }\n" %
                   (c, hex(value) if value > 1 else str(value), mapping[value]))
    extra = ""
    if spec.model == "xt4":
        extra = wrapped(0x0115b234,
                        " use_setting(0x3e4); use_setting(0x3e5);\n"
                        " FUN_%08x(uVar1 & 0xff);\n"
                        " FUN_%08x(uVar1 & 0xff);" %
                        (spec.format_setter, spec.codec_setter))
    readers = low + wrapped(spec.ui_exporter, export)
    highlog = high + boot + extra
    xr = ("PROBE_TARGET addr=%08x refs=%d\n"
          "PROBE_TARGET addr=%08x refs=%d\n" %
          (spec.codec_setter, 3 if spec.model == "xs10" else 4,
           spec.format_setter, 2 if spec.model == "xs10" else 3))
    return [readers, highlog, xr]


def run_audit(spec, parts=None):
    parts = parts or fixture(spec)
    with mock.patch("audit_codec_format_pair_stage23.check_site", return_value=1):
        return audit(spec, b"", b"", *parts)


class A32Tests(TestCase):
    def test_ldr_strb_register_offsets(self):
        self.assertEqual(a32_byte_immediate(encode_byte(load=False)),
                         (False, 3, 4, 0x5b0, False))
        self.assertEqual(a32_byte_immediate(
            encode_byte(load=True, rn=5, rd=1, writeback=True)),
            (True, 5, 1, 0x5b0, True))

    def test_wrong_opcode_family_rejected(self):
        with self.assertRaisesRegex(ValueError, "immediate"):
            a32_byte_immediate(0xe1a03000)

    def test_nonbyte_opcode_rejected(self):
        with self.assertRaisesRegex(ValueError, "byte"):
            a32_byte_immediate(encode_byte(byte=False))

    def test_negative_offset_rejected(self):
        with self.assertRaisesRegex(ValueError, "byte"):
            a32_byte_immediate(encode_byte(positive=False))

    def test_postindexed_rejected(self):
        with self.assertRaisesRegex(ValueError, "byte"):
            a32_byte_immediate(encode_byte(pre=False))

    def test_correct_synthetic_site(self):
        s = Site(1, 0x01021000, True, 3, 4, 0x5b0)
        dat = struct.pack("<I", encode_byte())
        self.assertEqual(check_site(s, dat, b"", 0x02000000),
                         encode_byte())

    def test_wrong_immediate_rejected(self):
        s = Site(1, 0x01021000, True, 3, 4, 0x5b1)
        with self.assertRaisesRegex(ValueError, "incorrect ARM site"):
            check_site(s, struct.pack("<I", encode_byte()), b"", 0)

    def test_misaligned_or_truncated_site_rejected(self):
        for addr in (0x01021002, 0x01021004):
            with self.subTest(addr=addr), self.assertRaisesRegex(
                    ValueError, "outside aligned"):
                check_site(Site(1, addr, True, 3, 4, 0x5b0),
                           b"\0\0\0\0", b"", 0)

    def test_only_function_definition_is_selected(self):
        different = wrapped(0x01000000, "FUN_0112fe18(1);")
        desired = wrapped(0x0112fe18, "DAT_01af2db9 = (char)param_1;")
        self.assertIn("DAT_01af2db9", decompiled(different+desired, 0x0112fe18))

    def test_unknown_function_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing decompiled"):
            decompiled(wrapped(0x01000000, ""), 0x0112fe18)


class CodecFormatTests(TestCase):
    def test_two_model_positive(self):
        for spec in SPECS:
            with self.subTest(model=spec.model):
                result = run_audit(spec)
                self.assertEqual(result["a32_byte_sites_verified"], 5)
                self.assertEqual(result["composite_ui_cases"]["0x101"], 2)
                self.assertFalse(result["frontend_to_recorder_snapshot_proven"])
                self.assertFalse(result["internal_hevc_main10_proven"])
                self.assertNotEqual(result["codec_gui_address"],
                                    result["recorder_snapshot_codec_address"])

    def test_two_byte_mapping_complete(self):
        for spec in SPECS:
            c = spec.settings_base+0x5b0
            writer = decompiled(fixture(spec)[0], spec.ui_exporter)
            self.assertEqual(reported_combined_cases(writer, c),
                             {1:0, 0:1, 0x101:2, 0x100:3})

    def test_codec_setter_absent_fails(self):
        s=SPECS[0]; parts=fixture(s)
        parts[0]=parts[0].replace("DAT_%08x = (char)param_1;" %
                                  (s.settings_base+0x5b0), "unused;")
        with self.assertRaisesRegex(ValueError, "low-byte"):
            run_audit(s, parts)

    def test_format_setter_absent_fails(self):
        s=SPECS[0]; parts=fixture(s)
        parts[1]=parts[1].replace("DAT_%08x = (char)param_1;" %
                                  (s.settings_base+0x5b1), "unused;")
        with self.assertRaisesRegex(ValueError, "high-byte"):
            run_audit(s, parts)

    def test_missing_initializer_pair_fails(self):
        s=SPECS[0]; parts=fixture(s)
        parts[1]=parts[1].replace("FUN_%08x(uVar2 & 0xff)" %
                                  s.format_setter, "removed()")
        with self.assertRaisesRegex(ValueError, "initialization"):
            run_audit(s, parts)

    def test_bad_exporter_setting_id_fails(self):
        s=SPECS[0]; parts=fixture(s)
        parts[0]=parts[0].replace("0x3fa,DAT_", "0x3fc,DAT_")
        with self.assertRaisesRegex(ValueError, "serializer"):
            run_audit(s, parts)

    def test_bad_composite_value_fails(self):
        s=SPECS[1]; parts=fixture(s)
        parts[0]=parts[0].replace("param_1[0xa1] = 2;",
                                  "param_1[0xa1] = 3;")
        with self.assertRaisesRegex(ValueError, "composite"):
            run_audit(s, parts)

    def test_missing_xt4_special_mode_path_fails(self):
        s=SPECS[1]; parts=fixture(s)
        prefix, marker, suffix = parts[1].rpartition("use_setting(0x3e5)")
        parts[1] = prefix + "use_setting(0x0)" + suffix
        with self.assertRaisesRegex(ValueError, "loader settings"):
            run_audit(s, parts)

    def test_unknown_xref_fails(self):
        s=SPECS[0]; parts=fixture(s)
        parts[2]="missing xrefs"
        with self.assertRaisesRegex(ValueError, "missing Ghidra xrefs"):
            run_audit(s, parts)

    def test_too_few_xrefs_fails(self):
        s=SPECS[0]; parts=fixture(s)
        parts[2]=parts[2].replace("refs=2", "refs=1")
        with self.assertRaisesRegex(ValueError, "unexpectedly small"):
            run_audit(s, parts)


if __name__ == "__main__":
    main()

"""Synthetic tests for Ghidra HEVC Q16.16 and builder-metadata audit."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from audit_hevc_recorder_builder import (
    audit_builder, assignment_constants, decode_q16_fps, MODELS
)


class HEVCBuilderAuditTests(unittest.TestCase):
    @staticmethod
    def fake_source(model, mode_values=(1, 3)):
        base, wrapper = MODELS[model]
        lines = [f"func_0x{wrapper:08x}(&DAT_{base:08x},handler);"]
        lines.extend(f"_DAT_{base+8:08x} = 0x{f:x};" for f in (
            0x17FAE1, 0x180000, 0x190000, 0x1DF851,
            0x320000, 0x3BF0A3))
        lines.extend(f"_DAT_{base+12:08x} = {v};" for v in mode_values)
        return "\n".join(lines)

    def test_q16_fps_values(self):
        self.assertAlmostEqual(decode_q16_fps(0x3BF0A3), 59.94, places=3)
        self.assertAlmostEqual(decode_q16_fps(0x1DF851), 29.97, places=3)
        self.assertEqual(decode_q16_fps(0x180000), 24.0)
        with self.assertRaises(ValueError):
            decode_q16_fps(-1)

    def test_all_synthetic_known_builders(self):
        for model in MODELS:
            with self.subTest(model=model):
                values = (3,) if model == "xs10" else (1, 3)
                result = audit_builder(self.fake_source(
                    model, mode_values=values), model)
                self.assertEqual(len(result["input_2_q16_fps_raw"]), 6)
                self.assertIn(59.94, [round(x, 2)
                                      for x in result["input_2_fps_interpreted"]])
                self.assertEqual(result["input_3_values_observed"], list(values))

    def test_reject_missing_cross_segment_call(self):
        with self.assertRaisesRegex(ValueError, "wrapper call"):
            audit_builder(self.fake_source("xs10").replace(
                "func_0x011f745c", "func_0x011f0000"), "xs10")

    def test_reject_missing_fps_assignments(self):
        code = self.fake_source("xt3")
        base, _ = MODELS["xt3"]
        code = "\n".join(line for line in code.splitlines()
                         if f"_DAT_{base+8:08x}" not in line)
        with self.assertRaisesRegex(ValueError, "FPS values"):
            audit_builder(code, "xt3")

    def test_no_false_assignment_matches(self):
        source = "_DAT_00000124 = 0x180000;\n_DAT_00000120 = 0x190000;\n"
        self.assertEqual(assignment_constants(source, 0x124), [0x180000])
        self.assertEqual(assignment_constants(source, 0x120), [0x190000])


if __name__ == "__main__":
    unittest.main()

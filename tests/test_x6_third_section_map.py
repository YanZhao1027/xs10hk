"""Synthetic-only tests for section-3 local ARM mapping inference."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from x6_third_section_map import analyze, decode_arm_bl, is_arm_push


def fake_good():
    base = 0x398A118
    out = bytearray(0x100)
    struct.pack_into("<4I", out, 0, base+8, 0, 0xE92D4800, 0xE28DB004)
    call_site = base + 0x80
    target = base + 0xA0
    imm24 = ((target - call_site - 8) // 4) & 0xFFFFFF
    struct.pack_into("<I", out, 0x80, 0xEB000000 | imm24)
    struct.pack_into("<I", out, 0xA0, 0xE92D4FF0)
    return bytes(out)


class AdditionalX6ARMTests(unittest.TestCase):
    def test_entry_and_local_branch(self):
        result = analyze(fake_good())
        self.assertEqual(result["candidate_load_base"], 0x398A118)
        self.assertEqual(result["candidate_entry"], 0x398A120)
        self.assertEqual(result["inner_call_site"], 0x398A198)
        self.assertEqual(result["inner_call_target"], 0x398A1B8)

    def test_reject_bad_entry(self):
        data = bytearray(fake_good())
        data[0] = 0
        # base=old+0x120 -> now out of RAM region but still plausibly aligned
        # so specifically corrupt prologue to assert strict validation.
        data[8] = 0
        with self.assertRaisesRegex(ValueError, "entry metadata"):
            analyze(bytes(data))

    def test_reject_bad_branch(self):
        data = bytearray(fake_good())
        struct.pack_into("<I", data, 0x80, 0xEA000006)
        with self.assertRaisesRegex(ValueError, "branch-with-link"):
            analyze(bytes(data))

    def test_reject_bad_bl_target(self):
        data = bytearray(fake_good())
        struct.pack_into("<I", data, 0xA0, 0)
        with self.assertRaisesRegex(ValueError, "prologue"):
            analyze(bytes(data))

    def test_bl_backward_sign_extension(self):
        site = 0x2000
        dest = 0x1800
        code = 0xEB000000 | (((dest - site - 8) // 4) & 0xFFFFFF)
        self.assertEqual(decode_arm_bl(code, site), dest)
        self.assertFalse(is_arm_push(0xE1A00000))
        self.assertTrue(is_arm_push(0xE92D4800))


if __name__ == "__main__":
    unittest.main()

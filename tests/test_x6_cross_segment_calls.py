"""Synthetic-only ARM32 BL decoder tests; no proprietary firmware."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from x6_cross_segment_calls import (
    a32_bl_target, find_direct_bl_calls, analyze_model, MODEL_BASES,
)


def encode_bl(pc, target):
    diff = target - (pc + 8)
    assert diff % 4 == 0
    assert -(1 << 25) <= diff < (1 << 25)
    return 0xEB000000 | ((diff // 4) & 0xFFFFFF)


class ARMBlTests(unittest.TestCase):
    def test_backward_bl(self):
        pc, target = 0x2200000, 0x11F745C
        word = encode_bl(pc, target)
        self.assertEqual(a32_bl_target(word, pc), target)

    def test_forward_bl(self):
        pc, target = 0x1001000, 0x1002000
        self.assertEqual(a32_bl_target(encode_bl(pc, target), pc), target)

    def test_not_bl_instruction(self):
        self.assertIsNone(a32_bl_target(0xEA000002, 0x100000))
        self.assertIsNone(a32_bl_target(0xFA000002, 0x100000))
        self.assertIsNone(a32_bl_target(0xE92D4800, 0x100000))

    def test_bl_scan_exact_target(self):
        base = 0x2200000
        target = 0x11F745C
        data = bytearray(16)
        struct.pack_into("<I", data, 8, encode_bl(base + 8, target))
        self.assertEqual(
            find_direct_bl_calls(bytes(data), section2_base=base,
                                 target=target), [base + 8])

    def test_validate_loader_bases_and_call(self):
        base1, base2, target = MODEL_BASES["xs10"]
        sec1 = bytearray(4096)
        sec2 = bytearray(4096)
        struct.pack_into("<8I", sec1, 0, 0, base1, 4096,
                         base1 + 32, 0, 0, 0, 0xAAAAFFFF)
        struct.pack_into("<8I", sec2, 0, 0, base2, 4096,
                         base2 + 32, 0, 0, 0, 0xAAAAFFFF)
        # This sample's 4-KiB section1 cannot cover the real target.
        with self.assertRaisesRegex(ValueError, "outside section 1"):
            analyze_model("xs10", bytes(sec1), bytes(sec2))

    def test_wrong_loader_base(self):
        base1, base2, target = MODEL_BASES["xs10"]
        sec1 = bytearray(4096)
        sec2 = bytearray(4096)
        struct.pack_into("<8I", sec1, 0, 0, 0xAAAAAAAA,
                         4096, 16, 0, 0, 0, 0xAAAAFFFF)
        struct.pack_into("<8I", sec2, 0, 0, base2,
                         4096, 16, 0, 0, 0, 0xAAAAFFFF)
        with self.assertRaisesRegex(ValueError, "loader base"):
            analyze_model("xs10", bytes(sec1), bytes(sec2))


if __name__ == "__main__":
    unittest.main()

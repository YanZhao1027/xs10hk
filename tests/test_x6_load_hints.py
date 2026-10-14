"""Tests for a probable X6 loader stub header, using fake ARM bytes only."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from x6_load_hints import interpret_loader_header


class LoaderHintTests(unittest.TestCase):
    @staticmethod
    def example():
        binary = bytearray(0x2147)
        base = 0x01021000
        ptr = base + 0x100
        struct.pack_into("<8I", binary, 0, 0, base, 0x3000,
                         ptr, 0, 0, 0, 0xAAAAFFFF)
        struct.pack_into("<2I", binary, 0x100, 0xE92D4810, 0xE28DB008)
        return binary

    def test_header_and_entry(self):
        result = interpret_loader_header(bytes(self.example()))
        self.assertEqual(result["base_candidate"], 0x01021000)
        self.assertEqual(result["mapped_size_candidate"], 0x3000)
        self.assertEqual(result["entry_file_offset"], 0x100)
        self.assertTrue(result["arm_prologue_at_entry"])

    def test_corrupt_header_rejected(self):
        binary = self.example()
        binary[28:32] = b"\x00" * 4
        with self.assertRaisesRegex(ValueError, "signature absent"):
            interpret_loader_header(bytes(binary))

    def test_bad_extent_rejected(self):
        binary = self.example()
        struct.pack_into("<I", binary, 8, 0x8000)
        with self.assertRaisesRegex(ValueError, "alignment"):
            interpret_loader_header(bytes(binary))

    def test_out_of_bounds_entry_rejected(self):
        binary = self.example()
        struct.pack_into("<I", binary, 12, 0x01231000)
        with self.assertRaisesRegex(ValueError, "outside"):
            interpret_loader_header(bytes(binary))

    def test_no_arm_code_detected(self):
        binary = self.example()
        struct.pack_into("<2I", binary, 0x100, 0, 0)
        result = interpret_loader_header(bytes(binary))
        self.assertFalse(result["arm_prologue_at_entry"])


if __name__ == "__main__":
    unittest.main()

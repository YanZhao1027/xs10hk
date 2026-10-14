"""Synthetic-only tests for X6 packed length and unknown checksum schemes."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from package_invariants import verify_packed_extents, simple_checksum_candidates


def make_x6_region():
    data = bytearray(0x60000)
    struct.pack_into("<5I", data, 0x20060, 0x30000, 0x18000, 0x12,
                     0x4000, 4)
    return data


class PackageInvariantsTests(unittest.TestCase):
    def test_segment_is_followed_by_zeros(self):
        rows = verify_packed_extents(bytes(make_x6_region()))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["header_offset"], 0x20060)
        self.assertEqual(rows[0]["predicted_end"], 0x38074)
        self.assertEqual(rows[0]["padded_to"], 0x40000)
        self.assertTrue(rows[0]["padding_all_zero"])

    def test_reject_nonzero_tail_as_padding(self):
        data = make_x6_region()
        data[0x3A000] = 1
        rows = verify_packed_extents(data)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["padding_all_zero"])

    def test_empty_image(self):
        self.assertEqual(verify_packed_extents(b""), [])

    def test_checksum_hypotheses_are_not_assumed_correct(self):
        dat = bytearray(2048)
        struct.pack_into("<I", dat, 0, 6)
        struct.pack_into("<4I", dat, 516, 3, 17, 0xF00D, 2)
        field, candidates = simple_checksum_candidates(bytes(dat))
        self.assertEqual(field, 0xF00D)
        self.assertFalse(field in candidates.values())


if __name__ == "__main__":
    unittest.main()

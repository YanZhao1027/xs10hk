"""Synthetic-only validation of the 64-byte Fuji recorder LUT reader."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from compare_recorder_tables import (
    ModelLayout, ROW_BYTES, FPS_ENUM, read_at_virt, parse_rows,
    audit_one, compare_models,
)


TEST_LAYOUT = ModelLayout(
    segment1_base=0x10000, segment2_base=0x20000,
    matrix_width=0x10100, matrix_height=0x10200,
    recorder_table=0x20040,
)


def make_samples(*, mismatch=False):
    s1 = bytearray(0x500)
    s2 = bytearray(0x500)
    dims = {
        (7, 4): (4096, 2160),
        (7, 2): (3840, 2160),
        (6, 4): (2048, 1080),
        (6, 2): (1920, 1080),
    }
    for (a, b), (w, h) in dims.items():
        offset = (a * 5 + b) * 4
        struct.pack_into("<I", s1, TEST_LAYOUT.matrix_width - 0x10000 + offset, w)
        struct.pack_into("<I", s1, TEST_LAYOUT.matrix_height - 0x10000 + offset, h)
    for i, (family, subtype, fps) in enumerate([
        (7, 7, 6), (7, 2, 6), (6, 2, 4), (6, 7, 2)
    ]):
        where = 0x40 + i * ROW_BYTES
        struct.pack_into("<BHBB", s2, where,
                         0, family | (subtype << 8), fps, i)
    s2[0x40 + 4*ROW_BYTES] = 0xFF
    if mismatch:
        s2[0x40 + ROW_BYTES + 20] = 1
    return bytes(s1), bytes(s2)


class RecorderLUTTests(unittest.TestCase):
    def test_parse_synthetic_four_rows(self):
        s1, s2 = make_samples()
        rows, b = parse_rows(s2, TEST_LAYOUT)
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(b), 4*ROW_BYTES)
        self.assertEqual(rows[0][3], 6)
        self.assertEqual(rows[1][1:3], bytes((7, 2)))

    def test_decode_width_height_and_frame_codes(self):
        s1, s2 = make_samples()
        out = audit_one("test", s1, s2, {"test": TEST_LAYOUT})
        self.assertEqual(out["rows"], 4)
        self.assertEqual(out["4k_5994_record_count"], 2)
        self.assertEqual(out["combinations"][(4096, 2160, 6)], 1)
        self.assertEqual(out["combinations"][(3840, 2160, 6)], 1)
        self.assertEqual(out["combinations"][(1920, 1080, 4)], 1)
        self.assertEqual(set(FPS_ENUM), set(range(1, 7)))

    def test_identical_rows_for_two_names(self):
        s1, s2 = make_samples()
        a = audit_one("a", s1, s2, {"a": TEST_LAYOUT})
        b = audit_one("b", s1, s2, {"b": TEST_LAYOUT})
        self.assertEqual(a["sha256_table_rows"], b["sha256_table_rows"])

    def test_one_byte_change_alters_table_hash_not_dimensions(self):
        s1, s2 = make_samples()
        _, other = make_samples(mismatch=True)
        a = audit_one("a", s1, s2, {"a": TEST_LAYOUT})
        b = audit_one("b", s1, other, {"b": TEST_LAYOUT})
        self.assertNotEqual(a["sha256_table_rows"], b["sha256_table_rows"])
        self.assertEqual(a["combinations"], b["combinations"])

    def test_duplicate_key_rejected(self):
        s1, s2 = make_samples()
        d = bytearray(s2)
        d[0x40+ROW_BYTES:0x40+ROW_BYTES+5] = d[0x40:0x40+5]
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_rows(bytes(d), TEST_LAYOUT)

    def test_missing_sentinel_rejected(self):
        _, s2 = make_samples()
        # Truncate just before sentinel: any complete 64-byte table row
        # must now be out of bounds before the sentinel could be read.
        before_sentinel = s2[:0x40 + 4*ROW_BYTES]
        with self.assertRaisesRegex(ValueError, "sentinel"):
            parse_rows(before_sentinel, TEST_LAYOUT)

    def test_out_of_range_rejected(self):
        with self.assertRaisesRegex(ValueError, "Out-of-range"):
            read_at_virt(b"abc", 0x100, 0x400, 2)
        with self.assertRaisesRegex(ValueError, "Out-of-range"):
            read_at_virt(b"abc", 0x100, 0x0FF, 1)

    def test_not_an_unlocker(self):
        """The only product is static table metadata; no data patching."""
        s1, s2 = make_samples()
        s1_before, s2_before = s1[:], s2[:]
        audit_one("test", s1, s2, {"test": TEST_LAYOUT})
        self.assertEqual(s1, s1_before)
        self.assertEqual(s2, s2_before)


if __name__ == "__main__":
    unittest.main()

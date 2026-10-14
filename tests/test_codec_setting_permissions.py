"""Unit tests for Fujifilm movie-codec permission matrix parser.

All test bytes are entirely synthetic, NOT copied from Fujifilm firmware.
"""
import pathlib
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from codec_setting_permissions import (
    ModelLayout, LAYOUTS, SENTINEL, parse_categories, parse_group_index,
    parse_options, analyze, allowed, preferred,
)


def fake_model(ncategories, *, key=0x3FC, flag1=1):
    cats = list(range(1, ncategories))
    # This caller category must be last and cannot be index 0.
    cats.append(0x2D)
    # The real X6 category terminator is 0x2E.
    base, cataddr, graddr, valaddr = 0x1000, 0x1100, 0x1200, 0x1300
    b = bytearray(0x900)
    b[cataddr-base:cataddr-base+len(cats)+1] = bytes(cats+[0x2E])
    struct.pack_into("<II", b, graddr-base, key, valaddr)
    struct.pack_into("<II", b, graddr-base+8, 0, 0)
    stride = 4 + ((len(cats)+3)//4)*4
    offset = valaddr-base
    struct.pack_into("<I", b, offset, 0)
    b[offset+4:offset+4+len(cats)] = bytes([2] * len(cats))
    struct.pack_into("<I", b, offset+stride, 1)
    b[offset+stride+4+len(cats)-1] = flag1
    struct.pack_into("<I", b, offset+stride*2, SENTINEL)
    layout = ModelLayout(base,cataddr,graddr,key,0x3FB)
    return bytes(b), layout


class CodecPermissionsTests(unittest.TestCase):
    def test_xt4_style_categories(self):
        blob, layout = fake_model(9)
        cats, opts, stride, addr = parse_options(blob, layout, 0x3FC)
        self.assertEqual((len(cats), stride, addr), (9, 16, 0x1300))
        self.assertEqual(opts[0][-1], 2)
        self.assertEqual(opts[1][-1], 1)
        self.assertTrue(allowed(opts[1][-1]))
        self.assertFalse(allowed(opts[1][0]))

    def test_xs10_style_categories(self):
        blob, layout = fake_model(24)
        cats, opts, stride, _ = parse_options(blob, layout, 0x3FC)
        self.assertEqual((len(cats), stride), (24, 28))
        self.assertEqual(opts[0][-1], 2)
        self.assertEqual(opts[1][-1], 1)
        self.assertEqual(sum(x != 0 for x in opts[1][:-1]), 0)
        with patch.dict(LAYOUTS, {"test": layout}):
            result = analyze(blob, "test")
        self.assertTrue(result["option_flags"][1]["passes_generic_validation"])
        self.assertFalse(result["option_flags"][1]["is_generic_fallback"])
        self.assertTrue(result["option_flags"][0]["is_generic_fallback"])

    def test_disallowed_h265(self):
        blob, layout = fake_model(24, flag1=0)
        with patch.dict(LAYOUTS, {"test": layout}):
            result = analyze(blob, "test")
        self.assertFalse(result["option_flags"][1]["passes_generic_validation"])

    def test_group_index(self):
        blob, layout = fake_model(9)
        idx = parse_group_index(blob, layout)
        self.assertEqual(idx[0x3FC], (0x1300, 0))

    def test_missing_index_pointer(self):
        blob, layout = fake_model(9)
        b = bytearray(blob)
        struct.pack_into("<II", b, 0x200, 0x3FC, 0xDEADBEEF)
        with self.assertRaisesRegex(ValueError, "out of range"):
            parse_group_index(bytes(b), layout)

    def test_missing_option_sentinel(self):
        blob, layout = fake_model(9)
        with self.assertRaisesRegex(ValueError, "Missing memory"):
            parse_options(blob[:0x320], layout, 0x3FC)

    def test_modes_and_flags(self):
        self.assertTrue(allowed(1))
        self.assertTrue(allowed(2))
        self.assertTrue(allowed(3))
        self.assertTrue(allowed(4))
        self.assertFalse(allowed(0))
        self.assertFalse(allowed(5))
        self.assertTrue(preferred(2))
        self.assertTrue(preferred(4))
        self.assertFalse(preferred(1))
        with self.assertRaises(ValueError):
            allowed(256)

    def test_category_duplicate_rejected(self):
        blob, layout = fake_model(9)
        b = bytearray(blob)
        b[0x101] = b[0x100]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_categories(bytes(b), layout)


if __name__ == "__main__":
    unittest.main()

"""Synthetic-only tests for decoded movie lookup table comparisons."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from compare_video_resources import (
    XS10_SECTION2_BASE, XT4_SECTION2_BASE,
    ResourceFormatError, parse_registry, fileformat_resource_ids,
    compare,
)


def sample_registry(base, *, change_id=False):
    data = bytearray(0x1000)
    strings = (
        b"UI_MOVIE_MODE_4K_59_94P_400M_16_9",
        b"UI_MOVIE_CODEC_H265",
        b"UI_MOVIE_CODEC_H264",
    )
    for i, token in enumerate(strings):
        name_at = 0x400 + 0x80 * i
        ptr_at = 0x100 + 8 * i
        data[name_at:name_at+len(token)+1] = token + b"\x00"
        numeric_id = (1 if change_id else 0) if i == 0 else i-1
        struct.pack_into("<II", data, ptr_at, base+name_at, numeric_id)
    return bytes(data)


class VideoResourcesTests(unittest.TestCase):
    def test_movie_and_codec_lookup(self):
        data = sample_registry(XS10_SECTION2_BASE)
        found = parse_registry(data, XS10_SECTION2_BASE)
        self.assertEqual(found["UI_MOVIE_MODE_4K_59_94P_400M_16_9"], 0)
        self.assertEqual(found["UI_MOVIE_CODEC_H265"], 0)
        self.assertEqual(found["UI_MOVIE_CODEC_H264"], 1)

    def test_parse_rejects_pointer_missing(self):
        with self.assertRaisesRegex(ResourceFormatError, "expected one"):
            parse_registry(sample_registry(XS10_SECTION2_BASE),
                           XT4_SECTION2_BASE)

    def test_fileformat_menu_resource_diff(self):
        a = b"MSG_COMMENT_FILEFORMAT_MOVH264IIII2\x00OTHER_foo\x00"
        b = b"MSG_VALS_TITLE_FILEFORMAT_MOVH265\x00"
        self.assertEqual(fileformat_resource_ids(a),
                         {"MSG_COMMENT_FILEFORMAT_MOVH264IIII2"})
        self.assertEqual(fileformat_resource_ids(b),
                         {"MSG_VALS_TITLE_FILEFORMAT_MOVH265"})

    def test_compare_same_mode_names_but_id_diffs(self):
        a = sample_registry(XS10_SECTION2_BASE)
        b = sample_registry(XT4_SECTION2_BASE, change_id=True)
        result = compare(
            b"MSG_COMMENT_FILEFORMAT_MOVH264IIII2\x00", a,
            b"MSG_VALS_TITLE_FILEFORMAT_MOVH265\x00", b)
        self.assertEqual(result["xs_mode_count"], 1)
        self.assertEqual(result["xt_mode_count"], 1)
        self.assertEqual(result["mode_4k5994_counts"], (1, 1))
        self.assertEqual(result["mode_id_mismatches"],
                         {"UI_MOVIE_MODE_4K_59_94P_400M_16_9": (0, 1)})
        self.assertIn("MSG_VALS_TITLE_FILEFORMAT_MOVH265",
                      result["fileformat_xt_only"])
        self.assertIn("MSG_COMMENT_FILEFORMAT_MOVH264IIII2",
                      result["fileformat_xs_only"])


if __name__ == "__main__":
    unittest.main()

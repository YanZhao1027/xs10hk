import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from compare_codecs import compare


class CodecCompareTests(unittest.TestCase):
    def test_identical_shifted_block(self):
        left = bytes(range(64))
        right = b"!" * 8 + left
        result = compare(left, right, 4, 20, 8)
        self.assertEqual(result["mismatch_bytes"], 0)
        self.assertEqual(result["equal_pct"], 100.0)
        self.assertEqual(result["sha256_xt4"], result["sha256_xs10"])

    def test_one_byte_changed(self):
        left = b"abcdefgh"
        right = b"abcxefgh"
        result = compare(left, right, 0, 8, 0)
        self.assertEqual(result["mismatch_bytes"], 1)
        self.assertEqual(result["first_diff"], "0x3")

    def test_outside_file_rejected(self):
        with self.assertRaises(ValueError):
            compare(b"abcdef", b"abc", 0, 6, 0)


if __name__ == "__main__":
    unittest.main()

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from align_images import find_matches, interesting


class AlignmentTests(unittest.TestCase):
    def test_trivial_data_excluded(self):
        self.assertFalse(interesting(bytes(4096)))
        self.assertFalse(interesting(bytes([255]) * 4096))
        self.assertTrue(interesting(bytes(range(256)) * 16))

    def test_shifted_match(self):
        block = bytes(range(256))
        head = b"w" * 4096
        left = head + block * 16 * 4 + bytes([1]) * 4096
        right = bytes([2]) * 4096 * 3 + block * 16 * 4
        runs = find_matches(left, right, 4096, 16384)
        self.assertTrue(any(r["delta"] == 8192 and r["length"] >= 16384 for r in runs))

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            find_matches(b"1234", b"1234", 0)

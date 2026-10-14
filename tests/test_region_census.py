import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from region_census import regions, classify


class RegionTests(unittest.TestCase):
    def test_extents(self):
        binary = bytes([255]) * 8192 + bytes(range(256)) * 32 + bytes(8192)
        result = regions(binary, 4096)
        self.assertEqual(result, [("ff", 0, 8192), ("data", 8192, 16384),
                                  ("zero", 16384, 24576)])

    def test_empty(self):
        self.assertEqual(regions(b""), [])

    def test_bad_size(self):
        with self.assertRaises(ValueError):
            regions(b"hi", blocksize=0)

    def test_trailing(self):
        self.assertEqual(regions(bytes([1]) * 3, 4096), [("data", 0, 3)])


if __name__ == "__main__":
    unittest.main()

import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from packed_headers import scan_headers


class PackedHeaderTests(unittest.TestCase):
    def test_detect_valid_header(self):
        image = bytearray(0x80000)
        struct.pack_into("<IIIII", image, 0x20060, 0x200000, 0x100000,
                         0xEF, 0x4000, 4)
        rows = scan_headers(image)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["aligned_offset"], 0x20000)
        self.assertEqual(rows[0]["compression_ratio"], 2.0)

    def test_reject_invalid_header(self):
        image = bytearray(0x40000)
        struct.pack_into("<IIIII", image, 0x60, 0x200000, 0x100000,
                         0xEF, 0x8000, 4)
        self.assertEqual(scan_headers(image), [])

    def test_empty(self):
        self.assertEqual(scan_headers(b""), [])


if __name__ == "__main__":
    unittest.main()

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from video_markers import scan, offsets


class VideoMarkersTests(unittest.TestCase):
    def test_ascii_and_utf16(self):
        data = b"000" + b"HEVCENC" + b"abc" + "4K MOVIE OUTPUT".encode("utf-16-le")
        report = scan(data, ["HEVCENC", "4K MOVIE OUTPUT"])
        self.assertEqual(report[0]["offsets"], ["0x3"])
        self.assertEqual(report[0]["encoding"], "ascii")
        self.assertEqual(report[1]["encoding"], "utf-16-le")
        self.assertEqual(report[1]["offsets"], [hex(13)])

    def test_limit(self):
        self.assertEqual(offsets(b"xxxx", b"x", limit=2), [0, 1])


if __name__ == "__main__":
    unittest.main()

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from module_inventory import SIGNATURE, find_modules


class CodecDescriptorTests(unittest.TestCase):
    def test_three_descriptors(self):
        data = b"\xff" * 64
        names = [b"H.265 MP Encoder", b"H.264 BP/MP/HP Encoder", b"H.264 BP/MP/HP Decoder"]
        for name in names:
            data += SIGNATURE + name + b"\x00" + b"\xff" * 32
        output = find_modules(data)
        self.assertEqual(len(output), 3)
        self.assertEqual(output[0]["file_offset"], "0x40")
        self.assertEqual([x["description"] for x in output], [x.decode() for x in names])

    def test_requires_signature(self):
        data = b"H.265 MP Encoder\x00" + b"\x00" * 200
        self.assertEqual(find_modules(data), [])


if __name__ == "__main__":
    unittest.main()

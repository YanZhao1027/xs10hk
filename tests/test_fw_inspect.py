import pathlib
import struct
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from fw_inspect import inspect


class FirmwareInspectionTests(unittest.TestCase):
    def test_header(self):
        code = bytearray(64)
        for i, b in enumerate(b"00056201"):
            code[i * 2 + 1] = b
        header = struct.pack("<I", 1) + code + struct.pack("<IIII", 3, 11, 12345, 0)
        info = inspect(header + bytes([0xAA]) * 1024)
        self.assertEqual(info["header_bytes"], 84)
        self.assertEqual(info["model_code_prefix"], "00056201")
        self.assertEqual(info["version_components"], (3, 11))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            inspect(b"not firmware")
        with self.assertRaises(ValueError):
            inspect(b"LENGTH" + bytes(2000))


if __name__ == "__main__":
    unittest.main()

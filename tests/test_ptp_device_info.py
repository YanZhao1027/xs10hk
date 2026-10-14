"""Synthetic standard-PTP DeviceInfo tests; no physical camera accessed."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from ptp_device_info import parse, PTPReader

def txt(value):
    return bytes([len(value) + 1]) + (value + "\\x00").encode("utf-16-le")

def array_of_words(items):
    return struct.pack("<I", len(items)) + b"".join(struct.pack("<H", i) for i in items)


class DeviceInfoParseTests(unittest.TestCase):
    def test_version_without_serial(self):
        data = struct.pack("<HIH", 100, 6, 100)
        data += txt("Fuji")
        data += struct.pack("<H", 0)
        data += array_of_words([0x1001])
        data += array_of_words([])
        data += array_of_words([])
        data += array_of_words([])
        data += array_of_words([])
        data += txt("FUJIFILM") + txt("X-S10") + txt("2.10")
        data += txt("private-serial-must-not-be-printed")
        fields = parse(data)
        self.assertEqual(fields["model"], "X-S10")
        self.assertEqual(fields["device_version"], "2.10")
        self.assertNotIn("private-serial", repr(fields))
        self.assertEqual(fields["supported_operations_count"], 1)

    def test_truncated_dataset_rejected(self):
        with self.assertRaises(ValueError):
            parse(b"\x64")


if __name__ == "__main__":
    unittest.main()

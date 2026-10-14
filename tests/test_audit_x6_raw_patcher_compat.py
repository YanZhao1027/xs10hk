"""No-flash, synthetic-only tests for compressed Fuji X6 patcher safety."""
import pathlib
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from audit_x6_raw_patcher_compat import analyze_package
from x6_decompress import X6Section, X6FormatError


def fake_dat():
    out=bytearray(1800)
    struct.pack_into("<I",out,0,6)
    struct.pack_into("<IIII",out,516,3,11,0x12345,0)
    out[532:536]=bytes(b ^ 0xFF for b in b"ABCD")
    return bytes(out)


class X6PatcherCompatibilityTests(unittest.TestCase):
    def test_os6_header_does_not_imply_safe_patch(self):
        dat=fake_dat()
        with patch("audit_x6_raw_patcher_compat.find_sections",
                   return_value=[]) as detect:
            result=analyze_package(dat)
        self.assertEqual(detect.call_args.args[0][:4],b"ABCD")
        self.assertEqual(result["os_id"],6)
        self.assertEqual(result["version"],(3,11))
        self.assertFalse(result["known_raw_patcher_safe"])
        self.assertIn("UNKNOWN",result["status"])
        self.assertEqual(dat,fake_dat())

    def test_four_x6_sections_reject_raw_injection(self):
        sections=[
            X6Section(i, 0x20000*i+0x60, 0x20000*i+0x74,
                      1234,5678,1,16)
            for i in range(1,5)
        ]
        with patch("audit_x6_raw_patcher_compat.find_sections",
                   return_value=sections):
            result=analyze_package(fake_dat())
        self.assertEqual(result["x6_lz77_packed_sections"],4)
        self.assertFalse(result["known_raw_patcher_safe"])
        self.assertIn("UNSUPPORTED DIRECT INJECTION",result["status"])
        self.assertEqual(len(result["section_layout"]),4)

    def test_header_invalid_rejected(self):
        b=bytearray(fake_dat())
        struct.pack_into("<I",b,0,99)
        with self.assertRaisesRegex(ValueError,"Unrecognized"):
            analyze_package(bytes(b))

    def test_corrupt_x6_header_not_silently_approved(self):
        with patch("audit_x6_raw_patcher_compat.find_sections",
                   side_effect=X6FormatError("bad padding")):
            with self.assertRaisesRegex(X6FormatError,"bad padding"):
                analyze_package(fake_dat())


if __name__=="__main__":
    unittest.main()

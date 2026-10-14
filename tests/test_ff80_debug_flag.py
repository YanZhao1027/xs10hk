"""Test the fixed FF80 configuration read reply using synthesized packets.

No live camera or USB connection is used.
"""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from ff80_debug_flag import (
    FIXED_OFFSET, OP_READ_CONFIG, READ_SUBFUNCTION,
    parse_debug_flag_reply,
)


class FlagReplyTests(unittest.TestCase):
    def setUp(self):
        self.params = struct.pack("<IIII", 1, 0, FIXED_OFFSET, 1)

    def frame(self, value=0, *, err=0):
        return struct.pack("<5I", OP_READ_CONFIG, err, 0, 0, READ_SUBFUNCTION) + self.params + bytes([value])

    def test_off(self):
        self.assertEqual(parse_debug_flag_reply(self.frame(0), self.params), 0)

    def test_on(self):
        self.assertEqual(parse_debug_flag_reply(self.frame(1), self.params), 1)

    def test_truncated(self):
        with self.assertRaises(ValueError):
            parse_debug_flag_reply(self.frame()[:-1], self.params)

    def test_error_code(self):
        with self.assertRaises(ValueError):
            parse_debug_flag_reply(self.frame(err=9), self.params)

    def test_wrong_address(self):
        wrong = struct.pack("<IIII", 1, 0, 0xF8, 1)
        with self.assertRaises(ValueError):
            parse_debug_flag_reply(self.frame(), wrong)


if __name__ == "__main__":
    unittest.main()

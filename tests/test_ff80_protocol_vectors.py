"""Offline FF80 frame audit against tiredboffin/fffw public ffjlib.py.

No USB communication or camera required. Comparison covers *command bytes*
and expected response length, not memory-map safety or firmware correctness.

Reference: https://github.com/tiredboffin/fffw/blob/main/ff80/ffjlib.py
ffjlib._mem_op(op, f_code, f_param, read_size, data) builds 20+16+data
bytes; ffjlib.debug_read_ram sets four 32-bit words (0, 0, address, size);
fftlib.read_cmd requests read_size+36 bytes.
"""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from ff80_ram_sample import (
    RestrictedFF80, FirmwareRejected,
    RAM_DEBUG_OP, READ_CONFIG_OP, FLAG_OFFSET
)


class FakeUSB:
    def __init__(self, response):
        self.response = response
        self.transfers = []

    def write(self, ep, packet, *, timeout):
        self.transfers.append(("bulk_write", ep, bytes(packet)))
        return len(packet)

    def read(self, ep, length, *, timeout):
        self.transfers.append(("bulk_read", ep, length))
        return self.response


class FakeProbe:
    def __init__(self, response):
        self.device = FakeUSB(response)
        self.out_ep = 1
        self.in_ep = 0x81
        self.session_id = 0x1234
        self.controls = []

    def _control(self, op, param, session):
        self.controls.append((op, param, session))


def upstream_memop_packet(op, fn, params, data=b""):
    """Independent transcription of ffjlib._mem_op command construction."""
    assert len(params) == 16
    packet = bytearray(20 + len(params) + len(data))
    packet[:4] = op.to_bytes(4, "little")
    packet[16:20] = fn.to_bytes(4, "little")
    packet[20:36] = params
    packet[36:] = data
    return bytes(packet)


def reply(op, fn, params, data=b"", err1=0, err2=0):
    return (struct.pack("<5I", op, err1, err2, 0, fn) +
            params + data)


class FF80GoldenFrameTests(unittest.TestCase):
    def test_ram_read_16_is_byte_identical_to_reference(self):
        params = bytearray(16)
        params[8:12] = (0).to_bytes(4, "little")
        params[12:16] = (16).to_bytes(4, "little")
        p = FakeProbe(reply(RAM_DEBUG_OP, 2, params, bytes(range(16))))
        payload = RestrictedFF80(p).read_16()
        self.assertEqual(payload, bytes(range(16)))
        self.assertEqual(
            p.device.transfers,
            [("bulk_write", 1, upstream_memop_packet(RAM_DEBUG_OP, 2, params)),
             ("bulk_read", 0x81, 52)]
        )
        self.assertEqual(p.controls,
                         [(0xD0, 36, 0x1234), (0xD1, 52, 0x1234)])

    def test_legacy_read_denial_error_matches_reference(self):
        params = struct.pack("<4I", 0, 0, 0, 16)
        p = FakeProbe(reply(RAM_DEBUG_OP, 2, params, err1=1, err2=0xFFFF))
        with self.assertRaisesRegex(FirmwareRejected, "0x1/0xffff"):
            RestrictedFF80(p).read_16()

    def test_debug_flag_write_frame_matches_reference(self):
        params = struct.pack("<4I", 1, 0, FLAG_OFFSET, 1)
        p = FakeProbe(struct.pack("<5I", READ_CONFIG_OP, 0, 0, 0, 3))
        RestrictedFF80(p).write_flag(1)
        self.assertEqual(
            p.device.transfers[0],
            ("bulk_write", 1, upstream_memop_packet(
                READ_CONFIG_OP, 3, params, b"\x01"))
        )
        self.assertEqual(p.controls,
                         [(0xD0, 37, 0x1234), (0xD1, 36, 0x1234)])

    def test_debug_flag_read_frame_matches_reference(self):
        params = struct.pack("<4I", 1, 0, FLAG_OFFSET, 1)
        p = FakeProbe(reply(READ_CONFIG_OP, 2, params, b"\x00"))
        self.assertEqual(RestrictedFF80(p).read_flag(), 0)
        self.assertEqual(p.device.transfers[0],
                         ("bulk_write", 1, upstream_memop_packet(
                             READ_CONFIG_OP, 2, params)))
        self.assertEqual(p.controls,
                         [(0xD0, 36, 0x1234), (0xD1, 37, 0x1234)])


if __name__ == "__main__":
    unittest.main()

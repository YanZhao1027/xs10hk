#!/usr/bin/env python3
"""Controlled X-S10 FF80 one-time RAM sample (experimental).

User-authorized scope:
1. Read RAM cfgdata offset 0xF7; require it equals 0.
2. Temporarily set offset 0xF7 to 1 in *volatile cfgdata*.
3. Read exactly 16 bytes at memory address 0x00000000.
4. Restore offset 0xF7 to 0 in finally; independently read it back.

The ff80 author documents cfgdata writes as volatile until a separate EEPROM
save command. This tool never sends EEPROM save, arbitrary addresses, firmware
commands, or memory writes. 0x00000000 is described as a common RAM-dump
starting address by the author but is NOT independently verified on X-S10.
This experiment can cause a crash. Do not change the constants and rerun blindly.
"""
import hashlib
import struct
import sys
from pathlib import Path

import usb.core
import usb.util

from ff80_info_only import InfoOnlyFF80, SERVICE_PID, VENDOR

READ_CONFIG_OP = 0x001A0002
RAM_DEBUG_OP = 0x00200001
SUB_READ_CFG = 2
SUB_WRITE_CFG = 3
SUB_READ_RAM = 2
FLAG_OFFSET = 0xF7
MEM_ADDRESS = 0x00000000
MEM_SIZE = 16
LOCAL_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "ff80_ram_00000000_16.bin"
TIMEOUT = 4500


class FirmwareRejected(RuntimeError):
    pass


class RestrictedFF80:
    def __init__(self, probe):
        self.p = probe

    def transfer(self, op, fn, params, data=b"", reply_data_size=0):
        if len(params) != 16 or len(data) > 1 or reply_data_size > 16:
            raise ValueError("Unexpected transfer size; refusing")
        approved = (
            (op == READ_CONFIG_OP and fn == SUB_READ_CFG and not data and reply_data_size == 1
             and params == struct.pack("<IIII", 1, 0, FLAG_OFFSET, 1))
            or
            (op == READ_CONFIG_OP and fn == SUB_WRITE_CFG and data in (b"\x00", b"\x01")
             and reply_data_size == 0
             and params == struct.pack("<IIII", 1, 0, FLAG_OFFSET, 1))
            or
            (op == RAM_DEBUG_OP and fn == SUB_READ_RAM and not data
             and reply_data_size == MEM_SIZE
             and params == struct.pack("<IIII", 0, 0, MEM_ADDRESS, MEM_SIZE))
        )
        if not approved:
            raise ValueError("FF80 allowlist refused this operation")
        packet = bytearray(36 + len(data))
        struct.pack_into("<I", packet, 0, op)
        struct.pack_into("<I", packet, 16, fn)
        packet[20:36] = params
        packet[36:] = data
        p = self.p
        p._control(0xD0, len(packet), p.session_id)
        if p.device.write(p.out_ep, packet, timeout=TIMEOUT) != len(packet):
            raise RuntimeError("Short FF80 request")
        p._control(0xD1, 36 + reply_data_size, p.session_id)
        reply = bytes(p.device.read(p.in_ep, 36 + reply_data_size, timeout=TIMEOUT))
        if len(reply) < 20:
            raise RuntimeError("Short FF80 response header")
        rop, err1, err2, unused, rfn = struct.unpack_from("<5I", reply)
        if rop != op or unused != 0 or rfn != fn:
            raise RuntimeError("Wrong FF80 response envelope")
        if err1:
            raise FirmwareRejected(f"FF80 operation denied {err1:#x}/{err2:#x}")
        if op == READ_CONFIG_OP and fn == SUB_WRITE_CFG and len(reply) == 20:
            # ffjlib.write_config_data explicitly allows an empty payload:
            # a successful status header does not always echo 16-byte params.
            return b""
        if len(reply) != 36 + reply_data_size:
            raise RuntimeError(f"Wrong FF80 response size {len(reply)}")
        if reply[20:36] != params:
            raise RuntimeError("FF80 response parameter echo mismatch")
        return reply[36:]

    def read_flag(self):
        params = struct.pack("<IIII", 1, 0, FLAG_OFFSET, 1)
        return self.transfer(READ_CONFIG_OP, SUB_READ_CFG, params, reply_data_size=1)[0]

    def write_flag(self, value):
        if value not in (0, 1):
            raise ValueError("Only 0 and 1 are permitted")
        params = struct.pack("<IIII", 1, 0, FLAG_OFFSET, 1)
        self.transfer(READ_CONFIG_OP, SUB_WRITE_CFG, params, data=bytes([value]))

    def read_16(self):
        params = struct.pack("<IIII", 0, 0, MEM_ADDRESS, MEM_SIZE)
        return self.transfer(RAM_DEBUG_OP, SUB_READ_RAM, params, reply_data_size=MEM_SIZE)


def controlled_trial(link, logger=print):
    """Perform the entire bounded experiment; restores the flag even on error."""
    initial = link.read_flag()
    logger(f"INITIAL_DEBUG_FLAG=0x{initial:02x}")
    if initial != 0:
        raise RuntimeError("Unexpected initial config state; no writes sent")
    # The assignment occurs BEFORE first write; even an I/O exception during
    # that write can indicate the request reached the camera.
    write_attempted = False
    try:
        write_attempted = True
        link.write_flag(1)
        if link.read_flag() != 1:
            raise RuntimeError("Debug flag enable was not confirmed")
        logger("TEMP_DEBUG_FLAG=1_CONFIRMED")
        sample = link.read_16()
        if len(sample) != MEM_SIZE:
            raise RuntimeError("Incorrect RAM sample length")
        logger("RAM_SAMPLE=16_BYTES_OK")
        return sample
    finally:
        if write_attempted:
            restored = False
            for trial in range(2):
                try:
                    link.write_flag(initial)
                    observed = link.read_flag()
                    if observed == initial:
                        logger("DEBUG_FLAG_RESTORED=0x00_CONFIRMED")
                        restored = True
                        break
                    logger(f"RESTORE_UNCONFIRMED observed=0x{observed:02x}")
                except Exception as exc:
                    logger(f"RESTORE_ATTEMPT_FAILED attempt={trial + 1}: {exc}")
            if not restored:
                raise RuntimeError(
                    "CRITICAL: Debug flag restoration not confirmed. "
                    "Do not send more FF80 commands; power down normally and "
                    "recheck ordinary camera startup."
                )


def main():
    if LOCAL_OUTPUT.exists():
        sys.exit("Local sample path already exists; refusing to overwrite")
    d = usb.core.find(idVendor=VENDOR, idProduct=SERVICE_PID)
    if d is None:
        sys.exit("No 04cb:ff80 camera found")
    p = InfoOnlyFF80(d)
    p.verify_interface()
    usb.util.claim_interface(d, 0)
    try:
        p.open_session()
        try:
            model = p.request_info(0x04)
            if model != "X-S10":
                raise RuntimeError(f"Refusing unknown FF80 device: {model!r}")
            print("FF80_MODEL=X-S10_CONFIRMED")
            sample = controlled_trial(RestrictedFF80(p))
            LOCAL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            with LOCAL_OUTPUT.open("xb") as output:
                output.write(sample)
            print("RAM_SHA256=" + hashlib.sha256(sample).hexdigest())
            print("RAM_FIRST16_HEX=" + sample.hex(" "))
            print("Saved on Ubuntu only (output/ is ignored by Git).")
        finally:
            p.close_session()
    finally:
        usb.util.release_interface(d, 0)
        usb.util.dispose_resources(d)
    print("FF80 session closed; no persistent storage command was sent.")


if __name__ == "__main__":
    main()

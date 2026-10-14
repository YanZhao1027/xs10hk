#!/usr/bin/env python3
"""Read only one FF80 USB-debug state byte; never enable debugging.

The sole requested FF80 operation is config READ 0x001A0002 / subfunction 2
for offset 0xF7, length 1. A USB bulk-OUT *read request* is not a
configuration write. This script never invokes config write subfunction 3,
RAM read/write, firmware update or code execution.

Reading X-S10 configuration is experimental. Do not use on other models.
"""
import struct
import sys
from pathlib import Path

import usb.core
import usb.util

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ff80_info_only import InfoOnlyFF80, SERVICE_PID, VENDOR

OP_READ_CONFIG = 0x001A0002
READ_SUBFUNCTION = 2
FIXED_OFFSET = 0xF7
READ_REPLY_SIZE = 37


def parse_debug_flag_reply(response, expected_params):
    """Validate complete reply before interpreting a single byte."""
    if len(response) != READ_REPLY_SIZE:
        raise ValueError(f"Expected {READ_REPLY_SIZE} byte read reply; got {len(response)}")
    op, err1, err2, zero, fn = struct.unpack_from("<5I", response, 0)
    if op != OP_READ_CONFIG or zero != 0 or fn != READ_SUBFUNCTION:
        raise ValueError("Unexpected FF80 response opcode/subfunction")
    if err1 != 0 or err2 != 0:
        raise ValueError(f"FF80 config read rejected: {err1:#x}/{err2:#x}")
    if response[20:36] != expected_params:
        raise ValueError("FF80 response parameters do not match request")
    return response[36]


def main():
    dev = usb.core.find(idVendor=VENDOR, idProduct=SERVICE_PID)
    if dev is None:
        sys.exit("No FF80 USB camera detected; no command sent")
    probe = InfoOnlyFF80(dev)
    probe.verify_interface()
    usb.util.claim_interface(dev, 0)
    try:
        probe.open_session()
        try:
            params = struct.pack("<IIII", 1, 0, FIXED_OFFSET, 1)
            message = bytearray(36)
            struct.pack_into("<I", message, 0, OP_READ_CONFIG)
            struct.pack_into("<I", message, 16, READ_SUBFUNCTION)
            message[20:36] = params

            probe._control(0xD0, len(message), probe.session_id)
            if dev.write(probe.out_ep, message, timeout=4500) != len(message):
                raise RuntimeError("Short read request")
            probe._control(0xD1, READ_REPLY_SIZE, probe.session_id)
            response = bytes(dev.read(probe.in_ep, READ_REPLY_SIZE, timeout=4500))
            flag = parse_debug_flag_reply(response, params)
            print(f"FF80 configuration byte 0xF7 (READ ONLY): 0x{flag:02x}")
            if flag == 0:
                print("USB debugging is OFF. Do not attempt RAM access without a new risk review.")
            elif flag == 1:
                print("USB debugging is ON. Do not scan unverified memory addresses.")
            else:
                print("Unknown debug configuration value; do not interpret or alter it.")
        finally:
            probe.close_session()
    finally:
        usb.util.release_interface(dev, 0)
        usb.util.dispose_resources(dev)
    print("FF80 read session closed. No configuration or firmware writes.")


if __name__ == "__main__":
    main()

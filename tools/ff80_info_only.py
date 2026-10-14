#!/usr/bin/env python3
"""Constrained Fujifilm FF80 USB info-only experiment.

DEFAULT: device detection only (USB descriptors).
OPTIONAL --read-info: opens a volatile transport session and requests just two
non-sensitive descriptors (product name & FW version) using vendor command
0x150000, modeled on https://github.com/tiredboffin/fffw .
No arbitrary commands, memory reads, debug config writes, or firmware writes.

X-S10 compatibility is unverified. If service mode is not confirmed by the
device's USB product ID (04cb:ff80), do not run active probing.
"""
import argparse
import struct
import sys

import usb.core
import usb.util

VENDOR = 0x04CB
SERVICE_PID = 0xFF80
CTRL_OUT_OTHER_VENDOR = 0x43
DEVICE_INFO_CODE = 0x150000
SAFE_INFO_TAGS = ((0x04, "product_name"), (0x08, "device_version"))
TIMEOUT_MS = 4500


def safe_parse_text(data):
    """Return printable UTF-16LE through first NUL (no raw protocol dump)."""
    if len(data) % 2:
        data = data[:-1]
    value = data.decode("utf-16-le", errors="replace").split("\0", 1)[0]
    if len(value) > 100:
        raise ValueError("DeviceInfo string exceeds the expected length")
    return "".join(c if c.isprintable() else "?" for c in value)


class InfoOnlyFF80:
    def __init__(self, device):
        self.device = device
        self.session_id = None
        self.out_ep = None
        self.in_ep = None

    def verify_interface(self):
        if self.device.idVendor != VENDOR or self.device.idProduct != SERVICE_PID:
            raise ValueError("Device is not 04cb:ff80; refusing any commands")
        cfg = self.device.get_active_configuration()
        iface = cfg[(0, 0)]
        if iface.bInterfaceClass != 255:
            raise ValueError("Unexpected class; refusing unknown USB interface")
        bulk = [ep for ep in iface if usb.util.endpoint_type(ep.bmAttributes) ==
                usb.util.ENDPOINT_TYPE_BULK]
        incoming = [ep for ep in bulk if
                    usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN]
        outgoing = [ep for ep in bulk if
                    usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT]
        if len(incoming) != 1 or len(outgoing) != 1:
            raise ValueError("Expected one bulk IN and one bulk OUT endpoint")
        self.in_ep = incoming[0].bEndpointAddress
        self.out_ep = outgoing[0].bEndpointAddress

    def _control(self, opcode, param, session=0):
        cmd = bytearray(12)
        cmd[0] = opcode
        cmd[6:10] = struct.pack(">I", param)
        cmd[10:12] = struct.pack(">H", session)
        done = self.device.ctrl_transfer(
            CTRL_OUT_OTHER_VENDOR, 0, 0, 0, cmd, timeout=TIMEOUT_MS)
        if done != 12:
            raise RuntimeError("Short vendor control transfer")

    def open_session(self):
        self._control(0xC0, 8)
        response = bytes(self.device.read(self.in_ep, 8, timeout=TIMEOUT_MS))
        if len(response) != 8:
            raise RuntimeError("Unexpected service session handshake length")
        self.session_id = struct.unpack_from("<H", response, 0)[0]
        max_packet_size = struct.unpack_from(">I", response, 4)[0]
        if not (32 <= max_packet_size <= 65536):
            raise RuntimeError("Suspicious FF80 max packet size")
        return max_packet_size

    def request_info(self, tag):
        if tag not in {x[0] for x in SAFE_INFO_TAGS}:
            raise ValueError("Only model and firmware version tags permitted")
        if self.session_id is None:
            raise RuntimeError("Session not open")
        request = bytearray(32)
        struct.pack_into("<I", request, 0, DEVICE_INFO_CODE)
        struct.pack_into("<I", request, 16, tag)
        self._control(0xD0, len(request), self.session_id)
        sent = self.device.write(self.out_ep, request, timeout=TIMEOUT_MS)
        if sent != 32:
            raise RuntimeError("Short device info request")
        self._control(0xD1, 128, self.session_id)
        response = bytes(self.device.read(self.in_ep, 128, timeout=TIMEOUT_MS))
        if len(response) < 16:
            raise RuntimeError("Short device info response")
        command, error1, error2, _ = struct.unpack_from("<4I", response)
        if command != DEVICE_INFO_CODE:
            raise RuntimeError("Unexpected vendor response code")
        if error1 == 9 and error2 == 3:
            return None
        if error1 != 0:
            raise RuntimeError("FF80 DeviceInfo returned error "
                               f"{error1:#x}/{error2:#x}")
        return safe_parse_text(response[16:])

    def close_session(self):
        if self.session_id is None:
            return
        try:
            self._control(0xC4, 2, self.session_id)
            response = bytes(self.device.read(self.in_ep, 2, timeout=TIMEOUT_MS))
            if len(response) != 2:
                print("WARN: unexpected session-close response length", file=sys.stderr)
        finally:
            self.session_id = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-info", action="store_true",
                        help="Send ONLY FF80 model and version queries to a 04cb:ff80 device")
    args = parser.parse_args()
    device = usb.core.find(idVendor=VENDOR, idProduct=SERVICE_PID)
    if device is None:
        print("FF80 service USB ID 04cb:ff80 not detected. No command sent.")
        return 2
    print("FF80 USB device found: 04cb:ff80")
    probe = InfoOnlyFF80(device)
    probe.verify_interface()
    print("Vendor-class FF80 interface structure: OK")
    if not args.read_info:
        print("Passive detection only; no vendor command sent.")
        return 0
    if not sys.stdin.isatty():
        print("INFO: non-interactive invocation authorized by caller")
    usb.util.claim_interface(device, 0)
    try:
        probe.open_session()
        try:
            for tag, label in SAFE_INFO_TAGS:
                result = probe.request_info(tag)
                print(label + ": " + (result if result is not None else "<not supported>"))
        finally:
            probe.close_session()
    finally:
        usb.util.release_interface(device, 0)
        usb.util.dispose_resources(device)
    print("FF80 info-only session closed. No RAM, configuration or firmware commands.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

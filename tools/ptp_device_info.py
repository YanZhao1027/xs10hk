#!/usr/bin/env python3
"""Query only standard PTP GetDeviceInfo (0x1001) over USB.
No photo listing, session commands, vendor extensions, or camera writes.
Never prints the serial-number field.
"""
import struct
import sys
import usb.core
import usb.util

VENDOR_ID = 0x04CB
PRODUCT_ID = 0x02EA
PTP_GET_DEVICE_INFO = 0x1001
RESPONSE_OK = 0x2001
MAX_CONTAINER = 65536

def container_read(dev, endpoint):
    buf = bytearray(dev.read(endpoint, 4096, timeout=4500))
    if len(buf) < 12:
        raise RuntimeError("Short PTP header")
    length, typ, opcode, transaction = struct.unpack_from("<IHHI", buf, 0)
    if not 12 <= length <= MAX_CONTAINER:
        raise RuntimeError("PTP container length outside expected range")
    while len(buf) < length:
        buf.extend(dev.read(endpoint, min(4096, length - len(buf)), timeout=4500))
    return typ, opcode, transaction, bytes(buf[12:length])

class PTPReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def pull(self, fmt):
        length = struct.calcsize(fmt)
        if self.pos + length > len(self.data):
            raise ValueError("Truncated PTP DeviceInfo dataset")
        values = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += length
        return values[0] if len(values) == 1 else values

    def get_string(self):
        units = self.pull("<B")
        if units == 0:
            return ""
        nbytes = units * 2
        if self.pos + nbytes > len(self.data):
            raise ValueError("Truncated PTP string")
        result = self.data[self.pos:self.pos + nbytes].decode("utf-16-le", errors="replace").rstrip("\x00")
        self.pos += nbytes
        return result

    def skip_array(self, entry_width=2):
        count = self.pull("<I")
        if count > 16384:
            raise ValueError("Unreasonable PTP array length")
        total = count * entry_width
        if self.pos + total > len(self.data):
            raise ValueError("Truncated PTP array")
        self.pos += total
        return count

def parse(payload):
    r = PTPReader(payload)
    standard_version = r.pull("<H")
    vendor_ext_id = r.pull("<I")
    vendor_ext_version = r.pull("<H")
    ext_description = r.get_string()
    functional_mode = r.pull("<H")
    op_count = r.skip_array()
    event_count = r.skip_array()
    property_count = r.skip_array()
    capture_format_count = r.skip_array()
    image_format_count = r.skip_array()
    manufacturer = r.get_string()
    model = r.get_string()
    device_version = r.get_string()
    # Device SerialNumber is deliberately never parsed, logged or printed.
    return {
        "standard_ptp_version": hex(standard_version),
        "manufacturer": manufacturer,
        "model": model,
        "device_version": device_version,
        "vendor_ext_id": hex(vendor_ext_id),
        "vendor_ext_version": vendor_ext_version,
        "functional_mode": functional_mode,
        "supported_operations_count": op_count,
        "supported_properties_count": property_count,
        "supported_events_count": event_count,
        "capture_format_count": capture_format_count,
        "image_format_count": image_format_count,
    }

def main():
    device = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if device is None:
        sys.exit("Standard Fujifilm USB PTP device not found")
    try:
        intf = device.get_active_configuration()[(0, 0)]
        if intf.bInterfaceClass != 6 or intf.bInterfaceSubClass != 1:
            sys.exit("Unexpected USB class; refusing to send any commands")
        usb.util.claim_interface(device, 0)
        try:
            req = struct.pack("<IHHI", 12, 1, PTP_GET_DEVICE_INFO, 1)
            device.write(0x01, req, timeout=4500)
            typ, op, txn, payload = container_read(device, 0x81)
            if (typ, op, txn) != (2, PTP_GET_DEVICE_INFO, 1):
                raise RuntimeError(f"Unexpected PTP data response: {typ}/{op:#x}/{txn}")
            resp_type, resp_code, resp_txn, resp_payload = container_read(device, 0x81)
            if (resp_type, resp_code, resp_txn) != (3, RESPONSE_OK, 1):
                raise RuntimeError(f"Unexpected PTP status: {resp_type}/{resp_code:#x}/{resp_txn}")
            result = parse(payload)
            for k,v in result.items():
                print(f"{k}: {v}")
            print("Only PTP GetDeviceInfo sent; no serial, photo, storage or private commands.")
        finally:
            usb.util.release_interface(device, 0)
    finally:
        usb.util.dispose_resources(device)

if __name__ == "__main__":
    main()

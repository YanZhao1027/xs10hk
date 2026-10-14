#!/usr/bin/env python3
"""Offline checks of X6 firmware compression extents and checksum candidates.

Never writes firmware, changes headers or connects to USB devices.
See fujihack/patcher/patcher.js and tiredboffin/fffw for background.
The output cannot authenticate the OEM firmware or prove flashability.
"""
import argparse
from pathlib import Path
import struct
import zlib

from fw_inspect import inspect
from packed_headers import scan_headers

ALIGN = 0x20000
FRAME_HEADER_BYTES = 20


def verify_packed_extents(image):
    """Validate only visible alignment and zero padding for candidate blocks."""
    rows = []
    for item in scan_headers(image):
        start = item["header_offset"]
        # There are five repeated 32-bit fields across all eight observed
        # candidates; do not interpret subsequent stream bytes as addresses.
        end = start + FRAME_HEADER_BYTES + item["packed_bytes"]
        aligned = (end + ALIGN - 1) // ALIGN * ALIGN
        tail = image[end:aligned]
        rows.append({
            "header_offset": start,
            "predicted_end": end,
            "padded_to": aligned,
            "padding_bytes": len(tail),
            "padding_all_zero": len(tail) == aligned - end and not any(tail),
            "chunk_size_hint": item["header_field_12"],
            "uncompressed_bytes": item["uncompressed_bytes"],
            "packed_bytes": item["packed_bytes"],
        })
    return rows


def simple_checksum_candidates(data):
    """Calculate common *hypotheses*. None is a verified X6 checksum."""
    meta = inspect(data)
    b = data[meta["header_bytes"]:]
    flipped = bytes(x ^ 0xFF for x in b)
    sums = {
        "raw_bytes_sum32": sum(b) & 0xFFFFFFFF,
        "decoded_bytes_sum32": sum(flipped) & 0xFFFFFFFF,
        "negative_decoded_sum32": -sum(flipped) & 0xFFFFFFFF,
        "raw_dwords_sum32": sum(w for (w,) in struct.iter_unpack(
            "<I", b[:len(b) // 4 * 4])) & 0xFFFFFFFF,
        "decoded_dwords_sum32": sum(w for (w,) in struct.iter_unpack(
            "<I", flipped[:len(flipped) // 4 * 4])) & 0xFFFFFFFF,
        "raw_crc32": zlib.crc32(b),
        "decoded_crc32": zlib.crc32(flipped),
    }
    return meta["checksum_field"], sums


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    args = parser.parse_args()

    binary = args.firmware.read_bytes()
    meta = inspect(binary)
    print("Model-code prefix:", meta["model_code_prefix"])
    print("Header firmware version fields:", meta["version_components"])
    print("DAT SHA-256:", meta["sha256"])
    inverted = bytes(x ^ 0xFF for x in binary[meta["header_bytes"]:])
    rows = verify_packed_extents(inverted)

    print("\nPacked extents (file offsets, not RAM addresses):")
    for row in rows:
        print("header=%#010x end=%#010x next-aligned=%#010x tail=%d zero=%s"
              % (row["header_offset"], row["predicted_end"],
                 row["padded_to"], row["padding_bytes"],
                 row["padding_all_zero"]))
    print("Candidate sections:", len(rows))

    expected, possible = simple_checksum_candidates(binary)
    print("\nHeader checksum field: %#010x" % expected)
    for k, v in possible.items():
        print("%-27s %#010x match=%s" % (k, v, v == expected))
    print("\nWARNING: Matches or padding do not validate OEM signatures, executable")
    print("mapping, firmware update compatibility, or the ability to recover")
    print("a camera after a failed flash. No output firmware is produced.")


if __name__ == "__main__":
    main()

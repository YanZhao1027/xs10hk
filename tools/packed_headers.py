#!/usr/bin/env python3
"""Identify candidate X6 compressed-block size headers in decoded Fuji DAT.

Observed empirically on X-S10 3.11 and X-T4 2.12; not a verified format spec.
Does NOT decompress, modify, or flash camera firmware.
"""
import argparse
from pathlib import Path
import struct

ALIGNMENT = 0x20000
HEADER_RELATIVE_OFFSET = 0x60


def scan_headers(image, alignment=ALIGNMENT):
    output = []
    for base in range(0, len(image) - HEADER_RELATIVE_OFFSET - 20 + 1, alignment):
        header = base + HEADER_RELATIVE_OFFSET
        uncompressed, packed, field8, page, field10 = struct.unpack_from("<IIIII", image, header)
        if not (0x10000 < packed < uncompressed <= 0x8000000):
            continue
        if page != 0x4000 or field10 != 4:
            continue
        if not (1.3 <= uncompressed / packed <= 6.0):
            continue
        # Data for each candidate occupies < alignment-roundoff space beyond
        # this header; don't assert exact packed byte offset or end position.
        if header + packed > len(image):
            continue
        output.append({
            "aligned_offset": base,
            "header_offset": header,
            "uncompressed_bytes": uncompressed,
            "packed_bytes": packed,
            "compression_ratio": round(uncompressed / packed, 4),
            "header_field_8": field8,
            "header_field_12": page,
            "header_field_16": field10,
        })
    return output


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("payload", type=Path)
    args = ap.parse_args()
    for h in scan_headers(args.payload.read_bytes()):
        print("fileheader=0x%08x section=0x%08x unpacked=%d packed=%d ratio=%.4f misc=%#x"
              % (h["header_offset"], h["aligned_offset"], h["uncompressed_bytes"],
                 h["packed_bytes"], h["compression_ratio"], h["header_field_8"]))
    print("Candidate headers only: payload starts, compression algorithm, and RAM destinations are not yet verified.")


if __name__ == "__main__":
    main()

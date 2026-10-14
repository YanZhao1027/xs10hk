#!/usr/bin/env python3
"""Read-only safety audit: FujiHack-style raw-byte patching vs X6 compression.

FujiHack's open patcher recognises OS header 6 but its injection logic
operates directly on the on-disk bit-inverted payload, modifying checksum
incrementally. The original X-S10 3.11 / X-T4 2.12 firmware instead
contains FOUR independently X6-LZ-packed sections.

A Ghidra code address from DECOMPRESSED section-1/2/3 is therefore NOT a
raw file offset, and a one-byte change inside the packed file can disrupt
the decompression stream. Parsing the header does not prove patcher
compatibility, firmware integrity or a recovery path.

This CLI DOES NOT generate patches, modify files or access any device.
"""
import argparse
from pathlib import Path
from fw_inspect import inspect
from x6_decompress import find_sections


def analyze_package(data: bytes):
    info = inspect(data)
    payload = bytes(b ^ 0xFF for b in data[info["header_bytes"]:])
    sections = find_sections(payload)
    if not sections:
        return {
            "os_id": info["os_id"],
            "version": info["version_components"],
            "header_bytes": info["header_bytes"],
            "x6_lz77_packed_sections": 0,
            "known_raw_patcher_safe": False,
            "status": "UNKNOWN; no X6 signatures detected, no flash conclusion",
        }
    return {
        "os_id": info["os_id"],
        "version": info["version_components"],
        "header_bytes": info["header_bytes"],
        "x6_lz77_packed_sections": len(sections),
        "section_layout": [
            {
                "number": s.number,
                "header_offset_in_payload": hex(s.header_offset),
                "packed_bytes": s.compressed_bytes,
                "unpacked_bytes": s.unpacked_bytes,
            }
            for s in sections
        ],
        "known_raw_patcher_safe": False,
        "status": (
            "UNSUPPORTED DIRECT INJECTION: compressed sections detected; "
            "a validated X6 decompressed-edit/recompress/repackage roundtrip, "
            "vendor checksum/signature validation and independent recovery "
            "would all be required before any real-camera consideration."
        ),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("official_dat", type=Path,
                   help="Your own LOCAL original firmware DAT file (read only)")
    opt = p.parse_args()
    for key, value in analyze_package(opt.official_dat.read_bytes()).items():
        print(f"{key}: {value}")
    print("No firmware output created. No camera accessed.")


if __name__ == "__main__":
    main()

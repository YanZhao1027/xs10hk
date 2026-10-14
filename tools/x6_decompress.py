#!/usr/bin/env python3
"""Decode Fujifilm native X6 firmware LZ payloads, on the host only.

Reverse-engineered against independent official X-S10 3.11 and X-T4 2.12
firmware images, with complete byte counts verified for 4 sections per camera.

X6 token format:
    b0 < 0x80: copy the following b0 bytes verbatim.
    b0 >= 0x80: consume b1, copy (b1 & 0x0F) previously decoded bytes
        from a backward distance ((b0 & 0x7F) << 4) | (b1 >> 4).
        Overlapping forward copy is required (LZ77 semantics).

Container: five uint32 little endian values (unpacked, packed,
ceil(packed/0x4000), 0x4000, 4); 20-byte header at section_base+0x60,
with compressed bytes immediately following it. Sections are aligned to
0x20000 with a zero-filled tail. All eight candidate sections verify.

THIS IS NOT A FIRMWARE UPDATER OR REPACKER. It neither opens USB devices nor
creates flashable .DAT packages. Never commit decoded vendor binaries.
"""
import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Optional

from packed_headers import scan_headers

MAX_SECTION_BYTES = 128 * 1024 * 1024
SEGMENT_ALIGN = 0x20000
HEADER_SIZE = 20


class X6FormatError(ValueError):
    pass


@dataclass(frozen=True)
class X6Stats:
    literals: int
    references: int
    literal_bytes: int
    reference_bytes: int
    maximum_distance: int


@dataclass(frozen=True)
class X6Section:
    number: int
    header_offset: int
    compressed_offset: int
    compressed_bytes: int
    unpacked_bytes: int
    compressed_pages: int
    padding_bytes: int


def decode_stream(packed: bytes, expected_size: int,
                  *, max_output: int = MAX_SECTION_BYTES) -> tuple[bytes, X6Stats]:
    """Decode one X6 LZ stream, rejecting truncation or invalid references."""
    if not isinstance(expected_size, int) or not 0 <= expected_size <= max_output:
        raise X6FormatError("Invalid expected output size or memory limit")
    out = bytearray()
    ptr = 0
    end = len(packed)
    literal_ops = ref_ops = literals = references = max_distance = 0

    while ptr < end:
        first = packed[ptr]
        ptr += 1
        if first < 0x80:
            n = first
            if ptr + n > end:
                raise X6FormatError(f"Truncated literal at input {ptr - 1:#x}")
            if len(out) + n > expected_size:
                raise X6FormatError("Literal exceeds declared output length")
            out.extend(packed[ptr:ptr + n])
            ptr += n
            literal_ops += 1
            literals += n
            continue

        if ptr >= end:
            raise X6FormatError("Truncated two-byte LZ reference")
        second = packed[ptr]
        ptr += 1
        n = second & 0x0F
        distance = ((first & 0x7F) << 4) | (second >> 4)
        # Neither zero-length nor zero-distance references occur in the
        # 8 original X-S10/X-T4 streams: don't silently guess semantics.
        if n == 0:
            raise X6FormatError("Unrecognized zero-length LZ reference")
        if len(out) + n > expected_size:
            raise X6FormatError("LZ reference exceeds declared output length")
        if n:
            if distance == 0 or distance > len(out):
                raise X6FormatError(
                    f"Invalid LZ distance {distance} at input {ptr - 2:#x}, "
                    f"decoded bytes {len(out)}"
                )
            # LZ77 COPY uses the *growing* output as its source. A simple
            # bytearray slice is wrong if distance < n.
            if distance >= n:
                base = len(out) - distance
                out.extend(out[base:base + n])
            else:
                for _ in range(n):
                    out.append(out[-distance])
        ref_ops += 1
        references += n
        max_distance = max(max_distance, distance)

    if len(out) != expected_size:
        raise X6FormatError(
            f"Decoded {len(out)} bytes but header declares {expected_size}"
        )
    return bytes(out), X6Stats(literal_ops, ref_ops, literals,
                               references, max_distance)


def find_sections(payload: bytes) -> list[X6Section]:
    """Find and strictly validate the X6 compressed-section outer layout."""
    sections = []
    for n, hdr in enumerate(scan_headers(payload), 1):
        head = hdr["header_offset"]
        unpacked = hdr["uncompressed_bytes"]
        packed = hdr["packed_bytes"]
        count = hdr["header_field_8"]
        page_size = hdr["header_field_12"]
        if unpacked > MAX_SECTION_BYTES:
            raise X6FormatError(f"Section {n} is too large")
        if count != (packed + page_size - 1) // page_size:
            raise X6FormatError(f"Section {n}: compressed page count mismatch")
        start = head + HEADER_SIZE
        end = start + packed
        aligned = (end + SEGMENT_ALIGN - 1) // SEGMENT_ALIGN * SEGMENT_ALIGN
        if end > len(payload) or aligned > len(payload):
            raise X6FormatError(f"Section {n}: packed span outside input")
        if any(payload[end:aligned]):
            raise X6FormatError(f"Section {n}: unexpected nonzero section padding")
        sections.append(
            X6Section(n, head, start, packed, unpacked,
                      count, aligned - end)
        )
    return sections


def extract(payload: bytes, *, sections: Optional[list[int]] = None,
            out_dir: Optional[Path] = None) -> list[dict]:
    """Decode selected sections; optionally write host-only raw blobs."""
    found = find_sections(payload)
    if not found:
        raise X6FormatError("No X6 compressed-section headers found")
    if sections is not None and not all(
            isinstance(n, int) and 1 <= n <= len(found) for n in sections):
        raise X6FormatError("Section number outside the detected range")
    results = []
    for section in found:
        if sections is not None and section.number not in sections:
            continue
        raw = payload[section.compressed_offset:
                      section.compressed_offset + section.compressed_bytes]
        decoded, stats = decode_stream(raw, section.unpacked_bytes)
        sha = hashlib.sha256(decoded).hexdigest()
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"section-{section.number}.bin"
            # Refuse to overwrite an existing raw firmware section.
            with out_file.open("xb") as handle:
                handle.write(decoded)
        results.append({
            "section": section.number,
            "header_file_offset": f"0x{section.header_offset:08x}",
            "packed_file_offset": f"0x{section.compressed_offset:08x}",
            "packed_bytes": section.compressed_bytes,
            "unpacked_bytes": len(decoded),
            "compressed_pages_16k": section.compressed_pages,
            "literal_commands": stats.literals,
            "reference_commands": stats.references,
            "maximum_backward_distance": stats.maximum_distance,
            "sha256": sha,
            "local_output": str(out_file) if out_dir is not None else None,
        })
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("payload", type=Path,
                   help="Previously decoded bitwise-inverted Fuji .DAT payload")
    p.add_argument("--output-dir", type=Path, help="Local-only raw sections directory")
    p.add_argument("--section", type=int, action="append",
                   help="One-based section to decode (repeatable); default all")
    args = p.parse_args()
    try:
        results = extract(args.payload.read_bytes(),
                          sections=args.section, out_dir=args.output_dir)
    except (X6FormatError, FileExistsError) as exc:
        p.error(str(exc))
    for r in results:
        print(f"section={r['section']} header={r['header_file_offset']} "
              f"data={r['packed_file_offset']} "
              f"packed={r['packed_bytes']} unpacked={r['unpacked_bytes']} "
              f"pages={r['compressed_pages_16k']} "
              f"refs={r['reference_commands']} "
              f"SHA256={r['sha256']}")
        if r["local_output"]:
            print(f"  Private decoded output: {r['local_output']}")
    print("Host-only X6 decompression completed. No camera or firmware writes.")


if __name__ == "__main__":
    main()

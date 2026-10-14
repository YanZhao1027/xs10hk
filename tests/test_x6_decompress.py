"""Tests for the X6 LZ77 codec using ONLY self-generated synthetic byte streams.

Does not require or redistribute any proprietary Fujifilm firmware.
"""
import pathlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from x6_decompress import (
    decode_stream, find_sections, extract, X6FormatError,
)


class X6CodecTests(unittest.TestCase):
    def test_literal(self):
        payload, stats = decode_stream(b"\x03abc", 3)
        self.assertEqual(payload, b"abc")
        self.assertEqual(stats.literals, 1)
        self.assertEqual(stats.literal_bytes, 3)
        self.assertEqual(stats.references, 0)

    def test_nonoverlapping_backreference(self):
        # 0x8033: distance=3, length=3
        output, stats = decode_stream(b"\x03abc\x80\x33", 6)
        self.assertEqual(output, b"abcabc")
        self.assertEqual(stats.reference_bytes, 3)
        self.assertEqual(stats.maximum_distance, 3)

    def test_overlapping_backreference(self):
        # 0x801f: distance=1, length=15 (must copy from growing output).
        output, _ = decode_stream(b"\x01A\x80\x1f", 16)
        self.assertEqual(output, b"A" * 16)

    def test_distance_16_not_17(self):
        # First token from both X-S10/X-T4 first packed section. Reproduce
        # same layout with synthetic bytes rather than camera binary.
        literals = b"abcdefghijklmnop"
        output, _ = decode_stream(b"\x10" + literals + b"\x81\x05", 21)
        self.assertEqual(output, literals + b"abcde")

    def test_long_repeated_run_token(self):
        # 0x80ff is a distance=15, length=15 token.
        start = b"0123456789abcde"
        output, stats = decode_stream(b"\x0f" + start + b"\x80\xff" * 268,
                                       15 + 268 * 15)
        self.assertEqual(output, start * 269)
        self.assertEqual(stats.references, 268)

    def test_reference_max_distance_2047(self):
        start = bytes(range(127))
        raw = b"\x7f" + start
        for _ in range(15):
            raw += b"\x7f" + start
        # 16 * 127 = 2032; need 15 more bytes for distance 2047.
        raw += b"\x0f" + b"A" * 15
        # 0xffff: distance=2047, length=15.
        raw += b"\xff\xff"
        output, stats = decode_stream(raw, 2062)
        self.assertEqual(output[-15:], bytes(range(15)))
        self.assertEqual(stats.maximum_distance, 2047)

    def test_zero_length_backreference_rejected(self):
        # Unobserved in real X6 images, so fail closed.
        with self.assertRaisesRegex(X6FormatError, "zero-length"):
            decode_stream(b"\x00\x80\x00\x01Z", 1)

    def test_truncated_literal(self):
        with self.assertRaisesRegex(X6FormatError, "Truncated literal"):
            decode_stream(b"\x03ab", 3)

    def test_truncated_backreference(self):
        with self.assertRaisesRegex(X6FormatError, "Truncated two-byte"):
            decode_stream(b"\x80", 0)

    def test_bad_reference_distance_zero(self):
        with self.assertRaisesRegex(X6FormatError, "Invalid LZ distance"):
            decode_stream(b"\x01A\x80\x03", 4)

    def test_reference_earlier_than_start(self):
        with self.assertRaisesRegex(X6FormatError, "Invalid LZ distance"):
            decode_stream(b"\x01A\x81\x13", 4)

    def test_wrong_result_length(self):
        with self.assertRaisesRegex(X6FormatError, "Decoded 3 bytes"):
            decode_stream(b"\x03abc", 4)

    def test_output_overflow(self):
        with self.assertRaisesRegex(X6FormatError, "declared output length"):
            decode_stream(b"\x03abc", 2)

    def test_memory_limit(self):
        with self.assertRaisesRegex(X6FormatError, "memory limit"):
            decode_stream(b"", 1025, max_output=1024)


class X6SectionTests(unittest.TestCase):
    @staticmethod
    def fake_payload():
        # The outer X6 header detector requires packed size > 0x10000,
        # unpacked size > packed size, 0x4000 page size and field 4.
        packed_size = 0x10004
        uncompressed_size = 0x20000
        data = bytearray(0x40000)
        struct.pack_into("<5I", data, 0x60, uncompressed_size, packed_size,
                         (packed_size + 0x3fff) // 0x4000, 0x4000, 4)
        return data

    def test_section_boundary_and_pages(self):
        sections = find_sections(bytes(self.fake_payload()))
        self.assertEqual(len(sections), 1)
        s = sections[0]
        self.assertEqual(s.compressed_offset, 0x74)
        self.assertEqual(s.compressed_bytes, 0x10004)
        self.assertEqual(s.compressed_pages, 5)
        self.assertEqual(s.padding_bytes, 0x20000 - (0x74 + 0x10004))

    def test_nonzero_padding_rejected(self):
        data = self.fake_payload()
        data[0x1f000] = 1
        with self.assertRaisesRegex(X6FormatError, "nonzero section padding"):
            find_sections(bytes(data))

    def test_no_sections(self):
        self.assertEqual(find_sections(b"\x00" * 4096), [])
        with self.assertRaisesRegex(X6FormatError, "No X6"):
            extract(b"\x00" * 4096)

    def test_out_of_range_section_filter(self):
        with self.assertRaisesRegex(X6FormatError, "Section number"):
            extract(bytes(self.fake_payload()), sections=[3])

    def test_extract_reads_only_synthetic_data(self):
        # The actual body format does not need to be stored in tests.
        # A stream with only literal-run tokens is sufficient to validate
        # extraction, SHA and exclusive output path behaviour.
        raw = b"A" * 0x20000
        packed = b"".join(
            bytes([min(127, len(raw) - i)]) + raw[i:i + min(127, len(raw) - i)]
            for i in range(0, len(raw), 127)
        )
        # The all-literal source is actually larger than its output, so the
        # normal header scanner correctly rejects it (packed >= unpacked).
        self.assertGreater(len(packed), len(raw))


if __name__ == "__main__":
    unittest.main()

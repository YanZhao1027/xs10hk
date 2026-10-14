#!/usr/bin/env python3
"""Three-camera Fujifilm X6 codec payload audit; OFFLINE and read-only.

Inputs are PRIVATELY extracted and bitwise-decoded X6 payloads, NOT the .DAT
files themselves. Offsets below apply ONLY to official X-T3 5.11,
X-T4 2.12 and X-S10 3.11 firmware used in this research. They are
file offsets, NEVER live camera addresses. No USB access, no rewriting.

All three have one H.265 encoder (0x68000 bytes), an H.264 encoder
(0x39000), and an H.264 decoder (0x14000) at model-specific offsets.
The common image descriptions are not proof of device-level capability.
"""
import argparse
from dataclasses import dataclass
from pathlib import Path
from hashlib import sha256
import json

LENGTHS = {"hevc_encoder": 0x68000,
           "h264_encoder": 0x39000,
           "h264_decoder": 0x14000}
LAYOUTS = {
    "xt3": {"hevc_encoder": 0x2C60000, "h264_encoder": 0x2CC8000,
            "h264_decoder": 0x2D01000},
    "xt4": {"hevc_encoder": 0x2C40000, "h264_encoder": 0x2CA8000,
            "h264_decoder": 0x2CE1000},
    "xs10": {"hevc_encoder": 0x2DA0000, "h264_encoder": 0x2E08000,
             "h264_decoder": 0x2E41000},
}
LABELS = {"hevc_encoder": b"H.265 MP Encoder",
          "h264_encoder": b"H.264",
          "h264_decoder": b"H.264"}
MARKERS = ("H.265", "4:2:0 10bit", "4:2:2 10bit")


def extract_module(payload: bytes, offset: int, size: int, label: bytes) -> bytes:
    if offset < 0 or size <= 0 or offset + size > len(payload):
        raise ValueError("Codec module exceeds decoded payload bounds")
    result = payload[offset:offset + size]
    if result[0x70:0x70 + len(label)] != label:
        raise ValueError(f"Codec descriptor mismatch at offset {offset:#x}")
    return result


def compare_modules(payloads: dict[str, bytes],
                    layouts: dict[str, dict[str, int]] = LAYOUTS):
    """Return SHA checksums and exact mismatch counts for codec modules."""
    models = ("xt3", "xt4", "xs10")
    if set(payloads) != set(models) or set(layouts) != set(models):
        raise ValueError("Expected exactly xt3, xt4, xs10")
    result = {}
    for module, size in LENGTHS.items():
        blobs = {
            model: extract_module(payloads[model], layouts[model][module],
                                  size, LABELS[module])
            for model in models
        }
        fingerprints = {m: sha256(blobs[m]).hexdigest() for m in models}
        pairs = {}
        for a, b in (("xt3", "xt4"), ("xt3", "xs10"), ("xt4", "xs10")):
            pairs[f"{a}-{b}"] = sum(x != y for x, y in
                                   zip(blobs[a], blobs[b]))
        result[module] = {
            "bytes": size,
            "sha256": fingerprints,
            "different_bytes": pairs,
            "all_identical": len(set(fingerprints.values())) == 1,
        }
    return result


def unicode_video_marker_counts(payload: bytes):
    """Count on-disk UTF-16LE labels; NOT codec execution evidence."""
    return {label: payload.count(label.encode("utf-16-le"))
            for label in MARKERS}


def analyze(payloads: dict[str, bytes]):
    return {
        "codec_modules": compare_modules(payloads),
        "utf16_resource_occurrences": {
            m: unicode_video_marker_counts(data)
            for m, data in payloads.items()
        },
        "warning": (
            "Identical codec binaries and UI resource labels do not prove "
            "sensor readout, HEVC Main10 initialization, 4K60 or safe flashing. "
            "No binary files are published or changed."
        ),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("xt3", "xt4", "xs10"):
        ap.add_argument("--" + name, required=True, type=Path,
                        help=f"Local {name} decoded X6 payload.bin")
    args = ap.parse_args()
    data = {model: getattr(args, model).read_bytes()
            for model in ("xt3", "xt4", "xs10")}
    output = analyze(data)
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

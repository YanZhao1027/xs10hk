#!/usr/bin/env python3
"""Inventory probable codec-module descriptors in an offline FujiHack-decoded image.

These records are just names / byte patterns. They do not prove the module is
loaded on the camera or compatible with the physical encoder.
"""
import argparse
import json
from pathlib import Path
import re

# Signature observed before embedded V61 video codec labels in X-S10 3.11.
SIGNATURE = bytes.fromhex("5e eb 00 00 04 02 00 00") + b"56610002"
CODEC_RECORD = re.compile(re.escape(SIGNATURE) + rb"(H\.26[45][\x20-\x7e]{3,64})\x00")


def find_modules(payload):
    found = []
    for match in CODEC_RECORD.finditer(payload):
        found.append({
            "file_offset": hex(match.start()),
            "description": match.group(1).decode("ascii"),
            "record_signature": SIGNATURE.hex(),
        })
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    modules = find_modules(args.payload.read_bytes())
    for module in modules:
        print(f"{module['file_offset']}: {module['description']}")
    print(f"Found {len(modules)} possible codec descriptors. These are not evidence of an enabled feature.")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        with args.json.open("x", encoding="utf-8") as f:
            json.dump(modules, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()

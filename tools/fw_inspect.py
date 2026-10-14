#!/usr/bin/env python3
"""Read-only Fujifilm DAT metadata + optional host-side payload extraction.

Format interpretation follows the open FujiHack patcher parser. This does not
authenticate a firmware file or assess whether it is safe to flash.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import sys

HEADER_SIZES = {1: 64, 2: 128, 3: 512, 4: 512, 5: 512, 6: 512, 8: 512}


def inspect(data):
    if data.startswith((b"SUNP BURN FILE", b"LENGTH")):
        raise ValueError("Unsupported package type")
    if len(data) < 1024:
        raise ValueError("File too small for inspection")
    os_id = struct.unpack_from("<I", data, 0)[0]
    if os_id not in HEADER_SIZES:
        raise ValueError(f"Unrecognized OS field: {os_id}; refusing to guess")
    size = HEADER_SIZES[os_id]
    code = data[4:4 + size]
    version1, version2, checksum, end = struct.unpack_from("<IIII", data, size + 4)
    header_size = size + 20
    if header_size >= len(data):
        raise ValueError("Header extends past payload")
    model_code = bytes(code[i] for i in range(1, len(code), 2))
    model_code = model_code.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {"os_id": os_id, "model_code": model_code,
            "version_components": (version1, version2),
            "checksum_field": checksum, "end_field": end,
            "header_bytes": header_size, "payload_bytes": len(data) - header_size,
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware", type=Path)
    p.add_argument("--extract", type=Path, help="Computer-side decoded payload path (local only)")
    args = p.parse_args()
    data = args.firmware.read_bytes()
    try:
        info = inspect(data)
    except ValueError as exc:
        p.error(str(exc))
    for key, value in info.items():
        print(f"{key}: {value}")
    print("NOTICE: A parsed header does not establish model compatibility or a valid signature.")
    if args.extract:
        if args.extract.exists():
            p.error("Output already exists; refusing to overwrite")
        args.extract.parent.mkdir(parents=True, exist_ok=True)
        start = info["header_bytes"]
        with args.extract.open("xb") as out:
            chunk = 1024 * 1024
            for pos in range(start, len(data), chunk):
                out.write(bytes(x ^ 0xFF for x in data[pos:pos + chunk]))
        print(f"Extracted host-side payload: {args.extract}")


if __name__ == "__main__":
    main()

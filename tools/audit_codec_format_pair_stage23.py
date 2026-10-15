#!/usr/bin/env python3
"""Offline X-S10/X-T4 codec + movie format pair audit (no device I/O).

Verify A32 byte reads/writes against privately stored original decoded X6
sections, then compare the corresponding private Ghidra decompilation logs.
This detects the frontend's two-byte state and serialization; it does NOT
establish that it reaches the recorder's independent source snapshot.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct


@dataclass(frozen=True)
class Site:
    section: int
    address: int
    load: bool
    rn: int
    rd: int
    offset: int
    writeback: bool = False


@dataclass(frozen=True)
class Spec:
    model: str
    section2_base: int
    settings_base: int
    codec_setter: int
    format_setter: int
    boot_pair: int
    ui_exporter: int
    codec_id: int
    format_id: int
    ui_export_id: int
    recorder_snapshot: int
    sites: tuple[Site, ...]


SPECS = (
    Spec("xs10", 0x01eaf000, 0x01b880a0, 0x0115b578, 0x0115b610,
         0x01179dc0, 0x01182820, 0x3fc, 0x3fb, 0x3fa, 0x02d9d284,
         (Site(1, 0x0115b5d4, False, 3, 4, 0x5b0),
          Site(1, 0x0115b66c, False, 3, 4, 0x5b1),
          Site(1, 0x0115b634, True, 3, 2, 0x5b1),
          Site(1, 0x0118390c, True, 5, 1, 0x5b0, True),
          Site(2, 0x0210b74c, True, 1, 1, 0x5b0))),
    Spec("xt4", 0x01e0f000, 0x01af2808, 0x0112fd80, 0x0112fe18,
         0x0114dab4, 0x0115663c, 0x3e5, 0x3e4, 0x3e3, 0x02d109d4,
         (Site(1, 0x0112fddc, False, 3, 4, 0x5b0),
          Site(1, 0x0112fe74, False, 3, 4, 0x5b1),
          Site(1, 0x0112fe3c, True, 3, 2, 0x5b1),
          Site(1, 0x01157708, True, 5, 1, 0x5b0, True),
          Site(2, 0x020613d0, True, 1, 1, 0x5b0))),
)


def a32_byte_immediate(word: int) -> tuple[bool, int, int, int, bool]:
    """Decode ARM A32 immediate, positive, pre-indexed LDRB/STRB only."""
    if ((word >> 26) & 3) != 1 or ((word >> 25) & 1) != 0:
        raise ValueError("not immediate ARM single-data-transfer")
    if not ((word >> 24) & 1 and (word >> 23) & 1 and (word >> 22) & 1):
        raise ValueError("not positive pre-indexed byte operation")
    if (word >> 28) == 15:
        raise ValueError("unconditional encoding not supported")
    return (bool((word >> 20) & 1), (word >> 16) & 15,
            (word >> 12) & 15, word & 4095, bool((word >> 21) & 1))


def check_site(site: Site, section1: bytes, section2: bytes,
               section2_base: int) -> int:
    base = 0x01021000 if site.section == 1 else section2_base
    data = section1 if site.section == 1 else section2
    pos = site.address - base
    if pos < 0 or pos % 4 or pos + 4 > len(data):
        raise ValueError("instruction outside aligned decoded section")
    word = struct.unpack_from("<I", data, pos)[0]
    actual = a32_byte_immediate(word)
    expected = (site.load, site.rn, site.rd, site.offset, site.writeback)
    if actual != expected:
        raise ValueError("incorrect ARM site 0x%08x: %r != %r" %
                         (site.address, actual, expected))
    return word


def decompiled(log: str, entry: int) -> str:
    name = "FUN_%08x" % entry
    for match in re.finditer(
        r"TRACE_DECOMP_BEGIN \(GhidraScript\)(.*?)"
        r"TRACE_DECOMP_END \(GhidraScript\)", log, re.S
    ):
        body = match.group(1)
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|char|byte)\s+%s\s*\(" % name, body):
            return body
    raise ValueError("missing decompiled function " + name)


def ensure(condition: bool, reason: str):
    if not condition:
        raise ValueError("codec/format audit: " + reason)


def reported_combined_cases(c: str, byte_address: int) -> dict[int, int]:
    pattern = (r"if\s*\(_DAT_%08x\s*==\s*(0x[0-9a-f]+|\d+)\)"
               r"\s*\{\s*param_1\[0xa1\]\s*=\s*(\d+);" % byte_address)
    return {int(a, 0): int(b) for a, b in re.findall(pattern, c)}


def get_refs(log: str, addr: int) -> int:
    match = re.search(r"PROBE_TARGET addr=%08x refs=(\d+)" % addr, log)
    if not match:
        raise ValueError("missing Ghidra xrefs for %08x" % addr)
    return int(match.group(1))


def audit(spec: Spec, section1: bytes, section2: bytes, reader_log: str,
          high_log: str, xrefs_log: str):
    codec_addr, format_addr = spec.settings_base + 0x5b0, spec.settings_base + 0x5b1
    ensure(codec_addr + 1 == format_addr, "settings not adjacent")
    ensure(spec.recorder_snapshot + 0x5b0 != codec_addr,
           "recorder snapshot and frontend state conflated")
    for site in spec.sites:
        check_site(site, section1, section2, spec.section2_base)

    low = decompiled(reader_log, spec.codec_setter)
    high = decompiled(high_log, spec.format_setter)
    pair = decompiled(high_log, spec.boot_pair)
    exporter = decompiled(reader_log, spec.ui_exporter)

    ensure("DAT_%08x = (char)param_1;" % codec_addr in low,
           "codec low-byte setter missing")
    ensure("eModeMovieCodec" in low, "codec label missing")
    ensure("DAT_%08x = (char)param_1;" % format_addr in high,
           "format high-byte setter missing")
    ensure("eModeMovieFormat" in high, "format label missing")

    for setting, func in ((spec.format_id, spec.format_setter),
                          (spec.codec_id, spec.codec_setter)):
        ensure("0x%x" % setting in pair and "FUN_%08x(uVar2 & 0xff)" % func in pair,
               "initialization does not map both menu values to setters")

    converter = "FUN_%08x" % (0x0102300c if spec.model == "xs10" else 0x01022f7c)
    ensure("%s(0x%x,DAT_%08x,3,0)" %
           (converter, spec.ui_export_id, codec_addr) in exporter,
           "frontend serializer not connected to low-byte state")
    ensure("param_1[0x90] = " in exporter,
           "frontend export field 0x90 not found")
    cases = reported_combined_cases(exporter, codec_addr)
    ensure(cases == {1: 0, 0: 1, 0x101: 2, 0x100: 3},
           "codec+format composite code was not recovered")

    codec_refs = get_refs(xrefs_log, spec.codec_setter)
    format_refs = get_refs(xrefs_log, spec.format_setter)
    ensure(codec_refs >= 2 and format_refs >= 2,
           "Ghidra xref counts unexpectedly small")
    if spec.model == "xt4":
        extra = decompiled(high_log, 0x0115b234)
        ensure("FUN_%08x(uVar1 & 0xff)" % spec.codec_setter in extra,
               "X-T4 conditional mode loader lacks codec setter")
        ensure("FUN_%08x(uVar1 & 0xff)" % spec.format_setter in extra,
               "X-T4 conditional mode loader lacks format setter")
        ensure("0x3e4" in extra and "0x3e5" in extra,
               "X-T4 conditional mode loader settings IDs missing")

    return {
        "model": spec.model,
        "codec_gui_address": "0x%08x" % codec_addr,
        "format_gui_address": "0x%08x" % format_addr,
        "recorder_snapshot_codec_address": "0x%08x" % (spec.recorder_snapshot + 0x5b0),
        "a32_byte_sites_verified": len(spec.sites),
        "menu_codec_setting_id": "0x%x" % spec.codec_id,
        "menu_format_setting_id": "0x%x" % spec.format_id,
        "frontend_export_setting_id": "0x%x" % spec.ui_export_id,
        "composite_ui_cases": {hex(k): v for k,v in sorted(cases.items())},
        "known_direct_codec_setter_xrefs": codec_refs,
        "known_direct_format_setter_xrefs": format_refs,
        "extra_xt4_mode_reload_path_observed": spec.model == "xt4",
        "xs10_extra_mode_reload_absent_proven": False,
        "frontend_to_recorder_snapshot_proven": False,
        "internal_hevc_main10_proven": False,
        "internal_4k60_proven": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("output"),
                        help="private offline analysis folder")
    args = parser.parse_args()
    results = []
    for s in SPECS:
        folder = args.output
        data = lambda filename: (folder / filename).read_text(encoding="utf-8")
        results.append(audit(
            s, (folder / ("x6-%s/section-1.bin" % s.model)).read_bytes(),
            (folder / ("x6-%s/section-2.bin" % s.model)).read_bytes(),
            data("%s_stage23_codec_ui_readers.log" % s.model),
            data("%s_stage23_codec_highbyte.log" % s.model),
            data("%s_stage23_codec_ui_reader_callers.log" % s.model)
            + "\n" + data("%s_stage23_pair_call_xrefs.log" % s.model),
        ))
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print("OFFLINE ONLY: separate UI settings, still no proven recorder bridge or Main10/4K60.")


if __name__ == "__main__":
    main()

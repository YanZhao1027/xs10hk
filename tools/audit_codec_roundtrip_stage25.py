#!/usr/bin/env python3
"""Verify a bidirectional Recorder *configuration* cycle, offline only.

X-S10 3.11 / X-T4 2.12:
  raw snapshot +0x5B0/+0x5B1 -> working+offset ->
  active Recorder CONFIG bytes -> response/export struct +0x5B0/+0x5B1.

This is NOT a GUI->snapshot edge, Main10 encoder confirmation, 4K60 capture,
or a camera patch. Inputs are private original unpacked sections and Ghidra logs.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json
import re
import struct


@dataclass(frozen=True)
class Site:
    address: int
    load: bool
    rn: int
    rd: int
    offset: int


@dataclass(frozen=True)
class Spec:
    model: str
    section2_base: int
    snapshot: int
    snapshot_literal: int
    working: int
    active: int
    mirror: int
    working_offset: int
    copy_bytes: int
    gui_codec: int
    producer: int
    translator: int
    commit_wrapper: int
    reverse_exporter: int
    commit: int
    parent_calls: tuple[tuple[int,int], ...]
    forward_sites: tuple[Site, ...]
    reverse_sites: tuple[Site, ...]
    dest_var: str
    source_var: str
    copy_function: int
    subsequent_start: int


SPECS = {
    "xs10": Spec(
        "xs10", 0x01eaf000,
        0x02d9d284, 0x0221d8e4, 0x02d9cc60, 0x01c24dd8,
        0x01c25498, 0x430, 0x478, 0x01b88650,
        0x0221d1bc, 0x012c9500, 0x012c0878,
        0x012be684, 0x012bd110,
        ((0x0221d210,0x012c9500),(0x0221d22c,0x012c0878),
         (0x0221d298,0x012be684)),
        (Site(0x012c9a40,True,5,3,0x5b0),
         Site(0x012c9a44,False,4,3,0x430),
         Site(0x012c9a48,True,5,3,0x5b1),
         Site(0x012c9a4c,False,4,3,0x431)),
        (Site(0x012beb8c,True,5,3,0x430),
         Site(0x012beb90,False,4,3,0x5b0),
         Site(0x012beb94,True,5,3,0x431),
         Site(0x012beb98,False,4,3,0x5b1)),
        "iVar3", "iVar11", 0x012a9148, 0x02d9d836
    ),
    "xt4": Spec(
        "xt4", 0x01e0f000,
        0x02d109d4, 0x0218a2fc, 0x02d103b0, 0x01b83540,
        0x01b83c00, 0x434, 0x47c, 0x01af2db8,
        0x02189bd4, 0x012a313c, 0x01299004,
        0x01296d38, 0x01295780,
        ((0x02189c28,0x012a313c),(0x02189c44,0x01299004),
         (0x02189cb0,0x01296d38)),
        (Site(0x012a3690,True,5,3,0x5b0),
         Site(0x012a3694,False,4,3,0x434),
         Site(0x012a3698,True,5,3,0x5b1),
         Site(0x012a369c,False,4,3,0x435)),
        (Site(0x01297250,True,5,3,0x434),
         Site(0x01297254,False,4,3,0x5b0),
         Site(0x01297258,True,5,3,0x435),
         Site(0x0129725c,False,4,3,0x5b1)),
        "iVar4", "iVar12", 0x01281848, 0x02d10f86
    ),
}


def require(ok: bool, message: str):
    if not ok:
        raise ValueError("stage25 Recorder config cycle: " + message)


def get_word(section: bytes, base: int, at: int):
    off = at - base
    if off < 0 or off % 4 or off + 4 > len(section):
        raise ValueError("A32 offset out of original section")
    return struct.unpack_from("<I", section, off)[0]


def decode_byte_transfer(word: int):
    """Immediate, preindexed positive-offset LDRB/STRB, conditional AL."""
    if word >> 28 != 14 or (word >> 26) & 3 != 1 or (word >> 25) & 1:
        raise ValueError("not standard A32 byte instruction")
    needed = (1 << 24) | (1 << 23) | (1 << 22)
    if (word & needed) != needed or (word >> 21) & 1:
        raise ValueError("wrong LDRB/STRB addressing mode")
    return (bool((word >> 20) & 1),
            (word >> 16) & 15, (word >> 12) & 15, word & 4095)


def check_site(section: bytes, site: Site):
    got = decode_byte_transfer(get_word(section, 0x01021000, site.address))
    expected = (site.load, site.rn, site.rd, site.offset)
    require(got == expected,
            "%08x: %r != %r" % (site.address, got, expected))
    return site.address


def decode_branch(word: int, at: int):
    if word >> 28 != 14 or (word >> 25) & 7 != 5 or not (word >> 24) & 1:
        raise ValueError("not an A32 AL BL")
    delta = word & 0xffffff
    if delta & 0x800000:
        delta -= 0x1000000
    return (at + 8 + (delta << 2)) & 0xffffffff


def function_c(log: str, entry: int) -> str:
    name = "FUN_%08x" % entry
    for segment in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        block = segment.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|char|byte)"
                     r"\s+(?:\*\s*)?" + name + r"\s*\(", block):
            return block
    raise ValueError("missing Ghidra function " + name)


def write_span_touches_pair(start: int, size: int) -> bool:
    if start < 0 or size < 0:
        raise ValueError("invalid write span")
    return size > 0 and start < 0x5b2 and start + size > 0x5b0


def skip_copy_span_proof(c: str, spec: Spec):
    """Only certify the two bounded copy spans, not every possible alias."""
    v = spec.dest_var
    require(
        ("*(undefined4 *)(%s + 0x5ac) = " % v) in c,
        "copy before byte pair not located"
    )
    expected = ("FUN_%08x(%s + 0x5b2,0x%x,3)" %
                (spec.copy_function, v, spec.subsequent_start))
    require(expected in c, "copy after byte pair not located")
    require(not write_span_touches_pair(0x5ac, 4)
            and not write_span_touches_pair(0x5b2, 3),
            "adjacent fields overwrite +5B0/+5B1")
    # No direct same-variable writes to these bytes in the recovered function.
    for off in ("0x5b0", "0x5b1"):
        require(not re.search(r"\*\(undefined\d+ \*\)\(%s \+ %s\)\s*=" %
                              (v, off), c),
                "explicit post-export overwrite of "+off)
        require("%s[%s] =" % (v, off) not in c,
                "array-style post-export overwrite of "+off)
    return [[hex(0x5ac), 4], [hex(0x5b2), 3]]


def audit(spec: Spec, section1: bytes, section2: bytes,
          parent_c: str, translator_c: str, reverse_c: str,
          memcpy_c: str, getter_c: str):
    # Crosscheck both adjacent bytes independently against ORIGINAL A32.
    for site in (*spec.forward_sites, *spec.reverse_sites):
        check_site(section1, site)

    # Parent links raw -> working -> active -> reverse snapshot, same call site.
    addresses = [addr for addr, target in spec.parent_calls]
    require(addresses == sorted(addresses), "parent BL order changed")
    for call, target in spec.parent_calls:
        got = decode_branch(get_word(section2,spec.section2_base,call),call)
        require(got == target, "unexpected call target from 0x%x" % call)
    ordered_targets = (spec.translator, spec.commit_wrapper,
                       spec.reverse_exporter)
    c_positions = [parent_c.find("FUN_%08x(" % func)
                   for func in ordered_targets]
    require(-1 not in c_positions and c_positions == sorted(c_positions)
            and len(set(c_positions)) == 3,
            "parent Ghidra C forward/commit/reverse order")
    require(("FUN_%08x(%s)" %
             (spec.reverse_exporter, spec.dest_var)) in parent_c,
            "reverse exporter not called with parent output buffer")
    require(("FUN_%08x(%s)" %
             (spec.commit_wrapper, "iVar1")) in parent_c,
            "missing working-pointer commit wrapper")
    require("DAT_%08x" % spec.snapshot_literal in parent_c,
            "snapshot pointer literal absent in parent")
    before_copy = parent_c.find("*(undefined4 *)(%s + 0x5ac)" % spec.dest_var)
    after_copy = parent_c.find("FUN_%08x(%s + 0x5b2" %
                               (spec.copy_function, spec.dest_var))
    require(c_positions[2] < before_copy < after_copy,
            "reverse export must precede both adjacent source copies")
    spans = skip_copy_span_proof(parent_c, spec)

    for byte_delta in (0,1):
        forward = ("*(undefined1 *)(param_1 + 0x%x) = param_2[0x%x];" %
                   (spec.working_offset + byte_delta, 0x5b0 + byte_delta))
        reverse = ("param_1[0x%x] = DAT_%08x;" %
                   (0x5b0+byte_delta,
                    spec.active + spec.working_offset + byte_delta))
        require(forward in translator_c, "forward snapshot-to-working byte")
        require(reverse in reverse_c, "reverse active-to-export byte")

    for active_base in (spec.active,spec.mirror):
        require(
            "func_0x" in memcpy_c
            and ("0x%x,param_1,0x%x)" %
                 (active_base, spec.copy_bytes)) in memcpy_c,
            "bulk commit into active/mirror runtime state"
        )
    require(spec.working_offset + 1 < spec.copy_bytes,
            "both bytes lie outside bulk memcpy range")
    getter_expected = ("return DAT_%08x;" %
                       (spec.active+spec.working_offset))
    require(getter_expected in getter_c,
            "recorder getter does not read active mode byte")
    require(spec.gui_codec != spec.active+spec.working_offset
            and spec.gui_codec != spec.snapshot+0x5b0,
            "GUI byte conflated with recorder state")

    # Only addresses appearing as literal uint32s; dynamically formed writes
    # and pointer aliases remain UNCHECKED.
    direct_source_codec_literals = sum(
        section.count(struct.pack("<I", spec.snapshot+0x5b0))
        for section in (section1,section2)
    )
    return {
        "model": spec.model,
        "original_a32_codec_format_sites_verified": 8,
        "original_a32_parent_calls_verified": 3,
        "config_snapshot_codec": "0x%08x" % (spec.snapshot+0x5b0),
        "recorder_active_config_codec": "0x%08x" %
                                        (spec.active+spec.working_offset),
        "gui_codec": "0x%08x" % spec.gui_codec,
        "roundtrip_source_to_runtime_to_export_function_order": True,
        "reverse_export_before_neighboring_source_copies": True,
        "adjacent_source_copy_ranges": spans,
        "raw_four_byte_literals_referencing_source_codec": direct_source_codec_literals,
        "computed_pointer_writers_covered_by_literal_scan": False,
        "gui_to_recorder_source_writer_proven": False,
        "bitstream_main10_proven": False,
        "sensor_4k60_proven": False,
        "camera_modified": False,
    }


def main():
    ap=ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    args=ap.parse_args()
    results=[]
    for spec in SPECS.values():
        folder=args.output
        read=lambda filename:(folder/filename).read_text(encoding="utf-8")
        log_parent=read("%s_stage25_snapshot_producer_candidates.log"%spec.model)
        log_rev=read("%s_stage25_snapshot_populate_pipeline.log"%spec.model)
        log_for=read("%s_runtime_430_write_sites_stage20.log"%spec.model)
        log_com=read("%s_runtime_config_state_commit_funcs_stage20.log"%spec.model)
        log_get=read("%s_actual_movie_codec_selection_at_context.log"%spec.model)
        section1=(folder/("x6-%s/section-1.bin"%spec.model)).read_bytes()
        section2=(folder/("x6-%s/section-2.bin"%spec.model)).read_bytes()
        results.append(audit(
            spec,section1,section2,function_c(log_parent,spec.producer),
            function_c(log_for,spec.translator),
            function_c(log_rev,spec.reverse_exporter),
            function_c(log_com,spec.commit),
            function_c(log_get,(0x012c048c if spec.model=="xs10"
                                else 0x01298c18))))
    print(json.dumps(results,indent=2,ensure_ascii=False))
    print("OFFLINE ONLY: Recorder config roundtrip, NOT GUI source writer or Main10/4K60.")


if __name__=="__main__":
    main()

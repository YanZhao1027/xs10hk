#!/usr/bin/env python3
"""Audit Fujifilm movie codec configuration commits, offline only.

For exact original X-S10 v3.11 and X-T4 v2.12 decoded firmware and private
Ghidra logs, trace:

    raw settings snapshot [+0x5b0] ->
    working context [+0x430 X-S10 / +0x434 X-T4] ->
    bulk memcpy to active runtime state ->
    same global byte returned by recorder getter

The commit function copies 0x478 / 0x47c bytes, respectively. That size
INCLUDES the codec byte: the earlier standalone setter is not the only
possible updater. The runtime/global serializer also has a reverse snapshot
export, and an independent eModeMovieCodec global is NOT synonymous with
the recorder runtime byte.

This establishes an executable *data-movement path*, not that the camera UI
ever permits an HEVC mode, that the snapshot can hold 1, or that VPU Main10
can initialize. No USB, device, firmware edit, DAT output, or live camera.
"""
from dataclasses import dataclass
from pathlib import Path
from argparse import ArgumentParser
import re
import struct


@dataclass(frozen=True)
class ModelSpec:
    name: str
    section1_base: int
    section2_base: int
    snapshot_ptr_literal: int
    working_ptr_literal: int
    snapshot_expected: int
    working_expected: int
    active_base: int
    mirror_base: int
    codec_byte: int
    e_mode_codec_byte: int
    destination_offset: int
    bytes_copied: int
    translator: int
    commit: int
    wrapper: int
    parent: int
    reverse_export: int
    runtime_getter: int
    memcpy_stub: int
    snapshot_arg: str
    work_arg: str


SPECS = (
    ModelSpec("xt4", 0x01021000, 0x01E0F000,
              0x0218A2FC, 0x0218A300,
              0x02D109D4, 0x02D103B0,
              0x01B83540, 0x01B83C00,
              0x01B83974, 0x01AF2DB8, 0x434, 0x47C,
              0x012A313C, 0x01295780, 0x01299004,
              0x02189BD4, 0x01296D38, 0x01298C18,
              0x00059108, "iVar12", "iVar1"),
    ModelSpec("xs10", 0x01021000, 0x01EAF000,
              0x0221D8E4, 0x0221D8E8,
              0x02D9D284, 0x02D9CC60,
              0x01C24DD8, 0x01C25498,
              0x01C25208, 0x01B88650, 0x430, 0x478,
              0x012C9500, 0x012BD110, 0x012C0878,
              0x0221D1BC, 0x012BE684, 0x012C048C,
              0x00059328, "iVar11", "iVar1"),
)


def assert_evidence(value, description):
    if not value:
        raise ValueError("Codec snapshot path missing: " + description)


def pointer_from_section(data: bytes, base: int, literal: int) -> int:
    offset = literal - base
    if offset < 0 or offset + 4 > len(data) or offset % 4 != 0:
        raise ValueError("Snapshot pointer literal not in aligned section")
    return struct.unpack_from("<I", data, offset)[0]


def c_function(log: str, func_address: int) -> str:
    name = f"FUN_{func_address:08x}"
    for segment in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c = segment.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(rf"^\s*(?:void|undefined\d|int|uint|byte|char)\s+"
                     rf"(?:\*\s*)?{name}\s*\(", c, re.M):
            return c
    raise ValueError("Ghidra function body missing: " + name)


def wrapper_preserves_r0(log: str, start: int, target_call_addr: int) -> bool:
    """The observed wrapper does not change register R0 before commit BL.

    This matters because Ghidra's C prototype incorrectly treats these
    92-byte wrappers as void() even though callers pass their context
    pointer as R0. Verify actual ARM instructions independently.
    """
    seen = {}
    for match in re.finditer(
        r"TRACE_INSN ([0-9a-f]{8}) (.*?) \(GhidraScript\)", log
    ):
        addr = int(match.group(1), 16)
        if start <= addr <= target_call_addr:
            seen[addr] = match.group(2)
    if start not in seen or target_call_addr not in seen:
        return False
    if not seen[target_call_addr].startswith("bl "):
        return False
    for addr, asm in seen.items():
        if addr == target_call_addr:
            continue
        # Reject functions that clobber the first argument or call anything
        # before forwarding it, not merely wrappers that contain the word R0.
        if re.search(
            r"^(?:movw?|movt|cpy|ldr(?:b|h|sb|sh)?|add|sub|eor|and|orr|"
            r"bic|mvn|rsb|mul|ldm\w*)\s+r0(?:\s*,|\s|$)",
            asm
        ):
            return False
        if re.match(r"^(?:bl|blx)\s", asm):
            return False
    return True


def audit(spec: ModelSpec, *, snapshot_ptr: int, working_ptr: int,
          translator_c: str, memcpy_c: str, parent_c: str,
          wrapper_asm: str, reverse_c: str, getter_c: str):
    m = spec.name
    assert_evidence(snapshot_ptr == spec.snapshot_expected,
                    f"{m}: raw source snapshot literal")
    assert_evidence(working_ptr == spec.working_expected,
                    f"{m}: raw intermediate working buffer literal")
    assert_evidence(spec.active_base + spec.destination_offset ==
                    spec.codec_byte, f"{m}: runtime codec offset")
    assert_evidence(spec.destination_offset < spec.bytes_copied,
                    f"{m}: codec byte must lie inside copied span")
    assert_evidence(
        re.search(
            rf"\*\(undefined1 \*\)\(param_1 \+ "
            rf"0x{spec.destination_offset:x}\)\s*=\s*param_2\[0x5b0\]\s*;",
            translator_c
        ) is not None,
        f"{m}: snapshot[+5b0] -> working[+{spec.destination_offset:x}]"
    )
    assert_evidence(
        f"FUN_{spec.translator:08x}" in translator_c,
        f"{m}: identified translator"
    )
    assert_evidence(
        f"FUN_{spec.commit:08x}" in memcpy_c and
        re.search(
            rf"func_0x{spec.memcpy_stub:08x}"
            rf"\(0x{spec.active_base:x},param_1,"
            rf"0x{spec.bytes_copied:x}\)\s*;", memcpy_c
        ) is not None and
        re.search(
            rf"func_0x{spec.memcpy_stub:08x}"
            rf"\(0x{spec.mirror_base:x},param_1,"
            rf"0x{spec.bytes_copied:x}\)\s*;", memcpy_c
        ) is not None,
        f"{m}: working context bulk-copied to active and mirrored state"
    )
    # Recovered decompiled caller explicitly passes the SAME work pointer
    # to translator and to wrapper. Wrapper passes R0 intact into memcpy.
    assert_evidence(
        f"FUN_{spec.parent:08x}" in parent_c and
        f"{spec.snapshot_arg} = DAT_{spec.snapshot_ptr_literal:08x};"
        in parent_c and
        f"{spec.work_arg} = DAT_{spec.working_ptr_literal:08x};"
        in parent_c and
        re.search(
            rf"FUN_{spec.translator:08x}"
            rf"\(DAT_{spec.working_ptr_literal:08x},"
            rf"{spec.snapshot_arg},", parent_c
        ) is not None and
        f"FUN_{spec.wrapper:08x}({spec.work_arg});" in parent_c,
        f"{m}: parent passes the same working context to translator/commit"
    )
    call_sites = {
        "xt4": 0x01299020,
        "xs10": 0x012C0894,
    }
    assert_evidence(
        wrapper_preserves_r0(wrapper_asm, spec.wrapper, call_sites[m])
        and f"bl 0x{spec.commit:08x}" in wrapper_asm,
        f"{m}: wrapper forwards original R0 to memcpy"
    )
    assert_evidence(
        re.search(
            rf"param_1\[0x5b0\]\s*=\s*DAT_{spec.codec_byte:08x};",
            reverse_c
        ) is not None and
        f"FUN_{spec.reverse_export:08x}" in reverse_c,
        f"{m}: independent global -> snapshot reverse exporter"
    )
    assert_evidence(
        f"FUN_{spec.runtime_getter:08x}" in getter_c and
        re.search(rf"\breturn\s+DAT_{spec.codec_byte:08x}\s*;", getter_c)
        is not None,
        f"{m}: recorder runtime getter reads active byte"
    )
    assert_evidence(spec.e_mode_codec_byte != spec.codec_byte,
                    f"{m}: separate eModeMovieCodec vs runtime registers")
    return {
        "model": m,
        "snapshot_pointer": hex(snapshot_ptr),
        "snapshot_mode_byte": hex(snapshot_ptr+0x5B0),
        "working_pointer": hex(working_ptr),
        "working_mode_byte": hex(working_ptr+spec.destination_offset),
        "active_state_base": hex(spec.active_base),
        "active_mode_byte": hex(spec.codec_byte),
        "mirror_state_base": hex(spec.mirror_base),
        "bulk_copy_size": hex(spec.bytes_copied),
        "snapshot_offset": "0x5B0",
        "active_offset": hex(spec.destination_offset),
        "decoder_clamps_codec_on_copy": False,
        "standalone_setter_only_write_path": False,
        "eModeMovieCodec_is_different_global": True,
        "snapshot_value_one_actual_UI_reachable": "UNPROVEN",
        "HEVC_Main10_recording_verified": False,
    }


def load_data(folder: Path, spec: ModelSpec):
    m = spec.name
    def load(name):
        return (folder/name).read_text(encoding="utf-8")
    raw = (folder/f"x6-{m}"/"section-2.bin").read_bytes()
    return {
        "snapshot_ptr": pointer_from_section(
            raw, spec.section2_base, spec.snapshot_ptr_literal),
        "working_ptr": pointer_from_section(
            raw, spec.section2_base, spec.working_ptr_literal),
        "translator_c": c_function(
            load(f"{m}_runtime_430_write_sites_stage20.log"),
            spec.translator),
        "memcpy_c": c_function(
            load(f"{m}_runtime_config_state_commit_funcs_stage20.log"),
            spec.commit),
        "parent_c": c_function(
            load(f"{m}_config_struct_copy_callers_stage20.log"),
            spec.parent),
        "wrapper_asm": load(f"{m}_global_config_memcpy_predecessors_stage20.log"),
        "reverse_c": c_function(
            load(f"{m}_codec_state_companion_reader.log"),
            spec.reverse_export),
        "getter_c": c_function(
            load(f"{m}_actual_movie_codec_selection_at_context.log"),
            spec.runtime_getter),
    }


def main():
    p = ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("output"),
                   help="private local decompiled sections/Ghidra logs")
    args = p.parse_args()
    for spec in SPECS:
        result = audit(spec, **load_data(args.output, spec))
        for key, value in result.items():
            print(f"{spec.name}.{key}: {value}")
    print("FULL OFFLINE SNAPSHOT -> ACTIVE CODEC COPY PATH VERIFIED. "
          "No claim that a current X-S10 menu permits HEVC Main10. "
          "No camera or firmware modified.")


if __name__ == "__main__":
    main()

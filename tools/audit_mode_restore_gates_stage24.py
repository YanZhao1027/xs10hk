#!/usr/bin/env python3
"""Offline comparison of Fuji X-S10/X-T4 movie mode restore control flow.

Use private, original X6 section bytes and local Ghidra decompilation logs
to confirm a unique A32 instruction fingerprint, then recover the diverging
call edges in each model. NEVER connects to a camera, patches firmware,
or claims HEVC Main10/4K60 hardware support.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct


# ldrb r3,[r4]; cmp r3,#0x2d; mov r2,#0; mov r1,#8
# This complete 16-byte A32 signature is unique in each model's section-2.
A32_RESTORE_FINGERPRINT = bytes.fromhex(
    "0030d4e52d0053e30020a0e30810a0e3"
)


@dataclass(frozen=True)
class Spec:
    name: str
    section2_base: int
    restore_addr: int
    signature_addr: int
    main_dispatcher: int
    gui_codec: int
    gui_format: int
    initializer: int


SPECS = {
    "xs10": Spec(
        "xs10", 0x01eaf000, 0x020eb5f4, 0x020eb638,
        0x0118b280, 0x01b88650, 0x01b88651, 0x01179dc0,
    ),
    "xt4": Spec(
        "xt4", 0x01e0f000, 0x02043ab4, 0x02043af4,
        0x0115e9c8, 0x01af2db8, 0x01af2db9, 0x0114dab4,
    ),
}


def ensure(ok: bool, what: str) -> None:
    if not ok:
        raise ValueError("stage24 mode-restore evidence mismatch: " + what)


def find_signature(section: bytes, base: int) -> list[int]:
    found = []
    start = 0
    while True:
        pos = section.find(A32_RESTORE_FINGERPRINT, start)
        if pos < 0:
            return found
        found.append(base + pos)
        start = pos + 1


def read_word(data: bytes, base: int, address: int) -> int:
    off = address - base
    if off < 0 or off % 4 or off + 4 > len(data):
        raise ValueError("unaligned/outside original section: 0x%08x" % address)
    return struct.unpack_from("<I", data, off)[0]


def decode_arm_branch(word: int, address: int):
    """Decode 32-bit ARM B/BL: (condition, link, absolute target)."""
    if (word >> 25) & 7 != 5 or word >> 28 == 15:
        raise ValueError("not A32 B/BL instruction")
    imm24 = word & 0xffffff
    if imm24 & 0x800000:
        imm24 -= 0x1000000
    return (word >> 28, bool((word >> 24) & 1),
            (address + 8 + (imm24 << 2)) & 0xffffffff)


def check_branch(data: bytes, base: int, at: int,
                 cond: int, link: bool, target: int) -> int:
    got = decode_arm_branch(read_word(data, base, at), at)
    ensure(got == (cond, link, target & 0xffffffff),
           "branch at 0x%08x: %r != %r" %
           (at, got, (cond, link, target)))
    return at


def decode_cond_ldrb(word: int):
    """Return (condition, base register, dst register, imm12) for LDRB."""
    if ((word >> 26) & 3) != 1 or (word >> 25) & 1:
        raise ValueError("wrong LDRB instruction family")
    required = (1 << 24) | (1 << 23) | (1 << 22) | (1 << 20)
    ensure((word & required) == required, "not pre-indexed +imm LDRB")
    ensure(not (word & (1 << 21)), "unexpected writeback LDRB")
    return (word >> 28, (word >> 16) & 15,
            (word >> 12) & 15, word & 0xfff)


def get_decomp(log: str, entry: int) -> str:
    name = "FUN_%08x" % entry
    for match in re.finditer(
        r"TRACE_DECOMP_BEGIN \(GhidraScript\)(.*?)"
        r"TRACE_DECOMP_END \(GhidraScript\)", log, re.S
    ):
        body = match.group(1)
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|byte|char)\s+"
                     + name + r"\s*\(", body):
            return body
    raise ValueError("missing Ghidra decompilation: " + name)


def function_references(log: str, address: int) -> set[int]:
    needle = "PROBE_TARGET addr=%08x refs=" % address
    i = log.find(needle)
    if i < 0:
        raise ValueError("missing Ghidra xref target: %08x" % address)
    j = log.find("PROBE_TARGET addr=", i + len(needle))
    scope = log[i:j] if j > 0 else log[i:]
    match = re.search(r"PROBE_TARGET addr=%08x refs=(\d+)" %
                      address, scope)
    if not match:
        raise ValueError("Ghidra xref count missing")
    references = {
        int(value, 16) for value in re.findall(
            r"PROBE_REF from=([0-9a-f]{8}) to=%08x type=UNCONDITIONAL_CALL" %
            address, scope
        )
    }
    expected = int(match.group(1))
    if expected < len(references):
        raise ValueError("Ghidra xref count smaller than reported calls")
    return references


def audit(spec: Spec, section1: bytes, section2: bytes,
          main_log: str, restore_log: str, helper_log: str, xrefs: str):
    sec1_base = 0x01021000
    loc = find_signature(section2, spec.section2_base)
    ensure(loc == [spec.signature_addr],
           "%s unique section2 byte signature" % spec.name)
    ensure(spec.gui_format == spec.gui_codec + 1, "GUI pair layout")

    # The same literal A32 instructions precede both models' divergence.
    eq_load = read_word(section2, spec.section2_base, spec.signature_addr + 0x14)
    ne_load = read_word(section2, spec.section2_base, spec.signature_addr + 0x18)
    if spec.name == "xt4":
        ensure(decode_cond_ldrb(eq_load) == (0, 3, 0, 0x832),
               "X-T4 movie-mode selection byte")
        ensure(decode_cond_ldrb(ne_load) == (1, 3, 0, 0x831),
               "X-T4 nonmovie selection byte")
    else:
        ensure(decode_cond_ldrb(eq_load) == (0, 3, 0, 0x582),
               "X-S10 movie-mode selection byte")
        ensure(decode_cond_ldrb(ne_load) == (1, 3, 0, 0x581),
               "X-S10 nonmovie selection byte")

    restore = get_decomp(restore_log, spec.restore_addr)
    main = get_decomp(main_log, spec.main_dispatcher)
    ensure("FUN_%08x" % spec.initializer in main,
           "main dispatcher does not call paired menu initializer")

    if spec.name == "xt4":
        reloader = 0x0115b234
        specific = get_decomp(main_log, reloader)
        ensure("0x3e4" in specific and "0x3e5" in specific,
               "extra mode reloader missing format/codec setting IDs")
        ensure("FUN_0112fe18(uVar1 & 0xff)" in specific
               and "FUN_0112fd80(uVar1 & 0xff)" in specific,
               "extra mode reloader missing both setters")
        check_branch(section1, sec1_base, 0x0115f2d0, 14, True, reloader)
        check_branch(section2, spec.section2_base,
                     0x02043b14, 14, True, reloader)
        ensure("FUN_0115b234();" in restore,
               "X-T4 restore missing direct paired reload")
        ensure("DAT_0115f340 + 0x834" in main
               and "FUN_0115b234();" in main,
               "X-T4 main mode reload flag missing")
        callers = function_references(xrefs, reloader)
        ensure({0x0115f2d0, 0x02043b14}.issubset(callers),
               "X-T4 verified reload callsites not both indexed")
        output = {
            "direct_extra_codec_format_reload": True,
            "extra_reloader": hex(reloader),
            "extra_reloader_call_sites": ["0x0115f2d0", "0x02043b14"],
            "main_conditional_reload_flag": "DAT_0115F340+0x834",
            "section2_restore_alternative": False,
        }
    else:
        # XS10 has the same unique prefix, but a DIFFERENT path afterwards.
        ensure(read_word(section2, spec.section2_base, 0x020eb658)
               == 0xe30830a0, "XS10 restores then starts MOVW, not XT4 BL")
        check_branch(section2, spec.section2_base,
                     0x020eb668, 0, False, 0x020eb688)
        check_branch(section2, spec.section2_base,
                     0x020eb67c, 14, True, 0x02058368)
        check_branch(section2, spec.section2_base,
                     0x020583ac, 14, True, spec.main_dispatcher)
        check_branch(section1, sec1_base, 0x0118b79c,
                     14, True, spec.initializer)
        helper = get_decomp(helper_log, 0x02058368)
        ensure("if (DAT_01b880a0 != '-')" in restore
               and "FUN_02058368(local_11[0])" in restore,
               "XS10 restore is not conditional nonmovie path")
        ensure("FUN_0118b280(DAT_01b880a0,0x23)" in helper,
               "XS10 alternative path not invoking main mode dispatcher")
        ensure("FUN_01179dc0(param_1)" in main,
               "XS10 main missing paired menu initialization")
        callers = function_references(xrefs, 0x02058368)
        ensure(0x020eb67c in callers,
               "XS10 alternative restore helper call not Ghidra verified")
        ensure("FUN_0115b234" not in restore
               and "FUN_0115b234" not in main,
               "XS10 body unexpectedly includes XT4-only address")
        output = {
            "direct_extra_codec_format_reload": False,
            "additional_codec_format_reload_elsewhere_ruled_out": False,
            "nonmovie_branch_condition": "GUI mode != 0x2D",
            "nonmovie_branch_skip": "BEQ 0x020EB668 -> 0x020EB688",
            "alt_call": "BL 0x020EB67C -> 0x02058368",
            "alt_chain": [
                "0x020EB5F4", "0x02058368", "0x0118B280",
                "0x01179DC0"
            ],
            "section2_restore_alternative": True,
        }

    return {
        "model": spec.name,
        "section2_fingerprint_matches": 1,
        "section2_fingerprint_address": hex(spec.signature_addr),
        "gui_codec_byte": hex(spec.gui_codec),
        "gui_format_byte": hex(spec.gui_format),
        "mode_dispatcher": hex(spec.main_dispatcher),
        "mode_restore_entry": hex(spec.restore_addr),
        "paired_menu_initializer_present": True,
        **output,
        "gui_to_recorder_snapshot_proven": False,
        "actual_h265_main10_recording_proven": False,
        "actual_4k60_sensor_capture_proven": False,
        "generated_firmware_patch": False,
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("output"),
                        help="private original firmware and Ghidra log directory")
    args = parser.parse_args()
    results = []
    for model, spec in SPECS.items():
        folder = args.output
        contents = lambda path: (folder / path).read_text(encoding="utf-8")
        main_log = contents(f"{model}_stage24_mode_switch_callers.log")
        restore_log = contents(
            "xt4_stage24_mode_switch_callers.log" if model == "xt4"
            else "xs10_stage24_analog_section2_mode_switch.log"
        )
        helper_log = (restore_log if model == "xt4"
                      else contents("xs10_stage24_alt_mode_handlers.log"))
        xrefs = contents(f"{model}_stage24_mode_restore_xrefs.log")
        results.append(audit(
            spec, (folder / f"x6-{model}/section-1.bin").read_bytes(),
            (folder / f"x6-{model}/section-2.bin").read_bytes(),
            main_log, restore_log, helper_log, xrefs
        ))
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print("OFFLINE ONLY. GUI->Recorder, Main10, Sensor/ISP 4K60 remain UNPROVEN.")


if __name__ == "__main__":
    main()

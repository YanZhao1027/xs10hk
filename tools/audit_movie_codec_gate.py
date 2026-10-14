#!/usr/bin/env python3
"""Audit the runtime movie-codec selection -> HEVC driver-init field path.

OFFLINE ONLY. Reads locally saved Ghidra logs and X6 decoded firmware
sections. NEVER communicates with camera or produces a patch.

For exact original X-T4 2.12 and X-S10 3.11 decoded firmware:
  runtime global byte -> 32B getter -> recorder context +0xADDA ->
  HEVC driver init struct +0x188 -> bitdepth-related validation.

This identifies a decision path. It does NOT establish that a visible
menu writes codec=1, that the setter is used, or that Main10 recording
is possible. Simple setter may be called indirectly, or may be unused.
"""
from dataclasses import dataclass
from pathlib import Path
from array import array
import re
import struct
import argparse


@dataclass(frozen=True)
class Model:
    name: str
    getter: int
    setter: int
    runtime_byte: int
    recorder: int
    init_struct: int
    validator: int
    highspeed_classify: int


MODELS = (
    Model("xt4", 0x01298C18, 0x01298C38, 0x01B83974,
          0x0224B65C, 0x028A5150, 0x011CCE88, 0x0223DCAC),
    Model("xs10", 0x012C048C, 0x012C04AC, 0x01C25208,
          0x022DEE64, 0x02945A08, 0x011F97DC, 0x022D171C),
)


def ensure(predicate: bool, name: str):
    if not predicate:
        raise ValueError("codec dataflow not confirmed: " + name)


def scan_arm_bl(blob: bytes, base: int, target: int) -> tuple[int, ...]:
    """Pure A32 BL scan; excludes condition 0xF and non-BL instructions."""
    if len(blob) % 4:
        raise ValueError("ARM image length not 4-byte aligned")
    words = array("I")
    words.frombytes(blob)
    sites = []
    for i, w in enumerate(words):
        if w & 0x0F000000 != 0x0B000000 or (w >> 28) == 0xF:
            continue
        imm = w & 0x00FFFFFF
        if imm & 0x00800000:
            imm -= 0x01000000
        if (base + i*4 + 8 + imm*4) & 0xFFFFFFFF == target:
            sites.append(base + i*4)
    return tuple(sites)


def analyze(model: Model, *, getter: str, setter: str,
            recorder_setup: str, hevc_builder: str,
            driver_validation: str, highspeed_classifier: str):
    byte = f"DAT_{model.runtime_byte:08x}"
    getter_fn = f"FUN_{model.getter:08x}"
    setter_fn = f"ResearchSetter_{model.setter:08x}"
    ensure(
        getter_fn in getter and
        re.search(r"\breturn\s+" + byte + r"\s*;", getter) is not None,
        f"{model.name}: runtime getter"
    )
    ensure(
        setter_fn in setter and
        re.search(r"\b" + byte + r"\s*=\s*param_1\s*;", setter) is not None,
        f"{model.name}: runtime setter"
    )
    ensure(
        re.search(
            r"(uVar\d+)\s*=\s*" + getter_fn +
            r"\(\s*\)\s*;\s*\*\(undefined1 \*\)\(iVar\d+ \+ "
            r"0xadda\)\s*=\s*\1\s*;",
            recorder_setup
        ) is not None,
        f"{model.name}: getter copied to recording context +0xADDA"
    )
    init_codec = model.init_struct + 0x188
    bitdepth_addr = model.init_struct + 0x0C
    ensure(
        f"FUN_{model.recorder:08x}" in hevc_builder,
        f"{model.name}: expected HEVC recorder function"
    )
    ensure(
        f"_DAT_{bitdepth_addr:08x} = 1;" in hevc_builder,
        f"{model.name}: bitdepth=1 in init struct"
    )
    ensure(
        re.search(
            r"bVar\d+\s*=\s*\*\(char \*\)\(param_1 \+ 0xadda\)"
            r"\s*==\s*'\\x01'\s*;",
            hevc_builder
        ) is not None,
        f"{model.name}: runtime codec==1 decision"
    )
    ensure(
        re.search(
            rf"_DAT_{init_codec:08x}\s*=\s*\(uint\)!bVar\d+\s*;",
            hevc_builder
        ) is not None,
        f"{model.name}: driver video_codec at init+0x188"
    )
    ensure(
        f"FUN_{model.validator:08x}" in driver_validation and
        "param_2 + 0x188" in driver_validation and
        "param_2 + 0xc" in driver_validation and
        "init_bit_depth_ERROR" in driver_validation,
        f"{model.name}: independent driver codec/bitdepth check"
    )
    ensure(
        f"FUN_{model.highspeed_classify:08x}" in highspeed_classifier and
        "case 1:" in highspeed_classifier and
        "case 4:" in highspeed_classifier and
        "case 2:" in highspeed_classifier and
        "case 3:" in highspeed_classifier and
        "return 0;" in highspeed_classifier and
        "return 1;" in highspeed_classifier,
        f"{model.name}: independent normal / HS movie-type selector"
    )
    return {
        "model": model.name,
        "runtime_byte": hex(model.runtime_byte),
        "getter": hex(model.getter),
        "setter": hex(model.setter),
        "recorder_context_offset": "0xADDA",
        "driver_codec_offset": "0x188",
        "driver_codec_value_when_context_is_1": 0,
        "driver_codec_value_otherwise": 1,
        "driver_bitdepth_init_offset": "0x0C",
        "driver_bitdepth_built_value": 1,
        "can_prove_ui_can_set_H265": False,
        "can_prove_Main10_stream": False,
    }


def load_logs(output: Path, model: Model):
    m = model.name
    files = {
        "getter": f"{m}_actual_movie_codec_selection_at_context.log",
        "setter": f"{m}_movie_codec_state_setter_decomp.log",
        "recorder_setup": f"{m}_codec_field_setters.log",
        "hevc_builder": f"{m}_recorder_hevc_init.c.txt",
        "driver_validation": f"{m}_h265_true_bitdepth_validator.log",
        "highspeed_classifier": f"{m}_recorder_5f5_movie_mode_classify.log",
    }
    return {key: (output / name).read_text(encoding="utf-8")
            for key, name in files.items()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("output"),
                   help="Private local Ghidra log directory, not public repo")
    p.add_argument("--scan-bl", action="store_true",
                   help="Scan decoded sections 1-3 for direct BL to setters")
    opt = p.parse_args()
    for m in MODELS:
        result = analyze(m, **load_logs(opt.output, m))
        print(result)
        if opt.scan_bl:
            calls = []
            for n in (1, 2, 3):
                b = (opt.output / f"x6-{m.name}" /
                     f"section-{n}.bin").read_bytes()
                base = (struct.unpack_from("<I", b, 4)[0] if n < 3
                        else struct.unpack_from("<I", b)[0] - 8)
                calls.extend((n, hex(at))
                             for at in scan_arm_bl(b, base, m.setter))
            print(f"{m.name}: direct A32 BL sites to optional setter={calls}")
            print("0 direct BL sites does NOT prove the setter is unreachable: "
                  "indirect function pointer / table dispatch may exist.")
    print("No device accessed. This is a static CALL/FORMAT trace, "
          "not an HEVC Main10 feature activation test.")


if __name__ == "__main__":
    main()

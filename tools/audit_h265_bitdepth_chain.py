#!/usr/bin/env python3
"""Offline three-camera HEVC bit-depth dataflow audit, never a firmware patcher.

Inputs: *PRIVATE* local Ghidra decompilation excerpts/logs (all in ignored
output/ directory) from X-T3 5.11, X-T4 2.12 and X-S10 3.11.

This verifies that:
  (1) recorder builds HEVC driver-init struct with bitdepth field +0x0c = 1;
  (2) driver-init validates +0x0c via literal '#init bit_depth ERROR';
  (3) the 400-byte init struct is copied to local state;
  (4) init event copies bitdepth into a runtime session DWORD [3], with an
      independent codec-dependent override;
  (5) the VPU/session option builder chooses literal 0x201 for zero versus
      literal 0x121 for nonzero bitdepth.
  (6) all THREE models show this SAME logical path.

X-T3/T4 are known-positive HEVC 10-bit internal recorders. That provides
strong comparative evidence for a compatible HEVC bitdepth enum on X-S10,
NOT definitive proof that enum 1 corresponds to a live Main10 10-bit HEVC
SPS for X-S10. Do not patch DAT or camera based only on these functions.
The third-party VPU firmware may still enforce limits or emit 8-bit output.

No proprietary decompiler text is printed or uploaded. Only short
structural findings, function addresses and enum values are emitted.
"""
import argparse
from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class ModelSpec:
    model: str
    init_global: int
    runtime_init_field: int
    validator_func: int
    copy_init_func: int
    session_init_func: int
    session_option_func: int
    session_variable_name: str
    h265_packet_func: int
    hevc_param_global: int


MODELS = {
    "xt3": ModelSpec("xt3", 0x0246BF6C, 0x018D272C,
                     0x01098ECC, 0x01098ECC, 0x01097B48,
                     0x0109A248, "_DAT_01924970",
                     0x0109A6A0, 0x0246BF30),
    "xt4": ModelSpec("xt4", 0x028A515C, 0x01B840E4,
                     0x011CCE88, 0x011CCE88, 0x011CBB0C,
                     0x011CE204, "_DAT_01be5808",
                     0x011CE65C, 0x028A5120),
    "xs10": ModelSpec("xs10", 0x02945A14, 0x01C2597C,
                      0x011F97DC, 0x011F97DC, 0x011F8460,
                      0x011FAB58, "_DAT_01c8573c",
                      0x011FAFB0, 0x029459D8),
}


def require(test: bool, description: str):
    if not test:
        raise ValueError(f"HEVC bitdepth trace missing: {description}")


def bitdepth_check_decompiled(source: str):
    """Exact compiler predicate, not inference from a 'bit_depth' label."""
    return bool(re.search(
        r"if\s*\(\s*\(\s*\*\(uint \*\)\(param_2 \+ 0x188\)\s*==\s*0\)"
        r"\s*&&\s*\(1\s*<\s*\*\(uint \*\)\(param_2 \+ 0xc\)\)\s*\)",
        source,
    ))


def audit(spec: ModelSpec, *, builder: str, validator: str,
          runtime: str, format_builder: str, vpu_packet: str):
    init_name = f"_DAT_{spec.init_global:08x}"
    runtime_name = f"_DAT_{spec.runtime_init_field:08x}"
    hevc_mode_name = f"_DAT_{spec.hevc_param_global:08x}"
    require(
        re.search(rf"\b{init_name}\s*=\s*1\s*;", builder,
                  re.IGNORECASE) is not None,
        f"{spec.model}: recorder init bitdepth (+0x0c) = 1"
    )
    require(
        f"FUN_{spec.validator_func:08x}" in validator and
        bitdepth_check_decompiled(validator) and
        "init_bit_depth_ERROR" in validator,
        f"{spec.model}: bitdepth validator conditional"
    )
    require(
        re.search(r"(?:func_0x[0-9a-f]{8}|FUN_[0-9a-f]{8})"
                  r"\([^;\n]*param_2\s*,\s*400\s*\)", validator,
                  re.IGNORECASE) is not None,
        f"{spec.model}: memcpy 400-byte driver init struct"
    )
    require(
        f"FUN_{spec.session_init_func:08x}" in runtime and
        f"= {runtime_name};" in runtime and
        re.search(r"puVar[0-9]+\[3\]\s*=\s*uVar[0-9]+\s*;", runtime)
        is not None,
        f"{spec.model}: runtime session bitdepth field"
    )
    # The conditional contains the per-model 0/nonzero test and 2 numeric
    # option encodings, not enough evidence to name their pixel format.
    require(
        f"FUN_{spec.session_option_func:08x}" in format_builder and
        f"{spec.session_variable_name}[3] == 0" in format_builder and
        "0x201" in format_builder and
        "0x121" in format_builder and
        "+ 0x18" in format_builder,
        f"{spec.model}: bitdepth-dependent descriptor 0x201/0x121"
    )
    # Input[3] is DIFFERENT; preserve it independently rather than calling
    # it Main10/profile. The recorder writes this *encoding parameter* and
    # driver encodes it into a command 0x0a with bitrate-related input[4].
    require(hevc_mode_name in builder,
            f"{spec.model}: HEVC encode input[3] field")
    require(
        f"FUN_{spec.h265_packet_func:08x}" in vpu_packet and
        "= 10;" in vpu_packet and
        ",0xbbb,0xc)" in vpu_packet and
        re.search(r"\bpuVar[0-9]+\[2\]\s*=\s*\*\(undefined4"
                  r" \*\)\(iVar[0-9]+ \+ 0xc\)",vpu_packet) is not None,
        f"{spec.model}: HEVC option packet #10 transfers two DWORDs"
    )
    return {
        "model": spec.model,
        "init_bitdepth_field_offset": "+0x0c",
        "init_bitdepth_written": 1,
        "driver_accepts_bitdepth_zero_or_one_when_codec_zero": True,
        "init_struct_size_bytes": 400,
        "runtime_session_bitdepth_dword_index": 3,
        "bitdepth_zero_session_descriptor": "0x0201",
        "bitdepth_nonzero_session_descriptor": "0x0121",
        "hevc_input_3_is_independent_of_init_bitdepth": True,
        "hevc_input_3_forwarded_via_option_packet": "0x0a",
        "main10_profile_verified": False,
        "safe_firmware_patch_known": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for model in MODELS:
        for name in ("builder", "validator", "runtime",
                     "format_builder", "vpu_packet"):
            parser.add_argument(f"--{model}-{name.replace('_','-')}",
                                type=Path, required=True,
                                help="local PRIVATE Ghidra output; ignored by git")
    args = parser.parse_args()
    for model, spec in MODELS.items():
        sources = {
            key: getattr(args,f"{model}_{key}").read_text(encoding="utf-8")
            for key in ("builder","validator","runtime",
                        "format_builder","vpu_packet")
        }
        print(audit(spec, **sources))
    print("STATIC EVIDENCE ONLY. DO NOT equate enum 1 with verified Main10")
    print("until a real X-S10 HEVC SPS reports profile_idc=2 and 10-bit "
          "luma/chroma, and sensor/VPU/recording pipeline is validated.")


if __name__ == "__main__":
    main()

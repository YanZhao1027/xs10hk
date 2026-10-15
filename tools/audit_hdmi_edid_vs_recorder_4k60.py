#!/usr/bin/env python3
"""Offline-only audit: distinguish HDMI sink EDID 4K60 from camera 4K60.

The same X-S10 3.11 / X-T4 2.12 executable has:
* eModeHdmiOutInfo setter (separate from eModeMovieCodec and recorder state).
* HDMI DDC/EDID scan of 0x80-byte EDID block and extension-count at 0x7E.
* a dynamic list of *HDMI sink-advertised* video codes: the 4K case for
  frame-rate index 6 checks internal EDID codes 0xF0/0xF6.
* 36 x 16-byte EDID code conversion rows, identical between both cameras.

Those HDMI receiver mode codes MUST NEVER be equated with supported
sensor readout / internal HEVC encoder / camera-output video formats.
The 96x64-byte VIDEO RECORDER LUT is a DIFFERENT downstream shared table,
not evidence that 4K60 acquisition is available in the X-S10.

All X-S10 symbols here are for original firmware v3.11; user's camera
was v2.10. No live camera, FF80, USB, RAM, flash, DAT patch or output.
Proprietary Ghidra logs and binaries remain in the ignored local output/.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from hashlib import sha256
import re
import struct


@dataclass(frozen=True)
class Model:
    name: str
    section1_base: int
    edid_rows_base: int
    hdmi_info_setter: int
    hdmi_info_global: int
    codec_global: int
    recorder_codec_global: int
    edid_reader: int
    edid_configurator: int
    edid_mode_checker: int
    dynamic_mode_list: int
    hardware_mode_provider: int
    code_mapper: int
    code_membership: int
    sink_mode_filter: int
    sink_bitmap: int
    mode_count: int
    cached_edid_mode_list: int


SPECS = {
    "xs10": Model(
        "xs10",0x01021000,0x0162DE08,0x011595C4,0x01B88623,
        0x01B88650,0x01C25208,0x0126B7E0,0x01269B80,
        0x02050094,0x01150B94,0x012BA020,0x012B99D8,
        0x01269634,0x012696E0,0x01C855E4,0x01C84FB8,0x018177BC),
    "xt4": Model(
        "xt4",0x01021000,0x01605D2C,0x0112DDCC,0x01AF2D8B,
        0x01AF2DB8,0x01B83974,0x012419F8,0x0123FD98,
        0x01FAC60C,0x01125190,0x01292568,0x01291F20,
        0x0123F84C,0x0123F8F8,0x01BE56B0,0x01BE5084,0x01786BD0)
}
ROWS = 36
ROW_SIZE = 16


def require(test: bool, message: str):
    if not test:
        raise ValueError("HDMI EDID audit failed: "+message)


def read_edid_code_rows(sec1: bytes, model: Model):
    base = struct.unpack_from("<I",sec1,4)[0]
    require(base==model.section1_base,model.name+" Section1 base")
    off=model.edid_rows_base-base
    require(off>=0 and off+ROWS*ROW_SIZE<=len(sec1), "EDID list in Section1")
    data=sec1[off:off+ROWS*ROW_SIZE]
    require(all(data[i*ROW_SIZE]==i for i in range(ROWS)),
            model.name+" raw EDID mode table sequence")
    return data


def split_ghidra(log: str, expected_entry: int) -> str:
    name=f"FUN_{expected_entry:08x}"
    for blk in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=blk.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(rf"\b{name}\(",c):
            return c
    raise ValueError("Expected Ghidra function absent: "+name)


def audit_decompiler(model: Model, *, hdmi_info: str, edid_reader: str,
                     edid_filter: str, edid_checker: str,
                     code_mapper: str, sink_membership: str,
                     dynamic_list: str, raw_provider: str):
    m=model.name
    f=split_ghidra(hdmi_info,model.hdmi_info_setter)
    require(f"DAT_{model.hdmi_info_global:08x} = (char)param_1;" in f,
            m+" HDMI info setter writes distinct setting")
    require(len({model.hdmi_info_global,model.codec_global,
                 model.recorder_codec_global})==3,m+" distinct globals")
    f=split_ghidra(edid_reader,model.edid_reader)
    require("0xfff7b000" in f and
            re.search(r",0x80\)",f) is not None and
            re.search(r",0x7e,",f) is not None,
            m+" HDMI EDID base-block and extension parsing")
    f=split_ghidra(edid_filter,model.edid_configurator)
    require("0x3840" in f and "0x3841" in f and
            f"FUN_{model.sink_mode_filter:08x}" in f and
            f"(&DAT_{model.edid_rows_base+1:08x})" in f,
            m+" sink modes generated from EDID and per-mode filtering")
    f=split_ghidra(edid_checker,model.edid_mode_checker)
    require("case 6:" in f and "0xf0" in f and "0xf6" in f and
            f"FUN_{model.dynamic_mode_list:08x}" in f and
            re.search(r"0x68",f) is not None,
            m+" 4K fps-index 6 HDMI sink video-code membership test")
    f=split_ghidra(code_mapper,model.code_mapper)
    require("case 0x11:" in f and "0xf0;" in f and
            "case 0x17:" in f and "0xf6;" in f,
            m+" HDMI/EDID code translator 0x11/0x17")
    f=split_ghidra(dynamic_list,model.dynamic_mode_list)
    require(f"FUN_{model.hardware_mode_provider:08x}" in f and
            f"0x{model.cached_edid_mode_list:x}" in f and
            re.search(r",0x68\)",f) is not None,
            m+" sink runtime list copy and caching")
    f=split_ghidra(raw_provider,model.hardware_mode_provider)
    require("0x86" in f and f"FUN_{model.code_mapper:08x}" in f and
            "0xffffffc1" in f,
            m+" HDMI monitor EDID mode enumeration and fallback")
    f=split_ghidra(sink_membership,model.code_membership)
    require(f"_DAT_{model.mode_count:08x}" in f and
            f"(&DAT_{model.sink_bitmap:08x})" in f and
            ">> 3" in f,
            m+" EDID sink membership list and auxiliary bitmap")
    return {
        "model":m,
        "external_recorder_HDMI_info_state":hex(model.hdmi_info_global),
        "internal_movie_codec_GUI_state":hex(model.codec_global),
        "internal_recorder_codec_state":hex(model.recorder_codec_global),
        "HDMI_EDID_extension_count_offset":"0x7E",
        "HDMI_EDID_base_block_bytes":128,
        "HDMI_EDID_parser":hex(model.edid_reader),
        "HDMI_capability_enumerator":hex(model.edid_configurator),
        "HDMI_dynamic_video_code_list_cache":hex(model.cached_edid_mode_list),
        "HDMI_capability_bitmap":hex(model.sink_bitmap),
        "4K_fps_index_6_EDID_codes":["0xF0","0xF6"],
        "EDID_sink_capabilities_prove_camera_4k60":False,
        "HDMI_10bit_proves_internal_Main10":False,
        "firmware_patch_generated":False,
    }


def model_ghidra_logs(folder:Path,m:str):
    paths={
        "hdmi_info": f"{m}_hdmi_info_ui_output_setter_stage22.log",
        "edid_reader": f"{m}_runtime_hdmi_mode_list_initializers_stage22.log",
        "edid_filter": f"{m}_hardware_video_modes_writer_stage22.log",
        "edid_checker": f"{m}_hdmi_4k_mode_gate_classifier_stage22.log",
        "code_mapper": f"{m}_movie_mode_runtime_provider_and_idmap_stage22.log",
        "sink_membership": f"{m}_runtime_sensor_interface_validate_stage22.log",
        "dynamic_list": f"{m}_hdmi_allowed_mode_list_builder_stage22.log",
        "raw_provider": f"{m}_movie_mode_context_predicate_stage22.log",
    }
    return {key:(folder/name).read_text(encoding="utf-8")
            for key,name in paths.items()}


def audit_both(folder:Path):
    reports={}
    rows={}
    for name,spec in SPECS.items():
        sec1=(folder/f"x6-{name}"/"section-1.bin").read_bytes()
        rows[name]=read_edid_code_rows(sec1,spec)
        reports[name]=audit_decompiler(spec,**model_ghidra_logs(folder,name))
    require(rows["xs10"]==rows["xt4"],
            "X-S10 and X-T4 HDMI EDID decoding tables differ")
    return {
        "models":reports,
        "HDMI_EDID_mode_record_count_each":ROWS,
        "HDMI_EDID_mode_record_bytes":ROWS*ROW_SIZE,
        "EDID_mode_conversion_equal":True,
        "mode_record_sha256":sha256(rows["xs10"]).hexdigest(),
        "contains_4K60_sink_mode_enum_0x11_and_0x17":
            {0x11,0x17}.issubset({rows["xs10"][i*16+1]
                                   for i in range(ROWS)}),
        "internal_4K60_sensor_capture_proven":False,
        "internal_10bit_HEVC_file_proven":False,
    }


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"),
                   help="PRIVATE decoded ROM sections and Ghidra logs")
    opt=p.parse_args()
    data=audit_both(opt.output)
    for m,record in data["models"].items():
        print(m,record)
    for key,val in data.items():
        if key!="models":print(key+":",val)
    print("HDMI EDID can advertise 4K60 without camera 4K60 support. "
          "NO DEVICE ACCESS, NO PATCH, NO FLASH")


if __name__ == "__main__":
    main()

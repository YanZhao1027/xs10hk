"""Synthetic only: HDMI sink EDID modes are NOT internal movie recording modes."""
import pathlib
import struct
import sys
import unittest
from dataclasses import replace

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from audit_hdmi_edid_vs_recorder_4k60 import (
    SPECS, ROWS, ROW_SIZE, audit_decompiler, read_edid_code_rows,
)


def gh(addr,body):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\nINFO Script> \n"
            f"void FUN_{addr:08x}(void) {{\n{body}\n}}\n"
            "TRACE_DECOMP_END (GhidraScript)\n")


def synthetic_logs(spec):
    return {
        "hdmi_info":gh(
            spec.hdmi_info_setter,
            f"DAT_{spec.hdmi_info_global:08x} = (char)param_1;"
        ),
        "edid_reader":gh(
            spec.edid_reader,
            "FUN_feedfa11(0xfff7b000, iVar1,0x80);\n"
            "FUN_feedfa12(iVar1,0x7e,local_29);"
        ),
        "edid_filter":gh(
            spec.edid_configurator,
            f"int a=FUN_abcddddd(0x3840);\nint b=FUN_abcddddd(0x3841);\n"
            f"FUN_{spec.sink_mode_filter:08x}(uVar3);\n"
            f"q=(&DAT_{spec.edid_rows_base+1:08x})[j*0x10];"
        ),
        "edid_checker":gh(
            spec.edid_mode_checker,
            "int mode=0;\n"
            "switch(param_2){case 6: mode=0xf6; if(b)mode=0xf0;break;}\n"
            f"FUN_{spec.dynamic_mode_list:08x}(local_68);\n"
            "memset(local_68,0,0x68);"
        ),
        "code_mapper":gh(
            spec.code_mapper,
            "switch(param_1){case 0x11:uVar1=0xf0;break;"
            "case 0x17:uVar1=0xf6;break;}"
        ),
        "sink_membership":gh(
            spec.code_membership,
            f"if(_DAT_{spec.mode_count:08x} == 0)return 0;\n"
            f"b=(&DAT_{spec.sink_bitmap:08x})[uVar2 >> 3];"
        ),
        "dynamic_list":gh(
            spec.dynamic_mode_list,
            f"v=FUN_{spec.hardware_mode_provider:08x}();\n"
            f"func_0x11111111(p,0x{spec.cached_edid_mode_list:x},0x68);"
        ),
        "raw_provider":gh(
            spec.hardware_mode_provider,
            f"param_1[0] = 0x86;\n"
            f"k=FUN_{spec.code_mapper:08x}(enum_code);\n"
            "return 0xffffffc1;"
        ),
    }


def synthetic_sec1(spec,*,mutate_index=None,base_delta=0):
    size=spec.edid_rows_base-spec.section1_base+ROWS*ROW_SIZE+8
    b=bytearray(size)
    struct.pack_into("<I",b,4,spec.section1_base+base_delta)
    off=spec.edid_rows_base-spec.section1_base
    for i in range(ROWS):
        b[off+i*ROW_SIZE]=i
        b[off+i*ROW_SIZE+1]= (
            0x11 if i in (22,23) else 0x17 if i in (34,35) else i % 0x18
        )
    if mutate_index is not None:
        b[off+mutate_index*ROW_SIZE] ^= 1
    return bytes(b)


class HDMIEDIDSafetyAuditTests(unittest.TestCase):
    def test_good_synthetic_decomp_logs_both_models(self):
        for m,spec in SPECS.items():
            with self.subTest(m=m):
                result=audit_decompiler(spec,**synthetic_logs(spec))
                self.assertEqual(result["HDMI_EDID_extension_count_offset"],
                                 "0x7E")
                self.assertFalse(
                    result["EDID_sink_capabilities_prove_camera_4k60"])
                self.assertFalse(result["HDMI_10bit_proves_internal_Main10"])
                self.assertEqual(len({
                    spec.hdmi_info_global,
                    spec.codec_global,
                    spec.recorder_codec_global,
                }),3)

    def test_good_36x16_synthetic_binary_tables(self):
        for m,spec in SPECS.items():
            with self.subTest(m=m):
                raw=read_edid_code_rows(synthetic_sec1(spec),spec)
                self.assertEqual(len(raw),576)
                self.assertEqual(raw[22*16+1],0x11)
                self.assertEqual(raw[34*16+1],0x17)

    def test_false_no_edid_extension_rejected(self):
        spec=SPECS["xs10"]
        x=synthetic_logs(spec)
        x["edid_reader"]=x["edid_reader"].replace("0x7e","0x7d")
        with self.assertRaisesRegex(ValueError,"EDID base-block"):
            audit_decompiler(spec,**x)

    def test_false_wrong_edid_block_size_rejected(self):
        spec=SPECS["xt4"]
        x=synthetic_logs(spec)
        x["edid_reader"]=x["edid_reader"].replace("0x80","0x70")
        with self.assertRaisesRegex(ValueError,"EDID base-block"):
            audit_decompiler(spec,**x)

    def test_no_external_hdmi_setter_rejected(self):
        spec=SPECS["xs10"]
        x=synthetic_logs(spec)
        x["hdmi_info"]=x["hdmi_info"].replace(
            f"DAT_{spec.hdmi_info_global:08x}",
            f"DAT_{spec.recorder_codec_global:08x}"
        )
        with self.assertRaisesRegex(ValueError,"distinct setting"):
            audit_decompiler(spec,**x)

    def test_4k_fps_code6_must_exist(self):
        spec=SPECS["xt4"]
        x=synthetic_logs(spec)
        x["edid_checker"]=x["edid_checker"].replace("case 6:","case 5:")
        with self.assertRaisesRegex(ValueError,"fps-index 6"):
            audit_decompiler(spec,**x)

    def test_f0_f6_edid_video_code_must_match(self):
        spec=SPECS["xs10"]
        x=synthetic_logs(spec)
        x["edid_checker"]=x["edid_checker"].replace("0xf6","0xf5")
        with self.assertRaisesRegex(ValueError,"fps-index 6"):
            audit_decompiler(spec,**x)

    def test_mapper_code17_must_match_f6(self):
        spec=SPECS["xt4"]
        x=synthetic_logs(spec)
        x["code_mapper"]=x["code_mapper"].replace("0xf6","0xf5")
        with self.assertRaisesRegex(ValueError,"code translator"):
            audit_decompiler(spec,**x)

    def test_mode_config_special_keys_required(self):
        spec=SPECS["xs10"]
        x=synthetic_logs(spec)
        x["edid_filter"]=x["edid_filter"].replace("0x3841","0x3842")
        with self.assertRaisesRegex(ValueError,"per-mode filtering"):
            audit_decompiler(spec,**x)

    def test_raw_edid_cache_required(self):
        spec=SPECS["xt4"]
        x=synthetic_logs(spec)
        x["dynamic_list"]=x["dynamic_list"].replace("0x68","0x50")
        with self.assertRaisesRegex(ValueError,"caching"):
            audit_decompiler(spec,**x)

    def test_sink_membership_and_bitmap_required(self):
        spec=SPECS["xs10"]
        x=synthetic_logs(spec)
        x["sink_membership"]=x["sink_membership"].replace(
            f"DAT_{spec.sink_bitmap:08x}", "DAT_deadbeef")
        with self.assertRaisesRegex(ValueError,"membership"):
            audit_decompiler(spec,**x)

    def test_bad_data_row_fails(self):
        spec=SPECS["xs10"]
        with self.assertRaisesRegex(ValueError,"sequence"):
            read_edid_code_rows(synthetic_sec1(spec,mutate_index=22),spec)

    def test_wrong_rom_load_address_fails(self):
        spec=SPECS["xt4"]
        with self.assertRaisesRegex(ValueError,"Section1 base"):
            read_edid_code_rows(synthetic_sec1(spec,base_delta=4),spec)

    def test_out_of_bounds_binary_fails(self):
        spec=SPECS["xs10"]
        with self.assertRaisesRegex(ValueError,"in Section1"):
            read_edid_code_rows(synthetic_sec1(spec)[:32],spec)


if __name__=="__main__":
    unittest.main()

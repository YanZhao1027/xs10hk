"""Synthetic-only tests for 3-model HEVC bitdepth-to-VPU trace."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from audit_h265_bitdepth_chain import MODELS, audit, bitdepth_check_decompiled


def synthetic(spec):
    return {
        "builder": (
            f"_DAT_{spec.init_global:08x} = 1;\n"
            f"_DAT_{spec.hevc_param_global:08x} = 3;\n"
        ),
        "validator": (
            f"undefined4 FUN_{spec.validator_func:08x}(uint param_1,int param_2,int param_3) {{\n"
            "if ((*(uint *)(param_2 + 0x188) == 0) && "
            "(1 < *(uint *)(param_2 + 0xc))) {\n"
            "FUN_deadbeef(s__init_bit_depth_ERROR,1);\nreturn 0xffffffff;\n}\n"
            "func_0x00059108(&DAT_01b840d8,param_2,400);\n}"
        ),
        "runtime": (
            f"int FUN_{spec.session_init_func:08x}(void) {{\n"
            f"uVar2 = _DAT_{spec.runtime_init_field:08x};\n"
            "if (_DAT_deadbeef != 0) {uVar2 = 1;}\n"
            "puVar3[3] = uVar2;\nreturn 0;\n}"
        ),
        "format_builder": (
            f"void FUN_{spec.session_option_func:08x}(void) {{\n"
            f"if ({spec.session_variable_name}[3] == 0) {{\n"
            "*(undefined2 *)(iVar1 + 0x18) = 0x201;\n"
            "} else {\n*(undefined2 *)(iVar1 + 0x18) = 0x121;\n}}\n"
        ),
        "vpu_packet": (
            f"void FUN_{spec.h265_packet_func:08x}(void) {{\n"
            "*_DAT_0191faac = 10;\n"
            "_DAT_0191faac[1] = *(undefined4 *)(_DAT_018b6628 + 8);\n"
            "puVar2[2] = *(undefined4 *)(iVar1 + 0xc);\n"
            "FUN_01099e04(puVar2,0xbbb,0xc);\n}\n"
        )
    }


class H265BitDepthTests(unittest.TestCase):
    def test_bit_depth_predicate_specific(self):
        self.assertTrue(bitdepth_check_decompiled(
            "if ((*(uint *)(param_2 + 0x188) == 0) && "
            "(1 < *(uint *)(param_2 + 0xc))) {"))
        self.assertFalse(bitdepth_check_decompiled(
            "if ((*(uint *)(param_2 + 0x188) == 0) && "
            "(2 < *(uint *)(param_2 + 0xc))) {"))

    def test_three_known_models_synthetic(self):
        for model, spec in MODELS.items():
            with self.subTest(model=model):
                result = audit(spec, **synthetic(spec))
                self.assertEqual(result["init_bitdepth_written"], 1)
                self.assertEqual(result["bitdepth_nonzero_session_descriptor"],
                                 "0x0121")
                self.assertFalse(result["main10_profile_verified"])

    def test_reject_wrong_init_bitdepth(self):
        model = MODELS["xs10"]
        s = synthetic(model)
        s["builder"] = s["builder"].replace("= 1;", "= 0;", 1)
        with self.assertRaisesRegex(ValueError, "recorder init"):
            audit(model, **s)

    def test_reject_missing_driver_check(self):
        model=MODELS["xt4"]
        s=synthetic(model)
        s["validator"]=s["validator"].replace("1 < *(uint", "2 < *(uint")
        with self.assertRaisesRegex(ValueError, "validator"):
            audit(model, **s)

    def test_reject_missing_400_byte_init_copy(self):
        model=MODELS["xt3"]
        s=synthetic(model)
        s["validator"]=s["validator"].replace("param_2,400", "param_2,256")
        with self.assertRaisesRegex(ValueError, "memcpy"):
            audit(model, **s)

    def test_reject_missing_runtime_init_copy(self):
        model=MODELS["xs10"]
        s=synthetic(model)
        s["runtime"]=s["runtime"].replace("puVar3[3]", "puVar3[4]")
        with self.assertRaisesRegex(ValueError, "runtime"):
            audit(model, **s)

    def test_reject_altered_vpu_descriptor(self):
        model=MODELS["xt4"]
        s=synthetic(model)
        s["format_builder"]=s["format_builder"].replace("0x121", "0x120")
        with self.assertRaisesRegex(ValueError, "descriptor"):
            audit(model, **s)

    def test_reject_missing_option_packet(self):
        model=MODELS["xt3"]
        s=synthetic(model)
        s["vpu_packet"]=s["vpu_packet"].replace("= 10;", "= 9;")
        with self.assertRaisesRegex(ValueError, "option packet"):
            audit(model, **s)


if __name__ == "__main__":
    unittest.main()

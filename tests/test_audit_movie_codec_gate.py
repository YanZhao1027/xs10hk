"""Synthetic-only tests for the runtime codec selection -> HEVC init audit."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from audit_movie_codec_gate import MODELS, analyze, scan_arm_bl


def snippets(m):
    return {
        "getter": (f"undefined1 FUN_{m.getter:08x}(void) "
                   f"{{return DAT_{m.runtime_byte:08x};}}"),
        "setter": (f"void ResearchSetter_{m.setter:08x}(undefined1 param_1) "
                   f"{{DAT_{m.runtime_byte:08x} = param_1;}}"),
        "recorder_setup": (
            f"uVar4 = FUN_{m.getter:08x}();\n"
            "*(undefined1 *)(iVar8 + 0xadda) = uVar4;"
        ),
        "hevc_builder": (
            f"undefined4 FUN_{m.recorder:08x}(int param_1) {{\n"
            f"_DAT_{m.init_struct+0x0c:08x} = 1;\n"
            "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';\n"
            f"_DAT_{m.init_struct+0x188:08x} = (uint)!bVar9;\n"
            "}"
        ),
        "driver_validation": (
            f"FUN_{m.validator:08x} (int param_2) {{\n"
            "if ((*(uint *)(param_2 + 0x188) == 0) && "
            "(1 < *(uint *)(param_2 + 0xc))) "
            "log(init_bit_depth_ERROR);\n}"
        ),
        "highspeed_classifier": (
            f"FUN_{m.highspeed_classify:08x}(int p) {{\n"
            "switch(p){case 1: case 4: case 5: case 6: case 7: "
            "return 0; case 2: case 3: return 1;}\n}"
        ),
    }


class RuntimeCodecGateTests(unittest.TestCase):
    def test_two_models_full_dataflow(self):
        for m in MODELS:
            with self.subTest(m=m.name):
                a = analyze(m, **snippets(m))
                self.assertEqual(a["driver_codec_value_when_context_is_1"], 0)
                self.assertEqual(a["driver_codec_value_otherwise"], 1)
                self.assertFalse(a["can_prove_Main10_stream"])

    def test_reject_wrong_getter_global(self):
        m=MODELS[1]; d=snippets(m)
        d["getter"]=d["getter"].replace("DAT_01c25208","DAT_01c25209")
        with self.assertRaisesRegex(ValueError,"runtime getter"):
            analyze(m, **d)

    def test_reject_wrong_setter_global(self):
        m=MODELS[1]; d=snippets(m)
        d["setter"]=d["setter"].replace("DAT_01c25208","DAT_01c25209")
        with self.assertRaisesRegex(ValueError,"runtime setter"):
            analyze(m, **d)

    def test_reject_missing_context_assignment(self):
        m=MODELS[1]; d=snippets(m)
        d["recorder_setup"]=d["recorder_setup"].replace("0xadda","0xadd9")
        with self.assertRaisesRegex(ValueError,"recording context"):
            analyze(m, **d)

    def test_reject_hevc_builder_missing_codec_decision(self):
        m=MODELS[0]; d=snippets(m)
        d["hevc_builder"]=d["hevc_builder"].replace("0xadda","0xadd9")
        with self.assertRaisesRegex(ValueError,"codec==1"):
            analyze(m, **d)

    def test_reject_hevc_builder_unconditional_h264(self):
        m=MODELS[1];d=snippets(m)
        d["hevc_builder"]=d["hevc_builder"].replace("(uint)!bVar9","1")
        with self.assertRaisesRegex(ValueError,"driver video_codec"):
            analyze(m, **d)

    def test_reject_wrong_init_bitdepth(self):
        m=MODELS[0]; d=snippets(m)
        d["hevc_builder"]=d["hevc_builder"].replace(
            f"_DAT_{m.init_struct+0x0c:08x} = 1;",
            f"_DAT_{m.init_struct+0x0c:08x} = 0;"
        )
        with self.assertRaisesRegex(ValueError, "bitdepth=1"):
            analyze(m, **d)

    def test_reject_missing_driver_validation(self):
        m=MODELS[1];d=snippets(m)
        d["driver_validation"]=d["driver_validation"].replace(
            "param_2 + 0x188", "param_2 + 0x18c")
        with self.assertRaisesRegex(ValueError,"driver codec/bitdepth"):
            analyze(m, **d)

    def test_reject_incompatible_hs_classifier(self):
        m=MODELS[0]; d=snippets(m)
        d["highspeed_classifier"]=d["highspeed_classifier"].replace(
            "case 3:", "case 9:")
        with self.assertRaisesRegex(ValueError,"movie-type selector"):
            analyze(m, **d)

    def test_bl_encoder_positive_and_backward(self):
        base=0x2000
        end=base+0x24
        site=base+0x4
        op=0xeb000000 | (((end-site-8)//4)&0xffffff)
        b=bytearray(0x40)
        struct.pack_into("<I",b,4,op)
        self.assertEqual(scan_arm_bl(bytes(b),base,end),(site,))
        back=base+0x08
        src=base+0x34
        op=0xeb000000 | (((back-src-8)//4)&0xffffff)
        struct.pack_into("<I",b,0x34,op)
        self.assertEqual(scan_arm_bl(bytes(b),base,back),(src,))

    def test_bl_reject_non_calls(self):
        b=bytearray(0x20)
        struct.pack_into("<I",b,0,0xea000002)  # B, not BL
        struct.pack_into("<I",b,4,0xfa000000)  # BLX, not A32 BL
        self.assertEqual(scan_arm_bl(bytes(b),0x1000,0x1010),())
        with self.assertRaises(ValueError):
            scan_arm_bl(b"no",0x1000,0x1004)


if __name__=="__main__":
    unittest.main()

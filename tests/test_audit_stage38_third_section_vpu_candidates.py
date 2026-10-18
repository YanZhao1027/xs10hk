"""Pure synthetic Stage38 third-ARM and VPU-codec candidate provenance tests.

No original Fujifilm firmware bytes, camera endpoints, flashing or binary
modifications. Every ARM word and every vendor-module-like fixture here is
constructed algorithmically. The unknown other-core code stays unknown.
"""
import dataclasses
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage38_third_section_vpu_candidates as a

def synth_movw(reg,imm,top=False,cond=14):
    return ((cond<<28)|(0x03400000 if top else 0x03000000)|
            ((imm>>12&15)<<16)|(reg<<12)|(imm&0xfff))

def synth_bl(pc,target):
    d=target-pc-8
    if d%4 or not -(1<<25)<=d<1<<25:raise ValueError("bad fake BL")
    return 0xeb000000|((d//4)&0xffffff)

def put32(buf,offset,w):
    buf[offset:offset+4]=w.to_bytes(4,"little")

def ghidra(pc,c):
    return ("STAGE38_C_BEGIN %08x\n"%pc+
            "void Stage38_probe_%08x(void)\n{\n"%pc+
            c+"\n}\nSTAGE38_C_END %08x\n"%pc)

def synthetic_rom_fixture(original):
    m=original
    third=bytearray(0x18000)
    put32(third,0,m.sec3_base+8)
    put32(third,4,0)
    put32(third,8,0xe92d4800)
    put32(third,12,0xe28db004)
    put32(third,0x80,synth_bl(m.sec3_base+0x80,m.sec3_base+0xa0))
    put32(third,0xa0,0xe92d4ff0)
    for pos,bl in zip(m.app_movw_sites,m.app_bl_sites):
        v=m.full_arg
        put32(third,pos-m.sec3_base,synth_movw(2,v&0xffff))
        put32(third,pos+4-m.sec3_base,synth_movw(2,v>>16,top=True))
        put32(third,bl-m.sec3_base,synth_bl(bl,m.arg_wrapper))
    real=bytes(third)
    m=dataclasses.replace(m,sec3_size=len(real),sec3_sha=hashlib.sha256(real).hexdigest())
    c={
      "app":ghidra(m.app_function,
        "func_0x%08x(0x%x,0x29,0x%08x,7);\n"%
              (m.arg_wrapper,m.error_code1,m.full_arg)+
        "func_0x%08x(0x%x,0x29,0x%08x,7);"%
              (m.arg_wrapper,m.error_code2,m.full_arg)),
      "wrapper":ghidra(m.arg_wrapper,"func_0x%08x();"%m.arg_inner),
      "inner":ghidra(m.arg_inner,"if (param_3 != 0) {func_0x01234567();}"),
      "drawing":ghidra(m.ui_draw,
                "iVar1 = (param_1 + -1) * 0x14;\n"
                "iVar2 = (param_2 + -1) * 0x18;"),
    }
    return {
      "m":m,"sec1":bytes(8),"sec2":bytes(8),"sec3":real,
      "C":c,
      "prev":{
         "model":m.model,
         "frame_sender_0xBB9_payload_bytes":72,
         "primary_tx_packet_location":"W+0x92010",
         "primary_rx_packet_location":"W+0x93010",
         "0xBB9_paired_to_0x7D5":"UNPROVEN",
         "0xBB9_direct_VPU_hardware_consumer_observed":False,
      },
      "counts":(m.other_sec1_movw,(),m.app_movw_sites if m.model=="xt4" else ()),
    }

def run_model(model,edit=None):
    f=synthetic_rom_fixture(a.MODELS[model])
    if edit:edit(f)
    # mutation to fixture sec3 bytes should pass the hash check only when
    # the adversarial test specifically targets a later instruction check.
    # Rebind the synthetic model SHA, but NEVER for full-ROM tests.
    m=f["m"]
    if getattr(edit,"allow_resign_synthetic",False):
        f["m"]=dataclasses.replace(m,sec3_sha=hashlib.sha256(f["sec3"]).hexdigest())
        m=f["m"]
    counter=[0]
    def scan(data,base,imm):
        idx=counter[0];counter[0]+=1
        return f["counts"][idx]
    with patch.object(a,"scan_unconditional_movw",side_effect=scan):
        return a.validate_third_arm(
           m,f["sec1"],f["sec2"],f["sec3"],f["C"],f["prev"])

def resign_mutation(fn):
    fn.allow_resign_synthetic=True
    return fn

class A32Primitives(unittest.TestCase):
    def test_movw(self):
        self.assertEqual(a.decode_movw(synth_movw(2,0x6b9),2),0x6b9)
    def test_movt(self):
        self.assertEqual(a.decode_movw(synth_movw(2,0xff00,True),2,True),0xff00)
    def test_bbb9_and_ff00_not_equal_bbb9(self):
        self.assertNotEqual((0xff00<<16)|0xbb9,0xbb9)
    def test_bad_reg(self):
        with self.assertRaisesRegex(ValueError,"MOVW/MOVT"):
            a.decode_movw(synth_movw(3,0xbb9),2)
    def test_bad_op_variant(self):
        with self.assertRaisesRegex(ValueError,"MOVW/MOVT"):
            a.decode_movw(synth_movw(2,0xbb9,True),2,False)
    def test_bad_cond(self):
        with self.assertRaisesRegex(ValueError,"MOVW/MOVT"):
            a.decode_movw(synth_movw(2,0xbb9,False,1),2)
    def test_backward_bl(self):
        self.assertEqual(a.decode_bl(synth_bl(0x1200,0x1000),0x1200),0x1000)
    def test_forward_bl(self):
        self.assertEqual(a.decode_bl(synth_bl(0x1000,0x1200),0x1000),0x1200)
    def test_reject_conditional_bl(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            a.decode_bl(0x1b000001,0x1200)
    def test_reject_nonbl(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            a.decode_bl(0xe3a00001,0x1200)
    def test_bad_word_alignment(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            a.word(b"\0"*12,0x1000,0x1003)
    def test_bad_word_bounds(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            a.word(b"\0"*12,0x1000,0x1010)
    def test_original_word_little_endian(self):
        self.assertEqual(a.word(bytes.fromhex("34127856"),0x1000,0x1000),0x56781234)
    def test_scanner_ignores_wrong_condition(self):
        p=synth_movw(2,0xbb9,False,1).to_bytes(4,"little")
        self.assertEqual(a.scan_unconditional_movw(p,0x1000,0xbb9),())
    def test_scanner_ignores_movt(self):
        p=synth_movw(2,0xbb9,True).to_bytes(4,"little")
        self.assertEqual(a.scan_unconditional_movw(p,0x1000,0xbb9),())
    def test_scanner_exact_count_and_address(self):
        p=(synth_movw(1,0xbb9).to_bytes(4,"little")
           +synth_movw(2,0xbb9,True).to_bytes(4,"little")
           +synth_movw(3,0xbb9).to_bytes(4,"little"))
        self.assertEqual(a.scan_unconditional_movw(p,0x1000,0xbb9),
                         (0x1000,0x1008))
    def test_scanner_does_not_parse_unaligned_bytes(self):
        p=b"\xff"+synth_movw(2,0xbb9).to_bytes(4,"little")+b"!\x00\x00"
        self.assertEqual(a.scan_unconditional_movw(p,0x1000,0xbb9),())
    def test_missing_Ghidra_marker(self):
        with self.assertRaisesRegex(ValueError,"missing read-only"):
            a.ghidra_c("",0x11223344)
    def test_missing_Ghidra_prototype(self):
        with self.assertRaisesRegex(ValueError,"bounded valid"):
            a.ghidra_c("STAGE38_C_BEGIN 11223344\nX\nSTAGE38_C_END 11223344",0x11223344)

class ThirdSectionEvidence(unittest.TestCase):
    def test_two_models_positive_synthetic(self):
        for model in ("xs10","xt4"):
            with self.subTest(model=model):
                r=run_model(model)
                self.assertTrue(r["third_section_Ghidra_independent_import_and_decomp"])
                self.assertTrue(r["third_section_internal_BL_to_ARM_prologue"])
                self.assertEqual(r["third_section_size"],0x18000)
                self.assertFalse(r["hardware_receiver_0xBB9_confirmed"])
    def test_xt4_full_32bit_not_video_queue_ID(self):
        r=run_model("xt4")
        self.assertEqual(r["app_function_full_32bit_constant"],"0xff000bb9")
        self.assertFalse(r["app_constant_true_VPU_frame_queue_command"])
    def test_xs10_different_full_32bit_service_ID(self):
        r=run_model("xs10")
        self.assertEqual(r["app_function_full_32bit_constant"],"0xff000c91")
    def test_xt4_scanned_candidate_sites(self):
        r=run_model("xt4")
        self.assertEqual(r["aligned_unconditional_MOVW_0xBB9_by_section_1_2_3"],[4,0,2])
    def test_xs10_scanned_candidate_count(self):
        r=run_model("xs10")
        self.assertEqual(r["aligned_unconditional_MOVW_0xBB9_by_section_1_2_3"],[4,0,0])
    def test_never_assert_10bit_or_4k60(self):
        for model in ("xt4","xs10"):
            r=run_model(model)
            self.assertFalse(r["physical_10bit_or_4K60_inferred"])
    def test_stage37_wrong_model(self):
        def edit(f):f["prev"]["model"]="none"
        with self.assertRaisesRegex(ValueError,"stage37"):run_model("xs10",edit)
    def test_stage37_wrong_payload(self):
        def edit(f):f["prev"]["frame_sender_0xBB9_payload_bytes"]=80
        with self.assertRaisesRegex(ValueError,"stage37"):run_model("xt4",edit)
    def test_stage37_wrong_tx_direction(self):
        def edit(f):f["prev"]["primary_tx_packet_location"]="W+0x93010"
        with self.assertRaisesRegex(ValueError,"stage37"):run_model("xs10",edit)
    def test_stage37_wrong_rx_direction(self):
        def edit(f):f["prev"]["primary_rx_packet_location"]="W+0x92010"
        with self.assertRaisesRegex(ValueError,"stage37"):run_model("xt4",edit)
    def test_stage37_false_0bb9_07d5_request_response_pair(self):
        def edit(f):f["prev"]["0xBB9_paired_to_0x7D5"]="PROVEN"
        with self.assertRaisesRegex(ValueError,"stage37"):run_model("xs10",edit)
    def test_stage37_premature_receiver_claim(self):
        def edit(f):f["prev"]["0xBB9_direct_VPU_hardware_consumer_observed"]=True
        with self.assertRaisesRegex(ValueError,"stage37"):run_model("xt4",edit)
    def test_bad_sha_detected(self):
        def edit(f):f["sec3"]=b"\xff"+f["sec3"][1:]
        with self.assertRaisesRegex(ValueError,"SHA256"):run_model("xs10",edit)
    def test_wrong_section3_length(self):
        def edit(f):f["sec3"]=f["sec3"][:-4]
        with self.assertRaisesRegex(ValueError,"SHA256"):run_model("xt4",edit)
    def test_wrong_sections1_count(self):
        def edit(f):f["counts"]=((),f["counts"][1],f["counts"][2])
        with self.assertRaisesRegex(ValueError,"section1/2"):run_model("xs10",edit)
    def test_wrong_section2_count(self):
        def edit(f):f["counts"]=(f["counts"][0],(0x120,),f["counts"][2])
        with self.assertRaisesRegex(ValueError,"section1/2"):run_model("xt4",edit)
    def test_spurious_section3_bbb9_claim(self):
        def edit(f):f["counts"]=(f["counts"][0],(),(0x22222222,))
        with self.assertRaisesRegex(ValueError,"third-section"):run_model("xs10",edit)
    def test_missing_real_xt4_third_candidates(self):
        def edit(f):f["counts"]=(f["counts"][0],(),())
        with self.assertRaisesRegex(ValueError,"third-section"):run_model("xt4",edit)
    def test_app_missing_first_arg_ID(self):
        def edit(f):f["C"]["app"]=f["C"]["app"].replace(
             "0xff000c91","0xff000bb9")
        with self.assertRaisesRegex(ValueError,"actual section3 call"):run_model("xs10",edit)
    def test_app_missing_one_branch(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["app"]=f["C"]["app"].replace(
            "0x%x,0x29"%(m.error_code2),"0x777,0x29")
        with self.assertRaisesRegex(ValueError,"actual section3 call"):run_model("xt4",edit)
    def test_missing_wrapper(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["wrapper"]=f["C"]["wrapper"].replace(
            "0x%08x"%m.arg_inner,"0x00000000")
        with self.assertRaisesRegex(ValueError,"parameter wrapper"):run_model("xs10",edit)
    def test_missing_inner_context(self):
        def edit(f):f["C"]["inner"]=f["C"]["inner"].replace("param_3 != 0","param_3 == 0")
        with self.assertRaisesRegex(ValueError,"inner dispatch"):run_model("xt4",edit)
    def test_missing_coordinate_scale1(self):
        def edit(f):f["C"]["drawing"]=f["C"]["drawing"].replace("0x14","0x12")
        with self.assertRaisesRegex(ValueError,"coordinate-scaled"):run_model("xs10",edit)
    def test_missing_coordinate_scale2(self):
        def edit(f):f["C"]["drawing"]=f["C"]["drawing"].replace("0x18","0x28")
        with self.assertRaisesRegex(ValueError,"coordinate-scaled"):run_model("xt4",edit)
    def test_unexpected_vpu_reference_in_app(self):
        def edit(f):f["C"]["app"]=f["C"]["app"].replace("STAGE38_C_END", "VPU_H265_RSP_CODE_INPUT\nSTAGE38_C_END")
        with self.assertRaisesRegex(ValueError,"resembles VPU"):run_model("xt4",edit)
    def test_bad_baseline_guard_in_app(self):
        def edit(f):f["C"]["app"]=f["C"]["app"].replace("STAGE38_C_END", "0xbb9,0x48\nSTAGE38_C_END")
        with self.assertRaisesRegex(ValueError,"resembles VPU"):run_model("xt4",edit)

def fake_codec_module():
    arr=bytearray(b"\xff"*0x68000)
    arr[0x60:0x60+len(a.HEVC_MAGIC)]=a.HEVC_MAGIC
    arr[0x70:0x70+len(a.HEVC_LABEL)]=a.HEVC_LABEL
    # 17 intentionally UNALIGNED low-halfword coincidences. None is a
    # 32-bit little-endian 0x00000BB9 nor 0x00480BB9.
    for i in range(17):
        at=0x100+7*i
        arr[at:at+2]=b"\xb9\x0b"
    return bytes(arr)

def run_module(mutator=None):
    b=fake_codec_module()
    data={k:b for k in ("xt3","xt4","xs10")}
    if mutator:mutator(data)
    sha=hashlib.sha256(b).hexdigest()
    with patch.object(a,"HEVC_OFFSETS",{k:0 for k in data}):
      with patch.object(a,"EXPECTED_HEVC_SHA",sha):
        return a.compare_hevc_modules(data)

class ModuleScreen(unittest.TestCase):
    def test_positive_three_synthetic_modules(self):
        r=run_module()
        self.assertEqual(set(r),{"xt3","xt4","xs10"})
        for x in r.values():
            self.assertEqual(x["vendor_module_size"],0x68000)
            self.assertEqual(x["nonaligned_raw_b9_0b_substring_occurrences"],17)
            self.assertEqual(x["little_endian_exact_u32_0x00000bb9_occurrences"],0)
            self.assertEqual(x["little_endian_exact_u32_0x00480bb9_occurrences"],0)
    def test_reject_wrong_magic(self):
        def edit(d):d["xt3"]=d["xt3"][:0x60]+b"\xff"+d["xt3"][0x61:]
        with self.assertRaisesRegex(ValueError,"descriptor signature"):run_module(edit)
    def test_reject_wrong_name(self):
        def edit(d):d["xt4"]=d["xt4"].replace(a.HEVC_LABEL,b"fictional codec!")
        with self.assertRaisesRegex(ValueError,"descriptor signature"):run_module(edit)
    def test_reject_short_module(self):
        def edit(d):d["xt4"]=d["xt4"][:-4]
        with self.assertRaisesRegex(ValueError,"out of bounds"):run_module(edit)
    def test_reject_bit_flip(self):
        def edit(d):d["xs10"]=d["xs10"][:0x1230]+b"\x00"+d["xs10"][0x1231:]
        with self.assertRaisesRegex(ValueError,"SHA256"):run_module(edit)
    def test_reject_32bit_command_exact_literal(self):
        def edit(d):
            b=bytearray(d["xs10"])
            b[0x800:0x804]=b"\xb9\x0b\x00\x00"
            d["xs10"]=bytes(b)
        with self.assertRaisesRegex(ValueError,"SHA256"):run_module(edit)
    def test_reject_added_raw_16bit(self):
        def edit(d):
            b=bytearray(d["xt3"])
            b[0x800:0x802]=b"\xb9\x0b"
            d["xt3"]=bytes(b)
        with self.assertRaisesRegex(ValueError,"SHA256"):run_module(edit)
    def test_respect_module_identity_unknown(self):
        r=run_module()
        self.assertEqual(len({v["sha256"] for v in r.values()}),1)
    def test_no_source_firmware_exported_in_test_vectors(self):
        b=fake_codec_module()
        self.assertNotIn(b"Main10",b)
        self.assertNotIn(b"FF80",b)

def make_original_word_corruption(kind,num,model):
    def test(self):
        old=a.MODELS[model]
        @resign_mutation
        def edit(f):
            b=bytearray(f["sec3"])
            if kind=="entry":idx=8
            elif kind=="frame":idx=12
            elif kind=="meta":idx=4
            elif kind=="internal_bl":idx=0x80
            elif kind=="internal_target":idx=0xa3
            elif kind=="movw":idx=old.app_movw_sites[num%2]-old.sec3_base
            elif kind=="movt":idx=old.app_movw_sites[num%2]+4-old.sec3_base
            elif kind=="app_bl":idx=old.app_bl_sites[num%2]-old.sec3_base
            else:raise AssertionError(kind)
            b[idx]^=1
            f["sec3"]=bytes(b)
        with self.assertRaises(ValueError):
            run_model(model,edit)
    test.__name__="test_bad_%s_%02d"%(kind,num)
    return test

idx=0
for kind in ("entry","frame","meta","internal_bl","internal_target",
             "movw","movt","app_bl"):
    for model in ("xs10","xt4"):
        repeat=2 if kind in ("movw","movt","app_bl") else 1
        for j in range(repeat):
            setattr(ThirdSectionEvidence,"test_A32_%02d_%s_%s_%d"%(idx,kind,model,j),
                    make_original_word_corruption(kind,j,model))
            idx+=1

if __name__=="__main__":
    unittest.main()

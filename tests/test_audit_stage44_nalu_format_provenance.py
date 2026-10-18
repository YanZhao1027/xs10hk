"""Entirely synthetic Stage44 ARM/Ghidra NALU provenance fault-injection tests.

The original ROMs and Ghidra databases are never packaged with public tests.
Toy "A32" words are generated in RAM, and verification methods are patched
ONLY inside this test to confirm fail-closed behavior.
"""
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage44_nalu_format_provenance as a
import audit_stage43_mve_bitstream_return as st43

def bl(site,dest):
    dist=dest-(site+8)
    assert dist%4==0 and abs(dist)<0x2000000
    return 0xeb000000|((dist//4)&0xffffff)

def fake_fn(fn,contents):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
           "void FUN_%08x(void)\n{\n%s\n}\n"
           "TRACE_DECOMP_END (GhidraScript)\n")%(fn,contents)

def synthetic(m):
    words=a.source_words(m).copy()
    for site,target in ((m.adapter_bl,m.source_fn),
                        (m.snd_bl,m.snd_fn),(m.hdr_bl,m.hdr_fn)):
        words[site]=bl(site,target)
    global_src="_DAT_%08x"%m.source_ram
    global_cfg="_DAT_%08x"%m.config_ptr
    filled="_DAT_%08x"%m.received_filled
    source=(
      "warning: dec_param synthetic test fixture\n"
      "%s = *param_1;\n"%global_src+
      "_DAT_%08x = param_1[0xb];\n"%(m.source_ram+0x2c)+
      "if (*param_1 == 0x10) { byte_reorder(); }\n"
      "if (*param_1 == 1) { validate(); }\n"
      "bVar1 = *pbVar10;\n"
      "*pbVar10 = bVar4;\n"
      "pbVar10[1] = bVar3;\n"
      "pbVar10[2] = bVar2;\n"
      "pbVar10[3] = bVar1;\n"
      "uVar12 = 2;\n"
      "uVar12 = 3;\n"
    )
    reader=("%s[6] = %s;\n"%(global_cfg,global_src)+
      "FUN_%08x();\nFUN_%08x();\n"%(m.snd_fn,m.hdr_fn))
    option=("if (param) {\n"
      "local_58 = 1;\nlocal_54 = %s[6];\n"%global_cfg+
      "FUN_%08x(0x3f2,8,&local_58);\n"%m.msg_sender+
      "local_58 = 0x10;\nlocal_54 = 3;\n"
      "FUN_%08x(0x3f2,8,&local_58);\n"%m.msg_sender+
      "local_58 = 0x26;\nlocal_54 = 0x80008;\n"
      "FUN_%08x(0x3f2,8,&local_58);\n"%m.msg_sender+
      "} else {\nlocal_58 = 1;\n"
      "local_54 = %s[6];\n"%global_cfg+
      "FUN_%08x(0x3f2,8,&local_58);\n"%m.msg_sender+
      "}\nlocal_58 = 5;\n"
      "FUN_%08x(0x3f2,8,&local_58);\n"%m.msg_sender)
    response=("if (%s[6] == 0x10) {handle();}\n"%global_cfg)
    rewrite=("if (%s[6] == 0x10) {\n"%global_cfg+
             "iVar9 = %s + -4;\n"%filled+
             "*puVar5 = (char)((uint)iVar9 >> 0x18);\n"
             "puVar5[1] = (char)((uint)iVar9 >> 0x10);\n"
             "puVar5[2] = (char)((uint)iVar9 >> 8);\n"
             "puVar5[3] = (char)iVar9;\n}\n")
    response+=rewrite*2
    logs={
     "source":fake_fn(m.source_fn,source)+fake_fn(m.reader_fn,reader),
     "refs":("PROBE_TARGET addr=%08x refs=2\n"%m.source_ram+
             "PROBE_REF from=%08x to=%08x type=WRITE\n"%(m.stm_a,m.source_ram)+
             "PROBE_REF from=%08x to=%08x type=READ\n"%(m.reader_ldr,m.source_ram)),
     "adapter":fake_fn(m.adapter_fn,"FUN_%08x();\n"%m.source_fn),
     "opts":fake_fn(m.snd_fn,option),
     "response":fake_fn(m.response_fn,response),
    }
    prior={"fuji_original_ARM_and_readonly_Ghidra":[
       {
         "model":name,
         "original_rom1_sha256":st43.MODELS[name].sha,
         "CPU_OUTPUT_bitstream_descriptor_global":"0x%08x"%st43.MODELS[name].response_bitstream_global,
         "OUTPUT_CODECCONFIG_test_mask":"0x80",
         "Main10_SPS_or_hvcC_extracted":False,
       }
       for name in ("xs10","xt4")
    ]}
    return {"words":words,"logs":logs,"prior":prior}

def verified_toy(model="xs10",change=None):
    m=a.MODELS[model]
    fixture=synthetic(m)
    if change:change(m,fixture)
    with patch.object(a,"arm_word",side_effect=lambda _rom,at:fixture["words"][at]),\
         patch.object(a,"sha256",return_value=SimpleNamespace(
              hexdigest=lambda:st43.MODELS[m.name].sha)):
        return a.verify_model(m,b"TOY-NONVENDOR-BYTES",fixture["logs"],fixture["prior"])

class NaluABI(unittest.TestCase):
    def test_public_format_list(self):
        self.assertEqual(a.NALU_FORMATS,(1,2,4,8,16))
    def test_index1_NALU_format(self):
        self.assertEqual(a.public_nalu_abi()["MVE_SET_OPT_INDEX_NALU_FORMAT"],1)
    def test_nalu_format1_startcode(self):
        self.assertEqual(a.public_nalu_abi()["START_CODES"],1)
    def test_nalu_format2_oneperbuffer(self):
        self.assertEqual(a.public_nalu_abi()["ONE_NALU_PER_BUFFER"],2)
    def test_nalu_format4_onelength(self):
        self.assertEqual(a.public_nalu_abi()["ONE_BYTE_LENGTH_FIELD"],4)
    def test_nalu_format8_twolength(self):
        self.assertEqual(a.public_nalu_abi()["TWO_BYTE_LENGTH_FIELD"],8)
    def test_nalu_format16_fourlength(self):
        self.assertEqual(a.public_nalu_abi()["FOUR_BYTE_LENGTH_FIELD"],16)
    def test_mve_profile4_not_bitstream_idc2(self):
        self.assertEqual(a.public_nalu_abi()["public_MVE_Main10_profile_option_enum"],4)
        self.assertEqual(a.public_nalu_abi()["coded_HEVC_SPS_Main10_general_profile_idc"],2)
    def test_index1_not_profile_index3(self):
        self.assertTrue(a.public_nalu_abi()["a_NALU_length_format_is_not_an_HEVC_Main10_profile"])
    def test_prefix_4B_total9(self):
        self.assertEqual(a.fourbyte_nalu_prefix(9),b"\x00\x00\x00\x05")
    def test_prefix_total65540(self):
        self.assertEqual(a.fourbyte_nalu_prefix(65540),b"\x00\x01\x00\x00")
    def test_prefix_total0(self):
        with self.assertRaisesRegex(ValueError,"filled_len"):
            a.fourbyte_nalu_prefix(0)
    def test_prefix_total4(self):
        with self.assertRaisesRegex(ValueError,"filled_len"):
            a.fourbyte_nalu_prefix(4)
    def test_prefix_negative(self):
        with self.assertRaisesRegex(ValueError,"filled_len"):
            a.fourbyte_nalu_prefix(-5)
    def test_prefix_fits32(self):
        self.assertEqual(a.fourbyte_nalu_prefix(0xffffffff),b"\xff\xff\xff\xfb")
    def test_prefix_overflows32(self):
        with self.assertRaisesRegex(ValueError,"filled_len"):
            a.fourbyte_nalu_prefix(0x100000000)
    def test_prefix_reject_float(self):
        with self.assertRaisesRegex(ValueError,"filled_len"):
            a.fourbyte_nalu_prefix(9.3)
    def test_a32_reader_little_endian(self):
        self.assertEqual(a.arm_word(bytes.fromhex("78563412"),a.BASE),0x12345678)
    def test_a32_reader_unaligned(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            a.arm_word(b"\x00"*8,a.BASE+1)
    def test_a32_reader_underrun(self):
        with self.assertRaisesRegex(ValueError,"absent"):
            a.arm_word(b"\x00"*8,a.BASE-4)
    def test_a32_reader_overrun(self):
        with self.assertRaisesRegex(ValueError,"absent"):
            a.arm_word(b"\x00"*8,a.BASE+8)
    def test_decode_bl_forward(self):
        self.assertEqual(a.bl_target(bl(0x1000,0x1800),0x1000),0x1800)
    def test_decode_bl_backward(self):
        self.assertEqual(a.bl_target(bl(0x1800,0x1000),0x1800),0x1000)
    def test_non_bl_opcode(self):
        with self.assertRaisesRegex(ValueError,"opcode"):
            a.bl_target(0xe3a00001,0x1000)
    def test_non_uncond_bl(self):
        with self.assertRaisesRegex(ValueError,"opcode"):
            a.bl_target(0x1b000000,0x1000)
    def test_short_synthetic_source_shape(self):
        for m in a.MODELS.values():
            self.assertEqual(len(a.source_words(m)),6)

class StaticToyROM(unittest.TestCase):
    def test_both_model_positive(self):
        for model in a.MODELS:
            with self.subTest(model=model):
                report=verified_toy(model)
                self.assertTrue(report["option1_NALU_FORMAT_uses_saved_value_in_two_branches"])
                self.assertTrue(report["output_mode16_converts_filled_len_minus4_to_be32"])
                self.assertEqual(report["param_block_bytes"],"0x30")
    def test_no_runtime_mode_proven(self):
        for model in a.MODELS:
            report=verified_toy(model)
            self.assertFalse(report["runtime_param_1_value_or_movie_encoder_invocation_proven"])
            self.assertFalse(report["real_main10_SPS_captured"])
            self.assertFalse(report["physical_camera_modified"])
    def test_direct_xref_bounded(self):
        report=verified_toy("xt4")
        self.assertEqual(report["direct_Ghidra_refs_to_source_RAM"],2)
        self.assertFalse(report["aliases_indirect_writers_excluded"])
    def test_source_wrong_ROM_hash(self):
        m=a.MODELS["xs10"];f=synthetic(m)
        with patch.object(a,"sha256",return_value=SimpleNamespace(hexdigest=lambda:"0"*64)):
            with self.assertRaisesRegex(ValueError,"SHA"):
                a.verify_model(m,b"TOY",f["logs"],f["prior"])
    def test_prior_missing_comparison(self):
        m=a.MODELS["xs10"];f=synthetic(m)
        del f["prior"]["fuji_original_ARM_and_readonly_Ghidra"]
        with self.assertRaises(Exception):
            a.check_prior43(f["prior"],m)
    def test_prior_main10_must_remain_unproven(self):
        m=a.MODELS["xs10"];f=synthetic(m)
        f["prior"]["fuji_original_ARM_and_readonly_Ghidra"][0]["Main10_SPS_or_hvcC_extracted"]=True
        with self.assertRaisesRegex(ValueError,"prior original"):
            a.check_prior43(f["prior"],m)

def changed_word(model,field):
    def t(self):
        def mutate(m,fixture):
            site=getattr(m,field)
            fixture["words"][site]^=1
        with self.assertRaisesRegex(ValueError,"original 48B"):
            verified_toy(model,mutate)
    return t

for model in a.MODELS:
    for field in ("stm_a","stm_b","stm_c","compare16","reader_ldr","reader_str"):
        setattr(StaticToyROM,"test_corrupt_orig_word_"+field+"_"+model,
                changed_word(model,field))

def changed_bl(model,field):
    def t(self):
        def mutate(m,fixture):
            site=getattr(m,field)
            fixture["words"][site]=bl(site,m.source_fn+0x58)
        with self.assertRaisesRegex(ValueError,"BL target"):
            verified_toy(model,mutate)
    return t

for model in a.MODELS:
    for field in ("adapter_bl","snd_bl","hdr_bl"):
        setattr(StaticToyROM,"test_wrong_orig_bl_"+field+"_"+model,
                changed_bl(model,field))

def changed_snippet(model,part,left,right,reason):
    def t(self):
        def mutate(m,fixture):
            assert left in fixture["logs"][part],(part,left)
            fixture["logs"][part]=fixture["logs"][part].replace(left,right)
        with self.assertRaisesRegex(ValueError,reason):
            verified_toy(model,mutate)
    return t

variants=(
  ("source","dec_param","other_case","decoder-parameter"),
  ("source","= *param_1;","= 0;","decoder-parameter"),
  ("source","= param_1[0xb];","= 0;","decoder-parameter"),
  ("source","*param_1 == 0x10","*param_1 == 0x20","decoder-parameter"),
  ("source","*param_1 == 1","*param_1 == 3","decoder-parameter"),
  ("source","bVar1 = *pbVar10;","bVar1 = 0;","decoder-parameter"),
  ("source","*pbVar10 = bVar4;","*pbVar10 = bVar1;","decoder-parameter"),
  ("source","pbVar10[1] = bVar3;","pbVar10[1] = bVar4;","decoder-parameter"),
  ("source","pbVar10[2] = bVar2;","pbVar10[2] = bVar4;","decoder-parameter"),
  ("source","pbVar10[3] = bVar1;","pbVar10[3] = bVar4;","decoder-parameter"),
  ("source","uVar12 = 2;","uVar12 = 4;","decoder-parameter"),
  ("source","uVar12 = 3;","uVar12 = 5;","decoder-parameter"),
  ("source","[6] = _DAT_","[5] = _DAT_","CPU init"),
  ("opts","local_58 = 1;","local_58 = 3;","SndSetOption"),
  ("opts","local_54 = _DAT_","local_54 = _MISSING_","SndSetOption"),
  ("opts","0x3f2,8","0x3f1,8","SndSetOption"),
  ("opts","local_58 = 0x10;","local_58 = 0x20;","SndSetOption"),
  ("opts","local_58 = 0x26;","local_58 = 0x27;","SndSetOption"),
  ("response","[6] == 0x10","[6] == 0x20","CPU return"),
  ("response"," + -4;"," + -5;","CPU return"),
  ("response","iVar9 >> 0x18","iVar9 >> 0x10","CPU return"),
  ("response","iVar9 >> 0x10","iVar9 >> 0x08","CPU return"),
  ("response","iVar9 >> 8","iVar9 >> 7","CPU return"),
  ("response","puVar5[3] = (char)iVar9;","puVar5[3] = 0;","CPU return"),
  ("refs","type=WRITE","type=READ","Ghidra direct"),
  ("refs","refs=2","refs=3","Ghidra direct"),
  ("adapter","();","(42);","API adapter"),
)
for i,(scope,left,right,reason) in enumerate(variants):
    model=("xs10","xt4")[i%2]
    setattr(StaticToyROM,"test_change_Ghidra_%02d_%s"%(i,model),
            changed_snippet(model,scope,left,right,reason))

# Prefix byte checks across disjoint uint32 ranges, to guard endianness.
for size in (5,8,24,255,256,1024,65536,65539,65540,1000000):
    def build_t(total):
        def t(self):
            raw=a.fourbyte_nalu_prefix(total)
            self.assertEqual(int.from_bytes(raw,"big"),total-4)
            self.assertEqual(len(raw),4)
        return t
    setattr(NaluABI,"test_be32_len_%d"%size,build_t(size))

if __name__=="__main__":unittest.main()

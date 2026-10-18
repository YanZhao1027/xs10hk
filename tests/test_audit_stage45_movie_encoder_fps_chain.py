"""Synthetic-only fault-injection tests for Stage45 movie fps->encoder MVE setup.

No Fuji samples, ROM slices or vendor Ghidra database are embedded.
All C-like fragments, A32 words, and fake SHA values are generated inside
tests and are checked via mocks. All real audit executions use pinned ROM.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import re
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage45_movie_encoder_fps_chain as s

def bl(site,dest):
    diff=dest-site-8
    assert diff%4==0 and -(1<<25)<=diff<(1<<25)
    return 0xeb000000|((diff//4)&0xffffff)

def c_fn(name,body,typ="void"):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"+
            "%s FUN_%08x(void)\n{\n%s\n}\n"%(typ,name,body)+
            "TRACE_DECOMP_END (GhidraScript)\n")

def fixtures(m):
    # Intentionally fictitious local instructions, only the positive sites'
    # decoded numeric form is reproduced for test of the verification logic.
    words={
        m.movie_wrapper_bl:bl(m.movie_wrapper_bl,s.ENCODER_ADAPTER[m.name]),
        m.source_fn_bl:bl(m.source_fn_bl,m.source_fn),
        m.init_bl:bl(m.init_bl,m.init_fn),
        m.option_bl:bl(m.option_bl,m.option_fn),
        m.bufferparam_bl:bl(m.bufferparam_bl,m.bufferparam_fn),
        m.source_stmia:0xe8ae000f,
        m.source_stmia2:0xe8ae000f,
        m.cached_codecreg:0xe5930000,
        m.cached_nalreg:0xe5933004,
        m.cached_fpsreg:0xe5930008,
        m.cached_rcmode_reg:0xe593000c,
        m.cached_rcbitrate_reg:0xe5930010,
        m.movie_mode_store:0xe5832004,
    }
    for site in m.fps_ram_store_sites:
        words[site]=s.FPS_STORE_ORIGINAL[m.name]
    p="_DAT_%08x"%m.movie_param_ram
    sv="_DAT_%08x"%m.saved_ram
    cfg="_DAT_%08x"%m.cache
    # Synthetic short MovieSetup with six switch cases: never vendor decompile
    movie=(
     "int iVar7;\n"
     "FUN_ffff0000(&DAT_%08x,0,0x3c);\n"%m.movie_param_ram+
     "_DAT_%08x = 0x10;\n"%(m.movie_param_ram+4)+
     "if (iVar7 + 0x5f5) pick((param_1 + 0x5c6),(param_1 + 0x5c7));\n"
     "width=(iVar7 + 0x602); height=(iVar7 + 0x600);\n"
     "if (param_1 + 0xadda) codec=0xca0000; else codec=0xd08000;\n")
    for k,v in s.FPS_TABLE.items():
        movie+="case %d:\n  _DAT_%08x = 0x%x;\n  break;\n"%(k,m.movie_param_ram+8,v)
    movie+="FUN_%08x(&DAT_%08x, 0x123);\n"%(s.ENCODER_ADAPTER[m.name],m.movie_param_ram)
    encoder="enc_param fixture\n%s = *param_1;\n"%sv
    for idx in range(1,15):
        encoder+="_DAT_%08x = param_1[0x%x];\n"%(m.saved_ram+idx*4,idx)
    loader=(
     "V61_drv_set_enc_param_start\n"
     "%s[2] = _DAT_%08x;\n"%(cfg,m.saved_ram+12)+
     "piVar1[3] = _DAT_%08x;\n"%(m.saved_ram+16)+
     "piVar1[4] = _DAT_%08x;\n"%(m.saved_ram+8)+
     "piVar1[5] = %s;\n"%sv+
     "piVar1[6] = _DAT_%08x;\n"%(m.saved_ram+4)+
     "FUN_%08x();\nFUN_%08x();\n"%(m.option_fn,m.bufferparam_fn))
    options=(
     "local_58 = 1;\nlocal_54 = %s[6];\n"%cfg+
     "FUN_%08x(0x3f2,8,&local_58);\n"%m.option_generic+
     "local_58 = 0x10;\nlocal_54 = piVar1[5];\n"
     "FUN_%08x(0x3f2,8,&local_58);\n"%m.option_generic+
     "local_58 = 1;\nlocal_54 = %s[6];\n"%cfg+
     "FUN_%08x(0x3f2,8,&local_58);\n"%m.option_generic)
    buf=(
     "*_DAT_fake = 9;\n"
     "payload = *(undefined4 *)(%s + 0x10);\n"%cfg+
     "FUN_%08x(puVar2,0xbbb,8);\n"%m.bufferparam_generic+
     "*_DAT_fake = 10;\n"
     "payload = *(undefined4 *)(%s + 8);\n"%cfg+
     "payload2 = *(undefined4 *)(iVar1 + 0xc);\n"
     "FUN_%08x(puVar2,0xbbb,0xc);\n"%m.bufferparam_generic+
     "*_DAT_fake = 0x17;\n"
     "*_DAT_fake = 0xf;\n"
     "*_DAT_fake = 0x15;\n"
    )
    src_refs=""
    for idx,readsite in enumerate((
        m.cached_codecreg,m.cached_nalreg,m.cached_fpsreg,
        m.cached_rcmode_reg,m.cached_rcbitrate_reg)):
        addr=m.saved_ram+4*idx
        writer=m.source_stmia if idx<4 else m.source_stmia2
        src_refs+=("PROBE_TARGET addr=%08x refs=2\n"%addr+
                   "PROBE_REF from=%08x to=%08x type=WRITE\n"%(writer,addr)+
                   "PROBE_REF from=%08x to=%08x type=READ\n"%(readsite,addr))
    state={"xs10":"_DAT_0182197c","xt4":"_DAT_01790d8c"}[m.name]
    router={"xs10":0x011f93dc,"xt4":0x011cca88}[m.name]
    decoder={"xs10":0x011f89f0,"xt4":0x011cc09c}[m.name]
    encoder+="%s = 2;\n"%state
    route=("if (%s == 2) FUN_%08x();\n"%(state,m.init_fn)+
           "if (%s == 3) FUN_%08x();\n"%(state,decoder))
    fps_xref="PROBE_TARGET addr=%08x refs=6\n"%(m.movie_param_ram+8)
    for site in m.fps_ram_store_sites:
        fps_xref+="PROBE_REF from=%08x to=%08x type=WRITE insn=synthetic\n"%(site,m.movie_param_ram+8)
    fps_xref+="PROBE_TARGET addr=%08x refs=1\n"%(m.movie_param_ram+4)
    return {
      "rawwords":words,
      "logs":{
        "movie":c_fn(m.movie_fn,movie,"undefined4"),
         "source":c_fn(m.source_fn,encoder,"undefined4")+c_fn(m.init_fn,loader,"int")+c_fn(router,route),
        "consumers":c_fn(m.option_fn,options)+c_fn(m.bufferparam_fn,buf),
        "entry_xrefs":"PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n"%(
                         m.movie_wrapper_bl,s.ENCODER_ADAPTER[m.name]),
        "fps_xrefs":fps_xref,
        "source_xrefs":src_refs,
      }
    }

def mock_result(model,mutator=None,part="ghidra"):
    m=s.MODELS[model]
    toy=fixtures(m)
    if mutator: mutator(m,toy)
    if part=="ghidra":
        return s.validate_ghidra(m,toy["logs"])
    sha=lambda arg:SimpleNamespace(hexdigest=lambda:
         s.ROM1_SHA[m.name] if arg==b"TOY1" else m.sha2)
    with patch.object(s,"sha256",side_effect=sha),patch.object(s,"u32",
                   side_effect=lambda _blob,at,_base:toy["rawwords"][at]):
        return s.check_raw_rom(m,b"TOY1",b"TOY2")

class Abi(unittest.TestCase):
    def test_official_public_mapping(self):
        self.assertEqual(s.check_public_abi()["public_MVE_abi_values"],s.PUBLIC_MVE)
    def test_nalu_index1(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_SET_OPT_INDEX_NALU_FORMAT"],1)
    def test_pframe_index16(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_SET_OPT_INDEX_ENC_P_FRAMES"],16)
    def test_fps_type9(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_BUFFER_PARAM_TYPE_FRAME_RATE"],9)
    def test_rate_control_type10(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_BUFFER_PARAM_TYPE_RATE_CONTROL"],10)
    def test_hrd_type23(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_BUFFER_PARAM_TYPE_RATE_CONTROL_HRD_BUF_SIZE"],23)
    def test_color_type15(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_BUFFER_PARAM_TYPE_COLOUR_DESCRIPTION"],15)
    def test_qp_type21(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_BUFFER_PARAM_TYPE_RATE_CONTROL_QP_RANGE"],21)
    def test_param_code_0bbb(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_BUFFER_CODE_PARAM"],3003)
    def test_setoption_code_0x3f2(self):
        self.assertEqual(s.PUBLIC_MVE["MVE_REQUEST_CODE_SET_OPTION"],1010)
    def test_q16_unit(self):
        self.assertEqual(s.Q16,65536)
    def test_no_default_MVE_Main10_proven(self):
        self.assertFalse(s.check_public_abi()["V61_default_Main10_profile_proven"])
    def test_no_profile_index3_in_senders(self):
        self.assertFalse(s.check_public_abi()["MVE_Main10_profile_option_index_3_seen_in_this_encoder_path"])
    def test_q16_validity(self):
        for k,v in s.FPS_TABLE.items():
            self.assertEqual(s.to_fps(v),v/65536)
    def test_false_neg_fps(self):
        with self.assertRaisesRegex(ValueError,"Q16"):
            s.to_fps(-2)
    def test_false_float_fps(self):
        with self.assertRaisesRegex(ValueError,"Q16"):
            s.to_fps(2400000.5)
    def test_false_64bit_fps(self):
        with self.assertRaisesRegex(ValueError,"Q16"):
            s.to_fps(0x100000000)
    def test_read_rom_little_endian(self):
        self.assertEqual(s.u32(b"\x78\x56\x34\x12",s.SECTION1_BASE,s.SECTION1_BASE),0x12345678)
    def test_read_rom_out_bounds(self):
        with self.assertRaisesRegex(ValueError,"OOB"):
            s.u32(b"\x00"*4,s.SECTION1_BASE+4,s.SECTION1_BASE)
    def test_read_rom_unaligned(self):
        with self.assertRaisesRegex(ValueError,"OOB"):
            s.u32(b"\x00"*4,s.SECTION1_BASE+1,s.SECTION1_BASE)
    def test_a32_bl_forward(self):
        self.assertEqual(s.a32_bl_target(bl(0x1000,0x4000),0x1000),0x4000)
    def test_a32_bl_backward(self):
        self.assertEqual(s.a32_bl_target(bl(0x4000,0x1000),0x4000),0x1000)
    def test_a32_bl_wrong_op(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            s.a32_bl_target(0xe3a00000,0x1000)
    def test_a32_bl_wrong_conditional(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            s.a32_bl_target(0x1b000000,0x1000)

class OriginalAuditSimulation(unittest.TestCase):
    def test_both_models_synthetic_Ghidra_positive(self):
        for m in s.MODELS:
            with self.subTest(m=m):
                x=mock_result(m)
                self.assertTrue(x["option1_NALU_FORMAT_uses_saved_value_in_two_branches"] if "option1_NALU_FORMAT_uses_saved_value_in_two_branches" in x else x["MovieSetup_statically_sets_param1_NALU_to"]=="0x10")
    def test_both_models_synthetic_original_rom_positive(self):
        for m in s.MODELS:
            x=mock_result(m,part="raw")
            self.assertEqual(len(x["six_original_fps_writer_A32_STR_sites"]),6)
    def test_both_models_have_framerate_option_not_profile3(self):
        for m in s.MODELS:
            x=mock_result(m)
            self.assertFalse(x["HEVC_V61_default_profile_known"])
            self.assertFalse(x["direct_SndSetOption_index3_profile_level_found_here"])
    def test_both_models_no_4k60_proven(self):
        for m in s.MODELS:
            x=mock_result(m)
            self.assertFalse(x["X_S10_physical_4K60_supported_proven"])
    def test_fps_5994_not_exact_60(self):
        self.assertGreater(s.to_fps(s.FPS_TABLE[6]),59.93)
        self.assertLess(s.to_fps(s.FPS_TABLE[6]),59.95)
        self.assertNotEqual(s.FPS_TABLE[6],0x3c0000)
    def test_fps_2997_not_exact_30(self):
        self.assertNotEqual(s.FPS_TABLE[4],0x1e0000)
    def test_23_98_value(self):
        self.assertAlmostEqual(s.to_fps(s.FPS_TABLE[1]),23.98,2)
    def test_24_00_value(self):
        self.assertEqual(s.to_fps(s.FPS_TABLE[2]),24)
    def test_25_00_value(self):
        self.assertEqual(s.to_fps(s.FPS_TABLE[3]),25)
    def test_50_00_value(self):
        self.assertEqual(s.to_fps(s.FPS_TABLE[5]),50)

def altered_a32(model,field,at_fn=None):
    def t(self):
        def change(m,d):
            site=(at_fn(m) if at_fn else getattr(m,field))
            d["rawwords"][site]^=1
        with self.assertRaises(ValueError):
            mock_result(model,change,"raw")
    return t

for m in s.MODELS:
    for f in ("movie_wrapper_bl","source_fn_bl","init_bl","option_bl",
              "bufferparam_bl","source_stmia","source_stmia2",
              "cached_codecreg","cached_nalreg","cached_fpsreg",
              "cached_rcmode_reg","cached_rcbitrate_reg","movie_mode_store"):
        setattr(OriginalAuditSimulation,"test_corrupt_A32_%s_%s"%(m,f),
                altered_a32(m,f))
    for i in range(6):
        setattr(OriginalAuditSimulation,"test_corrupt_fps_writer_%d_%s"%(i,m),
                altered_a32(m,None,at_fn=lambda obj,i=i:obj.fps_ram_store_sites[i]))

def corrupt_ghidra(model,scope,term,new):
    def t(self):
        def change(m,d):
            assert term in d["logs"][scope],(scope,term)
            d["logs"][scope]=d["logs"][scope].replace(term,new)
        with self.assertRaises(ValueError):
            mock_result(model,change)
    return t

mutations=(
 ("movie","0,0x3c);","0,0x38);"),
 ("movie"," + 0x5c6"," + 0x5c8"),
 ("movie"," + 0x5c7"," + 0x5c9"),
 ("movie"," + 0x5f5"," + 0x5f4"),
 ("movie"," + 0x600"," + 0x610"),
 ("movie"," + 0x602"," + 0x604"),
 ("movie"," + 0xadda"," + 0xaddc"),
 ("movie","0xca0000","0xcc0000"),
 ("movie","0xd08000","0xd0a000"),
 ("movie"," = 0x10;"," = 0x11;"),
 ("movie","case 1:","case 0:"),
 ("movie","case 2:","case 9:"),
 ("movie","case 3:","case 10:"),
 ("movie","case 4:","case 11:"),
 ("movie","case 5:","case 12:"),
 ("movie","case 6:","case 13:"),
 ("source","enc_param","dec_param"),
 ("source"," = *param_1;"," = 0;"),
 ("source"," = param_1[0xe];"," = param_1[0xd];"),
 ("source","[2] = _DAT_","[20] = _DAT_"),
 ("source","piVar1[3] =","piVar1[7] ="),
 ("source","piVar1[4] =","piVar1[8] ="),
 ("source","piVar1[5] =","piVar1[9] ="),
 ("source","piVar1[6] =","piVar1[10] ="),
 ("consumers","local_58 = 1;","local_58 = 3;"),
 ("consumers","local_58 = 0x10;","local_58 = 0x12;"),
 ("consumers","local_54 = piVar1[5];","local_54 = piVar1[7];"),
 ("consumers","0x3f2,8","0x3f2,12"),
 ("consumers"," = 9;"," = 8;"),
 ("consumers"," = 10;"," = 8;"),
 ("consumers","0xbbb,8","0xbb9,8"),
 ("consumers","0xbbb,0xc","0xbbb,0x10"),
 ("consumers"," = 0x17;"," = 0x18;"),
 ("consumers"," = 0xf;"," = 0xe;"),
 ("consumers"," = 0x15;"," = 0x16;"),
 ("fps_xrefs","refs=6","refs=7"),
 ("entry_xrefs","type=UNCONDITIONAL_CALL","type=READ"),
)
for i,(scope,term,new) in enumerate(mutations):
    model=list(s.MODELS)[i%2]
    setattr(OriginalAuditSimulation,"test_mutate_C_%02d_%s"%(i,model),
            corrupt_ghidra(model,scope,term,new))

# Synthetic variation over Q16 endpoints, each generated completely locally.
for i in range(1,7):
    def make_t(index):
        def t(self):
            f=s.to_fps(s.FPS_TABLE[index])
            self.assertGreater(f,0)
            self.assertEqual(round(f*65536),s.FPS_TABLE[index])
        return t
    setattr(Abi,"test_round_trip_q16_%d"%i,make_t(i))

if __name__=="__main__":unittest.main()

"""Stage48 pure-synthetic checks: runtime Recorder A8E flag provenance.

No vendor firmware, original Ghidra code, microcode or live camera data.
Ghidra-style text and ARM BL instructions are generated from scratch in
memory solely to exercise strict evidence-bound source auditing.
"""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage48_recorder_a8e_flag_origin as s
import audit_stage45_movie_encoder_fps_chain as old45

def toy_bl(site,target):
    delta=target-site-8
    assert delta%4==0 and -(1<<25)<=delta<1<<25
    return 0xeb000000|((delta//4)&0xffffff)

def fake_C(fn,body,ret="void"):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"+
            "%s FUN_%08x(void)\n{\n%s\n}\n"%(ret,fn,body)+
            "TRACE_DECOMP_END (GhidraScript)\n")

def fixture(m):
    point="_DAT_%08x"%m.parent_ptr
    cls="FUN_%08x"%m.classifier_fn
    live="DAT_%08x"%m.active_flag_ram
    pool=m.pool_head
    init=(
        "FUN_%08x(&DAT_%08x,&DAT_%08x,record);\n"%
        (m.registration_fn,m.parent_ptr-4,m.parent_ptr)+
        "uVar1 = FUN_%08x();\n"%m.movie_type_fn+
        "*(undefined1 *)(iVar2 + 0x%x) = uVar1;\n"%(pool+0xa8c)+
        "iVar2 = %s(*(undefined1 *)(%s + 0xa8c));\n"%(cls,point)+
        "if (iVar2 == 0) { uVar1 = 0; } else {\n"+
        "uVar1 = FUN_%08x();\n"%m.flag_getter_fn+
        "}\n"
        "*(undefined1 *)(local_30 * 0x%x + 0x%x) = uVar1;\n"%
        (m.stride,pool+0xa8e)+
        "iVar2 = FUN_%08x(1);\n"%m.classifier_fn+
        "if (iVar2 == 0) { uVar1 = 0; } else {\n"+
        "uVar1 = FUN_%08x();\n"%m.companion_getter_fn+
        "}\n"+
        "*(undefined1 *)(iVar2 + 0x%x) = uVar1;\n"%(pool+0xa8f)
    )
    reset=point+" = 0xffffffff;\n" if m.name=="xs10" else "param_4[1] = param_3;\n"
    getter=fake_C(m.flag_getter_fn,"return DAT_%08x;"%m.active_flag_ram,ret="undefined1")
    getter+=fake_C(m.companion_getter_fn,
                   "return DAT_%08x;"%m.active_companion_ram,ret="undefined1")
    getter+=fake_C(m.movie_type_fn,"return DAT_%08x;"%m.movie_type_ram,ret="undefined1")
    getter+=fake_C(m.classifier_fn,
                   "switch (param_1) { case 1: return 0; case 4: case 5: case 6: case 7: return 1;}",
                   ret="undefined4")
    exporter=fake_C(m.snapshot_exporter_fn,
                    "param_1[0x581] = DAT_%08x;\n"%m.active_flag_ram+
                    "param_1[0x580] = DAT_%08x;\n"%m.active_companion_ram+
                    "param_1[0x5b0] = DAT_%08x;\n"%m.active_codec_ram)
    ptrlog=("ST48_PTR_SUMMARY addr=%08x total=116 read=113 write=1 other=2\n"%m.parent_ptr+
            ("ST48_PTR_REF at=022402c0 function=FUN_022402bc type=WRITE\n"
            if m.name=="xt4" else ""))
    xref=""
    for a,site in ((m.active_flag_ram,m.flag_getter_ldrb),
                   (m.active_companion_ram,m.companion_getter_ldrb)):
        xref+=("PROBE_TARGET addr=%08x refs=2\n"%a+
               "PROBE_REF from=%08x to=%08x type=READ\n"%(site,a))
    arms={}
    for site,target in ((m.register_bl,m.registration_fn),
                        (m.movie_bl,m.movie_type_fn),
                        (m.classifier_bl,m.classifier_fn),
                        (m.flag_bl,m.flag_getter_fn),
                        (m.companion_bl,m.companion_getter_fn)):
        arms[site]=toy_bl(site,target)
    arms[m.flag_getter_ldrb]=s.EXPECTED_GETTER_LDRB[m.name][0]
    arms[m.companion_getter_ldrb]=s.EXPECTED_GETTER_LDRB[m.name][1]
    return {
      "logs":{
        "reset":fake_C(m.reset_fn,reset),
        "init":fake_C(m.init_fn,init),
        "getters":getter,"export":exporter,
        "pointer":ptrlog,"xref":xref
      },
      "arms":arms,
      "prior":{
        "stage46":{"both_original_ROM_96_by_64_records_byte_identical":True},
        "stage47":{
           "model_specific_4K60_restriction_proven":False,
           "two_original_ROMs_original_ARM_and_readonly_Ghidra":[
              {"model":name,
               "runtime_flag_offset":"0xA8E",
               "4K_type_and_flag1_forces_low_mode_key_6":True,
               "codec_source_getter":"FUN_%08x"%s.st47.MODELS[name].getter_fn}
              for name in ("xs10","xt4")
           ],
        }
      }
    }

def verified_toy(model,mutation=None):
    m=s.MODELS[model]
    f=fixture(m)
    if mutation: mutation(m,f)
    class FakeHash:
        def __init__(self,data): self.data=data
        def hexdigest(self):
            return (old45.ROM1_SHA[m.name] if self.data==b"fake-X6-section1"
                    else old45.MODELS[m.name].sha2)
    with patch.object(s,"sha256",side_effect=lambda data:FakeHash(data)),\
         patch.object(s.st47,"read_arm_word",
            side_effect=lambda _a,_b,_model,site:f["arms"][site]):
        return s.check_model(m,b"fake-X6-section1",b"fake-X6-section2",
                             f["logs"],f["prior"])

class TraceRules(unittest.TestCase):
    def test_all_8_movie_types_flag1(self):
        for typ in range(8):
            self.assertEqual(s.flag_from_source(typ,1),1 if 4<=typ<=7 else 0)
    def test_two_recorder_models_field_offsets(self):
        for model in s.MODELS:
            x=s.active_snapshot_offsets(s.MODELS[model])
            self.assertEqual(x["snap_export_source_flag_offset"],"0x581")
            self.assertEqual(x["snap_export_source_second_flag_offset"],"0x580")
            self.assertEqual(x["snap_export_source_codec_offset"],"0x5b0")
    def test_active_flag_is_not_codec(self):
        for m in s.MODELS.values():
            self.assertEqual(m.active_codec_ram-m.active_flag_ram,0x34)
    def test_xt4_active_flag_is_not_xs10_addr(self):
        self.assertNotEqual(s.MODELS["xt4"].active_flag_ram,
                            s.MODELS["xs10"].active_flag_ram)
    def test_parent_pool_stride_differs(self):
        self.assertNotEqual(s.MODELS["xt4"].stride,s.MODELS["xs10"].stride)
    def test_invalid_movie_type(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            s.flag_from_source(256,1)
    def test_negative_movie_type(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            s.flag_from_source(-1,1)
    def test_negative_flag(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            s.flag_from_source(4,-1)
    def test_bad_flag_gt255(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            s.flag_from_source(4,256)
    def test_bad_float_flag(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            s.flag_from_source(4,1.5)
    def test_4k_flag1_key_override_to_1080(self):
        self.assertEqual(s.compute_movie_key(4,1,7,2),0x0206)
        self.assertEqual(s.compute_movie_key(7,1,7,7),0x0706)
    def test_4k_flag2_does_not_force_key6(self):
        self.assertEqual(s.compute_movie_key(4,2,7,2),0x0207)
        self.assertEqual(s.compute_movie_key(7,2,7,7),0x0707)
    def test_not4k_flag1_does_not_force_key6(self):
        self.assertEqual(s.compute_movie_key(3,1,7,2),0x0207)
    def test_invalid_keybyte(self):
        with self.assertRaisesRegex(ValueError,"invalid"):
            s.compute_movie_key(4,1,7,-2)
    def test_original_snapshot_offset_not_runtime_flag(self):
        self.assertNotEqual(0x581,0xa8e)
    def test_flag2_independent_field(self):
        for m in s.MODELS.values():
            self.assertEqual(m.active_companion_ram,m.active_flag_ram+1)
    def test_no_physical_mode_claim_from_toy(self):
        for model in s.MODELS:
            r=verified_toy(model)
            self.assertFalse(r["observed_true_runtime_active_Recorder_flag_value"])
            self.assertFalse(r["X_S10_specific_4K59_94_gate_or_Main10_bitstream_proven"])
            self.assertFalse(r["original_active_config_field_assignment_writer_fully_proven"])

class AuditedSyntheticModels(unittest.TestCase):
    def test_both_models_valid_fixture(self):
        for model in s.MODELS:
            with self.subTest(model=model):
                r=verified_toy(model)
                self.assertEqual(r["parent_pointer_xrefs_total"],116)
                self.assertEqual(r["parent_flag_a8e_source_when_NOT_4K"],0)
                self.assertEqual(r["4K_class_movie_types"],[4,5,6,7])
    def test_xt4_reset_not_assumed_literal_minus1(self):
        r=verified_toy("xt4")
        self.assertFalse(r["generic_XT4_parent_reset_caller_value_minus_one_confirmed"])
    def test_xs10_literal_parent_reset(self):
        r=verified_toy("xs10")
        self.assertTrue(r["parent_pointer_direct_write_is_initializer_not_runtime_registration"])
    def test_prior_stage47_restriction_not_proven(self):
        def change(m,f):f["prior"]["stage47"]["model_specific_4K60_restriction_proven"]=True
        with self.assertRaisesRegex(ValueError,"Phase46/47"):
            verified_toy("xs10",change)
    def test_prior_rom_digest_wrong(self):
        m=s.MODELS["xs10"]; f=fixture(m)
        with patch.object(s,"sha256",
               return_value=SimpleNamespace(hexdigest=lambda:"0"*64)):
            with self.assertRaisesRegex(ValueError,"SHA256"):
                s.check_model(m,b"toy",b"toy",f["logs"],f["prior"])
    def test_wrong_pair_offsets(self):
        m=s.MODELS["xs10"]
        from dataclasses import replace
        with self.assertRaisesRegex(ValueError,"layout"):
            s.active_snapshot_offsets(replace(m,active_codec_ram=m.active_codec_ram+2))

# Fail-closed A32 sites: all five original independent BLs plus two live getters.
sites=("register_bl","movie_bl","classifier_bl","flag_bl","companion_bl",
       "flag_getter_ldrb","companion_getter_ldrb")
for model in s.MODELS:
    for name in sites:
        def build(model,name):
            def test(self):
                def mutant(m,fixture):fixture["arms"][getattr(m,name)]^=1
                with self.assertRaises(ValueError):
                    verified_toy(model,mutant)
            return test
        setattr(AuditedSyntheticModels,"test_mutate_A32_"+name+"_"+model,
                build(model,name))

# Mutate artificial string fragments to test object-pointer, conditional
# class, memory alias, snapshot field and source-to-parent assignment.
def altered(model,which,old,new,expect=""):
    def test(self):
        def mangle(m,fixture):
            assert old in fixture["logs"][which],(model,old)
            fixture["logs"][which]=fixture["logs"][which].replace(old,new)
        with self.assertRaisesRegex(ValueError,expect):
            verified_toy(model,mangle)
    return test

changes=[
 ("reset","0xffffffff","0x11111111"),
 ("init","0xa8c","0xa8b"),
 ("init"," = 0; } else"," = 1; } else"),
 ("init","local_30 * 0x","local_30 * 0x11111 + 0x"),
 ("init","iVar2 + 0x","iVar2 + 0x001"), 
 ("init","uVar1 = FUN_","uVar1 = FAKE_"),
 ("getters","return DAT_","return FAKE_"),
 ("getters","case 4:","case 9:"),
 ("getters","case 5:","case 9:"),
 ("getters","case 6:","case 9:"),
 ("getters","case 7:","case 9:"),
 ("export","param_1[0x581]","param_1[0x589]"),
 ("export","param_1[0x580]","param_1[0x588]"),
 ("export","param_1[0x5b0]","param_1[0x5b1]"),
 ("pointer","total=116","total=115"),
 ("pointer","read=113","read=112"),
 ("xref","refs=2","refs=3"),
 ("xref","type=READ","type=WRITE"),
]
for model in s.MODELS:
    for i,(scope,old,new) in enumerate(changes):
        # X-T4 generic reset is caller-param forwarded, not a literal.
        if model=="xt4" and scope=="reset":old,new="param_4[1]","param_4[2]"
        setattr(AuditedSyntheticModels,"test_bad_trace_%02d_%s"%(i,model),
                altered(model,scope,old,new))

for typ in range(0,8):
    for flag in (0,1,2,3):
        def mk(typ,flag):
            def test(self):
                actual=s.flag_from_source(typ,flag)
                self.assertEqual(actual,flag if typ in (4,5,6,7) else 0)
                expected_low=6 if typ in (4,5,6,7) and flag==1 else 7
                self.assertEqual(s.compute_movie_key(typ,flag,7,2),0x200+expected_low)
            return test
        setattr(TraceRules,"test_synthetic_class_%d_flag_%d"%(typ,flag),mk(typ,flag))

if __name__=="__main__": unittest.main()

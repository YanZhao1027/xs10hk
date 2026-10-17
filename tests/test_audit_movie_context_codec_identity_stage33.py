"""Synthetic-only positive and adversarial tests for phase33 X6 evidence audit.

No Fujifilm ROM words or private device data are embedded. All test ARM words,
decompiler text, and string fragments are constructed inside this module.
"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_movie_context_codec_identity_stage33 as a

def mw(reg,imm,high=False,cond=14):
    return ((cond<<28)|(0x03400000 if high else 0x03000000)|
            ((imm>>12&15)<<16)|(reg<<12)|(imm&0xfff))
def branch(frm,to):
    x=to-frm-8
    if x%4 or not -(1<<25)<=x<(1<<25):raise ValueError("unencodable")
    return 0xeb000000|(x>>2&0xffffff)
def func(addr,text):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
            "void FUN_%08x(void){\n"%addr+text+
            "\n}\nTRACE_DECOMP_END (GhidraScript)")
def start(s:a.Specs):
    field=0x5a8+s.codec_off
    words={
        s.primary_movw:mw(5,s.active&0xffff),
        s.primary_movw+4:mw(5,s.active>>16,True),
        s.primary_movw+8:mw(2,s.copy_length),
        s.primary_copy:branch(s.primary_copy,s.memcpy),
        s.backup_literal:s.active+0x6c0,
        s.backup_copy:branch(s.backup_copy,s.memcpy),
    }
    for addr in (s.primary_normalize,s.backup_normalize):
        for i,w in enumerate((0xe5d53008,0xe3530025,
                              0x03a03021,0x05c435b0)):
            words[addr+4*i]=w
    for i,w in enumerate((0xe5d43000|field,0xe3530001,
                          0x03a03004,0x13a03005,0xe3403001,0xe5853220)):
        words[s.codec_reader_site+4*i]=w
    for i,w in enumerate((0xe5d02000|field+1,0xe3520001,
                          mw(1,s.mov_label&0xffff,cond=1),
                          mw(1,s.mov_label>>16,True,cond=1),
                          mw(1,s.mp4_label&0xffff,cond=0),
                          mw(1,s.mp4_label>>16,True,cond=0))):
        words[s.format_reader_site+i*4]=w

    primary=func(s.primary,
        "FUN_%08x(param_1 + 0x5a8,0x%x,0x%x);\n"%
         (s.memcpy,s.active,s.copy_length)+
        "if (DAT_%08x == '%%') {\n"%(s.active+8)+
        "*(undefined1 *)(param_1 + 0x5b0) = 0x21;\n}")
    backup=func(s.backup,
        "FUN_%08x(param_1 + 0x5a8,DAT_%08x,0x%x);\n"%
         (s.memcpy,s.backup_literal,s.copy_length)+
        "if (*(char *)(iVar1 + 8) == '%') {\n"
        "*(undefined1 *)(param_1 + 0x5b0) = 0x21;\n}")
    codec=func(s.codec_reader,
        "if (*(char *)(param_1 + 0x%x) == '\\x01') {\n"%field+
        "uVar8 = 4;\n} else {\nuVar8 = 5;\n}\n"
        "*(uint *)(param_4 + 0x220) = uVar8 | 0x10000;")
    fmt=func(s.format_reader,
        "if (*(char *)(param_1 + 0x%x) == '\\x01') {\n"%(field+1)+
        "puVar1 = &DAT_%08x;\n"%s.mp4_label+
        "} else {\npuVar1 = &DAT_%08x;\n}"%s.mov_label)
    gui="".join(
        ("%s (_DAT_%08x == %s) {\n"%(("if" if i==0 else "else if"),
                                     s.gui_pair_global,str(hex(v)) if v>1 else str(v))+
         "param_1[0xa1] = %d;\n}\n"%n)
        for i,(v,n) in enumerate(((1,0),(0,1),(0x101,2),(0x100,3)))
    )
    return {"w":words,"primary":primary,"backup":backup,"codec":codec,
            "fmt":fmt,"gui":func(s.gui_reader,gui),
            "strings":{s.mov_label:b"MOV\0",s.mp4_label:b"MP4\0"},
            "p32":{"model":s.name,
              "input_to_active_static_data_flow_edges_proven":True,
              "active_Recorder_Codec_byte":"0x%08x"%s.active_codec}}

def run(s,change=None):
    case=start(s)
    if change:change(case)
    with patch.object(a,"word",side_effect=lambda b,base,addr:case["w"][addr]):
      with patch.object(a,"rom_four",side_effect=lambda b,base,addr:case["strings"][addr]):
        return a.audit(s,b"",b"",case["primary"],case["backup"],case["codec"],
                       case["fmt"],case["gui"],case["p32"])

class Decoder(unittest.TestCase):
    def test_little_endian(self):
        self.assertEqual(a.word(bytes.fromhex("dd4dc201"),0,0),0x01c24ddd)
    def test_oob(self):
        with self.assertRaisesRegex(ValueError,"ROM address"):a.word(b"\0"*4,0,8)
    def test_unaligned(self):
        with self.assertRaisesRegex(ValueError,"ROM address"):a.word(b"\0"*8,0,1)
    def test_slice_oob(self):
        with self.assertRaisesRegex(ValueError,"ROM literal"):a.rom_four(b"\0"*3,0,0)
    def test_slice_positive(self):
        self.assertEqual(a.rom_four(b"MOV\x00MP4\x00",0x10,0x14),b"MP4\0")
    def test_movw_low(self):
        self.assertEqual(a.movw_part(mw(5,0x4dd8),5),0x4dd8)
    def test_movt_high(self):
        self.assertEqual(a.movw_part(mw(5,0x1c2,True),5,True),0x1c2)
    def test_wrong_mov_register(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movw_part(mw(4,0x4dd8),5)
    def test_wrong_mov_part(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movw_part(mw(5,0x4dd8,True),5)
    def test_bl_positive(self):
        self.assertEqual(a.bl(branch(0x1000,0x2000),0x1000),0x2000)
    def test_bl_negative(self):
        self.assertEqual(a.bl(branch(0x2000,0x1000),0x2000),0x1000)
    def test_cond_bl_rejected(self):
        with self.assertRaisesRegex(ValueError,"not A32 BL"):
            a.bl(0x0b000001,0x1000)
    def test_function_finder_missing(self):
        with self.assertRaisesRegex(ValueError,"Ghidra function absent"):
            a.c_function("",0x1234)
    def test_function_finder_present(self):
        self.assertIn("hello",a.c_function(func(0x1234,"hello"),0x1234))

class Identity(unittest.TestCase):
    def test_models_pass(self):
        for s in a.SPECS.values():
            with self.subTest(s=s.name):
                o=run(s)
                self.assertFalse(o["movie_context_plus_0x5b0_is_Recorder_Codec"])
                self.assertFalse(o["GUI_MovieCodec_to_Recorder_initial_0x5b0_assignment_proven"])
                self.assertFalse(o["Main10_bitstream_proven"])
                self.assertFalse(o["4K60_internal_pipeline_proven"])
                self.assertFalse(o["camera_touched"])
                self.assertEqual(o["original_ROM_A32_and_literal_words_checked"],26)
    def test_context_offsets(self):
        self.assertEqual(run(a.SPECS["xs10"])["movie_context_codec_offset"],"0x9d8")
        self.assertEqual(run(a.SPECS["xt4"])["movie_context_codec_offset"],"0x9dc")
    def test_backup_bases(self):
        self.assertEqual(run(a.SPECS["xs10"])["second_backup_template"],"0x01c25498")
        self.assertEqual(run(a.SPECS["xt4"])["second_backup_template"],"0x01b83c00")
    def test_codec_control_unknown(self):
        for s in a.SPECS.values():
            o=run(s)
            self.assertEqual(o["codec_control_values_means_HEVC_or_Main10"],"UNKNOWN")
            self.assertEqual(o["codec_control_if_byte_equals_1"],"0x10004")
            self.assertEqual(o["codec_control_otherwise"],"0x10005")
    def test_labels(self):
        for s in a.SPECS.values():
            o=run(s)
            self.assertEqual(o["format_byte_1"],"MP4")
            self.assertEqual(o["format_other_byte"],"MOV")
    def test_header_phase32_false(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["p32"]["input_to_active_static_data_flow_edges_proven"]=False
        with self.assertRaisesRegex(ValueError,"parent Stage32"):
            run(s,mutate)
    def test_header_phase32_wrong_active(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["p32"]["active_Recorder_Codec_byte"]="0x01b83975"
        with self.assertRaisesRegex(ValueError,"parent Stage32"):
            run(s,mutate)
    def test_primary_movw_wrong_base(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.primary_movw]=mw(5,(s.active+8)&0xffff)
        with self.assertRaisesRegex(ValueError,"primary MOVW"):
            run(s,mutate)
    def test_primary_movt_wrong_high(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.primary_movw+4]=mw(5,(s.active>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"primary MOVW"):
            run(s,mutate)
    def test_primary_length_corrupt(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.primary_movw+8]=mw(2,s.copy_length-4)
        with self.assertRaisesRegex(ValueError,"copy length"):
            run(s,mutate)
    def test_primary_bl_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.primary_copy]=branch(s.primary_copy,s.memcpy+4)
        with self.assertRaisesRegex(ValueError,"primary movie-context copy BL"):
            run(s,mutate)
    def test_primary_normalization_cmp_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.primary_normalize+4]=0xe3530021
        with self.assertRaisesRegex(ValueError,"normalization instruction"):
            run(s,mutate)
    def test_primary_normalization_store_offset_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.primary_normalize+12]=0x05c435b1
        with self.assertRaisesRegex(ValueError,"normalization instruction"):
            run(s,mutate)
    def test_backup_rom_literal_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.backup_literal]=s.active+0x6c4
        with self.assertRaisesRegex(ValueError,"ROM literal for backup"):
            run(s,mutate)
    def test_backup_bl_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.backup_copy]=branch(s.backup_copy,s.memcpy+4)
        with self.assertRaisesRegex(ValueError,"backup movie-context copy BL"):
            run(s,mutate)
    def test_backup_normalize_value_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.backup_normalize+8]=0x03a03022
        with self.assertRaisesRegex(ValueError,"normalization instruction"):
            run(s,mutate)
    def test_primary_c_wrong_destination(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["primary"]=f["primary"].replace("param_1 + 0x5a8","param_1 + 0x5b0")
        with self.assertRaisesRegex(ValueError,"Ghidra primary copy"):
            run(s,mutate)
    def test_backup_c_wrong_destination(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["backup"]=f["backup"].replace("param_1 + 0x5a8","param_1 + 0x5a0")
        with self.assertRaisesRegex(ValueError,"Ghidra backup copy"):
            run(s,mutate)
    def test_backup_c_no_normalization(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["backup"]=f["backup"].replace("0x5b0) = 0x21","0x5b0) = 0x22")
        with self.assertRaisesRegex(ValueError,"normalization context"):
            run(s,mutate)
    def test_codec_field_read_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.codec_reader_site]=0xe5d439d8
        with self.assertRaisesRegex(ValueError,"packet codec"):
            run(s,mutate)
    def test_codec_compare_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.codec_reader_site+4]=0xe3530002
        with self.assertRaisesRegex(ValueError,"packet codec"):
            run(s,mutate)
    def test_codec_value4_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.codec_reader_site+8]=0x03a03005
        with self.assertRaisesRegex(ValueError,"packet codec"):
            run(s,mutate)
    def test_codec_value5_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.codec_reader_site+12]=0x13a03004
        with self.assertRaisesRegex(ValueError,"packet codec"):
            run(s,mutate)
    def test_codec_output_store_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.codec_reader_site+20]=0xe5853224
        with self.assertRaisesRegex(ValueError,"packet codec"):
            run(s,mutate)
    def test_codec_c_wrong_branch_label(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["codec"]=f["codec"].replace("uVar8 = 5","uVar8 = 7")
        with self.assertRaisesRegex(ValueError,"recording-context byte"):
            run(s,mutate)
    def test_codec_c_wrong_outfield(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["codec"]=f["codec"].replace("param_4 + 0x220","param_4 + 0x224")
        with self.assertRaisesRegex(ValueError,"recording-context byte"):
            run(s,mutate)
    def test_format_byte_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.format_reader_site]=0xe5d029d8
        with self.assertRaisesRegex(ValueError,"movie format byte"):
            run(s,mutate)
    def test_format_condition_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.format_reader_site+4]=0xe3520000
        with self.assertRaisesRegex(ValueError,"CMP #1"):
            run(s,mutate)
    def test_format_low_mov_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.format_reader_site+8]=mw(1,s.mov_label+4,cond=1)
        with self.assertRaisesRegex(ValueError,"selected string address"):
            run(s,mutate)
    def test_format_mov_condition_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.format_reader_site+8]=mw(1,s.mov_label&0xffff,cond=0)
        with self.assertRaisesRegex(ValueError,"condition-code"):
            run(s,mutate)
    def test_format_mp4_condition_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["w"][s.format_reader_site+16]=mw(1,s.mp4_label&0xffff,cond=1)
        with self.assertRaisesRegex(ValueError,"condition-code"):
            run(s,mutate)
    def test_format_mp4_low_literal_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["w"][s.format_reader_site+16]=mw(1,s.mp4_label+4,cond=0)
        with self.assertRaisesRegex(ValueError,"selected string address"):
            run(s,mutate)
    def test_format_c_missing_mp4_reference(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["fmt"]=f["fmt"].replace("DAT_%08x"%s.mp4_label,"DAT_deadbeef")
        with self.assertRaisesRegex(ValueError,"MOV/MP4 format branch"):
            run(s,mutate)
    def test_format_label_bytes_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["strings"][s.mp4_label]=b"JPG\x00"
        with self.assertRaisesRegex(ValueError,"Section2 string"):
            run(s,mutate)
    def test_gui_codec_state_map_wrong(self):
        s=a.SPECS["xs10"]
        def mutate(f):f["gui"]=f["gui"].replace("_DAT_%08x == 0x101"%s.gui_pair_global,"_DAT_%08x == 0x201"%s.gui_pair_global)
        with self.assertRaisesRegex(ValueError,"UI Codec"):
            run(s,mutate)
    def test_gui_option_label_wrong(self):
        s=a.SPECS["xt4"]
        def mutate(f):f["gui"]=f["gui"].replace("param_1[0xa1] = 3","param_1[0xa1] = 2")
        with self.assertRaisesRegex(ValueError,"UI Codec"):
            run(s,mutate)
    def test_cross_model_different_offsets_not_interchangeable(self):
        xs=a.SPECS["xs10"];xt=a.SPECS["xt4"]
        self.assertNotEqual(xs.codec_off,xt.codec_off)
        self.assertNotEqual(xs.active_codec,xt.active_codec)
        self.assertEqual(run(xs)["codec_control_if_byte_equals_1"],
                         run(xt)["codec_control_if_byte_equals_1"])
    def test_not_an_unlock(self):
        for s in a.SPECS.values():
            o=run(s)
            self.assertFalse(o["movie_copy_engine_runtime_execution_proven"])
            self.assertFalse(o["same_runtime_context_object_across_callers_proven"])
            self.assertFalse(o["Main10_bitstream_proven"])
            self.assertFalse(o["4K60_internal_pipeline_proven"])

if __name__=="__main__":unittest.main()

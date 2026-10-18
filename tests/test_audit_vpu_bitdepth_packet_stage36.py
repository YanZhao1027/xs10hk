"""Stage36 synthetic ARM, decompiler, provenance and uncertainty tests.

All firmware-memory/register identities are synthetic test fixtures built
in Python. No original ROM byte sequence, camera communication, or firmware
modification in this test module.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_vpu_bitdepth_packet_stage36 as a

def synthetic_movw(dst,low,cond=14):
    return cond<<28|0x03000000|((low>>12&0xf)<<16)|(dst<<12)|(low&0xfff)

def synthetic_movt(dst,high,cond=14):
    return cond<<28|0x03400000|((high>>12&0xf)<<16)|(dst<<12)|(high&0xfff)

def synthetic_bl(site,target):
    delta=target-site-8
    if delta%4 or not -(1<<25)<=delta<1<<25: raise ValueError("bad synthetic BL")
    return 0xeb000000|((delta>>2)&0xffffff)

def synthetic_b(site,target,cond=1):
    delta=target-site-8
    if delta%4 or not -(1<<25)<=delta<1<<25:raise ValueError("bad synthetic B")
    return cond<<28|0x0a000000|((delta>>2)&0xffffff)

def ghidra_stub(address,body):
    return (
        "TRACE_DECOMP_BEGIN (GhidraScript)\n"+
        "void FUN_%08x(void)\n{\n"%address+body+
        "\n}\nTRACE_DECOMP_END (GhidraScript)\n"
    )

def fixture(m):
    asm_source=0x011fcb5c if m.name=="xs10" else 0x011d0208
    w={
      m.assemble_codec_site:a.CODEC_FORWARD_WORDS[0],
      m.assemble_codec_site+4:a.CODEC_FORWARD_WORDS[1],
      m.frame_branch_base:synthetic_movw(3,m.packet_ptr_slot&0xffff),
      m.frame_branch_base+4:synthetic_movt(3,m.packet_ptr_slot>>16),
      m.frame_branch_base+8:0xe5933000,
      m.frame_branch_base+12:0xe593200c,
      m.frame_branch_base+16:0xe3520000,
      m.frame_branch_base+20:synthetic_b(m.frame_branch_base+20,m.format_nonzero_site-12),
      m.state_assembly_bl:synthetic_bl(m.state_assembly_bl,m.assembler),
      m.encoder_frame_builder_bl:synthetic_bl(m.encoder_frame_builder_bl,m.frame_builder),
      m.decoder_frame_builder_bl:synthetic_bl(m.decoder_frame_builder_bl,m.frame_builder),
      m.ring_send_enc_bl:synthetic_bl(m.ring_send_enc_bl,m.packet_ring_encoder),
      m.ring_send_dec_bl:synthetic_bl(m.ring_send_dec_bl,m.packet_ring_decoder),
    }
    for i,inst in enumerate(a.NORMAL_WORDS):
        w[m.assemble_bitdepth_site+i*4]=(
           synthetic_movw(3,m.cached_init&0xffff,0) if inst is None else inst
        )
    for site,values in (
       (m.format_zero_site,a.FORMAT_0_WORDS),
       (m.format_nonzero_site,a.FORMAT_NONZERO_WORDS),
       (m.stride_zero_site,a.STRIDE_0_WORDS),
       (m.stride_nonzero_site,a.STRIDE_NONZERO_WORDS)):
        for i,inst in enumerate(values):w[site+i*4]=inst
    depth=m.cached_init+0x0c
    codec=m.cached_init+0x188
    c={
      "assemble":(
        "FUN_%08x(_DAT_%08x,0,0x298);\n"%(asm_source,m.packet_ptr_slot)+
        "uVar2 = _DAT_%08x;\n"%depth+
        "if (_DAT_%08x != 0) {\n"%codec+
        "uVar2 = 1;\n}\n"+
        "puVar3[3] = uVar2;\n"+
        "puVar3[100] = _DAT_%08x;"%codec
      ),
      "state":(
        "if (_DAT_%08x == 1) { FUN_%08x(); }\n"%(m.state_global,m.assembler)+
        "else if (_DAT_%08x == 2) { FUN_%08x(); }\n"%(m.state_global,m.encoder_param_state)+
        "else if (_DAT_%08x == 3) { FUN_%08x(); }"%(m.state_global,m.decoder_param_state)
      ),
      "frame":(
        "FUN_%08x(_DAT_%08x,0,0x48);\n"%(asm_source,m.frame_packet_ptr_slot)+
        "if (_DAT_%08x[3] == 0) {\n"%m.packet_ptr_slot+
        "*(undefined2 *)(_DAT_%08x + 0x18) = 0x201;\n"%m.frame_packet_ptr_slot+
        "*(undefined4 *)(iVar1 + 0x34) = puVar2[2];\n"+
        "*(undefined4 *)(iVar1 + 0x38) = puVar2[2];\n"+
        "} else {\n"+
        "*(undefined2 *)(_DAT_%08x + 0x18) = 0x121;\n"%m.frame_packet_ptr_slot+
        "*(undefined4 *)(iVar1 + 0x34) = puVar2[2] << 2;\n}"
      ),
      "encode":"if (iVar2 == 0) { FUN_%08x(); }"%m.frame_builder,
      "decode":"FUN_%08x();"%m.frame_builder,
      "send":(
        "FUN_%08x(puVar1,0xbb9,0x48);\n"%m.packet_ring_encoder+
        "FUN_%08x(_DAT_%08x,0xbb9,0x48);"%
          (m.packet_ring_decoder,m.frame_packet_ptr_slot)
      ),
    }
    ref={
      "global":(
        "PROBE_TARGET addr=%08x refs=1\n"%depth+
        "PROBE_TARGET addr=%08x refs=3"%codec
      ),
      "pointer":(
        "VPU_PTR_TARGET %08x refs=55 funcs=17\n"%m.packet_ptr_slot+
        "VPU_BITDEPTH_CONTEXT %08x\n"%m.frame_builder+
        "VPU_BITDEPTH_CONTEXT %08x"%m.send_frame
      )
    }
    p35={
      "model":m.name,
      "VPU_bit_depth_enum_written_by_movie_setup":1,
      "VPU_video_codec_when_active_Codec_byte_is_1":0,
      "VPU_video_codec_when_active_Codec_byte_is_not_1":1,
      "VPU_driver_init_copy_bytes":400,
      "HEVC_Main10_SPS_bitdepth_proven":False,
    }
    return {"words":w,"c":c,"refs":ref,"prev":p35}

def run(m,edit=None):
    t=fixture(m)
    if edit: edit(t)
    return a.audit_model(m,lambda addr:t["words"][addr],
                         t["c"],t["refs"],t["prev"])

class ArmAndLimits(unittest.TestCase):
    def test_movw_roundtrip(self):
        self.assertEqual(a.decode_movw(synthetic_movw(3,0x3712)),0x3712)
    def test_movw_conditional_eq(self):
        self.assertEqual(a.decode_movw(synthetic_movw(3,0x2345,0),3,0),0x2345)
    def test_movw_wrong_reg(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.decode_movw(synthetic_movw(2,0x2345))
    def test_movw_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.decode_movw(synthetic_movw(3,0x2345,1),3,0)
    def test_movw_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.decode_movw(synthetic_movt(3,0x2345))
    def test_movt_roundtrip(self):
        self.assertEqual(a.decode_movt(synthetic_movt(3,0xabc)),0xabc)
    def test_movt_wrong_reg(self):
        with self.assertRaisesRegex(ValueError,"MOVT"):
            a.decode_movt(synthetic_movt(2,0x1234))
    def test_movt_wrong_variant(self):
        with self.assertRaisesRegex(ValueError,"MOVT"):
            a.decode_movt(synthetic_movw(3,0x1234))
    def test_bl_forward(self):
        self.assertEqual(a.decode_bl(synthetic_bl(0x8000,0x9110),0x8000),0x9110)
    def test_bl_backward(self):
        self.assertEqual(a.decode_bl(synthetic_bl(0x9110,0x8000),0x9110),0x8000)
    def test_bl_not_unconditional(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            a.decode_bl(0x1b000000,0x8000)
    def test_bl_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            a.decode_bl(0xe3a00001,0x8000)
    def test_bne_forward(self):
        self.assertEqual(a.decode_branch(synthetic_b(0x8080,0x8180),0x8080,1),0x8180)
    def test_bne_backward(self):
        self.assertEqual(a.decode_branch(synthetic_b(0x8080,0x7f80),0x8080,1),0x7f80)
    def test_bne_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"branch"):
            a.decode_branch(synthetic_b(0x8080,0x8180,0),0x8080,1)
    def test_bne_wrong_bl_opcode(self):
        with self.assertRaisesRegex(ValueError,"branch"):
            a.decode_branch(0xeb000000,0x8080,1)
    def test_rom_original_little_endian(self):
        self.assertEqual(a.read_word(bytes.fromhex("78563412"),a.ROM_SECTION1_BASE),0x12345678)
    def test_rom_out_of_range(self):
        with self.assertRaisesRegex(ValueError,"out-of-range"):
            a.read_word(bytes(8),a.ROM_SECTION1_BASE+12)
    def test_rom_misaligned(self):
        with self.assertRaisesRegex(ValueError,"out-of-range"):
            a.read_word(bytes(8),a.ROM_SECTION1_BASE+3)
    def test_c_parser_synthetic_positive(self):
        m=a.MODELS["xs10"]
        self.assertIn("Hi",a.extract_c(ghidra_stub(m.frame_builder,"Hi;"),m.frame_builder))
    def test_c_parser_reject_missing(self):
        with self.assertRaisesRegex(ValueError,"Missing Ghidra C"):
            a.extract_c("nothing",0x11000000)
    def test_effective_codec_zero_keeps_input_0(self):
        self.assertEqual(a.static_effective_depth(0,0),0)
    def test_effective_codec_zero_keeps_input_1(self):
        self.assertEqual(a.static_effective_depth(0,1),1)
    def test_effective_codec_one_forces_1(self):
        self.assertEqual(a.static_effective_depth(1,0),1)
        self.assertEqual(a.static_effective_depth(1,1),1)
    def test_reject_out_of_domain_codec(self):
        with self.assertRaisesRegex(ValueError,"domain"):
            a.static_effective_depth(2,1)
    def test_frame_code_depth_zero(self):
        self.assertEqual(a.static_frame_code(0),0x201)
    def test_frame_code_nonzero(self):
        self.assertEqual(a.static_frame_code(1),0x121)
        self.assertEqual(a.static_frame_code(2),0x121)

class Provenance(unittest.TestCase):
    def test_positive_both_models(self):
        for m in a.MODELS.values():
            with self.subTest(m=m.name):
                result=run(m)
                self.assertEqual(result["A32_normalization_words_checked"],7)
                self.assertEqual(result["A32_frame_format_and_stride_words_checked"],11)
                self.assertEqual(result["VPU_init_packet_bytes_cleared"],0x298)
                self.assertEqual(result["VPU_frame_descriptor_bytes_cleared"],0x48)
    def test_unchanged_movie_path_invariant(self):
        for m in a.MODELS.values():
            result=run(m)
            self.assertEqual(result["VPU_static_movie_path_effective_depth_by_codec_enum_0_1"],[1,1])
            self.assertEqual(result["VPU_static_movie_path_frame_code_if_no_intervening_writes"],"0x121")
    def test_format_branch_raw_codes(self):
        for m in a.MODELS.values():
            result=run(m)
            self.assertEqual(result["frame_format_code_if_effective_depth_0"],"0x201")
            self.assertEqual(result["frame_format_code_if_effective_depth_nonzero"],"0x121")
    def test_no_physical_bitdepth_claim(self):
        for m in a.MODELS.values():
            result=run(m)
            self.assertEqual(result["physical_bitdepth_enum_0_1_mapping"],"UNKNOWN")
            self.assertEqual(result["descriptor_0x201_0x121_pixel_format_mapping"],"UNKNOWN")
            self.assertFalse(result["VPU_hardware_acceptance_or_SPS_proven"])
    def test_no_unsafe_or_camera_action(self):
        for m in a.MODELS.values():
            result=run(m)
            self.assertFalse(result["HEVC_Main10_internal_recording_unlocked"])
            self.assertFalse(result["internal_4K60_unlocked"])
            self.assertFalse(result["camera_touched"])
    def test_upstream_GUI_still_missing(self):
        for m in a.MODELS.values():
            self.assertFalse(run(m)["GUI_to_Recorder_input_initial_assignment_proven"])
    def test_encoder_decoder_both_emit_frame_descriptor(self):
        for m in a.MODELS.values():
            result=run(m)
            self.assertTrue(result["VPU_frame_descriptor_consumed_by_both_encoder_decoder_param_branches"])
            self.assertTrue(result["frame_packet_encoder_decoder_BL_verified"])
            self.assertTrue(result["frame_message_ring_BL_verified"])
    def test_prior_stage35_wrong_depth(self):
        m=a.MODELS["xs10"]
        def change(t):t["prev"]["VPU_bit_depth_enum_written_by_movie_setup"]=0
        with self.assertRaisesRegex(ValueError,"stage35"):run(m,change)
    def test_prior_stage35_wrong_codec(self):
        m=a.MODELS["xt4"]
        def change(t):t["prev"]["VPU_video_codec_when_active_Codec_byte_is_1"]=1
        with self.assertRaisesRegex(ValueError,"stage35"):run(m,change)
    def test_prior_stage35_bad_copy_length(self):
        m=a.MODELS["xs10"]
        def change(t):t["prev"]["VPU_driver_init_copy_bytes"]=0x180
        with self.assertRaisesRegex(ValueError,"stage35"):run(m,change)
    def test_prior_stage35_bad_main10_claim(self):
        m=a.MODELS["xs10"]
        def change(t):t["prev"]["HEVC_Main10_SPS_bitdepth_proven"]=True
        with self.assertRaisesRegex(ValueError,"stage35"):run(m,change)
    def test_refs_wrong_cached_depth(self):
        m=a.MODELS["xs10"]
        def change(t):t["refs"]["global"]=t["refs"]["global"].replace(
             "%08x"%(m.cached_init+0xc),"deadbeef")
        with self.assertRaisesRegex(ValueError,"xref ground"):run(m,change)
    def test_refs_wrong_cached_codec(self):
        m=a.MODELS["xt4"]
        def change(t):t["refs"]["global"]=t["refs"]["global"].replace(
             "%08x"%(m.cached_init+0x188),"deadbeef")
        with self.assertRaisesRegex(ValueError,"xref ground"):run(m,change)
    def test_refs_wrong_packet_pointer(self):
        m=a.MODELS["xs10"]
        def change(t):t["refs"]["pointer"]=t["refs"]["pointer"].replace("refs=55","refs=54")
        with self.assertRaisesRegex(ValueError,"xref baseline"):run(m,change)
    def test_refs_missing_frame_producer(self):
        m=a.MODELS["xt4"]
        def change(t):t["refs"]["pointer"]=t["refs"]["pointer"].replace(
           "VPU_BITDEPTH_CONTEXT %08x"%m.frame_builder,"VPU_BITDEPTH_CONTEXT 00000000")
        with self.assertRaisesRegex(ValueError,"descriptor consumers"):run(m,change)
    def test_dispatch_missing_state1(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["state"]=t["c"]["state"].replace("== 1","== 0")
        with self.assertRaisesRegex(ValueError,"state dispatcher"):run(m,change)
    def test_dispatch_missing_encode(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["state"]=t["c"]["state"].replace(
            "FUN_%08x"%m.encoder_param_state,"FUN_00000000")
        with self.assertRaisesRegex(ValueError,"state dispatcher"):run(m,change)
    def test_dispatch_missing_decode(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["state"]=t["c"]["state"].replace(
            "FUN_%08x"%m.decoder_param_state,"FUN_00000000")
        with self.assertRaisesRegex(ValueError,"state dispatcher"):run(m,change)
    def test_asm_no_clear_298(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["assemble"]=t["c"]["assemble"].replace("0x298","0x290")
        with self.assertRaisesRegex(ValueError,"normalization C mismatch"):run(m,change)
    def test_asm_no_cached_depth(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["assemble"]=t["c"]["assemble"].replace(
            "_DAT_%08x"%(m.cached_init+0xc),"_DAT_ffffffff")
        with self.assertRaisesRegex(ValueError,"normalization C mismatch"):run(m,change)
    def test_asm_wrong_codec_gate(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["assemble"]=t["c"]["assemble"].replace("!= 0","== 0")
        with self.assertRaisesRegex(ValueError,"normalization C mismatch"):run(m,change)
    def test_asm_wrong_output_packet_idx(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["assemble"]=t["c"]["assemble"].replace("puVar3[3]","puVar3[4]")
        with self.assertRaisesRegex(ValueError,"normalization C mismatch"):run(m,change)
    def test_asm_wrong_codec_forward_idx(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["assemble"]=t["c"]["assemble"].replace("puVar3[100]","puVar3[99]")
        with self.assertRaisesRegex(ValueError,"normalization C mismatch"):run(m,change)
    def test_asm_wrong_event_order(self):
        m=a.MODELS["xs10"]
        def change(t):
            x="puVar3[3] = uVar2;\n"
            y="puVar3[100] = _DAT_%08x;"%(m.cached_init+0x188)
            t["c"]["assemble"]=t["c"]["assemble"].replace(x+y,y+"\n"+x)
        with self.assertRaisesRegex(ValueError,"wrong order"):run(m,change)
    def test_frame_wrong_clear_length(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["frame"]=t["c"]["frame"].replace("0x48","0x40")
        with self.assertRaisesRegex(ValueError,"constructor"):run(m,change)
    def test_frame_no_depth_cond(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["frame"]=t["c"]["frame"].replace("[3] == 0","[3] == 1")
        with self.assertRaisesRegex(ValueError,"constructor"):run(m,change)
    def test_frame_missing_201(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["frame"]=t["c"]["frame"].replace("0x201","0x202")
        with self.assertRaisesRegex(ValueError,"0x201"):run(m,change)
    def test_frame_missing_121(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["frame"]=t["c"]["frame"].replace("0x121","0x120")
        with self.assertRaisesRegex(ValueError,"0x121"):run(m,change)
    def test_frame_0_stride_missing_second_word(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["frame"]=t["c"]["frame"].replace(
            "iVar1 + 0x38","iVar1 + 0x30")
        with self.assertRaisesRegex(ValueError,"stride/header"):run(m,change)
    def test_frame_nonzero_stride_missing_shift(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["frame"]=t["c"]["frame"].replace(
            "puVar2[2] << 2","puVar2[2] << 1")
        with self.assertRaisesRegex(ValueError,"stride/header"):run(m,change)
    def test_encoder_missing_builder(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["encode"]=t["c"]["encode"].replace(
            "FUN_%08x"%m.frame_builder,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"encoded/decoded"):run(m,change)
    def test_encoder_missing_success_guard(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["encode"]=t["c"]["encode"].replace("iVar2 == 0","iVar2 != 0")
        with self.assertRaisesRegex(ValueError,"encoded/decoded"):run(m,change)
    def test_decoder_missing_builder(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["decode"]=t["c"]["decode"].replace(
            "FUN_%08x"%m.frame_builder,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"encoded/decoded"):run(m,change)
    def test_sender_missing_encoder_message(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["send"]=t["c"]["send"].replace(
            "FUN_%08x"%m.packet_ring_encoder,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"ring sender"):run(m,change)
    def test_sender_missing_decoder_message(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["send"]=t["c"]["send"].replace(
            "FUN_%08x"%m.packet_ring_decoder,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"ring sender"):run(m,change)
    def test_sender_wrong_payload_length(self):
        m=a.MODELS["xs10"]
        def change(t):t["c"]["send"]=t["c"]["send"].replace("0xbb9,0x48","0xbb9,0x44")
        with self.assertRaisesRegex(ValueError,"same 0x48"):run(m,change)
    def test_sender_wrong_pointer_source(self):
        m=a.MODELS["xt4"]
        def change(t):t["c"]["send"]=t["c"]["send"].replace(
           "_DAT_%08x"%m.frame_packet_ptr_slot,"_DAT_ffffffff")
        with self.assertRaisesRegex(ValueError,"same 0x48"):run(m,change)

def make_word_mutation(case_number,label,model,site,position):
    def test(self):
        m=a.MODELS[model]
        addr=site(m)+4*position
        def change(t):t["words"][addr]^=1
        with self.assertRaisesRegex(ValueError,label):
            run(m,change)
    test.__name__="test_a32_mutate_%02d"%case_number
    return test

tasks=[]
for idx in range(len(a.NORMAL_WORDS)):
    if idx==2:continue
    tasks.append(("A32 normalize",lambda m:m.assemble_bitdepth_site,idx))
tasks.append(("cached bitdepth pointer",lambda m:m.assemble_bitdepth_site,2))
for i in range(len(a.CODEC_FORWARD_WORDS)):
    tasks.append(("A32 VPU payload",lambda m:m.assemble_codec_site,i))
for prop,count,label in (
   ("format_zero_site",len(a.FORMAT_0_WORDS),"A32 frame 0x201"),
   ("format_nonzero_site",len(a.FORMAT_NONZERO_WORDS),"A32 frame 0x121"),
   ("stride_zero_site",len(a.STRIDE_0_WORDS),"A32 frame zero stride"),
   ("stride_nonzero_site",len(a.STRIDE_NONZERO_WORDS),"A32 frame nonzero stride"),
):
    for i in range(count):
        tasks.append((label,lambda m,prop=prop:getattr(m,prop),i))
for i in range(5):
    tasks.append(("A32 frame descriptor",lambda m:m.frame_branch_base,i))
tasks.append(("frame descriptor reads same",lambda m:m.frame_branch_base,0))
for prop,label in (
    ("state_assembly_bl","state=1"),
    ("encoder_frame_builder_bl","encoder/decoder"),
    ("decoder_frame_builder_bl","encoder/decoder"),
    ("ring_send_enc_bl","queue ARM"),
    ("ring_send_dec_bl","queue ARM"),
):
    tasks.append((label,lambda m,prop=prop:getattr(m,prop),0))
for idx,(label,site,pos) in enumerate(tasks):
    model="xs10" if idx%2 else "xt4"
    setattr(Provenance,"test_a32_mutate_%02d"%idx,
            make_word_mutation(idx,label,model,site,pos))

def bad_branch_test(self):
    m=a.MODELS["xs10"]
    def change(t):
        t["words"][m.frame_branch_base+20]=synthetic_b(
            m.frame_branch_base+20,m.format_nonzero_site-12,cond=0)
    with self.assertRaisesRegex(ValueError,"branch"):
        run(m,change)
setattr(Provenance,"test_bad_BNE_branch_cond",bad_branch_test)

def bad_branch_target_test(self):
    m=a.MODELS["xt4"]
    def change(t):
        t["words"][m.frame_branch_base+20]=synthetic_b(
            m.frame_branch_base+20,m.format_nonzero_site-8,cond=1)
    with self.assertRaisesRegex(ValueError,"BNE must select"):
        run(m,change)
setattr(Provenance,"test_bad_BNE_branch_target",bad_branch_target_test)

def synthetic_full_builder_fixture():
    """Two fictional frame functions differing only in known address literals."""
    xs,xt=a.MODELS["xs10"],a.MODELS["xt4"]
    tables={}
    pairs=((0x08,3,"frame_packet_ptr_slot"),
           (0x20,3,"packet_ptr_slot"),
           (0x38,2,"frame_packet_ptr_slot"),
           (0x6c,3,"packet_ptr_slot"),
           (0x78,3,"frame_packet_ptr_slot"),
           (0x98,2,"frame_packet_ptr_slot"))
    for model in (xs,xt):
        table={model.frame_builder+4*i:0xe1a00000 for i in range(51)}
        for off,reg,field in pairs:
            val=getattr(model,field)
            table[model.frame_builder+off]=synthetic_movw(reg,val&0xffff)
            table[model.frame_builder+off+4]=synthetic_movt(reg,val>>16)
        tables[model.name]=table
    return tables

def run_fingerprint(edit=None):
    xs,xt=a.MODELS["xs10"],a.MODELS["xt4"]
    tables=synthetic_full_builder_fixture()
    if edit:edit(tables)
    def lookup(payload,at):
        return tables["xs10" if payload==b"fiction-xs" else "xt4"][at]
    with patch.object(a,"read_word",side_effect=lookup):
        return a.compare_full_frame_builders(b"fiction-xs",b"fiction-xt",xs,xt)

class FullFunctionFingerprint(unittest.TestCase):
    def test_51_words_39_match_12_pointer_diffs(self):
        r=run_fingerprint()
        self.assertEqual(r["full_frame_builder_ARM_word_count"],51)
        self.assertEqual(r["cross_model_identical_ARM_words"],39)
        self.assertEqual(r["cross_model_MOVW_MOVT_address_only_differences"],12)
        self.assertEqual(r["frame_function_byte_count"],204)
    def test_same_frame_builder_function_identity(self):
        self.assertNotEqual(a.MODELS["xs10"].frame_builder,
                            a.MODELS["xt4"].frame_builder)
    def test_bad_branch_function_instruction(self):
        xs=a.MODELS["xs10"]
        def change(t):t["xs10"][xs.frame_builder+0x44]^=1
        with self.assertRaisesRegex(ValueError,"complete frame descriptor"):
            run_fingerprint(change)
    def test_corrupt_one_movw_pointer(self):
        xs=a.MODELS["xs10"]
        def change(t):t["xs10"][xs.frame_builder+0x8]^=1
        with self.assertRaisesRegex(ValueError,"address-literal"):
            run_fingerprint(change)
    def test_corrupt_movt_model_high_half(self):
        xt=a.MODELS["xt4"]
        def change(t):t["xt4"][xt.frame_builder+0x24]^=1
        with self.assertRaisesRegex(ValueError,"address-literal"):
            run_fingerprint(change)
    def test_wrong_MOVW_register(self):
        xs=a.MODELS["xs10"]
        def change(t):
            t["xs10"][xs.frame_builder+0x38]=synthetic_movw(
                3,xs.frame_packet_ptr_slot&0xffff)
        with self.assertRaisesRegex(ValueError,"MOVW"):
            run_fingerprint(change)
    def test_frame_ptr_and_packet_ptr_not_interchangeable(self):
        xs=a.MODELS["xs10"]
        def change(t):
            t["xs10"][xs.frame_builder+0x20]=synthetic_movw(
                3,xs.frame_packet_ptr_slot&0xffff)
        with self.assertRaisesRegex(ValueError,"address-literal"):
            run_fingerprint(change)

if __name__=="__main__":
    unittest.main()

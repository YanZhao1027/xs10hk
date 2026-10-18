"""Stage43 tests: fabricated toy A32 words & CPU MVE return/flag snippets ONLY.

No source Fuji ROM/firmware, no Ghidra confidential output, no device access.
We patch ROM-byte access and SHA only INSIDE artificial unit tests; the real
Stage43 audit ALWAYS checks unmodified source Section1 SHA, original words,
read-only Ghidra sites and Stage42 provenance.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import ctypes
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage43_mve_bitstream_return as a

def bl(site,dest):
    disp=dest-site-8
    if disp%4 or abs(disp)>=0x2000000:
        raise ValueError("Toy A32 branch displacement out of range")
    return 0xeb000000|((disp//4)&0xffffff)

def fake_c(fn,source):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
           "void FUN_%08x(void)\n{\n%s\n}\n"
           "TRACE_DECOMP_END (GhidraScript)\n")%(fn,source)

def fake_fixture(m):
    w=a.expected_sites(m).copy()
    for site,dest in ((m.header_send_bl,m.header_send_api),
                      (m.header_send2_bl,m.header_send2_api),
                      (m.response_flush_bl,m.response_msg_sender)):
        w[site]=bl(site,dest)
    marker=[]
    for at,mn,imm in (
       (m.header_alloc_mov,"mov",0x1000),
       (m.header_code_mov,"movw",0xbba),
       (m.header_code2_mov,"movw",0xbba),
       (m.response_flag_test,"tst",0x80),
       (m.response_flag_test2,"tst",0x80),
       (m.response_bufaddr_load,"ldr",0x20),
       (m.response_offset_load,"ldr",0x18),
       (m.response_filled_load,"ldr",0x1c),
       (m.status_confirm_mov,"movw",0x7d3),
       (m.status_sequence_mov,"movw",0x7df),
       (m.status_fail_mov,"movw",0x7e1),
       (m.response_flush_mov,"mov",0x3ec),
    ):
        fn=m.header_builder if at in (
             m.header_alloc_mov,m.header_code_mov,m.header_code2_mov
        ) else m.response_fn
        marker.append("ST43_SITE fn=FUN_%08x at=%08x mnemonic=%s imm=%x"%(
                      fn,at,mn,imm))
    p="_DAT_%08x"%m.header_global
    head=(
       "FUN_%08x();\n"%m.header_builder+
       "if (*(int *)(iVar2 + 400) == 1) { uVar7 = 2; } else {uVar7 = 3;}\n"+
       "*%s = uVar3 + 0x4b0da000;\n"%p+
       "puVar5[2] = 0; puVar5[3] = 0; puVar5[5] = 0x1000;\n"
       "puVar5[6] = 0;\n"
       "puVar5[8] = uVar4;\n"+
       "FUN_%08x(puVar5,0xbba,0x28);\n"%m.header_send_api+
       "puVar5[2] = 0; puVar5[3] = 0; puVar5[5] = 0x1000;\n"
       "puVar5[6] = 0;\n"
       "puVar1[8] = (0x20000000 - pbase) + off;\n"+
       "FUN_%08x(puVar1,0xbba,0x28);\n"%m.header_send2_api
    )
    ring=fake_c(m.response_ring_unpack,
      "uVar2 = (word >> 0x10) + 3 >> 2;\n"
      "uVar4 = (uVar4 + 1) % 0x3fc;\n"
      "*param_1 = *(undefined4 *)(ring_data + uVar4 * 4);\n")
    trans=fake_c(m.output_resolve_fn,
       "return (*(uint *)(_DAT_%08x + (param_1 >> 0xc) * 4)&0x3ffffc)<<10 | param_1 & 0xfff;"%
       m.output_resolve_table_global)
    o=m.response_bitstream_global
    flags="_DAT_%08x"%(o+0x10)
    off="_DAT_%08x"%(o+0x18)
    filled="_DAT_%08x"%(o+0x1c)
    ptr="_DAT_%08x"%(o+0x20)
    handler=(
      "if (uVar4 == 0x7d3) {setopt_ok();}\n"
      "if (uVar4 == 0x7d7) {input_flushed();}\n"
      "if (uVar4 < 0x7d7) {\n"+
      "  FUN_%08x(&DAT_%08x);\n"%(m.response_ring_unpack,o)+
      "  if ((%s & 0x80) != 0) {codec_conf();}\n"%flags+
      "  if ((%s & 0x11) == 0) {handle_header();}\n"%flags+
      "  iVar7 = %s + %s;\n"%(ptr,off)+
      "  puVar5 = FUN_%08x(iVar7);\n"%m.output_resolve_fn+
      "  count = %s;\n"%filled+
      "}\n"
      "if (uVar4 == 0x7df) {\n"+
      " FUN_%08x(0x10);\n"%m.response_event+
      " FUN_%08x(0x3ec,0);\n"%m.response_msg_sender+
      "}\n"
      "if (uVar4 == 0x7e1) {\n"+
      " FUN_%08x(0x20000);\n"%m.response_event+
      "}\n"
    )
    rows=[]
    for name in ("xs10","xt4"):
        rows.append({
          "model":name,
          "movie_codec_to_encoder_firmware_pointer":{
             "MovieCodec_byte_eq1_VPU_video_codec_enum":0,
             "MovieCodec_byte_ne1_VPU_video_codec_enum":1,
             "selected_Fuji_codec0_HEVC_static_support":True,
          },
          "direct_MVE_option3_and_job_site_inventory":{
             "SndSetOption_fixed_indices_order":[1,16,38,1,5],
             "SndSetOption_direct_profile_level_index3_occurrences":0,
             "SndSetOption_conditional_HEVC_stream_bitdepth_index38":False,
             "all_other_indirect_or_other_queue_messages_excluded":False,
          },
          "independent_header_count_consistency":{
             "input_video_codec_enum_0_header_record_count_if_split":3,
             "input_video_codec_enum_1_header_record_count_if_split":2,
          }
        })
    return {
      "words":w,
      "logs":{
        "a32sites":"\n".join(marker),
        "handler":fake_c(m.response_fn,handler),
        "header":fake_c(m.header_builder,head),
        "ring":ring+trans,
      },
      "prior":{"two_camera_original_ROM_A32_assignment_and_sender_inventory":rows}
    }

def verify_fake(model="xs10",mutator=None):
    m=a.MODELS[model]
    f=fake_fixture(m)
    if mutator:mutator(m,f)
    with patch.object(a,"original_word",
       side_effect=lambda _rom,at:f["words"][at]),\
       patch.object(a,"sha256",
       return_value=SimpleNamespace(hexdigest=lambda:m.sha)):
        return a.verify_model(m,b"ONLY_TOY_BYTES_NOT_A_VENDOR_ROM",
                              f["logs"],f["prior"])

class PublicMVEABI(unittest.TestCase):
    def test_complete_bitstream_protocol_shape(self):
        v=a.public_abi()
        self.assertEqual(v["mve_buffer_bitstream_bytes"],40)
    def test_separate_sequence_params_metadata(self):
        v=a.public_abi()
        self.assertEqual(v["sequence_parameters_bytes"],8)
        self.assertFalse(v["SEQUENCE_PARAMETERS_is_coded_HEVC_SPS_or_VPS"])
    def test_frame_source_72B_is_NOT_output_40B(self):
        self.assertEqual(ctypes.sizeof(a.MveBitstream),40)
        self.assertNotEqual(ctypes.sizeof(a.MveBitstream),72)
    def test_frame_buffer_code_0xBBA(self):
        self.assertEqual(a.CODE_BITSTREAM,3002)
    def test_output_response_0x7D6(self):
        self.assertEqual(a.RSP_OUTPUT,2006)
    def test_setoption_confirm_0x7D3(self):
        self.assertEqual(a.RSP_OPTION_CONFIRM,2003)
    def test_setoption_fail_0x7E1(self):
        self.assertEqual(a.RSP_OPTION_FAIL,2017)
    def test_seqparams_response_0x7DF(self):
        self.assertEqual(a.RSP_SEQUENCE_PARAMS,2015)
    def test_output_flush_request_0x3EC(self):
        self.assertEqual(a.REQUEST_OUTPUT_FLUSH,1004)
    def test_codeconfig_flag_0x80(self):
        self.assertEqual(a.CODECCONFIG_MASK,0x80)
    def test_eof_flag_0x10(self):
        self.assertEqual(a.EOFRAME_MASK,0x10)
    def test_eos_flag_0x1(self):
        self.assertEqual(a.EOS_MASK,1)
    def test_flag_combo_0x11_is_not_codecconfig(self):
        self.assertEqual(a.EOFRAME_MASK|a.EOS_MASK,0x11)
        self.assertFalse((a.EOFRAME_MASK|a.EOS_MASK)&a.CODECCONFIG_MASK)
    def test_bitstream_size_40(self):
        self.assertEqual(ctypes.sizeof(a.MveBitstream),0x28)
    def test_flag_offset_0x10(self):
        self.assertEqual(a.MveBitstream.bitstream_flags.offset,0x10)
    def test_alloc_len_offset_0x14(self):
        self.assertEqual(a.MveBitstream.bitstream_alloc_bytes.offset,0x14)
    def test_bitstream_offset_0x18(self):
        self.assertEqual(a.MveBitstream.bitstream_offset.offset,0x18)
    def test_filled_offset_0x1c(self):
        self.assertEqual(a.MveBitstream.bitstream_filled_len.offset,0x1c)
    def test_dataaddr_offset_0x20(self):
        self.assertEqual(a.MveBitstream.bitstream_buf_addr.offset,0x20)
    def test_frame_type_offset_0x24(self):
        self.assertEqual(a.MveBitstream.frame_type.offset,0x24)
    def test_transform_offset_0x25(self):
        self.assertEqual(a.MveBitstream.src_transform.offset,0x25)
    def test_sequence_luma_offset_2(self):
        self.assertEqual(a.MveSequenceParams.bitdepth_luma.offset,2)
    def test_sequence_chroma_offset_3(self):
        self.assertEqual(a.MveSequenceParams.bitdepth_chroma.offset,3)
    def test_pack_40B_msg_header(self):
        self.assertEqual(struct.pack("<HH",0xBBA,40),b"\xba\x0b\x28\x00")
    def test_not_coded_SPS_in_seqparam_metadata(self):
        self.assertEqual(a.MveSequenceParams._fields_[2][0],"bitdepth_luma")
        self.assertEqual(a.MveSequenceParams._fields_[3][0],"bitdepth_chroma")
        self.assertTrue(a.public_abi()["output_bitstream_data_must_be_captured_to_verify_SPS"])
    def test_invalid_original_rom_addr(self):
        with self.assertRaisesRegex(ValueError,"OOB"):
            a.original_word(b"\x00"*12,a.BASE+12)
    def test_invalid_original_rom_unaligned(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            a.original_word(b"\x00"*12,a.BASE+1)
    def test_raw_u32_le(self):
        self.assertEqual(a.original_word(bytes.fromhex("78563412"),a.BASE),0x12345678)
    def test_a32_bl_forward(self):
        self.assertEqual(a.a32_bl(bl(0x1100,0x1800),0x1100),0x1800)
    def test_a32_bl_backward(self):
        self.assertEqual(a.a32_bl(bl(0x1800,0x1100),0x1800),0x1100)
    def test_a32_bl_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,"opcode"):
            a.a32_bl(0xe3a00000,0x1100)
    def test_a32_bl_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"opcode"):
            a.a32_bl(0x1b000000,0x1100)
    def test_readonly_site_inventory_match(self):
        m=a.MODELS["xs10"]
        r=fake_fixture(m)
        a.require_site_trace(r["logs"]["a32sites"],m.response_fn,
                             m.response_flag_test,"tst",0x80)
    def test_readonly_site_inventory_false_value(self):
        m=a.MODELS["xs10"]
        r=fake_fixture(m)
        with self.assertRaisesRegex(ValueError,"scalar-site"):
            a.require_site_trace(r["logs"]["a32sites"],m.response_fn,
                                 m.response_flag_test,"tst",0x40)
    def test_required_orig_sites_size(self):
        for m in a.MODELS.values():
            self.assertEqual(len(a.expected_sites(m)),17)

class StaticModel(unittest.TestCase):
    def test_positive_for_both_models(self):
        for model in a.MODELS:
            with self.subTest(model=model):
                d=verify_fake(model)
                self.assertEqual(d["OUTPUT_CODECCONFIG_test_mask"],"0x80")
                self.assertEqual(d["CPU_header_descriptor_block_bytes"],40)
                self.assertTrue(d["OUTPUT_buf_addr_plus_offset_read_from_descriptor"])
    def test_hevc_three_header_buffers(self):
        for model in a.MODELS:
            d=verify_fake(model)
            self.assertEqual(d["HEVC_header_record_count_if_known_codec0"],3)
            self.assertEqual(d["H264_header_record_count_if_known_codec1"],2)
    def test_output_bitstream_runtime_translation(self):
        for model in a.MODELS:
            d=verify_fake(model)
            self.assertIn("FUN_",d["OUTPUT_runtime_buffer_address_translation_function"])
            self.assertTrue(d["OUTPUT_filled_len_read_from_descriptor"])
    def test_confirm_fail_handled_separately(self):
        for model in a.MODELS:
            d=verify_fake(model)
            self.assertEqual(d["SET_OPTION_CONFIRM_response"],"0x7d3")
            self.assertEqual(d["SET_OPTION_FAIL_response"],"0x7e1")
    def test_sequence_notice_triggers_flush_not_SPS(self):
        for model in a.MODELS:
            d=verify_fake(model)
            self.assertEqual(d["SEQUENCE_PARAMETERS_branch_statically_sends_OUTPUT_FLUSH"],"0x3ec")
            self.assertTrue(d["SEQUENCE_PARAMS_response_is_not_coded_HEVC_VPS_SPS_PPS"])
    def test_outstanding_Main10_unknown(self):
        for model in a.MODELS:
            d=verify_fake(model)
            for x in ("Main10_SPS_or_hvcC_extracted",
                      "successful_VPU_HEVC_Main10_encoder_execution_observed",
                      "unknown_V61_microcode_receiver_disassembled",
                      "hardware_camera_or_flash_accessed"):
                self.assertFalse(d[x])
    def test_prior_no_profile3_positive(self):
        m=a.MODELS["xs10"]
        a.validate_stage42(fake_fixture(m)["prior"],m.name)
    def test_prior_no_profile3_wrong_declared(self):
        m=a.MODELS["xs10"]
        data=fake_fixture(m)["prior"]
        data["two_camera_original_ROM_A32_assignment_and_sender_inventory"][0][
            "direct_MVE_option3_and_job_site_inventory"
        ]["SndSetOption_direct_profile_level_index3_occurrences"]=1
        with self.assertRaisesRegex(ValueError,"index3"):
            a.validate_stage42(data,m.name)
    def test_prior_unbounded_absence_forbidden(self):
        m=a.MODELS["xt4"]
        data=fake_fixture(m)["prior"]
        data["two_camera_original_ROM_A32_assignment_and_sender_inventory"][1][
            "direct_MVE_option3_and_job_site_inventory"
        ]["all_other_indirect_or_other_queue_messages_excluded"]=True
        with self.assertRaisesRegex(ValueError,"index3"):
            a.validate_stage42(data,m.name)
    def test_prior_wrong_2_vs_3_headers(self):
        m=a.MODELS["xs10"]
        data=fake_fixture(m)["prior"]
        data["two_camera_original_ROM_A32_assignment_and_sender_inventory"][0][
            "independent_header_count_consistency"
        ]["input_video_codec_enum_0_header_record_count_if_split"]=2
        with self.assertRaisesRegex(ValueError,"headers"):
            a.validate_stage42(data,m.name)
    def test_bad_original_hash(self):
        m=a.MODELS["xs10"]
        f=fake_fixture(m)
        with patch.object(a,"sha256",return_value=SimpleNamespace(
                hexdigest=lambda:"0"*64)):
            with self.assertRaisesRegex(ValueError,"SHA256"):
                a.verify_model(m,b"toy",f["logs"],f["prior"])

# Independently flip each of 17 synthetic ARM words on both camera layouts:
# proves read-only audit rejects incorrect flags, fields, response IDs and
# buffer lengths rather than merely searching text. No vendor bytes used.
def altered_site_test(model,at_func):
    def t(self):
        m=a.MODELS[model]
        at=at_func(m)
        def edit(_,f):f["words"][at]^=1
        with self.assertRaisesRegex(ValueError,"original ARM"):
            verify_fake(model,edit)
    return t

model0=a.MODELS["xs10"]
site_names=(
"header_flag_store","header_offset_store","header_alloc_mov",
"header_alloc_store","header_filled_store","header_ptr_store",
"header_code_mov","header_code2_mov","response_flag_test",
"response_flag_test2","response_bufaddr_load","response_offset_load",
"response_filled_load","status_confirm_mov","status_sequence_mov",
"status_fail_mov","response_flush_mov",
)
for i,name in enumerate(site_names):
    for model in a.MODELS:
        setattr(StaticModel,"test_corrupt_arm_%02d_%s"%(i,model),
                altered_site_test(model,lambda m,name=name:getattr(m,name)))

def corrupted_BL_test(model,name):
    def t(self):
        m=a.MODELS[model]
        def edit(m,f):
            x=getattr(m,name)
            f["words"][x]=bl(x,m.response_msg_sender+0x44)
        with self.assertRaisesRegex(ValueError,"BL target"):
            verify_fake(model,edit)
    return t
for name in ("header_send_bl","header_send2_bl","response_flush_bl"):
    for model in a.MODELS:
        setattr(StaticModel,"test_corrupt_bl_%s_%s"%(name,model),
                corrupted_BL_test(model,name))

def fake_c_mutation(model,log_name,original,new,error_regex):
    def t(self):
        def edit(m,f):
            assert original in f["logs"][log_name],(log_name,original)
            f["logs"][log_name]=f["logs"][log_name].replace(original,new)
        with self.assertRaisesRegex(ValueError,error_regex):
            verify_fake(model,edit)
    return t

mutations=(
 ("header","puVar5[5] = 0x1000;","puVar5[5] = 0x2000;","header producer"),
 ("header","puVar5[6] = 0;","puVar5[6] = 4;","header producer"),
 ("header","puVar5[2] = 0;","puVar5[2] = 1;","header producer"),
 ("header","puVar5[3] = 0;","puVar5[3] = 1;","header producer"),
 ("header","puVar5[8] = uVar4;","puVar5[8] = 2;","header producer"),
 ("header","puVar1[8] = (0x20000000 - pbase) + off;","puVar1[8] = 5;","header producer"),
 ("header","uVar7 = 2;","uVar7 = 5;","header producer"),
 ("header","uVar7 = 3;","uVar7 = 4;","header producer"),
 ("header","0xbba,0x28","0xbba,0x20","header producer"),
 ("handler","& 0x80","& 0x40","CODECCONFIG"),
 ("handler","& 0x11","& 0x21","addr\\+offset"),
 ("handler","0x7d3","0x7d4","confirm/fail"),
 ("handler","0x7df","0x7de","confirm/fail"),
 ("handler","0x7e1","0x7e2","confirm/fail"),
 ("handler","0x7d7","0x7d6","confirm/fail"),
 ("handler","< 0x7d7","< 0x7d5","confirm/fail"),
 ("handler","0x3ec,0","0x3eb,0","confirm/fail"),
 ("handler","(0x20000)","(0x20001)","confirm/fail"),
 ("handler","(0x10)","(0x11)","confirm/fail"),
 ("ring","0x3fc","0x3fb","ring payload"),
 ("ring",">> 0x10",">> 0x08","ring payload"),
 ("ring","(param_1 >> 0xc)","(param_1 >> 0xb)","runtime translation"),
 ("ring","param_1 & 0xfff","param_1 & 0xfef","runtime translation"),
)
for i,(scope,left,right,err) in enumerate(mutations):
    model="xs10" if i%2==0 else "xt4"
    setattr(StaticModel,"test_mutate_ghidra_%02d_%s"%(i,model),
            fake_c_mutation(model,scope,left,right,err))

if __name__=="__main__":unittest.main()

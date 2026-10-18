"""Pure synthetic Stage42 HEVC/H264 VPU source / Profile3 guard tests.

No real image or vendor microcode bytes: fake ROM buffers are zero arrays
populated with locally synthesized individual ARM instruction words. Fake
Ghidra function texts are handwritten test fixtures. All original firmware
remains privately in ignored output/ on the user's authorized Ubuntu.
"""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage42_vpu_codec_firmware_source_profile as s
import audit_stage40_v61_hevc_image_boundaries as st40

def a32_bl(at,destination):
    delta=destination-at-8
    assert delta%4==0 and -(1<<25)<=delta<(1<<25)
    return 0xeb000000 | ((delta//4)&0xffffff)

def synth_movie_words(m):
    return {
      m.movie_rom_codec_load:0xe5d33dda,
      m.movie_rom_codec_cmp:0xe1530002,
      m.movie_rom_beq:0x0a00007b,
      m.h264_codec_store-4:0xe3a02001,
      m.h264_codec_store:0xe5832188,
      m.h264_ptr_low:0xe3080000,
      m.h264_ptr_high:0xe34000d0,
      m.h264_ptr_store:0xe5830010,
      m.hevc_codec_store-4:0xe3a02000,
      m.hevc_codec_store:0xe5832188,
      m.hevc_ptr_low:0xe3000000,
      m.hevc_ptr_high:0xe34000ca,
      m.hevc_ptr_store:0xe5830010,
      m.fw_address_api_bl:a32_bl(m.fw_address_api_bl,m.fw_address_api),
    }

def synth_rom2(m,changes=None):
    d=synth_movie_words(m)
    if changes:
        for a,new in changes.items():d[a]=new
    last=max(d)
    raw=bytearray(last-m.section2_base+4)
    for a,w in d.items():struct.pack_into("<I",raw,a-m.section2_base,w)
    return bytes(raw)

def synth_movie_c(m):
    return (
      "undefined4 FUN_%08x(int param_1)\n{\n"%m.movie_func+
      "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';\n"
      "if (bVar9) {\n"
      "uVar2 = 0xca0000;\n"
      "_DAT_%08x = 0xca0000;\n"%(m.vpu_params_base+0x10)+
      "}\nelse {\n"
      "uVar2 = 0xd08000;\n"
      "_DAT_%08x = 0xd08000;\n"%(m.vpu_params_base+0x10)+
      "}\n"
      "_DAT_%08x = (uint)!bVar9;\n"%(m.vpu_params_base+0x188)+
      "FUN_%08x(uVar2,0x39000,9);\n"%m.fw_address_api
    )

def fake_movie(model="xs10",mutate=None,corrupt_ghidra=None):
    m=s.CAMERAS[model]
    b=synth_rom2(m,mutate)
    m=replace(m,section2_sha256=sha256(b).hexdigest())
    c=synth_movie_c(m)
    if corrupt_ghidra:
        c=corrupt_ghidra(c,m)
    return s.verify_movie_selection(m,None,b,c)

def synth_vpu_words(m):
    d={}
    for siter in s.EXPECTED_SEND_CALLS[m.name]:
        d[siter]=a32_bl(siter,m.vpu_option_sender)
    d.update({
      m.header_codecload:0xe5933190,
      m.header_codec_cmp:0xe3530001,
      m.header_count2:0x03a08002,
      m.header_count3:0x13a08003,
      m.header2_codecload:0xe5933190,
      m.header2_codec_cmp:0xe3530001,
      m.header2_count2:0x03a09002,
      m.header2_count3:0x13a09003,
      m.header_bitstream_mov:0xe3001bba,
      m.header_bitstream_bl:a32_bl(m.header_bitstream_bl,m.header_ring_write),
      m.job_bl-4:0xe30003f1,
      m.job_bl:a32_bl(m.job_bl,m.vpu_option_sender),
    })
    return d

def synth_rom1(m,changes=None):
    d=synth_vpu_words(m)
    if changes:
        for a,n in changes.items():d[a]=n
    raw=bytearray(max(d)-s.ROM1_BASE+4)
    for addr,word in d.items():
        struct.pack_into("<I",raw,addr-s.ROM1_BASE,word)
    return bytes(raw)

def synth_header_c(m):
    return (
      "TRACE_DECOMP_BEGIN (Synthetic)\n"
      "void FUN_%08x(void)\n{\n"%m.header_sender+
      "s_h265_SndBitStreamHeader;\n"
      "if (*(int *)(iVar2 + 400) == 1) {\n"
      "uVar7 = 2;\n"
      "} else {\n"
      "uVar7 = 3;\n"
      "}\n"
      "FUN_%08x(puVar5,0xbba,0x28);\n"%m.header_ring_write+
      "}\n"
      "TRACE_DECOMP_END\n"
    )

def synth_option_c(m):
    fmt="FUN_%08x(0x3f2,8,&local_58);\n"%m.vpu_option_sender
    return (
      "TRACE_DECOMP_BEGIN (Synthetic)\n"
      "void FUN_%08x(void)\n{\n"%m.option_function+
      "local_58 = 1;\nlocal_54 = 1;\n"+fmt+
      "local_58 = 0x10;\nlocal_54 = 1;\n"+fmt+
      "if (codec_enum1 == 1) {\n"
      "local_58 = 0x26;\nlocal_54 = 0x80008;\n"+fmt+
      "}\nelse {\n"
      "local_58 = 1;\n"+fmt+
      "}\nlocal_58 = 5;\nlocal_54 = 1;\n"+fmt+
      "}\nTRACE_DECOMP_END\n"
    )

def synth_job_c(m):
    return (
       "TRACE_DECOMP_BEGIN (Synthetic)\n"
       "void FUN_%08x(void)\n{\n"%m.job_sender+
       "local_10 = 4;\nlocal_c = 0;\n"
       "FUN_%08x(0x3f1,8,&local_10);\n"%m.vpu_option_sender+
       "}\nTRACE_DECOMP_END\n"
    )

def synth_refs(m):
    out=["ST42_TARGET=%08x REFS=%d"%(m.vpu_option_sender,
                                    len(s.EXPECTED_SEND_CALLS[m.name]))]
    for i,source in enumerate(s.EXPECTED_SEND_CALLS[m.name]):
        out.append("ST42_REF=%d source=%08x kind=UNCONDITIONAL_CALL function=TOY"%(i,source))
    out.append("ST42_TARGET=%08x REFS=0"%(m.option_function))
    return "\n".join(out)

def run_header(model="xs10",mutate=None,corrupt_c=None):
    m=s.CAMERAS[model]
    rom=synth_rom1(m,mutate)
    c=synth_header_c(m)
    if corrupt_c:c=corrupt_c(c,m)
    return s.verify_header_split(m,rom,c)

def run_sender(model="xs10",mutate=None,corrupt_c=None,corrupt_refs=None,
               corrupt_job=None):
    m=s.CAMERAS[model]
    rom=synth_rom1(m,mutate)
    c=synth_option_c(m)
    refs=synth_refs(m)
    job=synth_job_c(m)
    if corrupt_c:c=corrupt_c(c,m)
    if corrupt_refs:refs=corrupt_refs(refs,m)
    if corrupt_job:job=corrupt_job(job,m)
    return s.verify_direct_option_senders(m,rom,c,refs,job)

def fake_four_images():
    b=bytearray(st40.BUNDLE_BYTES)
    for im in st40.IMAGES:
        off=im.start
        b[off+0x60:off+0x60+len(st40.SIGNATURE)]=st40.SIGNATURE
        label=im.name.encode()
        b[off+0x70:off+0x70+len(label)+1]=label+b"\x00"
        for i,n in enumerate(im.metadata):
            struct.pack_into("<I",b,off+0xc0+i*4,n)
        # Artificial distinctive data in each fake image.
        b[off+0x800:off+0x830]=bytes((i+13)%256 for i in range(48))
    data=bytes(b)
    defs=tuple(replace(im,sha256=sha256(data[im.start:im.end]).hexdigest())
               for im in st40.IMAGES)
    return data,defs

def fake_cases():
    return {x.name:{"images":{
       "hevc_encoder":{"bytes":s.MVE_FW_REGION_BYTES},
       "h264_encoder":{"bytes":s.MVE_FW_REGION_BYTES}}}
       for x in st40.CAMERAS}

class Stage42PositiveSynthetic(unittest.TestCase):
    def test_three_camera_source_offset_alignment(self):
        data=s.correlate_payload_source_offsets(fake_cases())
        self.assertEqual(len(data),3)
        self.assertEqual(data["xs10"]["constant_difference_for_both"],"0x2100000")
        self.assertEqual(data["xt4"]["constant_difference_for_both"],"0x1fa0000")
        self.assertEqual(data["xt3"]["constant_difference_for_both"],"0x1fc0000")
    def test_source_pointer_delta_is_encoder_decoder_bundle_size(self):
        self.assertEqual(s.FUJI_H264_ENCODER_FW_ADDR-s.FUJI_HEVC_ENCODER_FW_ADDR,0x68000)
    def test_hevc_source_and_h264_source_distinct(self):
        self.assertEqual((s.FUJI_HEVC_ENCODER_FW_ADDR,
                          s.FUJI_H264_ENCODER_FW_ADDR),(0xca0000,0xd08000))
    def test_frame_region_one_encoder_size(self):
        self.assertEqual(s.MVE_FW_REGION_BYTES,0x39000)
    def test_hevc_encoder_has_its_own_V61_header(self):
        b,images=fake_four_images()
        facts=s.validate_firmware_image_order(b,images)
        self.assertEqual(facts["hevc_encoder"]["slot_file_offset"],"0x0")
        self.assertEqual(facts["hevc_decoder"]["slot_file_offset"],"0x39000")
    def test_h264_encoder_second_bounded_fw_source(self):
        b,images=fake_four_images()
        facts=s.validate_firmware_image_order(b,images)
        self.assertEqual(facts["h264_encoder"]["slot_file_offset"],"0x68000")
    def test_four_images_all_distinct_fake_sha(self):
        b,images=fake_four_images()
        self.assertEqual(len(set([x.sha256 for x in images])),4)
    def test_movie_hevc_source_selection_all_models(self):
        for m in ("xs10","xt4"):
            with self.subTest(m=m):
                a=fake_movie(m)
                self.assertEqual(a["MovieCodec_byte_eq1_VPU_video_codec_enum"],0)
                self.assertEqual(a["MovieCodec_byte_eq1_VPU_FW_addr"],"0x00ca0000")
    def test_movie_h264_source_selection_all_models(self):
        for m in ("xs10","xt4"):
            with self.subTest(m=m):
                a=fake_movie(m)
                self.assertEqual(a["MovieCodec_byte_ne1_VPU_video_codec_enum"],1)
                self.assertEqual(a["MovieCodec_byte_ne1_VPU_FW_addr"],"0x00d08000")
    def test_movie_region_service_is_not_claimed_to_be_memcpy(self):
        for m in ("xs10","xt4"):
            self.assertFalse(fake_movie(m)["region_service_verified_as_memcpy"])
    def test_header_selector_2_vs_3_in_both_models(self):
        for m in ("xs10","xt4"):
            c=run_header(m)
            self.assertEqual(c["input_video_codec_enum_1_header_record_count_if_split"],2)
            self.assertEqual(c["input_video_codec_enum_0_header_record_count_if_split"],3)
    def test_header_2vs3_no_actual_sps_claim(self):
        for m in ("xs10","xt4"):
            self.assertTrue(run_header(m)["header_count_alone_not_proof_of_actual_VPS_SPS_PPS_bytes"])
    def test_header_is_bitstream_not_frame(self):
        self.assertEqual(s.MVE_FRAME_BITSTREAM,3002)
        self.assertNotEqual(s.MVE_FRAME_BITSTREAM,3001)
    def test_option_sender_direct11_in_both_models(self):
        for m in ("xs10","xt4"):
            out=run_sender(m)
            self.assertEqual(out["direct_Ghidra_xrefs_to_VPU_send_message"],11)
    def test_option_sender_five_index_values_are_not_profile3(self):
        for m in ("xs10","xt4"):
            out=run_sender(m)
            self.assertEqual(out["SndSetOption_fixed_indices_order"],[1,16,38,1,5])
            self.assertEqual(out["SndSetOption_direct_profile_level_index3_occurrences"],0)
    def test_h264_stream_bitdepth_option_only(self):
        for m in ("xs10","xt4"):
            c=run_sender(m)
            self.assertTrue(c["SndSetOption_conditional_H264_stream_bitdepth_index38"])
            self.assertFalse(c["SndSetOption_conditional_HEVC_stream_bitdepth_index38"])
    def test_job_constant4_is_not_main10_profile(self):
        for m in ("xs10","xt4"):
            self.assertTrue(run_sender(m)["JOB_four_in_code_is_core_count_not_HEVC_Main10_profile"])
    def test_no_unproven_runtime_conclusions(self):
        self.assertTrue(all(v is False for v in s.UNPROVEN.values()))
    def test_xref_direct_inventory_not_exhaustive_all_indirect(self):
        self.assertFalse(run_sender()["all_other_indirect_or_other_queue_messages_excluded"])
    def test_main10_profile_from_different_source_is_unknown(self):
        self.assertEqual(run_sender()["Main10_profile_config_sent_somewhere_else"],"UNKNOWN")
    def test_original_samples_not_live_xs10(self):
        self.assertEqual(set(s.CAMERAS),{"xs10","xt4"})
    def test_xT4_section2_must_not_use_xS10_base(self):
        self.assertNotEqual(s.CAMERAS["xs10"].section2_base,s.CAMERAS["xt4"].section2_base)
    def test_movw_decode_originally_synthesized(self):
        self.assertEqual(s.movw16(0xe3080000,0,0x03000000),0x8000)
    def test_movt_decode_originally_synthesized(self):
        self.assertEqual(s.movw16(0xe34000ca,0,0x03400000),0xca)
    def test_BEQ_target_from_synthetic_ARM(self):
        for key in ("xs10","xt4"):
            m=s.CAMERAS[key]
            self.assertEqual(s.decode_arm_beq(0x0a00007b,m.movie_rom_beq),m.hevc_branch)
    def test_BL_roundtrip(self):
        for key in ("xs10","xt4"):
            m=s.CAMERAS[key]
            self.assertEqual(s.decode_arm_bl(a32_bl(m.fw_address_api_bl,m.fw_address_api),
                                             m.fw_address_api_bl),m.fw_address_api)
    def test_rom_word_boundary_guard(self):
        with self.assertRaisesRegex(ValueError,"misaligned"):
            s.from_rom(b"\x00"*4,s.ROM1_BASE,s.ROM1_BASE+2)
    def test_bl_invalid_cond(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            s.decode_arm_bl(0x1b000000,0x100000)
    def test_beq_invalid_opcode(self):
        with self.assertRaisesRegex(ValueError,"BEQ"):
            s.decode_arm_beq(0xeb000000,0x100000)
    def test_movw_invalid_dst(self):
        with self.assertRaisesRegex(ValueError,"wrong MOVW"):
            s.movw16(0xe3080000,1,0x03000000)
    def test_movt_invalid_opcode(self):
        with self.assertRaisesRegex(ValueError,"wrong MOVW"):
            s.movw16(0xe3080000,0,0x03400000)

def assert_movie_fails(model,addr):
    def test(self):
        m=s.CAMERAS[model]
        original=synth_movie_words(m)[addr]
        with self.assertRaises(ValueError):
            fake_movie(model,mutate={addr:original^1})
    return test

MOVIE_SITES=lambda m:(
    m.movie_rom_codec_load,m.movie_rom_codec_cmp,m.movie_rom_beq,
    m.h264_codec_store-4,m.h264_codec_store,m.h264_ptr_low,
    m.h264_ptr_high,m.h264_ptr_store,
    m.hevc_codec_store-4,m.hevc_codec_store,m.hevc_ptr_low,
    m.hevc_ptr_high,m.hevc_ptr_store,m.fw_address_api_bl,
)
for key in ("xs10","xt4"):
    for i,addr in enumerate(MOVIE_SITES(s.CAMERAS[key])):
        setattr(Stage42PositiveSynthetic,"test_movie_A32_mutation_%02d_%s"%(i,key),
                assert_movie_fails(key,addr))

def assert_header_fails(model,addr):
    def t(self):
        m=s.CAMERAS[model]
        original=synth_vpu_words(m)[addr]
        with self.assertRaises(ValueError):
            run_header(model,mutate={addr:original^1})
    return t

HEADER_SITES=lambda m:(
 m.header_codecload,m.header_codec_cmp,m.header_count2,m.header_count3,
 m.header2_codecload,m.header2_codec_cmp,m.header2_count2,m.header2_count3,
 m.header_bitstream_mov,m.header_bitstream_bl,
)
for key in ("xs10","xt4"):
    for i,addr in enumerate(HEADER_SITES(s.CAMERAS[key])):
        setattr(Stage42PositiveSynthetic,"test_header_A32_mutation_%02d_%s"%(i,key),
                assert_header_fails(key,addr))

def assert_caller_bl_fails(model,idx):
    def t(self):
        m=s.CAMERAS[model]
        addr=s.EXPECTED_SEND_CALLS[model][idx]
        original=synth_vpu_words(m)[addr]
        with self.assertRaises(ValueError):
            run_sender(model,mutate={addr:original^1})
    return t

for model in ("xs10","xt4"):
    for i,_ in enumerate(s.EXPECTED_SEND_CALLS[model]):
        setattr(Stage42PositiveSynthetic,
               "test_direct_sender_BL_mutation_%02d_%s"%(i,model),
               assert_caller_bl_fails(model,i))

class Stage42StringProvenanceMutations(unittest.TestCase):
    def test_movie_genuine_branch_marker_missing(self):
        for m in ("xs10","xt4"):
            with self.subTest(m=m):
                with self.assertRaisesRegex(ValueError,"Ghidra parent"):
                    fake_movie(m,corrupt_ghidra=lambda c,m:c.replace(
                      "0xca0000","0xcb0000",1))
    def test_movie_h264_address_marker_missing(self):
        with self.assertRaisesRegex(ValueError,"Ghidra parent"):
            fake_movie(corrupt_ghidra=lambda c,m:c.replace(
               "0xd08000","0xd18000",1))
    def test_movie_fw_region_helper_length_wrong(self):
        with self.assertRaisesRegex(ValueError,"Ghidra parent"):
            fake_movie("xt4",corrupt_ghidra=lambda c,m:c.replace(
               "0x39000,9","0x68000,9"))
    def test_movie_missing_codec_assignment(self):
        with self.assertRaisesRegex(ValueError,"Ghidra parent"):
            fake_movie(corrupt_ghidra=lambda c,m:c.replace(
               "(uint)!bVar9","0"))
    def test_hevc_FW_label_not_just_h264(self):
        b,images=fake_four_images()
        swapped=list(images)
        swapped[0]=replace(swapped[0],name="H.264 BP/MP/HP Encoder")
        with self.assertRaisesRegex(ValueError,"descriptor"):
            s.validate_firmware_image_order(b,tuple(swapped))
    def test_image_wrong_hash(self):
        b,images=fake_four_images()
        altered=list(images)
        altered[0]=replace(altered[0],sha256="0"*64)
        with self.assertRaisesRegex(ValueError,"SHA256"):
            s.validate_firmware_image_order(b,tuple(altered))
    def test_image_wrong_count(self):
        b,images=fake_four_images()
        with self.assertRaises(ValueError):
            s.validate_firmware_image_order(b[:-1],images)
    def test_three_camera_cases_missing(self):
        cases=fake_cases()
        del cases["xt3"]
        with self.assertRaisesRegex(ValueError,"not inspected"):
            s.correlate_payload_source_offsets(cases)
    def test_bad_image_sizes(self):
        cases=fake_cases()
        cases["xs10"]["images"]["h264_encoder"]["bytes"]=123
        with self.assertRaisesRegex(ValueError,"image sizes"):
            s.correlate_payload_source_offsets(cases)
    def test_fake_sender_refs_count_missing(self):
        m=s.CAMERAS["xs10"]
        refs=synth_refs(m).replace("REFS=11","REFS=12",1)
        with self.assertRaisesRegex(ValueError,"xref"):
            s.read_direct_call_refs(refs,m.vpu_option_sender)
    def test_fake_sender_refs_bad_kind(self):
        with self.assertRaisesRegex(ValueError,"xref"):
            run_sender(corrupt_refs=lambda c,m:c.replace(
               "kind=UNCONDITIONAL_CALL","kind=READ",1))
    def test_fake_sender_refs_out_of_order(self):
        m=s.CAMERAS["xs10"]
        data=synth_refs(m)
        a,b=data.splitlines()[1:3]
        changed=data.replace(a,"#TMP#",1).replace(b,a,1).replace("#TMP#",b,1)
        with self.assertRaisesRegex(ValueError,"direct caller"):
            s.verify_direct_option_senders(m,synth_rom1(m),synth_option_c(m),
                    changed,synth_job_c(m))
    def test_invented_profile3_in_sender_fails(self):
        for key in ("xs10","xt4"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError,"indices changed"):
                    run_sender(key,corrupt_c=lambda c,m:c.replace(
                       "local_58 = 0x10;","local_58 = 3;"))
    def test_missing_MVE_setoption_call_fails(self):
        with self.assertRaises(ValueError):
            run_sender(corrupt_c=lambda c,m:c.replace(
               "0x3f2,8,&local_58","0x3f2,4,&local_58",1))
    def test_corrupt_H264_bitdepth_8_8_fails(self):
        with self.assertRaises(ValueError):
            run_sender(corrupt_c=lambda c,m:c.replace(
               "local_54 = 0x80008;","local_54 = 0xA000A;"))
    def test_corrupt_JOB_core_count_fails(self):
        with self.assertRaisesRegex(ValueError,"mistaken"):
            run_sender(corrupt_job=lambda c,m:c.replace(
               "local_10 = 4;","local_10 = 3;"))
    def test_corrupt_JOB_MVE_request_code_fails(self):
        with self.assertRaisesRegex(ValueError,"mistaken"):
            run_sender(corrupt_job=lambda c,m:c.replace(
               "0x3f1","0x3f2"))
    def test_corrupt_header_selector_2_to_4(self):
        with self.assertRaisesRegex(ValueError,"header producer"):
            run_header(corrupt_c=lambda c,m:c.replace("uVar7 = 2;","uVar7 = 4;"))
    def test_corrupt_header_selector_3_to_4(self):
        with self.assertRaisesRegex(ValueError,"header producer"):
            run_header(corrupt_c=lambda c,m:c.replace("uVar7 = 3;","uVar7 = 4;"))
    def test_header_buffer_is_bitstream_0xBBA(self):
        with self.assertRaisesRegex(ValueError,"header producer"):
            run_header(corrupt_c=lambda c,m:c.replace("0xbba,0x28","0xbb9,0x28"))
    def test_header_buffer_length_40B_not_72B(self):
        with self.assertRaisesRegex(ValueError,"header producer"):
            run_header(corrupt_c=lambda c,m:c.replace("0xbba,0x28","0xbba,0x48"))
    def test_option_JOB_BL_wrong(self):
        m=s.CAMERAS["xt4"]
        with self.assertRaisesRegex(ValueError,"direct send ref|job code"):
            run_sender("xt4",mutate={m.job_bl:a32_bl(m.job_bl,m.vpu_option_sender+4)})
    def test_option_JOB_MOVW_opcode_wrong(self):
        m=s.CAMERAS["xs10"]
        with self.assertRaisesRegex(ValueError,"job code"):
            run_sender("xs10",mutate={m.job_bl-4:0xe30003f2})

if __name__=="__main__":
    unittest.main()

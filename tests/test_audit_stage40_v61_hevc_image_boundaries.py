"""Stage40 synthetic-only tests for the V61 image split and diagnostic provenance.

All four module-like payloads are GENERATED (zero filled plus synthetic
headers, text and deliberately seeded 16-bit integers). No original firmware
bytes or private Ghidra logs are embedded/published. No camera interaction.
"""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage40_v61_hevc_image_boundaries as a

def stamp_u16(b,off,n):
    b[off:off+2]=n.to_bytes(2,"little")
def stamp_u32(b,off,n):
    b[off:off+4]=n.to_bytes(4,"little")

def fake_images():
    b=bytearray(a.BUNDLE_BYTES) # synthetic zeros, no proprietary code or data
    for im in a.IMAGES:
        start=im.start
        b[start+0x60:start+0x60+len(a.SIGNATURE)]=a.SIGNATURE
        name=im.name.encode()
        b[start+0x70:start+0x70+len(name)+1]=name+b"\x00"
        for j,n in enumerate(im.metadata):
            stamp_u32(b,start+0xc0+4*j,n)
    for label,(offset,txt) in a.HEVC_ENC_STRINGS.items():
        b[offset:offset+len(txt)]=txt.encode("ascii")
    for label,(offset,txt) in a.HEVC_DEC_STRINGS.items():
        b[offset:offset+len(txt)]=txt.encode("ascii")
    # Synthetic 16-bit constants placed only to mimic *bounded coincidences*,
    # not to encode any actual V61 instruction. Exactly matched counts.
    for key,(val,sites) in a.V61_IMM16_OBSERVATIONS.items():
        for off,nextword in sites:
            stamp_u16(b,off,val)
            stamp_u16(b,off+2,nextword)
    for image,counts in (
       (a.IMAGES[0],{0x121:13,0x201:12,0xbb9:5}),
       (a.IMAGES[1],{0x121:6,0x201:6,0xbb9:3})):
        idx=0
        for val,num in counts.items():
            for _ in range(num):
                stamp_u16(b,image.start+0x1800+idx*8,val)
                idx+=1

    h264en=a.IMAGES[2].start
    fake1=b"encoding not supported of this 10-bit input format"
    fake2=b"hardware does not support MVE_FORMAT_YUV420_P010"
    b[h264en+0x3000:h264en+0x3000+len(fake1)]=fake1
    b[h264en+0x3100:h264en+0x3100+len(fake2)]=fake2
    h264dec=a.IMAGES[3].start
    fake3=b"Bitdepth of AFBC output buffer must be 10-bit"
    b[h264dec+0x3000:h264dec+0x3000+len(fake3)]=fake3
    blob=bytes(b)
    images=tuple(replace(im,sha256=sha256(blob[im.start:im.end]).hexdigest())
                 for im in a.IMAGES)
    return blob,images

def run_fake(which="all",mutator=None,pin_sha=False):
    blob,images=fake_images()
    raw=bytearray(blob)
    if mutator:mutator(raw)
    blob=bytes(raw)
    if pin_sha:
        images=tuple(replace(im,sha256=sha256(blob[im.start:im.end]).hexdigest())
                     for im in images)
    if which=="all":
        return (a.check_four_images(blob,images,require_hash=True),
                a.diagnostics(blob,images),
                a.audit_bounded_opaque_code(blob,images))
    if which=="meta":return a.check_four_images(blob,images,require_hash=False)
    if which=="sha":return a.check_four_images(blob,images,require_hash=True)
    if which=="diag":return a.diagnostics(blob,images)
    if which=="opaque":return a.audit_bounded_opaque_code(blob,images)
    raise AssertionError(which)

class SyntheticGuards(unittest.TestCase):
    def test_positive_all_three_audits(self):
        layout,diagnostics,opaque=run_fake()
        self.assertEqual(len(layout),4)
        self.assertEqual(len(diagnostics),len(a.HEVC_ENC_STRINGS)+len(a.HEVC_DEC_STRINGS))
        self.assertEqual(opaque["raw_16bit_coincidences_by_HEVC_image"]["encoder"]["0xbb9"],5)
        self.assertFalse(opaque["V61_instruction_set_decoder_or_cfg_verified"])
    def test_container_length_math(self):
        self.assertEqual(a.BUNDLE_BYTES,0xb5000)
        self.assertEqual(a.HEVC_BUNDLE_BYTES,0x68000)
        self.assertEqual(a.HEVC_DEC_OFFSET,0x39000)
    def test_corrected_encoder_decoder_length(self):
        self.assertEqual(a.IMAGES[0].end-a.IMAGES[0].start,0x39000)
        self.assertEqual(a.IMAGES[1].end-a.IMAGES[1].start,0x2f000)
    def test_distinct_encoder_decoder_hash(self):
        raw,images=fake_images()
        self.assertNotEqual(images[0].sha256,images[1].sha256)
        self.assertEqual(images[0].sha256,sha256(raw[:0x39000]).hexdigest())
    def test_multi_codec_four_image_contiguity(self):
        self.assertTrue(a.validate_layout())
    def test_cross_camera_three_golden_offsets(self):
        self.assertEqual({c.name for c in a.CAMERAS},{"xt3","xt4","xs10"})
        self.assertEqual({c.version for c in a.CAMERAS},{"5.11","2.12","3.11"})
    def test_signature_is_specific(self):
        self.assertEqual(len(a.SIGNATURE),16)
        self.assertEqual(a.SIGNATURE[-8:],b"56610002")
    def test_image_submodule_names(self):
        self.assertEqual([i.name for i in a.IMAGES],
             ["H.265 MP Encoder","HEVC Decoder","H.264 BP/MP/HP Encoder",
              "H.264 BP/MP/HP Decoder"])
    def test_image_boundary_not_metadata_word(self):
        self.assertNotEqual(a.IMAGES[0].metadata[1],a.HEVC_DEC_OFFSET)
    def test_bits_are_only_diagnostic_strings(self):
        r=run_fake("diag")
        for item in r.values():
            self.assertTrue(item["present_in_original_static_bytes"])
            self.assertEqual(item["rejection_path_reachable_at_runtime"],"UNKNOWN")
    def test_10bit_decoder_is_not_encoder(self):
        r=run_fake("diag")
        self.assertEqual(r["10bit_decoded_stream_output"]["which_image"],
                         "hevc_decoder")
        self.assertEqual(r["10bit_input_not_accepted"]["which_image"],
                         "hevc_encoder")
    def test_unsupported_profile_is_encoder_only(self):
        r=run_fake("diag")
        self.assertEqual(r["hevc_profile_rejected"]["which_image"],
                         "hevc_encoder")
    def test_p010_rejection_is_in_both_image_types(self):
        r=run_fake("diag")
        self.assertEqual(r["p010_not_supported"]["which_image"],"hevc_encoder")
        self.assertEqual(r["decoder_p010_not_supported"]["which_image"],"hevc_decoder")
    def test_opaque_V61_format_codes_not_mapped(self):
        x=run_fake("opaque")
        for key in ("format_0x121_equated_to_p010_or_10bit",
                    "format_0x201_equated_to_p010_or_10bit",
                    "V61_instruction_set_decoder_or_cfg_verified",
                    "V61_0xBB9_consumer_address_verified",
                    "no_0xBB9_consumer_anywhere_proven"):
            self.assertFalse(x[key])
    def test_code_candidates_not_proven_xrefs(self):
        x=run_fake("opaque")
        for row in x["two_byte_candidate_sites"].values():
            self.assertFalse(row["true_V61_instruction_xref_verified"])
    def test_bitdepth_16bit_candidate_sites(self):
        x=run_fake("opaque")
        self.assertEqual(x["two_byte_candidate_sites"]["unsupported_encode_bitdepth"][
                         "bounded_candidate_file_offsets"],["0x7dce","0x7e66"])
    def test_nalu_candidates_are_separate(self):
        x=run_fake("opaque")
        self.assertEqual(x["two_byte_candidate_sites"]["nalu_format_unknown"][
                         "bounded_candidate_file_offsets"],["0x73b8","0x742c"])
    def test_encoder_decoder_0xbb9_raw_counts(self):
        x=run_fake("opaque")["raw_16bit_coincidences_by_HEVC_image"]
        self.assertEqual(x["encoder"]["0xbb9"],5)
        self.assertEqual(x["decoder"]["0xbb9"],3)
    def test_encoder_decoder_0x121_raw_counts(self):
        x=run_fake("opaque")["raw_16bit_coincidences_by_HEVC_image"]
        self.assertEqual(x["encoder"]["0x121"],13)
        self.assertEqual(x["decoder"]["0x121"],6)
    def test_encoder_decoder_0x201_raw_counts(self):
        x=run_fake("opaque")["raw_16bit_coincidences_by_HEVC_image"]
        self.assertEqual(x["encoder"]["0x201"],12)
        self.assertEqual(x["decoder"]["0x201"],6)
    def test_16bit_le_read(self):
        self.assertEqual(a.read_u16(b"\x34\x12",0),0x1234)
    def test_32bit_le_read(self):
        self.assertEqual(a.read_u32(b"\x78\x56\x34\x12",0),0x12345678)
    def test_16bit_invalid(self):
        with self.assertRaisesRegex(ValueError,"u16 outside"):
            a.read_u16(b"123",2)
    def test_32bit_invalid(self):
        with self.assertRaisesRegex(ValueError,"u32 outside"):
            a.read_u32(b"123",0)
    def test_16bit_aligned_scan(self):
        self.assertEqual(a.scan_aligned_u16(b"\x34\x12\x00\x00\x34\x12",0x1234),
                         (0,4))
    def test_16bit_scanner_ignores_unaligned(self):
        self.assertEqual(a.scan_aligned_u16(b"\xff\x34\x12\xff",0x1234),())
    def test_16bit_scanner_nonaligned_start(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            a.scan_aligned_u16(b"abcdef",0x2222,1,6)
    def test_16bit_scanner_bad_end(self):
        with self.assertRaisesRegex(ValueError,"bad bounded"):
            a.scan_aligned_u16(b"abcdef",0x2222,0,8)
    def test_invalid_layout_wrong_order(self):
        with self.assertRaisesRegex(ValueError,"image sequence"):
            a.validate_layout((a.IMAGES[1],a.IMAGES[0],*a.IMAGES[2:]))
    def test_invalid_layout_gap(self):
        images=list(a.IMAGES)
        images[1]=replace(images[1],start=0x3a000)
        with self.assertRaisesRegex(ValueError,"not contiguous"):
            a.validate_layout(tuple(images))
    def test_invalid_layout_overlap(self):
        images=list(a.IMAGES)
        images[1]=replace(images[1],start=0x38000)
        with self.assertRaisesRegex(ValueError,"not contiguous"):
            a.validate_layout(tuple(images))
    def test_invalid_layout_hevc_decoder_boundary(self):
        images=list(a.IMAGES)
        images[0]=replace(images[0],end=0x38000)
        images[1]=replace(images[1],start=0x38000)
        with self.assertRaisesRegex(ValueError,"HEVC Encoder/Decoder"):
            a.validate_layout(tuple(images))
    def test_invalid_layout_end(self):
        images=list(a.IMAGES)
        images[3]=replace(images[3],end=0xb6000)
        with self.assertRaisesRegex(ValueError,"not contiguous"):
            a.validate_layout(tuple(images))
    def test_invalid_image_region_length(self):
        raw,images=fake_images()
        with self.assertRaisesRegex(ValueError,"firmware payload region"):
            a.check_four_images(raw[:-1],images)
    def test_sha_detects_mutation(self):
        def mut(b):b[0x3100]^=1
        with self.assertRaisesRegex(ValueError,"SHA256"):
            run_fake("sha",mut)
    def test_wrong_p010_meta_is_not_format_data(self):
        images=list(a.IMAGES)
        images[0]=replace(images[0],metadata=(0x39000,*images[0].metadata[1:]))
        b,_=fake_images()
        with self.assertRaisesRegex(ValueError,"metadata"):
            a.check_four_images(b,tuple(images),require_hash=False)
    def test_previous_cpu_baseline_positive(self):
        model=[]
        for n in ("xs10","xt4"):
            model.append(dict(model=n,interrupt_registration_id="0xdef00001",
                              hardware_side_0xBB9_receiver_known=False,
                              physical_VPU_interruption_or_Main10_bitdepth_verified=False,
                              internal_XS10_10bit_or_4K60_enabled=False))
        a.previous_cpu_evidence(model)
    def test_wrong_cpu_baseline_no_models(self):
        with self.assertRaisesRegex(ValueError,"model set"):
            a.previous_cpu_evidence([])
    def test_wrong_cpu_baseline_unknown_response(self):
        m=[dict(model=n,interrupt_registration_id="0xdef00001",
                hardware_side_0xBB9_receiver_known=False,
                physical_VPU_interruption_or_Main10_bitdepth_verified=False,
                internal_XS10_10bit_or_4K60_enabled=False) for n in ("xs10","xt4")]
        m[1]["hardware_side_0xBB9_receiver_known"]=True
        with self.assertRaisesRegex(ValueError,"hardware proof"):
            a.previous_cpu_evidence(m)
    def test_wrong_cpu_baseline_false_hardware_proof(self):
        m=[dict(model=n,interrupt_registration_id="0xdef00001",
                hardware_side_0xBB9_receiver_known=False,
                physical_VPU_interruption_or_Main10_bitdepth_verified=False,
                internal_XS10_10bit_or_4K60_enabled=False) for n in ("xs10","xt4")]
        m[0]["physical_VPU_interruption_or_Main10_bitdepth_verified"]=True
        with self.assertRaisesRegex(ValueError,"hardware proof"):
            a.previous_cpu_evidence(m)

# Programmatically added synthetic adversarial mutations: each guard has a
# distinct unittest name, and mutated original-signature *lookalike* buffer
# is never made from actual vendor ROM data.

def mutation_test(offset,mutkind):
    def t(self):
        def edit(b):
            if mutkind=="zero":b[offset]=0
            elif mutkind=="change":b[offset]^=1
            elif mutkind=="append":
                b[offset:offset+4]=b"\xff"*4
        target="meta"
        with self.assertRaises(ValueError):
            run_fake(target,edit)
    return t

mutid=0
for im in a.IMAGES:
    for delta in (0x60,0x68,0x70,0xc0,0xc4,0xc8,0xcc):
        for typ in ("change",):
            method=f"test_image_header_modified_{mutid:03d}_{im.key}_{delta:x}"
            setattr(SyntheticGuards,method,mutation_test(im.start+delta,typ))
            mutid+=1

def diagnostic_mutation_test(label,loc,model):
    def t(self):
        def edit(b):b[loc]=ord("#")
        with self.assertRaisesRegex(ValueError,"diagnostic"):
            run_fake("diag",edit)
    return t

for name,(off,val) in a.HEVC_ENC_STRINGS.items():
    setattr(SyntheticGuards,"test_encoder_bad_diagnostic_"+name,
            diagnostic_mutation_test(name,off,"encoder"))
for name,(off,val) in a.HEVC_DEC_STRINGS.items():
    setattr(SyntheticGuards,"test_decoder_bad_diagnostic_"+name,
            diagnostic_mutation_test(name,off,"decoder"))

def bounded_candidate_mutation(name,site,dynamic_kind):
    def t(self):
        def edit(b):
            if dynamic_kind=="val":
                b[site]^=1
            else:
                b[site+2]^=1
        with self.assertRaises(ValueError):
            run_fake("opaque",edit)
    return t

for key,(value,pairs) in a.V61_IMM16_OBSERVATIONS.items():
    for site,n in pairs:
        for typ in ("val","after"):
            setattr(SyntheticGuards,f"test_v61_candidate_bad_{key}_{site:x}_{typ}",
                    bounded_candidate_mutation(key,site,typ))

def numeric_coincidence_mutation(m,n):
    def t(self):
        def edit(b):
            start=0 if m=="encoder" else 0x39000
            # guaranteed toy literal at +0x1800, +0x1800+13*8 or +0x1800+25*8
            idx={0x121:0,0x201:(13 if m=="encoder" else 6),
                 0xbb9:(25 if m=="encoder" else 12)}[n]
            b[start+0x1800+idx*8]^=1
        with self.assertRaisesRegex(ValueError,"frequency"):
            run_fake("opaque",edit)
    return t
for model in ("encoder","decoder"):
    for n in (0x121,0x201,0xbb9):
        setattr(SyntheticGuards,f"test_raw_literal_frequency_bad_{model}_{n:x}",
                numeric_coincidence_mutation(model,n))

class MutateComparators(unittest.TestCase):
    def test_bad_H264_encoder_10bit_fake(self):
        def edit(b):
            off=a.IMAGES[2].start+0x3000
            b[off:off+8]=b"\x00"*8
        with self.assertRaisesRegex(ValueError,"H264 encode"):
            run_fake("diag",edit)
    def test_bad_H264_encoder_P010_fake(self):
        def edit(b):
            off=a.IMAGES[2].start+0x3100
            b[off:off+8]=b"\x00"*8
        with self.assertRaisesRegex(ValueError,"H264 encode"):
            run_fake("diag",edit)
    def test_bad_H264_decoder_10bit_fake(self):
        def edit(b):
            off=a.IMAGES[3].start+0x3000
            b[off:off+8]=b"\x00"*8
        with self.assertRaisesRegex(ValueError,"decoder 10bit"):
            run_fake("diag",edit)
    def test_enc_diagnostic_misattributed_to_decode(self):
        def edit(b):
            im=a.IMAGES[1]
            txt=b"set-opt: Unsupported HEVC profile"
            off=im.start+0x1800
            b[off:off+len(txt)]=txt
        with self.assertRaisesRegex(ValueError,"encoder-only"):
            run_fake("diag",edit)
    def test_decoder_sps_wrongly_claimed_in_encoder(self):
        def edit(b):
            txt=b"SPS: Warning: Stream uses more reference frames than profile permits"
            off=a.IMAGES[0].start+0x2400
            b[off:off+len(txt)]=txt
        with self.assertRaisesRegex(ValueError,"decoder-only"):
            run_fake("diag",edit)
    def test_opaque_full_frame_header_not_a_u16(self):
        def edit(b):
            b[0x2a00:0x2a04]=(0x48<<16|0xbb9).to_bytes(4,"little")
        with self.assertRaisesRegex(ValueError,"frequency|exact little-endian ARM"):
            run_fake("opaque",edit)

if __name__=="__main__":
    unittest.main()

"""Pure synthetic negative/positive tests: no copyrighted firmware bytes."""
import struct
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import scan_profile_header_writes_stage28 as audit

BASE = 0x1000
SPEC = audit.Spec("synthetic", BASE, 0x12345000, 0x12348000,
                  0x12348004, 0x1044, 0x1800)


def movhalf(rd, val, high=False):
    return ((0xe3400000 if high else 0xe3000000) |
            (((val >> 12)&15)<<16) | (rd<<12) | (val&4095))


def mov_imm(rd,n):
    assert 0<=n<256
    return 0xe3a00000 | (rd<<12) | n


def mem(load,rn,rd,imm,byte=False):
    assert 0<=imm<4096
    return (0xe5900000 if load else 0xe5800000) | (
        (int(byte)<<22) | (rn<<16)|(rd<<12)|imm)


def bl(at,target):
    delta=target-at-8
    assert delta%4==0 and -(1<<25)<=delta<(1<<25)
    return 0xeb000000 | ((delta>>2)&0xffffff)


def make_code(mapping,size=0x200):
    b=bytearray(size)
    for addr,word in mapping.items():
        struct.pack_into("<I",b,addr-BASE,word)
    return bytes(b)


def scan(mapping,spec=SPEC,size=0x200):
    b=make_code(mapping,size)
    return audit.scan_section(spec,"section-test",BASE,b,
                              (("section-test",BASE,b),))


def load_addr(reg,addr,at):
    return {at:movhalf(reg,addr&0xffff),
            at+4:movhalf(reg,addr>>16,True)}


class DecoderTests(unittest.TestCase):
    def test_rotate_immediate_plain(self):
        self.assertEqual(audit.rotate_imm12(0xe280000a),10)

    def test_rotate_immediate_large(self):
        self.assertEqual(audit.rotate_imm12(0xe2832a03),0x3000)

    def test_movw_movt(self):
        self.assertEqual(audit.decode_mov_half(movhalf(3,0x987e)),
                         (False,3,0x987e))
        self.assertEqual(audit.decode_mov_half(movhalf(3,0x02d9,True)),
                         (True,3,0x02d9))

    def test_mov_half_reject(self):
        self.assertIsNone(audit.decode_mov_half(0xe1a04003))

    def test_branch_forward(self):
        self.assertEqual(audit.decode_branch(bl(0x1100,0x1800),0x1100),
                         (14,True,0x1800))

    def test_branch_backward(self):
        self.assertEqual(audit.decode_branch(bl(0x1800,0x1100),0x1800),
                         (14,True,0x1100))

    def test_branch_non_branch(self):
        self.assertIsNone(audit.decode_branch(0xe2832a03,0x1000))

    def test_standard_word_store(self):
        self.assertEqual(audit.decode_single_memory(mem(False,3,1,16)),
                         (False,3,1,16,4))

    def test_standard_byte_store(self):
        self.assertEqual(audit.decode_single_memory(mem(False,3,1,16,True)),
                         (False,3,1,16,1))

    def test_standard_word_load(self):
        self.assertEqual(audit.decode_single_memory(mem(True,3,1,16)),
                         (True,3,1,16,4))

    def test_reg_offset_not_supported(self):
        self.assertIsNone(audit.decode_single_memory(mem(False,3,1,16)|(1<<25)))

    def test_postindex_not_supported(self):
        self.assertIsNone(audit.decode_single_memory(mem(False,3,1,16)&~(1<<24)))

    def test_writeback_not_supported(self):
        self.assertIsNone(audit.decode_single_memory(mem(False,3,1,16)|(1<<21)))

    def test_negative_ldr_offset(self):
        word=mem(True,15,3,0x30)&~(1<<23)
        self.assertEqual(audit.decode_single_memory(word),
                         (True,15,3,-0x30,4))

    def test_halfword_store(self):
        self.assertEqual(audit.decode_halfword_store(0xe1c300b0),
                         (3,0,0))

    def test_halfword_load_rejected(self):
        self.assertIsNone(audit.decode_halfword_store(0xe1d300b0))

    def test_dp_mov_reg(self):
        self.assertEqual(audit.decode_dp(0xe1a04003),
                         (13,4,0,(False,3)))

    def test_dp_mov_imm(self):
        self.assertEqual(audit.decode_dp(mov_imm(2,32)),
                         (13,2,0,(True,32)))

    def test_dp_cmp_has_no_dest(self):
        self.assertEqual(audit.decode_dp(0xe3530000)[0],"test")

    def test_overlap_boundary(self):
        r=[audit.Region("codec",0x1000,2)]
        self.assertEqual(audit.overlap_labels(r,0xffc,4),())
        self.assertEqual(audit.overlap_labels(r,0xfff,4),("codec",))
        self.assertEqual(audit.overlap_labels(r,0x1001,1),("codec",))
        self.assertEqual(audit.overlap_labels(r,0x1002,1),())

    def test_zero_copy_not_overlap(self):
        self.assertEqual(audit.overlap_labels([audit.Region("header",0x1000)],
                                              0x1000,0),())


class CandidateTests(unittest.TestCase):
    def test_direct_str_to_descriptor_primary(self):
        p={**load_addr(3,SPEC.descriptor,0x1000),
           0x1008:mem(False,3,1,0x10)}
        ev=scan(p)
        self.assertEqual([(e.instruction,e.target,e.kind) for e in ev],
                         [(0x1008,SPEC.descriptor+0x10,"STR")])
        self.assertIn("descriptor_primary_buffer_pointer",ev[0].overlaps)
        self.assertFalse(ev[0].runtime_executed)
        self.assertFalse(ev[0].input_value_proven)

    def test_slot_control_is_not_descriptor_write(self):
        p={**load_addr(3,SPEC.primary_slot-0xac4,0x1000),
           0x1008:mem(False,3,1,0xac4)}
        ev=scan(p)
        self.assertEqual(ev[0].overlaps,("runtime_primary_pointer_slot",))

    def test_add_3000_and_ac4_slot(self):
        base=SPEC.primary_slot-0xac4-0x3000
        p={**load_addr(3,base,0x1000),
           0x1008:0xe2832a03,
           0x100c:mem(False,2,1,0xac4)}
        ev=scan(p)
        self.assertEqual(ev[0].target,SPEC.primary_slot)
        self.assertEqual(ev[0].source_class,"computed_A32")

    def test_strb_is_single_byte_not_full_word(self):
        p={**load_addr(3,SPEC.descriptor+0x10,0x1000),
           0x1008:mem(False,3,1,0,True)}
        ev=scan(p)
        self.assertEqual(ev[0].kind,"STRB")
        self.assertEqual(ev[0].width,1)

    def test_strh_overlap(self):
        p={**load_addr(3,SPEC.descriptor+0x10,0x1000),
           0x1008:0xe1c300b0}
        ev=scan(p)
        self.assertEqual(ev[0].kind,"STRH")
        self.assertEqual(ev[0].width,2)

    def test_pc_relative_literal_address(self):
        addr=SPEC.descriptor
        p={0x1000:mem(True,15,3,0x20),
           0x1004:mem(False,3,1,0x10),
           0x1028:addr}
        ev=scan(p)
        self.assertEqual(ev[0].target,addr+0x10)
        self.assertEqual(ev[0].source_class,"PC_LITERAL")

    def test_mov_reg_alias(self):
        p={**load_addr(3,SPEC.descriptor,0x1000),
           0x1008:0xe1a04003, # MOV R4,R3
           0x100c:mem(False,4,1,0x10)}
        ev=scan(p)
        self.assertEqual(ev[0].target,SPEC.descriptor+0x10)

    def test_unrelated_plus_5b0_not_writer(self):
        p={**load_addr(3,0x20000000,0x1000),
           0x1008:mem(False,3,1,0x5b0,True)}
        self.assertEqual(scan(p),[])

    def test_branch_kills_provenance(self):
        p={**load_addr(3,SPEC.descriptor,0x1000),
           0x1008:0xea000000,
           0x100c:mem(False,3,1,0x10)}
        self.assertEqual(scan(p),[])

    def test_conditional_store_not_proof(self):
        p={**load_addr(3,SPEC.descriptor,0x1000),
           0x1008:mem(False,3,1,0x10)&0x0fffffff}
        self.assertEqual(scan(p),[])

    def test_load_from_runtime_clears_known_value(self):
        p={**load_addr(3,SPEC.descriptor,0x1000),
           0x1008:mem(True,3,3,0x10),
           0x100c:mem(False,3,1,0x10)}
        # LDR r3,[r3,#0x10] is a dynamic POINTER; cannot treat as
        # the descriptor base's literal address afterwards.
        ev=scan(p)
        self.assertEqual([e.kind for e in ev],["LDR"])

    def test_memcpy_known_length_candidate(self):
        p={**load_addr(0,SPEC.descriptor+0xc,0x1000),
           0x1008:mov_imm(2,0x14),
           0x100c:bl(0x100c,SPEC.known_copy_helper)}
        ev=scan(p)
        self.assertEqual(len(ev),1)
        self.assertEqual(ev[0].kind,"known_copy_helper_call")
        self.assertIn("descriptor_primary_buffer_pointer",ev[0].overlaps)
        self.assertFalse(ev[0].input_value_proven) # no input source proof

    def test_memcpy_unknown_helper_only_candidate(self):
        p={**load_addr(0,SPEC.descriptor+0xc,0x1000),
           0x1008:mov_imm(2,0x14),
           0x100c:bl(0x100c,0x1a00)}
        ev=scan(p)
        self.assertEqual(ev[0].kind,"unverified_copy_like_call")
        self.assertFalse(ev[0].input_value_proven)

    def test_memcpy_not_covered_byte(self):
        p={**load_addr(0,SPEC.descriptor+0xc,0x1000),
           0x1008:mov_imm(2,4),
           0x100c:bl(0x100c,SPEC.known_copy_helper)}
        events=scan(p)
        self.assertEqual(len(events),1)
        self.assertEqual(events[0].overlaps,("descriptor_object_pointer",))
        self.assertNotIn("descriptor_primary_buffer_pointer",events[0].overlaps)

    def test_memcpy_unknown_length_not_reported(self):
        p={**load_addr(0,SPEC.descriptor+0xc,0x1000),
           0x100c:bl(0x100c,SPEC.known_copy_helper)}
        self.assertEqual(scan(p),[])

    def test_memcpy_oversized_length_not_claimed(self):
        p={**load_addr(0,SPEC.descriptor+0xc,0x1000),
           **load_addr(2,audit.MAX_SPAN+0x10,0x1008),
           0x1010:bl(0x1010,SPEC.known_copy_helper)}
        self.assertEqual(scan(p),[])

    def test_event_serialization_no_value_proven(self):
        e=audit.Event("synthetic","section-test",0x1010,"STR",0x2000,
                      4,("descriptor_primary_buffer_pointer",),"MOVW/MOVT")
        d=e.serializable()
        self.assertFalse(d["input_value_proven"])
        self.assertFalse(d["runtime_executed"])
        self.assertEqual(d["instruction"],"0x00001010")

    def test_control_gate_refuses_unsupported_image(self):
        with patch.object(Path,"read_bytes",return_value=bytes(0x90)):
            with self.assertRaisesRegex(RuntimeError,"control missing"):
                audit.scan_model(SPEC,Path(".") )

    def test_end_to_end_synthetic_image_passes_control_and_detects_candidate(self):
        model=audit.SPECS[0]
        site=model.slot_control_site
        base=model.section2_base
        b=bytearray(site-base+0x20)
        # Synthetic stand-in, not any actual ROM sequence. The real Phase27
        # control instruction address must be detected to enable reporting.
        words={site-12:movhalf(3,model.descriptor&0xffff),
               site-8:movhalf(3,model.descriptor>>16,True),
               site-4:0xe2832a03,
               site:mem(False,2,1,0xac4),
               base+0x100:movhalf(3,model.descriptor&0xffff),
               base+0x104:movhalf(3,model.descriptor>>16,True),
               base+0x108:mem(False,3,1,0x10)}
        for addr,word in words.items():
            struct.pack_into("<I",b,addr-base,word)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/("x6-"+model.model)
            root.mkdir()
            (root/"section-1.bin").write_bytes(bytes(16))
            (root/"section-2.bin").write_bytes(b)
            result=audit.scan_model(model,Path(tmp))
        self.assertTrue(result["phase27_primary_slot_positive_control"])
        self.assertEqual(result["descriptor_header_candidate_count"],1)
        self.assertEqual(result["descriptor_header_write_candidates"][0]
                         ["instruction"],f"0x{base+0x108:08x}")
        self.assertFalse(result["current_buffer_codec_value_known"])

    def test_input_paths_are_private_output_files(self):
        s=audit.SPECS[0]
        self.assertEqual(s.model,"xs10")
        self.assertEqual(s.descriptor,0x02d987e8)
        self.assertEqual(s.slot_control_site,0x0221477c)


if __name__=="__main__":
    unittest.main()

"""Stage37 synthetic-only tests for the read-only X6 VPU ring-space audit.

No proprietary ROM bytes, device communication, patches, or flashable files.
Each A32 word is synthesized from public ARM instruction encoding, then
mutated to verify fail-closed original-ROM controls and uncertainty flags.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_vpu_ring_memory_stage37 as a

def synth_movw(reg,value,hi=False):
    return ((0xe3400000 if hi else 0xe3000000)|
            ((value>>12&15)<<16)|(reg<<12)|(value&0xfff))
def synth_bl(site,dst):
    d=dst-site-8
    if d%4 or not -(1<<25)<=d<1<<25:raise ValueError("bad synthetic BL")
    return 0xeb000000|((d>>2)&0xffffff)
def synth_add_imm(rd,rn,value):
    for rot in range(16):
        shift=rot*2
        v=((value<<shift)|(value>>(32-shift)))&0xffffffff if shift else value
        if v<=255:
            return 0xe2800000|(rn<<16)|(rd<<12)|(rot<<8)|v
    raise ValueError("ARM A32 immediate not encodable")
def synth_str(src,base,offset=0):
    return 0xe5800000|(base<<16)|(src<<12)|offset
def synth_ldr(dst,base,offset=0):
    return 0xe5900000|(base<<16)|(dst<<12)|offset

def make_fixture(m):
    w={
      m.ring_setup_source:synth_ldr(3,2,0x18),
      m.ring_setup_source+4:synth_str(3,2,0x198),
      m.ring_clear_src:synth_ldr(0,3,0x1ac),
      m.ring_clear_src+0x10:0xe3a02a07,
      m.ring_clear_src+0x14:0xe3a01000,
      m.ring_clear_bl:synth_bl(m.ring_clear_bl,m.memset_func),
      m.frame_cmd_movw1:synth_movw(1,0xbb9),
      m.frame_cmd_movw2:synth_movw(1,0xbb9),
      m.rx_irq_bl1:synth_bl(m.rx_irq_bl1,m.rx_queue),
      m.rx_irq_bl2:synth_bl(m.rx_irq_bl2,m.rx_queue),
      m.rx2_irq_bl1:synth_bl(m.rx2_irq_bl1,m.rx2_queue),
      m.rx2_irq_bl2:synth_bl(m.rx2_irq_bl2,m.rx2_queue),
    }
    for i,(offset,field) in enumerate(zip(a.RING_OFFSETS,a.PACKET_FIELDS)):
        w[m.ring_add_first+8*i]=synth_add_imm(1,3,offset)
        w[m.ring_add_first+8*i+4]=synth_str(1,2,field)
    idx_regs=((12,2),(0,2),(1,2),(2,6))
    data_regs=((14,12),(12,0),(0,1),(1,2))
    for pos,(_,header,dat,idxsite,datasite,*_) in enumerate(a.ring_slot_pairs(m)):
        r,d=idx_regs[pos]
        w[idxsite-12]=synth_ldr(r,3,a.ring_slot_pairs(m)[pos][0])
        w[idxsite-8]=synth_movw(d,header&0xffff)
        w[idxsite-4]=synth_movw(d,header>>16,True)
        w[idxsite]=synth_str(r,d,0)
        reg,src=data_regs[pos]
        w[datasite-12]=synth_movw(reg,dat&0xffff)
        w[datasite-8]=synth_movw(reg,dat>>16,True)
        w[datasite-4]=synth_add_imm(src,src,0x10)
        w[datasite]=synth_str(src,reg)
    work="_DAT_%08x"%m.work_packet_ptr_slot
    cached="_DAT_%08x"%(m.cached_init_base+0x18)
    workinit=[
       "iVar11 = *(int *)(%s + 0x18);"%work
    ]+[
       "*(int *)(iVar9 + 0x%x) = iVar11 + 0x%x;"%(field,offset)
       for offset,field in zip(a.RING_OFFSETS,a.PACKET_FIELDS)
    ]+["FUN_%08x(uVar2,0,0x7000);"%m.memset_func]
    for field,idx,dat,*_ in a.ring_slot_pairs(m):
        workinit += [
          "_DAT_%08x = *(int *)(%s + 0x%x);"%(idx,work,field),
          "_DAT_%08x = _DAT_%08x + 0x10;"%(dat,idx)
        ]

    def sender(own,other,dat):
        return (
            "uVar3 = (uint)*(ushort *)(_DAT_%08x + 2);\n"%own+
            "uVar2 = (uint)*(ushort *)(_DAT_%08x + 2);\n"%other+
            "iVar1 = _DAT_%08x;\n"%dat+
            "*(uint *)(iVar1 + uVar3 * 4) = param_2 | param_3 << 0x10;\n"+
            "uVar2 = param_3 + 3U >> 2;\n"+
            "uVar3 = (uVar3 + 1) % 0x3fc;\n"
        )
    def receiver(own,other,dat):
        return (
            "uVar2 = (uint)*_DAT_%08x;\n"%own+
            "uVar1 = (uint)*_DAT_%08x;\n"%other+
            "uVar2 = (*(uint *)(_DAT_%08x + uVar1 * 4) >> 0x10) + 3 >> 2;\n"%dat+
            "uVar3 = (uVar3 + 1) % 0x3fc;\n"
        )
    c={
      "packet_builder":"puVar3[6] = %s;"%cached,
      "work_init":"\n".join(workinit),
      "primary_tx":sender(m.tx_index_slot,m.rx_index_slot,m.tx_data_slot),
      "primary_rx":receiver(m.rx_index_slot,m.tx_index_slot,m.rx_data_slot),
      "secondary_tx":sender(m.tx2_index_slot,m.rx2_index_slot,m.tx2_data_slot),
      "secondary_rx":receiver(m.rx2_index_slot,m.tx2_index_slot,m.rx2_data_slot),
      "irq":(
        "if (uVar4 == 0x7d5) {\n"
        "s_DRV_<____VPU_H265_RSP_CODE_INPUT\n"
        "FUN_%08x(&DAT_12345678);\n"%m.rx_queue+
        "FUN_%08x(&DAT_12345678);\n"%m.rx2_queue+
        "}"
      ),
      "frame_send":(
         "FUN_%08x(_DAT_%08x,0xbb9,0x48);"%
             (m.tx_queue,m.frame_pkt_ptr_slot)),
    }
    refs={
      "depth":(
        "PROBE_TARGET addr=%08x refs=1\n"%m.bitdepth_input_addr+
        "PROBE_REF from=%08x to=%08x type=WRITE\n"%
            (m.bitdepth_input_write,m.bitdepth_input_addr)+
        "PROBE_TARGET addr=%08x refs=1\n"%(m.cached_init_base+0x0c)+
        "PROBE_TARGET addr=%08x refs=2\n"%m.stage35_vpu_wrapper+
        "PROBE_REF from=00000000 type=COMPUTED_JUMP\n"+
        "PROBE_TARGET addr=%08x refs=2\n"%m.rx_queue+
        "PROBE_TARGET addr=%08x refs=2\n"%m.rx2_queue
      )
    }
    prev={
      "model":m.name,
      "VPU_frame_descriptor_bytes_cleared":72,
      "frame_send_command":"0x0bb9",
      "VPU_init_packet_ptr_slot":"0x%08x"%m.work_packet_ptr_slot,
      "VPU_static_movie_path_frame_code_if_no_intervening_writes":"0x121",
      "VPU_hardware_acceptance_or_SPS_proven":False,
    }
    return {
       "words":w,"C":c,"refs":refs,"prior":prev,
       "lit1":tuple(sorted(m.expected_other_0xbb9_moves+
                           (m.frame_cmd_movw1,m.frame_cmd_movw2))),
       "lit2":(),
    }

def run(m,mutator=None):
    f=make_fixture(m)
    if mutator:mutator(f)
    return a.validate_ring_topology(
       m,lambda at:f["words"][at],f["C"],f["refs"],f["prior"],
       f["lit1"],f["lit2"])

class ArmHelpers(unittest.TestCase):
    def test_arm_rotated_immediate_90000(self):
        self.assertEqual(a.decode_add(synth_add_imm(1,3,0x90000),1,3),0x90000)
    def test_arm_rotated_immediate_94000(self):
        self.assertEqual(a.decode_add(synth_add_imm(1,3,0x94000),1,3),0x94000)
    def test_all_ring_offsets_encodable(self):
        for off in a.RING_OFFSETS:
            self.assertEqual(a.decode_add(synth_add_imm(1,3,off),1,3),off)
    def test_decode_wrong_add_reg(self):
        with self.assertRaisesRegex(ValueError,"ADD"):
            a.decode_add(synth_add_imm(1,3,0x92000),2,3)
    def test_decode_wrong_add_opcode(self):
        with self.assertRaisesRegex(ValueError,"ADD"):
            a.decode_add(0xe3a00001,1,3)
    def test_movw_roundtrip(self):
        self.assertEqual(a.decode_movw(synth_movw(3,0x935c),3),0x935c)
    def test_movt_roundtrip(self):
        self.assertEqual(a.decode_movw(synth_movw(3,0x1c8,True),3,True),0x1c8)
    def test_bad_mov_variant(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.decode_movw(synth_movw(3,0x1c8,True),3,False)
    def test_decode_str(self):
        self.assertEqual(a.decode_imm_str(synth_str(1,2,0x1b4),1,2),0x1b4)
    def test_decode_ldr(self):
        self.assertEqual(a.decode_imm_ldr(synth_ldr(12,3,0x1b4),12,3),0x1b4)
    def test_reject_str_opposite(self):
        with self.assertRaisesRegex(ValueError,"STR"):
            a.decode_imm_str(synth_ldr(1,2,0x1b4),1,2)
    def test_reject_ldr_opposite(self):
        with self.assertRaisesRegex(ValueError,"LDR"):
            a.decode_imm_ldr(synth_str(1,2,0x1b4),1,2)
    def test_bl_positive(self):
        self.assertEqual(a.decode_bl(synth_bl(0x1100,0x1300),0x1100),0x1300)
    def test_bl_negative(self):
        self.assertEqual(a.decode_bl(synth_bl(0x1300,0x1100),0x1300),0x1100)
    def test_bad_bl_cond(self):
        with self.assertRaisesRegex(ValueError,"BL"):
            a.decode_bl(0x1b000000,0x1300)
    def test_ring_page_math(self):
        self.assertEqual(a.RING_HEADER+4*a.RING_WORDS,a.RING_PAGE)
        self.assertEqual(a.RING_BYTES,7*a.RING_PAGE)
    def test_packet_field_offsets(self):
        self.assertEqual(a.PACKET_FIELDS,(0x1ac,0x1b0,0x1b4,
                                          0x1b8,0x1bc,0x1c0,0x1c4))
    def test_ring_offset_span(self):
        self.assertEqual(a.RING_OFFSETS,(0x90000,0x91000,0x92000,
                                          0x93000,0x94000,0x95000,0x96000))
    def test_word_read_little_endian(self):
        self.assertEqual(a.read_word(bytes.fromhex("3412ab56"),0x1000,0x1000),0x56ab1234)
    def test_word_read_boundary(self):
        with self.assertRaisesRegex(ValueError,"bad original"):
            a.read_word(b"\x00"*4,0x1000,0x1004)
    def test_word_read_alignment(self):
        with self.assertRaisesRegex(ValueError,"bad original"):
            a.read_word(b"\x00"*8,0x1000,0x1001)
    def test_literal_scan_single_synthetic(self):
        rom=b"\x00"*4+(synth_movw(1,0xbb9)).to_bytes(4,"little")+b"\x00"*4
        self.assertEqual(a.scan_literal_movw(rom,0x1000,0xbb9),(0x1004,))
    def test_literal_scan_reject_different_immediate(self):
        rom=(synth_movw(1,0xbba)).to_bytes(4,"little")
        self.assertEqual(a.scan_literal_movw(rom,0x1000,0xbb9),())
    def test_literal_scan_reject_not_movw(self):
        rom=(0xe3a01001).to_bytes(4,"little")
        self.assertEqual(a.scan_literal_movw(rom,0x1000,0xbb9),())
    def test_ghidra_c_parser_synthetic(self):
        fake="TRACE_DECOMP_BEGIN (GhidraScript)\nint FUN_01111111(void)\n{\nhi;\n}\nTRACE_DECOMP_END (GhidraScript)"
        self.assertIn("hi;",a.c_function(fake,0x01111111))
    def test_ghidra_missing_function(self):
        with self.assertRaisesRegex(ValueError,"Ghidra C missing"):
            a.c_function("",0x01111111)

class SyntheticPath(unittest.TestCase):
    def test_positive_synthetic_both_models(self):
        for m in a.MODELS.values():
            with self.subTest(model=m.name):
                r=run(m)
                self.assertEqual(r["data_words_per_ring"],0x3fc)
                self.assertEqual(r["ring_header_bytes"],16)
                self.assertEqual(r["cleared_ring_region_bytes"],0x7000)
                self.assertEqual(r["bounded_Section1_movw_0xBB9_count"],4)
                self.assertEqual(r["bounded_Section2_movw_0xBB9_count"],0)
    def test_symmetric_ring_addresses(self):
        for m in a.MODELS.values():
            r=run(m)
            self.assertEqual([x["work_memory_ring_page_offset"] for x in r["ring_sections"]],
                 ["0x92000","0x93000","0x94000","0x95000"])
            self.assertEqual([x["CPU_channel"] for x in r["ring_sections"]],
                 ["TX","RX","TX","RX"])
    def test_uncertainty_flag_guards(self):
        for m in a.MODELS.values():
            r=run(m)
            self.assertFalse(r["0xBB9_direct_VPU_hardware_consumer_observed"])
            self.assertFalse(r["0xBB9_and_0x7D5_proven_request_response_pair"])
            self.assertFalse(r["physical_pixel_bitdepth_or_Main10_profile_identified"])
            self.assertFalse(r["live_VPU_work_base_value_observed"])
            self.assertFalse(r["camera_communicated_with_or_flashing"])
            self.assertFalse(r["internal_4K60_unlocked"])
    def test_direct_bitdepth_xref_limited(self):
        for m in a.MODELS.values():
            r=run(m)
            self.assertEqual(r["bitdepth_explicit_direct_xref_site_count_in_loaded_Ghidra"],1)
            self.assertFalse(r["bitdepth_indirect_alias_or_other_core_writers_excluded"])
    def test_src_missing(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["packet_builder"]=f["C"]["packet_builder"].replace(
               "%08x"%(m.cached_init_base+0x18),"deadbeef")
        with self.assertRaisesRegex(ValueError,"work-memory source"):run(m,edit)
    def test_work_base_wrong_field(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["work_init"]=f["C"]["work_init"].replace(
            "+ 0x18","+ 0x1c",1)
        with self.assertRaisesRegex(ValueError,"work base W"):run(m,edit)
    def test_ring_pages_bad_clear_length(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["work_init"]=f["C"]["work_init"].replace("0x7000","0x6000")
        with self.assertRaisesRegex(ValueError,"clear 0x7000"):run(m,edit)
    def test_bad_work_pointer_slot_C(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["work_init"]=f["C"]["work_init"].replace(
             "_DAT_%08x"%m.work_packet_ptr_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"work base W"):run(m,edit)
    def test_ring_page_C_identity_modified(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["work_init"]=f["C"]["work_init"].replace(
              "iVar11 + 0x93000","iVar11 + 0x93100")
        with self.assertRaisesRegex(ValueError,"work-memory map"):run(m,edit)
    def test_index_global_Ghidra_alias_wrong(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["work_init"]=f["C"]["work_init"].replace(
              "_DAT_%08x = *(int *)"%(m.rx_index_slot),
              "_DAT_00000000 = *(int *)")
        with self.assertRaisesRegex(ValueError,"index and ring-data"):run(m,edit)
    def test_data_global_Ghidra_alias_wrong(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["work_init"]=f["C"]["work_init"].replace(
              "_DAT_%08x = _DAT_"%m.rx_data_slot,
              "_DAT_00000000 = _DAT_")
        with self.assertRaisesRegex(ValueError,"index and ring-data"):run(m,edit)
    def test_TX_peer_wrong(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["primary_tx"]=f["C"]["primary_tx"].replace(
             "_DAT_%08x"%m.rx_index_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"index & data"):run(m,edit)
    def test_TX_uses_wrong_halfword(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["primary_tx"]=f["C"]["primary_tx"].replace("+ 2","+ 0")
        with self.assertRaisesRegex(ValueError,"writer header"):run(m,edit)
    def test_TX_ring_data_wrong(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["secondary_tx"]=f["C"]["secondary_tx"].replace(
              "_DAT_%08x"%m.tx2_data_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"index & data"):run(m,edit)
    def test_TX_header_command_and_len_wrong(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["primary_tx"]=f["C"]["primary_tx"].replace(
                "param_2 | param_3 << 0x10","param_2 | param_3 << 0x08")
        with self.assertRaisesRegex(ValueError,"writer header"):run(m,edit)
    def test_TX_modulo_wrong(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["primary_tx"]=f["C"]["primary_tx"].replace("0x3fc","0x400")
        with self.assertRaisesRegex(ValueError,"index & data"):run(m,edit)
    def test_RX_wrong_index_read(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["primary_rx"]=f["C"]["primary_rx"].replace(
          "(uint)*_DAT_%08x"%m.rx_index_slot,
          "(uint)*_DAT_00000000",1)
        with self.assertRaisesRegex(ValueError,"index & data"):run(m,edit)
    def test_RX_wrong_ring(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["primary_rx"]=f["C"]["primary_rx"].replace(
          "_DAT_%08x"%m.rx_data_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"index & data"):run(m,edit)
    def test_RX_length_not_from_packet_header(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["secondary_rx"]=f["C"]["secondary_rx"].replace(
                   ">> 0x10",">> 0x0f")
        with self.assertRaisesRegex(ValueError,"indexes/length"):run(m,edit)
    def test_response_missing_branch_code(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["irq"]=f["C"]["irq"].replace("0x7d5","0x7d6")
        with self.assertRaisesRegex(ValueError,"0x7D5"):run(m,edit)
    def test_response_missing_label(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["irq"]=f["C"]["irq"].replace(
                   "VPU_H265_RSP_CODE_INPUT","VPU_OTHER")
        with self.assertRaisesRegex(ValueError,"0x7D5"):run(m,edit)
    def test_response_missing_primary_reader(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["irq"]=f["C"]["irq"].replace(
                   "FUN_%08x"%m.rx_queue,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"0x7D5"):run(m,edit)
    def test_response_missing_secondary_reader(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["irq"]=f["C"]["irq"].replace(
                   "FUN_%08x"%m.rx2_queue,"FUN_ffffffff")
        with self.assertRaisesRegex(ValueError,"0x7D5"):run(m,edit)
    def test_frame_sender_wrong_payload_len(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["frame_send"]=f["C"]["frame_send"].replace(
                    "0xbb9,0x48","0xbb9,0x4c")
        with self.assertRaisesRegex(ValueError,"frame sender"):run(m,edit)
    def test_frame_sender_wrong_command(self):
        m=a.MODELS["xs10"]
        def edit(f):f["C"]["frame_send"]=f["C"]["frame_send"].replace(
                    "0xbb9","0xbba")
        with self.assertRaisesRegex(ValueError,"frame sender"):run(m,edit)
    def test_frame_sender_wrong_data_pointer(self):
        m=a.MODELS["xt4"]
        def edit(f):f["C"]["frame_send"]=f["C"]["frame_send"].replace(
            "_DAT_%08x"%m.frame_pkt_ptr_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"frame sender"):run(m,edit)
    def test_literal_wrong_count(self):
        m=a.MODELS["xt4"]
        def edit(f):f["lit1"]=f["lit1"][:-1]
        with self.assertRaisesRegex(ValueError,"bounded original Sections"):run(m,edit)
    def test_literal_extra_second_section(self):
        m=a.MODELS["xt4"]
        def edit(f):f["lit2"]=(m.section2_base+0x40,)
        with self.assertRaisesRegex(ValueError,"bounded original Sections"):run(m,edit)
    def test_bitdepth_xref_wrong_count(self):
        m=a.MODELS["xs10"]
        def edit(f):f["refs"]["depth"]=f["refs"]["depth"].replace(
            "PROBE_TARGET addr=%08x refs=1"%m.bitdepth_input_addr,
            "PROBE_TARGET addr=%08x refs=2"%m.bitdepth_input_addr)
        with self.assertRaisesRegex(ValueError,"xref baseline"):run(m,edit)
    def test_bitdepth_xref_wrong_writer(self):
        m=a.MODELS["xt4"]
        def edit(f):f["refs"]["depth"]=f["refs"]["depth"].replace(
            "PROBE_REF from=%08x"%m.bitdepth_input_write,
            "PROBE_REF from=ffffffff")
        with self.assertRaisesRegex(ValueError,"xref baseline"):run(m,edit)
    def test_cached_bitdepth_xref_wrong(self):
        m=a.MODELS["xs10"]
        def edit(f):f["refs"]["depth"]=f["refs"]["depth"].replace(
            "PROBE_TARGET addr=%08x refs=1"%(m.cached_init_base+0xc),
            "PROBE_TARGET addr=fffffff0 refs=1")
        with self.assertRaisesRegex(ValueError,"cached bitdepth"):run(m,edit)
    def test_dynamic_wrapper_xref_missing(self):
        m=a.MODELS["xt4"]
        def edit(f):f["refs"]["depth"]=f["refs"]["depth"].replace(
            "type=COMPUTED_JUMP","type=READ")
        with self.assertRaisesRegex(ValueError,"dynamic API"):run(m,edit)
    def test_ring_reader_xref_count_wrong(self):
        m=a.MODELS["xs10"]
        def edit(f):f["refs"]["depth"]=f["refs"]["depth"].replace(
             "PROBE_TARGET addr=%08x refs=2"%m.rx_queue,
             "PROBE_TARGET addr=%08x refs=4"%m.rx_queue)
        with self.assertRaisesRegex(ValueError,"inbound ring helper"):run(m,edit)
    def test_stage36_baseline_invalid(self):
        m=a.MODELS["xt4"]
        def edit(f):f["prior"]["VPU_hardware_acceptance_or_SPS_proven"]=True
        with self.assertRaisesRegex(ValueError,"Stage36 baseline"):run(m,edit)

# Exhaustively mutate each original ARM ring pointer, data pointer and mapping
# instruction. Different models alternate, so both implementations are tested.
mutations=[]
for i in range(7):
    mutations.append(("original ARM ring region",lambda m,i=i:m.ring_add_first+8*i))
    mutations.append(("original ARM packet ring slot",lambda m,i=i:m.ring_add_first+8*i+4))
for site_field in ("ring_setup_source","ring_clear_src","ring_clear_bl"):
    mutations.append(("work memory base" if site_field=="ring_setup_source" else
                      "original ARM memset" if site_field=="ring_clear_src" else
                      "memset" if site_field=="ring_clear_bl" else "invalid",
                      lambda m,k=site_field:getattr(m,k)))
for idx,dat in (
  ("tx_index_store","tx_data_store"),
  ("rx_index_store","rx_data_store"),
  ("tx2_index_store","tx2_data_store"),
  ("rx2_index_store","rx2_data_store"),
):
    for field in (idx,dat):
        for relative in (-12,-8,-4,0):
            label="ring header pointer" if field==idx and relative==-12 else \
                  "pointer slot" if field==idx else \
                  "MOVW/MOVT" if relative in (-12,-8) else "DATA pointer"
            mutations.append((label,lambda m,field=field,rel=relative:
                             getattr(m,field)+rel))
for field in ("frame_cmd_movw1","frame_cmd_movw2"):
    mutations.append(("0xBB9",lambda m,field=field:getattr(m,field)))
for field in ("rx_irq_bl1","rx_irq_bl2","rx2_irq_bl1","rx2_irq_bl2"):
    mutations.append(("RX queue call",lambda m,field=field:getattr(m,field)))

def corrupted_word_case(number,label,site):
    def test(self):
        m=a.MODELS["xt4" if number%2 else "xs10"]
        def edit(f):
            addr=site(m)
            f["words"][addr]^=1
        # Exact error messages can differ by what field broke; failure
        # must happen, which is the key fail-closed property.
        with self.assertRaises(ValueError):
            run(m,edit)
    test.__name__="test_synthetic_A32_mutation_%03d"%number
    return test

for i,(label,site) in enumerate(mutations):
    setattr(SyntheticPath,"test_synthetic_A32_mutation_%03d"%i,
            corrupted_word_case(i,label,site))

if __name__=="__main__":
    unittest.main()

#!/usr/bin/env python3
"""Stage37 X6 read-only audit: VPU ring memory layout and response direction.

Original Section1/2 and private read-only Ghidra C/refs stay on authorized
Ubuntu in gitignored output/. This script NEVER connects to a camera or alters
DAT, firmware, CPU memory or device settings. No Main10/4K60 claims.

Scope: software ARM control plane, not the other side of the shared memory
queue. No VPU microcode execution or pixel-format-0x201/0x121 identification.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct

ROM1=0x01021000
RING_OFFSETS=tuple(0x90000+i*0x1000 for i in range(7))
PACKET_FIELDS=tuple(0x1ac+i*4 for i in range(7))
RING_PAGE=0x1000
RING_HEADER=0x10
RING_WORDS=0x3fc
RING_BYTES=0x7000
COMMAND=0x0bb9
RSP_INPUT=0x07d5
STAGE37_FLAGS={
 "0xBB9_direct_VPU_hardware_consumer_observed":False,
 "0xBB9_and_0x7D5_proven_request_response_pair":False,
 "live_VPU_work_base_value_observed":False,
 "physical_pixel_bitdepth_or_Main10_profile_identified":False,
 "internal_4K60_unlocked":False,
 "camera_communicated_with_or_flashing":False,
}

@dataclass(frozen=True)
class Model:
    name:str
    section2_base:int
    work_packet_ptr_slot:int
    cached_init_base:int
    ring_setup_func:int
    ring_setup_source:int
    ring_add_first:int
    ring_clear_src:int
    ring_clear_bl:int
    memset_func:int
    tx_index_store:int
    rx_index_store:int
    tx2_index_store:int
    rx2_index_store:int
    tx_index_slot:int
    rx_index_slot:int
    tx2_index_slot:int
    rx2_index_slot:int
    tx_data_store:int
    rx_data_store:int
    tx2_data_store:int
    rx2_data_store:int
    tx_data_slot:int
    rx_data_slot:int
    tx2_data_slot:int
    rx2_data_slot:int
    tx_queue:int
    rx_queue:int
    tx2_queue:int
    rx2_queue:int
    irq_dispatch:int
    rx_irq_bl1:int
    rx_irq_bl2:int
    rx2_irq_bl1:int
    rx2_irq_bl2:int
    frame_sender:int
    frame_cmd_movw1:int
    frame_cmd_movw2:int
    expected_other_0xbb9_moves:tuple
    bitdepth_input_addr:int
    bitdepth_input_write:int
    stage35_vpu_wrapper:int
    frame_pkt_ptr_slot:int
    packet_builder:int

MODELS={
 "xs10":Model(
  "xs10",0x01eaf000,0x01c8573c,0x01c25970,
  0x011fb93c,0x011fb954,0x011fb97c,0x011fbc84,0x011fbc9c,0x011fcb5c,
  0x011fbcf4,0x011fbd04,0x011fbd14,0x011fbd24,
  0x019e6880,0x01c62850,0x01b4a104,0x01b4c47c,
  0x011fbd64,0x011fbd74,0x011fbd84,0x011fbd94,
  0x01c7b720,0x01b53d38,0x01add918,0x019e33e4,
  0x011fa714,0x011fa974,0x011fa844,0x011faa68,
  0x011fcbc4,0x011fd6d4,0x011fd6fc,0x011fd22c,0x011fd3a0,
  0x011fac24,0x011fad74,0x011faf20,(0x01085f8c,0x0109ee44),
  0x02945a14,0x022def50,0x011f7190,0x01b8809c,0x011f8460),
 "xt4":Model(
  "xt4",0x01e0f000,0x01be5808,0x01b840d8,
  0x011cefe8,0x011cf000,0x011cf028,0x011cf330,0x011cf348,0x011d0208,
  0x011cf3a0,0x011cf3b0,0x011cf3c0,0x011cf3d0,
  0x019567b0,0x01bc2230,0x01ab2104,0x01ab63ac,
  0x011cf410,0x011cf420,0x011cf430,0x011cf440,
  0x01bdbab0,0x01abdd74,0x01a44c18,0x01953324,
  0x011cddc0,0x011ce020,0x011cdef0,0x011ce114,
  0x011d0270,0x011d0d80,0x011d0da8,0x011d08d8,0x011d0a4c,
  0x011ce2d0,0x011ce420,0x011ce5cc,(0x01084cb4,0x0109d310),
  0x028a515c,0x0224b748,0x011ca83c,0x01af2804,0x011cbb0c)
}

def must(flag,message):
    if not flag:raise ValueError("Stage37 VPU shared ring audit: "+message)

def read_word(buf,base,site):
    off=site-base
    must(off>=0 and off%4==0 and off+4<=len(buf),
         "bad original ROM word address")
    return struct.unpack_from("<I",buf,off)[0]

def arm_imm(inst):
    """Rotate right the ARM A32 immediate imm8 by twice its four-bit shift."""
    s=2*((inst>>8)&15)
    u=inst&0xff
    return ((u>>s)|(u<<(32-s)))&0xffffffff if s else u

def decode_add(inst,rd,rn):
    must((inst>>28)==14 and inst&0x0fe00000==0x02800000 and
         (inst>>12)&15==rd and (inst>>16)&15==rn,
         "wrong A32 ADD immediate opcode/registers")
    return arm_imm(inst)

def decode_imm_str(inst,src,base):
    must(inst>>28==14 and inst&0x0ff00000==0x05800000 and
         (inst>>12)&15==src and (inst>>16)&15==base,
         "wrong A32 STR immediate opcode/registers")
    return inst&0xfff

def decode_imm_ldr(inst,dst,base):
    must(inst>>28==14 and inst&0x0ff00000==0x05900000 and
         (inst>>12)&15==dst and (inst>>16)&15==base,
         "wrong A32 LDR immediate opcode/registers")
    return inst&0xfff

def decode_movw(inst,reg,hi=False):
    must(inst>>28==14 and inst&0x0ff00000==
          (0x03400000 if hi else 0x03000000) and (inst>>12)&15==reg,
         "wrong A32 MOVW/MOVT variant/register")
    return (((inst>>16)&15)<<12)|(inst&0xfff)

def decode_bl(inst,site):
    must((inst>>28)==14 and (inst&0x0f000000)==0x0b000000,
         "wrong A32 BL opcode/condition")
    disp=inst&0xffffff
    if disp&0x800000:disp-=0x1000000
    return (site+8+disp*4)&0xffffffff

def c_function(log,addr):
    fn="FUN_%08x"%addr
    for raw in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=raw.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:int|uint|void|undefined\d+)\s+"+
                     re.escape(fn)+r"\(",c):
            return c
    raise ValueError("Ghidra C missing "+fn)

def scan_literal_movw(buf,base,target):
    """Linear aligned A32 candidate screen: NOT a code ownership/CFG proof."""
    out=[]
    for off in range(0,len(buf)-3,4):
        w=struct.unpack_from("<I",buf,off)[0]
        if w>>28==14 and w&0x0ff00000==0x03000000:
            imm=(((w>>16)&15)<<12)|(w&0xfff)
            if imm==target:out.append(base+off)
    return tuple(out)

def ring_slot_pairs(m):
    """Packet field offset, xref index ptr global, xref ring data ptr global."""
    return ((0x1b4,m.tx_index_slot,m.tx_data_slot,m.tx_index_store,m.tx_data_store,
             m.tx_queue,m.rx_queue),
            (0x1b8,m.rx_index_slot,m.rx_data_slot,m.rx_index_store,m.rx_data_store,
             m.rx_queue,m.tx_queue),
            (0x1bc,m.tx2_index_slot,m.tx2_data_slot,m.tx2_index_store,m.tx2_data_store,
             m.tx2_queue,m.rx2_queue),
            (0x1c0,m.rx2_index_slot,m.rx2_data_slot,m.rx2_index_store,m.rx2_data_store,
             m.rx2_queue,m.tx2_queue))

def validate_ring_topology(m,word,c,refs,prev,lit1,lit2):
    must(prev["model"]==m.name and prev["VPU_frame_descriptor_bytes_cleared"]==72 and
         prev["frame_send_command"]=="0x0bb9" and
         prev["VPU_init_packet_ptr_slot"]=="0x%08x"%m.work_packet_ptr_slot and
         prev["VPU_static_movie_path_frame_code_if_no_intervening_writes"]=="0x121" and
         prev["VPU_hardware_acceptance_or_SPS_proven"] is False,
         "previous Stage36 baseline changed")

    asm=c["packet_builder"]
    s=c["work_init"]
    base="_DAT_%08x"%m.work_packet_ptr_slot
    bit="_DAT_%08x"%(m.cached_init_base+0x18)
    must("puVar3[6] = %s;"%bit in asm,
         "cached VPU work-memory source does not feed VPU init packet+0x18")
    must("iVar11 = *(int *)(%s + 0x18);"%base in s,
         "ring work base W no longer read from init packet +0x18")
    must(word(m.ring_setup_source)==0xe5923018 and
         decode_imm_str(word(m.ring_setup_source+4),3,2)==0x198,
         "A32 work memory base load/storage changed")
    must(decode_imm_ldr(word(m.ring_setup_source),3,2)==0x18,
         "work base loaded from wrong packet field")
    for i,(delta,field) in enumerate(zip(RING_OFFSETS,PACKET_FIELDS)):
        site=m.ring_add_first+8*i
        must(decode_add(word(site),1,3)==delta,
             "wrong original ARM ring region ADD +0x%x"%delta)
        must(decode_imm_str(word(site+4),1,2)==field,
             "wrong original ARM packet ring slot +0x%x"%field)
        must(("*(int *)(iVar9 + 0x%x) = iVar11 + 0x%x;"%(field,delta) in s or
              ("*(int *)(%s + 0x%x) = iVar11 + 0x%x;"%(base,field,delta) in s)),
             "Ghidra work-memory map missing W+0x%x into packet+0x%x"%
                 (delta,field))
    must("FUN_%08x(uVar2,0,0x7000);"%m.memset_func in s,
         "Ghidra ring region clear 0x7000 missing")
    must(decode_imm_ldr(word(m.ring_clear_src),0,3)==0x1ac and
         word(m.ring_clear_src+0x10)==0xe3a02a07 and
         word(m.ring_clear_src+0x14)==0xe3a01000 and
         decode_bl(word(m.ring_clear_bl),m.ring_clear_bl)==m.memset_func,
         "original ARM memset(W+0x90000,0,0x7000) path mismatch")
    must(RING_HEADER+4*RING_WORDS==RING_PAGE and
         RING_BYTES==7*RING_PAGE,
         "4KiB ring page capacity arithmetic inconsistent")

    regs=((12,2),(0,2),(1,2),(2,6))
    data_slot_registers=((14,12),(12,0),(0,1),(1,2))
    topology=[]
    for pos,(field,idx_slot,data_slot,idx_store,data_store,tx_func,paired_func) in enumerate(ring_slot_pairs(m)):
        src_reg,dst_reg=regs[pos]
        # Load packet[field] into source register, then build absolute
        # address of the static pointer-slot, and store that pointer.
        must(decode_imm_ldr(word(idx_store-12),src_reg,3)==field,
             "ring header pointer source (packet field) wrong")
        idx=decode_movw(word(idx_store-8),dst_reg)
        idx|=decode_movw(word(idx_store-4),dst_reg,True)<<16
        must(idx==idx_slot and
             decode_imm_str(word(idx_store),src_reg,dst_reg)==0,
             "A32 ring HEADER pointer slot register/address/STR mismatch")

        ptr_reg,add_reg=data_slot_registers[pos]
        addr=decode_movw(word(data_store-12),ptr_reg)
        addr|=decode_movw(word(data_store-8),ptr_reg,True)<<16
        must(addr==data_slot,
             "A32 DATA pointer slot MOVW/MOVT identity mismatch")
        must(decode_add(word(data_store-4),add_reg,add_reg)==0x10 and
             decode_imm_str(word(data_store),add_reg,ptr_reg)==0,
             "A32 DATA pointer +0x10 header skip / slot store mismatch")

        must(("%s = *(int *)(%s + 0x%x);"%
              ("_DAT_%08x"%idx_slot,base,field)) in s and
             ("%s = %s + 0x10;"%("_DAT_%08x"%data_slot,
                                   "_DAT_%08x"%idx_slot)) in s,
             "Ghidra queue index and ring-data-pointer alias mismatch")

        topology.append({
            "packet_field_offset":"0x%x"%field,
            "work_memory_ring_page_offset":"0x%x"%(0x90000+(field-0x1ac)//4*0x1000),
            "header_index_ptr_global":"0x%08x"%idx_slot,
            "ring_data_ptr_global":"0x%08x"%data_slot,
            "ring_data_offset_from_page":"0x10",
            "CPU_channel":"TX" if pos in (0,2) else "RX",
            "software_function":"FUN_%08x"%tx_func,
        })
    # Producer uses the upper 16-bit of each ring-page's first index word
    # and stores command+payload length in the first word of the ring data.
    # CPU-side consumer operates on a DISTINCT inbound page, lower 16-bit
    # read index, not on the outbound TX region where 0xBB9 was placed.
    primary_tx=c["primary_tx"];primary_rx=c["primary_rx"]
    tx2=c["secondary_tx"];rx2=c["secondary_rx"]
    pairs=(
       (primary_tx,m.tx_index_slot,m.rx_index_slot,m.tx_data_slot,True),
       (primary_rx,m.rx_index_slot,m.tx_index_slot,m.rx_data_slot,False),
       (tx2,m.tx2_index_slot,m.rx2_index_slot,m.tx2_data_slot,True),
       (rx2,m.rx2_index_slot,m.tx2_index_slot,m.rx2_data_slot,False)
    )
    for body,own_idx,peer_idx,data_ptr,is_writer in pairs:
        must("_DAT_%08x"%own_idx in body and
             "_DAT_%08x"%peer_idx in body and
             "_DAT_%08x"%data_ptr in body and
             "0x3fc" in body,
             "ring function lacks expected own/peer index & data pointer")
        if is_writer:
            must("*(ushort *)(_DAT_%08x + 2)"%own_idx in body and
                 "*(ushort *)(_DAT_%08x + 2)"%peer_idx in body and
                 "param_2 | param_3 << 0x10" in body and
                 "param_3 + 3U >> 2" in body,
                 "software ring writer header/producer halfword incorrect")
        else:
            must("uVar1 = (uint)*_DAT_%08x;"%peer_idx in body and
                 "uVar2 = (uint)*_DAT_%08x;"%own_idx in body and
                 ">> 0x10" in body,
                 "software inbound reader indexes/length header incorrect")

    irq=c["irq"]
    must(("uVar4 == 0x7d5" in irq) and
         ("VPU_H265_RSP_CODE_INPUT" in irq) and
         ("FUN_%08x("%m.rx_queue in irq) and
         ("FUN_%08x("%m.rx2_queue in irq),
         "CPU response callback does not consume inbound rings on 0x7D5/event")
    for at,dst in (
       (m.rx_irq_bl1,m.rx_queue),(m.rx_irq_bl2,m.rx_queue),
       (m.rx2_irq_bl1,m.rx2_queue),(m.rx2_irq_bl2,m.rx2_queue)
    ):
        must(decode_bl(word(at),at)==dst,
             "original ARM IRQ handler RX queue call BL target differs")

    frame=c["frame_send"]
    must("0xbb9,0x48" in frame and "_DAT_%08x"%m.frame_pkt_ptr_slot in frame,
         "0xBB9/72-byte frame sender destination missing")
    must(decode_movw(word(m.frame_cmd_movw1),1)==COMMAND and
         decode_movw(word(m.frame_cmd_movw2),1)==COMMAND,
         "two original A32 0xBB9 frame queue command MOVWs differ")
    must(lit1==tuple(sorted(m.expected_other_0xbb9_moves+
                            (m.frame_cmd_movw1,m.frame_cmd_movw2))) and not lit2,
         "bounded original Sections1/2 A32 MOVW 0xBB9 screen differs")

    r=refs["depth"]
    must("PROBE_TARGET addr=%08x refs=1"%m.bitdepth_input_addr in r and
         "PROBE_REF from=%08x to=%08x type=WRITE"%
              (m.bitdepth_input_write,m.bitdepth_input_addr) in r,
         "bounded Ghidra initial bitdepth field xref baseline missing")
    must("PROBE_TARGET addr=%08x refs=1"%(m.cached_init_base+0xc) in r,
         "cached bitdepth direct Ghidra xref baseline missing")
    must("PROBE_TARGET addr=%08x refs=2"%m.stage35_vpu_wrapper in r and
         "type=COMPUTED_JUMP" in r,
         "dynamic API potential callers must remain explicitly counted")
    must("PROBE_TARGET addr=%08x refs=2"%m.rx_queue in r and
         "PROBE_TARGET addr=%08x refs=2"%m.rx2_queue in r,
         "inbound ring helper xrefs missing")

    return {
       "model":m.name,
       "work_base_from_VPU_init_packet":"W = *(packet+0x18)",
       "work_base_value":"UNKNOWN at runtime",
       "VPU_ring_setup_func":"FUN_%08x"%m.ring_setup_func,
       "VPU_work_memory_queue_region":"W+0x90000",
       "cleared_ring_region_bytes":RING_BYTES,
       "ring_page_bytes":RING_PAGE,
       "ring_header_bytes":RING_HEADER,
       "data_words_per_ring":RING_WORDS,
       "data_bytes_per_ring":RING_WORDS*4,
       "ring_page_count_cleared":7,
       "ring_sections":topology,
       "primary_tx_packet_location":"W+0x92010",
       "primary_rx_packet_location":"W+0x93010",
       "secondary_tx_packet_location":"W+0x94010",
       "secondary_rx_packet_location":"W+0x95010",
       "primary_CPU_tx_ring_writer":"FUN_%08x"%m.tx_queue,
       "primary_CPU_rx_ring_reader":"FUN_%08x"%m.rx_queue,
       "secondary_CPU_tx_ring_writer":"FUN_%08x"%m.tx2_queue,
       "secondary_CPU_rx_ring_reader":"FUN_%08x"%m.rx2_queue,
       "CPU_incoming_response_dispatch":"FUN_%08x"%m.irq_dispatch,
       "incoming_response_input_branch":"0x7d5",
       "frame_sender_0xBB9_payload_bytes":72,
       "queue_header_u32_encoding":"(payload_bytes<<16) | command_id",
       "queue_writer_index_halfword_offset":"+2",
       "queue_reader_index_halfword_offset":"+0",
       "bounded_Section1_movw_0xBB9_count":len(lit1),
       "bounded_Section2_movw_0xBB9_count":len(lit2),
       "7_original_ring_offset_ADD_STR_pairs_verified":True,
       "original_clear_0x7000_BL_verified":True,
       "original_4_RX_BLs_verified":True,
       "bitdepth_explicit_direct_xref_site_count_in_loaded_Ghidra":1,
       "bitdepth_indirect_alias_or_other_core_writers_excluded":False,
       "all_original_VPU_receiver_instructions_loaded_or_recovered":False,
       "0xBB9_paired_to_0x7D5":"UNPROVEN",
       **STAGE37_FLAGS
    }

def load_c(out,m):
    logs={
      "ring":(out/f"{m.name}_stage37_ring_init_reader_cand_decomp.log").read_text(),
      "irq":(out/f"{m.name}_stage37_ring_host_irq_dispatch.log").read_text(),
      "frame":(out/f"{m.name}_stage36_frame_packet_bitdepth_branch.log").read_text(),
      "assembler":(out/f"{m.name}_stage36_vpu_field_consumers_trace.log").read_text(),
      "tx":(out/f"{m.name}_stage36_vpu_event_init_and_packet_transport.log").read_text(),
    }
    return {
      "packet_builder":c_function(logs["assembler"],m.packet_builder),
      "work_init":c_function(logs["ring"],m.ring_setup_func),
      "primary_tx":c_function(logs["tx"],m.tx_queue),
      "primary_rx":c_function(logs["ring"] if m.name=="xs10" else logs["irq"],m.rx_queue),
      "secondary_tx":c_function(logs["tx"] if m.name=="xs10" else logs["ring"],m.tx2_queue),
      "secondary_rx":c_function(logs["ring"],m.rx2_queue),
      "irq":c_function(logs["irq"],m.irq_dispatch),
      "frame_send":c_function(logs["frame"],m.frame_sender),
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    out=p.parse_args().output
    prev=json.loads((out/"stage36_vpu_bitdepth_packet_audit.jsonlog").read_text().split(
        "\nSTAGE36 ORIGINAL READ-ONLY ARM:")[0])
    result=[]
    for m in MODELS.values():
        rom1=(out/f"x6-{m.name}/section-1.bin").read_bytes()
        rom2=(out/f"x6-{m.name}/section-2.bin").read_bytes()
        c=load_c(out,m)
        refs={"depth":(out/f"{m.name}_stage37_bitdepth_altwriter_and_rx_refs.log").read_text()}
        prior=next(x for x in prev if x["model"]==m.name)
        result.append(validate_ring_topology(
            m,lambda at:read_word(rom1,ROM1,at),c,refs,prior,
            scan_literal_movw(rom1,ROM1,COMMAND),
            scan_literal_movw(rom2,m.section2_base,COMMAND)
        ))
    # Hard equality of BOTH original 14-word work-region ARM sequences.
    a,b=MODELS["xs10"],MODELS["xt4"]
    buf1=(out/"x6-xs10/section-1.bin").read_bytes()
    buf2=(out/"x6-xt4/section-1.bin").read_bytes()
    for i in range(14):
        must(read_word(buf1,ROM1,a.ring_add_first+i*4)==
             read_word(buf2,ROM1,b.ring_add_first+i*4),
             "two original models differ in 7*ADD/STR work-memory ring layout")
    for r in result:
        r["cross_model_ring_map_ARM_14_words_byte_identical"]=True
    print(json.dumps(result,ensure_ascii=False,indent=2))
    print("STAGE37 OFFLINE ORIGINAL ARM: both models PASS; CPU software rings only.")
    print("NO hardware VPU queue consumer/codec pixel-depth profile confirmed.")
if __name__=="__main__":
    main()

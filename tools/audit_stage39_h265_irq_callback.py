#!/usr/bin/env python3
"""Stage39 offline ARM provenance: encoder channel=0, registered H.265 IRQ,
CPU event notification, VpuReceive task, and software response dispatch.

Original Fuji X6 images and private read-only Ghidra logs must remain on the
authorized user's computer under ignored output/. No USB/FF80/camera access,
no firmware edit, write, physical tests, flash image, or bitdepth claim.

Shows *registered CPU callback and its software path*, NOT that a VPU core
executed or accepted any request. The other processor's 0x0BB9 consumer,
specific silicon register meanings, Main10 SPS and 4K60 remain unknown.
"""
from dataclasses import dataclass
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

SECTION1_BASE = 0x01021000
EVENT_TOKEN = 0xDEF00001
CONTROL_BASE = 0xFFE00000
ISR_FLAG_OFFSET = 0x18
ISR_CLEAR_OFFSET = 0x21C
TX_NOTIFY_OFFSET = 0x220
RSP_INPUT = 0x7D5
RSP_OUTFRAME = 0x7D8

@dataclass(frozen=True)
class Model:
    model: str
    section1_len: int
    section1_sha256: str
    control_ptr_slot: int
    channel_ptr_slot: int
    channel_scalar_addr: int
    irq_setup_func: int
    irq_token_site: int
    handler_addr_pair_site: int
    irq_start_bl: int
    irq_start_api: int
    irq_register_bl: int
    irq_register_api: int
    isr: int
    event_handle_global: int
    event_handle_create_func: int
    event_create_bl: int
    event_create_api: int
    event_handle_store: int
    isr_event_bl: int
    isr_event_api: int
    rx_task_create: int
    rx_task: int
    rx_task_wait_bl: int
    rx_task_wait_api: int
    rx_dispatch_bl: int
    rx_dispatch: int
    rsp_input_reader: int
    rsp_output_bl: int
    frame_sender: int
    encoder_setup: int
    encoder_channel_store: int
    decoder_setup: int
    decoder_channel_store: int
    map_session: int
    encoder_map_bl: int
    decoder_map_bl: int
    setup_log: str
    isr_log: str
    runtime_log: str
    task_log: str
    response_log: str
    response_xref_log: str

MODELS = {
 "xs10": Model(
  "xs10",8012912,
  "c86c9446a15a39e6e761c4ca96383e943cdb3a09cab6e609b85b3e48f3e91aff",
  0x01b4a12c,0x01c09b68,0x01c8b7b0,
  0x011f8460,0x011f887c,0x011f888c,
  0x011f8888,0x011fe398,0x011f8898,0x011fe340,
  0x011f977c,
  0x01821950,0x011f7c8c,0x011f7ca4,0x011fe71c,0x011f7cb4,
  0x011f97b0,0x011fe73c,
  0x011f7c14,0x011f7d4c,0x011f7e40,0x011fe74c,
  0x011f7e6c,0x011fcbc4,0x011fa974,
  0x011fd894,0x011fac24,
  0x011f8914,0x011f893c,0x011f89f0,0x011f8a18,
  0x011fc820,0x011f8978,0x011f8a30,
  "xs10_stage39_h265_isr_registration_c.log",
  "xs10_stage39_isr_candidate_independent_ghidra.log",
  "xs10_stage39_mmio_status_router_c.log",
  "xs10_stage39_irq_event_create_and_signal.log",
  "xs10_stage39_vpu_interrupt_outer_dispatch_parent.log",
  "xs10_stage39_frame_response_loop_callrefs.log"
 ),
 "xt4": Model(
  "xt4", 7420408,
  "0b5b0fb0ee5fe6b109dae9964b5cddfe18edab46b4a0c195f9da194448906eeb",
  0x01ab212c,0x01b682a8,0x01beb868,
  0x011cbb0c,0x011cbf28,0x011cbf38,
  0x011cbf34,0x011d1a44,0x011cbf44,0x011d19ec,
  0x011cce28,
  0x01790d60,0x011cb338,0x011cb350,0x011d1dc8,0x011cb360,
  0x011cce5c,0x011d1de8,
  0x011cb2c0,0x011cb3f8,0x011cb4ec,0x011d1df8,
  0x011cb518,0x011d0270,0x011ce020,
  0x011d0f40,0x011ce2d0,
  0x011cbfc0,0x011cbfe8,0x011cc09c,0x011cc0c4,
  0x011cfecc,0x011cc024,0x011cc0dc,
  "xt4_stage39_h265_isr_registration_c.log",
  "xt4_stage39_isr_candidate_independent_ghidra.log",
  "xt4_stage39_mmio_status_router_c.log",
  "xt4_stage39_irq_event_create_and_signal.log",
  "xt4_stage39_vpu_interrupt_outer_dispatch_parent.log",
  "xt4_stage39_frame_response_loop_callrefs.log"
 )
}

def must(flag, reason):
    if not flag:raise ValueError("Stage39 CPU IRQ+VpuReceive provenance: "+reason)

def romword(data,addr):
    off=addr-SECTION1_BASE
    must(off>=0 and off%4==0 and off+4<=len(data),
         "outside/unaligned original Section1 ARM word")
    return struct.unpack_from("<I",data,off)[0]

def movhalf(word,reg,hi=False):
    required=0x03400000 if hi else 0x03000000
    must(word>>28==14 and word&0x0ff00000==required and
         (word>>12)&15==reg,"wrong A32 MOVW/MOVT condition, reg or variant")
    return ((word>>16)&0xf)<<12 | (word&0xfff)

def mov32(read,at,reg):
    return movhalf(read(at),reg) | (movhalf(read(at+4),reg,True)<<16)

def a32_bl(word,at):
    must(word>>28==14 and word&0x0f000000==0x0b000000,
         "not a full ARM unconditional BL")
    delta=word&0xffffff
    if delta&0x800000:delta-=0x1000000
    return (at+8+(delta<<2))&0xffffffff

def decomp_c(log,at):
    name="FUN_%08x"%at
    for block in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=block.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+)\s+"+
                     name+r"\(",c):
            return c
    raise ValueError("Ghidra C not found "+name)

def transient_isr_c(log,at):
    name="Stage38_probe_%08x"%at
    start="STAGE38_C_BEGIN %08x"%at
    must(("STAGE38_PROBE addr=%08x"%at) in log and
         ("STAGE38_DECOMP_COMPLETED %08x true"%at) in log and
         start in log,"transient readOnly Ghidra CPU handler not decompiled")
    c=log.split(start,1)[1].split("STAGE38_C_END",1)[0]
    must(name in c,"independent handler function ownership not demonstrated")
    return c

def scan_direct_callback_movw_movt(buf,base,callback):
    """Bounded unconditional aligned A32 MOVW/MOVT pair screen, NOT a CFG proof."""
    result=[]
    for i in range(0,len(buf)-7,4):
        w,v=struct.unpack_from("<II",buf,i)
        if w>>28==14 and w&0x0ff00000==0x03000000 and \
           v>>28==14 and v&0x0ff00000==0x03400000 and \
           (w>>12)&15==(v>>12)&15:
            x=((w>>16)&15)<<12|(w&0xfff)
            y=((v>>16)&15)<<12|(v&0xfff)
            if (x|(y<<16))==callback:result.append(base+i)
    return tuple(result)

def handler_check(m,read,logs):
    c=transient_isr_c(logs["isr"],m.isr)
    for text in (
      "*(uint *)(_DAT_%08x + 0x18) & 1"%m.control_ptr_slot,
      "*(undefined4 *)(_DAT_%08x + 0x21c) = 0;"%m.control_ptr_slot,
      "FUN_%08x(_DAT_%08x)"%(m.isr_event_api,m.event_handle_global),
      "h265Int_Handler_err"
    ):
        must(text in c,"transient ARM ISR has missing status/clear/event branch: "+text)

    must(mov32(read,m.isr,3)==m.control_ptr_slot,
         "ISR original MOVW/MOVT does not load initialized control base slot")
    for rel,inst in (
      (8,0xe5933000),(12,0xe5932018),(16,0xe3120001),
      (20,0x012fff1e),(24,0xe92d4830),(28,0xe28db00c),
      (32,0xe3a02000),(36,0xe583221c),(48,0xe5930000),
      (56,0xe2504000),(92,0xe8bd8830)
    ):
        must(read(m.isr+rel)==inst,
             "ISR original branch/ack/event instruction differs at "+hex(m.isr+rel))
    must(mov32(read,m.isr+40,3)==m.event_handle_global,
         "IRQ handler stores event using different handle than RX task")
    must(a32_bl(read(m.isr_event_bl),m.isr_event_bl)==m.isr_event_api and
         m.isr_event_bl==m.isr+52,
         "ISR event-service direct BL target wrong")
    return {"handler_code_entry":"0x%08x"%m.isr,
            "reads_status_bit0_at_control_base_plus":"0x18",
            "clears_control_base_plus_0x21c_to_zero":True,
            "conditional_bxeq_returns_without_signalling":True,
            "event_signal_static_slot":"0x%08x"%m.event_handle_global,
            "event_signal_original_BL_site":"0x%08x"%m.isr_event_bl,
            "event_signal_service":"FUN_%08x"%m.isr_event_api,
            "readOnly_ghidra_transient_function_confirmed":True}

def verify_irq(m,read,logs,prev37,prev38,screened_callback_sites=None):
    must(prev37["model"]==m.model and
         prev37["frame_sender_0xBB9_payload_bytes"]==72 and
         prev37["primary_tx_packet_location"]=="W+0x92010" and
         prev37["primary_rx_packet_location"]=="W+0x93010" and
         prev37["0xBB9_paired_to_0x7D5"]=="UNPROVEN" and
         prev37["0xBB9_direct_VPU_hardware_consumer_observed"]==False,
         "Stage37 TX/RX/unknown hardware-consumer baseline changed")
    must(prev38["model"]==m.model and
         prev38["registered_control_range_base"]=="0xffe00000" and
         prev38["notification_register_value"]==1 and
         prev38["channel_scalar_runtime_value"]=="UNKNOWN" and
         prev38["hardware_register_is_a_VPU_doorbell_definition"]=="UNKNOWN" and
         prev38["HEVC_10bit_Main10_or_4K60_proven"]==False,
         "Stage38 static MMIO / open hardware semantic boundary changed")
    if screened_callback_sites is not None:
        must(screened_callback_sites==(m.handler_addr_pair_site,),
             "bounded four-section original ARM callback pair screen unexpected")

    init_c=decomp_c(logs["setup"],m.irq_setup_func)
    id_literal="0xdef00001"
    api="FUN_%08x"%m.irq_register_api
    expected="%s(%s,&LAB_%08x)"%(api,id_literal,m.isr)
    must(expected in init_c,
         "Ghidra setup no direct registration of this exact callback to event ID")
    must("FUN_%08x(0xdef00001)"%m.irq_start_api in init_c and
         "call_mali_start_interrupt" in init_c,
         "same interrupt ID is not initialized by VPU driver")
    must(read(m.irq_token_site)==0xe3a04001 and
         read(m.irq_token_site+4)==0xe34d4ef0 and
         read(m.irq_token_site+8)==0xe1a00004,
         "original A32 M4/MOVT event token 0xDEF00001 missing")
    must(a32_bl(read(m.irq_start_bl),m.irq_start_bl)==m.irq_start_api,
         "start-interrupt original BL target not proven")
    must(mov32(read,m.handler_addr_pair_site,1)==m.isr and
         read(m.handler_addr_pair_site+8)==0xe1a00004,
         "original MOVW/MOVT R1 handler callback pointer differs")
    must(a32_bl(read(m.irq_register_bl),m.irq_register_bl)==m.irq_register_api,
         "register-handler original BL target not proven")

    isr=handler_check(m,read,logs)

    create=decomp_c(logs["task"],m.event_handle_create_func)
    must("FUN_%08x(0,1,1,0x14)"%m.event_create_api in create and
         "_DAT_%08x = iVar1;"%m.event_handle_global in create and
         "if (iVar1 < 1)" in create,
         "event handle creation/positive result storage not grounded")
    must(a32_bl(read(m.event_create_bl),m.event_create_bl)==m.event_create_api and
         read(m.event_handle_store)==0xc5830000,
         "CPU receive handle create BL / conditional store mismatch")
    task_create=decomp_c(logs["task"],m.rx_task_create)
    must(("local_20 = FUN_%08x;"%m.rx_task) in task_create and
         "VpuReceive" in task_create,
         "registered CPU RX worker task missing or mismatched")
    task=decomp_c(logs["task_loop"],m.rx_task)
    must(("FUN_%08x(_DAT_%08x,0xffffffff)"%
          (m.rx_task_wait_api,m.event_handle_global)) in task and
         ("FUN_%08x();"%m.rx_dispatch) in task and
         "VpuReceive_task" in task,
         "VpuReceive CPU task no event wait followed by response dispatch")
    must(a32_bl(read(m.rx_task_wait_bl),m.rx_task_wait_bl)==m.rx_task_wait_api,
         "VpuReceive wait-loop ARM BL not verified")
    must(a32_bl(read(m.rx_dispatch_bl),m.rx_dispatch_bl)==m.rx_dispatch,
         "VpuReceive -> CPU response dispatch ARM BL not verified")

    disp=decomp_c(logs["response"],m.rx_dispatch)
    must("if (uVar4 == 0x7d5)" in disp and
         ("FUN_%08x("%m.rsp_input_reader) in disp and
         "if (uVar4 == 0x7d8)" in disp and
         ("FUN_%08x();"%m.frame_sender) in disp and
         "[0xc] == 1" in disp,
         "CPU dispatcher input 0x7D5 / outframe 0x7D8 branches not proven")
    must(a32_bl(read(m.rsp_output_bl),m.rsp_output_bl)==m.frame_sender,
         "0x7d8 branch's original ARM BL to next frame-send mismatch")
    refs=logs["response_xrefs"]
    must(("PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL"%
         (m.rsp_output_bl,m.frame_sender)) in refs,
         "read-only Ghidra xref to next frame-send missing")
    enc=decomp_c(logs["runtime"],m.encoder_setup)
    dec=decomp_c(logs["task_loop"],m.decoder_setup)
    sel="_DAT_%08x"%m.channel_ptr_slot
    for text in (enc,dec):
        must("*%s = 0;"%sel in text and
             "FUN_%08x();"%m.map_session in text,
             "no proven zero-channel assignment before MapSession")
    for store,fn,mapsite in (
      (m.encoder_channel_store,m.encoder_setup,m.encoder_map_bl),
      (m.decoder_channel_store,m.decoder_setup,m.decoder_map_bl)):
        must(mov32(read,store-16,3)==m.channel_ptr_slot and
             read(store-8)==0xe5932000 and
             read(store-4)==0xe3a01000 and
             read(store)==0xe5821000,
             "original ARM zero-store to runtime channel scalar mismatch")
        must(a32_bl(read(mapsite),mapsite)==m.map_session and
             fn<=store<mapsite,
             "original ARM zero-set precedes MapSession BL incorrectly")
    return {
      "model":m.model,
      "interrupt_registration_id":"0x%08x"%EVENT_TOKEN,
      "interrupt_registration_callback_pair_original":"0x%08x"%m.handler_addr_pair_site,
      "interrupt_registration_original_BL":"0x%08x"%m.irq_register_bl,
      "cpu_isr":isr,
      "event_handle_created_in_CPU_code":"0x%08x"%m.event_handle_global,
      "cpu_rx_task":"FUN_%08x"%m.rx_task,
      "cpu_rx_task_wait_event_BL":"0x%08x"%m.rx_task_wait_bl,
      "cpu_rx_task_dispatch_BL":"0x%08x"%m.rx_dispatch_bl,
      "software_rsp_0x7D5_uses_rx_queue_reader":"FUN_%08x"%m.rsp_input_reader,
      "software_rsp_0x7D8_may_submit_next_0xBB9_frame":{
        "when":"software response 0x7D8 and CPU-side state slot[0xC] == 1",
        "frame_send_routine":"FUN_%08x"%m.frame_sender,
        "original_BL_site":"0x%08x"%m.rsp_output_bl,
        "request_response_pair_0xBB9_to_0x7D8_proven":False,
      },
      "encoding_setup_channel_zero_ARM_store":"0x%08x"%m.encoder_channel_store,
      "decoding_setup_channel_zero_ARM_store":"0x%08x"%m.decoder_channel_store,
      "encoder_setup_notification_target_if_unchanged":"0xFFE00220",
      "hardware_side_0xBB9_receiver_known":False,
      "chip_IRQ_ID_official_definition_known":False,
      "physical_VPU_interruption_or_Main10_bitdepth_verified":False,
      "internal_XS10_10bit_or_4K60_enabled":False,
      "camera_contacted_or_firmware_modified":False,
    }

def load_log_data(m,out):
    return {
      "setup":(out/m.setup_log).read_text(),
      "isr":(out/m.isr_log).read_text(),
      "runtime":(out/m.runtime_log).read_text(),
      "task":(out/m.task_log).read_text(),
      "task_loop":(out/m.task_log).read_text()+
                  (out/m.task_log.replace("_irq_event_create_and_signal",
                       "_vpu_interrupt_outer_dispatch_parent")).read_text(),
      "response":(out/m.runtime_log).read_text(),
      "response_xrefs":(out/m.response_xref_log).read_text(),
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    out=ap.parse_args().output
    stage37=json.loads((out/"stage37_vpu_ring_memory_audit.jsonlog").read_text().split(
        "\nSTAGE37 OFFLINE ORIGINAL ARM:")[0])
    stage38=json.loads((out/"stage38_vpu_mmio_notify_audit.jsonlog").read_text().split(
        "\nSTAGE38 VPU TRANSPORT")[0])
    results=[]
    for m in MODELS.values():
        b=(out/f"x6-{m.model}/section-1.bin").read_bytes()
        must(len(b)==m.section1_len and
             hashlib.sha256(b).hexdigest()==m.section1_sha256,
             "unmodified original Section1 image size/SHA256 changed")
        candidates=[]
        for sec in (1,2,3,4):
            data=(out/f"x6-{m.model}/section-{sec}.bin").read_bytes()
            base=SECTION1_BASE if sec==1 else 0
            located=scan_direct_callback_movw_movt(data,base,m.isr)
            if sec==1:
                candidates.extend(located)
            else:
                must(not located,
                     "secondary X6 section contains unexpected A32 direct callback pair")
        old37=next(x for x in stage37 if x["model"]==m.model)
        old38=next(x for x in stage38 if x["model"]==m.model)
        result=verify_irq(m,lambda site:romword(b,site),
                          load_log_data(m,out),old37,old38,tuple(candidates))
        result["bounded_direct_callback_pointer_movw_movt_pairs_by_section"]= [1,0,0,0]
        result["section1_sha256"]=m.section1_sha256
        results.append(result)
    a,b=results
    must(a["interrupt_registration_id"]==b["interrupt_registration_id"] and
         a["encoder_setup_notification_target_if_unchanged"]==
         b["encoder_setup_notification_target_if_unchanged"],
         "X-S10/X-T4 IRQ registration or conditional channel values diverged")
    print(json.dumps(results,indent=2,ensure_ascii=False))
    print("STAGE39 ORIGINAL X6 IRQ CALLBACK/CPU EVENT/TASK ROUNDTRIP: TWO MODELS PASS.")
    print("Other-core command consumer / Main10 or 4K60 still UNPROVEN; no device access.")
if __name__=="__main__":
    main()

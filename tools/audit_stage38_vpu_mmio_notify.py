#!/usr/bin/env python3
"""Stage38 supplemental audit: queue producer -> register-range write candidate.

Strictly OFFLINE/read-only study of original X-S10 3.11, X-T4 2.12 X6
section1 A32 and existing private Ghidra read-only traces. No camera,
USB, FF80, firmware/DAT modifications, live HW access, or Main10 claims.

CPU Tx queue producer stores word 1 to
*(static_control_base + *(runtime_channel_slot)*0x40 + 0x220).
Original initializer stores base 0xFFE00000 and a model-dependent POINTER
to the selector scalar. Register looks like a notification/doorbell, but the
actual hardware consumer, semantics, runtime selector, and acceptance of
any HEVC profile remain UNKNOWN. Logger call after is text/hex logging.
"""
from dataclasses import dataclass
import argparse
import json
from pathlib import Path
import re
import struct

ROM_BASE = 0x01021000
CONTROL_BASE = 0xffe00000
REGISTER_ADDEND = 0x220
CHANNEL_STRIDE = 0x40
EFFECTIVE_CONST_REG_WORDS = (
    0xe5933000,  # LDR R3,[R3] - global control base
    0xe5922000,  # LDR R2,[R2] - ptr to channel scalar
    0xe5922000,  # LDR R2,[R2] - channel scalar
    0xe0833302,  # ADD R3,R3,R2,LSL #6
    0xe3a01001,  # MOV R1,#1
    0xe5831220,  # STR R1,[R3,#0x220]
)
INIT_CONST_WORDS = (0xe3a02000,0xe34f2fe0,0xe5832000)
HANDSHAKES = {
  "xs10": {
    "map_fn":0x011fc820,"unmap_fn":0x011fc958,
    "map_write":0x011fc85c,"map_write_218":0x011fc868,
    "unmap_read":0x011fc980,"unmap_clear_214":0x011fc9d4,
    "trace":"xs10_stage38_mmio_status_handshake_trace.log",
  },
  "xt4": {
    "map_fn":0x011cfecc,"unmap_fn":0x011d0004,
    "map_write":0x011cff08,"map_write_218":0x011cff14,
    "unmap_read":0x011d002c,"unmap_clear_214":0x011d0080,
    "trace":"xt4_stage38_mmio_status_handshake_trace.log",
  },
}


@dataclass(frozen=True)
class Model:
    name:str
    control_base_slot:int
    selector_ptr_slot:int
    selector_scalar_location:int
    control_initializer:int
    selector_initializer:int
    control_initializer_again:int
    control_init_fn:int
    second_init_fn:int
    TX_primary:int
    TX_secondary:int
    notify_primary:int
    notify_secondary:int
    dbg_string_logger:int
    dbg_hex_logger:int
    frame_sender:int
    shared_packet_ptr_slot:int
    ghidra_log:str
    init_extra_log:str
    dbg_log:str
    xref_log:str

MODELS={
 "xs10":Model(
    "xs10",0x01b4a12c,0x01c09b68,0x01c8b7b0,
    0x011fc504,0x011fc4f0,0x011f95e0,
    0x011fc4e8,0x011f95d4,
    0x011fa714,0x011fa844,
    0x011fa758,0x011fa888,
    0x011fda28,0x011fdaec,
    0x011fac24,0x01c8573c,
    "xs10_stage38_signal_mmio_complete_provenance.log",
    "xs10_stage38_queue_notify_slot_writer_trace.log",
    "xs10_stage38_vpu_queue_doorbell_cache_sink.log",
    "xs10_stage38_selector_and_controlbase_all_writes.log"
 ),
 "xt4":Model(
    "xt4",0x01ab212c,0x01b682a8,0x01beb868,
    0x011cfbb0,0x011cfb9c,0x011ccc8c,
    0x011cfb94,0x011ccc80,
    0x011cddc0,0x011cdef0,
    0x011cde04,0x011cdf34,
    0x011d10d4,0x011d1198,
    0x011ce2d0,0x01be5808,
    "xt4_stage38_signal_mmio_complete_provenance.log",
    "xt4_stage38_queue_notify_slot_writer_trace.log",
    "xt4_stage38_vpu_queue_doorbell_cache_sink.log",
    "xt4_stage38_selector_and_controlbase_all_writes.log"
 ),
}

def must(ok,reason):
    if not ok: raise ValueError("Stage38 VPU TX control write audit: "+reason)

def romword(buf,at):
    off=at-ROM_BASE
    must(off>=0 and off%4==0 and off+4<=len(buf),
         "original section1 ARM word out of range/unaligned")
    return struct.unpack_from("<I",buf,off)[0]

def movpart(inst,dst_reg,upper=False):
    desired=0x03400000 if upper else 0x03000000
    must(inst>>28==14 and (inst&0x0ff00000)==desired and
         ((inst>>12)&15)==dst_reg,
         "A32 original MOVW/MOVT register/variant changed")
    return (((inst>>16)&15)<<12)|(inst&0xfff)

def mov32(rom,site,reg):
    return movpart(rom(site),reg)|(movpart(rom(site+4),reg,True)<<16)

def extract_c(text,func):
    name="FUN_%08x"%func
    for b in text.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=b.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:int|uint|void|undefined\d+)\s+"+name+r"\(",c):
            return c
    raise ValueError("Ghidra C function missing "+name)

def validate_original(m,word,logs,previous):
    must(previous["model"]==m.name and
         previous["frame_sender_0xBB9_payload_bytes"]==72 and
         previous["primary_tx_packet_location"]=="W+0x92010" and
         previous["secondary_tx_packet_location"]=="W+0x94010" and
         previous["0xBB9_direct_VPU_hardware_consumer_observed"]==False,
         "stage37 original TX frame-send evidence invalid")
    must(mov32(word,m.selector_initializer,3)==m.selector_ptr_slot and
         mov32(word,m.selector_initializer+8,2)==m.selector_scalar_location and
         word(m.selector_initializer+16)==0xe5832000,
         "selector slot initialization original MOVW/MOVT/STR mismatch")
    init=extract_c(logs["init"],m.control_init_fn)
    p="_DAT_%08x"%m.control_base_slot
    q="_DAT_%08x"%m.selector_ptr_slot
    must(("%s = 0x%x;"%(q,m.selector_scalar_location)) in init and
         ("%s = 0xffe00000;"%p) in init,
         "Ghidra control base and selector pointer initial assignments absent")
    old=extract_c(logs["alt"],m.second_init_fn)
    must(("%s = 0xffe00000;"%p) in old,
         "secondary initializer of shared control MMIO base missing")
    for init_site in (m.control_initializer,m.control_initializer_again):
        must(mov32(word,init_site,3)==m.control_base_slot,
             "control global pointer address wrong in original A32")
        for idx,expected in enumerate(INIT_CONST_WORDS):
            must(word(init_site+8+4*idx)==expected,
                 "control base init constant 0xFFE00000 A32 mismatch")
    x=logs["xrefs"]
    for addr,count,writes in (
      (m.control_base_slot,62,2),
      (m.selector_ptr_slot,64,1),
      (m.shared_packet_ptr_slot,55,1)
    ):
        must(("STAGE38_XREF_SUMMARY addr=%08x n=%d WRITEs=%d"%
            (addr,count,writes)) in x,
            "Ghidra complete write-xrefs/xref counts differ")
    for site,slot in (
      (m.selector_initializer+16,m.selector_ptr_slot),
      (m.control_initializer+16,m.control_base_slot),
      (m.control_initializer_again+16,m.control_base_slot)
    ):
        must(("STAGE38_WRITE to=%08x from=%08x"%(slot,site)) in x,
             "Ghidra original control/selector global direct-writer absent")
    matches=[]
    for fn,site in ((m.TX_primary,m.notify_primary),
                    (m.TX_secondary,m.notify_secondary)):
        block=extract_c(logs["send"],fn)
        ptr_txt="*(undefined4 *)(%s + *%s * 0x40 + 0x220) = 1;"%(p,q)
        must(ptr_txt in block,
             "CPU TX sender does not write through same computed control address")
        must(("*(short *)(_DAT_" in block) and
             "param_2 | param_3 << 0x10" in block and
             ("FUN_%08x"%m.dbg_string_logger in block) and
             ("FUN_%08x"%m.dbg_hex_logger in block),
             "queue header + index update + logging provenance missing")
        # This is exact original ARM sequence, not merely string label:
        # two global slot pointer pairs, LDRs, channel value, ADD shift,
        # store 1 to calculated control register [R3,#0x220].
        must(mov32(word,site,3)==m.control_base_slot and
             mov32(word,site+12,2)==m.selector_ptr_slot,
             "ARM TX notify slots do not match initialized globals")
        for j,expected in enumerate(EFFECTIVE_CONST_REG_WORDS):
            rawsite=(site+8 if j==0 else site+20+(j-1)*4)
            must(word(rawsite)==expected,
                 "original ARM R3+R2<<6 notify store wrong at "+
                     hex(rawsite))
        matches.append({
          "sender":"FUN_%08x"%fn,
          "slot_global":"0x%08x"%m.control_base_slot,
          "selector_global":"0x%08x"%m.selector_ptr_slot,
          "arm_control_store_site":"0x%08x"%(site+36),
          "code_write_constant":1,
          "calculated_address_after_known_initializers":
             "0xFFE00220 + selected_channel*0x40",
        })
    session=HANDSHAKES[m.name]
    map_body=extract_c(logs["handshake"],session["map_fn"])
    unmap_body=extract_c(logs["handshake"],session["unmap_fn"])
    for snippet in (
      "h265_MapSession_start",
      " + 0x20c) = 1;",
      " + 0x218) = 1;",
      " + 0x230) = 0x33;",
      " + 0x220) = 0;",
      " + 0x214) = 1;",
      "iVar3 = 24000;",
      " + 0x218) == 0)",
    ):
        must(snippet in map_body,
             "read-only Ghidra H.265 MapSession register/status flow differs: "+snippet)
    for snippet in (
      " + 0x20c) == 0)",
      " + 0x214) = 0;",
      " + 0x218) = 1;",
      " + 0x20c) = 0;",
      "iVar3 = 0x4b0;",
    ):
        must(snippet in unmap_body,
             "read-only Ghidra unmap/handshake flow differs: "+snippet)
    map_arm=(
      (session["map_write"]-8,0xe0813303),
      (session["map_write"]-4,0xe3a02001),
      (session["map_write"],0xe583220c),
      (session["map_write_218"],0xe5832218),
      (session["unmap_read"],0xe593320c),
      (session["unmap_read"]+4,0xe3530000),
      (session["unmap_clear_214"],0xe582c214),
    )
    for at,inst in map_arm:
        must(word(at)==inst,
             "original A32 MMIO 0x20c / 0x218 / 0x214 ARM word changed at "+hex(at))
    logger1=extract_c(logs["debug"],m.dbg_string_logger)
    logger2=extract_c(logs["debug"],m.dbg_hex_logger)
    must("char *pcVar1;" in logger1 and "*pcVar1" in logger1 and
         "0x5b" in logger2 and "uVar1 = 0x1c;" in logger2 and
         "uVar1 = uVar1 - 4;" in logger2,
         "post-send logger functions are not proven to format text and hexadecimal")
    # Guard against mistakenly declaring logger a device driver callback:
    must("0x220" not in logger1 and "0x220" not in logger2,
         "unexpected control register effect in purported debug-only functions")
    return {
      "model":m.name,
      "registered_control_range_base":"0x%08x"%CONTROL_BASE,
      "control_range_base_static_global":"0x%08x"%m.control_base_slot,
      "registered_selector_scalar_pointer_location":"0x%08x"%m.selector_scalar_location,
      "selector_pointer_static_global":"0x%08x"%m.selector_ptr_slot,
      "channel_scalar_runtime_value":"UNKNOWN",
      "notification_register_address_formula":
        "0xFFE00000 + (*(u32 *)selector_scalar_pointer) * 0x40 + 0x220",
      "notification_register_value":1,
      "sender_original_ARM_verified":matches,
      "MapSession_static_software_handshake":{
         "function":"FUN_%08x"%session["map_fn"],
         "writes_control_0x20c":1,
         "writes_control_0x218":1,
         "writes_control_0x230":0x33,
         "polls_0x218_equal_zero":True,
         "literal_wait_count":24000,
      },
      "unmap_or_ack_static_software_handshake":{
         "function":"FUN_%08x"%session["unmap_fn"],
         "checks_control_0x20c_nonzero":True,
         "sets_control_0x214_zero":True,
         "sets_control_0x218_one":True,
         "clears_control_0x20c":True,
      },
      "A32_readonly_MMIO_map_unmap_words_checked":len(map_arm),
      "producer_TX_debug_string_and_hex_formatters_separate_from_control_write":True,
      "original_control_and_selector_init_A32_blocks_checked":3,
      "cross_camera_MMIO_base_and_register_offset_same":True,
      "hardware_register_is_a_VPU_doorbell_definition":"UNKNOWN",
      "silicon_or_coprocessor_receipt_observed":False,
      "HEVC_10bit_Main10_or_4K60_proven":False,
      "firmware_modified_or_camera_contacted":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    out=p.parse_args().output
    stage37=json.loads((out/"stage37_vpu_ring_memory_audit.jsonlog").read_text().split(
      "\nSTAGE37 OFFLINE ORIGINAL ARM:")[0])
    models=[]
    for m in MODELS.values():
        data=(out/f"x6-{m.name}/section-1.bin").read_bytes()
        logs={
           "init":(out/m.ghidra_log).read_text(),
           "alt":(out/m.init_extra_log).read_text(),
           "send":(out/m.ghidra_log).read_text(),
           "debug":(out/m.dbg_log).read_text(),
           "xrefs":(out/m.xref_log).read_text(),
           "handshake":(out/HANDSHAKES[m.name]["trace"]).read_text(),
        }
        prior=next(x for x in stage37 if x["model"]==m.name)
        models.append(validate_original(
          m,lambda at:romword(data,at),logs,prior))
    xs,xt=models
    must(xs["notification_register_address_formula"]==
          xt["notification_register_address_formula"] and
          all(x["code_write_constant"]==1 for m in models
              for x in m["sender_original_ARM_verified"]),
          "cross model fixed control write not equivalent")
    print(json.dumps(models,ensure_ascii=False,indent=2))
    print("STAGE38 VPU TRANSPORT MMIO original-only: X-S10 and X-T4 PASS.")
    print("STATIC register write confirmed, hardware VPU doorbell semantics UNKNOWN.")
if __name__=="__main__":
    main()

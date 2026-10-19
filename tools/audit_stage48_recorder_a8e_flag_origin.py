#!/usr/bin/env python3
"""Stage48: trace Movie 4K mode-low-key override flag back to Recorder state.

Read only original SHA-identified X-S10 3.11 and X-T4 2.12 X6 Sections1/2,
pre-existing read-only Ghidra logs, and prior Stage46/47 offline audits.
Proves: parent pointer registration / object-pool stride, movie type -> 4K
predicate -> source getter of active Recorder config byte -> parent+A8E
store -> Stage47 conditional low-key override; independent reverse export
of same active byte as snapshot+0x581 (companion +0x580, codec +0x5B0).
Does NOT prove who writes current Recorder +0x581, its runtime value,
camera 4K59.94 HEVC availability, Main10, or hardware V61 support.
No live camera, USB, FF80, hardware RAM/Flash, firmware patch or flashing.
"""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage45_movie_encoder_fps_chain as st45
import audit_stage46_joint_movie_mode_matrix as st46
import audit_stage47_mode_key_codec_ingress as st47

@dataclass(frozen=True)
class Model:
    name:str
    reset_fn:int
    parent_ptr:int
    init_fn:int
    registration_fn:int
    stride:int
    pool_head:int
    movie_type_fn:int
    movie_type_ram:int
    classifier_fn:int
    flag_getter_fn:int
    companion_getter_fn:int
    active_flag_ram:int
    active_companion_ram:int
    active_codec_ram:int
    snapshot_exporter_fn:int
    reset_log:str
    init_log:str
    getter_log:str
    export_log:str
    pointer_log:str
    active_refs_log:str
    register_bl:int
    movie_bl:int
    classifier_bl:int
    flag_bl:int
    companion_bl:int
    flag_getter_ldrb:int
    companion_getter_ldrb:int

MODELS={
"xs10":Model("xs10",
  0x022d3cdc,0x02eda0b4,0x022d3e00,0x022d2008,0x3c318,0x02eda0b8,
  0x022d1654,0x02da3119,0x022d1674,
  0x012bd7d0,0x012bd7f0,0x01c251d4,0x01c251d5,0x01c25208,
  0x012be684,
  "xs10_stage48_parent_pointer_initializer_funcs.log",
  "xs10_stage48_parent_pointer_initializer_funcs.log",
  "xs10_stage48_4k_mode_override_value_getters.log",
  "xs10_stage25_snapshot_populate_pipeline.log",
  "xs10_stage48_parent_pointer_full_xrefs.log",
  "xs10_stage48_active_recorder_flag_xrefs.log",
  0x022d3e94,0x022d3ec4,0x022d3ed4,0x022d4020,0x022d3f34,
  0x012bd7e0,0x012bd800),
"xt4":Model("xt4",
  0x022402bc,0x02e57934,0x022403c8,0x0223e5d4,0x4b0a0,0x02e57938,
  0x0223dbe4,0x02d16751,0x0223dc04,
  0x01295e44,0x01295e64,0x01b83940,0x01b83941,0x01b83974,
  0x01296d38,
  "xt4_stage48_parent_pointer_initializer_funcs.log",
  "xt4_stage48_parent_pointer_initializer_funcs.log",
  "xt4_stage48_4k_mode_override_value_getters.log",
  "xt4_stage25_snapshot_populate_pipeline.log",
  "xt4_stage48_parent_pointer_full_xrefs.log",
  "xt4_stage48_active_recorder_flag_xrefs.log",
  0x0224045c,0x0224048c,0x0224049c,0x022405e8,0x022404fc,
  0x01295e54,0x01295e74)
}
EXPECTED_GETTER_LDRB={
 "xs10":(0xe5d303fc,0xe5d303fd),
 "xt4":(0xe5d30400,0xe5d30401)
}

def need(ok,why):
    if not ok:raise ValueError("Stage48 Recorder A8E provenance: "+why)

def decomp(log,fn):
    pat=r"(?m)^\s*(?:void|bool|int|uint|undefined\d+|byte|char)\s+FUN_%08x\("%fn
    for block in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        text=block.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(pat,text):return text
    raise ValueError("read-only original Ghidra function absent "+hex(fn))

def flag_from_source(movie_type,active_recorder_flag):
    """Static per-record initialization rule, NOT runtime mode selection."""
    need(isinstance(movie_type,int) and 0<=movie_type<=255 and
         isinstance(active_recorder_flag,int) and 0<=active_recorder_flag<=255,
         "malformed mock source")
    return active_recorder_flag if movie_type in (4,5,6,7) else 0

def compute_movie_key(movie_type,active_recorder_flag,low,high):
    """Stage47 key override applied after Stage48 source initialization."""
    state=flag_from_source(movie_type,active_recorder_flag)
    return st47.compute_key(movie_type in (4,5,6,7),state,low,high)

def active_snapshot_offsets(m):
    need(m.active_companion_ram==m.active_flag_ram+1 and
         m.active_codec_ram-m.active_flag_ram==0x34,
         "active Recorder config flag vs codec layout changed")
    return {
     "active_4k_flag_ram":hex(m.active_flag_ram),
     "active_second_flag_ram":hex(m.active_companion_ram),
     "active_codec_ram":hex(m.active_codec_ram),
     "snap_export_source_flag_offset":"0x581",
     "snap_export_source_second_flag_offset":"0x580",
     "snap_export_source_codec_offset":"0x5b0",
     "codec_address_minus_4k_flag_address_hex":"0x34",
    }

def check_model(m,sec1,sec2,logs,previous):
    need(sha256(sec1).hexdigest()==st45.ROM1_SHA[m.name] and
         sha256(sec2).hexdigest()==st45.MODELS[m.name].sha2,
         "unmodified original Section1/2 SHA256 mismatch")
    need(previous["stage46"]["both_original_ROM_96_by_64_records_byte_identical"] is True and
         previous["stage47"]["model_specific_4K60_restriction_proven"] is False,
         "Phase46/47 status or permissions changed")
    # Original full 32-bit A32 instructions and real relative BL targets.
    a32=lambda a:st47.read_arm_word(sec1,sec2,st47.MODELS[m.name],a)
    for site,target in (
       (m.register_bl,m.registration_fn),
       (m.movie_bl,m.movie_type_fn),
       (m.classifier_bl,m.classifier_fn),
       (m.flag_bl,m.flag_getter_fn),
       (m.companion_bl,m.companion_getter_fn),
    ):
        need(st45.a32_bl_target(a32(site),site)==target,
             "original ARM initializer BL target mismatch at "+hex(site))
    expected=EXPECTED_GETTER_LDRB[m.name]
    need(a32(m.flag_getter_ldrb)==expected[0] and
         a32(m.companion_getter_ldrb)==expected[1],
         "original two Recorder state LDRB opcodes mismatch")
    need(m.pool_head+0xa8c==(0x02edab44 if m.name=="xs10" else 0x02e583c4)
         and m.pool_head+0xa8e==(0x02edab46 if m.name=="xs10" else 0x02e583c6)
         and m.pool_head+0xa8f==(0x02edab47 if m.name=="xs10" else 0x02e583c7),
         "dynamic parent slot field positions differ")
    old=next(x for x in previous["stage47"][
             "two_original_ROMs_original_ARM_and_readonly_Ghidra"]
             if x["model"]==m.name)
    need(old["runtime_flag_offset"].lower()=="0xa8e" and
         old["4K_type_and_flag1_forces_low_mode_key_6"] is True and
         old["codec_source_getter"]=="FUN_%08x"%st47.MODELS[m.name].getter_fn,
         "Stage47 conditional mode6/codec provenance changed")
    reset=decomp(logs["reset"],m.reset_fn)
    init=decomp(logs["init"],m.init_fn)
    getter=decomp(logs["getters"],m.flag_getter_fn)
    getter2=decomp(logs["getters"],m.companion_getter_fn)
    movie=decomp(logs["getters"],m.movie_type_fn)
    classify=decomp(logs["getters"],m.classifier_fn)
    exported=decomp(logs["export"],m.snapshot_exporter_fn)
    pointer="_DAT_%08x"%m.parent_ptr
    # The original X-S10 reset uses a literal -1 store. X-T4 uses a
    # generic indexed store of caller-supplied param_3, whose real value
    # has NOT been resolved. Do not invent a -1 value for that caller.
    reset_valid = (
        ("%s = 0xffffffff;"%pointer) in reset if m.name=="xs10"
        else ("param_4[1] = param_3;" in reset and
              "ST48_PTR_REF at=022402c0 " in logs["pointer"])
    )
    need(reset_valid and
         ("FUN_%08x(&DAT_%08x,&DAT_%08x,"%
          (m.registration_fn,m.parent_ptr-4,m.parent_ptr)) in init,
         "parent pointer reset/update or registration is absent")
    mtype="DAT_%08x"%m.movie_type_ram
    need(("return %s;"%mtype) in movie and
         all(z in classify for z in ("case 4:","case 5:","case 6:","case 7:")) and
         ("return 1;" in classify),
         "parent frame/movie class is not the original 4K 4..7 classifier")
    need(("return DAT_%08x;"%m.active_flag_ram) in getter and
         ("return DAT_%08x;"%m.active_companion_ram) in getter2,
         "4K flag getters do not return saved Recorder active config bytes")
    # The compiler writes via a dynamic slot (idx*stride + pool absolute)
    # rather than by an immediate STRB [register,#0xa8e] in original A32.
    init_c=' '.join(init.split())
    first=("*(undefined1 *)(local_30 * 0x%x + 0x%x) = uVar1;"%
           (m.stride,m.pool_head+0xa8e))
    second=("*(undefined1 *)(iVar2 + 0x%x) = uVar1;"%(m.pool_head+0xa8f))
    src0=("uVar1 = FUN_%08x();"%m.flag_getter_fn)
    src1=("uVar1 = FUN_%08x();"%m.companion_getter_fn)
    class_line=("iVar2 = FUN_%08x(*(undefined1 *)(%s + 0xa8c));"%
                (m.classifier_fn,pointer))
    need(all(z in init_c for z in (first,second,src0,src1,class_line,
                                   "if (iVar2 == 0) { uVar1 = 0; }")),
         "dynamic allocated parent A8E/A8F from classified Recorder globals missing")
    ix_class=init_c.index(class_line)
    ix_src=init_c.index(src0,ix_class)
    ix_store=init_c.index(first,ix_src)
    need(ix_class<ix_src<ix_store,
         "4K classification -> active flag getter -> parent slot store order differs")
    need(("*(undefined1 *)(iVar2 + 0x%x) = uVar1;"%(m.pool_head+0xa8c)) in init_c
         and ("FUN_%08x();"%m.movie_type_fn) in init_c,
         "runtime parent+A8C class is not written by Recorder movie type source")
    need(("param_1[0x581] = DAT_%08x;"%m.active_flag_ram) in exported and
         ("param_1[0x580] = DAT_%08x;"%m.active_companion_ram) in exported and
         ("param_1[0x5b0] = DAT_%08x;"%m.active_codec_ram) in exported,
         "independently confirmed Recorder snapshot export bytes 0x581/580/5b0 absent")
    # Literal RAM direct xref inventory is bounded: it does NOT exclude
    # whole-structure copies, indirect writers, DMA or pointer aliases.
    for addr,readsite in ((m.active_flag_ram,m.flag_getter_ldrb),
                          (m.active_companion_ram,m.companion_getter_ldrb)):
        x=logs["xref"]
        need(("PROBE_TARGET addr=%08x refs=2"%addr) in x and
             ("PROBE_REF from=%08x to=%08x type=READ"%(readsite,addr)) in x,
             "direct active Recorder source field read xref absent")
    need(("ST48_PTR_SUMMARY addr=%08x total=116 read=113 write=1 other=2"%
          m.parent_ptr) in logs["pointer"],
          "complete original parent pointer Ghidra xref inventory changed")
    return {
      "model":m.name,
      "Section1_SHA256":st45.ROM1_SHA[m.name],
      "Section2_SHA256":st45.MODELS[m.name].sha2,
      "parent_reset":"FUN_%08x"%m.reset_fn,
      "parent_pool_initializer":"FUN_%08x"%m.init_fn,
      "parent_registration_BL":"0x%08x"%m.register_bl,
      "parent_runtime_slot_pointer_RAM":"0x%08x"%m.parent_ptr,
      "parent_pool_stride":"0x%x"%m.stride,
      "parent_pool_first_slot":"0x%08x"%m.pool_head,
      "runtime_parent_movie_type_offset":"+0xa8c",
      "class_source_getter":"FUN_%08x"%m.movie_type_fn,
      "4K_class_movie_types":[4,5,6,7],
      "4K_flag_source_getter":"FUN_%08x"%m.flag_getter_fn,
      "4K_flag_direct_original_BL":"0x%08x"%m.flag_bl,
      "parent_flag_a8e_source_when_4K":"0x%08x"%m.active_flag_ram,
      "parent_flag_a8e_source_when_NOT_4K":0,
      "parent_companion_a8f_source_when_other_types":"0x%08x"%m.active_companion_ram,
      "Recorder_exporter":"FUN_%08x"%m.snapshot_exporter_fn,
      "Recorder_export_snapshot_offsets":active_snapshot_offsets(m),
      "original_ROM_getter_read_word_hex":"0x%08x"%expected[0],
      "parent_pointer_xrefs_total":116,
       "parent_pointer_direct_write_is_initializer_not_runtime_registration":True,
      "generic_XT4_parent_reset_caller_value_minus_one_confirmed":False,
      "observed_true_runtime_active_Recorder_flag_value":False,
      "original_active_config_field_assignment_writer_fully_proven":False,
      "source_byte_0x581_same_as_GUI_eModeMovieCodec":False,
      "X_S10_specific_4K59_94_gate_or_Main10_bitstream_proven":False,
      "physical_camera_ROM_RAM_flash_USB_used":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",default=Path("output"),type=Path)
    root=p.parse_args().output
    def oldfile(path,marker):
        return json.loads((root/path).read_text().split("\n"+marker,1)[0])
    prev={
     "stage46":oldfile("stage46_joint_mode_original_audit.jsonlog","STAGE46"),
     "stage47":oldfile("stage47_mode_key_codec_original_audit.jsonlog","STAGE47"),
    }
    res=[]
    for m in MODELS.values():
        logmap={
         "reset":m.reset_log,"init":m.init_log,
         "getters":m.getter_log,"export":m.export_log,
         "pointer":m.pointer_log,"xref":m.active_refs_log,
        }
        logs={k:(root/v).read_text() for k,v in logmap.items()}
        sec1=(root/f"x6-{m.name}/section-1.bin").read_bytes()
        sec2=(root/f"x6-{m.name}/section-2.bin").read_bytes()
        res.append(check_model(m,sec1,sec2,logs,prev))
    need(res[0]["runtime_parent_movie_type_offset"]==
         res[1]["runtime_parent_movie_type_offset"] and
         res[0]["Recorder_export_snapshot_offsets"][
         "snap_export_source_flag_offset"]==
         res[1]["Recorder_export_snapshot_offsets"][
         "snap_export_source_flag_offset"],
         "cross-model flag A8E to snapshot 0x581 mismatch")
    print(json.dumps({
      "two_original_ROM_A8E_write_source_and_snapshot_exports":res,
      "4K59_94_Camera_or_Main10_Proven":False,
      "vendor_original_bytes_or_video_in_public_repo":False,
      "camera_hardware_used_or_ROM_patched":False,
    },indent=2))
    print("STAGE48 ORIGINAL DYNAMIC PARENT A8E SOURCE / SNAPSHOT+581 OFFLINE AUDIT PASS")
    print("Unresolved: current Recorder state setter, physical mode, 4K60, Main10.")
if __name__=="__main__":main()

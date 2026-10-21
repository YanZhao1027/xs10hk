#!/usr/bin/env python3
"""Phase52: GUI schema equals Recorder offsets; P identity still unknown.

Cross-validate original SHA-pinned X-S10 3.11 / X-T4 2.12 GUI writes,
Recorder current pointer passed to HDMI-status reader, and full UI-buffer
comparisons. Distinguish GUI debug dumps and profile descriptor 0x206/0x207
from Recorder's guarded 0x200 initializer. Read-only offline; never patches,
contacts camera USB/FF80, accesses RAM/flash or uploads vendor binaries.
"""
from dataclasses import dataclass
import argparse
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage51_direct_mode_flag_table as st51
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

@dataclass(frozen=True)
class Spec:
    name:str
    sec2base:int
    gui_base:int
    ui4k_setter:int
    codec_setter:int
    ui4k_strb:int
    codec_strb:int
    hdmi_fn:int
    hdmi_583:int
    hdmi_6c:int
    hdmi_581:int
    hdmi_context_load:int
    hdmi_context_store:int
    p_caller_init:int
    p_caller_export:int
    guard_200:int
    gui_compare_caller:int
    gui_compare_bl:int
    gui_compare_target:int
    gui_shadow:int
    gui_record_len:int
    gui_dump_entry:int
    gui_dump_target:int
    n_gui_xrefs:int
    n_gui_fns:int
    n_current_p_xrefs:int
    n_p_fns:int
    n_descriptor_p_xrefs:int
    n_descriptor_p_fns:int
    gui_egress_copy_fns:int
    gui_egress_full_sized:int

SPECS={
 'xs10':Spec('xs10',0x01eaf000,0x01b880a0,0x01159648,0x0115b578,
   0x011596a4,0x0115b5d4,0x021fc43c,0x021fc48c,0x021fc49c,0x021fc518,
   0x021fc464,0x021fc474,0x022149b0,0x0221d738,0x02214750,
   0x02068184,0x020684ec,0x012a9498,0x01b55e10,0x5dc,
   0x02128290,0x0212814c,3409,801,521,325,111,82,18,23),
 'xt4':Spec('xt4',0x01e0f000,0x01af2808,0x0112de50,0x0112fd80,
   0x0112deac,0x0112fddc,0x02168510,0x02168560,0x02168570,0x021685ec,
   0x02168538,0x02168548,0x02180f9c,0x0218a14c,0x02180d24,
   0x01fc3578,0x01fc38e0,0x01281b98,0x01abfd88,0x5d8,
   0x0207b750,0x0207b60c,3493,809,555,343,111,83,11,20),
}

def need(ok,why):
    if not ok:raise ValueError('Phase52 GUI/Recorder alias boundary: '+why)

def verify_merged_gui(s,sec1word,gui4k_c,codec_c):
    """Pin two original A32 setters on the same GUI RAM base and schema."""
    gui4k=s.gui_base+0x581
    codec=s.gui_base+0x5b0
    need(codec-gui4k==0x2f and gui4k!=codec,
         '4K-out flag and MovieCodec must be separate GUI bytes')
    for src,offset,c in ((s.ui4k_strb,0x581,gui4k_c),(s.codec_strb,0x5b0,codec_c)):
        low=st31.mov_half(sec1word(src-8),False,3)
        high=st31.mov_half(sec1word(src-4),True,3)
        need((low|(high<<16))==s.gui_base,
             'original GUI field setter MOVW/MOVT base wrong '+hex(src))
        need(sec1word(src)==(0xe5c34000|offset),
             'original GUI STRB register or +offset changed '+hex(src))
        need(('DAT_%08x = (char)param_1;'% (s.gui_base+offset)) in c,
             'Ghidra GUI setter not writing same memory byte '+hex(offset))
    need('INPUT_eMode4kOut' in gui4k_c and
         'INPUT_eModeMovieCodec' in codec_c,
         'GUI debug labels no longer back field identities')
    return {'ui_struct_base':hex(s.gui_base),
            'ui4kOut_GUI_absolute':hex(gui4k),
            'movieCodec_GUI_absolute':hex(codec),
            'schema_offsets_match_P_plus_581_and_plus_5b0':True,
            'GUI_equals_recorder_runtime_P_proven':False,
            'UI_setting_value_equals_P_runtime_byte_proven':False}

def verify_hdmi(s,sec2word,hdmi_c,initializer_c,serializer_c):
    """The consumer receives P, but DOES NOT store to P+0x581."""
    orig=(
      (s.hdmi_583,0xe5d03583),
      (s.hdmi_6c,0xe5d0306c),
      (s.hdmi_581,0xe5d03581),
      (s.hdmi_context_load,0xe5d11ce1 if s.name=='xs10' else 0xe5d11f45),
      (s.hdmi_context_store,0xe5c32ce1 if s.name=='xs10' else 0xe5c32f45),
    )
    for site,expected in orig:
        need(sec2word(site)==expected,
             'original A32 HDMI config byte reference invalid at '+hex(site))
    need('param_1[0x581]' in hdmi_c and
         'param_1[0x583]' in hdmi_c and
         'param_1[0x6c]' in hdmi_c and
         'RECCONT__HDMI_CONECT_NG' in hdmi_c and
         '0x8043' in hdmi_c,
         'Ghidra HDMI state reader / event path mismatched')
    need(re.search(r'param_1\[0x581\]\s*=(?!=)',hdmi_c) is None and
         re.search(r'param_1\[0x583\]\s*=(?!=)',hdmi_c) is None,
         'HDMI reader unexpectedly directly writes candidate P fields')
    for site,caller in ((s.p_caller_init,initializer_c),
                        (s.p_caller_export,serializer_c)):
        need(st31.branch_target(sec2word(site),site)==s.hdmi_fn,
             'original BL does not enter claimed HDMI status function')
        need(('FUN_%08x(_DAT_%08x);'%(s.hdmi_fn,st31.SPECS[s.name].current_slot)) in caller,
             'higher-level caller not passing true Recorder current P slot')
    # Same relative branch computes HDMI/output status from nonzero flag,
    # but it does not name or prove an X-S10-specific hardware permission.
    return {'hdmi_status_consumer':'0x%08x'%s.hdmi_fn,
            'hdmi_status_4K_flag_ldrb':'0x%08x'%s.hdmi_581,
            'hdmi_status_PC_current_P_callers_A32_verified':2,
            'HDMI_related_flag_usage_P_confirmed':True,
            'flag_semantics_full_enumeration_proven':False,
            'this_consumer_initializes_P_plus_581':False}

def verify_gui_compare(s,sec2word,compare_c,helper_c,dump_c,dump_helper_c):
    # A32 R2=len; R1=second buffer; R0=GUI buffer; BL into memcmp.
    for a,w in ((s.gui_compare_bl-12,0xe3002000|s.gui_record_len),
                (s.gui_compare_bl-8,0xe1a01005),
                (s.gui_compare_bl-4,0xe1a00004)):
        need(sec2word(a)==w,
             'original GUI 0x5DC/5D8 compare setup changed')
    need(st31.branch_target(sec2word(s.gui_compare_bl),s.gui_compare_bl)==s.gui_compare_target,
         'original GUI buffer comparison calls wrong target')
    exact=('FUN_%08x(&DAT_%08x,0x%x,0x%x)'%
           (s.gui_compare_target,s.gui_base,s.gui_shadow,s.gui_record_len))
    need(exact in compare_c,
         'original GUI buffer compare source/destination or size changed')
    need('param_1 == *param_2' in helper_c and
         'if (param_3 == 0)' in helper_c and
         'return param_1;' in helper_c,
         'A32 helper no longer looks like a byte-wise equality check')
    need(('FUN_%08x(&DAT_%08x,0x%x);'%
          (s.gui_dump_target,s.gui_base,s.gui_record_len)) in dump_c and
         's_REC_INPUT_' in dump_c and
         'puVar3 = puVar3 + 1;' in dump_helper_c and
         'FUN_' in dump_helper_c,
         'GUI full-length call is not the established debug hex-dump path')
    need(('FUN_%08x'%s.gui_dump_target) in dump_helper_c,
         'expected dump helper function missing')
    return {'gui_comparison_length_bytes':s.gui_record_len,
            'gui_comparison_shadow_base':hex(s.gui_shadow),
            'original_GUI_memcmp_BL_and_length_verified':True,
            'full_gui_buffer_debug_hex_dump_is_not_memcpy_to_Recorder':True,
            'full_buffer_copy_into_P_from_GUI_proven':False}

def verify_scope_and_scans(s,sec2word,init_c,registry,intersection_log,gui_bulk_log):
    # Previous Phase29: installer selects 0x206/0x207 from mode status,
    # but Phase32 current config initializer has an explicit 0x200 guard.
    # This is a stage identity separator; no assertion about time ordering.
    need(sec2word(s.guard_200)==0xe3510c02,
         'original Recorder initializer cmp r1,#0x200 changed')
    need('!= 0x200' in init_c and '901c' in init_c,
         'Ghidra mode registry / descriptor guard absent')
    need(registry['selected_registry_type_values']==['0x206','0x207'] and
         registry['entire_pointer_overwritten_iff_payload_length_at_least_8'] and
         not registry['runtime_length_and_pointer_value_known'],
         'Phase29 copied profile descriptor not fully revalidated')
    need(len(re.findall(r'ST52_REF i=\d+ addr=[0-9a-f]+ refs=\d+ functions=\d+',intersection_log))==3,
         'GUI/current P/descriptor pointer groups missing')
    fields=[(s.gui_base,s.n_gui_xrefs,s.n_gui_fns),
            (st31.SPECS[s.name].current_slot,s.n_current_p_xrefs,s.n_p_fns),
            (st31.SPECS[s.name].descriptor+0x10,s.n_descriptor_p_xrefs,s.n_descriptor_p_fns)]
    for i,(addr,refcount,fns) in enumerate(fields):
        m=re.search(r'ST52_REF i=%d addr=([0-9a-f]+) refs=(\d+) functions=(\d+)'%i,intersection_log)
        need(m is not None and (int(m.group(1),16),int(m.group(2)),int(m.group(3)))==(addr,refcount,fns),
             'read-only Ghidra cross-reference count/slot identity changed')
    need('ST52_INTERSECTION gui_base_and=1 total=0' in intersection_log and
         'ST52_INTERSECTION gui_base_and=2 total=0' in intersection_log,
         'GUI/current P direct function intersection no longer empty')
    m=re.search(r'ST52_GUI_SUMMARY addr=([0-9a-f]+) decompiled=(\d+) with_copy=(\d+) with_full_size_literal=(\d+)',gui_bulk_log)
    need(m is not None and int(m.group(1),16)==s.gui_base and int(m.group(2))==s.n_gui_fns and
         int(m.group(3))==s.gui_egress_copy_fns and int(m.group(4))==s.gui_egress_full_sized,
         'GUI code inventory stats drifted')
    return {'phase29_record_selector_0x206_or_0x207_and_initializer_guard_0x200_are_not_same_type':True,
            'phase29_record_may_be_reloaded_before_initializer':True,
            'P_descriptor_pointer_runtime_value_observed':False,
            'GUI_vs_P_direct_slot_reference_function_intersection':0,
            'GUI_vs_descriptor_P_reference_function_intersection':0,
            'GUI_base_functions_decompiled':s.n_gui_fns,
            'GUI_base_with_copy_candidate_functions':s.gui_egress_copy_fns,
            'GUI_base_with_large_size_literals':s.gui_egress_full_sized,
            'absence_of_interprocedural_or_indirect_alias_proven':False}

def decode_c(log,entry):
    """Phase31 helper omits `bool` Ghidra return type; add that case."""
    try:return st31.function_c(log,entry)
    except ValueError:
        for chunk in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
            c=chunk.split("TRACE_DECOMP_END (GhidraScript)")[0]
            if re.search(r"(?m)^\s*bool\s+FUN_%08x\s*\("%entry,c):return c
        raise

def analyze(root):
    st51.analyze(root) # recertify SHA, A32, prior Phase31/32/48/49/50/51
    results=[]
    for s in SPECS.values():
        m=s.name
        a=(root/f'x6-{m}/section-1.bin').read_bytes()
        b=(root/f'x6-{m}/section-2.bin').read_bytes()
        w1=lambda v:st31.word(a,0x01021000,v)
        w2=lambda v:st31.word(b,s.sec2base,v)
        rd=lambda suf:(root/(m+'_'+suf+'.log')).read_text(encoding='utf-8')
        r=st29.audit(st29.SPECS[m],b,
           rd('stage29_registry_install_callsite'),
           rd('stage28_profile_descriptor_registry'),
           rd('stage29_registry_origins_xrefs'),
           rd('stage29_registry_install_callsite'))
        guiset=st31.function_c(rd('stage52_gui_base_descriptor_xrefs'),s.ui4k_setter)
        codec=st31.function_c(rd('stage31_gui_codec_setter_pipeline'),s.codec_setter)
        gui=verify_merged_gui(s,w1,guiset,codec)
        hdmitrace=rd('stage52_direct_P_mutator_candidates')
        hdmi=verify_hdmi(s,w2,
             st31.function_c(hdmitrace,s.hdmi_fn),
             st31.function_c(rd('stage52_pointer_record_bulk_candidates'),
                             0x02214738 if m=='xs10' else 0x02180d0c),
             st31.function_c(hdmitrace,
                             0x0221d1bc if m=='xs10' else 0x02189bd4))
        cmp_trace=rd('stage52_full_gui_transfer_trace')
        comp=verify_gui_compare(s,w2,
             decode_c(cmp_trace,s.gui_compare_caller),
             st31.function_c(rd('stage52_compare_helper_trace'),s.gui_compare_target),
             st31.function_c(cmp_trace,s.gui_dump_entry),
             st31.function_c(cmp_trace,s.gui_dump_target))
        guard=verify_scope_and_scans(s,w2,
             st31.function_c(rd('stage52_pointer_record_bulk_candidates'),
                             0x02214738 if m=='xs10' else 0x02180d0c),
             r,rd('stage52_gui_P_pointer_intersections'),
             rd('stage52_gui_bulk_egress'))
        results.append({'model':m,**gui,**hdmi,**comp,**guard,
             'first_P_plus_581_writer_identified':False,
             'X_S10_only_4K60_permission_or_Main10_proven':False,
             'camera_USB_FF80_RAM_flash_or_ROM_modified':False})
    return {'models':results,'source':'original Fujifilm X6 sections and local read-only Ghidra',
            'same_offsets_GUI_structure_to_recorder_P_in_two_models':True,
            'P_equals_GUI_base_unproven':True,'initial_flag_writer_unproven':True,
            'all_vendor_data_remain_ignored_on_Ubuntu':True}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(ap.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE52 ORIGINAL GUI FLAG/CODEC OFFSETS, HDMI P READ AND GUI CMP PASS')
    print('UNKNOWN: runtime P pointer alias, GUI->P initial data, 4K60 or Main10.')
if __name__=='__main__':main()
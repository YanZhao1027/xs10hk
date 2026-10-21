#!/usr/bin/env python3
"""Phase50: prove conditional active Recorder flag->export pointer feedback.

No live camera. SHA-pinned original X-S10 3.11 and X-T4 2.12 ARM / local
Ghidra logs only. Revalidates Phase31 pointer-value copy and gated serializer,
Phase49 input flag->active->parent link, then original 8 A32 LDRB/STRB words
for ACTIVE flag bytes to OUTPUT +581/+580/+583/+582, separately from Codec.

An output pointer copied from an input pointer may subsequently be modified:
"Q=P immediately after assignment" DOES NOT prove "Q=P at serialization".
Also inventories all statically disassembled direct STRB +581 candidates and
4-byte STR +580 candidates; neither offset identity nor finite instruction
inventory proves the true first writer of P+581 or any runtime value.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_recorder_input_export_alias_stage31 as st31
import audit_stage49_recorder_mode_flag_forward as st49

FLAGS=(0x581,0x580,0x583,0x582)

@dataclass(frozen=True)
class Spec:
    model: str
    ui_site: int
    ui_movw: int
    other_site: int
    other_movw_or_literal: int
    other_value_literal: int
    exporter_site: int
    exporter_first_ldrb: int
    direct_orig_asm: tuple[str,str,str]
    expected_ui_dest: int
    expected_other_dest: int
    active_first: int
    expected_word_writes_at_580: int
    alternate_mode_writer: int
    alternate_mode_source_writer: int
    static_aligned_mode_init: int

SPECS={
 'xs10':Spec('xs10',0x011596a4,0x0115969c,
             0x0116bbf4,0x0116bbf0,0x0116bc2c,
             0x012bea74,0x012bea70,
             ('strb r4,[r3,#0x581]','strb r4,[r3,#0x581]','strb r3,[r4,#0x581]'),
             0x01b88621,0x01c1fbc1,0x01c251d4,7,
             0x022368a0,0x0227e1f0,0x02231498),
 'xt4':Spec('xt4',0x0112deac,0x0112dea4,
           0x011f29a0,0x011f2990,0,
           0x01297138,0x01297134,
           ('strb r4,[r3,#0x581]','strb r2,[r3,#0x581]','strb r3,[r4,#0x581]'),
           0x01af2d89,0x01ac83bd,0x01b83940,6,
           0x021a35ac,0x021e2e74,0x0219e138),
}

def need(ok,reason):
    if not ok: raise ValueError('Stage50 feedback provenance audit: '+reason)

def original_export_words(m):
    """Little-endian ARM: active template[R5+flag] -> output[R4+field]."""
    offset=st49.MODELS[m.model].intermediate_flag
    return tuple((0xe5d53000 | (offset+i),0xe5c43000 | x)
                 for i,x in enumerate(FLAGS))

def read_inventory(log):
    """Ghidra static instruction listing only; does not resolve aliases."""
    m=re.search(r'ST50_TOTALS \{([^}]*)\}',log)
    need(m is not None,'Ghidra bounded inventory totals missing')
    totals={key:int(val) for key,val in re.findall(r'([0-9a-f]+/(?:READ|WRITE|OTHER))=(\d+)',m.group(1))}
    need(totals.get('581/WRITE')==3 and totals.get('582/WRITE')==3 and
         totals.get('583/WRITE')==3 and totals.get('580/WRITE')==12,
         'static immediate 580..583 counts unexpected')
    # Only parse the 581/WRITE group, not unrelated offset matches.
    group_header=re.search(r'ST50_GROUP 581/WRITE fns=(\d+)',log)
    need(group_header is not None and int(group_header.group(1))==3,
         'direct 581 writer function count changed')
    group=log.split('ST50_GROUP 581/WRITE fns=')[1].split('ST50_GROUP 582/',1)[0]
    owners=re.findall(r'ST50_OWNER 581/WRITE (FUN_[0-9a-f]+)@([0-9a-f]+) sites=(\d+)',group)
    sites=re.findall(r'ST50_SITE ([0-9a-f]{8}) ([^\r\n(]+)',group)
    need(len(owners)==3 and all(c=='1' for _,_,c in owners) and len(sites)==3,
         'direct 581 STORE group contains an unclassified writer')
    word_group=log.split('ST50_GROUP 580/WRITE fns=')[1].split('ST50_GROUP 581/',1)[0]
    word_sites=re.findall(r'ST50_SITE ([0-9a-f]{8}) (str [^\r\n(]+)',word_group)
    byte_sites=re.findall(r'ST50_SITE ([0-9a-f]{8}) (strb [^\r\n(]+)',word_group)
    need(len(word_sites)+len(byte_sites)==12,
         'aligned offset 580 4-byte writer count inconsistent')
    return {'sites':[(int(a,16),txt.strip().lower()) for a,txt in sites],
            'owners':owners,'aligned_580_word_sites':[int(a,16) for a,_ in word_sites],
            'totals':totals}

def validate(m,section1_word,listing,exporter_c,mode_c,caller_c,prior31,prior49):
    """Single-model checker: tests use entirely synthetic logs and ARM words."""
    p=st31.SPECS[m.model]
    new=st49.MODELS[m.model]
    need(prior31['model']==m.model and prior31['original_A32_R0_R1_pointer_copy_verified'] and
         prior31['pointer_value_equality_immediately_after_alias_instruction'] and
         prior31['same_caller_calls_initializer_before_serializer'] and
         prior31['runtime_pointer_equality_at_serializer_time_proven'] is False and
         int(prior31['input_pointer_slot'],16)==p.current_slot and
         int(prior31['export_pointer_slot'],16)==p.export_slot,
         'Phase31 value-copy/gate source proof missing')
    need(prior49['model']==m.model and prior49['forward_input_plus_581_to_active_flag_static_path_verified'] and
         int(prior49['active_flag_RAM'],16)==m.active_first and
         prior49['reverse_export_active_to_snapshot_plus_581_verified'] and
         prior49['initial_config_input_plus_581_writer_identified'] is False,
         'Phase49 forward active flag provenance missing')
    need(m.exporter_site==m.exporter_first_ldrb+4 and
         m.exporter_site in (0x012bea74,0x01297138) and
         p.exporter==(0x012be684 if m.model=='xs10' else 0x01296d38),
         'exporter identity differs')
    need(int(prior49['active_codec_RAM_separate'],16)-m.active_first==0x34,
         'flag and codec incorrectly merged')
    # All 8 A32 transfer words *originally* come from pinned X6 Section1.
    for i,(load,store) in enumerate(original_export_words(m)):
        a=m.exporter_first_ldrb+8*i
        need(section1_word(a)==load and section1_word(a+4)==store,
             'original active-to-export A32 LDRB/STRB mismatch pair '+str(i))
        need(('param_1[0x%x] = DAT_%08x;'%(FLAGS[i],m.active_first+i)) in exporter_c,
             'reverse exporter Ghidra assignment not verified pair '+str(i))
    inv=read_inventory(listing)
    expected={m.ui_site:m.direct_orig_asm[0],m.other_site:m.direct_orig_asm[1],
              m.exporter_site:m.direct_orig_asm[2]}
    need({a:s for a,s in inv['sites']}==expected,
         'Ghidra direct STRB +581 sites changed or missing')
    need(len(inv['aligned_580_word_sites'])==m.expected_word_writes_at_580,
         'possible full-word +580 alias candidates count changed')
    for addr in expected:
        need((section1_word(addr)&0x0fffffff)==
             ((0xe5c34581 if addr==m.ui_site or
               (m.model=='xs10' and addr==m.other_site)
               else 0xe5c32581 if addr==m.other_site
               else 0xe5c43581)&0x0fffffff),
             'original immediate 581 STRB word changed '+hex(addr))
    # Explicit original pointer reconstruction prevents substring-only
    # '0x581' writers in UI cache and unrelated status object being treated
    # as pointer P. Their bases are static global addresses, not P's slot.
    ui=(st31.mov_half(section1_word(m.ui_movw),False,3) |
        (st31.mov_half(section1_word(m.ui_movw+4),True,3)<<16))
    need(ui+0x581==m.expected_ui_dest,
         'UI4kOut absolute 581 destination changed')
    if m.model=='xs10':
        # Original PC-relative LDR R3 at 0x0116BBF0 has PC+8+0x34.
        need(section1_word(m.other_movw_or_literal)==0xe59f3034 and
             m.other_movw_or_literal+8+0x34==m.other_value_literal,
             'INFO_REC second candidate is not original literal LDR')
        other=section1_word(m.other_value_literal)
    else:
        other=st31.mov_half(section1_word(m.other_movw_or_literal),False,3) |\
              (st31.mov_half(section1_word(m.other_movw_or_literal+4),True,3)<<16)
    need(other+0x581==m.expected_other_dest and
         m.expected_ui_dest not in (p.current_slot,p.export_slot,m.active_first) and
         m.expected_other_dest not in (p.current_slot,p.export_slot,m.active_first),
         'non-Recorder global bytes incorrectly considered input field')
    # Two matched original Movie/movie-context 32-bit stores at +580 write
    # four bytes (thus potentially cover +581) but have *param_1* identity,
    # not the main Recorder descriptor's dynamic P pointer identity.
    need('*(undefined4 *)(param_1 + 0x580) = *(undefined4 *)(param_2 + 0x18);' in mode_c,
         'movie context +580 source is not independent structure field')
    need('*(undefined4 *)(param_1 + 0x580) = 1;' in caller_c,
         'other original movie-context +580 initializer missing')
    return {
       'model':m.model,
       'static_direct_STRB_581_sites':3,
       'static_aligned_STR_word_580_sites':m.expected_word_writes_at_580,
       'non_export_STRB_581_static_targets':[
           '0x%08x'%m.expected_ui_dest,'0x%08x'%m.expected_other_dest],
       'original_active_to_export_LDRB_STRB_words':8,
       'active_flag_RAM':'0x%08x'%m.active_first,
       'input_slot':'0x%08x'%p.current_slot,
       'output_slot':'0x%08x'%p.export_slot,
       'immediate_pointer_copy_P_to_Q_before_gated_serialization_proven':True,
       'serializes_active_flag_to_Q_plus_581':True,
       'possible_feedback_into_P_plus_581_if_Q_remains_P':True,
       'input_output_pointer_equality_during_actual_serialize_proven':False,
       'aligned_word_stores_have_verified_main_P_identity':False,
       'first_writer_of_P_plus_581_proven':False,
       'physical_Camera_Main10_or_4K60_unlocked':False,
       'physical_camera_USB_FF80_RAM_Flash_or_ROM_patch_used':False}

def phase31_check(root,m,sec1,sec2):
    p=st31.SPECS[m.model]
    rd=lambda f:(root/f).read_text(encoding='utf-8')
    return st31.audit(p,sec1,sec2,
            rd(m.model+'_stage31_export_pointer_slot_initializer.log'),
            rd(m.model+'_stage31_alias_producer_order_callers.log'),
            rd(m.model+'_stage25_snapshot_populate_pipeline.log'),
            rd(m.model+'_stage25_snapshot_producer_candidates.log'),
            rd(m.model+'_stage31_gui_codec_setter_pipeline.log'),
            rd(m.model+'_stage31_gui_setter_caller_context.log'),
            rd(m.model+'_stage31_export_pointer_slot_refs.log'),
            rd(m.model+'_stage31_dynamic_ram_mapping.log'))

def check_both_original(root):
    # Re-check entire original SHA-pinned 3.11/2.12 Phase32/48/49 audit too.
    old49=st49.check_both_original(root)
    reports=[]
    for m in SPECS.values():
        model=m.model
        sec1=(root/f'x6-{model}/section-1.bin').read_bytes()
        sec2=(root/f'x6-{model}/section-2.bin').read_bytes()
        prior31=phase31_check(root,m,sec1,sec2)
        prior49=next(x for x in old49['models'] if x['model']==model)
        rd=lambda f:(root/f).read_text(encoding='utf-8')
        exporter=st31.function_c(rd(model+'_stage25_snapshot_populate_pipeline.log'),st31.SPECS[model].exporter)
        dump=rd(model+'_stage50_aligned_580_word_store_candidates.log')
        mctx=st31.function_c(dump,m.alternate_mode_writer)
        minit=st31.function_c(dump,m.static_aligned_mode_init)
        reports.append(validate(m,lambda addr:st31.word(sec1,0x01021000,addr),
           rd(model+'_stage50_input_flag_immediate_writers.log'),
           exporter,mctx,minit,prior31,prior49))
    return {'source':'SHA-pinned original X6 Section1/2 + bounded read-only Ghidra',
           'models':reports,'camera_flash_or_USB_used':False,
           'scope':'possible feedback through copied output pointer, NOT initial writer'}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=Path('output'))
    args=ap.parse_args()
    data=check_both_original(args.output)
    print(json.dumps(data,indent=2,ensure_ascii=False))
    print('STAGE50 ORIGINAL A32 FLAG FEEDBACK + POINTER ALIAS INVENTORY PASS')
    print('UNKNOWN: initial input flag producer, runtime pointer alias stability and camera mode.')
if __name__=='__main__':main()
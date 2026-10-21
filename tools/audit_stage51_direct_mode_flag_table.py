#!/usr/bin/env python3
"""Stage51: a second, directly P-rooted Recorder flag -> 48x10 lookup path.

Original SHA-pinned X-S10 3.11 / X-T4 2.12 X6 Section1/2 + read-only
Ghidra logs. Proves that two independently called functions per model load
P from actual current-config holder +0xAC4, conditionally rewrite mode
7->6 when P[+0x581]==1, then BL a 48-row four-key lookup wrapper. Checks
four identical literal-based pointers, original ARM words and identical
48x10 tables. This does NOT identify the first writer of P+581; neither
mapping-index existence nor a speculative mode switch proves 4K60/Main10.
No hardware access, USB/FF80, firmware modification or ROM upload.
"""
import argparse
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage50_recorder_flag_feedback as st50
import audit_recorder_input_export_alias_stage31 as st31
import audit_stage49_recorder_mode_flag_forward as st49

TABLE_SHA='9aa3ab18a1604e9e4c9425d02dd042cce9b879dd4da349984035003516a7f9f0'

@dataclass(frozen=True)
class Spec:
    name:str
    sec2base:int
    table:int
    lookup:int
    wrapper:int
    first:int
    second:int
    first_literal:int
    second_literal:int
    first_ldr_base:int
    second_ldr_base:int
    mode_call_site:int
    mode_call_site2:int
    move_mode_reg:int
    phase50_slot:int
    first_reader_count:int
    stage51_slot_decompiled:int
    stage51_slot_helper_count:int
    stage51_slot_candidate_count:int

SPECS={
 'xs10':Spec('xs10',0x01eaf000,0x0171ac70,0x012c6adc,0x012c6b48,
             0x022182ec,0x02218464,0x02218408,0x02218518,
             0x022182fc,0x0221846c,0x02218334,0x022184a0,0x02218320,
             0x02d9c2ac,3,325,16,21),
 'xt4':Spec('xt4',0x01e0f000,0x0168a858,0x012a0710,0x012a077c,
           0x02184918,0x02184ae0,0x02184a84,0x02184b94,
           0x02184928,0x02184ae8,0x02184960,0x02184b1c,0x0218494c,
           0x02d0fa0c,4,343,18,24)
}

def need(ok,reason):
    if not ok:raise ValueError('Stage51 original P-rooted lookup audit: '+reason)

def word(rom,base,address):
    return st31.word(rom,base,address)

def branch_target(w,addr):
    return st31.branch_target(w,addr)

def choose_mode(mode,flag):
    """Only conditional input to lookup, NOT physical video dimensions."""
    need(type(mode) is int and 0<=mode<=255 and type(flag) is int and 0<=flag<=255,
         'invalid test mode or flag')
    return 6 if (mode==7 and flag==1) else mode

def table_lookup(table,mode,key2,key3,key4):
    """Original four-field scan: third/fourth bytes may be 0xff wildcards."""
    need(len(table)==480,'48x10 original table size wrong')
    for val in (mode,key2,key3,key4):
        need(type(val) is int and 0<=val<=255,'invalid synthetic lookup key')
    for i in range(48):
        row=table[i*10:i*10+10]
        if row[0]==mode and row[6]==key4 and row[2] in (0xff,key2) and row[4] in (0xff,key3):
            return i
    return None

def check_pointer_gate(s,sec2word,first_c,second_c):
    """Verify two independent function sites at raw A32 plus C level."""
    baseholder=st31.SPECS[s.name].descriptor+0x3000
    need(baseholder+0xac4==s.phase50_slot,'P pointer slot identity')
    sites=[(s.first_ldr_base,s.first_literal,s.mode_call_site,0),
           (s.second_ldr_base,s.second_literal,s.mode_call_site2,1)]
    for i,(origin,literal,bladdr,which) in enumerate(sites):
        w=sec2word(origin)
        need((w&0xfffff000)==0xe59f3000 and origin+8+(w&0xfff)==literal,
             'PC literal load for current config base invalid')
        need(sec2word(literal)==baseholder,'P holder PC literal is not current descriptor owner')
        offs=[0xe5931ac4,0xe5d1006c,
              0xe5d12581 if i==0 else 0xe5d13581,
              0xe3520001 if i==0 else 0xe3530001,
              0x03500007,
              0x03a02001 if i==0 else 0x03a03001,
              0x13a02000 if i==0 else 0x13a03000,
              0xe3520000 if i==0 else 0xe3530000]
        for j,op in enumerate(offs):
            need(sec2word(origin+4+j*4)==op,
                 'A32 direct P load/mode 7 & flag 1 gate word differs path%d index%d'%(i,j))
        # In the first function the MOVNE follows immediately; in second it
        # follows 3 neighboring LDRB calls, a separately verified stride.
        mo=origin+(0x24 if i==0 else 0x30)
        need(sec2word(mo)==0x13a00006,
             'original conditional MOVNE r0,#6 missing')
        need(branch_target(sec2word(bladdr),bladdr)==s.wrapper,
             'ARM BL downstream 48-row lookup wrapper not verified')
        c=first_c if i==0 else second_c
        check=('0x581', '0x6c',"'\\a'", "'\\x01'", "'\\x06'",' + 0xac4')
        need(all(k in c for k in check),
             'Ghidra C does not back conditional input and flag path')
        need(('FUN_%08x('%s.wrapper) in c,
             'C does not call original index lookup wrapper')
    return 2

def check_lookup(s,section1word,table,map_c,wrapper_c):
    need(len(table)==480 and sha256(table).hexdigest()==TABLE_SHA,
         'SHA-bound 48*10 row table changed')
    # Literal loader into r12 is a sequence MOVW/MOVT, target is within
    # original Section1, stride is +10, index bound is 0x30.
    base=s.lookup
    a=st31.mov_half(section1word(base+12),False,12)
    b=st31.mov_half(section1word(base+16),True,12)
    need(a|(b<<16)==s.table,'lookup ROM MOVW/MOVT table pointer wrong')
    for addr,expected in (
        (base+20,0xe3a00000), # index=0
        (base+28,0xe2800001), # increment index
        (base+32,0xe28cc00a), # 10-byte row stride
        (base+36,0xe3500030), # 48 index upper bound
    ):
        need(section1word(addr)==expected,
             'raw ARM 48x10 iterator/reg bounds do not match')
    wrap=s.wrapper
    need(branch_target(section1word(wrap+8),wrap+8)==s.lookup,
         'lookup wrapper does not call 48-row iterator')
    need(section1word(wrap+12)==0xe350002f and
         section1word(wrap+16)==0x98bd8800 and
         section1word(wrap+20)==0xeafffffe,
         'wrapper >=48 trap/no-match guard changed')
    need('pbVar2 = pbVar2 + 10;' in map_c and 'iVar1 == 0x30' in map_c and
         all(x in map_c for x in ('pbVar2[6]','pbVar2[2]','pbVar2[4]','0xff')),
         'Ghidra four-condition table scan differs')
    need(('FUN_%08x'%s.lookup) in wrapper_c and '0x30' in wrapper_c,
         'Ghidra bounded index wrapper no longer matches')
    # 18 ordinary low=6, 18 ordinary low=7, 12 extended low=6.
    groups=[table[i*10] for i in range(48)]
    need(groups.count(6)==30 and groups.count(7)==18 and all(v in (6,7) for v in groups),
         'unexpected mode classes in original table')
    # Verified example: common type7/key2=6/aux=2 maps to 19; flag1
    # rewrites to type6 which maps to index3; auxiliary=3 has no row for6.
    need(table_lookup(table,7,6,0,2)==19 and
         table_lookup(table,choose_mode(7,1),6,0,2)==3 and
         table_lookup(table,7,6,0,3)==18 and
         table_lookup(table,choose_mode(7,1),6,0,3) is None,
         'proven lookup row remapping and no-match boundary differ')
    return {'model':s.name,'raw_source_table_address':'0x%08x'%s.table,
           'mapping_rows':48,'row_size':10,'sha256':TABLE_SHA,
           'mode7_aux2_example_index_without_override':19,
           'mode7_aux2_example_index_when_flag1':3,
           'mode7_aux3_flag1_example_has_no_match':True,
           'original_iterator_A32_and_wrapper_guard_verified':True,
           'same_rows_prove_XS10_specific_permission':False}

def verify_slot_scan(s,scan):
    total=re.search(r'ST51_SLOT=([0-9a-f]+) xrefs=(\d+) functions=(\d+)',scan)
    summary=re.search(r'ST51_SUMMARY slot=([0-9a-f]+) decompiled=(\d+) with_helper=(\d+) possible=(\d+)',scan)
    need(total is not None and summary is not None and
         int(total.group(1),16)==s.phase50_slot and int(summary.group(1),16)==s.phase50_slot and
         int(total.group(3))==s.stage51_slot_decompiled and
         int(summary.group(2))==s.stage51_slot_decompiled and
         int(summary.group(3))==s.stage51_slot_helper_count and
         int(summary.group(4))==s.stage51_slot_candidate_count,
         'bounded original slot-reference Ghidra inventory has changed')
    # A scan of 325/343 functions with direct pointer-slot references is
    # NOT a complete interprocedural pointer-alias writer census.
    return {'direct_P_slot_referencing_functions_decompiled':s.stage51_slot_decompiled,
            'functions_with_original_copy_helper_call':s.stage51_slot_helper_count,
            'selected_candidate_functions':s.stage51_slot_candidate_count,
            'first_P_plus_581_writer_identified':False}

def analyze(root):
    predecessor=st50.check_both_original(root)
    evidence=[]; hashes=[]
    for s in SPECS.values():
        m=s.name
        sec1=(root/f'x6-{m}/section-1.bin').read_bytes()
        sec2=(root/f'x6-{m}/section-2.bin').read_bytes()
        need(any(r['model']==m and r['serializes_active_flag_to_Q_plus_581'] for r in predecessor['models']),
             'Phase50 original read-only predecessor bridge failed')
        rd=lambda n:(root/n).read_text(encoding='utf-8')
        c=rd(m+'_stage51_direct_live_581_readers_trace.log')
        fc=st31.function_c(c,s.first)
        sc=st31.function_c(c,s.second)
        gate=check_pointer_gate(s,lambda a:word(sec2,s.sec2base,a),fc,sc)
        map_c=st31.function_c(rd(m+'_stage51_mode_tuple_mapper_trace.log'),s.lookup)
        wrap_c=st31.function_c(rd(m+'_stage51_mode_tuple_lookup_trace.log'),s.wrapper)
        table=sec1[s.table-0x01021000:s.table-0x01021000+480]
        indices=check_lookup(s,lambda a:word(sec1,0x01021000,a),table,map_c,wrap_c)
        inventory=verify_slot_scan(s,rd(m+'_stage51_config_pointer_copy_uses.log'))
        hashes.append(indices['sha256'])
        evidence.append({**indices,**inventory,
            'P_global_slot':'0x%08x'%s.phase50_slot,
            'direct_P_rooted_mode_7_to_6_gates_original_A32_verified':gate,
            'same_mode_condition_on_both_models':True,
            'first_config_flag_setter_proven':False,
            'runtime_4K60_Sensor_ISP_or_HEVC_Main10_proven':False,
            'camera_USB_FF80_ROM_Flash_modified':False})
    need(hashes[0]==hashes[1],'cross-model 48-row LUT bytes not identical')
    return {'models':evidence,'source':'unaltered vendor X6 Section1/2 and private Ghidra, offline only',
            'shared_48_by_10_table_byte_identical':True,
            'initial_P_plus_581_source_still_unknown':True,
            'physical_camera_access':False}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    d=analyze(a.parse_args().output)
    import json
    print(json.dumps(d,indent=2,ensure_ascii=False))
    print('STAGE51 P+581 DIRECT MODE GATES AND IDENTICAL 48x10 TABLE ORIGINAL ARM PASS')
    print('NOT PROVEN: original flag writer, runtime mode selection, 4K60 or Main10.')
if __name__=='__main__':main()
#!/usr/bin/env python3
"""Phase56: decode ROM event row/column and state setter of Recorder FSM.

This disproves automatic group4 -> group13 invocation, while exhibiting
separate group13 row1/column0 callback under status(1,0xa9), as opposed to
0x102 fast-path. Original Section2/Ghidra read-only on authorized Ubuntu.
No live queue delivery, GUI staging lifetime, P pointer alias or Main10.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage55_recorder_20b_fsm_lifecycle as st55
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

@dataclass(frozen=True)
class Spec:
    model:str
    evt_ptr_table:int
    width_table:int
    desc_status_type:int
    group4_evt_table:int
    group13_evt_table:int
    group4_fn_table:int
    group13_fn_table:int
    group4_status:int
    group13_status:int
    group4_counter:int
    group13_counter:int
    group13_handler:int
    group13_index2_stub:int
    group13_state_setter:int
    setter_stores:int
    classifier:int
    class_check:int
    call_a9:int
    call_102:int
    direct_recv_classifier:int
    group13_event_group:int

SPECS={
 'xs10':Spec('xs10',0x0266a8b8,0x0266a7cc,0x02d987e8,
    0x026639c4,0x02665b7c,0x0266a5b8,0x02665d90,
    0x0327dedc,0x0327deee,0x031bf494,0x031bf4a6,
    0x021cdf50,0x021cdf20,0x0221ca7c,0x0221ca8c,0x021ba418,0x021ba428,
    0x021ca144,0x021c6928,0x021b8ad0,0x021ba7b4),
 'xt4':Spec('xt4',0x025c4d94,0x025c4ca8,0x02d0bf48,
    0x025bda80,0x025bfc38,0x025c4a90,0x025bfe4c,
    0x032aae9c,0x032aaeae,0x031ecc54,0x031ecc66,
    0x0213751c,0x021374ec,0x02189490,0x021894a0,0x02122c0c,0x02122c1c,
    0x02133710,0x0212ff0c,0x021213ac,0x02122fa8),
}

def need(p,text):
    if not p:raise ValueError('Stage56 original firmware ROM FSM: '+text)

def group_layout(s,w,rbyte,rhalf):
    g4=st55.ROUTES[s.model]
    need(w(s.evt_ptr_table+4*4)==s.group4_evt_table and
         w(s.evt_ptr_table+4*13)==s.group13_evt_table,
         'original event group4/13 table identities')
    need(w(g4.ptr_table+16)==s.group4_fn_table and
         w(g4.ptr_table+13*4)==s.group13_fn_table and
         s.group4_evt_table!=s.group13_evt_table and
         s.group4_fn_table!=s.group13_fn_table,
         'callback table group identity mismatch')
    need(rhalf(s.width_table+2*4)==7 and
         rhalf(s.width_table+2*13)==5,
         'event row width 7 and 5 not original')
    offsets=[(s.group4_evt_table+(5*7+i)*2,i) for i in range(7)]
    expected=(8,9,10,2,11,12,13)
    for site,i in offsets:
        need(rbyte(site)==expected[i] and rbyte(site+1)==1,
             'type 0x20B class5 -> group4 row5 callback/delta altered')
    # Group13: for internal state byte==1, classifier sets row1;
    # row1 col0 callback index4 (NOT index2). col0 has no runtime proof.
    need(rbyte(s.group13_evt_table+0)==2 and
         rbyte(s.group13_evt_table+1)==1 and
         rbyte(s.group13_evt_table+2*5)==4 and
         rbyte(s.group13_evt_table+2*5+1)==1,
         'group13 row0 col0 index2 / row1 col0 index4 mismatched')
    need(w(s.group13_fn_table+4*4)==s.group13_handler and
         w(s.group13_fn_table+4*2)==s.group13_index2_stub and
         s.group13_index2_stub!=s.group13_handler and
         st55.SPECS[s.model].handler_stub==s.group13_handler,
         'group13 callback address must be index 4 not 2')
    return {'group4_classifier_20B_fallback_row':5,
            'group4_row5_callback_indices':list(expected),
            'group4_event_columns':7,
            'group13_event_columns':5,
            'group13_state1_col0_callback_index':4,
            'phase55_report_index2_notation_corrected':True,
            'runtime_column_group13_known':False,
            '0x20B_receive_directly_invokes_group13':False}

def status_setter(s,w,call_c,setter_c,classifier_c,receiver_c):
    reg=s.group13_state_setter
    need(w(reg+16)==0xe5c30000 and w(reg+20)==0xe1c310b2 and
         st29.bl_target(w(reg+24),reg+24)==s.classifier,
         'original setter stores byte0/halfword2 then invokes group13 classifier')
    # Actual setter RAM base (MOVW/MOVT) must be same as Phase55's state code
    # base and callback guard: base+2 holds halfword state.
    RAM=st55.SPECS[s.model].state_global
    need((st29.half(w(reg+8),False,3) |
         st29.half(w(reg+12),True,3)<<16)==RAM,
         'state setter global does not match callback guard RAM')
    need(st29.half(w(s.class_check-8),False,3) |
         st29.half(w(s.class_check-4),True,3)<<16 ==RAM,
         'group13 classifier reads a different state global')
    need(w(s.class_check)==0xe5d33000 and
         w(s.class_check+4)==0xe3530000,
         'group13 classifier first byte read/zero test changed')
    for site,p0,p1 in ((s.call_a9,1,0xa9),(s.call_102,1,0x102)):
        need(w(site-8)==((0xe3a01000|p1) if p1==0xa9 else (0xe3001000|p1)) and
             w(site-4)==0xe3a00001 and
             st29.bl_target(w(site),site)==s.group13_state_setter,
             'original distinct callsite state args changed at '+hex(site))
    need(f'DAT_{RAM:08x} = param_1;' in setter_c and
         f'_DAT_{RAM+2:08x} = param_2;' in setter_c and
         f'FUN_{s.classifier:08x}();' in setter_c,
         'Ghidra setter param identity and classifier BL missing')
    need(f"if (DAT_{RAM:08x} == '\\x01')" in classifier_c and
         f'_DAT_{s.group13_status:08x} = 1;' in classifier_c and
         f'FUN_{st55.ROUTES[s.model].dispatcher:08x}(0xd);' in classifier_c,
         'group13 status1 event dispatch via classifier no longer confirmed')
    need(f'FUN_{s.group13_state_setter:08x}(1,0xa9)' in call_c,
         'separate 1,a9 Ghidra caller not validated')
    need(f'FUN_{s.group13_state_setter:08x}(1,0x102)' in receiver_c,
         'separate 1,102 Ghidra caller not validated')
    return {'state_setter_ram':hex(RAM),
            'group13_classifier_function':hex(s.classifier),
            'known_state_setter_arg_pair_1':['0x1','0xa9'],
            'known_state_setter_arg_pair_2':['0x1','0x102'],
            'state1_A9_allows_stub_ne_0x102_check':True,
            'state1_102_forces_stub_fast_return':True,
            'setter_A9_necessarily_selects_group13_column0':False,
            'A9_caller_always_follows_received_20B':False}

def receiver_classifier(s,c):
    need(f'if (_DAT_{s.desc_status_type:08x} == 0x200)' in c and
         f'_DAT_{s.group4_status:08x} = 5;' in c and
         f'FUN_{st55.ROUTES[s.model].dispatcher:08x}(4);' in c and
         '== 0x20b' not in c.lower(),
         'incoming 0x20B does not fall through to row5 event4')
    return {'0x20B_incoming_event4_status5_static':True,
            'this_receiver_runs_a_group13_controller_on_same_event':False}

def analyze(root):
    parent=st55.analyze(root)
    out=[]
    for s in SPECS.values():
        need(any(x['model']==s.model for x in parent['models']),
             'prior Phase55 audit not passed')
        buf=(root/f'x6-{s.model}/section-2.bin').read_bytes()
        base=st55.SPECS[s.model].sec2base
        w=lambda a:st29.word(buf,base,a)
        rb=lambda a:buf[a-base]
        rh=lambda a:int.from_bytes(buf[a-base:a-base+2],'little')
        prefix=s.model+'_'
        log=lambda name:(root/(prefix+name+'.log')).read_text(encoding='utf-8')
        get=st31.function_c
        lay=group_layout(s,w,rb,rh)
        cg=log('stage56_event13_root_trigger')
        setter=get(cg,s.group13_state_setter)
        cls= get(log('stage54_group13_event_dispatch') if s.model=='xs10' else
                 log('stage56_group13_classifier'),s.classifier)
        candidates=log('stage56_setter_timing_callers')
        # XS10/XT4 both examples share one log with two functions.
        call_c=get(candidates,s.call_a9-0x10)
        recv_c=get(candidates,s.call_102-0x30 if s.model=='xs10' else s.call_102-0x30)
        v=status_setter(s,w,call_c,setter,cls,recv_c)
        rc=receiver_classifier(s,get(log('stage55_type20b_profile_save_fsm'),s.direct_recv_classifier))
        out.append({'model':s.model,**lay,**v,**rc,
           'actual_incoming_20B_to_snapshot_callback_proven':False,
           'recorder_dynamic_P_plus581_initial_value_or_gui_alias_proven':False,
           'hardware_Main10_4K60_proven':False,'camera_USB_FF80_RAM_flash_access':False})
    return {'models':out,'scope':'original vendor Section2 FSM ROM + local private Ghidra',
           'previous_SHA_pinned_original_stages_reverified':True,
           'group4_vs_group13_separation_stronger_than_phase55':True,
           'live_hardware_access':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(ap.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE56 ORIGINAL 0x20B EVENT GROUP4 / GROUP13 ROW1 COL0 SETTER PASS')
    print('NOT PROVEN: same-event transition, col0 at runtime, actual P flag, Main10/4K60.')
if __name__=='__main__':main()
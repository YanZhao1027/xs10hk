#!/usr/bin/env python3
"""Phase58: real GUI -> distinct type0x200 P input buffer full copy, then IPC.

Two-model original X6 A32 + read-only Ghidra. A conditional UI setup
block first calls memcpy(GUI->P), unconditionally branches *backward* into
the type0x200 message-send call; a separate reverse P->GUI copy also exists.
Source GUI fields +581/+5B0 are covered. Phase57 type0x200 24-byte sender
puts P in desc+0x10 on successful module7 receipt, unlike type0x20B seq.
Not an observed camera run, Main10 /4K60 proof or patch recipe.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage57_recorder_200_P_ingress as prev
import audit_stage55_recorder_20b_fsm_lifecycle as st55
import audit_stage53_gui_rec_setparam_tx as st53
import audit_stage52_gui_recorder_hdmi_alias as st52
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

@dataclass(frozen=True)
class Spec:
    model:str
    sec2base:int
    gui:int
    p_input:int
    memcpy_wrap:int
    wrapper_bl:int
    size:int
    copy_then_sender_fn:int
    copy_site:int
    b_back_site:int
    ui_send_site:int
    ui_send_fn:int
    reverse_fn:int
    reverse_bl:int
    extra_src_fn:int
    extra_src_fn_alt:int

SPECS={
 'xs10':Spec('xs10',0x01eaf000,0x01b880a0,0x01b5375c,
   0x0114f164,0x0114f170,0x5dc,0x01f0c820,
   0x01f0ca90,0x01f0ca94,0x01f0ca18,0x02056240,
   0x0205b284,0x0205b29c,0x0118bb1c,0x020b2874),
 'xt4':Spec('xt4',0x01e0f000,0x01af2808,0x01abd79c,
   0x0112373c,0x01123748,0x5d8,0x01e6ab64,
   0x01e6ad08,0x01e6ad0c,0x01e6ac90,0x01fb21dc,
   0x01fb7408,0x01fb7420,0x0115f34c,0x0200dec0),
}

def need(ok,why):
    if not ok:raise ValueError('Stage58 original GUI -> Recorder P data-edge audit: '+why)

def armwords(s,b1,b2):
    w1=b1 if callable(b1) else lambda a:st29.word(b1,0x01021000,a)
    w2=b2 if callable(b2) else lambda a:st29.word(b2,s.sec2base,a)
    actual_mem=st53.SPECS[s.model].memcpy
    need(w1(s.wrapper_bl-4)==0xe3002000|s.size,
         'copy wrapper full block length not MOVW R2 expected')
    need(st29.bl_target(w1(s.wrapper_bl),s.wrapper_bl)==actual_mem,
         'copy wrapper BL to original memcpy changed')
    need(s.size>0x5b0 and s.size>0x581,'full config copy must cover relevant field offsets')
    a=s.copy_site
    for site,base,reg,up in ((a-16,s.gui,1,False),
                             (a-12,s.gui,1,True),
                             (a-8,s.p_input,0,False),
                             (a-4,s.p_input,0,True)):
        got=st29.half(w2(site),up,reg)
        need(got==((base>>16)&0xffff if up else base&0xffff),
             'original A32 GUI source/P target pointer MOVW/MOVT differs '+hex(site))
    need(st29.bl_target(w2(a),a)==s.memcpy_wrap,
         'GUI→P wrapper BL does not target same full memcpy')
    branch=w2(s.b_back_site)
    need(branch&0xff000000==0xea000000 and
         st55.branch(w2,s.b_back_site)==s.ui_send_site,
         'GUI→P copy branch does not go backward to next UI sender')
    need(s.ui_send_site<s.copy_site and
         st29.bl_target(w2(s.ui_send_site),s.ui_send_site)==s.ui_send_fn and
         prev.SPECS[s.model].ui_sender==s.ui_send_fn,
         'copy→back-branch target is not original 0x200 UI send wrapper')
    r=s.reverse_bl
    for site,base,reg,upper in ((r-16,s.p_input,1,False),
                                (r-12,s.p_input,1,True),
                                (r-8,s.gui,0,False),
                                (r-4,s.gui,0,True)):
        got=st29.half(w2(site),upper,reg)
        need(got==((base>>16)&0xffff if upper else base&0xffff),
             'reverse P→GUI routine pointer registers differ '+hex(site))
    need(st29.bl_target(w2(r),r)==s.memcpy_wrap,
         'reverse function is not same data-copy wrapper')
    return {'GUI_source':hex(s.gui),'type200_P_destination':hex(s.p_input),
        'GUI_to_P_full_copy_bytes':s.size,
        'original_control_flow_copy_BL_then_backwards_B_to_sender_BL':True,
        'original_reverse_P_to_GUI_memcpy_separately_present':True,
        'copy_covers_GUI_plus581_and_plus5B0':True}

def decompiled(s,wrapper_c,setup_c,reverse_c,extra_c,extra_alt_c):
    mem=st53.SPECS[s.model].memcpy
    need(f'FUN_{mem:08x}(param_1,param_2,0x{s.size:x});' in wrapper_c,
         'wrapper Ghidra C does not copy arg2->arg1 full config')
    cp=f'FUN_{s.memcpy_wrap:08x}(&DAT_{s.p_input:08x},&DAT_{s.gui:08x});'
    sp=f'FUN_{s.ui_send_fn:08x}();'
    need(cp in setup_c and setup_c.find(sp,setup_c.index(cp))>setup_c.index(cp),
         'conditional setup C does not call GUI→P before 0x200 UI send')
    rp=f'FUN_{s.memcpy_wrap:08x}(&DAT_{s.gui:08x},&DAT_{s.p_input:08x});'
    need(rp in reverse_c and cp not in reverse_c,
         'reverse copy accidentally mistaken as GUI→P producer')
    need(cp in extra_c and cp in extra_alt_c,
         'two separately identified GUI→P bulk copies not in original C')
    return {'two_other_original_GUI_to_P_copy_owners_confirmed':True,
            'reversed_P_to_GUI_copy_is_not_initial_input_writer':True,
            'runtime_setup_branch_executed_on_camera_proven':False}

def cross_phase(s):
    prior=prev.SPECS[s.model]
    need(prior.ui_P_const==s.p_input and st52.SPECS[s.model].gui_base==s.gui and
         st53.SPECS[s.model].staging!=s.p_input,
         'phase57 ui P and sender staging not distinct')
    return {'type200_P_pointer_in_second_word_of_24B_packet_and_desc_plus10_conditional':True,
            'direct_initial_GUI_plus581_value_observed':False,
            'direct_initial_GUI_plus5B0_value_observed':False,
            'IPC_delivered_and_Recorder_type200_initializer_ran_in_vivo':False,
            'GUI_0x20B_message_staging_equals_type200_P_buffer':False,
            'first_menu_selector_value_and_real_4K60_Main10_unproven':True}

def analyze(root):
    prev.analyze(root) # re-verify full SHA pinned original Stage29..57
    rows=[]
    for s in SPECS.values():
        b1=(root/f'x6-{s.model}/section-1.bin').read_bytes()
        b2=(root/f'x6-{s.model}/section-2.bin').read_bytes()
        get=st31.function_c
        private=(root/f'{s.model}_stage58_direct_GUI_to_type200_P_trace.log').read_text(encoding='utf-8')
        result=armwords(s,b1,b2)
        names=[s.memcpy_wrap,s.copy_then_sender_fn,s.reverse_fn,
               s.extra_src_fn,s.extra_src_fn_alt]
        parts=[get(private,fn) for fn in names]
        verified=decompiled(s,*parts)
        rows.append({'model':s.model,**result,**verified,**cross_phase(s),
                     'same_transaction_copy_and_queue_send_if_branch_taken':True,
                     'actual_camera_RAM_flash_USB_FF80_or_vendor_ROM_changed':False})
    return {'models':rows,'evidence':'original ROM Section1/2 and private read-only Ghidra',
            'previous_orig_SHA_audit_chain_passed':True,
            'runtime_or_hardware_claims_all_unproven':True}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(a.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE58 ORIGINAL GUI FULL CONFIG TO TYPE0x200 P BEFORE SEND PASS')
    print('UNKNOWN: runtime call branch/queue receipt, P flag+0x581 value, Main10/4K60.')
if __name__=='__main__':main()
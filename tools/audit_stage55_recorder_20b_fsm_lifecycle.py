#!/usr/bin/env python3
"""Stage55: original ARM evidence for 0x20B descriptor lifecycle in a state handler.

Cross-model X-S10 3.11 and X-T4 2.12. This follows Stage54's *conditional*
module7 receiver. It proves static handler table -> state gate, registry
shallow save -> conditional full source snapshot copy, four fail-closed checks,
then success-only 0x20B registry clearing. It does NOT prove that a queued
message invokes this handler, runtime pointer lifetime, P+0x581 initial value,
or 4K60/Main10. Offline, read-only; ROM & full Ghidra logs stay ignored.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage54_module7_receiver_pointer as st54
import audit_stage53_gui_rec_setparam_tx as st53
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

@dataclass(frozen=True)
class Spec:
    model:str
    sec2base:int
    table_ref:int
    table_base:int
    handler_slot:int
    handler_stub:int
    state_global:int
    controller:int
    register_save:int
    consumer:int
    checks:int
    checks_sites:tuple[int,int,int,int]
    followup_export:int
    zero_record:int
    zero_entry_site:int
    zero_helper:int
    cleanup_call_sites:tuple[int,int,int,int]
    reg_ptr_literal:int
    reg_payload:int
    reg_header_copy:int
    reg_body_copy:int
    memcpy:int
    rec_header:int
    snapshot:int
    exit_callback:int

SPECS={
 'xs10':Spec('xs10',0x01eaf000,0x0266a62c,0x02665d90,0x02665da0,
    0x021cdf50,0x035bd860,0x021cdf80,0x021f8100,0x0221c934,
    0x022b8438,(0x021cdffc,0x021ce034,0x021ce06c,0x021ce0a4),
    0x0221d1bc,0x021fb3f8,0x021ce138,0x012a9340,
    (0x021fb448,0x021fb4e8,0x021fb500,0x021fb59c),
    0x021f8610,0x02d98934,0x021f81cc,0x021f81ec,
    0x012a9148,0x02d987e8,0x02d9d284,0x0221ca14),
 'xt4':Spec('xt4',0x01e0f000,0x025c4b04,0x025bfe4c,0x025bfe5c,
    0x0213751c,0x03672070,0x0213754c,0x0216417c,0x02189348,
    0x02224bf8,(0x021375c8,0x02137600,0x02137638,0x02137670),
    0x02189bd4,0x021674c8,0x02137704,0x01281a40,
    (0x02167518,0x021675b8,0x021675d0,0x0216766c),
    0x0216468c,0x02d0c094,0x02164248,0x02164268,
    0x01281848,0x02d0bf48,0x02d109d4,0x02189428)
}

def need(p,why):
    if not p:raise ValueError('Stage55 original recorder FSM lifecycle: '+why)

def branch(w,site):
    opcode=w(site)
    need((opcode&0x0e000000)==0x0a000000,
         'A32 branch opcode identity')
    dist=opcode&0xffffff
    if dist&0x800000:dist-=0x1000000
    return (site+8+4*dist)&0xffffffff

def original_table_gate(s,w):
    """This is a table callback for the FSM; NOT proof of 0x20B routing."""
    need(w(s.table_ref)==s.table_base,
         'FSM data-region table owner pointer changed')
    need(w(s.handler_slot)==s.handler_stub and
         s.handler_slot==s.table_base+0x10,
         'FSM handler slot does not reference actual stub')
    need(st29.half(w(s.handler_stub),False,3) |
         st29.half(w(s.handler_stub+4),True,3)<<16 ==s.state_global,
         'FSM state field RAM literal changed')
    for a,v in ((s.handler_stub+8,0xe1d320b2),
                (s.handler_stub+12,0xe3003102),
                (s.handler_stub+16,0xe1520003)):
        need(w(a)==v,'FSM pre-state guard A32 differs '+hex(a))
    need(w(s.handler_stub+20)>>24==0x1a and
         branch(w,s.handler_stub+20)==s.controller,
         'FSM state != 0x102 branch does not reach controller')
    # For 0x102 the stub updates a separate status byte then returns 1;
    # thus invoking a table callback is not sufficient for snapshot work.
    need(w(s.handler_stub+0x20)==0xe3a02000 and
         w(s.handler_stub+0x24)==0xe5c32046 and
         w(s.handler_stub+0x28)==0xe3a00001 and
         w(s.handler_stub+0x2c)==0xe12fff1e,
         'FSM same-state fast path A32 altered')
    return {'FSM_handler_pointer_table_slot':hex(s.handler_slot),
            'FSM_handler_stub':hex(s.handler_stub),
            'FSM_state_Ram':hex(s.state_global+2),
            'only_if_state_ne_0x102_branch_to_controller':True,
            'specific_0x20B_message_to_this_table_callback_proven':False}

def original_controller(s,w,c):
    a=s.controller
    need(st29.bl_target(w(a+8),a+8)==s.register_save and
         st29.bl_target(w(a+12),a+12)==s.consumer,
         'descriptor save must precede conditional snapshot consumer')
    for i,site in enumerate(s.checks_sites):
        need(st29.bl_target(w(site),site)==s.checks and
             w(site+4)==0xe3500000 and w(site+8)==0x1a000005 and
             branch(w,site+8)==site+0x24 and
             w(site+0x14)==(0xe3a02000|(i+1)) and
             w(site+0x18)==0xe1c321ba and
             w(site+0x1c)==0xe3a00000,
             'four post-snapshot fail-closed checks changed at '+hex(site))
    cl=s.zero_entry_site
    need(s.checks_sites[-1]<cl and
         w(cl-8)==0xe3a0108c and
         w(cl-4)==0xe300020b and
         st29.bl_target(w(cl),cl)==s.zero_record and
         st29.bl_target(w(cl+4),cl+4)==s.exit_callback and
         w(cl+8)==0xe3a00001,
         '0x20B record clearing must be success-only after checks')
    # Status/recording export called after the four checks succeed and
    # before cleanup, so snapshot is not lost due merely to registry clear.
    expected=(
      f'FUN_{s.register_save:08x}();',
      f'FUN_{s.consumer:08x}();',
      f'FUN_{s.followup_export:08x}();',
      f'FUN_{s.zero_record:08x}(0x20b,0x8c);')
    positions=[c.find(x) for x in expected]
    need(min(positions)>=0 and positions==sorted(positions),
         'Ghidra controller call order differs from original')
    compare=f'FUN_{s.checks:08x}('
    need(c.count(compare)==4 and c.count('if (iVar2 == 0) {')>=4 and
         c.rfind('return 1;')>positions[-1],
         'four early-return failure gates and success-only cleanup missing')
    return {'confirmed_call_order':['save_descriptor_registry','copy_if_type20B',
       '4_staged_status_checks','followup_export','clear_type20B_record'],
       'post_snapshot_checks_return_0_on_failure':4,
       'success_only_registry_clear_parameters':['0x20b','0x8c'],
       'status_checks_hardware_success_observed':False}

def original_registry_save(s,w,c):
    r=s.reg_ptr_literal
    need(w(r)==s.reg_payload and s.reg_payload-0xc==(
         st53.SPECS[s.model].registry_header),
         '0x20B registry pointer original literal inconsistent')
    need(f'if (_DAT_{s.rec_header:08x} == 0x20b)' in c and
         f'puVar3 = DAT_{r:08x} + -0xc;' in c and
         f'puVar2 = DAT_{r:08x};' in c,
         'descriptor 0x20B case does not select same registry record')
    a=s.reg_header_copy;b=s.reg_body_copy
    for site in (a,b):
        need(st29.bl_target(w(site),site)==s.memcpy,
             'registered-record copy helper changed at '+hex(site))
    need(w(a-16)==0xe3a0200c and
         st29.half(w(a-12),False,1)|(st29.half(w(a-8),True,1)<<16)==s.rec_header and
         w(a-4)==0xe1a00005,
         'header memcpy must copy desc into selected record for 12B')
    need(st29.half(w(b-20),False,1)|(st29.half(w(b-16),True,1)<<16)==s.rec_header and
         w(b-12)==0xe5912004 and w(b-8)==0xe281100c and
         w(b-4)==0xe1a00004,
         'payload memcpy must use runtime desc.length/source desc+0x0C')
    need(f'FUN_{s.memcpy:08x}(puVar3,&DAT_{s.rec_header:08x},0xc);' in c and
         f'FUN_{s.memcpy:08x}(puVar2,&DAT_{s.rec_header+0xc:08x},_DAT_{s.rec_header+4:08x})' in c,
         'Ghidra registry 12B+runtime payload direction mismatched')
    return {'record_20B_header':hex(s.reg_payload-12),
            'record_20B_payload':hex(s.reg_payload),
            'record_20B_save_header_bytes':12,
            'record_20B_saved_payload_length_is_current_descriptor_length':True,
            'if_msg8_received_saved_payload_is_pointer_plus_sequence_8B':True,
            'saved_record_contains_an_independent_deep_GUI_copy':False}

def original_registry_clear(s,w,c,zero_c):
    need(f'FUN_{s.zero_helper:08x}(iVar2,0,0xc);' in c and
         f'FUN_{s.zero_helper:08x}(iVar3,0,0x44);' in c and
         f'FUN_{st53.SPECS[s.model].registry_header_fn:08x}(param_1,param_2,0)' in c and
         f'FUN_{st53.SPECS[s.model].registry_payload_fn:08x}(param_1,param_2,0)' in c,
         'success-phase registry lookup and zeroing not established')
    need('if (param_3 == 0)' in zero_c and
         '*puVar2 = (char)param_2;' in zero_c,
         'zero fill helper function is not confirmed memset semantics')
    for site in s.cleanup_call_sites:
        need(st29.bl_target(w(site),site)==s.zero_helper,
             'original registry cleanup memset BL not matched at '+hex(site))
    return {'separate_type20B_registry_header_zero_length':12,
            'separate_type20B_registry_payload_zero_length':0x44,
            'source_snapshot_copied_before_registry_clear_if_succeeded':True,
            'external_staging_buffer_wiped_by_this_function_proven':False}

@dataclass(frozen=True)
class Route:
    ptr_table:int
    group4_table:int
    dispatcher:int
    classifier:int
    classifier_wrapper:int
    incoming_callback:int
    event4_site:int
    event13_site:int
    classifier_status_ram:int

ROUTES={
 'xs10':Route(0x0266a5f8,0x0266a5b8,0x021b859c,0x021b8ad0,0x021b8b9c,
               0x021c549c,0x021b8b94,0x021ba7b4,0x0327dedc),
 'xt4':Route(0x025c4ad0,0x025c4a90,0x02120e78,0x021213ac,0x02121478,
             0x0212ea80,0x02121470,0x02122fa8,0x032aae9c),
}

def original_group_routing(s,route,w,classifier_c,dispatch_c,wrapper_c,callback_c):
    """Receiving 0x20B selects event group4, not automatic group13."""
    need(s.table_ref==route.ptr_table+13*4 and
         w(s.table_ref)==s.table_base and
         w(route.ptr_table+4*4)==route.group4_table and
         route.group4_table != s.table_base,
         'FSM group4 and group13 callback pointers erroneously aliased')
    need(w(route.event4_site-4)==0xe3a00004 and
         st29.bl_target(w(route.event4_site),route.event4_site)==route.dispatcher,
         'reccont received-event classification does not call event4')
    need(w(route.event13_site-4)==0xe3a0000d and
         st29.bl_target(w(route.event13_site),route.event13_site)==route.dispatcher,
         'independent event13 dispatch BL not proven')
    need(('_DAT_%08x == 0x200'%s.rec_header) in classifier_c and
         ('_DAT_%08x = 5;'%route.classifier_status_ram) in classifier_c and
         ('FUN_%08x(4)'%route.dispatcher) in classifier_c,
         'actual received 0x20B does not fall through to event4 status5')
    need(('(&PTR_DAT_%08x)[param_1]'%route.ptr_table) in dispatch_c and
         ('FUN_%08x();'%route.classifier) in wrapper_c and
         ('FUN_%08x();'%route.classifier_wrapper) in callback_c,
         'real receiver->FSM dispatcher and group-index table chain missing')
    return {'on_receipt_of_type20B_if_processed_default_FSM_status':5,
            'immediate_receipt_FSM_event_group':4,
            'snapshot_handler_FSM_event_group':13,
            'FSM_group4_function_table':hex(w(route.ptr_table+4*4)),
            'FSM_group13_function_table':hex(s.table_base),
            'same_0x20B_message_immediately_invokes_group13_controller_proven':False,
            'later_group13_transition_trigger_identified':False}

def analyze(root):
    parent=st54.analyze(root)
    output=[]
    for s in SPECS.values():
        need(any(row['model']==s.model for row in parent['models']),
             'Stage54 original receiver prerequisite failed')
        b=(root/f'x6-{s.model}/section-2.bin').read_bytes()
        w=lambda addr:st29.word(b,s.sec2base,addr)
        rd=lambda name:(root/(s.model+'_'+name+'.log')).read_text(encoding='utf-8')
        get=st31.function_c
        controller=get(rd('stage55_fsm_callchain'),s.controller)
        other=rd('stage55_type20b_profile_save_fsm')
        record=get(other,s.register_save)
        clear=get(other,s.zero_record)
        helper=get(rd('stage55_zero_fill_helper_trace'),s.zero_helper)
        table=original_table_gate(s,w)
        ctl=original_controller(s,w,controller)
        write=original_registry_save(s,w,record)
        zero=original_registry_clear(s,w,clear,helper)
        route=ROUTES[s.model]
        dispatchlog=rd('stage55_fsm_driver_routing')
        recvlog=rd('stage55_fsm_callchain')
        route_out=original_group_routing(s,route,w,
             get(rd('stage55_type20b_profile_save_fsm'),route.classifier),
             get(dispatchlog,route.dispatcher),
             get(dispatchlog,route.classifier_wrapper),
             get(recvlog,route.incoming_callback))
        output.append({'model':s.model,**table,**ctl,**write,**zero,**route_out,
           'recorder_source_snapshot_RAM':hex(s.snapshot),
           'registered_handler_indirectly_invoked_with_type20B_proven':False,
           'runtime_registry_length_and_pointer_lifetime_proven':False,
           'current_recorder_P_derived_from_type20B_sequence_word':False,
           'initial_P_plus0x581_writer_identified':False,
           'camera_4K60_Main10_sensor_or_recording_proven':False,
           'live_device_USB_FF80_ROM_RAM_Flash_modified':False})
    return {'models':output,
            'scope':'conditional static FSM handler + registry lifecycle on pinned original ROM',
            'previous_phase54_original_evidence_reverified':True,
            'hardware_or_live_camera_access':False}

def main():
    arg=argparse.ArgumentParser(description=__doc__)
    arg.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(arg.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE55 ORIGINAL 0x20B FSM REGISTRY SAVE / SNAPSHOT / SUCCESS CLEAR PASS')
    print('NOT PROVEN: live delivery, dispatch timing, current P alias, 4K60 or Main10.')
if __name__=='__main__':main()
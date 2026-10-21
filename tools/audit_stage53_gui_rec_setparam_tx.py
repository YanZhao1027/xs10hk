#!/usr/bin/env python3
"""Phase53: prove GUI->staging memcopy->module7 0x20B enqueue attempt.

Also verify a corresponding Recorder 0x20B descriptor registry and a
*separate* descriptor-based 0x20B snapshot writer. These are NOT an end-to-end
GUI->Recorder P proof: no queue receive/decode, runtime delivery, descriptor
+0xC pointer equality, initial P+0x581, Main10 or 4K60 is claimed.
Only offline original X6 Section1/2/Ghidra on authorized Ubuntu. No USB/FF80,
camera RAM/flash, patched firmware, full Ghidra logs or ROM redistribution.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage52_gui_recorder_hdmi_alias as st52
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

@dataclass(frozen=True)
class Spec:
    model:str
    sec2base:int
    caller:int
    seq_gen:int
    tx:int
    staging:int
    memcpy:int
    copy_bl:int
    enqueue_bl:int
    enqueue:int
    registry_header_fn:int
    registry_payload_fn:int
    registry_header_literal:int
    registry_payload_literal:int
    registry_header:int
    registry_payload:int
    recv:int
    recv_type_site:int
    recv_ptr_site:int
    recv_memcpy_site:int
    gui_clone:int
    clone_bl:int

SPECS={
 'xs10':Spec('xs10',0x01eaf000,0x02059de8,0x020bcb2c,
            0x02197ef8,0x028eba8c,0x012a9148,0x02197f3c,0x02197f78,0x012a6084,
            0x021f893c,0x021f8d64,0x021f8d5c,0x021f9128,
            0x02d98928,0x02d98934,0x0221c934,0x0221c95c,0x0221c9e4,0x0221ca04,
            0x0114f164,0x0114f170),
 'xt4':Spec('xt4',0x01e0f000,0x01fb5f6c,0x02017c6c,
           0x020eaf54,0x0284898c,0x01281848,0x020eaf98,0x020eafd4,0x0127e784,
           0x021649b8,0x02164de0,0x02164dd8,0x021651a4,
           0x02d0c088,0x02d0c094,0x02189348,0x02189370,0x021893f8,0x02189418,
           0x0112373c,0x01123748),
}

def need(x,msg):
    if not x:raise ValueError('Stage53 original GUI-to-0x20B message boundary audit: '+msg)

def arm_half(w,reg,upper):return st29.half(w,upper,reg)

def caller(s,w,c):
    gui=st52.SPECS[s.model].gui_base
    start=s.caller-0x1c
    value=arm_half(w(start),3,False)|(arm_half(w(start+4),3,True)<<16)
    need(value==gui,'GUI source pointer is not original GUI base MOVW/MOVT')
    for addr,op in ((start+8,0xe50b3014),(start+0xc,0xe3a00783),
                    (start+0x14,0xe50b0010),(start+0x18,0xe24b0014)):
        need(w(addr)==op,'original GUI→packet argument setup word differs at '+hex(addr))
    need(st29.bl_target(w(start+0x10),start+0x10)==s.seq_gen,
         'GUI seq generator or 0x20C0000 request value mismatch')
    need(st29.bl_target(w(s.caller),s.caller)==s.tx,'GUI caller BL to TX wrong')
    need(('local_18 = &DAT_%08x;'%gui) in c and
         ('FUN_%08x(0x20c0000)'%s.seq_gen) in c and
         ('FUN_%08x(&local_18)'%s.tx) in c and 'rec_setparam' in c,
         'Ghidra C no longer shows GUI pointer and rec_setparam send call')
    return True

def tx(s,w,c,queue):
    length=st52.SPECS[s.model].gui_record_len
    a=s.copy_bl
    # Original ARM mutates ONLY source +0x40A prior to snapshot, not flag/codec.
    need(w(a-0x1c)==0xe5d3240b and w(a-0x18)==0xe5c3240a,
         'normalization source +0x40A/+0x40B writes changed')
    stage=arm_half(w(a-0x14),5,False)|(arm_half(w(a-0x10),5,True)<<16)
    need(stage==s.staging,'original dest staging pointer differs')
    need(w(a-0xc)==0xe3002000|length,
         'whole GUI stage snapshot length is not original A32 MOVW R2')
    need(w(a-8)==0xe5941000 and w(a-4)==0xe1a00005,
         'memcpy R0=staging R1=GUI argument setup changed')
    need(st29.bl_target(w(a),a)==s.memcpy,'memcpy BL target modified')
    need(w(a+4)==0xe50b5020 and w(a+8)==0xe5943004 and
         w(a+12)==0xe50b301c,'two words of message payload do not reference staging and caller seq')
    need(w(a+16)==0xe300320b and w(a+20)==0xe14b31b8,
         'message command id 0x20B not stored in packet header')
    packet_expected=[(a+0x20,0xe3a00007),(a+0x24,0xe54b0015),
                     (a+0x28,0xe3a03008),(a+0x2c,0xe50b3014),
                     (a+0x30,0xe24b3020),(a+0x34,0xe50b3010),
                     (a+0x38,0xe24b1018)]
    for addr,op in packet_expected:
        need(w(addr)==op,'message to module 7 / size 8 / pointer metadata changed at '+hex(addr))
    need(st29.bl_target(w(s.enqueue_bl),s.enqueue_bl)==s.enqueue,
         'original queue/enqueue BL modified')
    need(all(z in c for z in ('0x40a','0x40b','0x20b',
        '0x%x'%s.staging,'0x%x'%length,
        'FUN_%08x(7,&local_1c)'%s.enqueue)),
         'Ghidra snapshot→0x20B send C path changed')
    need(('FUN_%08x(local_1c[0] + 4,'%s.memcpy) in queue and
         '*(undefined4 *)(param_2 + 4)' in queue and
         '*(int *)(param_2 + 2)' in queue and
         'func_0x0004' in queue,
         'original enqueue helper no longer copies packet contents into queue and invokes external IPC')
    return {'original_full_GUI_snapshotted_to':hex(s.staging),
            'staging_copy_bytes':length,
            'staging_covers_plus581':0x581<length,
            'staging_covers_plus5b0':0x5b0<length,
            'message_type':'0x20b','transport_arg':7,'packet_body_size_bytes':8,
            'GUI_snapshot_then_message_enqueue_attempt_A32_proven':True,
            'cross_thread_delivered_or_Receiver_gets_GUI_proven':False}

def registry(s,w,head,payload):
    # Receiver side has 0x20B table, separately; must not assume sender's
    # own staged pointer is registered in either RAM description field.
    header=w(s.registry_header_literal)
    data=w(s.registry_payload_literal)
    need(header==s.registry_header and data==s.registry_payload and
         header+12==data,'0x20B registry header / payload literal relation changed')
    need(re.search(r'if \(param_1 == 0x20b\)\s*\{\s*return DAT_%08x;'%
                   s.registry_header_literal,head)!=None,
         'Ghidra 0x20B header registry dispatch no longer matches')
    need(re.search(r'if \(param_1 == 0x20b\)\s*\{\s*return DAT_%08x;'%
                   s.registry_payload_literal,payload)!=None,
         'Ghidra 0x20B payload registry dispatch no longer matches')
    need(s.staging!=data and s.staging!=header,
         'different sender staging and 0x20B registry storage assumed equal')
    return {'separate_recorder_20b_registry_header':hex(header),
            'separate_recorder_20b_registry_payload':hex(data),
            'sender_staging_equals_recorder_registry_proven':False}

def receiver(s,w,c,head):
    desc=st29.SPECS[s.model].destination_header
    length=st52.SPECS[s.model].gui_record_len
    pslot=st31.SPECS[s.model].current_slot
    need(w(s.recv_type_site)==0xe300320b and w(s.recv_type_site+4)==0xe1520003,
         'receiver description type != 0x20B compare altered')
    need(w(s.recv_ptr_site)==0xe593100c and
         w(s.recv_ptr_site+4)==0xe3510000,
         '0x20B receiver source is not descriptor +0xC pointer')
    need(w(s.recv_memcpy_site-8)==(0xe3002000|length),
         'receiver copy len does not cover GUI flags')
    need(st29.bl_target(w(s.recv_memcpy_site),s.recv_memcpy_site)==s.memcpy,
         'receiver conditional memcpy target mismatch')
    need(('_DAT_%08x == 0x20b'%desc) in c and
         ('_DAT_%08x != 0'%(desc+12)) in c and
         ('_DAT_%08x = _DAT_%08x'%(st31.SPECS[s.model].export_slot,pslot)) in c and
         ('FUN_%08x(DAT_'%s.memcpy) in c and
         ('_DAT_%08x,0x%x'%(desc+12,length)) in c,
         'Ghidra separate conditional 0x20B snapshot handler does not match')
    return {'receiver_20b_conditional_descriptor_copy':True,
            'receiver_copy_source_is_descriptor_plus_0C_not_P':True,
            'receiver_descriptor_payload_address':hex(desc+12),
            'sender_staging_pointer_into_descriptor_plus_0C_proven':False,
            'receiver_initial_P_plus581_setter_proven':False}

def alias_copy(s,w1,c,gui_backup_c):
    size=st52.SPECS[s.model].gui_record_len
    need(w1(s.clone_bl-4)==(0xe3002000|size) and
         st29.bl_target(w1(s.clone_bl),s.clone_bl)==s.memcpy,
         'same-sized GUI clone helper is not a true memcpy wrapper')
    need(('FUN_%08x(param_1,param_2,0x%x);'%(s.memcpy,size)) in c,
         'full GUI backup clone helper direction/length differs')
    gui=st52.SPECS[s.model].gui_base
    need(('FUN_%08x(DAT_'%s.gui_clone) in gui_backup_c and
         ('FUN_%08x(&DAT_%08x,'% (s.gui_clone,gui)) in gui_backup_c,
         'Ghidra GUI backup helper not called in both directions')
    return {'GUI_full_buffer_backup_and_restore_copy_helpers_verified':True,
            'backup_source_equals_dynamic_recorder_P_proven':False}

def analyze(root):
    st52.analyze(root) # SHA-pinned original Phase29/31/32/48/49/50/51/52
    vals=[]
    for s in SPECS.values():
        m=s.model
        b1=(root/f'x6-{m}/section-1.bin').read_bytes()
        b2=(root/f'x6-{m}/section-2.bin').read_bytes()
        w=lambda a:st29.word(b2,s.sec2base,a)
        w1=lambda a:st29.word(b1,0x01021000,a)
        rd=lambda suf:(root/(m+'_'+suf+'.log')).read_text(encoding='utf-8')
        cs=st31.function_c
        a=caller(s,w,cs(rd('stage53_gui_pointer_transfer_candidates'),
                       0x02059c3c if m=='xs10' else 0x01fb5dc0))
        send=rd('stage53_rec_setparam_api_chain')
        b=tx(s,w,cs(send,s.tx),cs(rd('stage53_20b_sender_registry_trace'),s.enqueue))
        reg=rd('stage53_20b_sender_registry_trace')
        c=registry(s,w,cs(reg,s.registry_header_fn),cs(reg,s.registry_payload_fn))
        recv=receiver(s,w,cs(rd('stage53_candidate_20b_receivers'),s.recv),reg)
        clone=alias_copy(s,w1,
                 cs(rd('stage53_gui_pointer_transfer_candidates'),s.gui_clone),
                 cs(rd('stage53_gui_pointer_transfer_candidates'),
                    0x0116b61c if m=='xs10' else 0x0113fb3c))
        vals.append({'model':m,**b,**c,**recv,**clone,
                     'GUI_to_staging_caller_bl_validated':a,
                     'actual_queue_delivery_observed':False,
                     'GUI_to_runtime_P_pointer_identity_known':False,
                     'initial_P_plus_581_writer_identified':False,
                     '4K60_sensor_or_Main10_recording_proven':False,
                     'ROM_patch_USB_FF80_RAM_flash_or_camera_operations':False})
    return {'models':vals,'source':'original ROM + local read-only Ghidra; SHA previous phases',
           'sender_stage_then_enqueue_attempt_proven_both_models':True,
           'conditional_receiver_0x20B_handler_static_proven_both_models':True,
           'unresolved_queue_decode_and_P_alias':True,
           'Fujifilm_vendor_ROM_and_private_Ghidra_not_uploaded':True}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(ap.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE53 ORIGINAL GUI -> FULL SNAPSHOT -> MODULE7 0x20B QUEUE ATTEMPT PASS')
    print('NOT PROVEN: delivered/decode, descriptor 0x20B source, GUI=P or Main10/4K60.')
if __name__=='__main__':main()
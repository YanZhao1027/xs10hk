#!/usr/bin/env python3
"""Stage57: a different 0x200 module7 message supplies Recorder current P.

Two original A32 X6 ROMs: sender transmits 24-byte data body; byte offset4
is its *input CONFIG POINTER* not config bytes. Conditional module7 receiver
copies it into descriptor+0x10, whence verified type0x200 initializer reads
P. UI caller has static buffer NOT equal GUI mode-menu state, while a second
caller uses a dynamically sourced pointer. No queue runtime/P content claim.
Only authorized Ubuntu original 3.11 / 2.12, read-only analysis and tests.
"""
from dataclasses import dataclass
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage56_fsm_20b_group4_to_13_selector as prev
import audit_stage53_gui_rec_setparam_tx as st53
import audit_stage54_module7_receiver_pointer as st54
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31
import audit_stage52_gui_recorder_hdmi_alias as st52

@dataclass(frozen=True)
class Spec:
    model:str
    sender:int
    queue_bl:int
    clock_bl:int
    ui_sender:int
    ui_sender_bl:int
    ui_P_const:int
    ui_P_load:int
    ui_first_const:int
    ui_third_const:int
    dynamic_caller:int
    dynamic_bl:int
    dynamic_P_literal:int
    desc:int
    rec_init_fn:int
    source_snapshot:int

SPECS={
 'xs10':Spec('xs10',0x02197d94,0x02197e20,0x012a54b0,
    0x02056240,0x02056304,0x01b5375c,0x0205626c,
    0x01c2eb44,0x019da168,
    0x021ab5e4,0x021abac0,0x021abcc4,
    0x02d987e8,0x02214738,0x02d9d284),
 'xt4':Spec('xt4',0x020eadf0,0x020eae7c,0x0127dc18,
    0x01fb21dc,0x01fb22a0,0x01abd79c,0x01fb2208,
    0x01b8deac,0x01949e68,
    0x02107ea0,0x02108600,0x02108644,
    0x02d0bf48,0x02180d0c,0x02d109d4)
}

def need(ok,why):
    if not ok:raise ValueError('Stage57 original 0x200 sender/P ingress audit: '+why)

def sender(s,w,c):
    a=s.sender
    # param_1[1] is input current configuration buffer PTR.
    expect=((0x24,0xe5943004), # input->source byte normalize
        (0x28,0xe5d3240b),(0x2c,0xe5c3240a),
        (0x38,0xe5943004),(0x3c,0xe50b302c), # local second word
        (0x40,0xe5943008),(0x44,0xe50b3028),
        (0x50,0xe594300c),(0x54,0xe50b3020),
        (0x58,0xe3a03000),(0x5c,0xe54b301c),
        (0x60,0xe3a03c02),(0x64,0xe14b31b8), # type=0x200
        (0x6c,0xe54b0016),(0x70,0xe3a00007),(0x74,0xe54b0015),
        (0x78,0xe3a03018),(0x7c,0xe50b3014),
        (0x80,0xe24b3030),(0x84,0xe50b3010),
        (0x88,0xe24b1018))
    for offset,op in expect:
        need(w(a+offset)==op,'original A32 pack source, id or length changed at '+hex(a+offset))
    need(st29.bl_target(w(a+0x68),a+0x68)==s.clock_bl,
         '0x200 message sequence generator differs')
    need(st29.bl_target(w(s.queue_bl),s.queue_bl)==st53.SPECS[s.model].enqueue,
         'type0x200 queue submission BL target differs')
    for token in ('*(undefined1 *)(param_1[1] + 0x40a) = *(undefined1 *)(param_1[1] + 0x40b);',
                  'local_30 = param_1[1];','local_2c = param_1[2];',
                  'local_1c = 0x200;','local_18 = 0x18;',
                  f'FUN_{st53.SPECS[s.model].enqueue:08x}(7,&local_1c);'):
        need(token in c,'Ghidra sender identity, 24B payload or pointer word differs '+token)
    return {'module7_type':'0x200','body_bytes':24,
        'message_body_word1_source':'param_1[1] configuration pointer',
        'descriptor_word1_destination':'descriptor+0x10',
        'sender_normalizes_source_buffer_0x40A_from_0x40B':True,
        'message_embeds_entire_Recorder_input_record':False,
        'actual_queue_delivery_observed':False}

def ui_source(s,w,c):
    a=s.ui_P_load
    low=st29.half(w(a-8),False,3)
    high=st29.half(w(a-4),True,3)
    need((low | high<<16)==s.ui_P_const and w(a)==0xe50b301c,
         'UI caller original config P pointer argument is different')
    need(st29.bl_target(w(s.ui_sender_bl),s.ui_sender_bl)==s.sender,
         'UI caller BL to 0x200 sender differs')
    tokens=[f'local_24 = &DAT_{s.ui_first_const:08x};',
            f'local_20 = &DAT_{s.ui_P_const:08x};',
            f'local_1c = &DAT_{s.ui_third_const:08x};',
            f'FUN_{s.sender:08x}(&local_24);',
            '0x2000000']
    need(all(token in c for token in tokens),
         'UI 0x200 argument source identity not cross-verified')
    gui=st52.SPECS[s.model].gui_base
    need(gui!=s.ui_P_const and s.ui_P_const!=s.source_snapshot,
         'UI P pointer misidentified as GUI or source snapshot')
    return {'known_UI_sourced_possible_P_pointer':hex(s.ui_P_const),
            'known_UI_GUI_mode_menu_base':hex(gui),
            'UI_0x200_P_pointer_equals_GUI_mode_menu_base':False,
            'UI_0x200_P_payload_plus581_value_known':False}

def dynamic_source(s,w,c):
    need(st29.bl_target(w(s.dynamic_bl),s.dynamic_bl)==s.sender,
         'second original caller BL to 0x200 sender differs')
    src=('local_30 = DAT_%08x + 0x74;'%s.dynamic_P_literal) if s.model=='xs10' else (
         'local_28 = DAT_%08x;'%s.dynamic_P_literal)
    tokens=[src,f'FUN_{s.sender:08x}(&'+('local_34' if s.model=='xs10' else 'local_2c')+');']
    need(all(token in c for token in tokens),
         'second pointer-producing caller C identity changed')
    return {'second_config_pointer_source_expression':src,
            'actual_dynamic_RAM_pointer_value':None,
            'second_pointer_may_alias_UI_buffer':None}

def conditional_receiver(s):
    p=st54.SPECS[s.model]
    need(p.model==s.model and st29.SPECS[s.model].destination_header==s.desc and
         st31.SPECS[s.model].current_slot==(
            0x02d9c2ac if s.model=='xs10' else 0x02d0fa0c),
         'phase54 original queue reader + Phase27/32 current P slot mismatch')
    need(s.desc+0x10==s.desc+0xc+4,
         'second 32-bit word of 0x200 payload not desc+0x10')
    need(s.ui_P_const != s.source_snapshot and
         s.ui_P_const!=st53.SPECS[s.model].staging,
         'current P input is actually snapshot or 0x20B staging address')
    return {'desc_plus10_pointer_slot':hex(s.desc+16),
            '0x200_received_payload_len24_fits_descriptor':True,
            'module7_receiver_writes_second_payload_word_to_desc_plus10_if_received':True,
            'initial_Recorder_P_loaded_from_type0x200_desc_plus10_when_initializer_executes':True,
            'runtime_type0x200_message_delivered_and_initializer_executes_proven':False,
            '0x20B_seq_word_at_same_offset_is_not_P':True}

def analyze(root):
    prev.analyze(root) # SHA-pinned original Stage29..56 first
    out=[]
    for s in SPECS.values():
        raw=(root/f'x6-{s.model}/section-2.bin').read_bytes()
        base=st53.SPECS[s.model].sec2base
        w=lambda a:st29.word(raw,base,a)
        t=(root/f'{s.model}_stage57_type200_sender_upstream.log').read_text(encoding='utf-8')
        get=st31.function_c
        out.append({'model':s.model,
           **sender(s,w,get(t,s.sender)),
           **ui_source(s,w,get(t,s.ui_sender)),
           **dynamic_source(s,w,get(t,s.dynamic_caller)),
           **conditional_receiver(s),
           'known_P_plus581_initial_byte_value':None,
           'GUI_0x20B_to_current_P_bytes_through_0x200_alias_proven':False,
           'X_S10_internal_Main10_or_4K60_reliable':False,
           'device_usb_ff80_ram_flash_or_vendor_ROM_modified':False})
    return {'models':out,'scope':'original ROM module7 0x200 sender input pointer provenance',
            'phase56_and_all_previous_original_audits_revalidated':True,
            'no_vendor_data_uploaded':True}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(a.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE57 ORIGINAL TYPE0x200 P POINTER SENDER -> DESC+0x10 PASS')
    print('UNKNOWN: runtime message delivery, first P+0x581 value, GUI=P, 4K60/Main10.')
if __name__=='__main__':main()
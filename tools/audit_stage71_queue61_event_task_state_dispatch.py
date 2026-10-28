#!/usr/bin/env python3
"""Phase71: X-S10/X-T4 original queue 0x61 task and stateful reply dispatch.

Read-only X6 ARM and private Ghidra logs. Proves the *conditional static*
registration/response enqueue/dequeue/event row7-state4 callback-into-state5
edges, NOT successful runtime queue delivery, a hardware interface->Movie
recording link, Main10 SPS, or any change to Fujifilm firmware/camera.
"""
import argparse,json,sys
from pathlib import Path
from dataclasses import dataclass
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage70_interface_reverse_resolver_response as st70
import audit_stage59_movie_menu_ROM_allowlist as st59
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_codec_forward_stage32 as st32

@dataclass(frozen=True)
class Spec:
    model:str
    event_id:int
    first_event:int
    table:int
    state_var:str
    input_var:str
    task_register:int
    task_alloc:int
    task_alloc_BL:int
    task_alloc_helper:int
    task_create_BL:int
    task_create_helper:int
    task_entry:int
    task_entry_ref:int
    task_init:int
    sender:int
    sender_BL:int
    send_helper:int
    dequeue_BL:int
    dequeue_helper:int
    callback:int
    priority_select:int
    callback_priority_BL:int
    priority_table:int
    callback_request:int
    callback_request_BL:int
    start_request_alt:int
    sender_message_label:str
    event_entry_label:str
    state5_label:str
    descriptor_label:str
    statevar_zero:str

SPECS={
 'xs10':Spec('xs10',0x1795,0x178e,0x0162e138,
  'DAT_01c84f88','_DAT_01c84f50',
  0x01268ec0,0x012a5d2c,0x01268ee8,0x012a5d2c,
  0x01268f38,0x012a4ff0,0x0126c02c,0x01268f20,
  0x0126bf9c,0x0126b7e0,0x0126b910,0x012a6084,
  0x0126c0b8,0x012a62d0,0x0126bdc4,0x01269b80,
  0x0126bdfc,0x0162dde4,0x012b9f2c,0x0126be20,
  0x80d9,'local_38','&DAT_0162e13c','DAT_01c84f88 = 5;',
  '&DAT_0162dddc','DAT_01c84fb4'),
 'xt4':Spec('xt4',0x17a7,0x17a0,0x0160605c,
  'DAT_01be5054','_DAT_01be501c',
  0x0123f0d8,0x0127e42c,0x0123f100,0x0127e42c,
  0x0123f150,0x0127d76c,0x01242244,0x0123f138,
  0x012421b4,0x012419f8,0x01241b28,0x0127e784,
  0x012422d0,0x0127e9d0,0x01241fdc,0x0123fd98,
  0x01242014,0x01605d08,0x01292474,0x01242038,
  0x80d8,'local_38','&DAT_01606060','DAT_01be5054 = 5;',
  '&DAT_01605d00','DAT_01be5080'),
}

QUEUE=0x61
STATE_4=4
STATE_5=5
ROW_INDEX=7
ROW_STRIDE=0x1c
ROW_CALLBACKS=6


def require(ok,msg):
    if not ok:raise ValueError('STAGE71 queue0x61 event state dispatch: '+msg)


def event_row(spec,word):
    """Check original table lookup arithmetic, without executable ROM copying."""
    first=spec.table
    row=first+ROW_INDEX*ROW_STRIDE
    require(word(first)==spec.first_event,'row0 default event ID changed')
    require(word(row)==spec.event_id,'row7 outgoing event ID differs')
    callbacks=[word(row+4+i*4) for i in range(ROW_CALLBACKS)]
    expected=[0,0,0,0,spec.callback,0]
    require(callbacks==expected,'event row7 callback column4 changed')
    require(row+4+4*STATE_4==spec.table+4+(ROW_INDEX*7+STATE_4)*4,
            'original 7-word row*state lookup does not index callback')
    return {'event_row':ROW_INDEX,'event_ROM_addr':hex(row),
            'event_value':hex(spec.event_id),
            'event_state4_callback_cell':hex(row+4+4*STATE_4),
            'other_event_row_callbacks_zero':True,
            'state4_callback':hex(spec.callback)}


def original_arm(spec,word):
    edges={
        spec.task_alloc_BL:spec.task_alloc_helper,
        spec.task_create_BL:spec.task_create_helper,
        spec.sender_BL:spec.send_helper,
        spec.dequeue_BL:spec.dequeue_helper,
        spec.callback_priority_BL:spec.priority_select,
        spec.callback_request_BL:spec.callback_request,
    }
    for src,target in edges.items():
        require(st29.bl_target(word(src),src)==target,
                'raw A32 BL target differs at '+hex(src))
    require(spec.task_register<=spec.task_alloc_BL<spec.task_create_BL<spec.task_register+152 and
            spec.sender<=spec.sender_BL<spec.sender+1492 and
            spec.task_entry<=spec.dequeue_BL<spec.task_entry+176 and
            spec.callback<=spec.callback_priority_BL<spec.callback_request_BL<spec.callback+180,
            'registered, sender, queue receiver or callback BL lies outside expected original function')
    return {'original_ARM_BL_edges':len(edges),
       'task_create_queue':hex(QUEUE),
       'same_queue_sender_and_receiver':True,
       'runtime_task_creation_and_queue_delivery_observed':False}


def ordered(text,patterns,where):
    cursor=0
    for p in patterns:
        loc=text.find(p,cursor)
        require(loc>=0,where+' ordered statement absent: '+p)
        cursor=loc+len(p)


def check_decompiled(spec,registration,source,receiver,callback,
                     send_wrapper,recv_wrapper,xrefs):
    reg=[
       f'iVar1 = FUN_{spec.task_alloc_helper:08x}(0x61,&local_18);',
       'if (iVar1 == 0)',
       'local_34 = 0x61;',
       f'local_30 = {spec.descriptor_label};',
       'local_2c = 7;',
       'local_28 = 0xc00;',
       f'local_24 = FUN_{spec.task_entry:08x};',
       f'iVar1 = FUN_{spec.task_create_helper:08x}(&local_34);',
    ]
    ordered(registration,reg,'task register')
    require('uVar2 = 0xffffff01;' in registration and
            'uVar2 = 0;' in registration,'task registration failure/success split missing')
    tail=source[source.rfind(f'{spec.state_var} = 4;'):]
    require(tail and len(tail)<4000,'no state4 before sender')
    sent=[f'{spec.state_var} = 4;',
          f'{spec.sender_message_label} = 0x{spec.event_id:x};',
          'local_36 = 0x61;',
          'local_35 = 0x61;',
          f'FUN_{spec.send_helper:08x}(0x61,&{spec.sender_message_label});']
    ordered(tail,sent,'sensor packet -> event enqueue')
    receive=[
       f'FUN_{spec.task_init:08x}(*param_1);',
       f'FUN_{spec.dequeue_helper:08x}(0x61,&{spec.input_var[1:]},0xffffffff)',
       f'if ({spec.input_var} == 0x{spec.first_event:x})',
       f'iVar3 = 0x{spec.table:x};',
       'psVar1 = (short *)(iVar3 + 0x1c);',
       f'while (*psVar1 != {spec.input_var});',
       f'({spec.event_entry_label} + (iVar2 * 7 + (uint){spec.state_var}) * 4)',
    ]
    # The decompiler may phrase the table access as + (iVar2 * 7 +
    # state)*4, but must preserve its actual untrusted state selection.
    for p in receive[:6]:
        require(p in receiver,'receiver queue/ROM loop not confirmed '+p)
    require(f'{spec.event_entry_label} + (iVar2 * 7 + (uint){spec.state_var}) * 4)' in receiver,
            'state+7*row receiver function pointer lookup changed')
    require('iVar2 = iVar2 + 1;' in receiver and
            f'(*psVar1 != {spec.input_var})' in receiver and
            'if (*psVar1 == 0)' in receiver,
            'receiver event row scan or terminator differs')
    tailcb=callback[callback.find(spec.state5_label):]
    require(tailcb and tailcb.startswith(spec.state5_label),
            'event row7 callback does not set state5')
    require(f'FUN_{spec.priority_select:08x}(&DAT_{spec.priority_table:08x});' in tailcb,
            'state5 callback no longer calls interface priority resolver')
    require('local_48 = 0x13;' in tailcb and
            f'local_48 = 0x{spec.start_request_alt:x};' in tailcb and
            tailcb.count(f'FUN_{spec.callback_request:08x}(&local_48);')==2,
            'state5 callback follow-up control request branches shifted')
    require('if (*(int *)' in send_wrapper and
            'if (iVar1 == 0)' in send_wrapper and
            'local_1c[0]' in send_wrapper and
            'return iVar1;' in send_wrapper,
            'queue send wrapper does not retain fail-closed return path')
    require('func_0x00053c4c(param_1,local_1c)' in recv_wrapper and
            'else if (iVar1 == 0)' in recv_wrapper and
            'return iVar1;' in recv_wrapper,
            'queue receiver wrapper no success/timeout distinction')
    require(f'PROBE_TARGET addr={spec.task_entry:08x} refs=1' in xrefs and
            f'PROBE_REF from={spec.task_entry_ref:08x} to={spec.task_entry:08x} type=DATA' in xrefs,
            'registered task entry callback not observed as direct original reference')
    return {'task_registered_with_0x61_and_entry_callback':True,
       'handler_sets_state4_before_0x61_sender_attempt':True,
       'receiver_reads_0x61_and_selects_7wide_ROM_event_matrix':True,
       'row7_state4_calls_state5_callback_if_state_unchanged':True,
       'state5_triggers_priority_selection_and_one_of_two_requests':True,
       'actual_OS_delivery_callback_invocation_and_Movie_link_proven':False}


def function(log,addr):return st59.function_c_any(log,addr)


def analyze(root):
    st70.analyze(root)
    entries=[]
    for model,spec in SPECS.items():
        one=(root/f'x6-{model}/section-1.bin').read_bytes()
        W=lambda addr:st32.rom_word(one,st59.BASE,addr)
        reg=function((root/f'{model}_stage71_task_register_0x61.log').read_text(),spec.task_register)
        send_log=(root/f'{model}_stage70_sensor_resolver_pipeline.log').read_text()
        source=function(send_log,spec.sender)
        recv=function((root/(f'{model}_stage71_'+('1795' if model=='xs10' else '17a7')+
                '_event_table_registration.log')).read_text(),spec.task_entry)
        cb=function((root/(f'{model}_stage71_'+('1795' if model=='xs10' else '17a7')+
                '_callback_handlers.log')).read_text(),spec.callback)
        wrapper=(root/f'{model}_stage71_queue_0x61_sender_receive_wrapper.log').read_text()
        snd=function(wrapper,spec.send_helper)
        rcv=function(wrapper,spec.dequeue_helper)
        xrefs=(root/f'{model}_stage71_task_recv_entry_refs.log').read_text()
        entries.append({'model':model,**event_row(spec,W),**original_arm(spec,W),
             **check_decompiled(spec,reg,source,recv,cb,snd,rcv,xrefs),
             'camera_firmware_modified_or_live_sensor_readout':False})
    require(entries[0]['event_row']==entries[1]['event_row']==7,
            'original same event row not found in both models')
    return {'models':entries,'prior_original_ROM_Phase70_and_all_sha_pinned_stages_pass':True,
        'static_response_to_0x61_queue_to_state4_to_state5_closed':True,
        'runtime_success_sensor_2160P_60_HEVC_Main10_not_established':True,
        'USB_FF80_camera_RAM_flash_ROM_DAT_writes':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE71 ORIGINAL 0x61 QUEUE TASK -> EVENT ROW7 STATE4 -> STATE5 CALLBACK PASS')
    print('UNKNOWN: actual queue delivery, runtime state stability, Movie/sensor/ISP VPU bridge.')
if __name__=='__main__':main()
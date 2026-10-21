#!/usr/bin/env python3
"""Phase54 offline proof: GUI 0x20B packet → module7 receive descriptor (conditional).

This is a STATIC ARM/Ghidra data-flow audit, NOT evidence of real-device
message delivery, P-slot alias, successful codec configuration, Main10 or 4K60.
Authorized private Fuji X6 originals and Ghidra logs stay ONLY on Ubuntu.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,struct,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage53_gui_rec_setparam_tx as st53
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

@dataclass(frozen=True)
class Spec:
 model:str;rom2:int;init:int;init_ptr_setup:int;taskid:int;task_callback:int;task_registration:int
 callback:int;task_create:int;receive:int;receive_call:int;precheck:int;precheck_call:int
 loop_memcpy:int;fsm_call:int;fsm:int;recv_api:int;os_get:int;api_copy:int
 filter_table:int;filter_fn:int;filter_wrapper:int;receiver_20b:int;consumer_call:int
 source_snapshot:int;dest_literal:int;length:int

SPECS={
 'xs10':Spec('xs10',0x01eaf000,0x021b8344,0x021b84c0,0x021b84fc,0x021b8520,0x021b8538,
   0x021c549c,0x012a4ff0,0x021c549c,0x021c54d0,0x0225e9a8,0x021c54ec,
   0x021c5508,0x021c54c0,0x021b8b9c,0x012a62d0,0x012a62e8,0x012a637c,
   0x02690d40,0x02279708,0x0225e9a8,0x0221c934,0x021cdf8c,
   0x02d9d284,0x0221ca10,0x5dc),
 'xt4':Spec('xt4',0x01e0f000,0x02120c20,0x02120d9c,0x02120dd8,0x02120dfc,0x02120e14,
   0x0212ea80,0x0127d76c,0x0212ea80,0x0212eab4,0x021cb620,0x0212ead0,
   0x0212eaec,0x0212eaa4,0x02121478,0x0127e9d0,0x0127e9e8,0x0127ea7c,
   0x025efab4,0x021e7374,0x021cb620,0x02189348,0x02137558,
   0x02d109d4,0x02189424,0x5d8)
}

def need(value,why):
 if not value:raise ValueError('Stage54 original module7/0x20B receiver audit: '+why)

def wrd(section,base,at):return st29.word(section,base,at)

def bl(w,site,target):need(st29.bl_target(w(site),site)==target,'BL differs at '+hex(site))

def half(w,a,r,high):return st29.half(w(a),high,r)

def bound_c(log,addr):return st31.function_c(log,addr)

def check_task_registration(s,w,c):
 desc=st29.SPECS[s.model].destination_header
 a=s.init_ptr_setup
 need(half(w,a,3,False)|(half(w,a+4,3,True)<<16)==desc,
      'descriptor head pointer construction differs')
 for addr,opcode in ((a+8,0xe3a02044),(a+12,0xe5832004),
                     (a+16,0xe283200c),(a+20,0xe5832008),
                     (s.taskid,0xe3a03007),(s.taskid+4,0xe50b3030),
                     (s.task_callback+8,0xe50b3020)):
  need(w(addr)==opcode,'task registration / 0x44 / header+8 pointer setup at '+hex(addr))
 cb=half(w,s.task_callback,3,False)|(half(w,s.task_callback+4,3,True)<<16)
 need(cb==s.callback,'registered reccont callback pointer differs')
 bl(w,s.task_registration,s.task_create)
 need(all(v in c for v in ('_DAT_%08x = 0x44'%(desc+4),
                         '_DAT_%08x = &DAT_%08x'%(desc+8,desc+12),
                         'local_34 = 7',
                         'local_24 = FUN_%08x'%s.callback,
                         'FUN_%08x(&local_34)'%s.task_create)),
      'Ghidra module7 reccont task registration or descriptor body pointer inconsistent')
 return {'module7_receiver_task_function':hex(s.callback),
         'registered_descriptor_destination_pointer_initial':hex(desc+12),
         'descriptor_header_plus8_is_pointer_to_plus0C_original_ARM':True,
         'declaration_payload_capacity_0x44_original_ARM':True}

def check_receive_api(s,w1,c):
 a=s.api_copy
 need(bl_target(w1,s.os_get)==0x00053c4c,'external receive queue get BL mismatch')
 delta=0x012a6374 if s.model=='xs10' else 0x0127ea74
 load_length=delta-0x50; nonzero=delta-0x48
 for addr,opcode in ((load_length,0xe5912004),(load_length+4,0xe3520000),
                     (nonzero,0x1a000010),(delta,0xe2811008),
                     (delta+4,0xe5950008)):
  need(w1(addr)==opcode,'recv original load LEN + source(+8) dest(header+8) mismatch '+hex(addr))
 bl(w1,a,st53.SPECS[s.model].memcpy)
 tokens=[
  'func_0x00053c4c(param_1,local_1c)',
  '*(undefined4 *)(param_2 + 2) = *(undefined4 *)(local_1c[0] + 2)',
  'FUN_%08x(*(undefined4 *)(param_2 + 4),local_1c[0] + 4)' % st53.SPECS[s.model].memcpy,
  'func_0x00050aac(param_1,local_1c[0])',
 ]
 need(all(token in c for token in tokens),'Ghidra queue decoder head/size/body or post-ack inconsistent')
 return {'receive_helper_queue_data_source':'message+8',
         'receive_helper_queue_data_target':'*(receiver_descriptor+8)',
         'original_ARM_payload_size_from_message_header_plus4':True,
         'OS_queue_receipt_actual_runtime_observed':False}

def bl_target(w,site):return st29.bl_target(w(site),site)

def check_receive_loop(s,w,c):
 desc=st29.SPECS[s.model].destination_header
 a=s.receive_call
 cb=s.callback
 before=a-0x24
 for addr,opcode in ((a-0xc,0xe1a02005),(a-8,0xe1a01004),
                     (a-4,0xe3a00007),(a+4,0xe3500000),
                     (a+8,0x1afffff8),
                     (s.precheck_call+4,0xe3500001),
                     (s.precheck_call+8,0x0afffff2),
                     (s.loop_memcpy,0xe5942004),
                     (s.loop_memcpy+4,0xe5941008),
                     (s.loop_memcpy+8,0xe1a00006)):
  need(w(addr)==opcode,'module7 receiver header/memcpy branch differs '+hex(addr))
 init_movw=a-0x24
 need((half(w,init_movw,4,False)|(half(w,init_movw+4,4,True)<<16))==desc,
      'queue receive loop static header address differs')
 need(w(a-0x18)==0xe284600c,'payload final dest != descriptor+0xC')
 bl(w,a,s.recv_api)
 bl(w,s.precheck_call,s.precheck)
 bl(w,s.loop_memcpy+12,st53.SPECS[s.model].memcpy)
 bl(w,s.fsm_call,s.fsm)
 need(('FUN_%08x(7,&DAT_%08x,0xffffffff)'%(s.recv_api,desc)) in c and
      ('FUN_%08x(&DAT_%08x,_DAT_%08x,_DAT_%08x)'%
       (st53.SPECS[s.model].memcpy,desc+12,desc+8,desc+4)) in c and
      ('FUN_%08x(&local_24)'%s.precheck) in c and
      ('FUN_%08x()'%s.fsm) in c,
      'Ghidra reccont queue loop / variable payload copy / FSM call differs')
 return {'module7_receive_success_conditional_descriptor_payload':hex(desc+12),
         'message_body_8_bytes_first_word_is_sender_staging_pointer_if_delivery':True,
         'message_body_second_word_overwrites_descriptor_plus10_not_Pslot':True,
         'precheck_has_skip_path':True,
         'call_to_state_machine_after_passing_precheck':True}

def check_filter(s,b2,w,cfilter,cwrap,exception_c=""):
 base=s.rom2;seen=[];off=s.filter_table-base
 need(off>=0 and off<len(b2),'filter table not in original ROM section')
 for k in range(512):
  idx=off+k*16
  need(idx+16<=len(b2),'filter table runs off ROM')
  raw=struct.unpack_from('<H',b2,idx)[0]
  if raw==0:break
  seen.append(raw)
 else:raise ValueError('original filter table has no terminator')
 need(len(seen)>=100,'special handler filter table implausibly short')
 need(0x20b not in seen,'0x20B is intercepted by special filter list: no normal receiver assumption')
 if s.model=='xs10':
  need(('&DAT_%08x'%s.filter_table) in cfilter and
       'return 0;' in cfilter,'XS10 special message precheck no longer defaults to zero')
  need('FUN_%08x(param_1)'%s.filter_fn in cwrap,
       'XS10 special message precheck not invoking its table scanner')
 else:
  need('if (*param_1 == 0x123a)' in exception_c and
       'FUN_021f1e28(param_1)' in cwrap and
       ('FUN_%08x(param_1)'%s.filter_fn) in cwrap,
       'XT4 0x123A exceptional dispatch or 20B default branch changed')
  need(('&DAT_%08x'%s.filter_table) in cfilter and
       'return 0;' in cfilter,'XT4 special message table scanner no longer defaults to zero')
 return {'special_message_static_table_entry_count':len(seen),
         'special_message_table_contains_0x20B':False,
         '20B_normal_recv_loop_path_in_original_code':True,
         'module7_delivery_or_thread_schedule_observed':False}

def check_snapshot_consumer(s,w,c,owner):
 desc=st29.SPECS[s.model].destination_header
 spec53=st53.SPECS[s.model]
 if s.model=='xs10':
  typ=0x0221c95c;source=0x0221c9e4;length=0x0221c9fc;data=0x0221ca04;cont=0x021cdf80
 else:
  typ=0x02189370;source=0x021893f8;length=0x02189410;data=0x02189418;cont=0x0213754c
 need(w(typ)==0xe300320b and w(typ+4)==0xe1520003,'snapshot consumer not type 0x20B')
 need(w(source)==0xe593100c and w(length)==0xe3002000|s.length,
      'snapshot consumer no longer loads descriptor+0xC or full record length')
 need(st29.word(owner,s.rom2,s.dest_literal)==s.source_snapshot,
      'consumer destination not Recorder source snapshot prior Phase26')
 bl(w,data,spec53.memcpy)
 bl(w,s.consumer_call,s.receiver_20b)
 need(('_DAT_%08x == 0x20b'%desc) in c and
      ('FUN_%08x(DAT_'%spec53.memcpy) in c and
      ('_DAT_%08x,0x%x'%(desc+12,s.length)) in c,
      'consumer Ghidra C does not show conditional descriptor+0xC memcpy')
 return {'descriptor_conditional_source_pointer':'descriptor+0x0C',
         'recorder_source_snapshot_destination':hex(s.source_snapshot),
         'conditional_consumer_original_ARM_proven':True,
         'conditional_consumer_control_flow_after_same_queue_message_proven':False,
         'recorder_active_P_changed_from_GUI_proven':False}

def analyze(root):
 st53.analyze(root)
 out=[]
 for s in SPECS.values():
  b1=(root/f'x6-{s.model}/section-1.bin').read_bytes()
  b2=(root/f'x6-{s.model}/section-2.bin').read_bytes()
  w=lambda at:wrd(b2,s.rom2,at)
  w1=lambda at:wrd(b1,0x01021000,at)
  log=lambda suffix:(root/f'{s.model}_{suffix}.log').read_text(encoding='utf-8')
  init=bound_c(log('stage54_recorder_dispatch_baseline'),s.init)
  loop=bound_c(log('stage54_reccont_module7_handler'),s.receive)
  helper=bound_c(log('stage54_ipc_receiver_stage2'),s.recv_api)
  fil=bound_c(log('stage54_precheck_dispatch_gate'),s.filter_fn)
  wrap=bound_c(log('stage54_ipc_receiver_stage2'),s.filter_wrapper)
  consumer=bound_c(log('stage53_candidate_20b_receivers'),s.receiver_20b)
  out.append({'model':s.model,
              **check_task_registration(s,w,init),
              **check_receive_api(s,w1,helper),
              **check_receive_loop(s,w,loop),
              **check_filter(s,b2,w,fil,wrap,
                bound_c(log('stage54_precheck_dispatch_gate'),0x021f1e28) if s.model=='xt4' else ""),
              **check_snapshot_consumer(s,w,consumer,b2),
              'GUI_snapshot_to_recorder_descriptor_pointer_static_chain_if_delivered':True,
              'GUI_snapshot_to_Recorder_source_snapshot_static_chain_if_consumer_event':True,
              'configuration_message_also_initializes_type0x200_P_proven':False,
              'module7_actual_queue_delivery_observed':False,
              'codec_bitdepth_Main10_SPS_or_4K60_hardware_proven':False,
              'ROM_patch_or_camera_access':False})
 return {'phase':54,'models':out,'vendor_binary_disclosure':False,
         'only_original_ROM_read_and_synthetic_tests':True,
         'all_dynamic_or_hardware_unverified_flags':False,
         'discovery':'module7 reccont receiver callback + embedded pointer queue payload -> descriptor+0x0C; conditional 0x20B snapshot consumer'}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=Path('output'))
 result=analyze(p.parse_args().output)
 print(json.dumps(result,ensure_ascii=False,indent=2))
 print('STAGE54 ORIGINAL MODULE7 RECEIVE→DESCRIPTOR PTR AND CONDITIONAL SNAPSHOT PASS')
 print('NO RUNTIME PROOF: delivery, MSG+0x10 as P, 0x200 reinitialization, Main10, 4K60.')
if __name__=='__main__':main()
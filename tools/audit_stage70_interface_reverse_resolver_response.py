#!/usr/bin/env python3
"""Phase70: audited interface-mode reverse ID lookup and conditional queue response.

X-S10 FW3.11/X-T4 FW2.12 original section1 read-only static ROM, not
an X-S10 hardware 4K60 or HEVC Main10 capability or firmware patch.
"""
import argparse,json,sys,re
from pathlib import Path
from dataclasses import dataclass
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage69_interface_default_priority_runtime_override as st69
import audit_stage59_movie_menu_ROM_allowlist as st59
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_codec_forward_stage32 as st32

@dataclass(frozen=True)
class Spec:
    model:str
    record_start:int
    record_end:int
    resolver:int
    resolver_pointer_literal:int
    priority_RAM:int
    processor:int
    processor_size:int
    chooser:int
    resolver_call:int
    chooser_call:int
    queue_call:int
    queue_func:int
    priority_ptr_name:str
    row_name:str
    end_name:str
    response_buffer:str
    status_field:str

SPECS={
 'xs10':Spec('xs10',0x0162de08,0x0162e048,0x01269520,0x01269630,
   0x01c856a3,0x0126b7e0,1492,0x0126b508,0x0126b8a8,
   0x0126b89c,0x0126b910,0x012a6084,'DAT_01269630',
   'DAT_0162de08','0x162e048','DAT_0126bdb8','DAT_0162de0f'),
 'xt4':Spec('xt4',0x01605d2c,0x01605f6c,0x0123f738,0x0123f848,
   0x01be576f,0x012419f8,1492,0x01241720,0x01241ac0,
   0x01241ab4,0x01241b28,0x0127e784,'DAT_0123f848',
   'DAT_01605d2c','0x1605f6c','DAT_01241fd0','DAT_01605d33'),
}

def need(ok,msg):
    if not ok:raise ValueError('STAGE70 original reverse resolver: '+msg)

def decode_rows(raw):
    need(len(raw)==36*16,'36 x16 resolver record bytes not exact')
    result=[]
    for i in range(36):
        r=raw[i*16:(i+1)*16]
        need(r[0]==i,'record-index prefix differs from ROM row index')
        result.append({'index':r[0],'group':r[1],'id':r[2],
            'subcode':r[3],'runtime_gate':r[4],
            'numeric_rate':r[12], 'opaque_tail':r[1:]})
    need(tuple(x['numeric_rate'] for x in result if x['index'] in (0,3,5,11,22,23,34,35))==(60,)*8,
         'numeric60 interface descriptor indices changed')
    for i,j,k in ((12,13,93),(22,23,97),(34,35,102)):
        need(result[i]['id']==result[j]['id']==k and
             result[i]['opaque_tail']==result[j]['opaque_tail'],
             'duplicate resolver rows do not differ by index only')
    return result

def select_reverse(rows,priority,primary_id,secondary_subcode):
    """Model original Ghidra loop: table-order scan and priority *membership*.

    The candidate-list order does not decide the winner in this inverse
    resolver. A matching row present in the list overrides earlier rows;
    without any in-list match the first matching fallback persists.
    This is separate from the forward candidate chooser's ordered scan.
    """
    need(all(0<=v<36 for v in priority),'synthetic priority index out of range')
    result=0x25
    members=set(priority)
    for field,value in (('subcode',secondary_subcode),('id',primary_id)):
        if value==0:continue
        for rec in rows:
            if rec[field]==value:
                if result==0x25:result=rec['index']
                if rec['index'] in members:result=rec['index']
    return result

def original_rom(spec,one):
    need(spec.record_end-spec.record_start==36*16,'record range shifted')
    base=st59.BASE
    rows=decode_rows(one[spec.record_start-base:spec.record_end-base])
    old=st69.SPECS[spec.model]
    need(old.descriptor==spec.record_start+2,
         'prior Phase69 interface ID pointer changed vs resolver record start')
    default=st69.decode_priority(one[old.priority-base:old.priority-base+14])
    need(default==st69.DEFAULT_PRIORITY,'Phase69 priority no longer same')
    literal=st32.rom_word(one,base,spec.resolver_pointer_literal)
    need(literal==spec.priority_RAM,'resolver priority RAM literal pointer changed')
    need(select_reverse(rows,default,97,0)==22 and
         select_reverse(rows,default,102,0)==34,
         'unlisted duplicate-ID fallback not first matching ROM row')
    need(select_reverse(rows,[23],97,0)==23 and
         select_reverse(rows,[35],102,0)==35 and
         select_reverse(rows,[23,22],97,0)==23 and
         select_reverse(rows,[22,23],97,0)==23,
         'list membership/ROM-order reverse choice changed')
    need(select_reverse(rows,default,0xff,0)==0x25,
         'no-match sentinel not 0x25')
    return {'original_resolver_rows':len(rows),
       'original_row_index_prefix_0_to_35_verified':True,
       'record_prefix_two_bytes_before_Phase69_interface_ID':True,
       'runtime_priority_RAM_pointer':hex(spec.priority_RAM),
       'ID97_duplicate_indices':[22,23],
       'ID102_duplicate_indices':[34,35],
       'id97_without_duplicates_in_active_list_falls_back_to':22,
       'id97_active_list_only23_selects':23,
       'id97_active_list_order_does_not_override_ROM_order':True,
       'unmatched_return_code':'0x25',
       'record_selected_due_to_ID97_not_guaranteed_for_movie_4K59_94':True}

def function(log,addr):return st59.function_c_any(log,addr)

def check_code(spec,one,root):
    log=(root/f'{spec.model}_stage70_sensor_resolver_pipeline.log').read_text()
    resolver=function(log,spec.resolver)
    proc=function(log,spec.processor)
    required=(f'&{spec.row_name}',spec.end_name,
      '(byte)pcVar2[2] == param_1','(byte)pcVar2[3] == param_2',
      f'pcVar5 = {spec.priority_ptr_name}',
      'cVar1 == *pcVar2','cVar1 != -1',
      "cVar3 = '%';",'pcVar2 = pcVar2 + 0x10','return cVar3;')
    for x in required:need(x in resolver,'original resolver C lookup condition missing '+x)
    chooser=f'FUN_{spec.chooser:08x}({spec.response_buffer} + 4,{spec.response_buffer} + 5,{spec.response_buffer});'
    lookup=f'FUN_{spec.resolver:08x}(*(undefined1 *)(iVar6 + 4),*(undefined1 *)(iVar6 + 5));'
    result_store='*(char *)(iVar6 + -1) = (char)iVar7;'
    status=f'(&{spec.status_field})[iVar7 * 0x10]'
    reply=f'FUN_{spec.queue_func:08x}(0x61,&local_38);'
    terms=(chooser,lookup,result_store,status,'local_36 = 0x61;','local_35 = 0x61;',reply)
    locs=[proc.rfind(x) for x in terms]
    need(min(locs)>=0 and locs==sorted(locs),'handler chooser->reverse->store/status->0x61 enqueue order shifted')
    need('0x302' in proc and 'if (_DAT_' in proc,
         'handler no longer retains 0x302 response parse gate')
    W=lambda a:st32.rom_word(one,st59.BASE,a)
    for site,dest in ((spec.chooser_call,spec.chooser),
                      (spec.resolver_call,spec.resolver),
                      (spec.queue_call,spec.queue_func)):
        need(spec.processor<=site<spec.processor+spec.processor_size,
             'call site not inside expected response handler')
        need(st29.bl_target(W(site),site)==dest,
             'original A32 BL to expected interface handler/queue differs '+hex(site))
    need(spec.chooser_call<spec.resolver_call<spec.queue_call,
         'original A32 chooser/resolver/queue ordering changed')
    xrefs=(root/f'{spec.model}_stage70_resolver_event_xrefs.log').read_text()
    need(f'PROBE_TARGET addr={spec.resolver:08x} refs=5' in xrefs and
         f'PROBE_REF from={spec.resolver_call:08x} to={spec.resolver:08x} type=UNCONDITIONAL_CALL' in xrefs,
         'Ghidra original resolver crossrefs not anchored')
    return {'response_handler':hex(spec.processor),
       'chooser_BL':hex(spec.chooser_call),
       'reverse_resolver_BL':hex(spec.resolver_call),
       'result_queued_BL':hex(spec.queue_call),
       'reply_queue_channel':'0x61',
       'derived_original_A32_calls_verified':3,
       'source_message_0x302_parse_in_handler':True,
       'returns_selected_interface_record_index_to_response_buffer':True,
       'original_Ghidra_direct_resolver_xrefs':5,
       'indirect_handler_runtime_execution_observed':False,
       'response_0x61_consumed_by_Movie_2160P_FPS6_proven':False,
       'actual_runtime_supported_IDs_and_priority_received':False}

def analyze(root):
    st69.analyze(root)
    info=[]
    for name,s in SPECS.items():
        one=(root/f'x6-{name}/section-1.bin').read_bytes()
        info.append({'model':name,**original_rom(s,one),**check_code(s,one,root),
           'live_camera_USB_FF80_ROM_flash_patch':False})
    need(info[0]['original_row_index_prefix_0_to_35_verified'] and
         info[1]['original_row_index_prefix_0_to_35_verified'],'both models must verify row-index header')
    return {'models':info,'full_original_ROM_Phase69_and_prior_audits_pass':True,
        'interface_mode_ID_to_record_index_completion_message_verified_static_only':True,
        'sensor_ISR_4K60_capture_or_HEVC_Main10_SPS_observed':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE70 ORIGINAL INTERFACE ID REVERSE LOOKUP -> QUEUE 0x61 STATIC PASS')
    print('UNKNOWN: runtime delivery, interface/Movie lookup crosslink, real 4K60/Main10.')
if __name__=='__main__':main()
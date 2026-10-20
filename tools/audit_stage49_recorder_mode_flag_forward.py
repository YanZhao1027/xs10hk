#!/usr/bin/env python3
"""Stage49: original-ROM *static* config-input to active Recorder 4K flag.

For X-S10 3.11 and X-T4 2.12, cross-certify the Stage32 input descriptor,
config adapter -> intermediate -> active copy, and Stage48 active state
getter -> dynamic parent +A8E. Additionally verify the four A32 byte
transfers of input offsets 581/580/583/582 into the active template and
independent, reverse-direction snapshot export. This is NOT evidence of any
runtime input values or an unlocked camera mode. Entirely offline, read-only.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_recorder_codec_forward_stage32 as st32
import audit_stage48_recorder_a8e_flag_origin as st48

INPUT_FIELDS=(0x581,0x580,0x583,0x582)

@dataclass(frozen=True)
class Model:
    name:str
    start:int
    active_flag:int
    active_codec:int
    adapter:int
    output_exporter:int
    intermediate_flag:int

MODELS={
 'xs10':Model('xs10',0x012c9914,0x01c251d4,0x01c25208,0x012c9500,0x012be684,0x3fc),
 'xt4':Model('xt4',0x012a3560,0x01b83940,0x01b83974,0x012a313c,0x01296d38,0x400),
}

def need(condition,reason):
    if not condition: raise ValueError('Stage49 active Recorder flag forward audit: '+reason)

def expected_transfer_words(m):
    """A32 R5 input LDRB / R4 intermediate STRB; four pairs, no ROM data."""
    return [(0xe5d53000 | source,0xe5c43000 | (m.intermediate_flag+i))
            for i,source in enumerate(INPUT_FIELDS)]

def select_movie_key(movie_type,raw_flag,low=7,high=2):
    """Static predicate simulation only; NOT a hardware mode or selected fps."""
    need(type(raw_flag) is int and 0 <= raw_flag < 256,'invalid mock flag')
    return st48.compute_movie_key(movie_type,raw_flag,low,high)

def check_static_bridge(m,word_at,adapter_c,exporter_c,prior32,prior48):
    """Pure checker; external tests provide *entirely synthetic* fixtures."""
    ms=st32.MODELS[m.name]
    mr=st48.MODELS[m.name]
    need(prior32['model']==m.name and
         prior32['input_to_active_static_data_flow_edges_proven'] is True and
         prior32['intermediate_to_active_template_copy_size']==ms.copy_len,
         'Stage32 authenticated forward descriptor/active copy missing')
    need(prior32['input_offset_codec']=='0x5b0' and
         int(prior32['active_Recorder_Codec_byte'],16)==m.active_codec and
         int(prior32['intermediate_codec_address'],16)==ms.intermediate_base+ms.intermediate_codec_offset,
         'Stage32 active Codec and input identity mismatch')
    need(prior48['model']==m.name and
         int(prior48['parent_flag_a8e_source_when_4K'],16)==m.active_flag and
         prior48['4K_class_movie_types']==[4,5,6,7] and
         prior48['parent_flag_a8e_source_when_NOT_4K']==0 and
         prior48['Recorder_export_snapshot_offsets']['snap_export_source_flag_offset']=='0x581',
         'Stage48 source getter/4K class and snapshot mismatch')
    need(m.active_flag==mr.active_flag_ram and
         m.active_codec==mr.active_codec_ram and
         m.adapter==ms.adapter and m.output_exporter==mr.snapshot_exporter_fn,
         'cross-stage model identity conflict')
    need(m.intermediate_flag+0x34==ms.intermediate_codec_offset and
         ms.template_base+m.intermediate_flag==m.active_flag and
         ms.template_base+ms.intermediate_codec_offset==m.active_codec and
         m.intermediate_flag+3<ms.copy_len,
         'active template address/coverage mismatch')
    need(m.start>=ms.adapter and m.start+32<ms.adapter+1600,
         'original adapter transfer is outside function')
    # Literal contiguous original ARM bytes: LDRB R3,[R5,#in];
    # STRB R3,[R4,#out]. Require all four pairs, including companion order.
    for i,(read,write) in enumerate(expected_transfer_words(m)):
        need(word_at(m.start+8*i)==read,
             'original A32 input LDRB mismatch: '+str(i))
        need(word_at(m.start+8*i+4)==write,
             'original A32 intermediate STRB mismatch: '+str(i))
    for i,source in enumerate(INPUT_FIELDS):
        destination=m.intermediate_flag+i
        exact=('*(undefined1 *)(param_1 + 0x%x) = param_2[0x%x];' %
               (destination,source))
        need(exact in adapter_c,
             'Ghidra param_2/input -> param_1/intermediate missing: '+str(i))
        pos=adapter_c.find(exact)
        if i:
            need(pos>old_pos,'adapter flags not in verified order')
        old_pos=pos
    # Check 4 independently paired bytes for export direction (ACTIVE ->
    # output), not a mythical output buffer -> current input setter.
    exporter_sources=(m.active_flag,m.active_flag+1,m.active_flag+2,m.active_flag+3)
    for source_offset,ram in zip(INPUT_FIELDS,exporter_sources):
        need(('param_1[0x%x] = DAT_%08x;'%(source_offset,ram)) in exporter_c,
             'independent reverse exporter field differs: '+hex(source_offset))
    need(m.active_codec-m.active_flag==0x34 and
         prior48['Recorder_export_snapshot_offsets']['snap_export_source_codec_offset']=='0x5b0' and
         m.active_codec != m.active_flag,
         'codec is not 4K mode flag')
    return {
       'model':m.name,'input_source':'descriptor +0x10 pointer -> input[P+0x581]',
       'original_A32_LDRB_STRB_words_verified':8,
       'original_adapter':'FUN_%08x'%m.adapter,
       'first_original_A32_LDRB':'0x%08x'%m.start,
       'adapter_input_offsets':[hex(x) for x in INPUT_FIELDS],
       'intermediate_base':'0x%08x'%ms.intermediate_base,
       'intermediate_offsets':[hex(m.intermediate_flag+i) for i in range(4)],
       'active_template':'0x%08x'%ms.template_base,
       'original_copy_length':ms.copy_len,
       'active_flag_RAM':'0x%08x'%m.active_flag,
       'active_codec_RAM_separate':'0x%08x'%m.active_codec,
       'parent_plus_A8E_reads_this_flag_for_4K_type':True,
       'reverse_export_active_to_snapshot_plus_581_verified':True,
       'forward_input_plus_581_to_active_flag_static_path_verified':True,
       'current_input_byte_value_observed':False,
       'initial_config_input_plus_581_writer_identified':False,
       'forward_path_atomic_during_intervening_calls_proven':False,
       'external_memcpy_engine_implementation_validated':False,
       'X_S10_specific_4K60_gate_unlocked':False,
       'Main10_SPS_or_sensor_ISP_hardware_proven':False,
       'device_USB_FF80_RAM_Flash_modified':False,
    }

def phase32_check(root,m,sec1,sec2):
    read=lambda f:(root/f).read_text(encoding='utf-8')
    sm=st32.MODELS[m.name]
    return st32.audit(sm,sec1,sec2,
        read(m.name+'_stage32_descriptor_header_len_writer.log'),
        read(m.name+'_stage32_current_to_active_parent.log'),
        read(m.name+'_stage32_current_to_template_adapter.log'),
        read(m.name+'_stage32_template_update_callers.log'),
        read(m.name+'_stage32_template_copy_init.log'),
        read(m.name+'_stage32_bridge_field_xrefs.log'))

def phase48_check(root,m,sec1,sec2,old):
    rm=st48.MODELS[m.name]
    logs={
       'reset':(root/rm.reset_log).read_text(encoding='utf-8'),
       'init':(root/rm.init_log).read_text(encoding='utf-8'),
       'getters':(root/rm.getter_log).read_text(encoding='utf-8'),
       'export':(root/rm.export_log).read_text(encoding='utf-8'),
       'pointer':(root/rm.pointer_log).read_text(encoding='utf-8'),
       'xref':(root/rm.active_refs_log).read_text(encoding='utf-8')}
    return st48.check_model(rm,sec1,sec2,logs,old)

def old_json(root,name,marker):
    return json.loads((root/name).read_text(encoding='utf-8').split('\n'+marker,1)[0])

def check_both_original(root):
    prior={
       'stage46':old_json(root,'stage46_joint_mode_original_audit.jsonlog','STAGE46'),
       'stage47':old_json(root,'stage47_mode_key_codec_original_audit.jsonlog','STAGE47')}
    results=[]
    for m in MODELS.values():
        sec1=(root/f'x6-{m.name}/section-1.bin').read_bytes()
        sec2=(root/f'x6-{m.name}/section-2.bin').read_bytes()
        p32=phase32_check(root,m,sec1,sec2)
        # Includes SHA256 identity of both ROM sections, five BLs, pointer
        # registration and source getter; ensures original section identity.
        p48=phase48_check(root,m,sec1,sec2,prior)
        adapter=st32.c_function((root/f'{m.name}_runtime_430_write_sites_stage20.log').read_text(encoding='utf-8'),m.adapter)
        exporter=st32.c_function((root/f'{m.name}_stage25_snapshot_populate_pipeline.log').read_text(encoding='utf-8'),m.output_exporter)
        base=0x01021000
        word=lambda a:st32.rom_word(sec1,base,a)
        results.append(check_static_bridge(m,word,adapter,exporter,p32,p48))
    need(all(x['forward_input_plus_581_to_active_flag_static_path_verified'] for x in results),
         'not both original models proven')
    return {'source':'original SHA-pinned X-S10 3.11 / X-T4 2.12 sections, local Ghidra logs',
            'models':results,'physical_camera_access':False,
            'scope':'static input -> intermediate -> active -> 4K parent flag only'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=Path('output'),type=Path)
    opt=parser.parse_args()
    data=check_both_original(opt.output)
    print(json.dumps(data,indent=2,ensure_ascii=False))
    print('STAGE49 ORIGINAL ROM A32 + DESCRIPTOR + ACTIVE FLAG BRIDGE PASS')
    print('UNPROVEN: input flag writer/runtime value, X-S10 4K60, Main10, sensor/ISP.')
if __name__=='__main__':main()
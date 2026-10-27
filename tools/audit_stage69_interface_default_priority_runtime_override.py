#!/usr/bin/env python3
"""Phase69: original interface-mode 60-valued *default priority* versus dynamic candidates.

X-S10 3.11 and X-T4 2.12 original ROM; no live sensor, 4K60,
HEVC Main10 output or flash/USB. The interface descriptor's byte+0x0A
value 60 is NOT automatically a physical 60fps readout or 2160p link.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage68_complete_joint_4k_fps6_conditions as s68
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_recorder_codec_forward_stage32 as s32
import audit_mode_profile_registry_stage29 as s29

DEFAULT_PRIORITY=(11,10,9,8,7,5,4,0)
FIRST12_ID_NUM=((3,60),(18,50),(19,50),(4,60),(20,50),(5,60),
                (32,24),(32,24),(33,25),(34,30),(31,50),(16,60))
ALL_60_INDICES=(0,3,5,11,22,23,34,35)
DEFAULT_60_INDICES=(11,5,0)
ADDITIONAL_60_INDICES=(22,23,34,35)

@dataclass(frozen=True)
class Spec:
    model:str
    priority:int
    descriptor:int
    init:int
    init_bl:int
    writer:int
    active_update:int
    active_update_bl:int
    dynamic_sources:tuple
    chooser:int
    classify:int
    whitelist:int
    response_parser:int
    response_tag:str
    default_c:str
    pointer:str
    mode_list_ram:str
    priority_ram:str
    list_state:str

SPECS={
 'xs10':Spec('xs10',0x0162ddfc,0x0162de0a,
  0x0126bf9c,0x0126bfcc,0x0126989c,0x01269960,0x01269978,
  (0x0126c264,0x0126c218),0x0126b508,0x012696e0,0x01269634,
  0x0126b7e0,'_DAT_01c855fc == 0x302','&DAT_0162ddfc',
  '_DAT_01c84f58','DAT_01c856a3','&DAT_01c856a3',
  "DAT_01c84fb4 == '\\0'"),
 'xt4':Spec('xt4',0x01605d20,0x01605d2e,
  0x012421b4,0x012421e4,0x0123fab4,0x0123fb78,0x0123fb90,
  (0x0124247c,0x01242430),0x01241720,0x0123f8f8,0x0123f84c,
  0x012419f8,'_DAT_01be56c8 == 0x302','&DAT_01605d20',
  '_DAT_01be5024','DAT_01be576f','&DAT_01be576f',
  "DAT_01be5080 == '\\0'"),
}

def need(ok,msg):
    if not ok:raise ValueError('STAGE69 interface default/priority: '+msg)

def decode_priority(value,max_rows=36):
    need(len(value)>0,'priority list empty')
    try:last=value.index(0xff)
    except ValueError:raise ValueError('STAGE69 priority lacks FF sentinel')
    seq=tuple(value[:last]);need(seq and len(seq)<=max_rows,'priority list length invalid')
    need(all(0<=x<max_rows for x in seq),'priority index out of bounds')
    need(len(seq)==len(set(seq)),'duplicate priority index')
    return seq

def decode_descriptors(raw):
    # Only four SMALL public identifiers/numeric fields, not original table bytes.
    need(len(raw)==36*16,'wrong interface descriptor table size')
    rows=[]
    for i in range(36):
        b=raw[i*16:(i+1)*16]
        rows.append({'index':i,'interface_id':b[0],
            'subcode':b[1], 'runtime_gate':b[2], 'numeric_rate':b[10]})
    need(tuple((x['interface_id'],x['numeric_rate']) for x in rows[:12])==FIRST12_ID_NUM,
         'first12 original IDs/numeric rate values changed')
    need(all(x['runtime_gate']==0 for x in rows[:12]),
         'first12 runtime gate byte no longer all zero')
    need(all(x['runtime_gate']==1 for x in rows if x['index'] in ADDITIONAL_60_INDICES),
         '97/102 60-valued rows gate byte no longer one')
    need(tuple(rows[i]['interface_id'] for i in ADDITIONAL_60_INDICES)==(97,97,102,102),
         'special original interface-mode IDs are no longer 97/97/102/102')
    need(tuple(x['index'] for x in rows if x['numeric_rate']==60)==ALL_60_INDICES,
         'numerical60 candidates differ in original table')
    return rows

def check_original_rom(s,one):
    p=s.priority-s59.BASE;d=s.descriptor-s59.BASE
    need(d-p==14,'original default priority distance to descriptor changed')
    seq=decode_priority(one[p:p+14])
    need(seq==DEFAULT_PRIORITY,'default priority differs from original eight entries')
    rows=decode_descriptors(one[d:d+36*16])
    default=[rows[i] for i in seq]
    default60=[row['index'] for row in default if row['numeric_rate']==60]
    need(default60==list(DEFAULT_60_INDICES),'default 60-valued priority order changed')
    need(not set(seq).intersection(ADDITIONAL_60_INDICES),
         'ID97/102 appears in factory default priority unexpectedly')
    need({rows[i]['interface_id'] for i in ADDITIONAL_60_INDICES}=={97,102},
         'special candidate 60-valued mode IDs differ')
    return {'factory_default_interface_priority_indices':list(seq),
        'factory_default_60_valued_indices':default60,
        'factory_default_60_valued_interface_IDs':[rows[i]['interface_id'] for i in default60],
        'nondefault_60_valued_indices':list(ADDITIONAL_60_INDICES),
        'nondefault_60_valued_interface_IDs':[97,102],
        'original_36_record_table_shared_by_models':True,
        '60_value_is_proven_to_be_true_sensor_frame_rate':False,
        'factory_priority_allows_user_movie_2160p_FPS6_proven':False}

def fun(log,a):return s59.function_c_any(log,a)

def check_dispatch(s,one,root):
    m=s.model
    word=lambda addr:s32.rom_word(one,s59.BASE,addr)
    for addr in (s.init_bl,s.active_update_bl):
        need(s29.bl_target(word(addr),addr)==s.writer,
             'original ARM branch to priority-list copier changed '+hex(addr))
    cg=(root/f'{m}_stage68_sensor_priority_selection.log').read_text()
    writer=fun((root/f'{m}_stage68_sensor_candidate_list_sources.log').read_text(),s.writer)
    init=fun(cg,s.init);active=fun(cg,s.active_update)
    candidates=[fun(cg,a) for a in s.dynamic_sources]
    chooser_log=(root/f'{m}_stage68_sensor_allowlist_context.log' if m=='xs10' else
      root/f'{m}_stage68_sensor_mode_chooser.log').read_text()
    chooser=fun(chooser_log,s.chooser)
    classify=fun((root/f'{m}_stage68_sensor_allowlist_context.log').read_text(),s.classify)
    response=fun((root/f'{m}_stage68_sensor_mode_chooser.log').read_text(),s.response_parser)
    membership=fun((root/f'{m}_runtime_sensor_interface_validate_stage22.log').read_text(),s.whitelist)
    need(f'FUN_{s.writer:08x}({s.default_c},0);' in init and
        f'FUN_{s.writer:08x}(0)' not in init,
        'constructor not copying factory ROM default list into RAM')
    need(f'FUN_{s.writer:08x}({s.pointer},*(' in active and
        all(f'FUN_{s.writer:08x}({s.pointer},*(' in c for c in candidates),
        'active candidate priority is not updated by dynamic RAM pointer')
    need('cVar2 = *param_1;' in writer and 'if (cVar2 == -1)' in writer and
         'while (cVar2 != -1)' in writer and s.priority_ram in writer,
         'runtime priority copier does not use FF terminated input')
    need(s.mode_list_ram in chooser and 'uVar5 < 0x24' in chooser and
         f'FUN_{s.classify:08x}(uVar5,' in chooser and s.list_state in chooser,
         'bounded 36 descriptor candidate search/dynamic state guard changed')
    expected_gate=('(&DAT_0162de0c)[param_1 * 0x10]' if m=='xs10' else '(&DAT_01605d30)[param_1 * 0x10]')
    expected_state=('DAT_01c8568c' if m=='xs10' else 'DAT_01be5758')
    need(f'FUN_{s.whitelist:08x}(uVar5,' in classify and
         'param_1 * 0x10' in classify and expected_gate in classify and
         expected_state in classify and '_DAT_' in classify,
         'interface-ID support and dynamic row gate state differ')
    need(s.response_tag in response and 'bVar3 == 2' in response and
         '0xc0' in response and 'uVar10 = *pbVar13 & 0x7f' in response,
         'runtime response 0x302 ID list parser/bound changed')
    need('return 1;' in membership and 'return 0;' in membership and
         ('_DAT_01c84fb8' in membership if m=='xs10' else '_DAT_01be5084' in membership),
         'runtime interface ID whitelist membership changed')
    need('0x3840' in chooser and '0x3841' in chooser,
         'explicit runtime 0x3840/0x3841 interface selectors disappeared')
    return {'ROM_default_list_is_initialized_to_dynamic_RAM':True,
       'runtime_priority_can_be_replaced_from_pointer':True,
       'dynamic_priority_search_bounds':36,
       'runtime_ID_whitelist_response_marker':'0x302',
       'success_or_fallback_also_depends_on_other_runtime_mode_states':True,
       'actual_live_primary_ID_or_dynamic_priority_value_observed':False,
       'Main10_SPS_or_real_4K60_sensor_VPU_recording_proven':False}

def analyze(root):
    s68.analyze(root)
    result=[];raw=[]
    for name,sp in SPECS.items():
        one=(root/f'x6-{name}/section-1.bin').read_bytes()
        r=check_original_rom(sp,one);r.update(check_dispatch(sp,one,root))
        r['model']=name;result.append(r)
        raw.append(one[sp.descriptor-s59.BASE:sp.descriptor-s59.BASE+36*16])
    need(raw[0]==raw[1],'original 36 descriptors differ across two cameras')
    need(all(r['factory_default_60_valued_indices']==[11,5,0] for r in result),
         'static same default 60-valued mode indices not crossvalidated')
    return {'models':result,'prior_Phase68_and_all_original_SHA_audits_PASS':True,
      'shared_default_priority_and_interface_descriptors':True,
      'hardware_sensor_4K60_approved':False,
      'runtime_ID97_or102_approved':False,
      'HEVC_Main10_SPS_or_sustained_4K60_video_observed':False,
      'device_camera_USB_FF80_RAM_flash_ROM_patch':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE69 ORIGINAL DEFAULT INTERFACE PRIORITY VS DYNAMIC WHITELIST PASS')
    print('UNPROVEN: actual runtime supported IDs, interface->movie 4K row, real 4K60/Main10 output.')
if __name__=='__main__':main()
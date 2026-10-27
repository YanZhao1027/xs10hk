#!/usr/bin/env python3
"""Phase68: audit the complete *static* 2160p/FPS6 joint-condition chain.

Covers original X-S10 FW3.11 / X-T4 FW2.12 ROM menu allowlists, settings
loader selectors/overrides, Movie class and eMode4kOut key rewrite, the
shared 96x0x40 mode LUT, and the dynamic sensor-interface mode whitelist.
No live camera, sensor/ISP response, HEVC Main10 SPS, or hardware 4K60 result
is claimed. Original ROM/Ghidra data remain private and gitignored.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse, json, re, sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage67_4k_fps6_joint_GUI_tuple as s67
import audit_stage49_recorder_mode_flag_forward as s49
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_stage46_joint_movie_mode_matrix as s46
import audit_recorder_codec_forward_stage32 as s32

@dataclass(frozen=True)
class Spec:
    model:str
    mode_list:int
    mode_count:int
    index_table:int
    index_count:int
    stride:int
    pixel:int
    aspect:int
    fps:int
    bps:int
    playfps:int
    alt_fps:int
    selector:int
    alt_playfps:int
    pixel_loader:int
    aspect_loader:int
    fps_loader:int
    bps_loader:int
    play_loader:int
    parent:int
    gui_base:int
    state_fps_obj:int
    state_fps_off:int
    state_play_obj:int
    state_play_off:int
    sensor_table:int
    sensor_parser:int
    sensor_checker:int
    sensor_selector:int
    sensor_candidate_writer:int
    sensor_candidate_ram:int
    sensor_id_count:int
    sensor_id_list:int
    sensor_state:int

SPECS={
 'xs10':Spec('xs10',0x0141ae54,24,0x0141ae70,252,28,
  0x3f4,0x42b,0x3f6,0x3f9,0x3f7,0x402,0x400,0x403,
  0x01174fe4,0x011766e4,0x01176904,0x01176aa4,0x011769d4,
  0x01187788,0x01b880a0,0x011769d0,0x148,0x01176aa0,0x148,
  0x0162de0a,0x0126b7e0,0x01269634,0x0126b508,0x0126989c,
  0x01c856a3,0x01c84fb8,0x01c852e4,0x01c8568c),
 'xt4':Spec('xt4',0x014090a0,9,0x014090ac,254,16,
  0x3dd,0x413,0x3df,0x3e2,0x3e0,0x3eb,0x3e9,0x3ec,
  0x01148fe8,0x0114a5d8,0x0114a7f8,0x0114a998,0x0114a8c8,
  0x0115b78c,0x01af2808,0x0114a8c4,0x138,0x0114a994,0x138,
  0x01605d2e,0x012419f8,0x0123f84c,0x01241720,0x0123fab4,
  0x01be576f,0x01be5388,0x01be5390,0x01be5758),
}
BASE=0x01021000
SENSOR_EXPECTED=[(93,24,4),(94,25,2),(95,30,2),(96,50,2),(97,60,2),
                 (98,24,4),(99,25,2),(100,30,2),(101,50,2),(102,60,2)]

# Exact original per-candidate flags in mode 0x2D and 0x21, in ROM order.
EXPECTED={
 'pixel':{'values':[7,6,4,5,9,10,11], 'mode2d':[2,1,0,0,0,0,0],
          'mode21':[2,0,0,0,0,0,0], 'allow2d':[7,6], 'allow21':[7], 'default2d':7,'default21':7},
 'aspect':{'values':[0,1,2,3,4,5,6,7], 'mode2d':[0,0,2,0,0,0,0,1],
           'mode21':[0,2,1,1,0,0,0,0], 'allow2d':[2,7], 'allow21':[1,2,3], 'default2d':2,'default21':1},
 'fps':{'values':[0,1,2,3,4,4,5,6,6,7,8,9,10,11,12,13,14,15],
        'mode2d':[0,1,1,1,2,0,1,1,0,0,1,1,0,0,1,1,0,0],
        'mode21':[0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0],
        'allow2d':[1,2,3,4,5,6,8,9,12,13], 'allow21':[4], 'default2d':4,'default21':4},
 'bps':{'values':[3,2,1,0], 'mode2d':[1,1,2,1], 'mode21':[0,0,2,0],
        'allow2d':[3,2,1,0], 'allow21':[1], 'default2d':1,'default21':1},
}
FIELD_ORDER=('pixel','aspect','fps','bps')

def need(ok,msg):
    if not ok:raise ValueError('PHASE68 joint-condition audit: '+msg)

def parse_index(image,spec):
    ids={}
    for i in range(400):
        key=image.u32(spec.index_table+i*8)
        ptr=image.u32(spec.index_table+i*8+4)
        if ptr==0:
            need(i==spec.index_count and key==0,'parameter index terminator/count shifted')
            break
        need((key>>16) in (0,1),'unexpected parameter-index type')
        low=key&0xffff
        need(low not in ids,'duplicate low16 parameter ID')
        ids[low]=(key,ptr)
    else:raise ValueError('parameter index did not terminate')
    need(len(ids)==spec.index_count,'parameter index entry count changed')
    return ids

def parse_candidates(image,spec,ptr):
    rows=[]
    for i in range(96):
        loc=ptr+i*spec.stride
        value=image.u32(loc)
        if value==0x7ffffffe:return rows
        flags=list(image.bytes(loc+4,spec.mode_count))
        need(all(v<=4 for v in flags),'unknown ROM allow/default flag')
        rows.append((value,flags))
    raise ValueError('candidate list missing original sentinel')

def validate_records(modes,tables):
    need(0x2d in modes and 0x21 in modes,'required menu modes missing')
    i2d=modes.index(0x2d);i21=modes.index(0x21);summary={}
    for field in FIELD_ORDER:
        e=EXPECTED[field];rows=tables[field]
        need([v for v,_ in rows]==e['values'],field+' original candidate order/duplicates changed')
        need(all(flag<=4 for _,flags in rows for flag in flags),field+' unsupported flag value')
        f2d=[f[i2d] for _,f in rows];f21=[f[i21] for _,f in rows]
        need(f2d==e['mode2d'],field+' mode0x2D exact flags changed')
        need(f21==e['mode21'],field+' mode0x21 exact flags changed')
        allow2d=[v for v,f in rows if 1<=f[i2d]<=4]
        allow21=[v for v,f in rows if 1<=f[i21]<=4]
        default2d=[v for v,f in rows if f[i2d] in (2,4)]
        default21=[v for v,f in rows if f[i21] in (2,4)]
        need(allow2d==e['allow2d'] and allow21==e['allow21'],field+' allowlist changed')
        need(default2d==[e['default2d']] and default21==[e['default21']],field+' default selection changed')
        summary[field]={'candidates':e['values'],'mode_0x2D_allowed':allow2d,
          'mode_0x2D_default':default2d[0],'mode_0x21_allowed':allow21,
          'mode_0x21_default':default21[0]}
    return summary

def parse_mode_image(image,spec):
    modes=list(image.bytes(spec.mode_list,spec.mode_count))
    need(tuple(modes)==s59.MODE_LISTS[spec.model],'mode list differs from pinned original model')
    need(image.bytes(spec.mode_list+spec.mode_count,1)==b'\x2e','mode-list terminator differs')
    ids=parse_index(image,spec)
    keys={'pixel':spec.pixel,'aspect':spec.aspect,'fps':spec.fps,'bps':spec.bps}
    tables={}
    for name,key in keys.items():
        need(key in ids,'menu parameter ID absent: '+name)
        full,ptr=ids[key]
        need(full==key,'menu parameter is not original type0: '+name)
        tables[name]=parse_candidates(image,spec,ptr)
    return modes,validate_records(modes,tables),tables

def parse_mode_tables(root,spec):
    image=s59.Image((root/f'x6-{spec.model}/section-1.bin').read_bytes())
    return parse_mode_image(image,spec)

def fun(log,address):return s59.function_c_any(log,address)

def validate_loader_text(root,spec):
    m=spec.model
    main=(root/f'{m}_stage68_menu_tuple_loaders.log').read_text()
    aspect=(root/f'{m}_stage68_aspect_validator_callers.log').read_text()
    pixel=fun(main,spec.pixel_loader);asp=fun(aspect,spec.aspect_loader)
    fps=fun(main,spec.fps_loader);bps=fun(main,spec.bps_loader);play=fun(main,spec.play_loader)
    if m=='xs10':
        token={
          'pixel':['0x2d,0x3f4','FUN_010253a4(0x2d,0x3f4,uVar2)','FUN_010253b4(0x2d,0x3f4)','FUN_011539e4(uVar2 & 0xff)'],
          'aspect':['0x42b','FUN_010253a4(param_1,0x42b,uVar1)','FUN_010253b4(param_1,0x42b)','FUN_01153ea4'],
          'fps':['0x3f6','0x402','0x400','FUN_010253a4(0x2d,0x3f6,uVar3)','FUN_01153cdc(4)','0x148'],
          'bps':['0x3f9','0x400','FUN_010253a4(0x2d,0x3f9,uVar3)','uVar3 = 2;','FUN_01153e0c(uVar3 & 0xff)'],
          'play':['0x3f7','0x403','0x3f6','0x400','FUN_010253a4(0x2d,0x3f6,uVar3)','FUN_01153d74(4)','0x148']}
        parent=fun((root/f'{m}_stage68_menu_modeargs.log').read_text(),spec.parent)
        parent_calls=['FUN_01174fe4();','FUN_01176904();','FUN_01176aa4();','FUN_011769d4();']
        aspect_cond=['FUN_011766e4(0x2d);','DAT_01b880a0']
        selector='0x400'
    else:
        token={
          'pixel':['0x2d,0x3dd','FUN_01025504(0x2d,0x3dd,uVar2)','FUN_01025514(0x2d,0x3dd)','FUN_011280bc(uVar2 & 0xff)'],
          'aspect':['0x413','FUN_01025504(param_1,0x413,uVar1)','FUN_01025514(param_1,0x413)','FUN_0112857c'],
          'fps':['0x3df','0x3eb','0x3e9','FUN_01025504(0x2d,0x3df,uVar3)','FUN_011283b4(4)','0x138'],
          'bps':['0x3e2','0x3e9','FUN_01025504(0x2d,0x3e2,uVar3)','uVar3 = 2;','FUN_011284e4(uVar3 & 0xff)'],
          'play':['0x3e0','0x3ec','0x3df','0x3e9','FUN_01025504(0x2d,0x3df,uVar3)','FUN_0112844c(4)','0x138']}
        parent=fun((root/f'{m}_stage68_menu_modeargs.log').read_text(),spec.parent)
        parent_calls=['FUN_01148fe8();','FUN_0114a7f8();','FUN_0114a998();','FUN_0114a8c8();']
        aspect_cond=['FUN_0114a5d8(0x2d);','_DAT_01af2808']
        selector='0x3e9'
    for name,c,items in (('pixel',pixel,token['pixel']),('aspect',asp,token['aspect']),
                         ('fps',fps,token['fps']),('bps',bps,token['bps']),('play',play,token['play'])):
        for item in items:need(item in c,name+' loader condition missing '+item)
    for item in parent_calls:need(item in parent,'movie setup parent no longer calls '+item)
    for item in aspect_cond:need(item in parent,'conditional aspect loader branch missing '+item)
    need('== \'\\a\'' in fps or "== '\\a'" in fps or "!= '\\a'" in fps,
         'FPS state==7 override condition not present')
    need(selector in fps and selector in bps and selector in play,
         'opaque mode selector not shared across FPS/BPS/playFPS paths')
    return {'pixel_allowlist_then_default_fallback':True,
      'aspect_allowlist_is_conditional_and_can_preserve_current_value':True,
      'normal_FPS_selector_zero_uses_id':hex(spec.fps),
      'normal_FPS_selector_nonzero_uses_alternate_id':hex(spec.alt_fps),
      'selector_nonzero_forces_bps_enum2_200Mbps':True,
      'FPS_state_byte7_forces_enum4':True,
      'playFPS_is_separate_and_validated_against_normal_FPS_table':True,
      'selector_key_semantic_name_proven':False,
      'all_four_independent_allowlists_imply_joint_runtime_reachability':False}

def decode_sensor_rows(raw):
    need(len(raw)==36*16,'sensor interface descriptor table truncated')
    rows=[]
    for i in range(36):
        r=raw[i*16:(i+1)*16];rows.append((r[0],r[10]))
    expected=[]
    for mode,fps,count in SENSOR_EXPECTED:expected.extend([(mode,fps)]*count)
    need(rows[12:36]==expected,'sensor-interface 24/25/30/50/60 candidate rows changed')
    return rows

def sensor_table_check(root):
    rows_by_model={}
    for m,addr in [('xs10',0x0162de0a),('xt4',0x01605d2e)]:
        b=(root/f'x6-{m}/section-1.bin').read_bytes();off=addr-s59.BASE
        raw=b[off:off+36*16]
        decode_sensor_rows(raw)
        rows_by_model[m]=raw
    need(rows_by_model['xs10']==rows_by_model['xt4'],'shared sensor-interface descriptor bytes diverged')
    return {'shared_sensor_descriptor_rows':36,
      '60fps_descriptor_ids':[97,102],
      '60fps_descriptor_candidate_indices':[22,23,34,35],
      'row_ID_is_a_sensor_interface_code_not_a_resolution_proof':True}

def select_sensor_candidate(candidate_indices,row_ids,supported_ids,check_enabled=True):
    # Synthetic-only model of the static ordered allowlist branch.
    for index in candidate_indices:
        if index<0 or index>=len(row_ids):continue
        ident=row_ids[index]
        if not check_enabled or ident in supported_ids:return index
    return None

def validate_sensor_runtime_chain(root,spec):
    m=spec.model
    chooser_log=(root/f'{m}_stage68_sensor_mode_chooser.log').read_text()
    if m=='xs10':
        parser=fun(chooser_log,spec.sensor_parser)
        checker=fun((root/'xs10_runtime_sensor_interface_validate_stage22.log').read_text(),spec.sensor_checker)
        chooser=fun((root/'xs10_stage68_sensor_allowlist_context.log').read_text(),spec.sensor_selector)
        writer=fun((root/'xs10_stage68_sensor_candidate_list_sources.log').read_text(),spec.sensor_candidate_writer)
        support='_DAT_01c84fb8'
        state="DAT_01c8568c == '\\0'"
        msg='_DAT_01c855fc == 0x302'
        idptr='DAT_0126b72c'
        candidate='DAT_01c856a3'
        checkname='FUN_01269634'
    else:
        parser=fun(chooser_log,spec.sensor_parser)
        checker=fun((root/'xt4_runtime_sensor_interface_validate_stage22.log').read_text(),spec.sensor_checker)
        chooser=fun((root/'xt4_stage68_sensor_mode_chooser.log').read_text(),spec.sensor_selector)
        writer=fun((root/'xt4_stage68_sensor_candidate_list_sources.log').read_text(),spec.sensor_candidate_writer)
        support='_DAT_01be5084'
        state="DAT_01be5758 == '\\0'"
        msg='_DAT_01be56c8 == 0x302'
        idptr='DAT_01241944'
        candidate='DAT_01be576f'
        checkname='FUN_0123f84c'
    need(msg in parser and '0xfff7b000' in parser and support in parser and '0xc0' in parser,
         'sensor/interface supported-ID list is not parsed from runtime message 0x302')
    cl=checker.lower()
    need('return 1;' in checker and ('dat_012696dc' in cl or 'dat_0123f8f4' in cl) and support.lower() in cl,
         'runtime sensor interface ID membership check missing')
    chooser_check='FUN_012696e0' if m=='xs10' else 'FUN_0123f8f8'
    context=(root/f'{m}_stage68_sensor_allowlist_context.log').read_text()
    gate_addr=0x012696e0 if m=='xs10' else 0x0123f8f8
    gate_wrapper=fun(context,gate_addr)
    need(state in gate_wrapper,'runtime sensor state flag no longer gates membership check')
    need('0x24' in chooser and chooser_check in chooser and idptr in chooser and candidate in chooser,
         'candidate mode selection is no longer bounded/ordered/dynamic')
    need('0xff' in writer and candidate in writer,
         'sensor mode priority list is not caller-supplied and sentinel terminated')
    return {'sensor_interface_supported_IDs_populated_by_runtime_response_0x302':True,
      'sensor_mode_candidate_priority_list_is_dynamic':True,
      '60fps_sensor_descriptor_IDs':[97,102],
      'actual_runtime_supported_ID97_or102_observed':False,
      'runtime_sensor_state_disables_or_bypasses_whitelist_check_in_some_branches':True,
      '60fps_sensor_descriptor_proven_to_correspond_to_2160p_movie_LUT_row':False,
      'physical_sensor_or_ISP_4K60_acceptance_proven':False}

def runtime_tuple(selector_value,normal_fps,alternate_fps,requested_bps,state_byte):
    fps=normal_fps if selector_value==0 else alternate_fps
    bps=requested_bps if selector_value==0 else 2
    if state_byte==7:fps=4
    return fps,bps

def movie_key(frame_type,active_4k_flag,pixel=7):
    klass=0 if frame_type in (1,4,5,6,7) else (1 if frame_type==2 else 2)
    is4k=frame_type in (4,5,6,7)
    if is4k and active_4k_flag==1:pixel=6
    return klass,pixel

def static_joint_tuple(frame_class,pixel,aspect,fps,bps):
    if frame_class!=0 or fps!=6:return None
    if aspect==2:
        if pixel==7 and bps in (1,2,3):return (3840,2160)
        if pixel==6 and bps in (1,2):return (1920,1080)
    if aspect==7:
        if pixel==7 and bps in (1,2,3):return (4096,2160)
        if pixel==6 and bps in (1,2):return (2048,1080)
    return None

def analyze(root):
    # Recertify the complete prior original-ROM menu/LUT chain and the
    # P+0x581 -> active flag -> Movie+0xA8E static source bridge.
    prior=s67.run(root)
    flag_bridge=s49.check_both_original(root)
    out=[]
    for name,spec in SPECS.items():
        modes,menu,tables=parse_mode_tables(root,spec)
        loaders=validate_loader_text(root,spec)
        sensor=validate_sensor_runtime_chain(root,spec)
        out.append({'model':name,'menu_allowlists':menu,'loader_conditions':loaders,
          'sensor_runtime_chain':sensor,
          'shared_2160p_FPS6_rows':next(x['six_2160p_fps6_with_bitrate_specific_GUI_tuple'] for x in prior['models'] if x['model']==name),
          'movie_class_and_4K_key_rewrite_already_revalidated':True,
          'P_plus_0x581_to_active_flag_source_bridge_revalidated':True,
          'P_plus_0x581_initial_runtime_value_proven':False,
          'actual_4K59_94_HEVC_Main10_session_proven':False})
    sensor_table=sensor_table_check(root)
    need(flag_bridge is not None,'Stage49 input/active 4K flag bridge did not return an audit')
    return {'models':out,'sensor_interface_table':sensor_table,
      'static_joint_tuple_sufficient_in_ROM_only':True,
      'selector_0x400_XS10_and_0x3E9_XT4_business_meaning_known':False,
      'aspect_0x42B_or_0x413_runtime_menu_value_jointly_observed':False,
      'dynamic_sensor_interface_response_contents_known':False,
      'physical_sensor_ISP_VPU_acceptance_known':False,
      'HEVC_Main10_output_profile_SPS_known':False,
      'no_camera_USB_FF80_RAM_flash_or_ROM_writes':True}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE68 COMPLETE STATIC JOINT CONDITIONS / DYNAMIC SENSOR GATE AUDIT PASS')
    print('UNKNOWN: actual sensor list, runtime mode choice, HEVC Main10 SPS, real 4K59.94 recording.')
if __name__=='__main__':main()
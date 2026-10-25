#!/usr/bin/env python3
"""Phase63: original per-mode eMovieFps eligibility, not eContMode.

Decodes X-S10 FW3.11 / X-T4 FW2.12 Section1 original menu indexes,
first-match enum flags, human-readable ROM MODE_FPS_60 enum6, original
UI eMovieFps setter, mode0x2D validity/fallback and direct BL.
Also fail-closes false correlation of similarly numbered eContMode keys.
Proves static GUI candidate only, NOT 3840x2160+59.94 joint runtime state,
HEVC Main10 SPS/10bit encoded output, sensor/ISP capacity or patchability.
No USB/FF80, camera RAM/flash, firmware patch or flashing.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage62_active_codec_to_vpu_class_bridge as st62
import audit_stage59_movie_menu_ROM_allowlist as st59
import audit_mode_profile_registry_stage29 as st29

EXPECTED_VALUES=(0,1,2,3,4,4,5,6,6,7,8,9,10,11,12,13,14,15)
EXPECTED_MOVIE_2D=(1,2,3,4,5,6,8,9,12,13)
EXPECTED_NONMOVIE_21=(4,)
BASE=0x01021000

@dataclass(frozen=True)
class Spec:
    name:str
    param_id:int
    table_ptr:int
    enum_name60_addr:int
    enum_converter:int
    setter:int
    setter_RAM_addr:int
    icode:int
    input_parent:int
    input_setter_bl:int
    econt_param_id:int
    econt_setter:int

SPECS={
 'xs10':Spec('xs10',0x3f6,0x01421cd4,0x0143eb48,0x0102d4a8,
       0x01153cdc,0x01b8810e,0x01176904,0x01176904,0x0117699c,
       0x5e1,0x01152b98),
 'xt4':Spec('xt4',0x3df,0x0140d374,0x014287c8,0x0102d6d8,
       0x011283b4,0x01af2876,0x0114a7f8,0x0114a7f8,0x0114a890,
       0x5c6,0x01127270)
}

def require(condition,message):
    if not condition:raise ValueError('STAGE63 real eMovieFps: '+message)

def read_header(spec,base_spec,img):
    matching=[]
    for i in range(base_spec.total_param_ids):
        ident=img.u32(base_spec.index_table+i*8)
        ptr=img.u32(base_spec.index_table+i*8+4)
        if (ident&0xffff)==spec.param_id:matching.append((i,ident,ptr))
    require(len(matching)==1 and matching[0][1]==spec.param_id and
            matching[0][2]==spec.table_ptr,
            'real eMovieFps parameter ID/pointer/type does not match ROM')
    require(spec.param_id!=spec.econt_param_id and
            spec.setter_RAM_addr - (0x01b880a0 if spec.name=='xs10' else 0x01af2808)==0x6e,
            'false eContMode-as-FPS identity or GUI offset')
    return matching[0][0]

def parse_rows(spec,base_spec,img):
    modes=st59.MODE_LISTS[spec.name]
    require(tuple(img.bytes(base_spec.mode_list,len(modes)))==modes,
            'ROM mode-list order changed')
    records=[]
    for j,value in enumerate(EXPECTED_VALUES):
        addr=spec.table_ptr+j*base_spec.entry_stride
        v=img.u32(addr)
        flags=tuple(img.bytes(addr+4,len(modes)))
        require(v==value and all(flag<=4 for flag in flags),
                'candidate record value/order or flag status changed '+str(j))
        records.append((v,flags))
    require(img.u32(spec.table_ptr+len(records)*base_spec.entry_stride)==0x7ffffffe,
            'end-of-table sentinel absent')
    return tuple(modes),records

def first_match_allowed(modes,records,mode):
    require(mode in modes,'mode absent')
    ix=modes.index(mode)
    first={}
    for value,flags in records:
        first.setdefault(value,flags[ix])
    return tuple(v for v,f in first.items() if 1<=f<=4)

def eligible(spec,base_spec,img):
    index=read_header(spec,base_spec,img)
    modes,records=parse_rows(spec,base_spec,img)
    allowed2d=first_match_allowed(modes,records,0x2d)
    allowed21=first_match_allowed(modes,records,0x21)
    require(allowed2d==EXPECTED_MOVIE_2D and allowed21==EXPECTED_NONMOVIE_21,
            'Movie FPS allowed enum list changed')
    require(6 in allowed2d and 6 not in allowed21,
            'FPS enum6 mode eligibility changed')
    flag6=next(f[modes.index(0x2d)] for v,f in records if v==6)
    require(flag6==1,'first-match MODE_FPS_60 flag must be selectable')
    first4=next(f for v,f in records if v==4)
    require(first4[modes.index(0x2d)]==2 and first4[modes.index(0x21)]==2,
            'ROM default FPS enum4 flags for two modes changed')
    require(0 in (v for v,f in records) and 0 not in allowed2d,
            'different FPS mode0x2D enum default semantics')
    # Confirm original standalone string, *not* inference from the numeric 6.
    require(img.bytes(spec.enum_name60_addr,len('MODE_FPS_60')+1)==b'MODE_FPS_60\x00',
            'original ROM FPS=60 enum label absent')
    return {'parameter_id':hex(spec.param_id),'index_ordinal':index,
            'table_ROM_address':hex(spec.table_ptr),'mode_count':len(modes),
            'candidate_records':len(records),'has_duplicate_value_records':True,
            'allowed_menu_enums_mode0x2D':list(allowed2d),
            'allowed_menu_enums_mode0x21':list(allowed21),
            'MODE_FPS_60_numeric_enum':6,
            'MODE_FPS_60_allowed_in_mode0x2D':True,
            'mismatch_with_eContMode_param_id':hex(spec.econt_param_id),
            'any_confirmed_4K59_94_joint_recorder_state':False}

def get_func(src,address):return st59.function_c_any(src,address)

def ghidra(spec,converter,setter,parent,econt_setter,word):
    require('param_1 == 6' in converter and 's_MODE_FPS_60_' in converter and
            'param_1 == 5' in converter and 's_MODE_FPS_50_' in converter,
            'string enum6 != MODE_FPS_60 or enum5 != 50')
    require(f'DAT_{spec.setter_RAM_addr:08x} = (char)param_1;' in setter and
            's__INPUT_eMovieFps_' in setter,
            'original GUI eMovieFps setter does not identify expected RAM byte')
    if spec.name=='xs10':
        validation=f'FUN_010253a4(0x2d,0x{spec.param_id:x},uVar3)'
        fallback=f'FUN_010253b4(0x2d,0x{spec.param_id:x})'
    else:
        validation=f'FUN_01025504(0x2d,0x{spec.param_id:x},uVar3)'
        fallback=f'FUN_01025514(0x2d,0x{spec.param_id:x})'
    require(validation in parent and fallback in parent and
            f'FUN_{spec.setter:08x}(uVar3 & 0xff);' in parent and
            '0x7fffffff' in parent,
            'real FPS movie0x2D validity/fallback path absent')
    require(st29.bl_target(word(spec.input_setter_bl),spec.input_setter_bl)==spec.setter,
            'original movie0x2D setter BL instruction target mismatch')
    require('s__INPUT_eContMode_' in econt_setter and
            's__INPUT_eMovieFps_' not in econt_setter,
            'former eContMode mistake not demonstrably corrected')
    return {'GUI_movie_fps_RAM':hex(spec.setter_RAM_addr),
            'real_fps_setter':hex(spec.setter),
            'real_fps_validator_and_fallback_mode0x2D':True,
            'eContMode_is_a_separate_field':True,
            'movie_FPS_enum6_means_real_3840x2160_plus_59_94_recording':False}

def check_cross_model(entries):
    (xmode,xdata),(tmode,tdata)=entries
    require(len(xdata)==len(tdata) and all(vx==vt for (vx,_),(vt,_) in zip(xdata,tdata)),
            'X-S10/X-T4 18-entry FPS enum sequences differ')
    for (vx,fx),(vt,ft) in zip(xdata,tdata):
        for mode in tmode:
            require(mode in xmode and fx[xmode.index(mode)]==ft[tmode.index(mode)],
                    'X-S10/X-T4 eMovieFps common movie-mode flags differ')
    return True

def run(root):
    st62.analyze(root)
    rows=[];comp=[]
    for model,s in SPECS.items():
        b=(root/f'x6-{model}/section-1.bin').read_bytes()
        img=st59.Image(b)
        bs=st59.SPECS[model]
        data=eligible(s,bs,img)
        comp.append(parse_rows(s,bs,img))
        setter_log=(root/f'{model}_stage63_real_eMovieFps_GUI_setter.log').read_text()
        code_log=(root/f'{model}_stage63_movie_fps_enum_names.log').read_text()
        parent_log=(root/f'{model}_stage63_real_movie_fps_setter_parent.log').read_text()
        wrong_log=(root/f'{model}_stage63_FPS_menu_proven_setter.log').read_text()
        word=lambda addr:st29.word(b,BASE,addr)
        evidence=ghidra(s,get_func(code_log,s.enum_converter),
            get_func(setter_log,s.setter),get_func(parent_log,s.input_parent),
            get_func(wrong_log,s.econt_setter),word)
        rows.append({'model':model,**data,**evidence})
    check_cross_model(comp)
    return {'models':rows,
            'shared_9_mode_original_menu_flag_sequences_identical':True,
            'original_x6_SHA_pinned_all_prior_audits_passed':True,
            'both_ROMs_advertise_MODE_FPS_60_in_mode_0x2D':True,
            'joint_4K_resolution_59_94_HEVC_Main10_sensor_VPU_acceptance_proven':False,
            'no_camera_or_firmware_write':True}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(run(a.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE63 ORIGINAL eMovieFps ROM ALLOWLIST AND eContMode DISAMBIGUATION PASS')
    print('UNKNOWN: real X-S10 4K59.94+HEVC/Main10 joint recording, VPU output SPS.')
if __name__=='__main__':main()
#!/usr/bin/env python3
"""Stage60: original GUI enum 1 = H.265, menu default != hardware support.

Both X-S10 and X-T4 ROM codec value1 is H265, mode0x2D allows H264+H265,
but ROM default selector chooses H264. Additional X-T4 mode-reload path
uses *default* getter and can reset GUI codec to 0 on that path. This is not
a proof of HEVC Main10, 4K60, live trigger, or safe firmware modifications.
Only original X6, read-only Ghidra; SHA prior stages recertified.
"""
from dataclasses import dataclass
import re,json,argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage59_movie_menu_ROM_allowlist as st59
import audit_stage53_gui_rec_setparam_tx as st53
import audit_mode_profile_registry_stage29 as st29

@dataclass(frozen=True)
class Spec:
    model:str
    enum_labels:tuple[int,int,int]
    enum_converter:int
    direct_codec_setter:int
    codec_GUI_address:int
    direct_xref_count:int
    reloader:int|None
    reloader_codec_BL:int|None
    reloader_entry_bl1:int|None
    reloader_entry_bl2:int|None

SPECS={
 'xs10':Spec('xs10',(0x0144009c,0x014400b4,0x014400cc),
     0x01034dc4,0x0115b578,0x01b88650,3,None,None,None,None),
 'xt4':Spec('xt4',(0x01429d04,0x01429d1c,0x01429d34),
     0x01035078,0x0112fd80,0x01af2db8,4,
     0x0115b234,0x0115b314,0x0115f2d0,0x02043b14),
}

EXPECTED_LABELS=('MODE_MOVIE_CODEC_H264','MODE_MOVIE_CODEC_H265',
                 'MODE_MOVIE_CODEC_NUM')

def require(x,msg):
    if not x:raise ValueError('Stage60 H265/default/reloader: '+msg)

def default_from_rom(sp,image):
    """Original non-range parameter records: select first flag2 or flag4."""
    mode_list=st59.MODE_LISTS[sp.name]
    records={}
    for field,ptr,enum_values in (("MovieFormat",sp.fmt_ptr,(0,1)),
                                  ("MovieCodec",sp.codec_ptr,(0,1)),
                                  ("eMode4kOut",sp.out4k_ptr,(3,0,1,2))):
        table={}
        for mi,mode in enumerate(mode_list):
            choices=[];preferred=[]
            for vi,value in enumerate(enum_values):
                address=ptr+vi*sp.entry_stride
                require(image.u32(address)==value,field+' candidate mutated')
                flag=image.bytes(address+4+mi,1)[0]
                if 1<=flag<=4:choices.append(value)
                if flag in (2,4):preferred.append(value)
            require(choices and len(preferred)==1,
                    field+' default ROM status flag ambiguous')
            table[mode]=(preferred[0],choices)
        records[field]=table
    require(all(records['MovieCodec'][mode][0]==0 and
                records['MovieFormat'][mode][0]==0 and
                records['eMode4kOut'][mode][0]==3 for mode in mode_list),
            'X-S10/X-T4 original menu defaults were not 0/0/3')
    require(all(records[key][0x2d]==(0,[0,1]) and
                records[key][0x21]==(0,[0])
                for key in ('MovieCodec','MovieFormat')) and
            records['eMode4kOut'][0x2d]==(3,[3,0,1,2]) and
            records['eMode4kOut'][0x21]==(3,[3]),
            'MovieFormat/Codec/4kOut defaults or selectable values changed')
    return {'codec_mode_0x2D_default':0,
            'codec_mode_0x2D_allowed':[0,1],
            'codec_mode_0x21_default':0,
            '4kOut_mode_0x2D_default':3,
            'config_default_0_does_not_disallow_valid_H265_value_1':True}

def label_enum(spec,image,c):
    for i,(a,label) in enumerate(zip(spec.enum_labels,EXPECTED_LABELS)):
        data=image.bytes(a,len(label)+1)
        require(data==label.encode()+b'\0',
                'codec enum ROM label mismatch model '+spec.model+' index '+str(i))
        require((f'param_1 == {i}' if i<2 else 'param_1 != 2') in c,
                'enum converter branch case missing')
        require('s_'+label+'_' in c,'codec label not named in Ghidra converter')
    return {'enum0':'H264','enum1':'H265','enum2':'NUM sentinel',
            'H265_is_NOT_proof_of_Main10_bitdepth':True}

def code_paths(spec,loader,reload_c,init_c,wrapper_c,setter_c,xref_log,w1):
    require(f'DAT_{spec.codec_GUI_address:08x} = (char)param_1;' in setter_c,
            'original direct GUI Codec setter not writing expected byte')
    require(f'FUN_{spec.direct_codec_setter:08x}(uVar2 & 0xff)' in loader,
            'movie primary config loader does not set codec')
    require('0x7fffffff' in loader and
            f'0x2d,0x{st59.SPECS[spec.model].codec:x}' in loader,
            'primary validator/get-default path not verified')
    entries=re.findall(r'PROBE_REF from=([0-9a-f]+) to=([0-9a-f]+)',xref_log)
    direct=[int(a,16) for a,b in entries if int(b,16)==spec.direct_codec_setter]
    require(len(direct)==spec.direct_xref_count and
            len(set(direct))==spec.direct_xref_count,
            'direct static codec setter xrefs differ from model-specific inventory')
    info={'direct_codec_setter_callsite_count':len(direct),
          'direct_codec_setter_sites':[hex(v) for v in sorted(direct)],
          'codec_setter_has_no_HEVC_bitdepth_or_hardware_proof':True,
          'extra_XT4_default_reloader_proven':False}
    if spec.reloader is None:
        require(not reload_c and not init_c and not wrapper_c,
                'unexpected XS10 X-T4-only reload evidence')
        return info
    for site in (spec.reloader_codec_BL,spec.reloader_entry_bl1,
                 spec.reloader_entry_bl2):
        require(site is not None,'missing X-T4 extra codec reload ARM BL')
        expected=(spec.direct_codec_setter if site==spec.reloader_codec_BL
                  else spec.reloader)
        require(st29.bl_target(w1(site),site)==expected,
                'extra X-T4 mode reload original BL target changed '+hex(site))
    require(spec.reloader_codec_BL in direct,
            'X-T4 extra reload is not the fourth codec setter xref')
    require('DAT_01af2808 == \'-\'' in reload_c and
            'uVar3 = 0x2d;' in reload_c and
            'uVar3 = 0x21;' in reload_c and
            'FUN_01025514(uVar3,0x3e5)' in reload_c and
            f'FUN_{spec.direct_codec_setter:08x}(uVar1 & 0xff);' in reload_c and
            '0x7fffffff' in reload_c,
            'XT4 extra mode-dependent default codec reloader not cross-verified')
    require("if (*(char *)(DAT_0115f340 + 0x834) == '\\x01')" in init_c and
            f'FUN_{spec.reloader:08x}();' in init_c and
            f'FUN_{spec.reloader:08x}();' in wrapper_c,
            'X-T4 extra reload activation sites (conditional vs standalone) differ')
    info.update({'extra_XT4_default_reloader_proven':True,
                 'reloader_mode0x2D_chooses_preferred_H264_0':True,
                 'reloader_mode0x21_chooses_preferred_H264_0':True,
                 'conditional_branch_trigger_observed_at_runtime':False,
                 'does_reset_means_no_H265_encoding_capability':False})
    return info

def get_function(log,addr):return st59.function_c_any(log,addr)

def analyze(root):
    st59.run(root)  # SHA pinned Phase58 and prior; original ROM eligibility pass
    rows=[]
    for model,s in SPECS.items():
        spec=st59.SPECS[model]
        img=st59.Image((root/f'x6-{model}/section-1.bin').read_bytes())
        c=get_function((root/f'{model}_stage60_movie_mode_reload_boundaries.log').read_text(),s.enum_converter)
        getter=label_enum(s,img,c)
        defaults=default_from_rom(spec,img)
        loader=get_function((root/f'{model}_stage59_flag_codec_origins.log').read_text(),spec.primary_loader)
        setter=get_function((root/f'{model}_stage59_flag_codec_origins.log').read_text(),s.direct_codec_setter)
        xrefs=(root/f'{model}_stage59_GUI_setter_callers.log').read_text()
        if s.reloader is None:extra=('', '', '')
        else:
            log=(root/f'{model}_stage60_movie_mode_reload_boundaries.log').read_text()
            extra=(get_function(log,s.reloader),get_function(log,0x0115e9c8),
                   get_function(log,0x02043ab4))
        sec2=(root/f'x6-{model}/section-2.bin').read_bytes()
        base2=st53.SPECS[model].sec2base
        w=lambda addr:(st29.word(sec2,base2,addr) if addr>=base2
                        else st29.word(img.data,st59.BASE,addr))
        path=code_paths(s,loader,*extra,setter,xrefs,w)
        rows.append({'model':model,**getter,**defaults,**path})
    return {'models':rows,
            'original_ROM_SHA_prior_audits_passed':True,
            'X_S10_and_XT4_both_advertise_H265_in_mode0x2D':True,
            'confirmed_H265_Main10_depth_or_4K60_hardware':False,
            'read_only_no_camera_modified':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE60 ORIGINAL H265 ENUM STRINGS / DEFAULTS / XT4 RELOADER PASS')
    print('UNKNOWN: actual H265 bitdepth or Main10, 4K60 sensor/ISP/real recording.')
if __name__=='__main__':main()
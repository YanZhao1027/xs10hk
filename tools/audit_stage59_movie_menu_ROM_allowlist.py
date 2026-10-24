#!/usr/bin/env python3
"""Stage59: exact original ROM modal menu eligibility for MovieCodec/Format/4kOut.

Static X6 Section1 mode lists, parameter-ID pointer indexes, and packed
per-mode candidate flag bytes. Original validators accept flags 1..4;
flags 0 reject, 2 marks default but *not* a hardware guarantee.
Reruns SHA-pinned prior Stage58 and never mutates ROM / camera / USB / FF80.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,struct,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage58_gui_into_type200_recorder_input as st58

@dataclass(frozen=True)
class Spec:
    name:str
    mode_list:int
    index_table:int
    mode_count:int
    total_param_ids:int
    entry_stride:int
    fmt:int
    codec:int
    out4k:int
    fmt_ptr:int
    codec_ptr:int
    out4k_ptr:int
    validator:int
    default_getter:int
    primary_loader:int
    codec_setter:int

SPECS={
 'xs10':Spec('xs10',0x0141ae54,0x0141ae70,24,252,28,
             0x3fb,0x3fc,0x58e,0x01421c2c,0x01421c80,0x0141b6ac,
             0x0114dfac,0x0114e198,0x01179dc0,0x0115b578),
 'xt4':Spec('xt4',0x014090a0,0x014090ac,9,254,16,
           0x3e4,0x3e5,0x574,0x0140d314,0x0140d344,0x014098d4,
           0x011222dc,0x011224c8,0x0114dab4,0x0112fd80),
}

BASE=0x01021000
LIMIT=0x1000
MODE_LISTS={
 'xs10':(0x01,0x1d,0x2c,0x1f,0x20,0x24,0x23,0x22,0x21,0x05,0x18,0x08,
         0x0b,0x0c,0x0d,0x12,0x13,0x11,0x10,0x14,0x16,0x15,0x17,0x2d),
 'xt4':(0x1d,0x2c,0x1f,0x20,0x24,0x23,0x22,0x21,0x2d),
}

def require(ok,msg):
    if not ok:raise ValueError('STAGE59 original movie menu: '+msg)

class Image:
    def __init__(self,data):self.data=data
    def bytes(self,address,n):
        idx=address-BASE
        require(0<=idx and idx+n<=len(self.data),f'ROM address OOB {address:#x}+{n}')
        return self.data[idx:idx+n]
    def u32(self,address):return struct.unpack('<I',self.bytes(address,4))[0]

def analyze_model(s,image,validators):
    modes=list(image.bytes(s.mode_list,s.mode_count))
    require(tuple(modes)==MODE_LISTS[s.name] and
            image.bytes(s.mode_list+s.mode_count,1)==b'\x2e' and
            modes.count(0x2d)==1 and 0x21 in modes,
            'mode-list count, sentinel or active mode identity changed')
    ids={}
    for idx in range(LIMIT):
        head=image.u32(s.index_table+idx*8)
        ptr=image.u32(s.index_table+idx*8+4)
        if ptr==0:
            require(idx==s.total_param_ids and head==0,
                    'parameter index table sentinel/count changed')
            break
        require((head>>16) in (0,1) and (head&0xffff) not in ids,
                'parameter ID type or uniqueness changed')
        ids[head&0xffff]=ptr
        image.bytes(ptr,4)
    else:raise ValueError('no ROM parameter index terminator')
    expected=[(s.fmt,s.fmt_ptr,'MovieFormat'),
              (s.codec,s.codec_ptr,'MovieCodec'),
              (s.out4k,s.out4k_ptr,'eMode4kOut')]
    results={}
    for key,ptr,label in expected:
        require(ids.get(key)==ptr,f'{label} pointer or ID shifted')
        full_key=image.u32(s.index_table+list(ids).index(key)*8)
        require(full_key==key,f'{label} key type field unexpectedly nonzero')
        entries=[]
        for n in range(64):
            loc=ptr+n*s.entry_stride
            value=image.u32(loc)
            if value==0x7ffffffe:break
            require(value not in [v for v,_ in entries],label+' repeated enum value')
            flags=list(image.bytes(loc+4,s.mode_count))
            require(all(0<=flag<=4 for flag in flags),label+' out of expected eligibility range')
            entries.append((value,flags))
        else:raise ValueError(label+' has no sentinel')
        # Per-mode eligibility: flag 1,2,3,4 means selectable according to
        # both original validator implementations. Flag0 means absent.
        by_mode={hex(mode):[(v,f[mi]) for v,f in entries if 1<=f[mi]<=4]
                 for mi,mode in enumerate(modes)}
        if label in ('MovieCodec','MovieFormat'):
            require([v for v,_ in entries]==[0,1] and
                all([v for v,f in entries if 1<=f[mi]<=4]==
                    ([0,1] if mode==0x2d else [0])
                    for mi,mode in enumerate(modes)),
                label+' expected mode 0x2d/other eligibility changed')
            require(entries[0][1]==[2]*len(modes) and
                all(flag==(1 if mode==0x2d else 0)
                    for mode,flag in zip(modes,entries[1][1])),
                label+' flag exact values changed')
        else:
            require([v for v,_ in entries]==[3,0,1,2] and
                all([v for v,f in entries if 1<=f[mi]<=4]==
                    ([3,0,1,2] if mode==0x2d else [3])
                    for mi,mode in enumerate(modes)),
                '4kOut exact mode eligibility differs')
            require(entries[0][1]==[2]*len(modes) and
                all(all(x==(1 if mode==0x2d else 0) for mode,x in zip(modes,f))
                    for _,f in entries[1:]),'4kOut flags unexpected')
        results[label]={'parameter_id':hex(key),'ROM_table_pointer':hex(ptr),
                        'candidates':list(v for v,_ in entries),
                        'mode_0x2d':by_mode['0x2d'],
                        'mode_0x21':by_mode['0x21'],
                        'additional_nonmovie_modes_in_table':len(modes)-1}
    require('0x7fffffff' in validators['default'] and
            '0x7ffffffe' in validators['default'] and
            '0x7ffffffe' in validators['validate'] and
            validators['validate'].count('return false;')>=5,
            'ROM-derived enum table interpretation not supported by Ghidra')
    required_step='piVar2 = piVar2 + '+('7' if s.name=='xs10' else '4')+';'
    require(required_step in validators['validate'],
            'Ghidra validator entry stride mismatch')
    require('param_1 == ' in validators['validate'] and
            'param_3 == iVar6' in validators['validate'],
            'param/model validity test missing')
    require('0x7fffffff' in validators['loader'] and
            ('0x2d,0x'+format(s.codec,'x')) in validators['loader'] and
            ('0x2d,0x'+format(s.fmt,'x')) in validators['loader'] and
            ('FUN_%08x(uVar2 & 0xff)'%s.codec_setter) in validators['loader'],
            'primary loader did not pin both keys or sentinel before direct setter')
    return {'model':s.name,'mode_count':len(modes),
            'param_index_entries':len(ids),'rom_stride_bytes':s.entry_stride,
            'validated_accessor_eligibility_flags':'1..4',
            'menu_rom_candidates':results,
            'user_camera_runtime_uses_these_selected_values_proven':False,
            'menu_eligibility_implies_hardware_4K60_or_HEVC_Main10':False}

def function_c_any(t,fn):
    import re
    for chunk in t.split('TRACE_DECOMP_BEGIN (GhidraScript)')[1:]:
        c=chunk.split('TRACE_DECOMP_END (GhidraScript)')[0]
        if re.search(r'\bFUN_%08x\s*\('%fn,c[:320]):return c
    raise ValueError('Ghidra function absent '+hex(fn))

def run(root):
    st58.analyze(root)
    rows=[]
    for m,s in SPECS.items():
        image=Image((root/f'x6-{m}/section-1.bin').read_bytes())
        t=(root/f'{m}_stage60_config_resolver_implementation.log').read_text()
        l=(root/f'{m}_stage59_flag_codec_origins.log').read_text()
        rows.append(analyze_model(s,image,
          {'default':function_c_any(t,s.default_getter),
           'validate':function_c_any(t,s.validator),
           'loader':function_c_any(l,s.primary_loader)}))
    require([row['menu_rom_candidates']['MovieCodec']['mode_0x2d']
             for row in rows]==[[(0,2),(1,1)],[(0,2),(1,1)]],
             'X-S10 vs X-T4 codec availability not matched')
    return {'models':rows,
            'original_pinned_phase58_and_prior_audits_passed':True,
            'ROM_menu_eligibility_XS10_and_XT4_match_for_movie_keys':True,
            'hardware_codec_or_sensor_capability_not_established':True,
            'vendor_firmware_and_full_decompilation_not_uploaded':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(run(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE59 ORIGINAL X-S10/X-T4 MODE/FORMAT/CODEC/4KOUT ROM ELIGIBILITY PASS')
    print('UNKNOWN: live byte values, bitdepth Main10 or 4K60 physical recording.')
if __name__=='__main__':main()
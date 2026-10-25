#!/usr/bin/env python3
"""Phase64: original eMovieFps GUI/P input +0x6E into active Recorder FPS.

Both X-S10 v3.11 and X-T4 v2.12 X6: prior Stage58 original GUI->P
copy, Section1 conditional converter P[0x6E]->fixed intermediate[0x1E]
(two identical A32 LDRB/STRB pairs per model), prior Stage32 active template
memcpy covers 0x1E, independently pinned active FPS getter and reverse
snapshot exporter. The getter is consumed by movie mode builders, which
include a switch-case handling numeric enum6. This is a conditional static
host data flow; NOT proof of Movie+0x5C6/0x5C7 writer, live 4K59.94,
Main10 output SPS, physical VPU acceptance, or firmware modification.

Separately, X-S10 one STRB using raw immediate #0x5C6 actually writes to
*another pointer's effective +0x15C6 (base adjusted by 0x1000); xref
integer alone does NOT identify a Movie+0x5C6 write. All sections read-only.
"""
from dataclasses import dataclass
import argparse,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage63_real_movie_fps_menu_eligibility as st63
import audit_recorder_codec_forward_stage32 as st32
import audit_stage59_movie_menu_ROM_allowlist as st59

BASE=0x01021000

@dataclass(frozen=True)
class Spec:
    name:str
    first_load:int
    first_store:int
    second_load:int
    second_store:int
    active_fps_ram:int
    getter:int
    exporter:int
    consumer1:int
    consumer2:int
    consumer3:int
    movie_parent_func:int
    other_stride_site:int|None
    other_stride_func:int|None

SPECS={
 'xs10':Spec('xs10',0x012c959c,0x012c95a0,0x012c9a84,0x012c9a88,
   0x01c24df6,0x012bd550,0x012be684,
   0x022d18ac,0x022d3fd8,0x022d41d0,0x022d3e00,
   0x021f6b44,0x021f6b2c),
 'xt4':Spec('xt4',0x012a31d8,0x012a31dc,0x012a36d4,0x012a36d8,
   0x01b8355e,0x01295bc4,0x01296d38,
   0x0223de3c,0x022405a0,0x02240798,0x022403c8,
   None,None),
}


def require(ok,desc):
    if not ok:raise ValueError('STAGE64 original GUI eMovieFps -> active: '+desc)


def original_arm(s,w1,w2):
    m=st32.MODELS[s.name]
    old=st63.SPECS[s.name]
    require(s.active_fps_ram==m.template_base+0x1e and
            0x1e<m.copy_len and s.getter!=0 and
            old.setter_RAM_addr==(0x01b880a0 if s.name=='xs10' else 0x01af2808)+0x6e,
            'Phase63 real GUI address / Stage32 Recorder copy arithmetic differs')
    require(m.adapter<s.first_load<s.first_store<m.adapter+1600 and
            m.adapter<s.second_load<s.second_store<m.adapter+1600,
            'original input converter locations outside original function')
    for addr,expected in ((s.first_load,0xe5d1306e),
                          (s.first_store,0xe5c0301e),
                          (s.second_load,0xe5d1306e),
                          (s.second_store,0xe5c0301e)):
        require(w1(addr)==expected,
            f'original A32 LDRB P+6E / STRB intermediate+1E changed {addr:#x}')
    require(s.first_store==s.first_load+4 and
            s.second_store==s.second_load+4,
            'source->dest A32 instructions must be adjacent')
    f=s.getter
    ram=st32.movpart(w1(f+8),3)|(st32.movpart(w1(f+12),3,True)<<16)
    require(ram==m.template_base and
            w1(f+16)==0xe5d3001e and
            ram+0x1e==s.active_fps_ram,
            'original getter MOVW/MOVT and LDRB active RAM+0x1e changed')
    require(st32.a32_bl(w2(s.consumer1),s.consumer1)==s.getter and
            st32.a32_bl(w2(s.consumer2),s.consumer2)==s.getter and
            st32.a32_bl(w2(s.consumer3),s.consumer3)==s.getter,
            'three original movie mode getter BL sites shifted')
    if s.other_stride_site is not None:
        require(w2(s.other_stride_site)==0x15c305c6,
            'raw misleading STRB NE immediate0x5C6 changed')
    return {
        'p_source_offset':'0x6e',
        'intermediate_offset':'0x1e',
        'first_32bit_LDRB_STRB_pair':hex(s.first_load),
        'second_32bit_LDRB_STRB_pair':hex(s.second_load),
        'active_Recorder_fps_RAM':hex(s.active_fps_ram),
        'original_byte_pairs_verified':2,
        'template_copy_contains_FPS':True,
        'active_FPS_getter_A32_verified':True,
        'direct_original_getter_BL_verified':3,
    }


def decomp(s,adapter,getter,exporter,consumers,refs,wrong):
    transfer='*(undefined1 *)(param_1 + 0x1e) = param_2[0x6e];'
    require(adapter.count(transfer)==2 and 'if (param_3 == 1)' in adapter,
            'both original FPS source P->intermediate paths not present')
    require(f'return DAT_{s.active_fps_ram:08x};' in getter,
            'active getter not reading isolated FPS byte')
    require(f'param_1[0x6e] = DAT_{s.active_fps_ram:08x};' in exporter,
            'reverse ACTIVE->snapshot FPS exporter not present')
    getter_name=f'FUN_{s.getter:08x}()'
    c1,c2=consumers
    require(getter_name in c1 and
            c2.count(getter_name)>=2 and
            'case 6:' in c2 and
            'switch(uVar3)' in c2,
            'original movie mode consumers not using FPS getter enum6')
    require(f'PROBE_TARGET addr={s.active_fps_ram:08x} refs=2' in refs and
            f'PROBE_REF from={s.getter+16:08x} to={s.active_fps_ram:08x} type=READ' in refs,
            'read-only Ghidra original active RAM xref not pinned')
    if s.other_stride_site is not None:
        require('0x15c6) = param_1;' in wrong and
                '0xac8' in wrong and
                '0x5c6) = param_1;' not in wrong,
                'false writer #0x5c6 must remain a different base+0x15c6')
    else:
        require(wrong=='','unexpected XT4 candidate asserted')
    return {
       'input_movie_fps_transferred_conditional_twice':True,
       'active_fps_getter_received_by_movie_mode_constructor':True,
       'snapshot_exporter_is_reverse_not_input_initial_writer':True,
       'raw_A32_offset_only_is_not_pointer_identity':True,
       'original_camera_actual_runtime_fps_value_observed':False,
       'Movie_context_plus_5C6_or_5C7_equal_active_fps_proven':False,
       'Main10_hardware_accepted_or_4K60_recorded':False,
    }

def func(log,addr):return st59.function_c_any(log,addr)

def run(root):
    st63.run(root)  # all original SHA-pinned prior stages + current menu audit
    rows=[]
    for name,s in SPECS.items():
        m=st32.MODELS[name]
        b1=(root/f'x6-{name}/section-1.bin').read_bytes()
        b2=(root/f'x6-{name}/section-2.bin').read_bytes()
        w1=lambda addr:st32.rom_word(b1,BASE,addr)
        w2=lambda addr:st32.rom_word(b2,m.sec2base,addr)
        a=func((root/f'{name}_stage64_recorder_converter_movie_fps.log').read_text(),m.adapter)
        t=(root/f'{name}_stage64_active_FPS_getters_export.log').read_text()
        g=func(t,s.getter);e=func(t,s.exporter)
        c=(root/f'{name}_stage64_active_FPS_getter_consumers.log').read_text()
        if s.name=='xs10':first=0x022d1870
        else:first=0x0223de00
        consumers=(func(c,first),func(c,s.movie_parent_func))
        refs=(root/f'{name}_stage64_active_eMovieFps_refs.log').read_text()
        wrong=(func((root/'xs10_stage64_fps_writer_candidate.log').read_text(),s.other_stride_func)
               if s.other_stride_func is not None else '')
        rows.append({'model':name,**original_arm(s,w1,w2),
                     **decomp(s,a,g,e,consumers,refs,wrong),
                     'camera_USB_FF80_RAM_Flash_ROM_edit':False})
    return {'models':rows,
        'same_source_to_active_and_movie_getter_EVIDENCE_both_models':True,
        'earlier_original_ROM_SHA_audits_recertified':True,
        'independent_LUT_4K59_94_and_VPU_Main10_hardware_joint_reachability':False}

def main():
    arg=argparse.ArgumentParser(description=__doc__)
    arg.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(run(arg.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE64 ORIGINAL GUI FPS +0x6E -> RECORDER ACTIVE +0x1E AND GETTER PASS')
    print('UNKNOWN: Movie+0x5C6/5C7 alias and joint 4K59.94 HEVC Main10 recording')
if __name__=='__main__':main()
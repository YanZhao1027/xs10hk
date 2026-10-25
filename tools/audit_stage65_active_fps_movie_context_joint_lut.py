#!/usr/bin/env python3
"""Phase65: close conditional active FPS -> Movie +0x5C6 -> joint 4K LUT.

X-S10 3.11 and X-T4 2.12 ORIGINAL ARM and read-only Ghidra: a
Movie-object initializer copies 0x478/0x47C from active Recorder template to
Movie+0x5A8 before the class-selective 96x0x40 mode lookup. FPS+0x1E in
that template maps to Movie+0x5C6; adjacent +0x1F maps Movie+0x5C7 but its
initial source is not independently established. For class0 the lookup uses
+0x5C6, for classes1/2 +0x5C7. Shared ROM rows include 4K fps6 when
mode key remains 7 and variant matches; flag/other branches can select 1080.
Static conditions, not evidence of X-S10 physical 4K60/Main10 recording.
No USB/FF80, ROM edits, VPU flashing or proprietary data publication.
"""
import argparse,json,re,sys
from dataclasses import dataclass
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage64_real_movie_fps_active_recorder_bridge as st64
import audit_stage46_joint_movie_mode_matrix as st46
import audit_recorder_codec_forward_stage32 as st32
import audit_mode_profile_registry_stage29 as st29
import audit_stage59_movie_menu_ROM_allowlist as st59

@dataclass(frozen=True)
class Spec:
    model:str
    copier:int
    copier_bl:int
    constructor:int
    copy_call:int
    table_bl:int
    table_matcher:int
    length:int
    template:int
    memcpy:int

SPECS={
 'xs10':Spec('xs10',0x012bd150,0x012bd178,0x022d5fec,
             0x022d61ac,0x022d6978,0x022e123c,0x478,
             0x01c24dd8,0x012a9148),
 'xt4':Spec('xt4',0x012957c0,0x012957e8,0x022425bc,
            0x0224277c,0x02242f48,0x0224db10,0x47c,
            0x01b83540,0x01281848),
}


def require(ok,why):
    if not ok:raise ValueError('STAGE65 original active FPS to Movie joint lookup: '+why)


def arm(s,w1,w2):
    a=s.copier
    require(st32.movpart(w1(a+16),5) | st32.movpart(w1(a+20),5,True)<<16 ==s.template,
            'A32 MOVW/MOVT source is not active Recorder template')
    need={
      a+24:0xe3002000|s.length,
      a+28:0xe1a01005,
      a+32:0xe2840e5a,
      a+36:0xe2800008,
    }
    for loc,word in need.items():
        require(w1(loc)==word,'A32 active->Movie memcpy length/source/dest changed '+hex(loc))
    require(st29.bl_target(w1(s.copier_bl),s.copier_bl)==s.memcpy,
            'actual original memcpy helper BL differs')
    require(st29.bl_target(w2(s.copy_call),s.copy_call)==s.copier,
            'Movie constructor BL does not call template copy')
    require(st29.bl_target(w2(s.table_bl),s.table_bl)==s.table_matcher,
            'Movie constructor BL does not call 4-key LUT matcher')
    require(s.copy_call<s.table_bl and
            s.template+0x1e == st64.SPECS[s.model].active_fps_ram and
            0x1f<s.length and 0x5a8+0x1e==0x5c6 and
            0x5a8+0x1f==0x5c7 and
            s.length==st32.MODELS[s.model].copy_len and
            s.template==st32.MODELS[s.model].template_base,
            'active template FPS arithmetic or known copy length changed')
    return {'active_FPS_source_RAM':hex(s.template+0x1e),
            'Movie_FPS_offset_if_class0':'0x5C6',
            'Movie_FPS_offset_if_class1_2':'0x5C7',
            'copy_bytes':s.length,
            'movie_constructor_calls_copy_before_LUT':True,
            'original_A32_memcpy_and_parent_calls_verified':True}


def cflow(s,copier,constructor,matcher):
    cp=f'FUN_{s.memcpy:08x}(param_1 + 0x5a8,0x{s.template:x},0x{s.length:x});'
    require(cp in copier,'Ghidra source/destination/length not matched')
    # The post-copy correction adjusts +0x5B0, +0x5CB; no direct fps setter.
    require('param_1 + 0x5b0' in copier and 'param_1 + 0x5cb' in copier,
            'Movie copy post-copy normalization disappeared')
    locations=[constructor.find(text) for text in (
        f'FUN_{s.copier:08x}(iVar8);',
        'cVar2 = *(char *)(iVar8 + 0x5c6);',
        'cVar3 = *(char *)(iVar8 + 0x5c7);',
        f'FUN_{s.table_matcher:08x}(iVar8);')]
    require(min(locations)>=0 and locations==sorted(locations),
            'Ghidra Movie init no longer contains ordered copy->fps reads->LUT')
    require('cVar2 = *(char *)(param_1 + 0x5c6);' in matcher and
            'cVar2 = *(char *)(param_1 + 0x5c7);' in matcher and
            '(byte)(cVar1 - 1U) < 2' in matcher and
            'pcVar10[3] == cVar2' in matcher,
            'Movie LUT no longer chooses two fps fields by class')
    return {'Movie_parent_same_argument_copied_and_looked_up':True,
            'Movie_FPS_copy_necessarily_survives_indirect_calls_proven':False,
            'Movie_0x5C7_adjacent_byte_initial_provenance':False}


def static_joint(s,section1,section2):
    model=st46.MODELS[s.model]
    base2=st32.MODELS[s.model].sec2base
    rows=st46.read_records(st46.section_slice(
            section2,base2,model.movie_table,st46.RECORDS*st46.STRIDE+1))
    width=st46.section_slice(section1,st59.BASE,model.widths,st46.DIM_BYTES)
    height=st46.section_slice(section1,st59.BASE,model.heights,st46.DIM_BYTES)
    hits=[]
    for index,r in enumerate(rows):
        if r[0]==0 and r[3]==6:
            resolution=st46.lookup_width_height(r,width,height)
            if resolution[1]==2160:
                hits.append((index,resolution))
    require(hits==[(15,(4096,2160)),(16,(4096,2160)),(17,(4096,2160)),
                   (33,(3840,2160)),(34,(3840,2160)),(35,(3840,2160))],
            'genuine 4K fps6 candidates in original same-model ROM changed')
    pairs=[]
    for hi,wide,narrow in ((2,(3840,2160),(1920,1080)),
                           (7,(4096,2160),(2048,1080))):
        original=st46.match_record(rows,0,(hi<<8)|7,6,1)
        coerced=st46.match_record(rows,0,(hi<<8)|6,6,1)
        require(len(original)==len(coerced)==1,
                'paired mode keys no longer yield unique ROM records')
        decoded=(st46.lookup_width_height(rows[original[0]],width,height),
                 st46.lookup_width_height(rows[coerced[0]],width,height))
        require(decoded==(wide,narrow),
                'fps6 mode low7 vs low6 ROM candidate resolution changed')
        pairs.append({'mode_key_hi':hi,'fps_menu_enum':6,'class':0,'variant':1,
            'hypothetical_mode7_record_index':original[0],
            'hypothetical_mode7_resolution':list(wide),
            'hypothetical_mode6_record_index':coerced[0],
            'hypothetical_mode6_resolution':list(narrow)})
    return {'original_ROM_class0_2160p_fps6_candidates':len(hits),
            'joint_mode_fps6_counterfactuals':pairs,
            'actual_4K59_94_source_or_codec_device_success_proven':False,
            'separate_4K_flag_mode_key_may_select_1080':True}


def fun(log,a):return st59.function_c_any(log,a)


def analyze(root):
    st64.run(root)
    out=[]
    for m,s in SPECS.items():
        section1=(root/f'x6-{m}/section-1.bin').read_bytes()
        section2=(root/f'x6-{m}/section-2.bin').read_bytes()
        w1=lambda a:st32.rom_word(section1,st59.BASE,a)
        w2=lambda a:st32.rom_word(section2,st32.MODELS[m].sec2base,a)
        cp=fun((root/f'{m}_stage65_movie_object_init_sources.log').read_text(),s.copier)
        cs=(root/f'{m}_stage65_fps_to_movie_mode_chain.log').read_text()
        ctor=fun(cs,s.constructor);match=fun(cs,s.table_matcher)
        out.append({'model':m,**arm(s,w1,w2),**cflow(s,cp,ctor,match),
            **static_joint(s,section1,section2),
            'camera_USB_FF80_RAM_flash_ROM_patch':False})
    return {'models':out,
       'all_prior_original_SHA_pinned_ROM_audits_reverified':True,
       'runtime_menu_sensor_encoder_joint_mode_reachability_unproven':True,
       'physical_Main10_SPS_not_observed':True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE65 ORIGINAL ACTIVE FPS -> MOVIE+0x5C6 -> CLASS0 JOINT LUT PASS')
    print('UNKNOWN: runtime +0x5C7 source, mode-gate joint reachability, 4K60 Main10 file.')
if __name__=='__main__':main()
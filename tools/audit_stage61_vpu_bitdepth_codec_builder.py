#!/usr/bin/env python3
"""Phase61: same Recorder->VPU bitdepth-code and codec-class gate on both ROMs.

The confirmed source-config constructor stores *constant numeric code 1* at
VPU config+0x0C, sets config+0x188 to 0/1 from a distinct Recorder runtime
flag at input+0xADDA, and calls a shared-architecture VPU wrapper. VPU init
rejects codec0 if depth>1, and rejects codec>1. This does NOT map numeric
bitdepth1 to actual 8/10-bit samples, nor prove Main10, 4K60 or flashability.
Read-only SHA-pinned original X6, no camera USB/FF80 or firmware changes.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage60_h265_codec_reloader as st60
import audit_stage53_gui_rec_setparam_tx as st53
import audit_mode_profile_registry_stage29 as st29
import audit_stage55_recorder_20b_fsm_lifecycle as st55

@dataclass(frozen=True)
class Spec:
    name:str
    cfg:int
    builder:int
    driver_wrapper:int
    driver_init:int
    bitdepth_mov:int
    codec_flag_load:int
    codec0_branch:int
    codec1_mov:int
    codec0_mov:int
    codec0_back_branch:int
    wrapper_BL:int
    wrapper_driver_BL:int
    codec_read:int
    depth_read:int
    depth_cmp:int
    reject_depth_branch:int
    reject_codec_cmp:int
    xref_bitdepth_site:int
    xref_codec_sites:tuple[int,int]

SPECS={
 'xs10':Spec('xs10',0x02945a08,0x022dee64,0x011f7190,0x011f97dc,
       0x022def4c,0x022def58,0x022def60,0x022def6c,
       0x022df15c,0x022df17c,0x022df0f8,0x011f7330,
       0x011f97fc,0x011f9808,0x011f980c,0x011f9810,
       0x011f991c,0x022def50,(0x022def70,0x022df160)),
 'xt4':Spec('xt4',0x028a5150,0x0224b65c,0x011ca83c,0x011cce88,
       0x0224b744,0x0224b750,0x0224b758,0x0224b764,
       0x0224b954,0x0224b974,0x0224b8f0,0x011ca9dc,
       0x011ccea8,0x011cceb4,0x011cceb8,0x011ccebc,
       0x011ccfc8,0x0224b748,(0x0224b768,0x0224b958))
}

def require(ok,reason):
    if not ok:raise ValueError('STAGE61 original Recorder/VPU bitdepth: '+reason)

def arm(s,section1,section2):
    w1=section1 if callable(section1) else lambda a:st29.word(section1,0x01021000,a)
    w2=section2 if callable(section2) else lambda a:st29.word(section2,st53.SPECS[s.name].sec2base,a)
    for offset,expected in ((-8,None),(-4,None),(0,0xe583200c)):
        a=s.bitdepth_mov+4+offset
        if expected is not None:require(w2(a)==expected,'VPU depth original STR word differs')
    require(w2(s.bitdepth_mov)==0xe3a02001 and
            w2(s.bitdepth_mov+4)==0xe583200c and
            w2(s.codec_flag_load)==0xe5d33dda and
            w2(s.codec_flag_load+4)==0xe1530002 and
            st55.branch(w2,s.codec0_branch)==
               (0x022df154 if s.name=='xs10' else 0x0224b94c),
            'original A32 VPU config code1 store/codec source flag compare')
    # MOVW/MOVT for config-base in R3 immediately before the depth store.
    need_base=(st29.half(w2(s.bitdepth_mov-8),False,3) |
               (st29.half(w2(s.bitdepth_mov-4),True,3)<<16))
    require(need_base==s.cfg,'original config pointer base before depth store differs')
    require(w2(s.codec1_mov)==0xe3a02001 and
            w2(s.codec1_mov+4)==0xe5832188 and
            w2(s.codec0_mov)==0xe3a02000 and
            w2(s.codec0_mov+4)==0xe5832188,
            'both codec class 0/1 writes not encoded in original ARM')
    back=st55.branch(w2,s.codec0_back_branch)
    require(back==(0x022def90 if s.name=='xs10' else 0x0224b788) and
            back<s.wrapper_BL and s.codec0_back_branch>s.wrapper_BL,
            'codec0 alternative block is not jumping back before VPU init')
    require(st29.bl_target(w2(s.wrapper_BL),s.wrapper_BL)==s.driver_wrapper and
            st29.bl_target(w1(s.wrapper_driver_BL),s.wrapper_driver_BL)==s.driver_init,
            'actual VPU wrapper or driver call target changed')
    require(w1(s.codec_read)==0xe5913188 and
            w1(s.codec_read+4)==0xe3530000 and
            w1(s.depth_read)==0xe591200c and
            w1(s.depth_cmp)==0xe3520001 and
            w1(s.reject_depth_branch)==0x8a000067 and
            w1(s.reject_codec_cmp)==0xe3530001,
            'VPU bitdepth/codec A32 input check does not match decompiler')
    return {'bitdepth_fixed_numeric_code_on_this_path':1,
            'codec_class_0_or_1_from_distinct_runtime_predicate':True,
            'codec0_plus_bitdepth_code_gt1_rejected_at_driver_gate':True,
            'codec1_does_not_trigger_this_particular_depth_gate':True,
            'wrapper_original_BL_and_driver_A32_checked':True,
            'branch_backwards_for_codec0_still_before_driver_call':True}

def decomp(s,builder,wrapper,driver,refs):
    depth_addr=s.cfg+0xc;codec_addr=s.cfg+0x188
    require(f'_DAT_{depth_addr:08x} = 1;' in builder and
            f'_DAT_{codec_addr:08x} = (uint)!bVar9;' in builder and
            "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';" in builder,
            'source VPU builder byte code1 and codec class runtime predicate differ')
    require(f'FUN_{s.driver_wrapper:08x}(0,&DAT_{s.cfg:08x},' in builder and
            f'FUN_{s.driver_init:08x}();' in wrapper,
            'VPU builder/wrapper interface path missing')
    require('(*(uint *)(param_2 + 0x188) == 0) && (1 < *(uint *)(param_2 + 0xc))' in driver and
            '1 < *(uint *)(param_2 + 0x188)' in driver and
            's__init_bit_depth_ERROR_' in driver and
            's__init_video_codec_ERROR_' in driver and
            's__init_h265_drv_sequence_sts_ERRO_' in driver,
            'underlying driver VPU bitdepth/codec checks missing or changed')
    lines=re.findall(r'PROBE_TARGET addr=([0-9a-f]+) refs=(\d+)',refs)
    summary={int(a,16):int(count) for a,count in lines}
    require(summary.get(depth_addr)==1 and summary.get(codec_addr)==2,
            'bounded direct GUI/Ghidra xrefs of VPU config stores drifted')
    writes=re.findall(r'PROBE_REF from=([0-9a-f]+) to=([0-9a-f]+) type=WRITE',refs)
    w={(int(a,16),int(b,16)) for a,b in writes}
    require((s.xref_bitdepth_site,depth_addr) in w and
            all((a,codec_addr) in w for a in s.xref_codec_sites),
            'original VPU config direct writer xrefs not confirmed')
    return {'bitdepth_GUI_MovieCodec_same_field_proven':False,
            'VPU_bitdepth_numeric1_maps_to_HEVC_Main10_10bit_proven':False,
            'upstream_runtime_param1_plus_ADDA_flag_meaning_proven':False,
            'no_other_indirect_VPU_struct_mutators_proven':False}

def function(log,addr):
    import re
    for chunk in log.split('TRACE_DECOMP_BEGIN (GhidraScript)')[1:]:
        c=chunk.split('TRACE_DECOMP_END (GhidraScript)')[0]
        if re.search(r'\bFUN_%08x\s*\('%addr,c[:320]):return c
    raise ValueError('Ghidra function not captured '+hex(addr))

def run(root):
    st60.analyze(root)
    rows=[]
    for m,s in SPECS.items():
        a=(root/f'x6-{m}/section-1.bin').read_bytes()
        b=(root/f'x6-{m}/section-2.bin').read_bytes()
        code=function((root/f'{m}_stage61_recorder_calls_vpu.log').read_text(),s.builder)
        wrapper=function((root/f'{m}_stage61_vpu_init_upstream.log').read_text(),s.driver_wrapper)
        driver=function((root/f'{m}_stage61_bitdepth_error_callsite.log').read_text(),s.driver_init)
        refs=(root/f'{m}_stage61_vpu_config_field_refs.log').read_text()
        rows.append({'model':m,**arm(s,a,b),**decomp(s,code,wrapper,driver,refs),
                     'hardware_codec_Main10_or_4K60_tested':False,
                     'no_camera_USB_FF80_firmware_write_or_flash':True})
    return {'models':rows,
            'all_previous_SHA_pinned_original_X6_audits_recertified':True,
            'same_static_VPU_bitdepth_code1_constructed_on_both_models':True,
            'the_static_VPU_gate_is_not_a_complete_H265_Main10_capability_test':True}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(run(a.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE61 ORIGINAL VPU BITDEPTH CODE1 / CODEC CLASS GUARD PASS')
    print('UNKNOWN: actual 10bit SPS/Main10/4K60, VPU depth enum map, live path.')
if __name__=='__main__':main()
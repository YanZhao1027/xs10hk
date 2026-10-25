#!/usr/bin/env python3
"""Stage62 close-loop of Phase47 activity Codec source into Phase61 VPU class.

Original X-S10 3.11 and X-T4 2.12 ROM ARM confirms getter LDRB of
Recorder active Codec RAM, BL from movie context init, and STRB to movie
+0xADDA; Phase61 uses byte+0xADDA to decide VPU class0/1 independently
of bitdepth code1. This is NOT proof numeric VPU class == GUI Codec enum,
Main10, 4K60, actual camera execution, or safe patching.
Rerun Stage61 and all preceding SHA-pinned original X6 audits first.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage61_vpu_bitdepth_codec_builder as st61
import audit_stage53_gui_rec_setparam_tx as st53
import audit_mode_profile_registry_stage29 as st29

@dataclass(frozen=True)
class Spec:
    model:str
    cfg_active:int
    getter:int
    getter_base:int
    getter_offset:int
    call_site:int
    store_site:int
    source_setup_fn:int
    vpu_config_fn:int
    vpu_class_addr:int

SPECS={
 'xs10':Spec('xs10',0x01c25208,0x012c048c,0x01c24dd8,0x430,
          0x022d62a4,0x022d62a8,0x022d5fec,0x022dee64,0x02945b90),
 'xt4':Spec('xt4',0x01b83974,0x01298c18,0x01b83540,0x434,
          0x02242874,0x02242878,0x022425bc,0x0224b65c,0x028a52d8),
}

def require(ok,why):
    if not ok:raise ValueError('Stage62 active Recorder codec->VPU bridge: '+why)

def original_arm(s,w1,w2):
    getter=s.getter
    gbase=(st29.half(w1(getter+8),False,3) |
           st29.half(w1(getter+12),True,3)<<16)
    require(gbase==s.getter_base and
            gbase+s.getter_offset==s.cfg_active,
            'original A32 getter base and offset cannot identify active codec')
    require(w1(getter+16)==0xe5d30000|s.getter_offset,
            'original getter must LDRB R0 of active codec address')
    require(st29.bl_target(w2(s.call_site),s.call_site)==getter and
            w2(s.store_site)==0xe5c50dda,
            'original movie initialization does not store getter result into +0xADDA')
    require(s.store_site==s.call_site+4,
            'BL->STRB must be adjacent; no redefinition of R0')
    require(st61.SPECS[s.model].codec_flag_load==
            (0x022def58 if s.model=='xs10' else 0x0224b750),
            'Phase61 downstream runtime flag load not same model')
    require(st61.SPECS[s.model].cfg+0x188==s.vpu_class_addr,
            'VPU codec class field identity differs')
    return {'source_activity_codec_RAM':hex(s.cfg_active),
            'getter_function':hex(getter),
            'movie_context_flag_offset':'+0xADDA',
            'getter_to_movie_context_BL_STRB_original_A32_verified':True,
            'phase61_VPU_class_selector_uses_this_context_flag':True,
            'codec_class0_when_context_flag_equals_one':True,
            'codec_class1_when_context_flag_not_one':True,
            'independent_VPU_bitdepth_numeric_code_on_that_path':1}

def decomp(s,getter_c,source_c,vpu_c):
    require(f'return DAT_{s.cfg_active:08x};' in getter_c,
            'Ghidra getter does not read precise activity byte')
    require(('FUN_%08x();'%s.getter) in source_c and
            '*(undefined1 *)(iVar8 + 0xadda) = uVar4;' in source_c and
            source_c.index('FUN_%08x();'%s.getter)<source_c.index('0xadda) = uVar4;'),
            'Ghidra movie init not assigning returned active codec to flag')
    require("bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';" in vpu_c and
            f'_DAT_{s.vpu_class_addr:08x} = (uint)!bVar9;' in vpu_c and
            f'_DAT_{st61.SPECS[s.model].cfg+0xc:08x} = 1;' in vpu_c,
            'VPU runtime class/independent constant depth not verified')
    return {'GUI_mode_codec_enum_and_VPU_class_same_numbering_proven':False,
            'other_unobserved_context_flag_writers_excluded':False,
            'actual_bitdepth1_corresponds_to_8bit_or_10bit_proven':False,
            'actual_Main10_SPS_or_4K60_file_proven':False}

def get_function(log,address):
    for chunk in log.split('TRACE_DECOMP_BEGIN (GhidraScript)')[1:]:
        c=chunk.split('TRACE_DECOMP_END (GhidraScript)')[0]
        if re.search(r'\bFUN_%08x\s*\('%address,c[:320]):return c
    raise ValueError('Ghidra not found '+hex(address))

def analyze(root):
    st61.run(root)
    out=[]
    for name,s in SPECS.items():
        b1=(root/f'x6-{name}/section-1.bin').read_bytes()
        b2=(root/f'x6-{name}/section-2.bin').read_bytes()
        w1=lambda a:st29.word(b1,0x01021000,a)
        w2=lambda a:st29.word(b2,st53.SPECS[name].sec2base,a)
        getter=get_function((root/f'{name}_stage62_codec_runtime_value_origin.log').read_text(),s.getter)
        source=get_function((root/f'{name}_stage62_vpu_codec_runtime_flag_setter.log').read_text(),s.source_setup_fn)
        vpu=get_function((root/f'{name}_stage61_recorder_calls_vpu.log').read_text(),s.vpu_config_fn)
        out.append({'model':name,**original_arm(s,w1,w2),**decomp(s,getter,source,vpu),
                    'phase47_already_identified_source_setter':True,
                    'new_work_links_phase47_to_phase61_driver':True,
                    'camera_firmware_ROM_modified':False})
    return {'models':out,
            'SHA_pinned_all_prior_audits_reverified':True,
            'both_models_have_same_qualified_ROM_data_edge':True,
            'no_actual_camera_USB_FF80_RAM_Flash':True}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(a.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE62 ORIGINAL ACTIVE CODEC TO VPU CLASS WITH SEPARATE DEPTH PASS')
    print('UNKNOWN: GUI/VPU enum inversion semantic, bitdepth numeric mapping, Main10, 4K60.')
if __name__=='__main__':main()
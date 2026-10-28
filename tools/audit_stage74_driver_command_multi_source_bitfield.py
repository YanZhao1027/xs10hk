#!/usr/bin/env python3
"""Phase74: two original interface-status producers write one driver +0x624 word.

X-S10 3.11/X-T4 2.12 static ROM, read-only Ghidra, no hardware.
The CPU effective address from the original call is 0xFFF7B624 but the
physical mapping, peripheral behavior and 4K60/Main10 are UNOBSERVED.
"""
import argparse,json,sys
from dataclasses import dataclass
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage73_interface_index_into_driver_command as st73
import audit_stage59_movie_menu_ROM_allowlist as st59
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_codec_forward_stage32 as st32

BASE=0xfff7b000
MODE_MASK=0x00300000
STATUS22_MASK=0x00c00000
STATUS28_MASK=0x70000000
STATUS_MASK=STATUS22_MASK|STATUS28_MASK
ENABLE19=0x00080000
ENABLE21=0x00200000

@dataclass(frozen=True)
class Spec:
    model:str
    driver:int
    builder:int
    marshaller:int
    finalizer:int
    status:int
    status_word:int
    alternative:int
    alternative_wrapper:int
    rmw:int
    build_BL:int
    after_build_status_BL:int
    status_rmw_BL:int
    alternative_status_BL:int
    alternative_wrapper_BL:int
    original_marshaller624_store:int
    original_rmw624_read:int
    original_rmw624_store:int
    original_finalizer828_read:int
    original_finalizer828_store:int
    state_name:str
    state_word:str
    selected_type:str
    secondary_flag:str

SPECS={
 'xs10':Spec('xs10',0x0126c388,0x0126d1fc,0x0126f050,0x0126e804,
   0x0126ae08,0x0126ae08,0x0126c0fc,0x01269494,0x0126d6b4,
   0x0126c944,0x0126c948,0x0126ae58,0x0126c11c,0x0126949c,
   0x0126f184,0x0126d6c4,0x0126d708,0x0126e900,0x0126e908,
   'DAT_01c84f88','_DAT_01c85688','DAT_01c84f8a','DAT_01c84f8c'),
 'xt4':Spec('xt4',0x012425a0,0x01243414,0x01245268,0x01244a1c,
   0x01241020,0x01241020,0x01242314,0x0123f6ac,0x012438cc,
   0x01242b5c,0x01242b60,0x01241070,0x01242334,0x0123f6b4,
   0x0124539c,0x012438dc,0x01243920,0x01244b18,0x01244b20,
   'DAT_01be5054','_DAT_01be5754','DAT_01be5056','DAT_01be5058'),
}

def require(ok,message):
    if not ok:raise ValueError('STAGE74 original driver command multi-source: '+message)


def status_params(stateword,kind,subcode):
    """Simulate original status switch. No live sensor values or output.

    stateword contains a runtime data word; kind and subcode are separate
    runtime bytes. This models the *conditional* choices for the RMW helper.
    """
    kind=int(kind)&0xff
    if (int(stateword)&0xffff00)==0x10100:
        return 3,(5 if ((kind-1)&0xff)<2 else 6)
    if kind<2:return (1 if int(subcode)==0 else 2),0xf
    return 0xf,0xf


def update_fields(word624,word614,field22,field28):
    """Original RMW arithmetic on caller-supplied values: no IO of any kind."""
    w=int(word624)&0xffffffff;en=int(word614)&0xffffffff
    if field22==0xf:en|=ENABLE19
    else:
        en&=~ENABLE19
        w=(w&0xff3fffff)|((field22&3)<<22)
    if field28==0xf:en|=ENABLE21
    else:
        en&=~ENABLE21
        w=(w&0x8fffffff)|((field28&7)<<28)
    w&=0xffffffff;en&=0xffffffff
    require((word624^w)&~STATUS_MASK==0,
           'RMW unexpectedly modifies command word outside bits22/23 and 28/30')
    return w,en


def simulate_command(mode_field8,stateword,kind,subcode,other_word=0,
                     enable614=0):
    """Stage73 field20/21 plus Stage74 original RMW masks, entirely synthetic."""
    source=(other_word&~MODE_MASK)|st73.word_20_21_from_byte(mode_field8)
    p2,p3=status_params(stateword,kind,subcode)
    w,en=update_fields(source,enable614,p2,p3)
    return {'word624':w,'word614':en,'status22':p2,'status28':p3,
            'mode20_21':w&MODE_MASK}


def original_code(spec,rom):
    W=lambda a:st32.rom_word(rom,st59.BASE,a)
    links=[(spec.build_BL,spec.builder),
           (spec.after_build_status_BL,spec.status),
           (spec.status_rmw_BL,spec.rmw),
           (spec.alternative_status_BL,spec.status),
           (spec.alternative_wrapper_BL,spec.alternative)]
    for address,destination in links:
        require(st29.bl_target(W(address),address)==destination,
                'original A32 BL destination changed '+hex(address))
    for addr,offset,isread,reg in [
        (spec.original_marshaller624_store,0x624,False,3),
        (spec.original_rmw624_read,0x624,True,0),
        (spec.original_rmw624_store,0x624,False,0),
        (spec.original_finalizer828_read,0x828,True,0),
        (spec.original_finalizer828_store,0x828,False,0),
    ]:
        w=W(addr)
        require(w&0x0c000000==0x04000000 and w&0xfff==offset and
                ((w>>20)&1)==int(isread) and (w>>16)&15==reg,
                'original ARM direct offset load/store changed '+hex(addr))
    require(spec.build_BL+4==spec.after_build_status_BL,
            'initial pack and status RMW call no longer adjacent')
    return {'original_A32_direct_BL_count':len(links),
       'original_A32_direct_field_load_store_count':5,
       'driver_builder_next_instruction_calls_status_RMW':True,
       'effective_context_base_passed_to_both_paths':hex(BASE),
       'calculated_A32_command_word_address':hex(BASE+0x624),
       'calculated_A32_finalizer_word_address':hex(BASE+0x828),
       'absolute_region_proven_to_be_MMIO_hardware_register':False}


def fun(log,a):return st59.function_c_any(log,a)


def original_decompile(spec,root):
    m=spec.model
    dr=fun((root/f'{m}_stage72_only_driver_state5.log').read_text(),spec.driver)
    status=fun((root/f'{m}_stage74_RMW_caller_trace.log').read_text(),spec.status)
    rmw=fun((root/f'{m}_stage74_RMW_caller_trace.log').read_text(),spec.rmw)
    alt=fun((root/f'{m}_stage74_alt_status_caller.log').read_text(),spec.alternative)
    wrap=fun((root/f'{m}_stage74_state5_dynamic_trigger.log').read_text(),spec.alternative_wrapper)
    marshal=fun((root/f'{m}_stage73_driver_command_marshalling.log').read_text(),spec.marshaller)
    finalize=fun((root/f'{m}_stage73_driver_command_marshalling.log').read_text(),spec.finalizer)
    d=f'FUN_{spec.builder:08x}(0xfff7b000,&local_7c,&local_6c,'
    s=f'FUN_{spec.status:08x}();'
    require(d in dr and s in dr and dr.index(d)<dr.index(s) and
            s in dr[dr.index(d):dr.index(d)+220],
            'driver original setup no immediate status bit RMW after builder')
    require(f'FUN_{spec.rmw:08x}(0xfff7b000,uVar1,uVar2);' in status and
            f'if (({spec.state_word} & 0xffff00) == 0x10100)' in status and
            f'if ((byte)({spec.selected_type} - 1) < 2)' in status and
            f'else if ({spec.selected_type} < 2)' in status and
            f"if ({spec.secondary_flag} == '\\0')" in status and
            'uVar1 = 3;' in status and 'uVar2 = 5;' in status and
            'uVar2 = 6;' in status and 'uVar1 = 0xf;' in status,
            'runtime type/secondary/status conditional RMW arguments shifted')
    for needle in ('uVar2 = *(uint *)(param_1 + 0x624);',
       'uVar2 = uVar2 & 0xff3fffff | (param_2 & 3) << 0x16;',
       'uVar2 = uVar2 & 0x8fffffff | (param_3 & 7) << 0x1c;',
       'if (param_2 == 0xf)', 'if (param_3 == 0xf)',
       '*(uint *)(param_1 + 0x614) = *(uint *)(param_1 + 0x614) | 0x80000;',
       '*(uint *)(param_1 + 0x614) = *(uint *)(param_1 + 0x614) | 0x200000;',
       '*(uint *)(param_1 + 0x624) = uVar2;',
       '*(uint *)(param_1 + 0x81c) = *(uint *)(param_1 + 0x81c) & 0xffffff;'):
        require(needle in rmw,'original context RMW mask/enable or auxiliary clear missing '+needle)
    require('(param_2[4] & 3) << 0x14' in marshal and
            '*(uint *)(param_1 + 0x624) = uVar2;' in marshal and
            '*(uint *)(param_1 + 0x620)' in marshal and
            '*(uint *)(param_1 + 0x628)' in marshal and
            '*(uint *)(param_1 + 0x630)' in marshal,
            'Phase73 original packet word not written by initial marshaller')
    require('*(uint *)(param_1 + 0x828)' in finalize and
            'return 0xffffffff;' in finalize and 'return 0;' in finalize,
            'finalizer +828 success/failure calculation differs')
    require(f'{spec.state_word} = CONCAT12(param_1,{spec.state_word});' in alt and
            spec.state_name in alt and "!= '\\x05'" in alt and f'FUN_{spec.status:08x}();' in alt and
            '0x2000000' in alt and '0x4000' in alt,
            'state5-only alternate reconfiguration path no longer repeats status RMW')
    require(f'FUN_{spec.alternative:08x}();' in wrap,
            'alternate control wrapper no longer calls status reconfiguration')
    refs=(root/f'{m}_stage74_status_word_provenance_refs.log').read_text()
    for addr,dest in ((spec.after_build_status_BL,spec.status),
                      (spec.status_rmw_BL,spec.rmw),
                      (spec.alternative_status_BL,spec.status)):
        require(f'PROBE_REF from={addr:08x} to={dest:08x} type=UNCONDITIONAL_CALL' in refs,
                'status context original Ghidra direct call missing '+hex(addr))
    scanner=(root/f'{m}_stage74_cmd_field_offset_scan.log').read_text()
    for tag,addr in [('624/READ',spec.original_rmw624_read),
                     ('624/WRITE',spec.original_rmw624_store),
                     ('624/WRITE',spec.original_marshaller624_store),
                     ('828/READ',spec.original_finalizer828_read),
                     ('828/WRITE',spec.original_finalizer828_store)]:
        require(f'ST74_SITE {tag} {addr:08x} ' in scanner,
                'independent Ghidra instruction offset scan missing '+hex(addr))
    return {'two_source_stores_target_same_plus624_word_in_original_code':True,
       'original_marshaller_sets_bits20_21':True,
       'status_updater_modifies_only_bits22_23_and_28_30':True,
       'status_updater_preserves_bits20_21_for_all_inputs':True,
       'status_sentinel_0xF_preserves_existing_subfield_and_sets_enable_flags':True,
       'separate_state5_gated_reconfiguration_caller':hex(spec.alternative),
       'actual_state5_delivery_and_hardware_acceptance_seen':False,
       'Movie_2160P_FPS6_input_to_status_word_verified':False}


def analyze(root):
    st73.analyze(root)
    result=[]
    for m,s in SPECS.items():
        rom=(root/f'x6-{m}/section-1.bin').read_bytes()
        r={'model':m,**original_code(s,rom),**original_decompile(s,root)}
        for byte in (0,1):
            for stateword in (0,0x10100):
                for typ in range(4):
                    for subcode in (0,1):
                        sim=simulate_command(byte,stateword,typ,subcode,0x89abcdef)
                        require(sim['mode20_21']==st73.word_20_21_from_byte(byte),
                            'synthetic unrelated status RMW removed Phase73 mode bits')
        result.append(r)
    return {'models':result,'SHA_pinned_original_Phase73_and_all_earlier_audits_pass':True,
       'static_two_independent_sources_reach_same_effective_driver_word':True,
       'no_proven_real_sensor_ISP_VPU_2160p60_or_Main10_video':True,
       'no_camera_USB_FF80_RAM_flash_ROM_DAT_changes':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE74 ORIGINAL INTERFACE + STATUS COMPOSE SAME DRIVER +0x624 WORD PASS')
    print('UNKNOWN: physical address classification, actual sensor timing or Movie/HEVC Main10 link.')
if __name__=='__main__':main()

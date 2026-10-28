#!/usr/bin/env python3
"""Phase76 read-only original-ROM: caller stack byte2 -> profile class2.

Only X-S10 FW3.11/X-T4 FW2.12 static ARM/Ghidra evidence. The caller sets
sixth config byte2, writes word+0x4B0 bits24..27 before the Phase75 finalizer.
Any concurrent overwrite, actual HDMI/sensor mapping, real 4K60 or Main10
output remains unknown. This script never touches a camera or modifies ROM.
"""
import argparse,json,sys
from dataclasses import dataclass
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage75_video_clock_range_catchall as s75
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_mode_profile_registry_stage29 as s29
import audit_recorder_codec_forward_stage32 as s32

@dataclass(frozen=True)
class Spec:
    model:str
    driver:int
    mov2:int
    store2:int
    argpointer:int
    driverbase:int
    class_builder_BL:int
    class_builder:int
    setter_BL:int
    setter:int
    setter_load:int
    setter_store:int
    packet_builder_BL:int
    packet_builder:int
    finalize_BL:int
    finalizer:int

SPECS={
 'xs10':Spec('xs10',0x0126c388,0x0126c7f4,0x0126c7f8,
  0x0126c804,0x0126c808,0x0126c80c,0x0126d13c,
  0x0126d198,0x0126e7a8,0x0126e7b0,0x0126e7b8,
  0x0126c944,0x0126d1fc,0x0126d298,0x0126e804),
 'xt4':Spec('xt4',0x012425a0,0x01242a0c,0x01242a10,
  0x01242a1c,0x01242a20,0x01242a24,0x01243354,
  0x012433b0,0x012449c0,0x012449c8,0x012449d0,
  0x01242b5c,0x01243414,0x012434b0,0x01244a1c)
}

COMMAND_CONTEXT=0xfff7b000
CLASS_FIELD=0x4b0
CLASS_SHIFT=24
CLASS_MASK=0x0f000000
CLASS_SOURCE_BYTE=2


def need(ok,msg):
    if not ok:raise ValueError('STAGE76 driver profile category provenance: '+msg)


def class_from_six_bytes(blob,initial_word=0):
    """Artificial dataflow model of sixth byte, not a hardware command."""
    need(len(blob)>=6,'six input configuration bytes required')
    v=(blob[5]&15)
    result=((initial_word&0xf0ffffff)|(v<<24))&0xffffffff
    return result,(result&CLASS_MASK)>>CLASS_SHIFT


def original_arm(spec,rom):
    W=lambda a:s32.rom_word(rom,s59.BASE,a)
    words={
      spec.mov2:0xe3a03002,
      spec.store2:0xe54b304f,
      spec.argpointer:0xe24b1054,
      spec.driverbase:0xe1a00005,
      spec.setter_load:0xe59034b0,
      spec.setter_store:0xe58034b0,
    }
    for site,expected in words.items():
        need(W(site)==expected,'raw ARM stack byte or +4B0 instruction differs '+hex(site))
    edges={
       spec.class_builder_BL:spec.class_builder,
       spec.setter_BL:spec.setter,
       spec.packet_builder_BL:spec.packet_builder,
       spec.finalize_BL:spec.finalizer,
    }
    for site,target in edges.items():
        need(s29.bl_target(W(site),site)==target,
             'original ARM BL target differs '+hex(site))
    need(spec.mov2+4==spec.store2 and
         spec.argpointer+4==spec.driverbase and
         spec.driverbase+4==spec.class_builder_BL and
         spec.class_builder_BL<spec.packet_builder_BL<spec.driver+1780 and
         spec.setter_BL>=spec.class_builder and
         spec.setter_BL<spec.class_builder+112 and
         spec.finalize_BL>=spec.packet_builder and
         spec.finalize_BL<spec.packet_builder+172,
         'local byte2 to selected class to finalizer original call structure differs')
    return {'original_exact_A32_stack_store_and_plus4B0_load_store':len(words),
            'original_A32_direct_BL_edges':len(edges),
            'original_stack_value_2_written_at':hex(spec.store2),
            'original_class_write_effective_address':hex(COMMAND_CONTEXT+CLASS_FIELD),
            'original_driver_profile_before_finalizer':True}


def fun(log,addr):return s59.function_c_any(log,addr)


def original_decompile(spec,root):
    m=spec.model
    dr=fun((root/f'{m}_stage72_only_driver_state5.log').read_text(),spec.driver)
    builder=fun((root/f'{m}_stage76_finalizer_category_writer.log').read_text(),spec.class_builder)
    setter=fun((root/f'{m}_stage76_finalizer_category_writer.log').read_text(),spec.setter)
    pk=fun((root/f'{m}_stage73_driver_command_pack.log').read_text(),spec.packet_builder)
    fi=fun((root/f'{m}_stage75_finalizer_source_fields.log').read_text(),spec.finalizer)
    stack=('local_58 = 0x101;', 'local_54 = 0;', 'local_53 = 2;',
          f'FUN_{spec.class_builder:08x}(0xfff7b000,&local_58);',
          f'FUN_{spec.packet_builder:08x}(0xfff7b000,&local_7c,&local_6c,')
    locs=[dr.find(x) for x in stack]
    need(min(locs)>=0 and locs==sorted(locs),
         'driver local_53 initialization or class builder before packet builder changed')
    need('param_2 != (undefined1 *)0x0' in builder and
         'param_1 != 0' in builder and
         f'FUN_{spec.setter:08x}(param_1,param_2[5]);' in builder and
         'return 0xffffffff;' in builder,
         'sixth-byte to class setter with null guard not confirmed')
    need('*(uint *)(param_1 + 0x4b0) = *(uint *)(param_1 + 0x4b0) & 0xf0ffffff | (param_2 & 0xf) << 0x18;' in setter,
         'class setter no longer updates category nibble at +0x4b0')
    need(f'uVar1 = FUN_{spec.finalizer:08x}(param_1);' in pk and
         'switch((*(uint *)(param_1 + 0x4b0) & 0xfffffff) >> 0x18)' in fi and
         'case 2:' in fi and 'default:' in fi and
         'return 0xffffffff;' in fi,
         'finalizer no longer selects category2 from same context nibble')
    trace=(root/f'{m}_stage76_class2_A32_evidence.log').read_text()
    for addr,s in ((spec.mov2,'mov r3,#0x2'),
                   (spec.store2,'strb r3,[r11,#-0x4f]'),
                   (spec.argpointer,'sub r1,r11,#0x54'),
                   (spec.class_builder_BL,f'bl 0x{spec.class_builder:08x}')):
        need(f'TRACE_INSN {addr:08x} {s}' in trace,
             'original Ghidra ARM stack class2 argument not confirmed '+hex(addr))
    refs=(root/f'{m}_stage76_class2_builder_xrefs.log').read_text()
    for site,target in ((spec.class_builder_BL,spec.class_builder),
                        (spec.setter_BL,spec.setter),
                        (spec.finalize_BL,spec.finalizer)):
        need(f'PROBE_REF from={site:08x} to={target:08x} type=UNCONDITIONAL_CALL' in refs,
             'original Ghidra xref class builder/setter/finalizer mismatch')
    return {'original_stack_byte5_value_2_used_as_category_nibble':True,
            'driver_setup_initializes_profile_class2_before_command_finalizer':True,
            'class2_is_a_supported_finalizer_case':True,
            'raw_stack_and_original_Ghidra_xrefs_verification':True,
            'no_intervening_or_concurrent_context_writers_proven':False,
            'actual_hardware_interface_2160p60_or_HEVC_Main10_output_proven':False}


def analyze(root):
    s75.analyze(root)
    result=[]
    for model,spec in SPECS.items():
        rom=(root/f'x6-{model}/section-1.bin').read_bytes()
        r={'model':model,**original_arm(spec,rom),**original_decompile(spec,root)}
        v,cat=class_from_six_bytes(bytes([1,1,0,0,0,2]),0xffffffff)
        need(cat==2 and (v&CLASS_MASK)==0x02000000,
             'synthetic six byte profile class2 not produced')
        result.append(r)
    need(all(r['class2_is_a_supported_finalizer_case'] for r in result),
         'both models must classify class2 as supported')
    return {'models':result,
        'original_SHA_pinned_Phase75_and_earlier_audits_pass':True,
        'specific_driver_branch_explicitly_chooses_valid_category2':True,
        'no_runtime_persistence_hardware_output_or_Movie_VPU_link_proven':True,
        'camera_USB_FF80_RAM_flash_ROM_DAT_writes':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE76 ORIGINAL DRIVER STACK BYTE 2 -> +4B0 CLASS2 -> FINALIZER PASS')
    print('UNKNOWN: concurrent class overwrite, interface hardware 4K60, Movie/VPU Main10.')
if __name__=='__main__':main()

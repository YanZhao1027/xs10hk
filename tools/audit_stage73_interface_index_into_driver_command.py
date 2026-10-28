#!/usr/bin/env python3
"""Phase73 offline original ROM: interface record index -> packed driver command.

Read-only Fujifilm X-S10 FW3.11 / X-T4 FW2.12 ROM and private Ghidra
from output/. Never infer physical 2160p60, HEVC Main10 or hardware acceptance.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage72_state5_driver_setup_gate as s72
import audit_stage70_interface_reverse_resolver_response as s70
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_mode_profile_registry_stage29 as s29
import audit_recorder_codec_forward_stage32 as s32

@dataclass(frozen=True)
class Spec:
    model:str
    response:int
    index_ptr_literal:int
    index_byte:int
    reverse:int
    reverse_store:int
    driver:int
    driver_index_load:int
    driver_record_load:int
    record_base:int
    record_field8:int
    second_gate:int
    first_read_count:str
    packet_tag:str
    gate_packet_name:str
    gate_packet_sig12:str
    gate_packet_sig0:str
    driver_call:int
    command_builder:int
    builder_marshaller_BL:int
    marshaller:int
    builder_finalize_BL:int
    finalize:int
    mirror:str
    ready_set_site:int
    ready_reset_site:int

SPECS={
 'xs10':Spec('xs10',0x0126b7e0,0x0126bdb8,0x01c84f89,0x01269520,
   0x0126b8ac,0x0126c388,0x0126c888,0x0126c890,
   0x0162de08,0x0162de10,0x01c84fb4,
   '_DAT_01c8567c','_DAT_01c855fc','0x1c855fd',
   '(&DAT_01c855fe)[uVar15]','(&DAT_01c855ff)[uVar15]',
   0x0126c944,0x0126d1fc,0x0126d240,0x0126f050,
   0x0126d298,0x0126e804,'_DAT_01823e60',
   0x0126ba7c,0x0126b920),
 'xt4':Spec('xt4',0x012419f8,0x01241fd0,0x01be5055,0x0123f738,
   0x01241ac4,0x012425a0,0x01242aa0,0x01242aa8,
   0x01605d2c,0x01605d34,0x01be5080,
   '_DAT_01be5748','_DAT_01be56c8','0x1be56c9',
   '(&DAT_01be56ca)[uVar15]','(&DAT_01be56cb)[uVar15]',
   0x01242b5c,0x01243414,0x01243458,0x01245268,
   0x012434b0,0x01244a1c,'_DAT_01793074',
   0x01241c94,0x01241b38),
}

def require(ok,reason):
    if not ok:raise ValueError('STAGE73 interface-to-packed-driver-command: '+reason)


def command_mode_from_byte(field8):
    """ONLY one verified command field, not resolution, frame timing or SPS."""
    return 2 if field8==0 else 0

def word_20_21_from_byte(field8):
    return (command_mode_from_byte(field8)&3)<<20

def readiness_after_response(prior,first_read,tag,tlv_kind,name,sig12,sig0,length):
    """A narrow synthetic abstraction of the original ready-flag writes.

    The assignment to 1 happens BEFORE the `7 < uVar14` subcondition;
    length controls later extended parsing, not the flag assignment.
    """
    if first_read:return 0,False
    match=tag==0x302 and tlv_kind==3 and name==3 and sig12==12 and sig0==0
    return (1 if match else prior),bool(match and length>7)


def original_bytes(spec,rom):
    W=lambda a:s32.rom_word(rom,s59.BASE,a)
    require(W(spec.index_ptr_literal)==spec.index_byte+1,
            'original response destination pointer no longer targets selected-index+1')
    prev=s70.SPECS[spec.model]
    require(spec.record_base==prev.record_start and
            spec.record_field8==prev.record_start+8,
            'driver ROM interface field not same Phase70 36-row descriptor')
    rows=s70.decode_rows(rom[spec.record_base-s59.BASE:prev.record_end-s59.BASE])
    bits=[rom[spec.record_field8-s59.BASE+16*i] for i in range(len(rows))]
    require(bits==([0]*24+[1]*12),
            'original 36 hardware interface row+8 values differ from two blocks')
    require(tuple((rows[i]['id'],rows[i]['numeric_rate'],bits[i]) for i in
             (0,3,5,11,22,23,34,35))==
            ((3,60,0),(4,60,0),(5,60,0),(16,60,0),
             (97,60,0),(97,60,0),(102,60,1),(102,60,1)),
            '60-valued interface-mode rows do not show distinct packed bit choice')
    for src,dest in ((spec.driver_call,spec.command_builder),
                     (spec.builder_marshaller_BL,spec.marshaller),
                     (spec.builder_finalize_BL,spec.finalize)):
        require(s29.bl_target(W(src),src)==dest,
                'original ROM BL edge not same command packer/finalizer '+hex(src))
    return {'interface_descriptors':36,'selected_index_RAM_byte':hex(spec.index_byte),
      'literal_pointer_to_response_data':hex(W(spec.index_ptr_literal)),
      'row8_first24_zero_last12_one':True,'numeric60_rows':8,
      'id97_indices':[22,23], 'id102_indices':[34,35],
      'id97_row8':[0,0],'id102_row8':[1,1],
      'id97_generated_driver_field_value':2,'id102_generated_driver_field_value':0,
      'id97_command_word_bits20_to21':hex(word_20_21_from_byte(0)),
      'id102_command_word_bits20_to21':hex(word_20_21_from_byte(1)),
      'direct_A32_BL_sites_verified':3}


def fun(log,addr):return s59.function_c_any(log,addr)

def text_audit(spec,src,drv,builder,marshall,final,xrefs):
    label=f'DAT_{spec.index_ptr_literal:08x}'
    require(f'iVar6 = {label};' in src and
            f'iVar7 = FUN_{spec.reverse:08x}(' in src and
            '*(char *)(iVar6 + -1) = (char)iVar7;' in src,
            'response reverse index not stored to literal pointer minus1')
    require(src.index(f'iVar7 = FUN_{spec.reverse:08x}(')<
            src.index('*(char *)(iVar6 + -1) = (char)iVar7;'),
            'reverse ID output store before lookup')
    flag=f'DAT_{spec.second_gate:08x}'
    require(f'if ({spec.first_read_count} == 0)' in src and
            f'{flag} = 0;' in src and
            f'if ({spec.packet_tag} == 0x302)' in src and
            'else if (bVar3 == 3)' in src and
            f'*(char *)(uVar15 + {spec.gate_packet_name}) == \'\\x03\'' in src and
            f"{spec.gate_packet_sig12} == '\\f'" in src and
            f"{spec.gate_packet_sig0} == '\\0'" in src and
            f'({flag} = 1, 7 < uVar14)' in src,
            '0x302 type3 acknowledgement readiness flag provenance differs')
    require(f"if ({flag} == '\\x01')" in drv and
            f'(&DAT_{spec.record_field8:08x})[(uint)DAT_{spec.index_byte:08x} * 0x10]' in drv and
            'local_68 = 2;' in drv and 'local_68 = 0;' in drv,
            'driver no longer reuses same selected index / ROM field8')
    require(drv.index('local_68 = 2;')<
            drv.index(f'FUN_{spec.command_builder:08x}(0xfff7b000,&local_7c,&local_6c,'),
            'interface bit choice no longer precedes command creation')
    require(f'FUN_{spec.command_builder:08x}(0xfff7b000,&local_7c,&local_6c,' in drv,
            'selected-index configuration no longer passed as third command object')
    require('if (param_3 != 0)' in builder and
            f'FUN_{spec.marshaller:08x}(param_1,param_3);' in builder and
            f'uVar1 = FUN_{spec.finalize:08x}(param_1);' in builder,
            'command builder no longer dispatches param3 to marshaller then finalize')
    require('(param_2[4] & 3) << 0x14' in marshall and
            f'{spec.mirror} = uVar2;' in marshall and
            '*(uint *)(param_1 + 0x624) = uVar2;' in marshall,
            'marshalling local_68 into command context bits20..21 not confirmed')
    require('if (iVar1 == 0xf)' in final and
            'return 0xffffffff;' in final and
            '*(uint *)(param_1 + 0x828)' in final,
            'finalizer no longer has 15-slot bounds or error return')
    for target,from_addr,rtype in (
       (spec.index_byte,spec.reverse_store,'WRITE'),
       (spec.index_byte,spec.driver_index_load,'READ'),
       (spec.record_field8,spec.driver_record_load,'DATA'),
       (spec.second_gate,spec.ready_set_site,'WRITE'),
       (spec.second_gate,spec.ready_reset_site,'WRITE'),
       (spec.command_builder,spec.driver_call,'UNCONDITIONAL_CALL'),
       (spec.marshaller,spec.builder_marshaller_BL,'UNCONDITIONAL_CALL')):
        require(f'PROBE_REF from={from_addr:08x} to={target:08x} type={rtype}' in xrefs,
                'direct Ghidra original cross-reference absent '+hex(from_addr))
    return {'response_selected_index_original_Ghidra_WRITE':hex(spec.reverse_store),
      'driver_reads_same_index_original_Ghidra_READ':hex(spec.driver_index_load),
      'driver_reads_original_ROM_plus8_original_Ghidra_DATA':hex(spec.driver_record_load),
      '0x302_type3_specific_signature_sets_readiness_flag':True,
      'readiness_flag_reset_on_initial_read':True,
      'other_index_or_readiness_writers_exist_and_can_override':True,
      'driver_config_byte_local_68_as_param3_offset4_to_word20_21':True,
      'command_marshalling_context_offset':'+0x624',
      'finalizer_may_fail_15_slot_range_test':True,
      'finalizer_successful_hardware_4K60_capture_proven':False,
      'actual_camera_runtime_index_and_0x302_response_observed':False,
      'any_ROM_or_camera_writes_performed':False}



@dataclass(frozen=True)
class Poll:
    func:int
    driver_call:int
    helper:int
    helper_call:int
    check:int
    check_call:int
    delay:int

POLL={
  'xs10':Poll(0x0126b018,0x0126c96c,0x0126da5c,0x0126b044,
              0x0126da2c,0x0126da80,0x012874c4),
  'xt4':Poll(0x01241230,0x01242b84,0x01243c74,0x0124125c,
             0x01243c44,0x01243c98,0x0125ce70),
}

def synthetic_poll_status(statuses):
    """Simulated consecutive results, never a hardware poll."""
    for status in list(statuses)[:42]:
        if status==0:return 0
    return -0x32

def audit_poll(spec,rom,driver,poll,helper,check,refs):
    W=lambda a:s32.rom_word(rom,s59.BASE,a)
    for site,dest in ((spec.driver_call,spec.func),
                      (spec.helper_call,spec.helper),
                      (spec.check_call,spec.check)):
        require(s29.bl_target(W(site),site)==dest,
                'post-build hardware readiness original A32 BL target differs '+hex(site))
        require(f'PROBE_REF from={site:08x} to={dest:08x} type=UNCONDITIONAL_CALL' in refs,
                'readiness test original code xref absent '+hex(site))
    require(f'iVar1 = FUN_{spec.func:08x}();' in driver and
            'if (iVar1 == 0)' in driver and
            driver.index(f'iVar1 = FUN_{spec.func:08x}();') >
            driver.index('0xfff7b000,&local_7c,&local_6c,'),
            'bounded readiness poll not after command build')
    require('iVar2 = 0x2a;' in poll and
            f'iVar1 = FUN_{spec.helper:08x}(0xfff7b000);' in poll and
            f'FUN_{spec.delay:08x}(5);' in poll and
            'if (iVar1 == 0)' in poll and
            'return 0xffffffce;' in poll,
            '42-iteration status polling, pacing or timeout result changed')
    require('return 0xffffffff;' in helper and
            'uVar1 = 0xff00;' in helper and 'uVar1 = 0x9500;' in helper and
            f'uVar1 = FUN_{spec.check:08x}(param_1,uVar1);' in helper,
            '0x9500/0xff00 status selection altered')
    require('return -(uint)(iVar1 == -1);' in check and
            'if (param_1 == 0)' in check,
            'lower-level ready check does not return 0/-1 by status')
    return {'poll_checks_after_command_context_construction':True,
      'synthetic_max_poll_iterations':42,
      'poll_delay_argument':5,
      'poll_exhausted_return':'-0x32',
      'two_internal_status_command_constants':['0x9500','0xFF00'],
      'post_build_ARM_BL_verified':3,
      'successful_REAL_hardware_readout_or_2160p60_ever_observed':False}

def analyze(root):
    s72.analyze(root)
    result=[]
    for m,s in SPECS.items():
        rom=(root/f'x6-{m}/section-1.bin').read_bytes()
        response=fun((root/f'{m}_stage70_sensor_resolver_pipeline.log').read_text(),s.response)
        driver=fun((root/f'{m}_stage72_only_driver_state5.log').read_text(),s.driver)
        builder=fun((root/f'{m}_stage73_driver_command_pack.log').read_text(),s.command_builder)
        marshall=fun((root/f'{m}_stage73_driver_command_marshalling.log').read_text(),s.marshaller)
        final=fun((root/f'{m}_stage73_driver_command_marshalling.log').read_text(),s.finalize)
        refs=(root/f'{m}_stage73_selected_idx_ready_xrefs.log').read_text()
        ps=POLL[m]
        poll=fun((root/f'{m}_stage73_driver_status_checks.log').read_text(),ps.func)
        helper=fun((root/f'{m}_stage73_driver_ready_condition.log').read_text(),ps.helper)
        check=fun((root/f'{m}_stage73_driver_status_checks.log').read_text(),ps.check)
        poll_refs=(root/f'{m}_stage73_ready_poll_xrefs.log').read_text()
        result.append({'model':m,**original_bytes(s,rom),
                       **text_audit(s,response,driver,builder,marshall,final,refs),
                       **audit_poll(ps,rom,driver,poll,helper,check,poll_refs)})
    require(all(r['driver_config_byte_local_68_as_param3_offset4_to_word20_21'] for r in result),
            'both original models must reach same interface command bitfield')
    return {'models':result,'SHA_pinned_original_Phase72_and_all_prior_audits_pass':True,
      'conditional_static_reverse_ID_to_driver_command_field20_21_complete':True,
      'no_proof_interface_record_maps_to_Movie_2160p60_or_HEVC_Main10':True,
      'no_camera_USB_FF80_RAM_flash_ROM_DAT_write':True}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(a.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE73 ORIGINAL INTERFACE ID INDEX -> DRIVER BIT20-21 COMMAND FIELD PASS')
    print('UNKNOWN: real sensor data rate, ISP acceptance, Movie/VPU 4K60/Main10.')
if __name__=='__main__':main()

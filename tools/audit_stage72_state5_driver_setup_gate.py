#!/usr/bin/env python3
"""Phase72: independent conditional hardware/HD driver setup shares Phase71 state5.

Read-only original X-S10 3.11/X-T4 2.12 ARM+Ghidra cross-checks.
No proof callback starts setup task, sensor 2160p60, VPU/HEVC Main10,
or any live camera/USB/FF80/ROM patch operation.
"""
import argparse,json,sys
from pathlib import Path
from dataclasses import dataclass
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage71_queue61_event_task_state_dispatch as st71
import audit_stage59_movie_menu_ROM_allowlist as st59
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_codec_forward_stage32 as st32

@dataclass(frozen=True)
class Spec:
    model:str
    setup:int
    prelim_func:int
    prelim_BL:int
    wrapper:int
    wrapper_BL:int
    driver:int
    driver_BL:int
    state_var:str
    status_flag:str
    sys_queue:int
    generic_module:int
    acquire_func:int
    release_func:int
    acquire_state_func:int
    hardware_start_func:int
    external_gate_func:str
    caller_xref_site:int
    caller_setup_guard:str

SPECS={
 'xs10':Spec('xs10',0x01241908,0x012418c0,0x01241988,
   0x012690c4,0x01241994,0x0126c388,0x012690cc,
   'DAT_01c84f88','DAT_01c84fb4',0x61,0x35,
   0x012a5c50,0x012a5ca0,0x012a5344,0x0126d01c,
   'FUN_012418c0(1)',0x01241994,'FUN_0125d3b8(param_2), param_2 == 0'),
 'xt4':Spec('xt4',0x0121823c,0x012181f4,0x012182bc,
   0x0123f2dc,0x012182c8,0x012425a0,0x0123f2e4,
   'DAT_01be5054','DAT_01be5080',0x61,0x37,
   0x0127e350,0x0127e3a0,0x0127daac,0x01243234,
   'FUN_012181f4(1)',0x012182c8,'FUN_01233cd0(param_2), param_2 == 0')
}


def need(ok,msg):
    if not ok:raise ValueError('STAGE72 gated interface driver startup: '+msg)

def gated(setup_subroutine_succeeded,param2,prelim_success,state,driver_active):
    """Artificial model of *necessary* gates, never actual hardware output."""
    return bool(setup_subroutine_succeeded and param2==0 and
                prelim_success and state==5 and driver_active==1)

def original_arm(spec,word):
    anchors=((spec.prelim_BL,spec.prelim_func),
             (spec.wrapper_BL,spec.wrapper),
             (spec.driver_BL,spec.driver))
    for src,dest in anchors:
        need(st29.bl_target(word(src),src)==dest,
             'original A32 call target changed '+hex(src))
    need(spec.setup<=spec.prelim_BL<spec.wrapper_BL<spec.setup+148 and
         spec.wrapper<=spec.driver_BL<spec.wrapper+16,
         'setup/driver wrapper calls outside original function boundaries')
    return {'original_A32_bl_edges_verified':len(anchors),
        'driver_setup_wrapper_has_independent_caller':True,
        'driver_setup_invoked_by_Phase71_state5_callback_directly':False}

def decompiled(spec,setup,wrapper,driver,refs):
    need('int '+('FUN_%08x'%spec.setup) in setup or
         ('FUN_%08x'%spec.setup) in setup,'wrong caller function')
    need('param_2 == 0' in setup and spec.caller_setup_guard in setup and
         spec.external_gate_func in setup and
         ('iVar2 = '+spec.external_gate_func) in setup and
         f'FUN_{spec.wrapper:08x}();' in setup,
         'independent caller lacks setup/param2==0/initialization success gates')
    need(setup.find(spec.external_gate_func)<setup.find(f'FUN_{spec.wrapper:08x}();'),
         'driver entry appears before setup success gate')
    need(f'FUN_{spec.driver:08x}();' in wrapper,
         'original tiny wrapper no longer calls shared-state driver')
    need(f"if ({spec.state_var} == '\\x05')" in driver and
         f"if ({spec.status_flag} == '\\x01')" in driver,
         'hardware-side mode state5 and secondary readiness gates differ')
    for x in (f'FUN_{spec.acquire_func:08x}(0x{spec.generic_module:x},0xffffffff);',
              f'FUN_{spec.release_func:08x}(0x{spec.generic_module:x});',
              f'FUN_{spec.acquire_state_func:08x}(0x{spec.sys_queue:x});',
              f'FUN_{spec.acquire_state_func:08x}(0x{spec.sys_queue:x},7);',
              f'FUN_{spec.hardware_start_func:08x}(0xfff7b000,1);'):
        need(x in driver,'hardware setup module0x35/37 or interface call absent '+x)
    need('local_24[0] < 7' in driver and '0xfff7b000' in driver and
         '0x9000' in driver and '0x2000000' in driver and
         'return;' in driver,'driver setup retry/error/control branches changed')
    need(f'PROBE_TARGET addr={spec.driver:08x} refs=1' in refs and
         f'PROBE_REF from={spec.driver_BL:08x} to={spec.driver:08x} type=UNCONDITIONAL_CALL' in refs and
         f'PROBE_REF from={spec.wrapper_BL:08x} to={spec.wrapper:08x} type=UNCONDITIONAL_CALL' in refs,
         'driver/wrapper crossreferences differ in original project')
    return {'shared_Phase71_state5_read_in_separate_driver':True,
            'independent_setup_param2_zero_and_return0_gates':True,
            'driver_state5_plus_secondary_status1_branch':True,
            'separate_driver_coordination_module':hex(spec.generic_module),
            'also_uses_queue_0x61_control':True,
            'hardware_interfaces_called_with_0xFFF7B000':True,
            'callback_to_driver_runtime_timing_proven':False,
            'hardware_sensor_ISP_VPU_Main10_output_observed':False}

def func(log,addr):return st59.function_c_any(log,addr)

def analyze(root):
    st71.analyze(root)
    result=[]
    for model,spec in SPECS.items():
        one=(root/f'x6-{model}/section-1.bin').read_bytes()
        W=lambda addr:st32.rom_word(one,st59.BASE,addr)
        log=(root/f'{model}_stage72_driver_boot_callers.log').read_text()
        caller=func(log,spec.setup)
        wrap=func((root/f'{model}_stage72_driver_start_caller.log').read_text(),spec.wrapper)
        dr=func((root/f'{model}_stage72_only_driver_state5.log').read_text(),spec.driver)
        refs=(root/f'{model}_stage72_interface_driver_entry_refs.log').read_text()+\
            (root/f'{model}_stage72_driver_task_origin_refs.log').read_text()
        r={'model':model,**original_arm(spec,W),**decompiled(spec,caller,wrap,dr,refs),
           'camera_USB_FF80_ROM_PATCH_RAM_FLASH':False}
        result.append(r)
    return {'models':result,'prior_SHA_pinned_Phase71_and_all_ROM_audits_pass':True,
       'positive_shared_state5_gated_external_driver':True,
       'same_invocation_or_2160p60_HEVC_Main10_proven':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE72 ORIGINAL SEPARATE HD DRIVER SETUP SHARES PHASE71 STATE5 GATE PASS')
    print('UNKNOWN: live queue timing, real camera sensor/ISP/VPU success, 4K60/Main10 file.')
if __name__=='__main__':main()
"""Phase72 100% synthetic A32, control predicates and driver-call boundary tests.

Generated text and branch words only: NO proprietary firmware/Ghidra bytes,
real sensor, device messages, HEVC bitstream, camera USB or patching.
"""
import sys,itertools,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage72_state5_driver_setup_gate as s


def artificial_word(spec):
    def branch(a,t):
        assert (t-a-8)%4==0
        return 0xeb000000|(((t-a-8)//4)&0xffffff)
    return {spec.prelim_BL:branch(spec.prelim_BL,spec.prelim_func),
       spec.wrapper_BL:branch(spec.wrapper_BL,spec.wrapper),
       spec.driver_BL:branch(spec.driver_BL,spec.driver)}

def fake_fields(spec):
    setup=(f'int FUN_{spec.setup:08x}(int param_1,int param_2) {{\n'
      'if (iVar2 == 0){}\n'
      f'if (((iVar2 == 0) && ({spec.caller_setup_guard})) && '\
      f'(iVar2 = {spec.external_gate_func}, iVar2 == 0)) {{\n'
      f'FUN_{spec.wrapper:08x}();\n}}\n}}')
    wrapper=f'void FUN_{spec.wrapper:08x}() {{FUN_{spec.driver:08x}(); return;}}'
    driver=(f"if ({spec.state_var} == '\\x05') {{\n"
       f"if ({spec.status_flag} == '\\x01') {{\n"
       f'FUN_{spec.hardware_start_func:08x}(0xfff7b000,1);}}}}\n'
       f'if (local_24[0] < 7) {{\n'
       f'FUN_{spec.acquire_state_func:08x}(0x{spec.sys_queue:x});\n'
       f'FUN_{spec.acquire_func:08x}(0x{spec.generic_module:x},0xffffffff);\n'
       f'FUN_{spec.acquire_state_func:08x}(0x{spec.sys_queue:x},7);\n}}'
       'int x=0x9000; int y=0x2000000; int z=0xfff7b000;\n'
       f'FUN_{spec.release_func:08x}(0x{spec.generic_module:x});\nreturn;')
    refs=(f'PROBE_TARGET addr={spec.driver:08x} refs=1\n'
          f'PROBE_REF from={spec.driver_BL:08x} to={spec.driver:08x} type=UNCONDITIONAL_CALL\n'
          f'PROBE_REF from={spec.wrapper_BL:08x} to={spec.wrapper:08x} type=UNCONDITIONAL_CALL')
    return [setup,wrapper,driver,refs]

class Good(unittest.TestCase):
    def test_both_models_original_A32_schema(self):
        for m,sp in s.SPECS.items():
            with self.subTest(model=m):
                r=s.original_arm(sp,artificial_word(sp).__getitem__)
                self.assertEqual(r['original_A32_bl_edges_verified'],3)
    def test_both_models_independent_driver_gate(self):
        for m,sp in s.SPECS.items():
            with self.subTest(model=m):
                r=s.decompiled(sp,*fake_fields(sp))
                self.assertTrue(r['shared_Phase71_state5_read_in_separate_driver'])
                self.assertFalse(r['callback_to_driver_runtime_timing_proven'])
                self.assertFalse(r['hardware_sensor_ISP_VPU_Main10_output_observed'])
    def test_queue61_and_separate_control_module_distinct(self):
        for sp in s.SPECS.values():
            self.assertEqual(sp.sys_queue,0x61)
            self.assertIn(sp.generic_module,(0x35,0x37))
            self.assertNotEqual(sp.generic_module,sp.sys_queue)
    def test_gate_all_80_artificial_state_combinations(self):
        for setup_ok,param2,prelim,state,drv in itertools.product(
                (False,True),(0,1),(False,True),(4,5,6,7,8),(0,1)):
            expected=setup_ok and param2==0 and prelim and state==5 and drv==1
            self.assertEqual(s.gated(setup_ok,param2,prelim,state,drv),expected)
    def test_only_both_setup_and_state5_and_driverflag1_enter(self):
        self.assertTrue(s.gated(True,0,True,5,1))
        for args in ((False,0,True,5,1),(True,1,True,5,1),
                     (True,0,False,5,1),(True,0,True,4,1),
                     (True,0,True,5,0),(True,0,True,6,1)):
            self.assertFalse(s.gated(*args))

class Bad(unittest.TestCase):pass
for m,sp in s.SPECS.items():
    for n,loc in enumerate((sp.prelim_BL,sp.wrapper_BL,sp.driver_BL)):
        for flip in (1,0x100):
            def mk(m,loc,flip):
                def test(self):
                    sp=s.SPECS[m];d=artificial_word(sp);d[loc]^=flip
                    with self.assertRaises(ValueError):s.original_arm(sp,d.__getitem__)
                return test
            setattr(Bad,f'test_wrong_A32_BL_{m}_{n}_{flip}',mk(m,loc,flip))
    terms=[(0,'param_2 == 0'),(0,sp.caller_setup_guard),
           (0,sp.external_gate_func),(0,f'FUN_{sp.wrapper:08x}();'),
           (1,f'FUN_{sp.driver:08x}();'),
           (2,sp.state_var),(2,sp.status_flag),
           (2,f'FUN_{sp.hardware_start_func:08x}(0xfff7b000,1);'),
           (2,f'FUN_{sp.acquire_func:08x}(0x{sp.generic_module:x},0xffffffff);'),
           (2,f'FUN_{sp.release_func:08x}(0x{sp.generic_module:x});'),
           (2,f'FUN_{sp.acquire_state_func:08x}(0x{sp.sys_queue:x});'),
           (2,f'FUN_{sp.acquire_state_func:08x}(0x{sp.sys_queue:x},7);'),
           (2,'0x2000000'),(2,'0x9000'),(2,'local_24[0] < 7'),
           (3,f'PROBE_TARGET addr={sp.driver:08x} refs=1'),
           (3,f'PROBE_REF from={sp.wrapper_BL:08x} to={sp.wrapper:08x} type=UNCONDITIONAL_CALL')]
    for n,(idx,tok) in enumerate(terms):
        def mk(m,idx,tok):
            def test(self):
                sp=s.SPECS[m];a=fake_fields(sp)
                self.assertIn(tok,a[idx]);a[idx]=a[idx].replace(tok,'CORRUPTED')
                with self.assertRaises(ValueError):s.decompiled(sp,*a)
            return test
        setattr(Bad,f'test_missing_guard_{m}_{n}',mk(m,idx,tok))
    for n,field in enumerate(('prelim_func','wrapper','driver','state_var','status_flag','generic_module')):
        def mk(m,field):
            def test(self):
                from dataclasses import replace
                sp=s.SPECS[m]
                if field=='generic_module':sp2=replace(sp,generic_module=0x34)
                elif field in ('state_var','status_flag'):sp2=replace(sp,**{field:'DAT_FAKE'})
                else:sp2=replace(sp,**{field:getattr(sp,field)+4})
                raw=artificial_word(sp)
                if field in ('prelim_func','wrapper','driver'):
                    with self.assertRaises(ValueError):s.original_arm(sp2,raw.__getitem__)
                else:
                    with self.assertRaises(ValueError):s.decompiled(sp2,*fake_fields(sp))
            return test
        setattr(Bad,f'test_other_original_data_alias_{m}_{n}',mk(m,field))

if __name__=='__main__':unittest.main()
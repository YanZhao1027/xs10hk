"""Synthetic-only Phase74 selected-interface bitfield + status updates.

All 32-bit A32 words, input values, fake decompilation and xrefs in these
unittests are generated here. No Fujifilm vendor files, hardware, USB/FF80,
real MMIO, firmware edits, camera memory or private Ghidra logs are read.
"""
import itertools,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage74_driver_command_multi_source_bitfield as s


def bl_word(site,target):
    d=target-site-8
    assert d%4==0
    return 0xeb000000|((d>>2)&0xffffff)


def ls_word(offset,read,base_reg):
    return 0xe5800000|((int(read)&1)<<20)|(base_reg<<16)|offset


def fake_section(spec):
    edges=[(spec.build_BL,spec.builder),(spec.after_build_status_BL,spec.status),
       (spec.status_rmw_BL,spec.rmw),(spec.alternative_status_BL,spec.status),
       (spec.alternative_wrapper_BL,spec.alternative)]
    sites=[site for site,_ in edges]+[
       spec.original_marshaller624_store,spec.original_rmw624_read,
       spec.original_rmw624_store,spec.original_finalizer828_read,
       spec.original_finalizer828_store]
    rom=bytearray(max(sites)-s.st59.BASE+4)
    for a,dest in edges:struct.pack_into('<I',rom,a-s.st59.BASE,bl_word(a,dest))
    for a,offset,rd,reg in [
       (spec.original_marshaller624_store,0x624,False,3),
       (spec.original_rmw624_read,0x624,True,0),
       (spec.original_rmw624_store,0x624,False,0),
       (spec.original_finalizer828_read,0x828,True,0),
       (spec.original_finalizer828_store,0x828,False,0)]:
        struct.pack_into('<I',rom,a-s.st59.BASE,ls_word(offset,rd,reg))
    return rom


def synthetic_decomp(spec):
    # Minimal artificial Ghidra-like statements anchored to meaning;
    # intentionally not extracts from the real vendor image.
    dr=(f'FUN_{spec.builder:08x}(0xfff7b000,&local_7c,&local_6c,&other);\n'
        f'FUN_{spec.status:08x}();\nother++;')
    status=(f'if (({spec.state_word} & 0xffff00) == 0x10100) {{\n'
       f'if ((byte)({spec.selected_type} - 1) < 2) {{uVar2 = 5;}}\n'
       'else {uVar2 = 6;}\nuVar1 = 3;\n}\n'
       f'else if ({spec.selected_type} < 2) {{\n'
       f"if ({spec.secondary_flag} == '\\0') {{uVar1 = 1;}}\n"
       'else {uVar1 = 2;}\n}\n'
       'else {uVar1 = 0xf;}\n'
       f'FUN_{spec.rmw:08x}(0xfff7b000,uVar1,uVar2);')
    rmw=('uVar2 = *(uint *)(param_1 + 0x624);\n'
       'if (param_2 == 0xf) {\n'
       '*(uint *)(param_1 + 0x614) = *(uint *)(param_1 + 0x614) | 0x80000;\n}\n'
       'uVar2 = uVar2 & 0xff3fffff | (param_2 & 3) << 0x16;\n'
       'if (param_3 == 0xf) {\n'
       '*(uint *)(param_1 + 0x614) = *(uint *)(param_1 + 0x614) | 0x200000;\n}\n'
       'uVar2 = uVar2 & 0x8fffffff | (param_3 & 7) << 0x1c;\n'
       '*(uint *)(param_1 + 0x624) = uVar2;\n'
       '*(uint *)(param_1 + 0x81c) = *(uint *)(param_1 + 0x81c) & 0xffffff;')
    alt=(f'{spec.state_word} = CONCAT12(param_1,{spec.state_word});\n'
         f"if ({spec.state_name} != '\\x05') {{return;}}\n"
         f'FUN_{spec.status:08x}();\n'
         'FUN_SAMPLE(0xfff7b000,0x4000,0);\n'
         'FUN_SAMPLE2(0xfff7b000,0x2000000);')
    wrap=f'FUN_{spec.alternative:08x}();'
    marshal=('uVar2 = (param_2[4] & 3) << 0x14;\n'
         '*(uint *)(param_1 + 0x620) = 3;\n'
         '*(uint *)(param_1 + 0x624) = uVar2;\n'
         '*(uint *)(param_1 + 0x628) = 1;\n'
         '*(uint *)(param_1 + 0x630) = 2;')
    final=('if (foo) {*(uint *)(param_1 + 0x828)=bar;\nreturn 0;}\n'
           'else return 0xffffffff;')
    return {spec.driver:dr,spec.status:status,spec.rmw:rmw,
         spec.alternative:alt,spec.alternative_wrapper:wrap,
         spec.marshaller:marshal,spec.finalizer:final}


def fake_root(spec,root):
    model=spec.model
    for f in (f'{model}_stage72_only_driver_state5.log',
              f'{model}_stage74_RMW_caller_trace.log',
              f'{model}_stage74_alt_status_caller.log',
              f'{model}_stage74_state5_dynamic_trigger.log',
              f'{model}_stage73_driver_command_marshalling.log'):
        (root/f).write_text('GENERATED TEST PLACEHOLDER - NO ORIGINAL GHIDRA')
    refs=[]
    for addr,dest in ((spec.after_build_status_BL,spec.status),
                      (spec.status_rmw_BL,spec.rmw),
                      (spec.alternative_status_BL,spec.status)):
        refs.append(f'PROBE_REF from={addr:08x} to={dest:08x} type=UNCONDITIONAL_CALL')
    (root/f'{model}_stage74_status_word_provenance_refs.log').write_text('\n'.join(refs))
    tags=[('624/READ',spec.original_rmw624_read),
          ('624/WRITE',spec.original_rmw624_store),
          ('624/WRITE',spec.original_marshaller624_store),
          ('828/READ',spec.original_finalizer828_read),
          ('828/WRITE',spec.original_finalizer828_store)]
    (root/f'{model}_stage74_cmd_field_offset_scan.log').write_text('\n'.join(
        f'ST74_SITE {tag} {addr:08x} TEST_INSTRUCTION' for tag,addr in tags))


def check_fake(spec,mutation=None):
    texts=synthetic_decomp(spec)
    if mutation:
        fn,token=mutation
        assert token in texts[fn],(hex(fn),token)
        texts[fn]=texts[fn].replace(token,'INVALID')
    with tempfile.TemporaryDirectory() as path:
        root=Path(path);fake_root(spec,root)
        with patch.object(s,'fun',side_effect=lambda _,addr:texts[addr]):
            return s.original_decompile(spec,root)


class Positive(unittest.TestCase):
    def test_original_call_and_field_offset_A32_both_models(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                out=s.original_code(sp,fake_section(sp))
                self.assertEqual(out['original_A32_direct_BL_count'],5)
                self.assertEqual(out['original_A32_direct_field_load_store_count'],5)
                self.assertEqual(out['calculated_A32_command_word_address'],'0xfff7b624')
                self.assertFalse(out['absolute_region_proven_to_be_MMIO_hardware_register'])
    def test_generated_Ghidra_crosslinks_both_models(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                r=check_fake(sp)
                self.assertTrue(r['two_source_stores_target_same_plus624_word_in_original_code'])
                self.assertFalse(r['actual_state5_delivery_and_hardware_acceptance_seen'])
    def test_all_status_parameter_branches(self):
        for special,kind,flag in itertools.product((0,0x10100),range(8),(0,1)):
            p2,p3=s.status_params(special,kind,flag)
            if special:
                self.assertEqual((p2,p3),(3,5 if kind in (1,2) else 6))
            elif kind<2:self.assertEqual((p2,p3),(1 if flag==0 else 2,15))
            else:self.assertEqual((p2,p3),(15,15))
    def test_rmw_does_not_touch_unrelated_bits(self):
        for field22,field28 in itertools.product((0,1,2,3,15),(0,1,2,3,5,6,7,15)):
            for x,y in ((0,0),(0xffffffff,0xffffffff),(0x89abcdef,0x98765432)):
                a,b=s.update_fields(x,y,field22,field28)
                self.assertEqual((x^a)&~s.STATUS_MASK,0)
                self.assertEqual((y^b)&~(s.ENABLE19|s.ENABLE21),0)
    def test_selected_interface_ID_bit20_21_preservation(self):
        for byte in (0,1):
            for special,kind,flag in itertools.product((0,0x10100),range(12),(0,1)):
                r=s.simulate_command(byte,special,kind,flag,0x89abcdef,0xffffffff)
                self.assertEqual(r['mode20_21'],s.st73.word_20_21_from_byte(byte))
    def test_id97_vs_id102_same_status_different_mode_bits(self):
        for state,kind,flag in ((0x10100,1,0),(0x10100,3,1),(0,1,0),(0,3,1)):
            x=s.simulate_command(0,state,kind,flag)
            y=s.simulate_command(1,state,kind,flag)
            self.assertEqual(x['status22'],y['status22'])
            self.assertEqual(x['status28'],y['status28'])
            self.assertEqual(y['word624']^x['word624'],0x200000)
    def test_two_unmodified_sentinel_fields_preserved(self):
        for init in (0,0xffffffff,0x5aefffff,0x70000000):
            word,enable=s.update_fields(init,0,15,15)
            self.assertEqual(word,init&0xffffffff)
            self.assertEqual(enable&s.ENABLE19,s.ENABLE19)
            self.assertEqual(enable&s.ENABLE21,s.ENABLE21)
    def test_non_sentinel_only_updates_requested_fields(self):
        word,enable=s.update_fields(0xffffffff,0xffffffff,3,5)
        self.assertEqual(word&s.STATUS22_MASK,0xc00000)
        self.assertEqual(word&s.STATUS28_MASK,0x50000000)
        self.assertEqual(enable&(s.ENABLE19|s.ENABLE21),0)

class Negative(unittest.TestCase):pass

for model,sp in s.SPECS.items():
    original_links=[sp.build_BL,sp.after_build_status_BL,sp.status_rmw_BL,
                    sp.alternative_status_BL,sp.alternative_wrapper_BL]
    for j,site in enumerate(original_links):
        for mask in (1,0x100):
            def make(model,site,mask):
                def test(self):
                    x=s.SPECS[model];rom=fake_section(x)
                    loc=site-s.st59.BASE
                    before=struct.unpack_from('<I',rom,loc)[0]
                    struct.pack_into('<I',rom,loc,before^mask)
                    with self.assertRaises(ValueError):s.original_code(x,rom)
                return test
            setattr(Negative,f'test_A32_changed_BL_{model}_{j}_{mask}',make(model,site,mask))
    original_offsets=[sp.original_marshaller624_store,sp.original_rmw624_read,
                      sp.original_rmw624_store,sp.original_finalizer828_read,
                      sp.original_finalizer828_store]
    for j,site in enumerate(original_offsets):
        for mask in (1,0x100000,0x10000):
            def make(model,site,mask):
                def test(self):
                    x=s.SPECS[model];rom=fake_section(x)
                    loc=site-s.st59.BASE
                    before=struct.unpack_from('<I',rom,loc)[0]
                    struct.pack_into('<I',rom,loc,before^mask)
                    with self.assertRaises(ValueError):s.original_code(x,rom)
                return test
            setattr(Negative,f'test_A32_offset_or_rw_bad_{model}_{j}_{mask}',make(model,site,mask))
    # Each check deliberately mutates only a generated fake decompiler token.
    essential=[
       (sp.driver,f'FUN_{sp.builder:08x}(0xfff7b000,&local_7c,&local_6c,'),
       (sp.driver,f'FUN_{sp.status:08x}();'),
       (sp.status,f'FUN_{sp.rmw:08x}(0xfff7b000,uVar1,uVar2);'),
       (sp.status,sp.state_word),(sp.status,sp.selected_type),
       (sp.status,sp.secondary_flag),(sp.status,'uVar2 = 5;'),
       (sp.status,'uVar2 = 6;'),(sp.status,'uVar1 = 0xf;'),
       (sp.rmw,'uVar2 = *(uint *)(param_1 + 0x624);'),
       (sp.rmw,'0xff3fffff'),(sp.rmw,'0x8fffffff'),
       (sp.rmw,'0x80000'),(sp.rmw,'0x200000'),
       (sp.rmw,'*(uint *)(param_1 + 0x624) = uVar2;'),
       (sp.marshaller,'(param_2[4] & 3) << 0x14'),
       (sp.marshaller,'*(uint *)(param_1 + 0x624) = uVar2;'),
       (sp.marshaller,'*(uint *)(param_1 + 0x630)'),
       (sp.finalizer,'*(uint *)(param_1 + 0x828)'),
       (sp.finalizer,'return 0xffffffff;'),
       (sp.alternative,'CONCAT12(param_1,'),
       (sp.alternative,f'FUN_{sp.status:08x}();'),
       (sp.alternative,'0x2000000'),
       (sp.alternative_wrapper,f'FUN_{sp.alternative:08x}();'),
    ]
    for j,mutation in enumerate(essential):
        def make(model,mutation):
            def test(self):
                with self.assertRaises(ValueError):check_fake(s.SPECS[model],mutation)
            return test
        setattr(Negative,f'test_fake_Ghidra_field_bad_{model}_{j}',make(model,mutation))

# Additional independent, fully synthetic field-mask contract tests.
for byte,special,kind,flag in itertools.product((0,1),(0,0x10100),range(4),(0,1)):
    def make(byte,special,kind,flag):
        def test(self):
            r=s.simulate_command(byte,special,kind,flag,0x2a850000,0x7faacc11)
            expected=s.st73.word_20_21_from_byte(byte)
            self.assertEqual(r['mode20_21'],expected)
            p2,p3=s.status_params(special,kind,flag)
            self.assertEqual((r['status22'],r['status28']),(p2,p3))
            if p2!=15:self.assertEqual(r['word624']&s.STATUS22_MASK,(p2&3)<<22)
            if p3!=15:self.assertEqual(r['word624']&s.STATUS28_MASK,(p3&7)<<28)
        return test
    setattr(Negative,f'test_generated_condition_{byte}_{special}_{kind}_{flag}',make(byte,special,kind,flag))

if __name__=='__main__':unittest.main()

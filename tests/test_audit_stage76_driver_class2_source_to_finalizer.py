"""All data here is original synthetic test input: not Fujifilm ROM, private logs,
actual hardware, camera commands, USB/FF80, memory writes, patches or flashes.
"""
import struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage76_driver_class2_source_to_finalizer as s


def gen_arm_bl(a,target):
    assert (target-a-8)%4==0
    return 0xeb000000|(((target-a-8)//4)&0xffffff)


def fake_rom(sp):
    sites=[sp.mov2,sp.store2,sp.argpointer,sp.driverbase,
       sp.class_builder_BL,sp.setter_BL,sp.setter_load,sp.setter_store,
       sp.packet_builder_BL,sp.finalize_BL]
    rom=bytearray(max(sites)-s.s59.BASE+4)
    values={
       sp.mov2:0xe3a03002,
       sp.store2:0xe54b304f,
       sp.argpointer:0xe24b1054,
       sp.driverbase:0xe1a00005,
       sp.setter_load:0xe59034b0,
       sp.setter_store:0xe58034b0,
       sp.class_builder_BL:gen_arm_bl(sp.class_builder_BL,sp.class_builder),
       sp.setter_BL:gen_arm_bl(sp.setter_BL,sp.setter),
       sp.packet_builder_BL:gen_arm_bl(sp.packet_builder_BL,sp.packet_builder),
       sp.finalize_BL:gen_arm_bl(sp.finalize_BL,sp.finalizer),
    }
    for loc,w in values.items():struct.pack_into('<I',rom,loc-s.s59.BASE,w)
    return rom


def fake_decompiled(sp):
    driver=('void FAKE() {\nlocal_58 = 0x101;\nlocal_54 = 0;\nlocal_53 = 2;\n'
       f'FUN_{sp.class_builder:08x}(0xfff7b000,&local_58);\n'
       'FAKE_INTERMEDIATE;\n'
       f'FUN_{sp.packet_builder:08x}(0xfff7b000,&local_7c,&local_6c,&local_74);\n}}')
    builder=('if (param_2 != (undefined1 *)0x0 && param_1 != 0) {\n'
       f'FUN_{sp.setter:08x}(param_1,param_2[5]);\nreturn 0;\n}}\n'
       'return 0xffffffff;')
    setter=('*(uint *)(param_1 + 0x4b0) = *(uint *)(param_1 + 0x4b0) & '
            '0xf0ffffff | (param_2 & 0xf) << 0x18;')
    packet=f'uVar1 = FUN_{sp.finalizer:08x}(param_1);'
    final=('switch((*(uint *)(param_1 + 0x4b0) & 0xfffffff) >> 0x18) {\n'
       'case 2: break;\ncase 3: break;\ndefault: return 0xffffffff;\n}')
    return {sp.driver:driver,sp.class_builder:builder,sp.setter:setter,
            sp.packet_builder:packet,sp.finalizer:final}


def setup_fake_root(sp,root):
    m=sp.model
    for f in (f'{m}_stage72_only_driver_state5.log',
              f'{m}_stage76_finalizer_category_writer.log',
              f'{m}_stage73_driver_command_pack.log',
              f'{m}_stage75_finalizer_source_fields.log'):
        (root/f).write_text('SELF-GENERATED PLACEHOLDER, NOT ORIGINAL GHIDRA')
    trace=[]
    for addr,asm in ((sp.mov2,'mov r3,#0x2'),
                     (sp.store2,'strb r3,[r11,#-0x4f]'),
                     (sp.argpointer,'sub r1,r11,#0x54'),
                     (sp.class_builder_BL,f'bl 0x{sp.class_builder:08x}')):
        trace.append(f'TRACE_INSN {addr:08x} {asm}')
    (root/f'{m}_stage76_class2_A32_evidence.log').write_text('\n'.join(trace))
    refs=[]
    for site,target in ((sp.class_builder_BL,sp.class_builder),
                        (sp.setter_BL,sp.setter),
                        (sp.finalize_BL,sp.finalizer)):
        refs.append(f'PROBE_REF from={site:08x} to={target:08x} type=UNCONDITIONAL_CALL')
    (root/f'{m}_stage76_class2_builder_xrefs.log').write_text('\n'.join(refs))


def check_fake(sp,mutation=None):
    entries=fake_decompiled(sp)
    if mutation:
        addr,needle=mutation
        assert needle in entries[addr],(hex(addr),needle)
        entries[addr]=entries[addr].replace(needle,'CORRUPTED_TOKEN')
    with tempfile.TemporaryDirectory() as path:
        root=Path(path)
        setup_fake_root(sp,root)
        with patch.object(s,'fun',side_effect=lambda _,addr:entries[addr]):
            return s.original_decompile(sp,root)

class Positive(unittest.TestCase):
    def test_each_model_generated_original_A32_evidence(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                r=s.original_arm(sp,fake_rom(sp))
                self.assertEqual(r['original_A32_direct_BL_edges'],4)
                self.assertEqual(r['original_exact_A32_stack_store_and_plus4B0_load_store'],6)
                self.assertEqual(r['original_class_write_effective_address'],'0xfff7b4b0')
    def test_each_model_artificial_decomp_and_source(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                r=check_fake(sp)
                self.assertTrue(r['original_stack_byte5_value_2_used_as_category_nibble'])
                self.assertTrue(r['class2_is_a_supported_finalizer_case'])
                self.assertFalse(r['no_intervening_or_concurrent_context_writers_proven'])
    def test_sixth_byte_2_is_profile_case2(self):
        for initial in (0,0xffffffff,0xdeadbeef,0x10203040):
            out,cat=s.class_from_six_bytes(bytes([1,1,0,0,0,2]),initial)
            self.assertEqual(cat,2)
            self.assertEqual((out^initial)&~s.CLASS_MASK,0)
            self.assertEqual(out&s.CLASS_MASK,0x02000000)
    def test_full_0_through_15_category_roundtrip(self):
        for byte in range(16):
            out,cat=s.class_from_six_bytes(bytes([9,8,7,6,5,byte]),0)
            self.assertEqual(cat,byte)
            self.assertEqual(out,byte<<24)
    def test_16_through_255_only_low_nibble_affects_category(self):
        for b in range(16,256):
            word,cat=s.class_from_six_bytes(bytes([1,2,3,4,5,b]),0xF0FFFFFF)
            self.assertEqual(cat,b&15)
            self.assertEqual(word>>28,0xf)
    def test_source_is_sixth_byte_not_fourth_or_fifth(self):
        for p in (0,1,2,3,4):
            values=bytearray([1,1,0,0,0,2]);values[p]^=0x7f
            self.assertEqual(s.class_from_six_bytes(values)[1],2)
    def test_return_category_is_not_a_hardware_assertion(self):
        self.assertIn(2,s.s75.CATEGORIES)
        self.assertNotIn(1,s.s75.CATEGORIES)
        self.assertTrue(s.s75.verify_shape(s.s75.rows_from_bytes(
           b''.join(struct.pack('<5I',*r) for r in [(1+i*20,10+i*20,100,200,300) for i in range(14)]+[(0,0xffffffff,100,200,300)]))))

class Negative(unittest.TestCase):pass

for m,sp in s.SPECS.items():
    anchors=[sp.mov2,sp.store2,sp.argpointer,sp.driverbase,
             sp.setter_load,sp.setter_store,
             sp.class_builder_BL,sp.setter_BL,sp.packet_builder_BL,sp.finalize_BL]
    for i,addr in enumerate(anchors):
        for bit in (1,0x100):
            def mk(model,addr,bit):
                def test(self):
                    sp=s.SPECS[model];rom=fake_rom(sp)
                    off=addr-s.s59.BASE
                    value=struct.unpack_from('<I',rom,off)[0]
                    struct.pack_into('<I',rom,off,value^bit)
                    with self.assertRaises(ValueError):s.original_arm(sp,rom)
                return test
            setattr(Negative,f'test_A32_mutation_{m}_{i}_{bit}',mk(m,addr,bit))
    needs=[
       (sp.driver,'local_58 = 0x101;'),
       (sp.driver,'local_54 = 0;'),
       (sp.driver,'local_53 = 2;'),
       (sp.driver,f'FUN_{sp.class_builder:08x}(0xfff7b000,&local_58);'),
       (sp.driver,f'FUN_{sp.packet_builder:08x}(0xfff7b000,&local_7c,&local_6c,'),
       (sp.class_builder,'param_2 != (undefined1 *)0x0'),
       (sp.class_builder,'param_1 != 0'),
       (sp.class_builder,f'FUN_{sp.setter:08x}(param_1,param_2[5]);'),
       (sp.class_builder,'return 0xffffffff;'),
       (sp.setter,'*(uint *)(param_1 + 0x4b0)'),
       (sp.setter,'0xf0ffffff'),
       (sp.setter,'(param_2 & 0xf) << 0x18'),
       (sp.packet_builder,f'FUN_{sp.finalizer:08x}(param_1);'),
       (sp.finalizer,'switch((*(uint *)(param_1 + 0x4b0) & 0xfffffff) >> 0x18)'),
       (sp.finalizer,'case 2:'),
       (sp.finalizer,'default:'),
       (sp.finalizer,'return 0xffffffff;'),
    ]
    for i,mutation in enumerate(needs):
        def mk(model,mutation):
            def test(self):
                with self.assertRaises(ValueError):check_fake(s.SPECS[model],mutation)
            return test
        setattr(Negative,f'test_fake_decomp_corrupt_{m}_{i}',mk(m,mutation))
    for src in ('stackmov','stackwrite','stackptr','BL'):
        def mk(model,src):
            def test(self):
                sp=s.SPECS[model]
                entries=fake_decompiled(sp)
                with tempfile.TemporaryDirectory() as td:
                    root=Path(td);setup_fake_root(sp,root)
                    path=root/f'{model}_stage76_class2_A32_evidence.log'
                    txt=path.read_text()
                    token={'stackmov':f'TRACE_INSN {sp.mov2:08x}',
                           'stackwrite':f'TRACE_INSN {sp.store2:08x}',
                           'stackptr':f'TRACE_INSN {sp.argpointer:08x}',
                           'BL':f'TRACE_INSN {sp.class_builder_BL:08x}'}[src]
                    path.write_text(txt.replace(token,'REMOVED'))
                    with patch.object(s,'fun',side_effect=lambda _,a:entries[a]):
                        with self.assertRaises(ValueError):s.original_decompile(sp,root)
            return test
        setattr(Negative,f'test_original_traced_arm_corrupt_{m}_{src}',mk(m,src))
    for src in ('classBuilder','profileSetter','finalizer'):
        def mk(model,src):
            def test(self):
                sp=s.SPECS[model]
                entries=fake_decompiled(sp)
                with tempfile.TemporaryDirectory() as td:
                    root=Path(td);setup_fake_root(sp,root)
                    path=root/f'{model}_stage76_class2_builder_xrefs.log'
                    txt=path.read_text()
                    token={'classBuilder':f'PROBE_REF from={sp.class_builder_BL:08x}',
                           'profileSetter':f'PROBE_REF from={sp.setter_BL:08x}',
                           'finalizer':f'PROBE_REF from={sp.finalize_BL:08x}'}[src]
                    path.write_text(txt.replace(token,'MISSING'))
                    with patch.object(s,'fun',side_effect=lambda _,a:entries[a]):
                        with self.assertRaises(ValueError):s.original_decompile(sp,root)
            return test
        setattr(Negative,f'test_original_xref_corrupt_{m}_{src}',mk(m,src))

for size in range(6):
    def mk(size):
        def test(self):
            with self.assertRaises(ValueError):s.class_from_six_bytes(bytes([2]*size))
        return test
    setattr(Negative,f'test_bad_synthetic_byte_count_{size}',mk(size))

if __name__=='__main__':unittest.main()

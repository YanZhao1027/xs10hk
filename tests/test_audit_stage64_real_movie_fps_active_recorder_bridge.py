"""Phase64 wholly synthetic ROM A32, getter/adapter and reverse export.

Fake ARM words and fabricated C lines ONLY; no Fuji ROM, Ghidra content,
Main10 output or physical 4K60 recording proof.
"""
import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage64_real_movie_fps_active_recorder_bridge as stage
import audit_recorder_codec_forward_stage32 as st32

def enc_movhalf(value,high=False):
    n=((value>>16) if high else value)&0xffff
    return (0xe3403000 if high else 0xe3003000)|(((n>>12)&0xf)<<16)|(n&0xfff)

def arm_bl(addr,target):
    assert (target-addr-8)%4==0
    return 0xeb000000|(((target-addr-8)//4)&0xffffff)

def fixture(name):
    spec=stage.SPECS[name]
    m=st32.MODELS[name]
    a={
      spec.first_load:0xe5d1306e,
      spec.first_store:0xe5c0301e,
      spec.second_load:0xe5d1306e,
      spec.second_store:0xe5c0301e,
      spec.getter+8:enc_movhalf(m.template_base),
      spec.getter+12:enc_movhalf(m.template_base,True),
      spec.getter+16:0xe5d3001e,
    }
    b={addr:arm_bl(addr,spec.getter) for addr in (spec.consumer1,spec.consumer2,spec.consumer3)}
    if spec.other_stride_site is not None:b[spec.other_stride_site]=0x15c305c6
    t='*(undefined1 *)(param_1 + 0x1e) = param_2[0x6e];'
    g=f'undefined1 FUN_{spec.getter:08x}(void){{return DAT_{spec.active_fps_ram:08x};}}'
    exported=f'void FUN_{spec.exporter:08x}(){{param_1[0x6e] = DAT_{spec.active_fps_ram:08x};}}'
    c1=f'FUN_{spec.getter:08x}();'
    c2=f'uVar3=FUN_{spec.getter:08x}();switch(uVar3){{case 6: case 4: break;}}uVar1=FUN_{spec.getter:08x}();'
    xrefs=(f'PROBE_TARGET addr={spec.active_fps_ram:08x} refs=2\n'
           f'PROBE_REF from={spec.getter+16:08x} to={spec.active_fps_ram:08x} type=READ')
    false=('void FUN_021f6b2c(undefined1 param_1) {\n'
          'if (*(int *)(DAT_021f6b54 + 0xac8) != 0) '
          '*(undefined1 *)(*(int *)(DAT_021f6b54 + 0xac8) + 0x15c6) = param_1;\n}') if name=='xs10' else ''
    return {'a':a,'b':b,'converter':f'if (param_3 == 1){{{t}}}else{{{t}}}',
            'getter':g,'exporter':exported,'consumers':(c1,c2),
            'xrefs':xrefs,'false_writer':false}

def verify(name,f,part):
    s=stage.SPECS[name]
    if part=='A32':return stage.original_arm(s,f['a'].__getitem__,f['b'].__getitem__)
    if part=='C':return stage.decomp(s,f['converter'],f['getter'],
      f['exporter'],f['consumers'],f['xrefs'],f['false_writer'])
    raise ValueError(part)

class Pass(unittest.TestCase):
    def test_two_models(self):
        for name in stage.SPECS:
            with self.subTest(name=name):
                f=fixture(name)
                self.assertEqual(verify(name,f,'A32')['original_byte_pairs_verified'],2)
                self.assertTrue(verify(name,f,'C')['snapshot_exporter_is_reverse_not_input_initial_writer'])
                self.assertFalse(verify(name,f,'C')['Movie_context_plus_5C6_or_5C7_equal_active_fps_proven'])
    def test_source_not_vpu_output_and_other_object(self):
        for name,s in stage.SPECS.items():
            self.assertEqual(s.active_fps_ram,st32.MODELS[name].template_base+0x1e)
            self.assertNotEqual(s.active_fps_ram,st32.MODELS[name].gui_byte)
            self.assertFalse(verify(name,fixture(name),'C')['Main10_hardware_accepted_or_4K60_recorded'])
    def test_fps_branch_is_not_exclusive_mode(self):
        for name in stage.SPECS:
            f=fixture(name)
            self.assertEqual(f['converter'].count('param_2[0x6e]'),2)
            self.assertEqual(f['converter'].count('param_1 + 0x1e'),2)

class Fail(unittest.TestCase):pass

for name,s in stage.SPECS.items():
    m=st32.MODELS[name]
    A=[s.first_load,s.first_store,s.second_load,s.second_store,
       s.getter+8,s.getter+12,s.getter+16]
    B=[s.consumer1,s.consumer2,s.consumer3]
    if s.other_stride_site is not None:B.append(s.other_stride_site)
    for index,(reg,addr) in enumerate([('a',z) for z in A]+[('b',z) for z in B]):
        for mask in (1,1<<12):
            def mutate_arm(name,reg,addr,mask):
                def test(self):
                    f=fixture(name);f[reg][addr]^=mask
                    with self.assertRaises(ValueError):verify(name,f,'A32')
                return test
            setattr(Fail,f'test_bad_a32_{name}_{index:02d}_{mask}',mutate_arm(name,reg,addr,mask))
    for index,(field,term) in enumerate((
      ('converter','param_3 == 1'),
      ('converter','param_2[0x6e]'),
      ('converter','param_1 + 0x1e'),
      ('getter',f'DAT_{s.active_fps_ram:08x}'),
      ('exporter',f'param_1[0x6e] = DAT_{s.active_fps_ram:08x}'),
      ('xrefs',f'PROBE_TARGET addr={s.active_fps_ram:08x} refs=2'),
      ('xrefs',f'PROBE_REF from={s.getter+16:08x}'),
    )):
        def mutate_c(name,field,term):
            def test(self):
                f=fixture(name)
                self.assertIn(term,f[field]);f[field]=f[field].replace(term,'CORRUPT')
                with self.assertRaises(ValueError):verify(name,f,'C')
            return test
        setattr(Fail,f'test_bad_c_{name}_{index:02d}',mutate_c(name,field,term))
    for index in (0,1):
        def mutate_cons(name,index):
            def test(self):
                f=fixture(name);cons=list(f['consumers'])
                cons[index]=cons[index].replace(f'FUN_{stage.SPECS[name].getter:08x}','DUMMY')
                f['consumers']=tuple(cons)
                with self.assertRaises(ValueError):verify(name,f,'C')
            return test
        setattr(Fail,f'test_bad_caller_{name}_{index}',mutate_cons(name,index))
    if name=='xs10':
        for index,term in enumerate(('0x15c6) = param_1;','0xac8')):
            def mutate_wrong(term):
                def test(self):
                    f=fixture('xs10');f['false_writer']=f['false_writer'].replace(term,'MISIDENTIFIED')
                    with self.assertRaises(ValueError):verify('xs10',f,'C')
                return test
            setattr(Fail,f'test_no_raw_offset_false_writer_{index}',mutate_wrong(term))

if __name__=='__main__':unittest.main()
"""Stage62 synthetic-only ARM active-codec->runtime-context->VPU-class.

Test strings and words are fabricated. They are not vendor decompilation,
nor evidence of live Main10 10bit/4K60 recordings or safe firmware patches.
"""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage62_active_codec_to_vpu_class_bridge as m
import audit_stage61_vpu_bitdepth_codec_builder as v


def half(value,reg,high):
    x=((value>>16) if high else value)&0xffff
    return (0xe3400000 if high else 0xe3000000)|(reg<<12)|((x>>12)<<16)|(x&0xfff)

def branch(site,target):
    assert (target-site-8)%4==0
    return 0xeb000000|(((target-site-8)//4)&0xffffff)

def fixture(s):
    down=v.SPECS[s.model]
    w1={s.getter+8:half(s.getter_base,3,False),
        s.getter+12:half(s.getter_base,3,True),
        s.getter+16:0xe5d30000|s.getter_offset}
    w2={s.call_site:branch(s.call_site,s.getter),s.store_site:0xe5c50dda}
    g=f'undefined1 FUN_{s.getter:08x}(){{return DAT_{s.cfg_active:08x};}}'
    source=(f'void FUN_{s.source_setup_fn:08x}(){{'
       f'uVar4=FUN_{s.getter:08x}();'
       '*(undefined1 *)(iVar8 + 0xadda) = uVar4;}')
    downstream=(f'void FUN_{s.vpu_config_fn:08x}(){{'
       "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';"
       f'_DAT_{s.vpu_class_addr:08x} = (uint)!bVar9;'
       f'_DAT_{down.cfg+0xc:08x} = 1;}}')
    return {'w1':w1,'w2':w2,'getter':g,'source':source,'vpu':downstream}


def verify(s,f,part):
    if part=='arm':return m.original_arm(s,f['w1'].__getitem__,f['w2'].__getitem__)
    if part=='C':return m.decomp(s,f['getter'],f['source'],f['vpu'])
    raise ValueError(part)

class Positive(unittest.TestCase):
    def test_both_models(self):
        for name,s in m.SPECS.items():
            for part in ('arm','C'):
                with self.subTest(name=name,part=part):self.assertTrue(verify(s,fixture(s),part))
    def test_semantics_of_two_separate_enums(self):
        for s in m.SPECS.values():
            for raw_codec in (0,1,2,3):
                vpu_class=int(raw_codec!=1)
                self.assertEqual(vpu_class,0 if raw_codec==1 else 1)
                self.assertNotEqual('Main10',raw_codec)
                self.assertEqual(verify(s,fixture(s),'arm')['independent_VPU_bitdepth_numeric_code_on_that_path'],1)
    def test_known_phase47_source_vs_new_driver(self):
        for s in m.SPECS.values():
            self.assertNotEqual(s.cfg_active,s.vpu_class_addr)
            self.assertEqual(s.cfg_active,s.getter_base+s.getter_offset)
            self.assertFalse(verify(s,fixture(s),'C')['actual_Main10_SPS_or_4K60_file_proven'])

class Negative(unittest.TestCase):pass

for name,s in m.SPECS.items():
    for n,(table,site) in enumerate([('w1',s.getter+8),('w1',s.getter+12),
                                    ('w1',s.getter+16),('w2',s.call_site),
                                    ('w2',s.store_site)]):
        for bit in (1,0x100):
            def make(name,table,site,bit):
                def test(self):
                    s=m.SPECS[name];f=fixture(s)
                    f[table][site]^=bit
                    with self.assertRaises(ValueError):verify(s,f,'arm')
                return test
            setattr(Negative,f'test_corrupt_A32_{name}_{n}_{bit}',make(name,table,site,bit))
    for n,(field,needle) in enumerate([
        ('getter',f'DAT_{s.cfg_active:08x}'),
        ('getter','return '),
        ('source',f'FUN_{s.getter:08x}();'),
        ('source','0xadda) = uVar4;'),
        ('vpu','param_1 + 0xadda'),
        ('vpu',f'_DAT_{s.vpu_class_addr:08x} = (uint)!bVar9;'),
        ('vpu',f'_DAT_{v.SPECS[name].cfg+0xc:08x} = 1;'),
    ]):
        def make(name,field,needle):
            def test(self):
                s=m.SPECS[name];f=fixture(s)
                self.assertIn(needle,f[field]);f[field]=f[field].replace(needle,'CORRUPTED')
                with self.assertRaises(ValueError):verify(s,f,'C')
            return test
        setattr(Negative,f'test_corrupt_C_{name}_{n}',make(name,field,needle))

if __name__=='__main__':unittest.main()
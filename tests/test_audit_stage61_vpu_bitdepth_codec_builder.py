"""Stage61 synthetic-only VPU configuration/ARM gate tests.

No Fujifilm code or ROM data; mock instructions are artificial encodings.
A passing test proves neither bitdepth-code meanings nor Main10/4K60.
"""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage61_vpu_bitdepth_codec_builder as st


def mov_half(value,high):
    v=((value>>16) if high else value)&0xffff
    return (0xe3403000 if high else 0xe3003000) | ((v>>12)<<16) | (v&0xfff)

def branch(site,target,cond=0xe,link=False):
    assert (target-site-8)%4==0
    return (cond<<28)|(0x0b000000 if link else 0x0a000000)|(((target-site-8)//4)&0xffffff)


def toy(spec):
    w1={spec.wrapper_driver_BL:branch(spec.wrapper_driver_BL,spec.driver_init,link=True),
        spec.codec_read:0xe5913188,
        spec.codec_read+4:0xe3530000,
        spec.depth_read:0xe591200c,
        spec.depth_cmp:0xe3520001,
        spec.reject_depth_branch:0x8a000067,
        spec.reject_codec_cmp:0xe3530001}
    w2={
        spec.bitdepth_mov-8:mov_half(spec.cfg,False),
        spec.bitdepth_mov-4:mov_half(spec.cfg,True),
        spec.bitdepth_mov:0xe3a02001,
        spec.bitdepth_mov+4:0xe583200c,
        spec.codec_flag_load:0xe5d33dda,
        spec.codec_flag_load+4:0xe1530002,
        spec.codec0_branch:branch(spec.codec0_branch,
            0x022df154 if spec.name=='xs10' else 0x0224b94c,cond=0),
        spec.codec1_mov:0xe3a02001,
        spec.codec1_mov+4:0xe5832188,
        spec.codec0_mov:0xe3a02000,
        spec.codec0_mov+4:0xe5832188,
        spec.codec0_back_branch:branch(spec.codec0_back_branch,
            0x022def90 if spec.name=='xs10' else 0x0224b788),
        spec.wrapper_BL:branch(spec.wrapper_BL,spec.driver_wrapper,link=True),
    }
    bit=spec.cfg+0xc;codec=spec.cfg+0x188
    C={
        'builder':(f'_DAT_{bit:08x} = 1;'
                   + "bVar9 = *(char *)(param_1 + 0xadda) == '\\x01';"
                   + f'_DAT_{codec:08x} = (uint)!bVar9;'
                   + f'FUN_{spec.driver_wrapper:08x}(0,&DAT_{spec.cfg:08x},FUN_01234567);'),
        'wrapper':f'FUN_{spec.driver_init:08x}();',
        'driver':('if ((*(uint *)(param_2 + 0x188) == 0) &&'
                  ' (1 < *(uint *)(param_2 + 0xc)))'
                  ' {s__init_bit_depth_ERROR_0;} '
                  'if (1 < *(uint *)(param_2 + 0x188))'
                  ' {s__init_video_codec_ERROR_0;} '
                  's__init_h265_drv_sequence_sts_ERRO_0;'),
        'refs':('\n'.join([
                 f'PROBE_TARGET addr={bit:08x} refs=1',
                 f'PROBE_TARGET addr={codec:08x} refs=2',
                 f'PROBE_REF from={spec.xref_bitdepth_site:08x} to={bit:08x} type=WRITE',
                ]+[f'PROBE_REF from={a:08x} to={codec:08x} type=WRITE' for a in spec.xref_codec_sites]))
    }
    return {'w1':w1,'w2':w2,'c':C}


def audit(spec,q,part):
    if part=='arm':return st.arm(spec,q['w1'].__getitem__,q['w2'].__getitem__)
    if part=='C':return st.decomp(spec,q['c']['builder'],q['c']['wrapper'],
                                  q['c']['driver'],q['c']['refs'])
    raise ValueError(part)

class Positive(unittest.TestCase):
    def test_both_architectures(self):
        for model,spec in st.SPECS.items():
            with self.subTest(model=model):
                for part in ('arm','C'):
                    self.assertTrue(audit(spec,toy(spec),part))
                self.assertEqual(audit(spec,toy(spec),'arm')['bitdepth_fixed_numeric_code_on_this_path'],1)
                self.assertFalse(audit(spec,toy(spec),'C')['VPU_bitdepth_numeric1_maps_to_HEVC_Main10_10bit_proven'])
    def test_gate_counterexamples_without_extrapolating_hardware(self):
        for model in st.SPECS:
            for codec in (0,1,2):
                for depth in (0,1,2,3):
                    rejected=(codec>1) or (codec==0 and depth>1)
                    if codec==0 and depth==2:self.assertTrue(rejected)
                    if codec==1 and depth==2:self.assertFalse(rejected)
                    # Accepting this one gate is insufficient to verify actual
                    # bitdepth mapping or complete output encoder readiness.
                    self.assertNotEqual('Main10',codec)

class Mutate(unittest.TestCase):pass

for model,spec in st.SPECS.items():
    keys1=(spec.wrapper_driver_BL,spec.codec_read,spec.codec_read+4,
           spec.depth_read,spec.depth_cmp,spec.reject_depth_branch,spec.reject_codec_cmp)
    keys2=(spec.bitdepth_mov-8,spec.bitdepth_mov-4,spec.bitdepth_mov,
           spec.bitdepth_mov+4,spec.codec_flag_load,spec.codec_flag_load+4,
           spec.codec0_branch,spec.codec1_mov,spec.codec1_mov+4,
           spec.codec0_mov,spec.codec0_mov+4,spec.codec0_back_branch,spec.wrapper_BL)
    for n,(name,key) in enumerate([('w1',k) for k in keys1]+[('w2',k) for k in keys2]):
        def make(model,name,key):
            def test(self):
                spec=st.SPECS[model];q=toy(spec)
                q[name][key]^=1
                with self.assertRaises(ValueError):audit(spec,q,'arm')
            return test
        setattr(Mutate,f'test_A32_fault_{model}_{n:02d}',make(model,name,key))
    for n,(field,token) in enumerate((
       ('builder',f'_DAT_{spec.cfg+0xc:08x} = 1;'),
       ('builder','0xadda'),
       ('builder',f'_DAT_{spec.cfg+0x188:08x} = (uint)!bVar9;'),
       ('builder',f'FUN_{spec.driver_wrapper:08x}(0,&DAT_{spec.cfg:08x},'),
       ('wrapper',f'FUN_{spec.driver_init:08x}();'),
       ('driver','(param_2 + 0x188) == 0'),
       ('driver','1 < *(uint *)(param_2 + 0xc)'),
       ('driver','s__init_bit_depth_ERROR_'),
       ('driver','1 < *(uint *)(param_2 + 0x188)'),
       ('driver','s__init_video_codec_ERROR_'),
       ('driver','s__init_h265_drv_sequence_sts_ERRO_'),
       ('refs',f'PROBE_TARGET addr={spec.cfg+0xc:08x} refs=1'),
       ('refs',f'PROBE_TARGET addr={spec.cfg+0x188:08x} refs=2'),
       ('refs',f'PROBE_REF from={spec.xref_bitdepth_site:08x}'),
       ('refs',f'PROBE_REF from={spec.xref_codec_sites[0]:08x}'),
       ('refs',f'PROBE_REF from={spec.xref_codec_sites[1]:08x}'),
    )):
        def make(model,field,token):
            def test(self):
                q=toy(st.SPECS[model]);self.assertIn(token,q['c'][field])
                q['c'][field]=q['c'][field].replace(token,'BROKEN')
                with self.assertRaises(ValueError):audit(st.SPECS[model],q,'C')
            return test
        setattr(Mutate,f'test_decomp_fault_{model}_{n:02d}',make(model,field,token))

if __name__=='__main__':unittest.main()
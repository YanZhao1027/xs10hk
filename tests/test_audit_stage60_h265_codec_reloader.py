"""Stage60 synthetic-only H264/H265 enum, defaults, and XT4 reload tests.

Fabricated ROM bytes, fake Ghidra C and encoded BL instructions; passing
these does NOT establish live H265 Main10, 4K60 or camera firmware safety.
"""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage60_h265_codec_reloader as mod
import audit_stage59_movie_menu_ROM_allowlist as s59
import test_audit_stage59_movie_menu_ROM_allowlist as f59


def bl(site,target):
    assert (target-site-8)%4==0
    return 0xeb000000|(((target-site-8)//4)&0xffffff)


def fixture(model):
    spec=mod.SPECS[model]
    base_spec,b,t=f59.fixture(model)
    addresses=(s59.BASE+0x3700,s59.BASE+0x3760,s59.BASE+0x37c0)
    spec=replace(spec,enum_labels=addresses)
    for addr,label in zip(addresses,mod.EXPECTED_LABELS):
        x=addr-s59.BASE
        b[x:x+len(label)+1]=label.encode()+b'\0'
    c_enum='''char* mock(int param_1) {
        if (param_1 == 0) return s_MODE_MOVIE_CODEC_H264_0;
        else if (param_1 == 1) return s_MODE_MOVIE_CODEC_H265_0;
        if (param_1 != 2) return 0;
        return s_MODE_MOVIE_CODEC_NUM_0; }'''
    loader=f'FUN_HELPER(0x2d,0x{base_spec.codec:x}); if (v==0x7fffffff)return; FUN_{spec.direct_codec_setter:08x}(uVar2 & 0xff);'
    setter=f'DAT_{spec.codec_GUI_address:08x} = (char)param_1;'
    sources={'xs10':[0x01179e54,0x021039f8,0x02103a38],
             'xt4':[0x0114db48,0x0115b314,0x02057e3c,0x02057e7c]}[model]
    xrefs='\n'.join(f'PROBE_REF from={a:08x} to={spec.direct_codec_setter:08x}' for a in sources)
    if model=='xt4':
        reload="if (DAT_01af2808 == '-') uVar3 = 0x2d; else uVar3 = 0x21; FUN_01025514(uVar3,0x3e5); if (uVar1 == 0x7fffffff) return; FUN_0112fd80(uVar1 & 0xff);"
        init="if (*(char *)(DAT_0115f340 + 0x834) == '"+chr(92)+"x01') { FUN_0115b234(); }"
        wrapper='FUN_0115b234();'
        words={spec.reloader_codec_BL:bl(spec.reloader_codec_BL,spec.direct_codec_setter),
               spec.reloader_entry_bl1:bl(spec.reloader_entry_bl1,spec.reloader),
               spec.reloader_entry_bl2:bl(spec.reloader_entry_bl2,spec.reloader)}
    else:
        reload=init=wrapper='';words={}
    return {'spec':spec,'s59':base_spec,'bin':b,
            'enum':c_enum,'load':loader,'setter':setter,'xref':xrefs,
            'reload':reload,'init':init,'wrapper':wrapper,'words':words}


def verify(q,group):
    if group=='enum':return mod.label_enum(q['spec'],s59.Image(bytes(q['bin'])),q['enum'])
    if group=='default':return mod.default_from_rom(q['s59'],s59.Image(bytes(q['bin'])))
    if group=='paths':
        return mod.code_paths(q['spec'],q['load'],q['reload'],q['init'],
                              q['wrapper'],q['setter'],q['xref'],q['words'].__getitem__)
    raise ValueError(group)

class PositiveCases(unittest.TestCase):
    def test_both_models(self):
        for model in mod.SPECS:
            q=fixture(model)
            for group in ('enum','default','paths'):
                with self.subTest(model=model,group=group):self.assertTrue(verify(q,group))
            self.assertEqual(verify(q,'enum')['enum1'],'H265')
            self.assertEqual(verify(q,'default')['codec_mode_0x2D_default'],0)
            self.assertFalse(verify(q,'paths')['codec_setter_has_no_HEVC_bitdepth_or_hardware_proof'] is False)
    def test_h265_allowed_but_normal_default_zero(self):
        for model in mod.SPECS:
            q=fixture(model)
            a=verify(q,'default')
            self.assertEqual(a['codec_mode_0x2D_allowed'],[0,1])
            self.assertEqual(a['codec_mode_0x2D_default'],0)
            self.assertTrue(a['config_default_0_does_not_disallow_valid_H265_value_1'])
    def test_xt4_default_reload_separate_from_eligibility(self):
        q=fixture('xt4')
        self.assertTrue(verify(q,'paths')['reloader_mode0x2D_chooses_preferred_H264_0'])
        self.assertFalse(verify(q,'paths')['conditional_branch_trigger_observed_at_runtime'])

class Faults(unittest.TestCase):pass

for model in mod.SPECS:
    for index in range(3):
        def make(model,index):
            def test(self):
                q=fixture(model)
                addr=q['spec'].enum_labels[index]
                q['bin'][addr-s59.BASE]^=1
                with self.assertRaises(ValueError):verify(q,'enum')
            return test
        setattr(Faults,f'test_corrupt_label_{model}_{index}',make(model,index))
    for index,key in enumerate(('H264','H265','NUM','param_1 == 0','param_1 == 1','param_1 != 2')):
        def make(model,key):
            def test(self):
                q=fixture(model)
                q['enum']=q['enum'].replace(key,'WRONG')
                with self.assertRaises(ValueError):verify(q,'enum')
            return test
        setattr(Faults,f'test_bad_enum_C_{model}_{index}',make(model,key))
    for index,which in enumerate(('load','setter','xref')):
        def make(model,which):
            def test(self):
                q=fixture(model)
                q[which]='INVALID'
                with self.assertRaises(ValueError):verify(q,'paths')
            return test
        setattr(Faults,f'test_bad_core_C_{model}_{index}',make(model,which))
    for index,token in enumerate(('0x7fffffff','0x2d,0x'+format(s59.SPECS[model].codec,'x'),
        f'FUN_{mod.SPECS[model].direct_codec_setter:08x}', 'uVar2 & 0xff')):
        def make(model,token):
            def test(self):
                q=fixture(model);q['load']=q['load'].replace(token,'WRONG')
                with self.assertRaises(ValueError):verify(q,'paths')
            return test
        setattr(Faults,f'test_loader_component_{model}_{index}',make(model,token))
    for field,vi in (('MovieFormat',0),('MovieCodec',0),('eMode4kOut',0),
                     ('MovieFormat',1),('MovieCodec',1),('eMode4kOut',1)):
        for mode in (0x2d,0x21):
            def make(model,field,vi,mode):
                def test(self):
                    q=fixture(model);sp=q['s59']
                    ptr={'MovieFormat':sp.fmt_ptr,'MovieCodec':sp.codec_ptr,
                         'eMode4kOut':sp.out4k_ptr}[field]
                    mi=list(s59.MODE_LISTS[model]).index(mode)
                    idx=ptr-s59.BASE+vi*sp.entry_stride+4+mi
                    q['bin'][idx]=0 if q['bin'][idx] else 1
                    with self.assertRaises(ValueError):verify(q,'default')
                return test
            setattr(Faults,f'test_default_changed_{model}_{field}_{vi}_{mode}',make(model,field,vi,mode))
    for entry in (0,1):
        def make(model,entry):
            def test(self):
                q=fixture(model)
                xs=q['xref'].splitlines()
                xs[entry]='PROBE_REF from=12345678 to=87654321'
                q['xref']='\n'.join(xs)
                with self.assertRaises(ValueError):verify(q,'paths')
            return test
        setattr(Faults,f'test_xref_changed_{model}_{entry}',make(model,entry))
    if model=='xt4':
        for index,addr in enumerate((mod.SPECS[model].reloader_codec_BL,
                                   mod.SPECS[model].reloader_entry_bl1,
                                   mod.SPECS[model].reloader_entry_bl2)):
            def make(model,addr):
                def test(self):
                    q=fixture(model)
                    q['words'][addr]^=1
                    with self.assertRaises(ValueError):verify(q,'paths')
                return test
            setattr(Faults,f'test_xt4_ARM_{index}',make(model,addr))
        for index,(field,needle) in enumerate((
           ('reload',"DAT_01af2808 == '-'") ,('reload','uVar3 = 0x2d;'),
           ('reload','uVar3 = 0x21;'),('reload','FUN_01025514(uVar3,0x3e5)'),
           ('reload','0x7fffffff'),('reload','FUN_0112fd80(uVar1 & 0xff);'),
           ('init','DAT_0115f340 + 0x834'),('init','FUN_0115b234();'),
           ('wrapper','FUN_0115b234();'))):
            def make(model,field,needle):
                def test(self):
                    q=fixture(model)
                    self.assertIn(needle,q[field])
                    q[field]=q[field].replace(needle,'INVALID')
                    with self.assertRaises(ValueError):verify(q,'paths')
                return test
            setattr(Faults,f'test_xt4_reloader_C_{index}',make(model,field,needle))

if __name__=='__main__':unittest.main()
"""Stage52 completely synthetic ARM/alias-confidence tests (NO Fujifilm ROM).

All data is fabricated, so being able to pass tests is NOT evidence of
runtime P==GUI buffer, 4K60, real encoder Main10 or an initial setter.
"""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage52_gui_recorder_hdmi_alias as s
import audit_recorder_input_export_alias_stage31 as st31


def movh(base,high):
    v=(base>>16)&0xffff if high else base&0xffff
    return (0xe3403000 if high else 0xe3003000)|((v>>12)<<16)|(v&0xfff)

def branch(site,target):return 0xeb000000|(((target-site-8)>>2)&0xffffff)

def toy(name):
    p=s.SPECS[name]
    words1={}
    for site,off in ((p.ui4k_strb,0x581),(p.codec_strb,0x5b0)):
        words1[site-8]=movh(p.gui_base,False)
        words1[site-4]=movh(p.gui_base,True)
        words1[site]=0xe5c34000|off
    ui_c='void MOCK(){INPUT_eMode4kOut;DAT_%08x = (char)param_1;}'%(p.gui_base+0x581)
    codec_c='void MOCK(){INPUT_eModeMovieCodec;DAT_%08x = (char)param_1;}'%(p.gui_base+0x5b0)
    words2={
      p.hdmi_583:0xe5d03583,
      p.hdmi_6c:0xe5d0306c,
      p.hdmi_581:0xe5d03581,
      p.hdmi_context_load:0xe5d11ce1 if name=='xs10' else 0xe5d11f45,
      p.hdmi_context_store:0xe5c32ce1 if name=='xs10' else 0xe5c32f45,
      p.guard_200:0xe3510c02,
      p.gui_compare_bl-12:0xe3002000|p.gui_record_len,
      p.gui_compare_bl-8:0xe1a01005,
      p.gui_compare_bl-4:0xe1a00004,
      p.gui_compare_bl:branch(p.gui_compare_bl,p.gui_compare_target),
      p.p_caller_init:branch(p.p_caller_init,p.hdmi_fn),
      p.p_caller_export:branch(p.p_caller_export,p.hdmi_fn),
    }
    ptr=st31.SPECS[name].current_slot
    hdmi='''void hdmi(char *param_1){\nif (param_1[0x583] == 0 && param_1[0x6c] == 7 &&
 param_1[0x581] == 0) FUN_01(); RECCONT__HDMI_CONECT_NG;
 FUN_02(0x8043); }'''
    caller='FUN_%08x(_DAT_%08x);'%(p.hdmi_fn,ptr)
    gui_compare='FUN_%08x(&DAT_%08x,0x%x,0x%x);'%(
                  p.gui_compare_target,p.gui_base,p.gui_shadow,p.gui_record_len)
    cmp_helper='if (*param_1 == *param_2) { if (param_3 == 0) return 0; } return param_1;'
    dump_c='s_REC_INPUT_; FUN_%08x(&DAT_%08x,0x%x);'%(
                p.gui_dump_target,p.gui_base,p.gui_record_len)
    dump_helper='void FUN_%08x() {puVar3 = puVar3 + 1; FUN_1234();}'%p.gui_dump_target
    reg=dict(selected_registry_type_values=['0x206','0x207'],
        entire_pointer_overwritten_iff_payload_length_at_least_8=True,
        runtime_length_and_pointer_value_known=False)
    inter='\n'.join([
      'ST52_REF i=0 addr=%08x refs=%d functions=%d'%(p.gui_base,p.n_gui_xrefs,p.n_gui_fns),
      'ST52_REF i=1 addr=%08x refs=%d functions=%d'%(ptr,p.n_current_p_xrefs,p.n_p_fns),
      'ST52_REF i=2 addr=%08x refs=%d functions=%d'%(
           st31.SPECS[name].descriptor+0x10,p.n_descriptor_p_xrefs,p.n_descriptor_p_fns),
      'ST52_INTERSECTION gui_base_and=1 total=0',
      'ST52_INTERSECTION gui_base_and=2 total=0'])
    bulk=('ST52_GUI_SUMMARY addr=%08x decompiled=%d with_copy=%d with_full_size_literal=%d'%
          (p.gui_base,p.n_gui_fns,p.gui_egress_copy_fns,p.gui_egress_full_sized))
    return {'word1':words1,'word2':words2,'ui':ui_c,'codec':codec_c,
            'hdmi':hdmi,'initcaller':caller,'serializecaller':caller,
            'compare':gui_compare,'comparehelper':cmp_helper,
            'dump':dump_c,'dumphelper':dump_helper,
            'init':'if (_DAT_%08x != 0x200) { ERR_901c; }'%st31.SPECS[name].descriptor,
            'registry':reg,'intersection':inter,'bulk':bulk}

def run_parts(name,case):
    p=s.SPECS[name]
    result1=s.verify_merged_gui(p,case['word1'].__getitem__,case['ui'],case['codec'])
    result2=s.verify_hdmi(p,case['word2'].__getitem__,case['hdmi'],case['initcaller'],case['serializecaller'])
    result3=s.verify_gui_compare(p,case['word2'].__getitem__,case['compare'],case['comparehelper'],case['dump'],case['dumphelper'])
    result4=s.verify_scope_and_scans(p,case['word2'].__getitem__,case['init'],case['registry'],case['intersection'],case['bulk'])
    return result1,result2,result3,result4

class SyntheticPositive(unittest.TestCase):
    def test_two_models(self):
        for name in s.SPECS:
            with self.subTest(name=name):
                a,b,c,d=run_parts(name,toy(name))
                self.assertTrue(a['schema_offsets_match_P_plus_581_and_plus_5b0'])
                self.assertFalse(a['GUI_equals_recorder_runtime_P_proven'])
                self.assertFalse(a['UI_setting_value_equals_P_runtime_byte_proven'])
                self.assertFalse(b['this_consumer_initializes_P_plus_581'])
                self.assertTrue(b['HDMI_related_flag_usage_P_confirmed'])
                self.assertTrue(c['full_gui_buffer_debug_hex_dump_is_not_memcpy_to_Recorder'])
                self.assertFalse(c['full_buffer_copy_into_P_from_GUI_proven'])
                self.assertFalse(d['absence_of_interprocedural_or_indirect_alias_proven'])
    def test_independent_offsets_and_lengths(self):
        for p in s.SPECS.values():
            self.assertEqual(p.gui_base+0x581,p.gui_base+0x5b0-0x2f)
            self.assertLess(0x5b0,p.gui_record_len)
            self.assertNotEqual(p.gui_shadow,p.gui_base)
    def test_hypothetical_alias_is_not_proof(self):
        for spec in s.SPECS.values():
            gui=bytearray(spec.gui_record_len)
            p=bytearray(spec.gui_record_len)
            gui[0x581]=1;gui[0x5b0]=2
            self.assertEqual(p[0x581],0)
            self.assertEqual(p[0x5b0],0)
            # Only an additional assumption aliases GUI and P.
            p=gui
            self.assertEqual(p[0x581],1)
    def test_hdmi_mock_branch_is_not_4k60(self):
        # From Ghidra HDMI consumer: for modes 7/8, when other preconditions
        # hold, branch maps flag zero->connection-state 1, nonzero->2.
        for mode in (7,8):
            for flag in (0,1,2,255):
                state=1 if flag==0 else 2
                self.assertEqual(state,1 if flag==0 else 2)
                self.assertNotIn(state,('4K60','Main10'))

class FailClosed(unittest.TestCase):pass

for name,spec in s.SPECS.items():
    for base_key in ('ui4k_strb','codec_strb'):
        for off in (-8,-4,0):
            def make(name,base_key,off):
                def test(self):
                    d=toy(name);site=getattr(s.SPECS[name],base_key)+off
                    d['word1'][site]^=1
                    with self.assertRaises(ValueError):run_parts(name,d)
                return test
            setattr(FailClosed,'test_A32_GUI_%s_%s_%d'%(name,base_key,off),make(name,base_key,off))
    for ckey,textpart in (('ui','INPUT_eMode4kOut'),('codec','INPUT_eModeMovieCodec'),
                          ('ui',' = (char)param_1;'),('codec',' = (char)param_1;')):
        def make(name,ckey,textpart):
            def test(self):
                d=toy(name);d[ckey]=d[ckey].replace(textpart,'ERROR')
                with self.assertRaises(ValueError):run_parts(name,d)
            return test
        setattr(FailClosed,'test_GUI_mock_%s_%s_%s'%(name,ckey,textpart.encode().hex()),make(name,ckey,textpart))
    for sitekey in ('hdmi_583','hdmi_6c','hdmi_581','hdmi_context_load','hdmi_context_store',
                    'p_caller_init','p_caller_export','guard_200',
                    'gui_compare_bl'):
        def make(name,sitekey):
            def test(self):
                d=toy(name);site=getattr(s.SPECS[name],sitekey)
                d['word2'][site]^=1
                with self.assertRaises(ValueError):run_parts(name,d)
            return test
        setattr(FailClosed,'test_A32_Hdmi_etc_%s_%s'%(name,sitekey),make(name,sitekey))
    for off in (-12,-8,-4):
        def make(name,off):
            def test(self):
                d=toy(name);site=s.SPECS[name].gui_compare_bl+off
                d['word2'][site]^=1
                with self.assertRaises(ValueError):run_parts(name,d)
            return test
        setattr(FailClosed,'test_GUI_compare_ARM_%s_%d'%(name,off),make(name,off))
    for k,frag in (
      ('hdmi','param_1[0x581]'),('hdmi','param_1[0x583]'),('hdmi','param_1[0x6c]'),
      ('hdmi','RECCONT__HDMI_CONECT_NG'),('hdmi','0x8043'),
      ('initcaller','_DAT_'),('serializecaller','_DAT_'),
      ('compare','0x5dc' if name=='xs10' else '0x5d8'),
      ('comparehelper','param_1 == *param_2'),
      ('comparehelper','param_3 == 0'),
      ('dump','s_REC_INPUT_'),('dumphelper','puVar3 = puVar3 + 1;'),
      ('init','0x200'),('init','901c'),
      ('intersection','gui_base_and=1 total=0'),
      ('intersection','gui_base_and=2 total=0'),
      ('bulk','with_full_size_literal='),
    ):
        def make(name,k,frag):
            def test(self):
                d=toy(name)
                self.assertIn(frag,d[k]);d[k]=d[k].replace(frag,'BAD',1)
                with self.assertRaises(ValueError):run_parts(name,d)
            return test
        setattr(FailClosed,'test_mock_removed_%s_%s_%s'%(name,k,frag.encode().hex()),make(name,k,frag))
    for index,bad in enumerate([
            ('selected_registry_type_values',['0x200']),
            ('entire_pointer_overwritten_iff_payload_length_at_least_8',False),
            ('runtime_length_and_pointer_value_known',True)]):
        def make(name,bad):
            def test(self):
                d=toy(name);d['registry'][bad[0]]=bad[1]
                with self.assertRaises(ValueError):run_parts(name,d)
            return test
        setattr(FailClosed,'test_registry_%s_%d'%(name,index),make(name,bad))
    for key,old in [
       ('intersection','functions='),('intersection','refs='),
       ('bulk','decompiled='),('bulk','with_copy=')]:
        def make(name,key,old):
            def test(self):
                d=toy(name);d[key]=d[key].replace(old,'WRONG=',1)
                with self.assertRaises(ValueError):run_parts(name,d)
            return test
        setattr(FailClosed,'test_statscan_%s_%s_%s'%(name,key,old.encode().hex()),make(name,key,old))

if __name__=='__main__':unittest.main()
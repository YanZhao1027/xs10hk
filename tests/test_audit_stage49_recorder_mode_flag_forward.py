"""Stage49 synthetic-only model / ARM transfer / data-direction adversarial tests.

No vendor firmware, real Ghidra logs or hardware data are embedded here.
"""
import copy
from dataclasses import replace
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage49_recorder_mode_flag_forward as s


def toy(model):
    m=s.MODELS[model]
    ms=s.st32.MODELS[model]
    original={}
    for i,(ld,st) in enumerate(s.expected_transfer_words(m)):
        original[m.start+i*8]=ld
        original[m.start+i*8+4]=st
    converted='\n'.join('*(undefined1 *)(param_1 + 0x%x) = param_2[0x%x];'%
                    (m.intermediate_flag+i,inp)
                    for i,inp in enumerate(s.INPUT_FIELDS))
    exporter='\n'.join('param_1[0x%x] = DAT_%08x;'%
                       (inp,m.active_flag+i)
                       for i,inp in enumerate(s.INPUT_FIELDS))
    p32={
       'model':model,
       'input_to_active_static_data_flow_edges_proven':True,
       'intermediate_to_active_template_copy_size':ms.copy_len,
       'input_offset_codec':'0x5b0',
       'active_Recorder_Codec_byte':'0x%08x'%m.active_codec,
       'intermediate_codec_address':'0x%08x'% (ms.intermediate_base+ms.intermediate_codec_offset)
    }
    p48={
       'model':model,
       'parent_flag_a8e_source_when_4K':'0x%08x'%m.active_flag,
       '4K_class_movie_types':[4,5,6,7],
       'parent_flag_a8e_source_when_NOT_4K':0,
       'Recorder_export_snapshot_offsets':{
          'snap_export_source_flag_offset':'0x581',
          'snap_export_source_codec_offset':'0x5b0'}
    }
    return {'rom':original,'adapter':converted,'exporter':exporter,
            'p32':p32,'p48':p48}

def validate(model,fixture):
    m=s.MODELS[model]
    return s.check_static_bridge(m,fixture['rom'].__getitem__,
                                 fixture['adapter'],fixture['exporter'],
                                 fixture['p32'],fixture['p48'])

class StaticSemantics(unittest.TestCase):
    def test_two_positive_models(self):
        for model in s.MODELS:
            with self.subTest(model=model):
                ret=validate(model,toy(model))
                self.assertTrue(ret['forward_input_plus_581_to_active_flag_static_path_verified'])
                self.assertFalse(ret['initial_config_input_plus_581_writer_identified'])
                self.assertFalse(ret['X_S10_specific_4K60_gate_unlocked'])
                self.assertEqual(ret['original_A32_LDRB_STRB_words_verified'],8)
    def test_source_order_not_ascending(self):
        self.assertEqual(s.INPUT_FIELDS,(0x581,0x580,0x583,0x582))
    def test_codec_distinct_from_flag(self):
        for m in s.MODELS.values():
            self.assertEqual(m.active_codec-m.active_flag,0x34)
            self.assertEqual(m.intermediate_flag+0x34,
                             s.st32.MODELS[m.name].intermediate_codec_offset)
    def test_active_flag_getter_class_not_proven_runtime(self):
        for model in s.MODELS:
            f=toy(model)
            self.assertFalse(validate(model,f)['current_input_byte_value_observed'])
    def test_flag1_size_key_override_is_static_only(self):
        for movtype in (4,5,6,7):
            self.assertEqual(s.select_movie_key(movtype,1,7,2),0x0206)
            self.assertEqual(s.select_movie_key(movtype,2,7,2),0x0207)
        for movtype in (0,1,2,3):
            self.assertEqual(s.select_movie_key(movtype,1,7,2),0x0207)
    def test_invalid_flags(self):
        for v in (-1,256,'1',1.0,None):
            with self.subTest(v=v):
                with self.assertRaises(ValueError):s.select_movie_key(4,v)

class FailClosed(unittest.TestCase):
    pass

# Each original A32 word is verified, not just a Ghidra text snippet.
for model in s.MODELS:
    m=s.MODELS[model]
    for i in range(8):
        def make(model,i):
            def test(self):
                f=toy(model)
                addr=s.MODELS[model].start+4*i
                f['rom'][addr]^=1
                with self.assertRaisesRegex(ValueError,'A32'):
                    validate(model,f)
            return test
        setattr(FailClosed,'test_corrupt_instruction_%s_%d'%(model,i),make(model,i))
    for i in range(4):
        def make(model,i):
            def test(self):
                f=toy(model)
                src=s.INPUT_FIELDS[i];dst=s.MODELS[model].intermediate_flag+i
                old='*(undefined1 *)(param_1 + 0x%x) = param_2[0x%x];'%(dst,src)
                f['adapter']=f['adapter'].replace(old,'/* missing verified edge */')
                with self.assertRaisesRegex(ValueError,'Ghidra'):
                    validate(model,f)
            return test
        setattr(FailClosed,'test_missing_adapter_%s_%d'%(model,i),make(model,i))
    for i in range(4):
        def make(model,i):
            def test(self):
                f=toy(model)
                src=s.INPUT_FIELDS[i];addr=s.MODELS[model].active_flag+i
                old='param_1[0x%x] = DAT_%08x;'%(src,addr)
                f['exporter']=f['exporter'].replace(old,'param_1[0x%x] = 0;'%(src,))
                with self.assertRaisesRegex(ValueError,'reverse exporter'):
                    validate(model,f)
            return test
        setattr(FailClosed,'test_missing_export_%s_%d'%(model,i),make(model,i))

    # Predecessor checks prevent the common error of proving a mapping in an
    # unrelated temporary struct and declaring a physical runtime value.
    fields=[
       ('p32','input_to_active_static_data_flow_edges_proven',False),
       ('p32','intermediate_to_active_template_copy_size',1),
       ('p32','model','wrong'),
       ('p32','input_offset_codec','0x581'),
       ('p32','active_Recorder_Codec_byte','0xdeadbeef'),
       ('p32','intermediate_codec_address','0xdeadbeef'),
       ('p48','model','wrong'),
       ('p48','parent_flag_a8e_source_when_4K','0xdeadbeef'),
       ('p48','4K_class_movie_types',[1,2,3]),
       ('p48','parent_flag_a8e_source_when_NOT_4K',1),
    ]
    for i,(part,key,bad) in enumerate(fields):
        def make(model,part,key,bad):
            def test(self):
                f=toy(model)
                f[part][key]=bad
                with self.assertRaises(ValueError):validate(model,f)
            return test
        setattr(FailClosed,'test_invalid_predecessor_%s_%02d'%(model,i),
                make(model,part,key,bad))
    for i,(part,key,bad) in enumerate([
       ('p48','snap_export_source_flag_offset','0x580'),
       ('p48','snap_export_source_codec_offset','0x581')]):
        def make(model,part,key,bad):
            def test(self):
                f=toy(model)
                f[part]['Recorder_export_snapshot_offsets'][key]=bad
                with self.assertRaises(ValueError):validate(model,f)
            return test
        setattr(FailClosed,'test_wrong_reverse_offset_%s_%d'%(model,i),
                make(model,part,key,bad))
    def make_order(model):
        def test(self):
            f=toy(model)
            lines=f['adapter'].splitlines()
            lines[0],lines[1]=lines[1],lines[0]
            f['adapter']='\n'.join(lines)
            with self.assertRaisesRegex(ValueError,'order'):
                validate(model,f)
        return test
    setattr(FailClosed,'test_adapter_reordered_'+model,make_order(model))

# 0/1/2/3 flag values for eight movie types, each with two high-byte keys;
# mathematical branch assertions only (no actual hardware observation).
for movtype in range(8):
    for flag in (0,1,2,3):
        for high in (2,7):
            def make(movtype,flag,high):
                def test(self):
                    expected_low=6 if movtype in (4,5,6,7) and flag==1 else 7
                    expected=(high<<8)|expected_low
                    self.assertEqual(s.select_movie_key(movtype,flag,7,high),expected)
                return test
            setattr(StaticSemantics,'test_mode_%d_flag_%d_hi_%d'%(movtype,flag,high),
                    make(movtype,flag,high))

if __name__=='__main__':unittest.main()
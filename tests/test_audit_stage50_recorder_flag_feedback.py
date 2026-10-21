"""Stage50 ROM-FREE synthetic tests, no Fuji firmware or Ghidra extracts.

The original audit separately reads SHA pinned proprietary ROM and private
read-only Ghidra logs. These tests only generate invented ARM instructions,
addresses, statuses and one-line snippets to verify fail-closed behavior.
"""
from dataclasses import replace
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage50_recorder_flag_feedback as s


def movw(value,rd=3,high=False):
    half=(value>>16)&0xffff if high else value&0xffff
    return (0xe3400000 if high else 0xe3000000) | (rd<<12) | ((half>>12)<<16) | (half&0xfff)

def toy(name):
    m=s.SPECS[name]
    word={}
    for i,(load,store) in enumerate(s.original_export_words(m)):
        word[m.exporter_first_ldrb+i*8]=load
        word[m.exporter_first_ldrb+i*8+4]=store
    word[m.ui_movw]=movw(m.expected_ui_dest-0x581)
    word[m.ui_movw+4]=movw(m.expected_ui_dest-0x581,high=True)
    if name=='xs10':
        word[m.other_movw_or_literal]=0xe59f3034
        word[m.other_value_literal]=m.expected_other_dest-0x581
    else:
        word[m.other_movw_or_literal]=movw(m.expected_other_dest-0x581)
        word[m.other_movw_or_literal+4]=movw(m.expected_other_dest-0x581,high=True)
    word[m.ui_site]=0xe5c34581
    word[m.other_site]=0xe5c34581 if name=='xs10' else 0xe5c32581
    listing=['INFO > ST50_TOTALS {580/WRITE=12,581/WRITE=3,582/WRITE=3,583/WRITE=3}',
             'INFO > ST50_GROUP 580/WRITE fns=10']
    num=m.expected_word_writes_at_580
    for i in range(12):
        addr=0x02200000+i*4
        asm='str r3,[r4,#0x580]' if i<num else 'strb r3,[r4,#0x580]'
        listing.append('INFO > ST50_SITE %08x %s (GhidraScript)'%(addr,asm))
    listing.append('INFO > ST50_GROUP 581/WRITE fns=3')
    for i,(site,asm) in enumerate(zip((m.ui_site,m.other_site,m.exporter_site),m.direct_orig_asm)):
        listing.append('INFO > ST50_OWNER 581/WRITE FUN_%08x@%08x sites=1'%(site-16,site-16))
        listing.append('INFO > ST50_SITE %08x %s (GhidraScript)'%(site,asm))
    listing.append('INFO > ST50_GROUP 582/WRITE fns=3')
    exporter='\n'.join('param_1[0x%x] = DAT_%08x;'%(off,m.active_first+i)
                       for i,off in enumerate(s.FLAGS))
    p=s.st31.SPECS[name];old=s.st49.MODELS[name]
    p31={
     'model':name,
     'original_A32_R0_R1_pointer_copy_verified':True,
     'pointer_value_equality_immediately_after_alias_instruction':True,
     'same_caller_calls_initializer_before_serializer':True,
     'runtime_pointer_equality_at_serializer_time_proven':False,
     'input_pointer_slot':hex(p.current_slot),
     'export_pointer_slot':hex(p.export_slot),
    }
    p49={
      'model':name,
      'forward_input_plus_581_to_active_flag_static_path_verified':True,
      'active_flag_RAM':hex(m.active_first),
      'active_codec_RAM_separate':hex(old.active_codec),
      'reverse_export_active_to_snapshot_plus_581_verified':True,
      'initial_config_input_plus_581_writer_identified':False,
    }
    return dict(word=word,inventory='\n'.join(listing),exporter=exporter,
         mode='*(undefined4 *)(param_1 + 0x580) = *(undefined4 *)(param_2 + 0x18);',
         initializer='*(undefined4 *)(param_1 + 0x580) = 1;',p31=p31,p49=p49)

def audit(name,case):
    m=s.SPECS[name]
    return s.validate(m,case['word'].__getitem__,case['inventory'],
                      case['exporter'],case['mode'],case['initializer'],
                      case['p31'],case['p49'])

class ForwardAndBackward(unittest.TestCase):
    def test_two_models(self):
        for name in s.SPECS:
            with self.subTest(name=name):
                x=audit(name,toy(name))
                self.assertTrue(x['serializes_active_flag_to_Q_plus_581'])
                self.assertFalse(x['first_writer_of_P_plus_581_proven'])
                self.assertFalse(x['input_output_pointer_equality_during_actual_serialize_proven'])
                self.assertEqual(x['original_active_to_export_LDRB_STRB_words'],8)
    def test_nonmonotonic_field_order(self):
        self.assertEqual(s.FLAGS,(0x581,0x580,0x583,0x582))
    def test_outside_ui_globals(self):
        for name in s.SPECS:
            x=audit(name,toy(name))
            self.assertEqual(len(x['non_export_STRB_581_static_targets']),2)
            self.assertNotIn(x['input_slot'],x['non_export_STRB_581_static_targets'])
    def test_snapshot_alias_is_a_conditional_model(self):
        # Pure logic: assignment P->Q is immediately equal but could differ
        # after Q is updated again, before exporter invokes its call.
        p=bytearray(0x5dc);q=p
        q[0x581]=2
        self.assertEqual(p[0x581],2)
        q=bytearray(0x5dc)
        q[0x581]=1
        self.assertEqual(p[0x581],2)
        self.assertEqual(q[0x581],1)

class Adversarial(unittest.TestCase):
    pass

for name in s.SPECS:
    m=s.SPECS[name]
    for ix in range(8):
        def make(name,ix):
            def test(self):
                x=toy(name)
                addr=s.SPECS[name].exporter_first_ldrb+ix*4
                x['word'][addr]^=1
                with self.assertRaisesRegex(ValueError,'A32'):
                    audit(name,x)
            return test
        setattr(Adversarial,'test_corrupt_original_export_%s_%02d'%(name,ix),make(name,ix))
    for ix in range(4):
        def make(name,ix):
            def test(self):
                x=toy(name)
                m=s.SPECS[name]
                old='param_1[0x%x] = DAT_%08x;'%(s.FLAGS[ix],m.active_first+ix)
                x['exporter']=x['exporter'].replace(old,'param_1[0x%x] = 0;'%s.FLAGS[ix])
                with self.assertRaisesRegex(ValueError,'exporter Ghidra'):
                    audit(name,x)
            return test
        setattr(Adversarial,'test_wrong_export_semantics_%s_%d'%(name,ix),make(name,ix))
    for ix in range(3):
        def make(name,ix):
            def test(self):
                x=toy(name)
                addr=(s.SPECS[name].ui_site,s.SPECS[name].other_site,s.SPECS[name].exporter_site)[ix]
                x['word'][addr]^=8
                with self.assertRaises(ValueError):
                    audit(name,x)
            return test
        setattr(Adversarial,'test_wrong_direct_store_%s_%d'%(name,ix),make(name,ix))
    for ix in range(2):
        def make(name,ix):
            def test(self):
                x=toy(name);m=s.SPECS[name]
                addr=m.ui_movw+4*ix
                x['word'][addr]^=0x1000
                with self.assertRaises(ValueError):audit(name,x)
            return test
        setattr(Adversarial,'test_ui_global_wrong_mov_%s_%d'%(name,ix),make(name,ix))
    for ix in range(2):
        def make(name,ix):
            def test(self):
                x=toy(name);m=s.SPECS[name]
                addr=m.other_movw_or_literal if ix==0 else m.other_value_literal if name=='xs10' else m.other_movw_or_literal+4
                x['word'][addr]^=1
                with self.assertRaises(ValueError):audit(name,x)
            return test
        setattr(Adversarial,'test_alt_writer_wrong_target_%s_%d'%(name,ix),make(name,ix))
    for ix,change in enumerate([
       ('model','other'),('original_A32_R0_R1_pointer_copy_verified',False),
       ('pointer_value_equality_immediately_after_alias_instruction',False),
       ('same_caller_calls_initializer_before_serializer',False),
       ('runtime_pointer_equality_at_serializer_time_proven',True),
       ('input_pointer_slot','0x1234'),('export_pointer_slot','0x1234')]):
        def make(name,change):
            def test(self):
                x=toy(name)
                x['p31'][change[0]]=change[1]
                with self.assertRaisesRegex(ValueError,'Phase31'):
                    audit(name,x)
            return test
        setattr(Adversarial,'test_bad_prior_pointer_%s_%02d'%(name,ix),make(name,change))
    for ix,change in enumerate([
       ('model','other'),('forward_input_plus_581_to_active_flag_static_path_verified',False),
       ('active_flag_RAM','0x1234'),('active_codec_RAM_separate','0x1234'),
       ('reverse_export_active_to_snapshot_plus_581_verified',False),
       ('initial_config_input_plus_581_writer_identified',True)]):
        def make(name,change):
            def test(self):
                x=toy(name)
                x['p49'][change[0]]=change[1]
                with self.assertRaises(ValueError):audit(name,x)
            return test
        setattr(Adversarial,'test_bad_prior_flag_%s_%02d'%(name,ix),make(name,change))
    for ix,changed in enumerate([
        ('581/WRITE=3','581/WRITE=4'),
        ('580/WRITE=12','580/WRITE=11'),
        ('582/WRITE=3','582/WRITE=2'),
        ('583/WRITE=3','583/WRITE=2'),
        ('ST50_OWNER 581/WRITE','ST50_OWNER 582/WRITE'),
        ('ST50_GROUP 581/WRITE fns=3','ST50_GROUP 581/WRITE fns=2'),
        ('strb r3,[r4,#0x581]','strb r3,[r4,#0x580]'),
        ('str r3,[r4,#0x580]','strb r3,[r4,#0x580]'),
       ]):
        def make(name,changed):
            def test(self):
                x=toy(name)
                old,new=changed
                self.assertIn(old,x['inventory'])
                x['inventory']=x['inventory'].replace(old,new,1)
                with self.assertRaises(ValueError):audit(name,x)
            return test
        # Store string mutation only applies if exporter store is as chosen.
        if 'strb r3' in changed[0] and s.SPECS[name].direct_orig_asm[2]!=changed[0]:
            continue
        setattr(Adversarial,'test_inventory_corrupt_%s_%02d'%(name,ix),make(name,changed))
    for ix,scope in enumerate(['mode','initializer']):
        def make(name,scope):
            def test(self):
                x=toy(name)
                x[scope]=x[scope].replace('0x580','0x581')
                with self.assertRaises(ValueError):audit(name,x)
            return test
        setattr(Adversarial,'test_wrong_movie_context_%s_%d'%(name,ix),make(name,scope))

if __name__=='__main__':unittest.main()
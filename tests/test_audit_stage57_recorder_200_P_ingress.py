"""Synthetic 24-byte type200 Recorder P ingress tests: no vendor ROM.

A passing fabricated queue handoff is NOT evidence a real camera queued,
received, initialized, or recorded Main10/4K60; pointer equality unknown.
"""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage57_recorder_200_P_ingress as s
import audit_stage53_gui_rec_setparam_tx as old
import audit_stage52_gui_recorder_hdmi_alias as gui


def BL(site,target):
    assert (target-site-8)%4==0
    return 0xeb000000|(((target-site-8)//4)&0xffffff)

def half(v,reg,high):
    x=((v>>16) if high else v)&0xffff
    return (0xe3400000 if high else 0xe3000000)|(reg<<12)|((x>>12)<<16)|(x&0xfff)


def fixture(sp):
    a=sp.sender
    instructions={
      0x24:0xe5943004,0x28:0xe5d3240b,0x2c:0xe5c3240a,
      0x38:0xe5943004,0x3c:0xe50b302c,
      0x40:0xe5943008,0x44:0xe50b3028,
      0x50:0xe594300c,0x54:0xe50b3020,
      0x58:0xe3a03000,0x5c:0xe54b301c,
      0x60:0xe3a03c02,0x64:0xe14b31b8,
      0x6c:0xe54b0016,0x70:0xe3a00007,0x74:0xe54b0015,
      0x78:0xe3a03018,0x7c:0xe50b3014,
      0x80:0xe24b3030,0x84:0xe50b3010,0x88:0xe24b1018,
    }
    words={a+k:v for k,v in instructions.items()}
    words[a+0x68]=BL(a+0x68,sp.clock_bl)
    words[sp.queue_bl]=BL(sp.queue_bl,old.SPECS[sp.model].enqueue)
    words[sp.ui_P_load-8]=half(sp.ui_P_const,3,False)
    words[sp.ui_P_load-4]=half(sp.ui_P_const,3,True)
    words[sp.ui_P_load]=0xe50b301c
    words[sp.ui_sender_bl]=BL(sp.ui_sender_bl,sp.sender)
    words[sp.dynamic_bl]=BL(sp.dynamic_bl,sp.sender)
    cs={
      'sender':('*(undefined1 *)(param_1[1] + 0x40a) = *(undefined1 *)(param_1[1] + 0x40b);'
           'local_30 = param_1[1]; local_2c = param_1[2];'
           'local_1c = 0x200; local_18 = 0x18;'
           'FUN_%08x(7,&local_1c);'%old.SPECS[sp.model].enqueue),
      'ui':('local_24 = &DAT_%08x; local_20 = &DAT_%08x;'
            'local_1c = &DAT_%08x; local_18 = FUN_1234(0x2000000);'
            'FUN_%08x(&local_24);'%
            (sp.ui_first_const,sp.ui_P_const,sp.ui_third_const,sp.sender)),
      'dynamic':(('local_30 = DAT_%08x + 0x74; FUN_%08x(&local_34);'%
                (sp.dynamic_P_literal,sp.sender)) if sp.model=='xs10'
                else ('local_28 = DAT_%08x; FUN_%08x(&local_2c);'%
                (sp.dynamic_P_literal,sp.sender)))
    }
    return {'w':words,'c':cs}


def verify(sp,fixture,group):
    w=fixture['w'].__getitem__;c=fixture['c']
    if group=='sender':return s.sender(sp,w,c['sender'])
    if group=='ui':return s.ui_source(sp,w,c['ui'])
    if group=='dynamic':return s.dynamic_source(sp,w,c['dynamic'])
    if group=='receiver':return s.conditional_receiver(sp)
    raise ValueError(group)

class SyntheticGood(unittest.TestCase):
    def test_both_model_groups(self):
        for m,sp in s.SPECS.items():
            for group in ('sender','ui','dynamic','receiver'):
                with self.subTest(m=m,group=group):
                    self.assertTrue(verify(sp,fixture(sp),group))
    def test_type200_data_second_word_is_pointer_not_config(self):
        for m,sp in s.SPECS.items():
            import struct
            fake_pointer=0x19001000
            ptrs=[0x10203040,fake_pointer,0x55667788]
            msg=bytearray(24)
            struct.pack_into('<III',msg,0,*ptrs)
            desc=bytearray(0x60)
            desc[0x0c:0x0c+24]=msg
            self.assertEqual(struct.unpack_from('<I',desc,0x10)[0],fake_pointer)
            self.assertNotEqual(fake_pointer,struct.unpack_from('<I',desc,0x0c)[0])
            self.assertNotEqual(desc[0x10],1)
            self.assertGreater(0x581,len(msg))
    def test_20b_sequence_same_slot_not_P(self):
        for m,sp in s.SPECS.items():
            payload=[0x12456780,0x20003000]
            desc=payload[:]
            self.assertEqual(desc[1],0x20003000)
            self.assertNotEqual(desc[1],sp.ui_P_const)
            self.assertFalse(verify(sp,fixture(sp),'receiver')['runtime_type0x200_message_delivered_and_initializer_executes_proven'])
    def test_gui_addresses_still_distinct(self):
        for m,sp in s.SPECS.items():
            self.assertNotEqual(sp.ui_P_const,gui.SPECS[m].gui_base)
            self.assertNotEqual(sp.ui_P_const,old.SPECS[m].staging)

class SyntheticNegatives(unittest.TestCase):pass

for m,sp in s.SPECS.items():
    expected_offsets=[0x24,0x28,0x2c,0x38,0x3c,0x40,0x44,0x50,0x54,
        0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c,0x80,0x84,0x88]
    for i,off in enumerate(expected_offsets):
        def make(model,off):
            def test(self):
                sp=s.SPECS[model];f=fixture(sp);f['w'][sp.sender+off]^=0x1
                with self.assertRaises(ValueError):verify(sp,f,'sender')
            return test
        setattr(SyntheticNegatives,f'test_corrupt_sender_{m}_{i:02d}',make(m,off))
    for i,(part,addr) in enumerate([('sender',sp.queue_bl),('ui',sp.ui_P_load-8),
        ('ui',sp.ui_P_load-4),('ui',sp.ui_P_load),('ui',sp.ui_sender_bl),
        ('dynamic',sp.dynamic_bl)]):
        def make(model,part,addr):
            def test(self):
                sp=s.SPECS[model];f=fixture(sp);f['w'][addr]^=1
                with self.assertRaises(ValueError):verify(sp,f,part)
            return test
        setattr(SyntheticNegatives,f'test_corrupt_other_ARM_{m}_{i:02d}',make(m,part,addr))
    for i,(field,needle) in enumerate([
       ('sender','param_1[1] + 0x40a'),('sender','param_1[1] + 0x40b'),
       ('sender','local_30 = param_1[1];'),('sender','local_2c = param_1[2];'),
       ('sender','local_1c = 0x200;'),('sender','local_18 = 0x18;'),
       ('sender',f'FUN_{old.SPECS[m].enqueue:08x}(7,&local_1c);'),
       ('ui',f'&DAT_{sp.ui_first_const:08x};'),
       ('ui',f'&DAT_{sp.ui_P_const:08x};'),
       ('ui',f'&DAT_{sp.ui_third_const:08x};'),
       ('ui',f'FUN_{sp.sender:08x}(&local_24);'),
       ('ui','0x2000000'),
       ('dynamic',f'DAT_{sp.dynamic_P_literal:08x}'),
       ('dynamic',f'FUN_{sp.sender:08x}('),
    ]):
        def make(model,field,needle):
            def test(self):
                sp=s.SPECS[model];f=fixture(sp)
                self.assertIn(needle,f['c'][field])
                f['c'][field]=f['c'][field].replace(needle,'BROKEN')
                with self.assertRaises(ValueError):verify(sp,f,field)
            return test
        setattr(SyntheticNegatives,f'test_corrupt_C_{m}_{i:02d}',make(m,field,needle))

if __name__=='__main__':unittest.main()
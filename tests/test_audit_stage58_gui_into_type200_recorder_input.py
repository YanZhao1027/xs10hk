"""Fully synthetic Stage58 GUI->distinct Recorder P conditionally copied then sent.

Synthetic A32 and artificial Ghidra lines only. No vendor code/binary and
never assert runtime entry, device recording, Main10 or 4K60.
"""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage58_gui_into_type200_recorder_input as s
import audit_stage53_gui_rec_setparam_tx as st53


def mov(value,reg,high):
    half=((value>>16) if high else value)&0xffff
    return (0xe3400000 if high else 0xe3000000) | (reg<<12)|((half>>12)<<16)|(half&0xfff)

def branch(site,target,link=False):
    assert (target-site-8)%4==0
    return (0xeb000000 if link else 0xea000000)|(((target-site-8)//4)&0xffffff)


def fake(sp):
    b1={sp.wrapper_bl-4:0xe3002000|sp.size,
        sp.wrapper_bl:branch(sp.wrapper_bl,st53.SPECS[sp.model].memcpy,True)}
    a=sp.copy_site;r=sp.reverse_bl
    b2={
      a-16:mov(sp.gui,1,False),a-12:mov(sp.gui,1,True),
      a-8:mov(sp.p_input,0,False),a-4:mov(sp.p_input,0,True),
      a:branch(a,sp.memcpy_wrap,True),
      sp.b_back_site:branch(sp.b_back_site,sp.ui_send_site),
      sp.ui_send_site:branch(sp.ui_send_site,sp.ui_send_fn,True),
      r-16:mov(sp.p_input,1,False),r-12:mov(sp.p_input,1,True),
      r-8:mov(sp.gui,0,False),r-4:mov(sp.gui,0,True),
      r:branch(r,sp.memcpy_wrap,True),
    }
    copy=f'FUN_{sp.memcpy_wrap:08x}(&DAT_{sp.p_input:08x},&DAT_{sp.gui:08x});'
    rev=f'FUN_{sp.memcpy_wrap:08x}(&DAT_{sp.gui:08x},&DAT_{sp.p_input:08x});'
    return {'w1':b1,'w2':b2,'texts':[
       f'FUN_{st53.SPECS[sp.model].memcpy:08x}(param_1,param_2,0x{sp.size:x});',
       ('FUN_%08x(); if (x) {%s FUN_%08x();}'%(sp.ui_send_fn,copy,sp.ui_send_fn)),
       rev, 'void extra(){'+copy+'}', 'void extraAlt(){'+copy+'}']}

def verify(sp,f,part):
    if part=='ARM':return s.armwords(sp,f['w1'].__getitem__,f['w2'].__getitem__)
    if part=='C':return s.decompiled(sp,*f['texts'])
    if part=='cross':return s.cross_phase(sp)
    raise ValueError(part)

class Positives(unittest.TestCase):
    def test_two_firmware_versions(self):
        for model,sp in s.SPECS.items():
            for part in ('ARM','C','cross'):
                with self.subTest(model=model,part=part):self.assertTrue(verify(sp,fake(sp),part))
    def test_copies_both_field_bytes(self):
        for sp in s.SPECS.values():
            buf=bytearray(sp.size);buf[0x581]=1;buf[0x5b0]=3
            P=bytearray(sp.size)
            P[:]=buf[:]
            self.assertEqual(P[0x581],1)
            self.assertEqual(P[0x5b0],3)
            self.assertNotEqual(sp.gui,sp.p_input)
    def test_reverse_direction_is_not_copy_into_P(self):
        for sp in s.SPECS.values():
            P=bytearray(sp.size);GUI=bytearray(sp.size)
            P[0x581]=2;GUI[0x581]=1
            GUI[:]=P[:]
            self.assertEqual(GUI[0x581],2)
            self.assertFalse(verify(sp,fake(sp),'C')['reversed_P_to_GUI_copy_is_not_initial_input_writer'] is False)
    def test_fsm_and_staging_not_current_P(self):
        for sp in s.SPECS.values():
            self.assertNotEqual(st53.SPECS[sp.model].staging,sp.p_input)
            self.assertNotEqual(sp.p_input,sp.gui)
            self.assertTrue(verify(sp,fake(sp),'ARM')['original_control_flow_copy_BL_then_backwards_B_to_sender_BL'])

class Mutations(unittest.TestCase):pass

for model,sp in s.SPECS.items():
    sites1=(sp.wrapper_bl-4,sp.wrapper_bl)
    sites2=tuple(sp.copy_site+d for d in (-16,-12,-8,-4,0))+(
         sp.b_back_site,sp.ui_send_site)+tuple(sp.reverse_bl+d for d in (-16,-12,-8,-4,0))
    for i,(wname,addr) in enumerate([('w1',a) for a in sites1]+[('w2',a) for a in sites2]):
        def make(model,wname,addr):
            def test(self):
                sp=s.SPECS[model];f=fake(sp)
                f[wname][addr]^=1
                with self.assertRaises(ValueError):verify(sp,f,'ARM')
            return test
        setattr(Mutations,f'test_ARM_{model}_{i:02d}',make(model,wname,addr))
    for n,which in enumerate(range(5)):
        def make(model,which):
            def test(self):
                sp=s.SPECS[model];f=fake(sp)
                f['texts'][which]='WRONG'
                with self.assertRaises(ValueError):verify(sp,f,'C')
            return test
        setattr(Mutations,f'test_missing_C_{model}_{n}',make(model,which))
    for i,v in enumerate(('source','dest','size','sender','branch','reverse')):
        def make(model,v):
            def test(self):
                sp=s.SPECS[model];f=fake(sp)
                if v=='source':f['w2'][sp.copy_site-16]=mov(0x11998877,1,False)
                elif v=='dest':f['w2'][sp.copy_site-8]=mov(0x33445566,0,False)
                elif v=='size':f['w1'][sp.wrapper_bl-4]=0xe3002000|0x580
                elif v=='sender':f['w2'][sp.ui_send_site]=branch(sp.ui_send_site,sp.memcpy_wrap,True)
                elif v=='branch':f['w2'][sp.b_back_site]=branch(sp.b_back_site,sp.b_back_site+8)
                else:f['w2'][sp.reverse_bl-8]=mov(sp.p_input,0,False)
                with self.assertRaises(ValueError):verify(sp,f,'ARM')
            return test
        setattr(Mutations,f'test_semantic_fault_{model}_{i}',make(model,v))
    # More mutations of all four literal halfwords in both copy directions,
    # with alternative bit-flips to guard against mask regression.
    for j,a in enumerate([sp.copy_site-16,sp.copy_site-12,sp.copy_site-8,
                           sp.copy_site-4,sp.reverse_bl-16,sp.reverse_bl-12,
                           sp.reverse_bl-8,sp.reverse_bl-4]):
        for bit in (0x10,0x100):
            def make(model,a,bit):
                def test(self):
                    sp=s.SPECS[model];f=fake(sp);f['w2'][a]^=bit
                    with self.assertRaises(ValueError):verify(sp,f,'ARM')
                return test
            setattr(Mutations,f'test_operand_{model}_{j}_{bit}',make(model,a,bit))

if __name__=='__main__':unittest.main()
"""Stage56 synthetic ROM-free FSM selector tests. No vendor ROM bytes.

Static byte-matrix data cannot establish runtime callback execution,
GUI staging pointer lifetime, working codec Main10 or 4K60 sensor readout.
"""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage56_fsm_20b_group4_to_13_selector as s
import audit_stage55_recorder_20b_fsm_lifecycle as base


def movh(value,reg,high):
    half=((value>>16) if high else value)&0xffff
    return (0xe3400000 if high else 0xe3000000) | (reg<<12) | ((half>>12)<<16) | (half&0xfff)

def bl(site,target):
    assert (target-site-8)%4==0
    return 0xeb000000|(((target-site-8)//4)&0xffffff)

def artificial(m):
    sp=s.SPECS[m]; b=base.SPECS[m];rt=base.ROUTES[m]
    w={
      sp.evt_ptr_table+4*4:sp.group4_evt_table,
      sp.evt_ptr_table+4*13:sp.group13_evt_table,
      rt.ptr_table+4*4:sp.group4_fn_table,
      rt.ptr_table+13*4:sp.group13_fn_table,
      sp.group13_fn_table+4*4:sp.group13_handler,
      sp.group13_fn_table+4*2:sp.group13_index2_stub,
      sp.group13_state_setter+8:movh(b.state_global,3,False),
      sp.group13_state_setter+12:movh(b.state_global,3,True),
      sp.group13_state_setter+16:0xe5c30000,
      sp.group13_state_setter+20:0xe1c310b2,
      sp.group13_state_setter+24:bl(sp.group13_state_setter+24,sp.classifier),
      sp.class_check-8:movh(b.state_global,3,False),
      sp.class_check-4:movh(b.state_global,3,True),
      sp.class_check:0xe5d33000,
      sp.class_check+4:0xe3530000,
    }
    for site,immed in ((sp.call_a9,0xa9),(sp.call_102,0x102)):
        w[site-8]=0xe3a01000|immed if immed==0xa9 else 0xe3001000|immed
        w[site-4]=0xe3a00001
        w[site]=bl(site,sp.group13_state_setter)
    widths={sp.width_table+2*4:7,sp.width_table+2*13:5}
    bts={}
    for col,i in enumerate((8,9,10,2,11,12,13)):
        at=sp.group4_evt_table+(5*7+col)*2
        bts[at]=i;bts[at+1]=1
    bts[sp.group13_evt_table]=2
    bts[sp.group13_evt_table+1]=1
    bts[sp.group13_evt_table+10]=4
    bts[sp.group13_evt_table+11]=1
    c={
       'setter':('DAT_%08x = param_1; _DAT_%08x = param_2; FUN_%08x();'%
                 (b.state_global,b.state_global+2,sp.classifier)),
       'cls':(("if (DAT_%08x == " + chr(39) + chr(92) + "x01" + chr(39) +
               ") _DAT_%08x = 1; FUN_%08x(0xd);")%
              (b.state_global,sp.group13_status,rt.dispatcher)),
       'caller':('FUN_%08x(1,0xa9);'%sp.group13_state_setter),
       'receiver':('FUN_%08x(1,0x102);'%sp.group13_state_setter),
       'rc':('if (_DAT_%08x == 0x200) { } else { _DAT_%08x = 5; }'
             ' FUN_%08x(4);'%(sp.desc_status_type,sp.group4_status,rt.dispatcher))
    }
    return {'w':w,'width':widths,'byte':bts,'c':c}

def evaluate(sp,one,part):
    if part=='layout':
        return s.group_layout(sp,one['w'].__getitem__,one['byte'].__getitem__,one['width'].__getitem__)
    if part=='setter':
        c=one['c']
        return s.status_setter(sp,one['w'].__getitem__,c['caller'],c['setter'],c['cls'],c['receiver'])
    if part=='receiver':
        return s.receiver_classifier(sp,one['c']['rc'])
    raise AssertionError(part)

class PositiveSynthetic(unittest.TestCase):
    def test_both_models_all_boundaries(self):
        for m,sp in s.SPECS.items():
            for part in ('layout','setter','receiver'):
                with self.subTest(model=m,group=part):
                    result=evaluate(sp,artificial(m),part)
                    self.assertTrue(result)
    def test_synthetic_selector_row1_column0(self):
        for m,sp in s.SPECS.items():
            f=artificial(m)
            row=1;column=0;width=5
            fnidx=f['byte'][sp.group13_evt_table+2*(row*width+column)]
            self.assertEqual(fnidx,4)
            self.assertEqual(f['w'][sp.group13_fn_table+4*fnidx],sp.group13_handler)
            self.assertNotEqual(f['w'][sp.group13_fn_table+2*4],sp.group13_handler)
    def test_synthetic_group4_row5_callbacks_not_controller(self):
        for m,sp in s.SPECS.items():
            f=artificial(m)
            indices=[f['byte'][sp.group4_evt_table+2*(5*7+col)] for col in range(7)]
            self.assertNotIn(4,indices)
            self.assertEqual(indices,[8,9,10,2,11,12,13])
    def test_synthetic_guard_a9_vs_102(self):
        for m,sp in s.SPECS.items():
            out=evaluate(sp,artificial(m),'setter')
            self.assertTrue(out['state1_A9_allows_stub_ne_0x102_check'])
            self.assertTrue(out['state1_102_forces_stub_fast_return'])
            self.assertFalse(out['A9_caller_always_follows_received_20B'])

class NegativeSynthetic(unittest.TestCase):pass

for m,sp in s.SPECS.items():
    rt=base.ROUTES[m]
    word_sites=[sp.evt_ptr_table+4*4,sp.evt_ptr_table+4*13,
       rt.ptr_table+4*4,rt.ptr_table+13*4,sp.group13_fn_table+16,
       sp.group13_fn_table+8,
       sp.group13_state_setter+8,sp.group13_state_setter+12,
       sp.group13_state_setter+16,sp.group13_state_setter+20,
       sp.group13_state_setter+24,
       sp.class_check-8,sp.class_check-4,sp.class_check,sp.class_check+4,
       sp.call_a9-8,sp.call_a9-4,sp.call_a9,
       sp.call_102-8,sp.call_102-4,sp.call_102]
    for n,at in enumerate(word_sites):
        part='layout' if n<6 else 'setter'
        def make(model,at,part):
            def test(self):
                sp=s.SPECS[model];f=artificial(model)
                f['w'][at]^=1
                with self.assertRaises(ValueError):evaluate(sp,f,part)
            return test
        setattr(NegativeSynthetic,f'test_word_{m}_{n:02d}',make(m,at,part))
    for col in range(7):
        for ext in (0,1):
            a=sp.group4_evt_table+2*(5*7+col)+ext
            def make(model,a):
                def test(self):
                    f=artificial(model);f['byte'][a]^=1
                    with self.assertRaises(ValueError):evaluate(s.SPECS[model],f,'layout')
                return test
            setattr(NegativeSynthetic,f'test_row5_byte_{m}_{col}_{ext}',make(m,a))
    for i,a in enumerate((sp.group13_evt_table,sp.group13_evt_table+1,
                          sp.group13_evt_table+10,sp.group13_evt_table+11)):
        def make(model,a):
            def test(self):
                f=artificial(model);f['byte'][a]^=1
                with self.assertRaises(ValueError):evaluate(s.SPECS[model],f,'layout')
            return test
        setattr(NegativeSynthetic,f'test_row13_byte_{m}_{i}',make(m,a))
    for which in (4,13):
        a=sp.width_table+which*2
        def make(model,a):
            def test(self):
                f=artificial(model);f['width'][a]^=1
                with self.assertRaises(ValueError):evaluate(s.SPECS[model],f,'layout')
            return test
        setattr(NegativeSynthetic,f'test_width_{m}_{which}',make(m,a))
    for i,(field,token) in enumerate((
        ('setter',' = param_1;'),('setter',' = param_2;'),
        ('setter',f'FUN_{sp.classifier:08x}();'),
        ('cls',f'DAT_{base.SPECS[m].state_global:08x}'),
        ('cls',f'_DAT_{sp.group13_status:08x} = 1;'),
        ('cls',f'FUN_{rt.dispatcher:08x}(0xd);'),
        ('caller','(1,0xa9)'),('receiver','(1,0x102)'),
        ('rc',f'_DAT_{sp.desc_status_type:08x} == 0x200'),
        ('rc',f'_DAT_{sp.group4_status:08x} = 5;'),
        ('rc',f'FUN_{rt.dispatcher:08x}(4);'))):
        def make(model,field,token):
            def test(self):
                f=artificial(model)
                self.assertIn(token,f['c'][field])
                f['c'][field]=f['c'][field].replace(token,'CORRUPT')
                part='receiver' if field=='rc' else 'setter'
                with self.assertRaises(ValueError):evaluate(s.SPECS[model],f,part)
            return test
        setattr(NegativeSynthetic,f'test_bad_C_{m}_{i:02d}',make(m,field,token))
    def change_table_to_same(model):
        def test(self):
            sp=s.SPECS[model]; f=artificial(model)
            f['w'][base.ROUTES[model].ptr_table+16]=sp.group13_fn_table
            with self.assertRaises(ValueError):evaluate(sp,f,'layout')
        return test
    setattr(NegativeSynthetic,'test_group4_13_same_'+m,change_table_to_same(m))

if __name__=='__main__':unittest.main()
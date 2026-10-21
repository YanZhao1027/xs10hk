"""ROM-free Stage51 synthetic-only A32, pointer, mode-table and negative tests.

The vendor Section1/2 and proprietary Ghidra excerpts are never bundled in
this test source. Original validation is a separate offline audit.
"""
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage51_direct_mode_flag_table as s


def mov_half(value,reg=12,high=False):
    v=(value>>16) if high else value
    v&=0xffff
    return (0xe3400000 if high else 0xe3000000)|(reg<<12)|((v>>12)<<16)|(v&0xfff)

def bl(site,target):
    return 0xeb000000|(((target-site-8)//4)&0xffffff)

def toy_pointer(name):
    p=s.SPECS[name]
    words={}
    base=s.st31.SPECS[name].descriptor+0x3000
    for i,(origin,literal,bladdr) in enumerate([
             (p.first_ldr_base,p.first_literal,p.mode_call_site),
             (p.second_ldr_base,p.second_literal,p.mode_call_site2)]):
        words[origin]=0xe59f3000 | (literal-origin-8)
        words[literal]=base
        ops=[0xe5931ac4,0xe5d1006c,0xe5d12581 if i==0 else 0xe5d13581,
             0xe3520001 if i==0 else 0xe3530001,
             0x03500007,0x03a02001 if i==0 else 0x03a03001,
             0x13a02000 if i==0 else 0x13a03000,
             0xe3520000 if i==0 else 0xe3530000]
        words.update({origin+4+4*j:w for j,w in enumerate(ops)})
        words[origin+(0x24 if i==0 else 0x30)]=0x13a00006
        words[bladdr]=bl(bladdr,p.wrapper)
    c=("if (*(char *)(iVar8 + 0x581) == '\\x01' && "
       "*(char *)(iVar8 + 0x6c) == '\\a' && "
       "*(int *)(DAT_MOCK + 0xac4)) { cVar2 = '\\x06'; } "
       "FUN_%08x(cVar2,0,0,0);" %p.wrapper)
    return words,c


def toy_table():
    # Deliberately synthetic row contents; not actual Fujifilm ROM bytes.
    rows=[]
    for i in range(48):
        r=bytearray([6 if i<30 else 7,55,0xe0,37,0xe1,38,0x77,0x88,0x99,0xaa])
        rows.append(r)
    rows[3][0]=6;rows[3][2]=6;rows[3][4]=0xff;rows[3][6]=2
    rows[18][0]=7;rows[18][2]=6;rows[18][4]=0xff;rows[18][6]=3
    rows[19][0]=7;rows[19][2]=6;rows[19][4]=0xff;rows[19][6]=2
    # Two newly introduced class7 examples require two class7->class6
    # compensating rows to preserve synthetic 30/18 group counts.
    for i in (30,31): rows[i][0]=6
    return b''.join(rows)


def toy_map(name):
    p=s.SPECS[name]
    words={
        p.lookup+12:mov_half(p.table),
        p.lookup+16:mov_half(p.table,high=True),
        p.lookup+20:0xe3a00000,
        p.lookup+28:0xe2800001,
        p.lookup+32:0xe28cc00a,
        p.lookup+36:0xe3500030,
        p.wrapper+8:bl(p.wrapper+8,p.lookup),
        p.wrapper+12:0xe350002f,
        p.wrapper+16:0x98bd8800,
        p.wrapper+20:0xeafffffe,
    }
    table=toy_table()
    c='''while(pbVar2[6] != param_4 || pbVar2[2] != 0xff || pbVar2[4] != 0xff){\n pbVar2 = pbVar2 + 10; if (iVar1 == 0x30) return;\n}'''
    wrapper='FUN_%08x(); if (uVar1 < 0x30) return;'%p.lookup
    return words,table,c,wrapper

class StaticRules(unittest.TestCase):
    def test_choose_mode_only_7_and_1(self):
        for mode in range(9):
            for flag in (0,1,2,3,0xff):
                self.assertEqual(s.choose_mode(mode,flag),6 if mode==7 and flag==1 else mode)
    def test_input_type_rejections(self):
        for bad in (-1,256,1.0,None,'1',True):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):s.choose_mode(bad,1)
                with self.assertRaises(ValueError):s.choose_mode(7,bad)
    def test_synthetic_lookup(self):
        t=toy_table()
        self.assertEqual(len(t),480)
        self.assertEqual(s.table_lookup(t,7,6,17,2),19)
        self.assertEqual(s.table_lookup(t,s.choose_mode(7,1),6,17,2),3)
        self.assertEqual(s.table_lookup(t,7,6,17,3),18)
        self.assertIsNone(s.table_lookup(t,6,6,17,3))
    def test_lookup_invalid_size_and_keys(self):
        for t in (b'',b'0',b'0'*479,b'0'*481):
            with self.assertRaises(ValueError):s.table_lookup(t,1,1,1,1)
        for key in (-1,256,'1',1.5,None,True):
            with self.assertRaises(ValueError):s.table_lookup(toy_table(),7,key,0,2)
    def test_model_pointer_roots(self):
        for p in s.SPECS.values():
            self.assertEqual(s.st31.SPECS[p.name].descriptor+0x3000+0xac4,p.phase50_slot)
    def test_positive_pointer_two_read_sites(self):
        for model,p in s.SPECS.items():
            w,c=toy_pointer(model)
            self.assertEqual(s.check_pointer_gate(p,w.__getitem__,c,c),2)
    def test_positive_synthetic_row_table(self):
        for model,p in s.SPECS.items():
            w,tab,mc,wc=toy_map(model)
            with patch.object(s,'TABLE_SHA',hashlib.sha256(tab).hexdigest()):
                x=s.check_lookup(p,w.__getitem__,tab,mc,wc)
                self.assertEqual(x['mode7_aux2_example_index_when_flag1'],3)
                self.assertFalse(x['same_rows_prove_XS10_specific_permission'])
    def test_scan_counts(self):
        for p in s.SPECS.values():
            sample=('ST51_SLOT=%08x xrefs=777 functions=%d\n'
                    'ST51_SUMMARY slot=%08x decompiled=%d with_helper=%d possible=%d')%(
                p.phase50_slot,p.stage51_slot_decompiled,p.phase50_slot,
                p.stage51_slot_decompiled,p.stage51_slot_helper_count,p.stage51_slot_candidate_count)
            self.assertFalse(s.verify_slot_scan(p,sample)['first_P_plus_581_writer_identified'])

class FaultInjection(unittest.TestCase):pass

for model,p in s.SPECS.items():
    for i in range(2):
        for j in range(8):
            def case(model,i,j):
                def test(self):
                    w,c=toy_pointer(model); spec=s.SPECS[model]
                    root=spec.first_ldr_base if i==0 else spec.second_ldr_base
                    w[root+4+4*j]^=1
                    with self.assertRaisesRegex(ValueError,'gate'):
                        s.check_pointer_gate(spec,w.__getitem__,c,c)
                return test
            setattr(FaultInjection,'test_bad_gate_%s_%d_%02d'%(model,i,j),case(model,i,j))
    for i in range(2):
        def case(model,i):
            def test(self):
                w,c=toy_pointer(model);p=s.SPECS[model]
                root=p.first_ldr_base if i==0 else p.second_ldr_base
                w[root]^=4
                with self.assertRaisesRegex(ValueError,'PC literal'):
                    s.check_pointer_gate(p,w.__getitem__,c,c)
            return test
        setattr(FaultInjection,'test_wrong_literal_offset_%s_%d'%(model,i),case(model,i))
        def case2(model,i):
            def test(self):
                w,c=toy_pointer(model);p=s.SPECS[model]
                target=p.first_literal if i==0 else p.second_literal
                w[target]^=8
                with self.assertRaisesRegex(ValueError,'PC literal is not'):
                    s.check_pointer_gate(p,w.__getitem__,c,c)
            return test
        setattr(FaultInjection,'test_wrong_literal_value_%s_%d'%(model,i),case2(model,i))
    for key in ('0x581','0x6c',"'\\a'","'\\x01'","'\\x06'",' + 0xac4'):
        def case(model,key):
            def test(self):
                w,c=toy_pointer(model);p=s.SPECS[model]
                with self.assertRaisesRegex(ValueError,'Ghidra C'):
                    s.check_pointer_gate(p,w.__getitem__,c.replace(key,'NA'),c)
            return test
        setattr(FaultInjection,'test_missing_C_%s_%s'%(model,key.encode().hex()),case(model,key))
    for site in ('mode_call_site','mode_call_site2'):
        def case(model,site):
            def test(self):
                w,c=toy_pointer(model);p=s.SPECS[model]
                w[getattr(p,site)]^=1
                with self.assertRaisesRegex(ValueError,'BL'):
                    s.check_pointer_gate(p,w.__getitem__,c,c)
            return test
        setattr(FaultInjection,'test_wrong_BL_%s_%s'%(model,site),case(model,site))
    for k in (12,16,20,28,32,36):
        def case(model,k):
            def test(self):
                w,table,mc,wc=toy_map(model);p=s.SPECS[model]
                w[p.lookup+k]^=1
                with patch.object(s,'TABLE_SHA',hashlib.sha256(table).hexdigest()):
                    with self.assertRaises(ValueError):s.check_lookup(p,w.__getitem__,table,mc,wc)
            return test
        setattr(FaultInjection,'test_corrupt_mapper_%s_%d'%(model,k),case(model,k))
    for k in (8,12,16,20):
        def case(model,k):
            def test(self):
                w,table,mc,wc=toy_map(model);p=s.SPECS[model]
                w[p.wrapper+k]^=1
                with patch.object(s,'TABLE_SHA',hashlib.sha256(table).hexdigest()):
                    with self.assertRaises(ValueError):s.check_lookup(p,w.__getitem__,table,mc,wc)
            return test
        setattr(FaultInjection,'test_corrupt_wrapper_%s_%d'%(model,k),case(model,k))
    for i in (3,18,19,30):
        def case(model,i):
            def test(self):
                w,table,mc,wc=toy_map(model);p=s.SPECS[model]
                z=bytearray(table);z[i*10+(0 if i==30 else 6)]^=1
                with patch.object(s,'TABLE_SHA',hashlib.sha256(z).hexdigest()):
                    with self.assertRaises(ValueError):s.check_lookup(p,w.__getitem__,bytes(z),mc,wc)
            return test
        setattr(FaultInjection,'test_corrupt_table_%s_%d'%(model,i),case(model,i))
    for wordpart in ('pbVar2[6]','pbVar2[2]','pbVar2[4]','pbVar2 = pbVar2 + 10','iVar1 == 0x30'):
        def case(model,wordpart):
            def test(self):
                w,t,mc,wc=toy_map(model);p=s.SPECS[model]
                with patch.object(s,'TABLE_SHA',hashlib.sha256(t).hexdigest()):
                    with self.assertRaises(ValueError):s.check_lookup(p,w.__getitem__,t,mc.replace(wordpart,'WRONG'),wc)
            return test
        setattr(FaultInjection,'test_mapper_C_%s_%s'%(model,wordpart.encode().hex()),case(model,wordpart))

if __name__=='__main__':unittest.main()
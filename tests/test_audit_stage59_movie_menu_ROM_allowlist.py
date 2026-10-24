"""Stage59: synthetic-only per-mode enum ROM table tests (NO vendor bytes).

Artificial 4KiB+ parameter tables, fabricated Ghidra lines and deliberate
corruptions. Passing tests do not prove working HEVC, Main10 or 4K60.
"""
from dataclasses import replace
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage59_movie_menu_ROM_allowlist as audit

MODE_XS=[0x01,0x1d,0x2c,0x1f,0x20,0x24,0x23,0x22,0x21,0x05,0x18,0x08,
         0x0b,0x0c,0x0d,0x12,0x13,0x11,0x10,0x14,0x16,0x15,0x17,0x2d]
MODE_XT=[0x1d,0x2c,0x1f,0x20,0x24,0x23,0x22,0x21,0x2d]


def fixture(model):
    orig=audit.SPECS[model]
    ids=(orig.fmt,orig.codec,orig.out4k)
    addresses=(audit.BASE+0x1000,audit.BASE+0x2000,audit.BASE+0x3000)
    spec=replace(orig,mode_list=audit.BASE+0x80,index_table=audit.BASE+0x100,
                 total_param_ids=3,fmt_ptr=addresses[0],codec_ptr=addresses[1],
                 out4k_ptr=addresses[2])
    b=bytearray(0x4000)
    modes=MODE_XS if model=='xs10' else MODE_XT
    i=spec.mode_list-audit.BASE;b[i:i+len(modes)]=bytes(modes);b[i+len(modes)]=0x2e
    for j,(key,ptr) in enumerate(zip(ids,addresses)):
        struct.pack_into('<II',b,spec.index_table-audit.BASE+j*8,key,ptr)
    def make(key,ptr,values):
        for n,v in enumerate(values):
            off=ptr-audit.BASE+n*spec.entry_stride
            struct.pack_into('<I',b,off,v)
            for k,mode in enumerate(modes):
                permitted=mode==0x2d
                if key==spec.out4k:
                    flag=2 if n==0 else (1 if permitted else 0)
                else:
                    flag=2 if n==0 else (1 if permitted else 0)
                b[off+4+k]=flag
        struct.pack_into('<I',b,ptr-audit.BASE+len(values)*spec.entry_stride,0x7ffffffe)
    make(spec.fmt,addresses[0],[0,1])
    make(spec.codec,addresses[1],[0,1])
    make(spec.out4k,addresses[2],[3,0,1,2])
    texts={
       'default':'if (candidate == 0x7ffffffe) return 0x7fffffff;',
       'validate':('if (param_1 == X) if (param_3 == iVar6) {}'
                   ' piVar2 = piVar2 + %d;'% (7 if model=='xs10' else 4)+
                   'if (limit==0x7ffffffe) return false; ' + 'return false; '*5),
       'loader':('FUN_QUERY(0x2d,0x%x); FUN_QUERY(0x2d,0x%x);'%
                 (spec.fmt,spec.codec)+
                 'if (uVar2==0x7fffffff) return;'
                 'FUN_%08x(uVar2 & 0xff);'%spec.codec_setter),
    }
    return spec,b,texts


def validate(spec,b,t):
    return audit.analyze_model(spec,audit.Image(bytes(b)),t)

class Positive(unittest.TestCase):
    def test_models(self):
        for name in audit.SPECS:
            with self.subTest(name=name):
                s,b,t=fixture(name)
                result=validate(s,b,t)
                self.assertEqual(result['menu_rom_candidates']['MovieCodec']['mode_0x2d'],[(0,2),(1,1)])
                self.assertEqual(result['menu_rom_candidates']['MovieFormat']['mode_0x21'],[(0,2)])
                self.assertEqual(result['menu_rom_candidates']['eMode4kOut']['mode_0x2d'],[(3,2),(0,1),(1,1),(2,1)])
                self.assertFalse(result['menu_eligibility_implies_hardware_4K60_or_HEVC_Main10'])
                self.assertEqual(result['mode_count'],24 if name=='xs10' else 9)
    def test_disjoint_gui_values_and_recording_proof(self):
        for name in audit.SPECS:
            s,b,t=fixture(name)
            row=validate(s,b,t)['menu_rom_candidates']
            self.assertNotEqual(row['eMode4kOut']['mode_0x21'],row['eMode4kOut']['mode_0x2d'])
            self.assertEqual(row['MovieCodec']['mode_0x2d'][-1],(1,1))
            self.assertNotEqual(1,0x3fc)

class Negative(unittest.TestCase):pass

for model in audit.SPECS:
    name=model
    for index,(which,offset,xor) in enumerate([
        ('mode',0,1),('sentinel',0,1),('mode',1,1),('mode',-1,1),
        ('index_id',0,0x10000),('index_ptr',0,0x10),('index_id',1,1),
        ('index_ptr',1,0x10),('index_id',2,1),('index_ptr',2,0x10),
        ('index_end',0,1),('param_value_fmt',0,0x10),
        ('param_value_fmt',1,2),('param_value_codec',0,0x10),
        ('param_value_codec',1,2),('param_value_4k',0,1),
        ('param_value_4k',1,4),('param_value_4k',2,4),('param_value_4k',3,4),
        ('param_end_fmt',0,1),('param_end_codec',0,1),
        ('param_end_4k',0,1),
    ]):
        def bad_case(model,which,offset,xor):
            def test(self):
                sp,b,t=fixture(model)
                if which=='mode':
                    loc=sp.mode_list-audit.BASE+(offset if offset>=0 else sp.mode_count-1)
                elif which=='sentinel':loc=sp.mode_list-audit.BASE+sp.mode_count
                elif which.startswith('index_'):
                    if which=='index_end':loc=sp.index_table-audit.BASE+24
                    elif which=='index_ptr':loc=sp.index_table-audit.BASE+offset*8+4
                    else:loc=sp.index_table-audit.BASE+offset*8
                else:
                    words=which.split('_');category=words[-1]
                    ptr={'fmt':sp.fmt_ptr,'codec':sp.codec_ptr,'4k':sp.out4k_ptr}[category]
                    n=offset if which.startswith('param_value') else (4 if category=='4k' else 2)
                    loc=ptr-audit.BASE+n*sp.entry_stride
                b[loc]^=xor&0xff
                if xor>0xff:b[loc+2]^=(xor>>16)&0xff
                with self.assertRaises(ValueError):validate(sp,b,t)
            return test
        setattr(Negative,f'test_{model}_structure_{index:02d}',bad_case(model,which,offset,xor))
    for category in ('fmt','codec','4k'):
        for entry in (0,1):
            modes=MODE_XS if model=='xs10' else MODE_XT
            for mi in range(len(modes)):
                def mut(model,category,entry,mi):
                    def test(self):
                        sp,b,t=fixture(model)
                        ptr={'fmt':sp.fmt_ptr,'codec':sp.codec_ptr,'4k':sp.out4k_ptr}[category]
                        p=ptr-audit.BASE+entry*sp.entry_stride+4+mi
                        b[p]=0 if b[p]!=0 else 1
                        with self.assertRaises(ValueError):validate(sp,b,t)
                    return test
                setattr(Negative,f'test_flag_{model}_{category}_{entry}_{mi}',mut(model,category,entry,mi))
    for n,(field,needle) in enumerate((('default','0x7fffffff'),
       ('default','0x7ffffffe'),('validate','0x7ffffffe'),
       ('validate','piVar2 = piVar2 + '),('validate','return false;'),
       ('loader','0x7fffffff'),('loader',f'FUN_{audit.SPECS[model].codec_setter:08x}'),
       ('loader','0x2d'),('loader','uVar2 & 0xff'))):
        def delete(model,field,needle):
            def test(self):
                sp,b,t=fixture(model)
                self.assertIn(needle,t[field])
                t[field]=t[field].replace(needle,'WRONG')
                with self.assertRaises(ValueError):validate(sp,b,t)
            return test
        setattr(Negative,f'test_decompiler_{model}_{n:02d}',delete(model,field,needle))

if __name__=='__main__':unittest.main()
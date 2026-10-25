"""Stage63 synthetic-only counterexample tests: correct eMovieFps vs eContMode.

All code/data are fabricated toy ROM, ARM BL, and Ghidra snippet strings.
No original ROM, firmware payloads, decompilation logs or physical images.
"""
from dataclasses import replace
from pathlib import Path
import struct,sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage63_real_movie_fps_menu_eligibility as mod
import audit_stage59_movie_menu_ROM_allowlist as s59

BASE=mod.BASE

def arm_bl(src,dst):
    assert (dst-src-8)%4==0
    return 0xeb000000|(((dst-src-8)//4)&0xffffff)

def fixture(model):
    source=mod.SPECS[model]
    bs=replace(s59.SPECS[model],mode_list=BASE+0x100,index_table=BASE+0x200,
               total_param_ids=1)
    s=replace(source,table_ptr=BASE+0x600,enum_name60_addr=BASE+0x3000,
              setter=BASE+0x4000,input_setter_bl=BASE+0x3800)
    image=bytearray(0x4700)
    modes=s59.MODE_LISTS[model]
    image[0x100:0x100+len(modes)]=bytes(modes)
    struct.pack_into('<II',image,0x200,s.param_id,s.table_ptr)
    vals=mod.EXPECTED_VALUES
    for k,v in enumerate(vals):
        at=s.table_ptr-BASE+k*bs.entry_stride
        struct.pack_into('<I',image,at,v)
        for i,mode in enumerate(modes):
            if mode==0x2d:
                flag=2 if (k==4) else (1 if (v in mod.EXPECTED_MOVIE_2D and k not in (5,8)) else 0)
            elif mode==0x21:
                flag=2 if k==4 else 0
            else:flag=2 if k==4 else 0
            image[at+4+i]=flag
    struct.pack_into('<I',image,s.table_ptr-BASE+len(vals)*bs.entry_stride,0x7ffffffe)
    image[s.enum_name60_addr-BASE:s.enum_name60_addr-BASE+12]=b'MODE_FPS_60\x00'
    if model=='xs10':
        check=f'FUN_010253a4(0x2d,0x{s.param_id:x},uVar3)'
        fallback=f'FUN_010253b4(0x2d,0x{s.param_id:x})'
    else:
        check=f'FUN_01025504(0x2d,0x{s.param_id:x},uVar3)'
        fallback=f'FUN_01025514(0x2d,0x{s.param_id:x})'
    fake={
      'converter':'if (param_1 == 6) return s_MODE_FPS_60_; if (param_1 == 5) return s_MODE_FPS_50_;',
      'setter':f'DAT_{s.setter_RAM_addr:08x} = (char)param_1; s__INPUT_eMovieFps_',
      'parent':f'{check}; {fallback}; FUN_{s.setter:08x}(uVar3 & 0xff); if (v==0x7fffffff) return;',
      'econt':'s__INPUT_eContMode_',
      'BL_word':arm_bl(s.input_setter_bl,s.setter),
    }
    return {'spec':s,'base':bs,'image':image,'fake':fake}

def check(f,part):
    s=f['spec'];img=s59.Image(bytes(f['image']))
    if part=='rom':return mod.eligible(s,f['base'],img)
    if part=='ghidra':
        z=f['fake']
        return mod.ghidra(s,z['converter'],z['setter'],z['parent'],
                          z['econt'],lambda addr:z['BL_word'])
    raise ValueError(part)

class Positive(unittest.TestCase):
    def test_models_in_real_menu(self):
        for m in mod.SPECS:
            with self.subTest(model=m):
                f=fixture(m)
                self.assertEqual(check(f,'rom')['MODE_FPS_60_numeric_enum'],6)
                self.assertEqual(check(f,'rom')['allowed_menu_enums_mode0x2D'],list(mod.EXPECTED_MOVIE_2D))
                self.assertTrue(check(f,'ghidra')['real_fps_validator_and_fallback_mode0x2D'])
    def test_first_matching_duplicates_not_last_row(self):
        for model in mod.SPECS:
            f=fixture(model)
            s=f['spec'];bs=f['base']
            # second occurrence of value6 deliberately disabled on mode2D
            key=8;mi=s59.MODE_LISTS[model].index(0x2d)
            ptr=s.table_ptr-BASE+key*bs.entry_stride+4+mi
            self.assertEqual(f['image'][ptr],0)
            self.assertIn(6,check(f,'rom')['allowed_menu_enums_mode0x2D'])
    def test_cross_model_original_like_flags_agree(self):
        f=fixture('xs10');g=fixture('xt4')
        def get(z):return mod.parse_rows(z['spec'],z['base'],s59.Image(bytes(z['image'])))
        self.assertTrue(mod.check_cross_model([get(f),get(g)]))
    def test_no_4k60_or_main10_from_menu(self):
        for m in mod.SPECS:
            f=fixture(m)
            self.assertFalse(check(f,'rom')['any_confirmed_4K59_94_joint_recorder_state'])
            self.assertFalse(check(f,'ghidra')['movie_FPS_enum6_means_real_3840x2160_plus_59_94_recording'])

class Negative(unittest.TestCase):pass

for model in mod.SPECS:
    for j in range(len(mod.EXPECTED_VALUES)):
        def corrupt_value(m,j):
            def test(self):
                f=fixture(m);at=f['spec'].table_ptr-BASE+j*f['base'].entry_stride
                f['image'][at]^=0x40
                with self.assertRaises(ValueError):check(f,'rom')
            return test
        setattr(Negative,f'test_bad_record_{model}_{j}',corrupt_value(model,j))
        def corrupt_flag(m,j):
            def test(self):
                f=fixture(m);at=f['spec'].table_ptr-BASE+j*f['base'].entry_stride+4
                f['image'][at]=7
                with self.assertRaises(ValueError):check(f,'rom')
            return test
        setattr(Negative,f'test_bad_flag_{model}_{j}',corrupt_flag(model,j))
    for n,(part,shift) in enumerate((('id',0),('type',2),('ptr',4),('first_movie',0),
                                    ('first_21',0),('rom_label',0),('end',0),('mode',0))):
        def test_mutation(m,part):
            def test(self):
                f=fixture(m);s=f['spec'];bs=f['base'];b=f['image']
                if part=='id':off=0x200
                elif part=='type':off=0x202
                elif part=='ptr':off=0x204
                elif part=='first_movie':off=s.table_ptr-BASE+bs.entry_stride+4+s59.MODE_LISTS[m].index(0x2d)
                elif part=='first_21':off=s.table_ptr-BASE+bs.entry_stride*4+4+s59.MODE_LISTS[m].index(0x21)
                elif part=='rom_label':off=s.enum_name60_addr-BASE
                elif part=='end':off=s.table_ptr-BASE+len(mod.EXPECTED_VALUES)*bs.entry_stride
                else:off=0x100
                b[off]^=1
                with self.assertRaises(ValueError):check(f,'rom')
            return test
        setattr(Negative,f'test_mutate_menu_{model}_{n}',test_mutation(model,part))
    for n,(kind,token) in enumerate((('converter','param_1 == 6'),
               ('converter','s_MODE_FPS_60_'),('converter','param_1 == 5'),
               ('converter','s_MODE_FPS_50_'),
               ('setter','s__INPUT_eMovieFps_'),
               ('setter',f'DAT_{mod.SPECS[model].setter_RAM_addr:08x}'),
               ('parent','0x2d'),('parent','uVar3 & 0xff'),
               ('parent','0x7fffffff'),('econt','s__INPUT_eContMode_'),
            )):
        def corrupt_code(m,kind,token):
            def test(self):
                f=fixture(m)
                self.assertIn(token,f['fake'][kind]);f['fake'][kind]=f['fake'][kind].replace(token,'DAMAGE')
                with self.assertRaises(ValueError):check(f,'ghidra')
            return test
        setattr(Negative,f'test_bad_decomp_{model}_{n}',corrupt_code(model,kind,token))
    def corrupt_bl(m):
        def test(self):
            f=fixture(m);f['fake']['BL_word']^=1
            with self.assertRaises(ValueError):check(f,'ghidra')
        return test
    setattr(Negative,f'test_bad_bl_{model}',corrupt_bl(model))

for model in mod.SPECS:
    for v in sorted(set(mod.EXPECTED_VALUES)):
        def revoke(m,v,mode):
            def test(self):
                f=fixture(m);s=f['spec'];bs=f['base']
                mi=s59.MODE_LISTS[m].index(mode)
                pos=mod.EXPECTED_VALUES.index(v)
                off=s.table_ptr-BASE+pos*bs.entry_stride+4+mi
                f['image'][off]=0 if f['image'][off] else 1
                with self.assertRaises(ValueError):check(f,'rom')
            return test
        setattr(Negative,f'test_mode2d_changed_{model}_{v}',revoke(model,v,0x2d))
        setattr(Negative,f'test_mode21_changed_{model}_{v}',revoke(model,v,0x21))

for mode in (0x2d,0x21,0x1d,0x2c,0x1f,0x20,0x24,0x23,0x22):
    def mismatch(m):
        def test(self):
            f=fixture('xs10');g=fixture('xt4');s=g['spec'];bs=g['base']
            off=s.table_ptr-BASE+bs.entry_stride*1+4+s59.MODE_LISTS['xt4'].index(m)
            g['image'][off]=2 if g['image'][off] else 1
            a=mod.parse_rows(f['spec'],f['base'],s59.Image(bytes(f['image'])))
            b=mod.parse_rows(g['spec'],g['base'],s59.Image(bytes(g['image'])))
            with self.assertRaises(ValueError):mod.check_cross_model([a,b])
        return test
    setattr(Negative,f'test_common_mode_mismatch_{mode:02x}',mismatch(mode))

if __name__=='__main__':unittest.main()
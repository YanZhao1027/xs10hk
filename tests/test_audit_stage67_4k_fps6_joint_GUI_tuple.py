"""Synthetic-only Stage67: original four-key GUI->Movie mode tuple invariants.

All A32 words, enum names and 96-row LUTs are FAKE: no Fuji binary or ROM
fragments. These tests NEVER imply physical X-S10 4K60, Main10 or a patch.
"""
from pathlib import Path
import struct,sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage67_4k_fps6_joint_GUI_tuple as s


def synthetic_arm(sp):
    w={}
    for pair,ops in (
      (sp.low_pair,(0xe5d1306c,0xe5c03015)),
      (sp.high_pair,(0xe5d13070,0xe5c03016)),
      (sp.alt_low_pair,(0xe5d1306c,0xe5c03015)),
      (sp.alt_high_pair,(0xe5d12070,0xe5c02016)),
      (sp.bitrate_pair,(0xe5d53596,0xe5c43000|sp.bitrate_intermediate))):
        w.update(zip(pair,ops))
    return w


def synthetic_C(sp):
    p='char* pixel(int param_1){if(param_1 == 7) return s_MODE_PIXEL_4K_X; if(param_1 == 6) return s_MODE_PIXEL_FULLHD_X;}'
    aspect='char* aspect(int param_1){if(param_1 == 2) return s_MODE_ASPECT_WIDE_X; if(param_1 == 7) return s_MODE_ASPECT_17_9_X;}'
    bps='\n'.join(f'if (param_1 == {enum}) return s_MODE_BPS_{speed}_X;' for enum,speed in enumerate((50,100,200,400)))
    setters=[f's__INPUT_{label} DAT_{ram:08x} = (char)param_1;' for label,ram in (
       ('eaPixel_Movie',sp.pixel_ram),('eAspect',sp.aspect_ram),('eMovieBps',sp.bitrate_ram))]
    conv=''.join([
      '*(undefined1 *)(param_1 + 0x15) = param_2[0x6c];',
      '*(undefined1 *)(param_1 + 0x16) = param_2[0x70];',
      f'*(undefined1 *)(param_1 + 0x{sp.bitrate_intermediate:x}) = param_2[0x596];',
    ])
    HS='''case 1:
  case 4:
  case 5:
  case 6:
  case 7:
    return 0;
case 2:
  case 3:
    return 1;'''
    k4='''case 1:
  case 2:
  case 3:
    return 0;
case 4:
  case 5:
  case 6:
  case 7:
    return 1;'''
    c=(f'FUN_{sp.HS_class:08x}(cVar1);'
       f'FUN_{sp.is4k_class:08x}(cVar1);'
       f'FUN_{s.s66.s65.SPECS[sp.model].table_matcher:08x}(iVar8);'
       '0x12294) == 0) (iVar8 + 0xadd8) = 6;'
       '0xa8e) 0x5f5) = 0;')
    return [p,aspect,bps,*setters,conv,c,HS,k4]


def check_C(sp,C):
    return s.enum_names(sp,C[0],C[1],C[2],C[3],C[4],C[5],C[6],C[7],C[8],C[9])


def fake_lut(sp):
    m=s.s46.MODELS[sp.model];base=s.s32.MODELS[sp.model].sec2base
    one=bytearray(max(m.widths,m.heights)-s.s59.BASE+s.s46.DIM_BYTES)
    two=bytearray(m.movie_table-base+s.s46.RECORDS*s.s46.STRIDE+1)
    off=m.movie_table-base
    for i in range(s.s46.RECORDS):two[off+i*64]=3
    def write_row(i,klass,pixel,aspect,fps,bps):
        two[off+i*64:off+i*64+5]=bytes((klass,pixel,aspect,fps,bps))
    for aspect,bigstart,smallstart in ((7,15,52),(2,33,70)):
        for bps in (1,2,3):write_row(bigstart+bps-1,0,7,aspect,6,bps)
        for bps in (1,2):write_row(smallstart+bps-1,0,6,aspect,6,bps)
    two[off+s.s46.RECORDS*64]=0xff
    def dims(pixel,aspect,w,h):
        pos=(pixel*5+(aspect if aspect<=3 else 4))*4
        struct.pack_into('<I',one,m.widths-s.s59.BASE+pos,w)
        struct.pack_into('<I',one,m.heights-s.s59.BASE+pos,h)
    dims(7,2,3840,2160);dims(7,7,4096,2160)
    dims(6,2,1920,1080);dims(6,7,2048,1080)
    return one,two

class Good(unittest.TestCase):
    def test_original_arm_and_field_names(self):
        for sp in s.SPECS.values():
            with self.subTest(model=sp.model):
                self.assertTrue(s.original_arm(sp,synthetic_arm(sp).__getitem__))
                self.assertTrue(check_C(sp,synthetic_C(sp)))
    def test_original_ROM_free_four_key_4K_and_1080(self):
        for sp in s.SPECS.values():
            with self.subTest(model=sp.model):
                u,v=fake_lut(sp)
                ans=s.joint(sp,u,v)
                self.assertEqual(len(ans['six_2160p_fps6_with_bitrate_specific_GUI_tuple']),6)
                for j,row in enumerate(ans['six_2160p_fps6_with_bitrate_specific_GUI_tuple']):
                    self.assertEqual(row['class'],0)
                    self.assertEqual(row['bps_mbps'],(100,200,400)[j%3])
                    if row['bps_mbps']==400:self.assertIsNone(row['flag1_coerced_row'])
                    else:self.assertIsNotNone(row['flag1_coerced_row'])
    def test_4k_gate_selector_is_explicitly_conditional(self):
        for typ in range(1,8):
            class0=typ in (1,4,5,6,7)
            gated=typ in (4,5,6,7)
            for flag in (0,1,2):
                for lo in (6,7):
                    result=(6 if gated and flag==1 else lo)
                    reaches_2160=class0 and result==7
                    if gated and flag==1:self.assertFalse(reaches_2160)
                    if not class0:self.assertFalse(reaches_2160)
    def test_original_unknowns_stay_false(self):
        for sp in s.SPECS.values():
            b=s.joint(sp,*fake_lut(sp))
            self.assertFalse(b['actual_device_2160p_59_94fps_HEVC_Main10_joint_reachability_proven'])

class Bad(unittest.TestCase):pass

for name,sp in s.SPECS.items():
    for j,a in enumerate(sorted(synthetic_arm(sp))):
        for bit in (1,0x100):
            def mk(name,a,bit):
                def test(self):
                    sp=s.SPECS[name];w=synthetic_arm(sp);w[a]^=bit
                    with self.assertRaises(ValueError):s.original_arm(sp,w.__getitem__)
                return test
            setattr(Bad,f'test_wrong_A32_{name}_{j}_{bit}',mk(name,a,bit))
    for j in range(10):
        def mk(name,j):
            def test(self):
                sp=s.SPECS[name];c=synthetic_C(sp);c[j]='BROKEN'
                with self.assertRaises(ValueError):check_C(sp,c)
            return test
        setattr(Bad,f'test_wrong_GUI_name_or_cond_{name}_{j}',mk(name,j))
    for j,(aspect,bps) in enumerate(((2,1),(2,2),(2,3),(7,1),(7,2),(7,3))):
        def mk(name,aspect,bps):
            def test(self):
                sp=s.SPECS[name];x,y=fake_lut(sp)
                model=s.s46.MODELS[name];base=s.s32.MODELS[name].sec2base
                idx=(33 if aspect==2 else 15)+bps-1
                pos=model.movie_table-base+idx*64+4
                y[pos]=0
                with self.assertRaises(ValueError):s.joint(sp,x,y)
            return test
        setattr(Bad,f'test_break_one_4k_candidate_{name}_{j}',mk(name,aspect,bps))
    for j,key in enumerate(('WIDTH','HEIGHT','SENTINEL')):
        def mk(name,key):
            def test(self):
                sp=s.SPECS[name];x,y=fake_lut(sp)
                model=s.s46.MODELS[name];base=s.s32.MODELS[name].sec2base
                if key=='WIDTH':x[model.widths-s.s59.BASE+(7*5+2)*4+1]^=1
                elif key=='HEIGHT':x[model.heights-s.s59.BASE+(7*5+2)*4]=0
                else:y[model.movie_table-base+s.s46.RECORDS*64]=0
                with self.assertRaises(ValueError):s.joint(sp,x,y)
            return test
        setattr(Bad,f'test_break_dimensions_{name}_{j}',mk(name,key))

if __name__=='__main__':unittest.main()
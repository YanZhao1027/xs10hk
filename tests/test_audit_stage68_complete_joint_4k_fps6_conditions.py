"""Pure synthetic Phase68 conditional four-field menu and sensor-mode tests.

No original Fuji ROM bytes, real Ghidra logs, real sensor responses,
physical camera access, patches or HEVC bitstreams are used here.
"""
from dataclasses import dataclass
import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage68_complete_joint_4k_fps6_conditions as s

class FakeImage:
    def __init__(self):self.words={};self.spans={}
    def u32(self,addr):return self.words.get(addr,0)
    def bytes(self,addr,n):
        if (addr,n) not in self.spans:raise ValueError('missing synthetic span '+hex(addr))
        return bytes(self.spans[(addr,n)])

def fake_menu(spec):
    im=FakeImage();modes=list(s.s59.MODE_LISTS[spec.model]);i2d=modes.index(0x2d);i21=modes.index(0x21)
    im.spans[(spec.mode_list,spec.mode_count)]=modes
    im.spans[(spec.mode_list+spec.mode_count,1)]=[0x2e]
    keys=[spec.pixel,spec.aspect,spec.fps,spec.bps]
    for i in range(spec.index_count):
        key=keys[i] if i<4 else 0x1000+i
        ptr=0x05000000+i*0x1000
        im.words[spec.index_table+i*8]=key
        im.words[spec.index_table+i*8+4]=ptr
        if i<4:
            e=s.EXPECTED[s.FIELD_ORDER[i]]
            for j,value in enumerate(e['values']):
                addr=ptr+j*spec.stride
                flags=[0]*spec.mode_count
                flags[i2d]=e['mode2d'][j];flags[i21]=e['mode21'][j]
                im.words[addr]=value
                im.spans[(addr+4,spec.mode_count)]=flags
            im.words[ptr+len(e['values'])*spec.stride]=0x7ffffffe
    im.words[spec.index_table+spec.index_count*8]=0
    im.words[spec.index_table+spec.index_count*8+4]=0
    return im

def synthetic_sensor_rows():
    b=bytearray(36*16)
    for i in range(12):b[i*16]=i+1;b[i*16+10]=i%3+24
    j=12
    for ident,fps,count in s.SENSOR_EXPECTED:
        for _ in range(count):b[j*16]=ident;b[j*16+10]=fps;j+=1
    assert j==36
    return b

class Positive(unittest.TestCase):
    def test_fake_menu_both_rom_layouts(self):
        for m,sp in s.SPECS.items():
            with self.subTest(model=m):
                modes,result,_=s.parse_mode_image(fake_menu(sp),sp)
                self.assertEqual(len(modes),sp.mode_count)
                self.assertEqual(result['pixel']['mode_0x2D_allowed'],[7,6])
                self.assertEqual(result['aspect']['mode_0x2D_allowed'],[2,7])
                self.assertIn(6,result['fps']['mode_0x2D_allowed'])
                self.assertEqual(result['bps']['mode_0x2D_allowed'],[3,2,1,0])
                self.assertEqual(result['fps']['mode_0x21_allowed'],[4])
    def test_sensor_fake_36_rows(self):
        b=synthetic_sensor_rows()
        rows=s.decode_sensor_rows(b)
        self.assertEqual(len(rows),36)
        self.assertEqual([i for i,(ident,fps) in enumerate(rows) if ident in (97,102)],
                         [22,23,34,35])
    def test_mode2D_defaults_are_not_60fps(self):
        for sp in s.SPECS.values():
            _,r,_=s.parse_mode_image(fake_menu(sp),sp)
            self.assertEqual((r['pixel']['mode_0x2D_default'],r['aspect']['mode_0x2D_default'],
                              r['fps']['mode_0x2D_default'],r['bps']['mode_0x2D_default']),
                             (7,2,4,1))
    def test_conditional_mode_switch(self):
        for movie_type in range(1,8):
            for flag in (0,1,2,3):
                classv,pixel=s.movie_key(movie_type,flag)
                self.assertEqual(classv,0 if movie_type in (1,4,5,6,7) else (1 if movie_type==2 else 2))
                self.assertEqual(pixel,6 if movie_type in (4,5,6,7) and flag==1 else 7)
    def test_selector_nonzero_forces_bps200(self):
        for selector in (-1,1,2,255):
            self.assertEqual(s.runtime_tuple(selector,6,6,3,0),(6,2))
            self.assertEqual(s.runtime_tuple(selector,6,6,1,7),(4,2))
    def test_mode6_matrix_400_has_no_match(self):
        for aspect in (2,7):
            for bps in (1,2,3):
                self.assertEqual(s.static_joint_tuple(0,7,aspect,6,bps)[1],2160)
                fallback=s.static_joint_tuple(0,6,aspect,6,bps)
                self.assertEqual(fallback is None,bps==3)
    def test_opaque_dynamic_support_list(self):
        idxs=[22,23,34,35]
        ids=[0]*36
        for i in (22,23):ids[i]=97
        for i in (34,35):ids[i]=102
        self.assertIsNone(s.select_sensor_candidate(idxs,ids,set()))
        self.assertEqual(s.select_sensor_candidate(idxs,ids,{102}),34)
        self.assertEqual(s.select_sensor_candidate(idxs,ids,{97}),22)
        self.assertEqual(s.select_sensor_candidate(idxs,ids,set(),False),22)
    def test_no_GUImenu_joint_guarantee(self):
        for movie_type in (2,3,4,5,6,7):
            c,pixel=s.movie_key(movie_type,1)
            for aspect in (2,7):
                self.assertNotEqual((s.static_joint_tuple(c,pixel,aspect,6,2) or (0,0))[1],2160)

class Negative(unittest.TestCase):pass

# Each synthetic setting candidate, sentinel and mode-list mutation is rejected.
for model,sp in s.SPECS.items():
    for field_i,field in enumerate(s.FIELD_ORDER):
        e=s.EXPECTED[field]
        for j in range(len(e['values'])):
            for mode in ('2d','21'):
                def make(model,field_i,j,mode):
                    def test(self):
                        spec=s.SPECS[model];im=fake_menu(spec)
                        ptr=0x05000000+field_i*0x1000
                        loc=ptr+j*spec.stride+4
                        arr=im.spans[(loc,spec.mode_count)]
                        k=list(s.s59.MODE_LISTS[model]).index(0x2d if mode=='2d' else 0x21)
                        arr[k]=((arr[k]+1)%5)
                        with self.assertRaises(ValueError):s.parse_mode_image(im,spec)
                    return test
                setattr(Negative,f'test_bad_{model}_{field}_{j}_{mode}',make(model,field_i,j,mode))
    for what in ('missing_key','wrong_type','early_sentinel','late_sentinel','wrong_mode','bad_mode_term',
                 'candidate_deleted','no_candidate_term','candidate_invalid_flag'):
        def make(model,what):
            def test(self):
                sp=s.SPECS[model];im=fake_menu(sp)
                if what=='missing_key':im.words[sp.index_table]=0x2000
                elif what=='wrong_type':im.words[sp.index_table]=sp.pixel|(2<<16)
                elif what=='early_sentinel':im.words[sp.index_table+(sp.index_count-1)*8+4]=0
                elif what=='late_sentinel':im.words[sp.index_table+sp.index_count*8+4]=0x12345678
                elif what=='wrong_mode':im.spans[(sp.mode_list,sp.mode_count)][0]=0
                elif what=='bad_mode_term':im.spans[(sp.mode_list+sp.mode_count,1)]=[0xff]
                elif what=='candidate_deleted':im.words[0x05000000]=99
                elif what=='no_candidate_term':im.words[0x05000000+len(s.EXPECTED['pixel']['values'])*sp.stride]=10
                elif what=='candidate_invalid_flag':
                    loc=0x05000000+4
                    im.spans[(loc,sp.mode_count)][list(s.s59.MODE_LISTS[model]).index(0x2d)]=7
                with self.assertRaises((ValueError,KeyError)):
                    s.parse_mode_image(im,sp)
            return test
        setattr(Negative,f'test_bad_schema_{model}_{what}',make(model,what))

for i in range(12,36):
    def make(i):
        def test(self):
            x=synthetic_sensor_rows();x[i*16+10]^=1
            with self.assertRaises(ValueError):s.decode_sensor_rows(x)
        return test
    setattr(Negative,f'test_mutate_sensor_fps_{i}',make(i))

for i in range(12,36):
    def make(i):
        def test(self):
            x=synthetic_sensor_rows();x[i*16]^=1
            with self.assertRaises(ValueError):s.decode_sensor_rows(x)
        return test
    setattr(Negative,f'test_mutate_sensor_id_{i}',make(i))

for i,(c,p,a,f,b) in enumerate(((1,7,2,6,2),(2,7,7,6,1),(0,7,2,4,2),
                                 (0,7,7,6,0),(0,7,2,6,4),(0,7,1,6,2),
                                 (0,6,2,6,3),(0,6,7,6,3))):
    def make(c,p,a,f,b):
        def test(self):self.assertIsNone(s.static_joint_tuple(c,p,a,f,b))
        return test
    setattr(Negative,f'test_no_matching_2160_tuple_{i}',make(c,p,a,f,b))

if __name__=='__main__':unittest.main()
"""Phase75 entirely artificial clock-like u32 range/profile tests.

No Fuji original table rows/bytes, private Ghidra logs, real device MMIO,
USB/FF80, firmware patching or hardware throughput are used.
"""
import hashlib,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage75_video_clock_range_catchall as s


def fake_rows():
    arr=[]
    for i in range(14):
        low=1000+i*100
        arr.append((low,low+20,100+i,200+i,300+i))
    arr.append((0,0xffffffff,1000,2000,3000))
    return arr


def fake_table():
    return b''.join(struct.pack('<5I',*row) for row in fake_rows())


def fake_bl(a,target):
    assert (target-a-8)%4==0
    return 0xeb000000|(((target-a-8)//4)&0xffffff)


def artificial_section(spec):
    b=bytearray(max(spec.table_start+300,spec.literal_ptr+4,
             spec.word828_write+4,spec.BL+4)-s.s59.BASE)
    base=s.s59.BASE
    def W(a,v):struct.pack_into('<I',b,a-base,v)
    for i,(numer,denom) in enumerate(((1,1),(5,4),(3,2))):
        W(spec.ratio_start+8*i,numer);W(spec.ratio_start+8*i+4,denom)
    b[spec.table_start-base:spec.table_start-base+300]=fake_table()
    W(spec.literal_ptr,spec.table_start+4)
    W(spec.BL,fake_bl(spec.BL,spec.finalizer))
    W(spec.word828_read,0xe5900828)
    W(spec.word828_write,0xe5800828)
    return b


def fake_original_function(spec):
    c=('uVar3 = (*(uint *)(param_1 + 8) & 0x3ff) >> 8;\n'
       'a = *(uint *)(param_1 + 0xc) & 0xfffff;\n'
       'b = *(uint *)(param_1 + 0x50) & 0xfffff;\n'
       'c = *(uint *)(param_1 + 0x4b0) & 0xfffffff;\n'
       f'puVar2 = DAT_{spec.literal_ptr:08x};\n'
       'while (uVar3 < puVar2[-1] || *puVar2 < uVar3) {\n'
       'iVar1 = iVar1 + 1;\npuVar2 = puVar2 + 5;\n'
       'if (iVar1 == 0xf) {return 0xffffffff;}}\n'
       'switch(mode) {\n'
       'case 0:\ncase 2:\ncase 3:\ncase 8:\ncase 10:\n'
       'case 0xc:\ncase 0xe:\ndefault: return 0xffffffff;\n}\n'
       '*(uint *)(param_1 + 0x828)=value;\nreturn 0;')
    builder=(f'FUN_{s.s73.SPECS[spec.model].marshaller:08x}(param_1,param_3);\n'
             f'uVar1 = FUN_{spec.finalizer:08x}(param_1);\n')
    return {spec.finalizer:c,spec.builder:builder}


def check_fake_function(spec,mutation=None):
    c=fake_original_function(spec)
    if mutation:
        addr,needle=mutation
        assert needle in c[addr],(hex(addr),needle)
        c[addr]=c[addr].replace(needle,'CORRUPTED')
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        (root/f'{spec.model}_stage75_finalizer_source_fields.log').write_text('TEST-ONLY DUMMY')
        (root/f'{spec.model}_stage73_driver_command_pack.log').write_text('TEST-ONLY DUMMY')
        with patch.object(s.s59,'function_c_any',side_effect=lambda _,a:c[a]):
            return s.original_function(spec,root)

class Positive(unittest.TestCase):
    def test_all_synthetic_valid_rows(self):
        self.assertEqual(s.rows_from_bytes(fake_table()),fake_rows())
        self.assertTrue(s.verify_shape(fake_rows()))
    def test_fallback_accepts_numeric_boundaries_and_large_values(self):
        r=fake_rows()
        for n in (0,1,21,1000-1,1000+21,0xffffffff,0x7fffffff,0x80000000):
            self.assertIsNotNone(s.range_index(r,n))
    def test_each_specific_interval_is_selected_before_fallback(self):
        r=fake_rows()
        for i in range(14):
            lo,hi,*_=r[i]
            self.assertEqual(s.range_index(r,lo),i)
            self.assertEqual(s.range_index(r,hi),i)
            self.assertEqual(s.range_index(r,lo+10),i)
            self.assertEqual(s.range_index(r,hi+1),14)
    def test_category_mapping_and_scaling(self):
        r=fake_rows()
        expected={0:200,2:300,3:100,8:400,10:600,12:800,14:1200}
        for cat,value in expected.items():
            self.assertEqual(s.profile_code(r,1010,cat),value)
    def test_unknown_categories_reject_even_with_numeric_fallback(self):
        for cat in range(16):
            if cat in s.CATEGORIES:continue
            self.assertIsNone(s.profile_code(fake_rows(),0xffffffff,cat))
    def test_two_models_generated_A32_rom_and_fallback(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                artificial=artificial_section(sp)
                digest=hashlib.sha256(fake_table()).hexdigest()
                with patch.object(s,'SHA',digest), patch.object(s,'ORIGINAL_ANCHORS',
                    ((2310,13),(1010,0),(0,14),(0xffffffff,14))):
                    r=s.original_rom(sp,artificial)
                self.assertTrue(r['row14_universal_u32_catchall'])
                self.assertTrue(r['same_base_828_direct_A32_load_and_store_verified'])
    def test_two_models_generated_Ghidra_like_functions(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                r=check_fake_function(sp)
                self.assertEqual(r['allowed_switch_category_cases'],[0,2,3,8,10,12,14])
                self.assertFalse(r['real_sensor_4K60_or_Main10_hardware_confirmation'])
    def test_signed_overflow_is_not_invented(self):
        # All artificial profile values fit signed 32-bit, by design.
        for clock in (0,1000,1300,0xffffffff):
            for cat in s.CATEGORIES:
                value=s.profile_code(fake_rows(),clock,cat)
                self.assertIsNotNone(value)
                self.assertTrue(0<=value<0x80000000)

class Negative(unittest.TestCase):pass

for i in range(14):
    def make(i):
        def test(self):
            r=fake_rows();lo,hi,*_=r[i]
            self.assertEqual(s.range_index(r,lo-1),14)
            self.assertEqual(s.range_index(r,hi+1),14)
            self.assertEqual(s.range_index(r,lo),i)
            self.assertEqual(s.range_index(r,hi),i)
        return test
    setattr(Negative,f'test_synthetic_first14_window_boundaries_{i}',make(i))
for i in range(14):
    for mutation in ('overlap','inverted','zero_profile'):
        def make(i,mutation):
            def test(self):
                r=fake_rows();q=list(r[i])
                if mutation=='overlap':
                    if i<13:q[1]=r[i+1][0]
                    else:q[0]=r[12][1]
                elif mutation=='inverted':q[0]=q[1]+1
                else:q[3]=0
                r[i]=tuple(q)
                with self.assertRaises(ValueError):s.verify_shape(r)
            return test
        setattr(Negative,f'test_bad_synthetic_window_{i}_{mutation}',make(i,mutation))
for i in range(5):
    def make(i):
        def test(self):
            r=fake_rows();q=list(r[-1]);q[i]=(q[i]+1)&0xffffffff
            r[-1]=tuple(q)
            if i in (0,1):
                with self.assertRaises(ValueError):s.verify_shape(r)
            else:
                # Changing fallback profile is valid range data but not same result.
                cat={2:3,3:0,4:2}[i]
                self.assertNotEqual(s.profile_code(r,0,cat),s.profile_code(fake_rows(),0,cat))
        return test
    setattr(Negative,f'test_synthetic_fallback_mutation_{i}',make(i))
for m,sp in s.SPECS.items():
    for src in ('literal','BL','read828','write828','ratio','table'):
        def make(m,src):
            def test(self):
                sp=s.SPECS[m];rom=artificial_section(sp);base=s.s59.BASE
                a={'literal':sp.literal_ptr,'BL':sp.BL,'read828':sp.word828_read,
                   'write828':sp.word828_write,'ratio':sp.ratio_start,
                   'table':sp.table_start}[src]
                rom[a-base]^=1
                with patch.object(s,'SHA',hashlib.sha256(fake_table()).hexdigest()):
                    with self.assertRaises(ValueError):s.original_rom(sp,rom)
            return test
        setattr(Negative,f'test_generated_ROM_anchor_mutation_{m}_{src}',make(m,src))
    needles=[(sp.finalizer,x) for x in (
       '(*(uint *)(param_1 + 8) & 0x3ff) >> 8',
       '*(uint *)(param_1 + 0xc) & 0xfffff',
       '*(uint *)(param_1 + 0x50) & 0xfffff',
       '*(uint *)(param_1 + 0x4b0) & 0xfffffff',
       'puVar2[-1]','puVar2 = puVar2 + 5;',
       'if (iVar1 == 0xf)','case 0:','case 2:','case 3:',
       'case 8:','case 10:','case 0xc:','case 0xe:',
       'default:', '*(uint *)(param_1 + 0x828)',
       'return 0xffffffff;')]
    needles += [(sp.builder,f'FUN_{sp.finalizer:08x}(param_1);')]
    for j,needle in enumerate(needles):
        def make(m,needle):
            def test(self):
                with self.assertRaises(ValueError):check_fake_function(s.SPECS[m],needle)
            return test
        setattr(Negative,f'test_fake_Ghidra_field_mutation_{m}_{j}',make(m,needle))
for cat in range(16):
    if cat in s.CATEGORIES:continue
    def make(cat):
        def test(self):
            self.assertIsNone(s.profile_code(fake_rows(),1020,cat))
            self.assertIsNone(s.profile_code(fake_rows(),0,cat))
        return test
    setattr(Negative,f'test_unsupported_category_{cat}',make(cat))
for j,n in enumerate((-1,0x100000000,0x100000001,2**64-1)):
    def make(n):
        def test(self):
            with self.assertRaises(ValueError):s.range_index(fake_rows(),n)
        return test
    setattr(Negative,f'test_non_u32_metric_{j}',make(n))

if __name__=='__main__':unittest.main()

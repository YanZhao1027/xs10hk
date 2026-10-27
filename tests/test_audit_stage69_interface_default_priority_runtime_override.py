"""Entirely artificial interface-descriptor priority and dynamic-parser tests.

Every descriptor and Ghidra-like function below is generated for unit tests;
no Fujifilm original table, private logs, live camera mode or VPU bitstream.
"""
import sys,unittest,struct,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage69_interface_default_priority_runtime_override as s


def made_descriptors():
    table=bytearray(36*16)
    for i,(idnum,rate) in enumerate(s.FIRST12_ID_NUM):
        table[16*i]=idnum;table[16*i+10]=rate
    i=12
    for idnum,rate,count in s.s68.SENSOR_EXPECTED:
        for _ in range(count):
            table[16*i]=idnum;table[16*i+10]=rate
            table[16*i+2]=int(i in s.ADDITIONAL_60_INDICES)
            i+=1
    assert i==36
    return table

class SparseROM:
    def __init__(self,sp):
        self.sp=sp;self.priority=bytearray([*s.DEFAULT_PRIORITY,255,0,0,0,0,0])
        self.records=made_descriptors()
    def __getitem__(self,key):
        if not isinstance(key,slice):raise KeyError(key)
        p=self.sp.priority-s.s59.BASE;d=self.sp.descriptor-s.s59.BASE
        if key.start==p:return bytes(self.priority[:key.stop-key.start])
        if key.start==d:return bytes(self.records[:key.stop-key.start])
        raise KeyError(key)


def fake_bl(a,target):
    assert (target-a-8)%4==0
    return 0xeb000000|(((target-a-8)//4)&0xffffff)


def text_fun(a,code):
    return (f'INFO TraceX6Function.java> TRACE_DECOMP_BEGIN (GhidraScript)\n'
            f'INFO TraceX6Function.java> void FUN_{a:08x}(void) {{\n{code}\n}}\n'
            f'INFO TraceX6Function.java> TRACE_DECOMP_END (GhidraScript)\n')

def fake_dispatch(sp,root):
    w=bytearray(max(sp.init_bl,sp.active_update_bl)-s.s59.BASE+4)
    for addr in (sp.init_bl,sp.active_update_bl):
        struct.pack_into('<I',w,addr-s.s59.BASE,fake_bl(addr,sp.writer))
    active=f'FUN_{sp.writer:08x}({sp.pointer},*(int *)({sp.pointer} + 0x28));'
    init=f'FUN_{sp.writer:08x}({sp.default_c},0);'
    writer=("cVar2 = *param_1; if (cVar2 == -1) { return; }"
             " do{ cVar2 = *param_1; } while (cVar2 != -1); "
             f'{sp.priority_ram}[iVar1] = 0xff;')
    chooser=(f'if ({sp.list_state}) {{return;}} uVar5 = {sp.mode_list_ram}; '
             f'if (uVar5 < 0x24) FUN_{sp.classify:08x}(uVar5, a,b,c,d); '
             'i=0x3840; j=0x3841;')
    gate='(&DAT_0162de0c)[param_1 * 0x10]' if sp.model=='xs10' else '(&DAT_01605d30)[param_1 * 0x10]'
    state='DAT_01c8568c' if sp.model=='xs10' else 'DAT_01be5758'
    klass=(f'if({gate} || {state}) {{}}; _DAT_0 = 0; '
           f'FUN_{sp.whitelist:08x}(uVar5,&local_21);')
    parser=(f'if ({sp.response_tag}) {{}}\n'
            'if (bVar3 == 2) { int max=0xc0; uVar10 = *pbVar13 & 0x7f; }')
    support=('_DAT_01c84fb8' if sp.model=='xs10' else '_DAT_01be5084')+' return 1; return 0;'
    files={
       f'{sp.model}_stage68_sensor_priority_selection.log':
         text_fun(sp.init,init)+text_fun(sp.active_update,active)+
         ''.join(text_fun(a,active) for a in sp.dynamic_sources),
       f'{sp.model}_stage68_sensor_candidate_list_sources.log':text_fun(sp.writer,writer),
       f'{sp.model}_stage68_sensor_allowlist_context.log':text_fun(sp.classify,klass)+
           (text_fun(sp.chooser,chooser) if sp.model=='xs10' else ''),
       f'{sp.model}_stage68_sensor_mode_chooser.log':text_fun(sp.response_parser,parser)+
           (text_fun(sp.chooser,chooser) if sp.model=='xt4' else ''),
       f'{sp.model}_runtime_sensor_interface_validate_stage22.log':text_fun(sp.whitelist,support),
    }
    for name,contents in files.items():(root/name).write_text(contents)
    return w,files

class Positive(unittest.TestCase):
    def test_two_original_like_synthetic_default_lists(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                r=s.check_original_rom(sp,SparseROM(sp))
                self.assertEqual(r['factory_default_60_valued_indices'],[11,5,0])
                self.assertEqual(r['factory_default_60_valued_interface_IDs'],[16,5,3])
                self.assertEqual(r['nondefault_60_valued_interface_IDs'],[97,102])
                self.assertFalse(r['60_value_is_proven_to_be_true_sensor_frame_rate'])
    def test_generated_original_style_dispatch(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model),tempfile.TemporaryDirectory() as d:
                w,_=fake_dispatch(sp,Path(d))
                r=s.check_dispatch(sp,w,Path(d))
                self.assertTrue(r['runtime_priority_can_be_replaced_from_pointer'])
                self.assertFalse(r['Main10_SPS_or_real_4K60_sensor_VPU_recording_proven'])
    def test_different_types_of_60_valued_rows(self):
        rows=s.decode_descriptors(made_descriptors())
        self.assertEqual([r['index'] for r in rows if r['numeric_rate']==60],list(s.ALL_60_INDICES))
        self.assertEqual([r['index'] for r in rows[:12] if r['numeric_rate']==60],[0,3,5,11])
        self.assertTrue(all(rows[i]['runtime_gate']==0 for i in s.DEFAULT_60_INDICES))
        self.assertTrue(all(rows[i]['runtime_gate']==1 for i in s.ADDITIONAL_60_INDICES))
    def test_runtime_priority_length_and_bounds_are_not_hardware_status(self):
        for seq in ([0],[35],[34,22],[11,0,3,5],[5,11,0],list(range(36))):
            self.assertEqual(s.decode_priority(bytes(seq+[255])),tuple(seq))
    def test_menu_4K_and_interface_candidates_are_different_tables(self):
        for k in s.ADDITIONAL_60_INDICES:self.assertNotIn(k,s.DEFAULT_PRIORITY)
        self.assertEqual(len(s.DEFAULT_PRIORITY),8)
        self.assertEqual(len(s.s68.SENSOR_EXPECTED),10)

class Negative(unittest.TestCase):pass

for i in range(12):
    for field,offset in [('id',0),('rate',10),('gate',2)]:
        def make(i,offset):
            def test(self):
                data=made_descriptors();data[i*16+offset]^=1
                with self.assertRaises(ValueError):s.decode_descriptors(data)
            return test
        setattr(Negative,f'test_first12_{field}_{i}',make(i,offset))
for i in s.ADDITIONAL_60_INDICES:
    for field,offset in [('id',0),('rate',10),('gate',2)]:
        def make(i,offset):
            def test(self):
                data=made_descriptors();data[i*16+offset]^=1
                with self.assertRaises(ValueError):s.decode_descriptors(data)
            return test
        setattr(Negative,f'test_special_{field}_{i}',make(i,offset))
for i in range(12,36):
    if i in s.ADDITIONAL_60_INDICES:continue
    def make(i):
        def test(self):
            data=made_descriptors();data[i*16+10]=60
            with self.assertRaises(ValueError):s.decode_descriptors(data)
        return test
    setattr(Negative,f'test_unexpected_extra_numeric60_{i}',make(i))
for model,sp in s.SPECS.items():
    for pos in range(8):
        def make(model,pos):
            def test(self):
                sp=s.SPECS[model];one=SparseROM(sp);one.priority[pos]=(one.priority[pos]+1)%36
                with self.assertRaises(ValueError):s.check_original_rom(sp,one)
            return test
        setattr(Negative,f'test_wrong_ROM_default_{model}_{pos}',make(model,pos))
    for addr in ('init_bl','active_update_bl'):
        def make(model,addr):
            def test(self):
                sp=s.SPECS[model]
                with tempfile.TemporaryDirectory() as d:
                    root=Path(d);w,_=fake_dispatch(sp,root)
                    ix=getattr(sp,addr)-s.s59.BASE;w[ix]^=1
                    with self.assertRaises(ValueError):s.check_dispatch(sp,w,root)
            return test
        setattr(Negative,f'test_wrong_ARM_branch_{model}_{addr}',make(model,addr))
    for token in ('default','runtime','writer','chooser','classify','response','membership'):
        def make(model,token):
            def test(self):
                sp=s.SPECS[model]
                with tempfile.TemporaryDirectory() as d:
                    root=Path(d);w,files=fake_dispatch(sp,root)
                    if token in ('default','runtime'):
                        file=f'{model}_stage68_sensor_priority_selection.log'
                        target=(sp.default_c if token=='default' else sp.pointer)
                    elif token=='writer':
                        file=f'{model}_stage68_sensor_candidate_list_sources.log';target='cVar2 = *param_1'
                    elif token=='chooser':
                        file=(f'{model}_stage68_sensor_allowlist_context.log' if model=='xs10'
                              else f'{model}_stage68_sensor_mode_chooser.log')
                        target=sp.mode_list_ram
                    elif token=='classify':
                        file=f'{model}_stage68_sensor_allowlist_context.log'
                        target='param_1 * 0x10'
                    elif token=='response':
                        file=f'{model}_stage68_sensor_mode_chooser.log'
                        target=sp.response_tag
                    else:
                        file=f'{model}_runtime_sensor_interface_validate_stage22.log'
                        target='_DAT_01c84fb8' if model=='xs10' else '_DAT_01be5084'
                    text=files[file];self.assertIn(target,text)
                    (root/file).write_text(text.replace(target,'CORRUPTED'))
                    with self.assertRaises(ValueError):s.check_dispatch(sp,w,root)
            return test
        setattr(Negative,f'test_synthetic_control_flow_{model}_{token}',make(model,token))

for i,seq in enumerate(([],[255],[1,1,255],[36,255],[255,0],[0,36,255],[0,0,255],
                        [0],[99,255],[0,1,1,255],list(range(37))+[255])):
    def make(seq):
        def test(self):
            with self.assertRaises(ValueError):s.decode_priority(bytes(seq))
        return test
    # [255] deliberately invalid: empty decoded priority.
    setattr(Negative,f'test_bad_sentinel_{i}',make(seq))

if __name__=='__main__':unittest.main()
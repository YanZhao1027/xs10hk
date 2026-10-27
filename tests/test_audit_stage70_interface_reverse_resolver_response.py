"""Phase70 ROM-free generated interface-ID resolver/queued response regressions.

All descriptor records, A32 branch words and fake Ghidra texts are generated;
no Fujifilm vendor original binary, real camera or runtime packets.
"""
import sys,tempfile,struct,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage70_interface_reverse_resolver_response as s


def fake_records():
    raw=bytearray(36*16)
    pairs=list(s.st69.FIRST12_ID_NUM)
    for ident,rate,count in s.st69.s68.SENSOR_EXPECTED:
        pairs.extend([(ident,rate)]*count)
    assert len(pairs)==36
    for i,(ident,rate) in enumerate(pairs):
        offset=i*16
        raw[offset]=i
        raw[offset+1]=min(31,ident//6)
        raw[offset+2]=ident
        raw[offset+3]=0
        raw[offset+4]=int(ident in (97,102))
        raw[offset+5]=3
        raw[offset+12]=rate
    return raw


def synthetic_original(spec):
    end=max(spec.record_end,spec.resolver_pointer_literal+4,
      spec.chooser_call+4,spec.resolver_call+4,spec.queue_call+4)
    b=bytearray(end-s.st59.BASE+16)
    b[spec.record_start-s.st59.BASE:spec.record_end-s.st59.BASE]=fake_records()
    prior=s.st69.SPECS[spec.model]
    seq=bytes([*s.st69.DEFAULT_PRIORITY,255,0,0,0,0,0])
    b[prior.priority-s.st59.BASE:prior.priority-s.st59.BASE+14]=seq
    struct.pack_into('<I',b,spec.resolver_pointer_literal-s.st59.BASE,spec.priority_RAM)
    for loc,fn in ((spec.chooser_call,spec.chooser),
                   (spec.resolver_call,spec.resolver),
                   (spec.queue_call,spec.queue_func)):
        disp=(fn-loc-8)//4
        assert (fn-loc-8)%4==0
        struct.pack_into('<I',b,loc-s.st59.BASE,0xeb000000|(disp&0xffffff))
    return b


def fake_function(addr,body):
    return ('INFO TraceX6Function.java> TRACE_DECOMP_BEGIN (GhidraScript)\n'
       +f'INFO TraceX6Function.java> char FUN_{addr:08x}(void) {{\n'
       +body+'\n}\n'
       +'INFO TraceX6Function.java> TRACE_DECOMP_END (GhidraScript)\n')


def fake_code(spec):
    resolver=('cVar3 = \'%\';\n'
      f'pcVar2 = &{spec.row_name};\n'
      '(byte)pcVar2[3] == param_2;\n'
      '(byte)pcVar2[2] == param_1;\n'
      f'pcVar5 = {spec.priority_ptr_name};\n'
      'if (cVar1 == *pcVar2){};\n'
      'while (cVar1 != -1){};\n'
      'pcVar2 = pcVar2 + 0x10;\n'
      f'while (pcVar2 != (char *){spec.end_name}){{}};\n'
      'return cVar3;')
    proc=("if (_DAT_1234 == 0x302){}\n"
      f'FUN_{spec.chooser:08x}({spec.response_buffer} + 4,{spec.response_buffer} + 5,{spec.response_buffer});\n'
      f'iVar7 = FUN_{spec.resolver:08x}(*(undefined1 *)(iVar6 + 4),*(undefined1 *)(iVar6 + 5));\n'
      '*(char *)(iVar6 + -1) = (char)iVar7;\n'
      f'*(byte *)(iVar6 + 2) = (&{spec.status_field})[iVar7 * 0x10];\n'
      'local_36 = 0x61;\nlocal_35 = 0x61;\n'
      f'FUN_{spec.queue_func:08x}(0x61,&local_38);')
    xrefs=(f'PROBE_TARGET addr={spec.resolver:08x} refs=5\n'
           f'PROBE_REF from={spec.resolver_call:08x} to={spec.resolver:08x} type=UNCONDITIONAL_CALL')
    return {'processor':proc,'resolver':resolver,'xrefs':xrefs}


def make_root(spec,root,patch=None):
    body=fake_code(spec)
    if patch:
        where,old,new=patch
        assert old in body[where]
        body[where]=body[where].replace(old,new)
    (root/f'{spec.model}_stage70_sensor_resolver_pipeline.log').write_text(
      fake_function(spec.resolver,body['resolver'])+fake_function(spec.processor,body['processor']))
    (root/f'{spec.model}_stage70_resolver_event_xrefs.log').write_text(body['xrefs'])

class Positive(unittest.TestCase):
    def test_rows_all_indices_are_unique(self):
        r=s.decode_rows(fake_records())
        self.assertEqual([x['index'] for x in r],list(range(36)))
        self.assertEqual([(r[i]['id'],r[i]['numeric_rate']) for i in (22,23,34,35)],
            [(97,60),(97,60),(102,60),(102,60)])
    def test_two_models_generated_original_rom(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                data=s.original_rom(sp,synthetic_original(sp))
                self.assertEqual(data['id97_active_list_only23_selects'],23)
                self.assertEqual(data['unmatched_return_code'],'0x25')
    def test_generated_ARM_and_decoder_C_calls(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model),tempfile.TemporaryDirectory() as d:
                root=Path(d);make_root(sp,root)
                r=s.check_code(sp,synthetic_original(sp),root)
                self.assertEqual(r['derived_original_A32_calls_verified'],3)
                self.assertEqual(r['reply_queue_channel'],'0x61')
                self.assertFalse(r['response_0x61_consumed_by_Movie_2160P_FPS6_proven'])
    def test_membership_overrides_table_fallback_but_order_is_ignored(self):
        rows=s.decode_rows(fake_records())
        for seq in ([22,23],[23,22]):
            self.assertEqual(s.select_reverse(rows,seq,97,0),23)
        self.assertEqual(s.select_reverse(rows,[22],97,0),22)
        self.assertEqual(s.select_reverse(rows,[23],97,0),23)
        self.assertEqual(s.select_reverse(rows,[35,34],102,0),35)
        self.assertEqual(s.select_reverse(rows,[34,35],102,0),35)
    def test_priority_not_present_first_ROM_match_fallback(self):
        rows=s.decode_rows(fake_records())
        for seq in ([],list(s.st69.DEFAULT_PRIORITY),[0,1,2]):
            self.assertEqual(s.select_reverse(rows,seq,97,0),22)
            self.assertEqual(s.select_reverse(rows,seq,102,0),34)
        self.assertEqual(s.select_reverse(rows,[],0xff,0),0x25)
        self.assertEqual(s.select_reverse(rows,[],0,0),0x25)
    def test_single_unique_ID_even_if_not_in_priority(self):
        rows=s.decode_rows(fake_records())
        for i in (0,3,5,11):
            self.assertEqual(s.select_reverse(rows,[],rows[i]['id'],0),i)
    def test_second_stage_lookup_may_override_primary_fallback(self):
        rows=s.decode_rows(fake_records())
        rows[5]['subcode']=1
        rows[6]['subcode']=1
        self.assertEqual(s.select_reverse(rows,[],0,1),5)
        self.assertEqual(s.select_reverse(rows,[6],0,1),6)
        self.assertEqual(s.select_reverse(rows,[6],0xff,1),6)
    def test_default_priority_list_is_separate_from_movie_LUT(self):
        self.assertEqual(len(s.st69.DEFAULT_PRIORITY),8)
        self.assertTrue(all(v<36 for v in s.st69.DEFAULT_PRIORITY))
        self.assertEqual(len(s.decode_rows(fake_records())),36)
        self.assertFalse(set((22,23,34,35)) & set(s.st69.DEFAULT_PRIORITY))

class Negative(unittest.TestCase):pass
for j in range(36):
    def make(j):
        def test(self):
            x=fake_records();x[j*16]^=1
            with self.assertRaises(ValueError):s.decode_rows(x)
        return test
    setattr(Negative,f'test_wrong_row_prefix_{j}',make(j))
for j in (12,13,22,23,34,35):
    for k in (1,2,3,4,5,12):
        def make(j,k):
            def test(self):
                x=fake_records();x[j*16+k]^=1
                with self.assertRaises(ValueError):s.decode_rows(x)
            return test
        setattr(Negative,f'test_duplicate_payload_{j}_{k}',make(j,k))
for model,sp in s.SPECS.items():
    for which in ('ptr','priority','resolveBL','chooseBL','queueBL','row'):
        def make(model,which):
            def test(self):
                sp=s.SPECS[model];b=synthetic_original(sp)
                if which=='ptr':b[sp.resolver_pointer_literal-s.st59.BASE]^=1
                elif which=='priority':b[s.st69.SPECS[model].priority-s.st59.BASE]^=1
                elif which=='resolveBL':b[sp.resolver_call-s.st59.BASE]^=1
                elif which=='chooseBL':b[sp.chooser_call-s.st59.BASE]^=1
                elif which=='queueBL':b[sp.queue_call-s.st59.BASE]^=1
                else:b[sp.record_start-s.st59.BASE+22*16]^=1
                if which.endswith('BL'):
                    with tempfile.TemporaryDirectory() as d:
                        root=Path(d);make_root(sp,root)
                        with self.assertRaises(ValueError):s.check_code(sp,b,root)
                else:
                    with self.assertRaises(ValueError):s.original_rom(sp,b)
            return test
        setattr(Negative,f'test_wrong_original_anchor_{model}_{which}',make(model,which))
    replacements=[
      ('resolver','(byte)pcVar2[2] == param_1','CORRUPT_PRIMARY'),
      ('resolver','(byte)pcVar2[3] == param_2','CORRUPT_SECONDARY'),
      ('resolver','pcVar2 = pcVar2 + 0x10;','CORRUPT_STRIDE'),
      ('resolver','cVar1 == *pcVar2','CORRUPT_PRIORITY_MEMBERSHIP'),
      ('resolver',f'pcVar5 = {sp.priority_ptr_name}','CORRUPT_POINTER'),
      ('resolver',"cVar3 = '%';",'CORRUPT_SENTINEL'),
      ('processor','*(char *)(iVar6 + -1) = (char)iVar7;','CORRUPT_RESULT_STORE'),
      ('processor',f'FUN_{sp.queue_func:08x}(0x61,&local_38);','CORRUPT_QUEUE'),
      ('processor','local_35 = 0x61;','CORRUPT_CHANNEL'),
      ('processor',f'FUN_{sp.resolver:08x}(*(undefined1 *)(iVar6 + 4),*(undefined1 *)(iVar6 + 5));','CORRUPT_LOOKUP')]
    for j,p in enumerate(replacements):
        def make(model,p):
            def test(self):
                sp=s.SPECS[model]
                with tempfile.TemporaryDirectory() as d:
                    root=Path(d);make_root(sp,root,p)
                    with self.assertRaises(ValueError):s.check_code(sp,synthetic_original(sp),root)
            return test
        setattr(Negative,f'test_corrupt_synthetic_Ghidra_{model}_{j}',make(model,p))
    def invert(model):
        def test(self):
            sp=s.SPECS[model]
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);make_root(sp,root)
                path=root/f'{model}_stage70_sensor_resolver_pipeline.log'
                t=path.read_text()
                a=f'FUN_{sp.chooser:08x}({sp.response_buffer} + 4,{sp.response_buffer} + 5,{sp.response_buffer});'
                b=f'FUN_{sp.resolver:08x}(*(undefined1 *)(iVar6 + 4),*(undefined1 *)(iVar6 + 5));'
                t=t.replace(a,'TMP_PLACEHOLDER').replace(b,a).replace('TMP_PLACEHOLDER',b)
                path.write_text(t)
                with self.assertRaises(ValueError):s.check_code(sp,synthetic_original(sp),root)
        return test
    setattr(Negative,f'test_reverse_chooser_resolver_order_{model}',invert(model))
for j,x in enumerate(([-1],[36],[0,36],[255],[0,-1])):
    def make(x):
        def test(self):
            with self.assertRaises(ValueError):s.select_reverse(s.decode_rows(fake_records()),x,97,0)
        return test
    setattr(Negative,f'test_invalid_priority_index_{j}',make(x))
if __name__=='__main__':unittest.main()
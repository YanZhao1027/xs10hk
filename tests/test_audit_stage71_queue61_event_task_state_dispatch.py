"""Purely synthetic Phase71 queue0x61 event row/state dispatch regressions.

Every word and decompiler-like string is freshly generated. No vendor ROM,
private Ghidra transcript, hardware queue or camera action is required.
"""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage71_queue61_event_task_state_dispatch as s


def bl(a,target):
    assert (target-a-8)%4==0
    return 0xeb000000|(((target-a-8)//4)&0xffffff)


def fake_word_map(spec):
    m={spec.table:spec.first_event,
        spec.table+s.ROW_INDEX*s.ROW_STRIDE:spec.event_id}
    row=spec.table+s.ROW_INDEX*s.ROW_STRIDE
    for i in range(s.ROW_CALLBACKS):m[row+4+i*4]=(spec.callback if i==4 else 0)
    for addr,target in ((spec.task_alloc_BL,spec.task_alloc_helper),
                        (spec.task_create_BL,spec.task_create_helper),
                        (spec.sender_BL,spec.send_helper),
                        (spec.dequeue_BL,spec.dequeue_helper),
                        (spec.callback_priority_BL,spec.priority_select),
                        (spec.callback_request_BL,spec.callback_request)):
        m[addr]=bl(addr,target)
    return m


def fake_text(spec):
    reg=(f'iVar1 = FUN_{spec.task_alloc_helper:08x}(0x61,&local_18);\n'
         'if (iVar1 == 0) {\nlocal_34 = 0x61;\n'
         f'local_30 = {spec.descriptor_label};\n'
         'local_2c = 7;\nlocal_28 = 0xc00;\n'
         f'local_24 = FUN_{spec.task_entry:08x};\n'
         f'iVar1 = FUN_{spec.task_create_helper:08x}(&local_34);\n'
         'if(iVar1==0) uVar2 = 0; else uVar2 = 0xffffff01;}')
    source=("if (_DAT_FAKE == 0x302) {}\n"
            f'{spec.state_var} = 4;\n'
            f'{spec.sender_message_label} = 0x{spec.event_id:x};\n'
            'local_36 = 0x61;\nlocal_35 = 0x61;\n'
            f'FUN_{spec.send_helper:08x}(0x61,&{spec.sender_message_label});')
    recv=(f'FUN_{spec.task_init:08x}(*param_1);\n'
          f'while(iVar2 = FUN_{spec.dequeue_helper:08x}(0x61,&{spec.input_var[1:]},0xffffffff)){{}}\n'
          f'if ({spec.input_var} == 0x{spec.first_event:x}) {{}}\n'
          f'iVar3 = 0x{spec.table:x};\n'
          'iVar2 = iVar2 + 1;\n'
          'psVar1 = (short *)(iVar3 + 0x1c);\n'
          'if (*psVar1 == 0) break;\n'
          f'}} while (*psVar1 != {spec.input_var});\n'
          f'if (*(code **)({spec.event_entry_label} + (iVar2 * 7 + (uint){spec.state_var}) * 4)) {{}}')
    cb=(f'{spec.state5_label}\n'
        f'FUN_{spec.priority_select:08x}(&DAT_{spec.priority_table:08x});\n'
        'if (state == 0) { local_48 = 0x13;\n'
        f'FUN_{spec.callback_request:08x}(&local_48);\n'
        f'}} else {{ local_48 = 0x{spec.start_request_alt:x};\n'
        f'FUN_{spec.callback_request:08x}(&local_48); }}')
    send_wrapper=('if (*(int *)(param_2) > 0) {}\n'
                  'if (iVar1 == 0) { local_1c[0] = param_2; }\n'
                  'return iVar1;')
    recv_wrapper=('iVar1 = func_0x00053c4c(param_1,local_1c);\n'
                  'if (iVar1 == -0x32) {}\n'
                  'else if (iVar1 == 0) { }\nreturn iVar1;')
    xrefs=(f'PROBE_TARGET addr={spec.task_entry:08x} refs=1\n'
           f'PROBE_REF from={spec.task_entry_ref:08x} to={spec.task_entry:08x} type=DATA')
    return [reg,source,recv,cb,send_wrapper,recv_wrapper,xrefs]


def check_fake(s0,t):return s.check_decompiled(s0,*t)

class Positive(unittest.TestCase):
    def test_two_models_ROM_row7_state4_only(self):
        for model,spec in s.SPECS.items():
            with self.subTest(model=model):
                words=fake_word_map(spec)
                r=s.event_row(spec,words.__getitem__)
                self.assertEqual(r['event_row'],7)
                self.assertEqual(r['state4_callback'],hex(spec.callback))
                for state in range(6):
                    ptr=words[spec.table+s.ROW_INDEX*28+4+4*state]
                    self.assertEqual(ptr!=0,state==4)
    def test_two_models_ARM_call_edges(self):
        for model,spec in s.SPECS.items():
            with self.subTest(model=model):
                r=s.original_arm(spec,fake_word_map(spec).__getitem__)
                self.assertEqual(r['original_ARM_BL_edges'],6)
                self.assertFalse(r['runtime_task_creation_and_queue_delivery_observed'])
    def test_two_models_registration_sender_receiver_callback(self):
        for model,spec in s.SPECS.items():
            with self.subTest(model=model):
                r=check_fake(spec,fake_text(spec))
                self.assertTrue(r['handler_sets_state4_before_0x61_sender_attempt'])
                self.assertTrue(r['receiver_reads_0x61_and_selects_7wide_ROM_event_matrix'])
                self.assertTrue(r['row7_state4_calls_state5_callback_if_state_unchanged'])
                self.assertFalse(r['actual_OS_delivery_callback_invocation_and_Movie_link_proven'])
    def test_0x61_is_a_queue_not_ROM_event_or_recorder_module7(self):
        for spec in s.SPECS.values():
            self.assertNotEqual(spec.event_id,s.QUEUE)
            self.assertNotEqual(spec.event_id,0x20b)
            self.assertNotEqual(spec.event_id,0x200)
            self.assertNotEqual(s.QUEUE,7)
            self.assertNotEqual(spec.start_request_alt,0x13)
    def test_callback_would_be_conditional_on_current_state(self):
        for spec in s.SPECS.values():
            data=fake_word_map(spec)
            row=spec.table+7*28
            state=4
            self.assertEqual(data[row+4+state*4],spec.callback)
            state=5
            self.assertEqual(data[row+4+state*4],0)
            state=3
            self.assertEqual(data[row+4+state*4],0)
    def test_handler_state5_is_a_new_control_step(self):
        for spec in s.SPECS.values():
            t=fake_text(spec)
            self.assertIn('0x13;',t[3])
            self.assertIn('0x'+format(spec.start_request_alt,'x'),t[3])
            self.assertNotIn('Movie+0x5c6',t[3])

class Negative(unittest.TestCase):pass

for model,spec in s.SPECS.items():
    six_calls=(spec.task_alloc_BL,spec.task_create_BL,spec.sender_BL,
               spec.dequeue_BL,spec.callback_priority_BL,spec.callback_request_BL)
    for j,addr in enumerate(six_calls):
        for bit in (1,0x100):
            def make(model,addr,bit):
                def test(self):
                    sp=s.SPECS[model];words=fake_word_map(sp)
                    words[addr]^=bit
                    with self.assertRaises(ValueError):s.original_arm(sp,words.__getitem__)
                return test
            setattr(Negative,f'test_bad_original_BL_{model}_{j}_{bit}',make(model,addr,bit))
    for j,addr in enumerate([spec.table,spec.table+7*28]+[spec.table+7*28+4+i*4 for i in range(6)]):
        def make(model,addr):
            def test(self):
                sp=s.SPECS[model];words=fake_word_map(sp)
                words[addr]^=1
                with self.assertRaises(ValueError):s.event_row(sp,words.__getitem__)
            return test
        setattr(Negative,f'test_wrong_event_row_{model}_{j}',make(model,addr))
    for j in range(7):
        def make(model,j):
            def test(self):
                sp=s.SPECS[model];t=fake_text(sp)
                t[j]='BROKEN'
                with self.assertRaises(ValueError):check_fake(sp,t)
            return test
        setattr(Negative,f'test_missing_decomp_part_{model}_{j}',make(model,j))
    for j,token in enumerate((
         'local_34 = 0x61;',
         'local_2c = 7;',
         'local_28 = 0xc00;',
         f'local_24 = FUN_{spec.task_entry:08x};',
         f'iVar1 = FUN_{spec.task_create_helper:08x}(&local_34);')):
        def make(model,token):
            def test(self):
                sp=s.SPECS[model];t=fake_text(sp)
                self.assertIn(token,t[0]);t[0]=t[0].replace(token,'BROKEN')
                with self.assertRaises(ValueError):check_fake(sp,t)
            return test
        setattr(Negative,f'test_break_registration_{model}_{j}',make(model,token))
    for j,token in enumerate((f'{spec.state_var} = 4;',
         f'{spec.sender_message_label} = 0x{spec.event_id:x};',
         'local_36 = 0x61;',
         'local_35 = 0x61;',
         f'FUN_{spec.send_helper:08x}(0x61,&{spec.sender_message_label});')):
        def make(model,token):
            def test(self):
                sp=s.SPECS[model];t=fake_text(sp)
                self.assertIn(token,t[1]);t[1]=t[1].replace(token,'BROKEN')
                with self.assertRaises(ValueError):check_fake(sp,t)
            return test
        setattr(Negative,f'test_break_sender_{model}_{j}',make(model,token))
    for j,token in enumerate((f'FUN_{spec.dequeue_helper:08x}(0x61,&{spec.input_var[1:]},0xffffffff)',
      f'if ({spec.input_var} == 0x{spec.first_event:x})',
      'psVar1 = (short *)(iVar3 + 0x1c);',
      f'}} while (*psVar1 != {spec.input_var});',
      f'({spec.event_entry_label} + (iVar2 * 7 + (uint){spec.state_var}) * 4)')):
        def make(model,token):
            def test(self):
                sp=s.SPECS[model];t=fake_text(sp)
                self.assertIn(token,t[2]);t[2]=t[2].replace(token,'BROKEN')
                with self.assertRaises(ValueError):check_fake(sp,t)
            return test
        setattr(Negative,f'test_break_receiver_{model}_{j}',make(model,token))
    for j,token in enumerate((spec.state5_label,
       f'FUN_{spec.priority_select:08x}(&DAT_{spec.priority_table:08x});',
       'local_48 = 0x13;',f'local_48 = 0x{spec.start_request_alt:x};',
       f'FUN_{spec.callback_request:08x}(&local_48);')):
        def make(model,token):
            def test(self):
                sp=s.SPECS[model];t=fake_text(sp)
                self.assertIn(token,t[3]);t[3]=t[3].replace(token,'BROKEN')
                with self.assertRaises(ValueError):check_fake(sp,t)
            return test
        setattr(Negative,f'test_break_state5_callback_{model}_{j}',make(model,token))
    def swapped(model):
        def test(self):
            sp=s.SPECS[model];t=fake_text(sp)
            a=f'{sp.state_var} = 4;';b=f'{sp.sender_message_label} = 0x{sp.event_id:x};'
            t[1]=t[1].replace(a,'SENTINEL_TMP').replace(b,a).replace('SENTINEL_TMP',b)
            with self.assertRaises(ValueError):check_fake(sp,t)
        return test
    setattr(Negative,f'test_sender_state_after_event_{model}',swapped(model))

if __name__=='__main__':unittest.main()
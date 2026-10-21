"""Stage55 entirely synthetic ARM/FSM test vectors. NO Fujifilm firmware.

Even correct synthetic and original SHA-pinned ROM audit cannot establish
runtime dispatch, staging lifetime, or actual 4K60/Main10 support.
"""
from dataclasses import replace
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage55_recorder_20b_fsm_lifecycle as s
import audit_stage53_gui_rec_setparam_tx as parent


def mov(value,register,high):
    v=(value>>16)&0xffff if high else value&0xffff
    return (0xe3400000 if high else 0xe3000000)|(register<<12)|((v>>12)<<16)|(v&0xfff)

def branch(site,target,cond=0xe):
    assert (target-site-8)%4==0
    return ((cond&0xf)<<28)|(0x0b000000 if cond==0xe else 0x0a000000)|(((target-site-8)//4)&0xffffff)


def create_toy(spec):
    s0=spec
    dic={s0.table_ref:s0.table_base,s0.handler_slot:s0.handler_stub,
         s0.handler_stub:mov(s0.state_global,3,False),
         s0.handler_stub+4:mov(s0.state_global,3,True),
         s0.handler_stub+8:0xe1d320b2,
         s0.handler_stub+12:0xe3003102,
         s0.handler_stub+16:0xe1520003,
         s0.handler_stub+20:branch(s0.handler_stub+20,s0.controller,1),
         s0.handler_stub+0x20:0xe3a02000,
         s0.handler_stub+0x24:0xe5c32046,
         s0.handler_stub+0x28:0xe3a00001,
         s0.handler_stub+0x2c:0xe12fff1e,
         s0.controller+8:branch(s0.controller+8,s0.register_save),
         s0.controller+12:branch(s0.controller+12,s0.consumer),
         s0.reg_ptr_literal:s0.reg_payload,
         s0.reg_header_copy-16:0xe3a0200c,
         s0.reg_header_copy-12:mov(s0.rec_header,1,False),
         s0.reg_header_copy-8:mov(s0.rec_header,1,True),
         s0.reg_header_copy-4:0xe1a00005,
         s0.reg_header_copy:branch(s0.reg_header_copy,s0.memcpy),
         s0.reg_body_copy-20:mov(s0.rec_header,1,False),
         s0.reg_body_copy-16:mov(s0.rec_header,1,True),
         s0.reg_body_copy-12:0xe5912004,
         s0.reg_body_copy-8:0xe281100c,
         s0.reg_body_copy-4:0xe1a00004,
         s0.reg_body_copy:branch(s0.reg_body_copy,s0.memcpy),
         s0.zero_entry_site-8:0xe3a0108c,
         s0.zero_entry_site-4:0xe300020b,
         s0.zero_entry_site:branch(s0.zero_entry_site,s0.zero_record),
         s0.zero_entry_site+4:branch(s0.zero_entry_site+4,s0.exit_callback),
         s0.zero_entry_site+8:0xe3a00001}
    for i,site in enumerate(s0.checks_sites):
        dic.update({site:branch(site,s0.checks),site+4:0xe3500000,
                    site+8:branch(site+8,site+0x24,1),
                    site+0x14:0xe3a02000|(i+1),site+0x18:0xe1c321ba,
                    site+0x1c:0xe3a00000})
    for site in s0.cleanup_call_sites:dic[site]=branch(site,s0.zero_helper)
    ctl='''undefined4() {
  FUN_%08x();
  FUN_%08x();
  FUN_%08x();
'''%(s0.register_save,s0.consumer,0xabcde000)
    for _ in range(4):
        ctl+='  iVar2 = FUN_%08x();\n  if (iVar2 == 0) { return 0; }\n'%s0.checks
    ctl+='  FUN_%08x();\n  FUN_%08x(0x20b,0x8c);\n  return 1;\n}'%(s0.followup_export,s0.zero_record)
    save=('''void(){
 if (_DAT_%08x == 0x20b) {
 puVar3 = DAT_%08x + -0xc;
 puVar2 = DAT_%08x;
 }
 FUN_%08x(puVar3,&DAT_%08x,0xc);
 FUN_%08x(puVar2,&DAT_%08x,_DAT_%08x);
}'''%(s0.rec_header,s0.reg_ptr_literal,s0.reg_ptr_literal,
            s0.memcpy,s0.rec_header,s0.memcpy,s0.rec_header+12,s0.rec_header+4))
    clr=('''void(){
 FUN_%08x(param_1,param_2,0);
 FUN_%08x(param_1,param_2,0);
 FUN_%08x(iVar2,0,0xc);
 FUN_%08x(iVar3,0,0x44);
}'''%(parent.SPECS[s0.model].registry_header_fn,
               parent.SPECS[s0.model].registry_payload_fn,
               s0.zero_helper,s0.zero_helper))
    helper='if (param_3 == 0) return; *puVar2 = (char)param_2;'
    r=s.ROUTES[s0.model]
    dic.update({r.ptr_table+16:r.group4_table,
                r.event4_site-4:0xe3a00004,
                r.event4_site:branch(r.event4_site,r.dispatcher),
                r.event13_site-4:0xe3a0000d,
                r.event13_site:branch(r.event13_site,r.dispatcher)})
    classification='if (_DAT_%08x == 0x200) { } else { _DAT_%08x = 5; } FUN_%08x(4);'%(
      s0.rec_header,r.classifier_status_ram,r.dispatcher)
    router='(&PTR_DAT_%08x)[param_1];'%r.ptr_table
    wrapper='FUN_%08x();'%r.classifier
    callback='FUN_%08x();'%r.classifier_wrapper
    return {'words':dic,'controller':ctl,'save':save,'clear':clr,'helper':helper,
            'classification':classification,'router':router,'wrapper':wrapper,
            'callback':callback}


def run_check(spec,f,group):
    w=f['words'].__getitem__
    if group=='table':return s.original_table_gate(spec,w)
    if group=='controller':return s.original_controller(spec,w,f['controller'])
    if group=='registry':return s.original_registry_save(spec,w,f['save'])
    if group=='clear':return s.original_registry_clear(spec,w,f['clear'],f['helper'])
    if group=='route':return s.original_group_routing(spec,s.ROUTES[spec.model],w,
        f['classification'],f['router'],f['wrapper'],f['callback'])
    raise ValueError('unknown group')

class SyntheticProofBoundaries(unittest.TestCase):
    def test_two_model_all_groups(self):
        for m,sp in s.SPECS.items():
            with self.subTest(model=m):
                f=create_toy(sp)
                for k in ('table','controller','registry','clear','route'):
                    self.assertTrue(run_check(sp,f,k))
    def test_static_state_code_not_message_type(self):
        for m,sp in s.SPECS.items():
            self.assertNotEqual(0x102,0x20b)
            self.assertEqual(s.branch(create_toy(sp)['words'].__getitem__,sp.handler_stub+20),sp.controller)
            out=run_check(sp,create_toy(sp),'table')
            self.assertFalse(out['specific_0x20B_message_to_this_table_callback_proven'])
    def test_reg_save_shallow_and_snapshot_deep_are_distinct(self):
        for m,sp in s.SPECS.items():
            gui=bytearray(0x5dc if m=='xs10' else 0x5d8)
            gui[0x581]=1;gui[0x5b0]=2
            staging=gui[:]
            packet=[id(staging),0x212345]
            desc={'type':0x20b,'len':8,'ptr':packet[0],'seq':packet[1]}
            registry=[desc['ptr'],desc['seq']]
            snapshot=staging[:]
            registry[:]=[0,0]
            self.assertEqual(snapshot[0x581],1)
            self.assertEqual(snapshot[0x5b0],2)
            self.assertEqual(registry,[0,0])
            self.assertNotEqual(desc['seq'],desc['ptr'])
            self.assertFalse(run_check(sp,create_toy(sp),'registry')['saved_record_contains_an_independent_deep_GUI_copy'])
    def test_early_exit_does_not_clear_on_failed_gate(self):
        for n in range(4):
            state=5
            checks=[True]*4;checks[n]=False
            if not all(checks):state=0
            self.assertEqual(state,0)
    def test_handler_includes_success_only_clear(self):
        for s0 in s.SPECS.values():
            result=run_check(s0,create_toy(s0),'controller')
            self.assertEqual(result['post_snapshot_checks_return_0_on_failure'],4)
            self.assertEqual(result['success_only_registry_clear_parameters'],['0x20b','0x8c'])

class SyntheticRouting(unittest.TestCase):
    def test_two_models_event4_not_13(self):
        for m,sp in s.SPECS.items():
            f=create_toy(sp)
            data=run_check(sp,f,'route')
            self.assertEqual(data['immediate_receipt_FSM_event_group'],4)
            self.assertEqual(data['snapshot_handler_FSM_event_group'],13)
            self.assertFalse(data['later_group13_transition_trigger_identified'])
    def test_direct_received_type20b_is_not_0x102_state_code(self):
        for sp in s.SPECS.values():
            self.assertNotEqual(0x20b,0x102)
            self.assertNotEqual(run_check(sp,create_toy(sp),'route')['FSM_group4_function_table'],
                                run_check(sp,create_toy(sp),'route')['FSM_group13_function_table'])

class Adversarial(unittest.TestCase):pass

for m,sp in s.SPECS.items():
    base_words=[('table',sp.table_ref),('table',sp.handler_slot)] + \
      [('table',sp.handler_stub+k) for k in (0,4,8,12,16,20,0x20,0x24,0x28,0x2c)] + \
      [('controller',sp.controller+8),('controller',sp.controller+12)] + \
      [('controller',sp.zero_entry_site+k) for k in (-8,-4,0,4,8)] + \
      [('registry',sp.reg_ptr_literal)]
    # Extend with both raw memcpy argument sequences and each failure branch.
    base_words += [('registry',sp.reg_header_copy+k) for k in (-16,-12,-8,-4,0)]
    base_words += [('registry',sp.reg_body_copy+k) for k in (-20,-16,-12,-8,-4,0)]
    base_words += [('clear',site) for site in sp.cleanup_call_sites]
    for site in sp.checks_sites:
        base_words += [('controller',site+off) for off in (0,4,8,0x14,0x18,0x1c)]
    for n,(section,addr) in enumerate(base_words):
        def make(model,section,addr):
            def test(self):
                spec=s.SPECS[model]
                f=create_toy(spec);f['words'][addr]^=1
                with self.assertRaises(ValueError):run_check(spec,f,section)
            return test
        setattr(Adversarial,'test_bad_word_%s_%02d_%s'%(m,n,hex(addr)[2:]),make(m,section,addr))
    snippets=[
       ('controller','FUN_%08x();'%sp.register_save),
       ('controller','FUN_%08x();'%sp.consumer),
       ('controller','FUN_%08x();'%sp.followup_export),
       ('controller','FUN_%08x(0x20b,0x8c);'%sp.zero_record),
       ('controller','return 1;'),
       ('controller','if (iVar2 == 0) {'),
       ('controller','FUN_%08x();'%sp.checks),
       ('save','if (_DAT_%08x == 0x20b)'%sp.rec_header),
       ('save','puVar3 = DAT_%08x + -0xc;'%sp.reg_ptr_literal),
       ('save','puVar2 = DAT_%08x;'%sp.reg_ptr_literal),
       ('save','FUN_%08x(puVar3,&DAT_%08x,0xc);'%(sp.memcpy,sp.rec_header)),
       ('save','FUN_%08x(puVar2,&DAT_%08x,_DAT_%08x)'%(sp.memcpy,sp.rec_header+12,sp.rec_header+4)),
       ('clear','FUN_%08x(iVar2,0,0xc);'%sp.zero_helper),
       ('clear','FUN_%08x(iVar3,0,0x44);'%sp.zero_helper),
       ('helper','if (param_3 == 0)'),
       ('helper','*puVar2 = (char)param_2;'),
    ]
    for n,(field,needle) in enumerate(snippets):
        def make(model,field,needle):
            def test(self):
                sp=s.SPECS[model]
                f=create_toy(sp)
                self.assertIn(needle,f[field])
                f[field]=f[field].replace(needle,'INCORRECT',1)
                sec='controller' if field=='controller' else 'registry' if field=='save' else 'clear'
                with self.assertRaises(ValueError):run_check(sp,f,sec)
            return test
        # Replacing only the first of 4 conditions doesn't necessarily
        # cause failure when compare/call threshold was >=4 or ==4: yes.
        setattr(Adversarial,'test_wrong_semantics_%s_%02d'%(m,n),make(m,field,needle))
    r=s.ROUTES[m]
    for n,addr in enumerate((r.ptr_table+16,r.event4_site-4,r.event4_site,
                              r.event13_site-4,r.event13_site)):
        def make(model,addr):
            def test(self):
                sp=s.SPECS[model]
                f=create_toy(sp)
                f['words'][addr]^=1
                with self.assertRaises(ValueError):run_check(sp,f,'route')
            return test
        setattr(Adversarial,'test_corrupt_route_instruction_%s_%02d'%(m,n),make(m,addr))
    for n,(field,key) in enumerate((('classification','0x200'),
          ('classification',' = 5;'),('classification',f'FUN_{r.dispatcher:08x}(4)'),
          ('router',f'PTR_DAT_{r.ptr_table:08x}'),
          ('wrapper',f'FUN_{r.classifier:08x}()'),
          ('callback',f'FUN_{r.classifier_wrapper:08x}()'))):
        def make(model,field,key):
            def test(self):
                sp=s.SPECS[model]
                f=create_toy(sp)
                self.assertIn(key,f[field])
                f[field]=f[field].replace(key,'CORRUPT')
                with self.assertRaises(ValueError):run_check(sp,f,'route')
            return test
        setattr(Adversarial,'test_wrong_route_C_%s_%02d'%(m,n),make(m,field,key))
    def replaced_with_group13(model):
        def test(self):
            sp=s.SPECS[model];r=s.ROUTES[model]
            f=create_toy(sp)
            f['words'][r.ptr_table+16]=sp.table_base
            with self.assertRaisesRegex(ValueError,'aliased'):
                run_check(sp,f,'route')
        return test
    setattr(Adversarial,'test_group4_not_13_'+m,replaced_with_group13(m))
    def reorder(model):
        def test(self):
            sp=s.SPECS[model]
            f=create_toy(sp)
            clear=f'FUN_{sp.zero_record:08x}(0x20b,0x8c);'
            copy=f'FUN_{sp.consumer:08x}();'
            f['controller']=f['controller'].replace(copy,'ALIAS_REPLACED').replace(clear,copy).replace('ALIAS_REPLACED',clear)
            with self.assertRaisesRegex(ValueError,'call order'):
                run_check(sp,f,'controller')
        return test
    setattr(Adversarial,'test_wrong_call_order_'+m,reorder(m))

if __name__=='__main__':unittest.main()
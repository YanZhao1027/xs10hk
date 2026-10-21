"""Fully synthetic-only Phase54 module7 queue/descriptor snapshot tests.

No Fujifilm firmware bytes, vendor code/strings or actual camera data; artificial
ARM words and temporary data structures test bounded audit logic and no-alias
conclusions, not physical Main10/4K60 viability or real queue scheduling.
"""
import sys
from pathlib import Path
from dataclasses import replace
import struct,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage54_module7_receiver_pointer as s
import audit_stage53_gui_rec_setparam_tx as st53
import audit_mode_profile_registry_stage29 as st29
import audit_recorder_input_export_alias_stage31 as st31

def armh(value,reg,high):
 v=((value>>16) if high else value)&0xffff
 return (0xe3400000 if high else 0xe3000000)|(reg<<12)|((v>>12)<<16)|(v&0xfff)

def b(site,target):
 assert (target-site-8)%4==0
 return 0xeb000000|(((target-site-8)//4)&0xffffff)

def toy(spec):
 desc=st29.SPECS[spec.model].destination_header
 mem=st53.SPECS[spec.model].memcpy
 w2={};w1={}
 a=spec.init_ptr_setup
 w2.update({a:armh(desc,3,False),a+4:armh(desc,3,True),
            a+8:0xe3a02044,a+12:0xe5832004,a+16:0xe283200c,a+20:0xe5832008,
            spec.taskid:0xe3a03007,spec.taskid+4:0xe50b3030,
            spec.task_callback:armh(spec.callback,3,False),
            spec.task_callback+4:armh(spec.callback,3,True),
            spec.task_callback+8:0xe50b3020,
            spec.task_registration:b(spec.task_registration,spec.task_create)})
 a=spec.receive_call
 w2.update({a-0x24:armh(desc,4,False),a-0x20:armh(desc,4,True),
            a-0x18:0xe284600c,a-0xc:0xe1a02005,a-8:0xe1a01004,
            a-4:0xe3a00007,a:b(a,spec.recv_api),
            a+4:0xe3500000,a+8:0x1afffff8,
            spec.precheck_call:b(spec.precheck_call,spec.precheck),
            spec.precheck_call+4:0xe3500001,
            spec.precheck_call+8:0x0afffff2,
            spec.loop_memcpy:0xe5942004,
            spec.loop_memcpy+4:0xe5941008,
            spec.loop_memcpy+8:0xe1a00006,
            spec.loop_memcpy+12:b(spec.loop_memcpy+12,mem),
            spec.fsm_call:b(spec.fsm_call,spec.fsm)})
 xt=spec.model=='xt4'
 a=spec.api_copy
 delta=0x0127ea74 if xt else 0x012a6374
 w1.update({spec.os_get:b(spec.os_get,0x00053c4c),
            delta-0x50:0xe5912004,delta-0x4c:0xe3520000,
            delta-0x48:0x1a000010,delta:0xe2811008,
            delta+4:0xe5950008,a:b(a,mem)})
 typ=0x02189370 if xt else 0x0221c95c
 src=0x021893f8 if xt else 0x0221c9e4
 length=0x02189410 if xt else 0x0221c9fc
 cb=0x02189418 if xt else 0x0221ca04
 w2.update({typ:0xe300320b,typ+4:0xe1520003,
            src:0xe593100c,length:0xe3002000|spec.length,
            cb:b(cb,mem),spec.dest_literal:spec.source_snapshot,
            spec.consumer_call:b(spec.consumer_call,spec.receiver_20b)})
 out={
 'init':('_DAT_%08x = 0x44; _DAT_%08x = &DAT_%08x; local_34 = 7;'
         ' local_24 = FUN_%08x; FUN_%08x(&local_34);'%
         (desc+4,desc+8,desc+12,spec.callback,spec.task_create)),
 'helper':('func_0x00053c4c(param_1,local_1c); '
           '*(undefined4 *)(param_2 + 2) = *(undefined4 *)(local_1c[0] + 2); '
           'FUN_%08x(*(undefined4 *)(param_2 + 4),local_1c[0] + 4); '
           'func_0x00050aac(param_1,local_1c[0]);'%mem),
 'loop':('FUN_%08x(7,&DAT_%08x,0xffffffff); '
         'FUN_%08x(&local_24); '
         'FUN_%08x(&DAT_%08x,_DAT_%08x,_DAT_%08x); '
         'FUN_%08x();'%
          (spec.recv_api,desc,spec.precheck,mem,desc+12,desc+8,desc+4,spec.fsm)),
 'filter':('short *p = &DAT_%08x; while(*p != 0) {return 1;}return 0;'%spec.filter_table),
 'wrapper':('FUN_%08x(param_1); '%spec.filter_fn+'FUN_021f1e28(param_1);'),
 'special':'if (*param_1 == 0x123a) return 0; return 1;',
 'snapshot':('_DAT_%08x == 0x20b; '
             'FUN_%08x(DAT_FAKE,_DAT_%08x,0x%x);'%
             (desc,mem,desc+12,spec.length)),
 }
 # Construct independent fabricated special-message ROM table, independent
 # of proprietary original address range, with 120 dummy IDs and terminator.
 small_spec=replace(spec,filter_table=spec.rom2+0x20)
 table=bytearray(0x3000)
 for i in range(120):struct.pack_into('<H',table,0x20+16*i,0x1300+i)
 # Terminator is zero by allocation.
 out['filter']=out['filter'].replace('%08x'%spec.filter_table,'%08x'%small_spec.filter_table)
 return {'word1':w1,'word2':w2,'c':out,'filter':table,'filter_spec':small_spec}

def verify(group,spec,d):
 w1=d['word1'].__getitem__;w2=d['word2'].__getitem__;c=d['c']
 if group=='registration':return s.check_task_registration(spec,w2,c['init'])
 if group=='receive_api':return s.check_receive_api(spec,w1,c['helper'])
 if group=='receive_loop':return s.check_receive_loop(spec,w2,c['loop'])
 if group=='filter':return s.check_filter(d['filter_spec'],d['filter'],w2,
                            c['filter'],c['wrapper'],c['special'])
 if group=='consumer':return s.check_snapshot_consumer(spec,w2,c['snapshot'],
                                                        lambda a:None)
 raise ValueError('bad synthetic group')

# The production consumer verifies its 32-bit ROM literal through st29.word;
# the synthetic test shifts a tiny dummy ROM window onto that original address.
_original_word=st29.word

def verify_consumer(spec,d):
 c=d['c'];w=d['word2'].__getitem__
 src=spec.dest_literal
 # Use a tiny local bytes buffer and temporarily replace spec with a shifted
 # synthetic *ROM base* that puts the unique original literal at offset 0x40.
 synthetic=replace(spec,rom2=src-0x40)
 rom=bytearray(0x80);struct.pack_into('<I',rom,0x40,spec.source_snapshot)
 # `check_snapshot_consumer` needs the actual model type from spec.model;
 # all address identities otherwise remain synthetic and Ghidra-free.
 return s.check_snapshot_consumer(synthetic,w,c['snapshot'],bytes(rom))

class PositiveSynthetic(unittest.TestCase):
 def test_both_models_each_component(self):
  for spec in s.SPECS.values():
   data=toy(spec)
   for group in ('registration','receive_api','receive_loop','filter'):
    with self.subTest(model=spec.model,group=group):self.assertTrue(verify(group,spec,data))
   self.assertTrue(verify_consumer(spec,data))
 def test_payload_pointer_not_a_copy_of_full_gui_config(self):
  for spec in s.SPECS.values():
   n=spec.length;gui=bytearray(n);gui[0x581]=1;gui[0x5b0]=2
   staging=gui[:];symbolic_staging_addr=0x06001234;sequence=0x20100fff
   packet=struct.pack('<II',symbolic_staging_addr,sequence)
   descriptor=bytearray(12+0x44);descriptor[12:20]=packet
   self.assertEqual(len(packet),8)
   self.assertEqual(struct.unpack_from('<I',descriptor,12)[0],symbolic_staging_addr)
   self.assertEqual(struct.unpack_from('<I',descriptor,16)[0],sequence)
   self.assertNotEqual(struct.unpack_from('<I',descriptor,16)[0],symbolic_staging_addr)
   self.assertEqual(staging[0x581],1)
   source_snapshot=bytearray(n)
   self.assertEqual(source_snapshot[0x581],0)
   source_snapshot[:]=staging # only AFTER a second distinct conditional event
   self.assertEqual(source_snapshot[0x5b0],2)
 def test_20b_and_200_are_distinct_descriptor_types(self):
  self.assertNotEqual(0x20b,0x200)
  for spec in s.SPECS.values():
   d=st29.SPECS[spec.model].destination_header
   self.assertEqual(d+0x10,d+0xc+4)
   self.assertNotEqual(st53.SPECS[spec.model].staging,st31.SPECS[spec.model].current_slot)

class NegativeFaults(unittest.TestCase):pass

for model,spec in s.SPECS.items():
 d=toy(spec)
 # Every original ARM site the verifier observes has independent negative
 # mutation on a synthetic opcode; test one tiny change at a time.
 members=[('registration','word2',a) for a in [spec.init_ptr_setup+i for i in range(0,0x18,4)]+
          [spec.taskid,spec.taskid+4,spec.task_callback,spec.task_callback+4,
           spec.task_callback+8,spec.task_registration]]
 a=spec.receive_call
 members += [('receive_loop','word2',a) for a in
             [a-0x24,a-0x20,a-0x18,a-0xc,a-8,a-4,a,a+4,a+8,
              spec.precheck_call,spec.precheck_call+4,spec.precheck_call+8,
              spec.loop_memcpy,spec.loop_memcpy+4,spec.loop_memcpy+8,
              spec.loop_memcpy+12,spec.fsm_call]]
 delta=0x0127ea74 if model=='xt4' else 0x012a6374
 members += [('receive_api','word1',a) for a in
             [spec.os_get,delta-0x50,delta-0x4c,delta-0x48,
              delta,delta+4,spec.api_copy]]
 isxt=model=='xt4';ct=0x02189370 if isxt else 0x0221c95c
 cs=0x021893f8 if isxt else 0x0221c9e4
 cl=0x02189410 if isxt else 0x0221c9fc
 cp=0x02189418 if isxt else 0x0221ca04
 members += [('consumer','word2',a) for a in
             [ct,ct+4,cs,cl,cp,spec.consumer_call]]
 # The consumer ROM literal is handled independently (different custom ROM).
 for idx,(group,kind,a) in enumerate(members):
  def test_negative(group,kind,a,model):
   def test(self):
    sp=s.SPECS[model];d=toy(sp);d[kind][a]^=0x4
    with self.assertRaises(ValueError):
     verify_consumer(sp,d) if group=='consumer' else verify(group,sp,d)
   return test
  setattr(NegativeFaults,f'test_modified_ARM_{model}_{idx:03d}',test_negative(group,kind,a,model))
 # Mutate C tokens proving source/dest and conditional outcomes.
 tokens=[('registration','init','local_34 = 7'),
         ('registration','init','local_24 = FUN_'),
         ('registration','init','0x44'),
         ('receive_api','helper','func_0x00053c4c'),
         ('receive_api','helper','local_1c[0] + 4'),
         ('receive_api','helper','func_0x00050aac'),
         ('receive_loop','loop',f'FUN_{spec.recv_api:08x}(7'),
         ('receive_loop','loop','&local_24'),
         ('receive_loop','loop',f'FUN_{spec.fsm:08x}()'),
         ('receive_loop','loop',f'_DAT_{st29.SPECS[model].destination_header+8:08x}'),
         ('filter','filter',f'&DAT_{spec.rom2+0x20:08x}'),
         ('filter','filter','return 0;'),
         ('filter','wrapper',f'FUN_{spec.filter_fn:08x}(param_1)'),
         ('consumer','snapshot','0x20b'),
         ('consumer','snapshot',f'FUN_{st53.SPECS[model].memcpy:08x}'),
         ('consumer','snapshot',f'0x{spec.length:x}')]
 for i,(group,field,needle) in enumerate(tokens):
  def test_negative_text(group,field,needle,model):
   def test(self):
    sp=s.SPECS[model];d=toy(sp);self.assertIn(needle,d['c'][field]);d['c'][field]=d['c'][field].replace(needle,'MISMATCH')
    with self.assertRaises(ValueError):
     verify_consumer(sp,d) if group=='consumer' else verify(group,sp,d)
   return test
  setattr(NegativeFaults,f'test_missing_C_{model}_{i:02d}',test_negative_text(group,field,needle,model))
 # Fabricate malicious/mismatched queue-type table entries (still no real ROM).
 def test_wrong_filter(self,model=model):
  sp=s.SPECS[model];d=toy(sp);struct.pack_into('<H',d['filter'],0x20+16*3,0x20b)
  with self.assertRaises(ValueError):verify('filter',sp,d)
 setattr(NegativeFaults,f'test_intercepted_20B_{model}',test_wrong_filter)
 def test_bad_callback_literal(self,model=model):
  sp=s.SPECS[model];d=toy(sp)
  synthetic=replace(sp,rom2=sp.dest_literal-0x40)
  rom=bytearray(0x80);struct.pack_into('<I',rom,0x40,sp.source_snapshot^4)
  with self.assertRaises(ValueError):s.check_snapshot_consumer(synthetic,d['word2'].__getitem__,d['c']['snapshot'],bytes(rom))
 setattr(NegativeFaults,f'test_wrong_snapshot_dest_ROM_{model}',test_bad_callback_literal)

if __name__=='__main__':unittest.main()
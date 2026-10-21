"""Synthetic-only Phase53 ARM packet, pointer and direction tests.

Every word here is fabricated from an instruction encoder, not extracted
from Fujifilm vendor ROM; no real GUI, camera, IPC, USB, FF80 or flash I/O.
"""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage53_gui_rec_setparam_tx as p
import audit_stage52_gui_recorder_hdmi_alias as prev
import audit_recorder_input_export_alias_stage31 as st31
import audit_mode_profile_registry_stage29 as st29


def mov_half(value,reg,upper):
    v=((value>>16) if upper else value)&0xffff
    return (0xe3400000 if upper else 0xe3000000)|(reg<<12)|((v>>12)<<16)|(v&0xfff)


def bl(site,target):
    assert (target-site-8)%4==0
    return 0xeb000000|(((target-site-8)//4)&0xffffff)


def artificial(s):
    gui=prev.SPECS[s.model].gui_base
    size=prev.SPECS[s.model].gui_record_len
    desc=st29.SPECS[s.model].destination_header
    ptr=st31.SPECS[s.model].current_slot
    clone_target=0x98765400
    word1={
      s.clone_bl-4:0xe3002000|size,
      s.clone_bl:bl(s.clone_bl,s.memcpy),
    }
    x=s.caller-0x1c
    word2={
        x:mov_half(gui,3,False),
        x+4:mov_half(gui,3,True),
        x+8:0xe50b3014,
        x+12:0xe3a00783,
        x+16:bl(x+16,s.seq_gen),
        x+20:0xe50b0010,
        x+24:0xe24b0014,
        s.caller:bl(s.caller,s.tx),
    }
    a=s.copy_bl
    word2.update({
        a-0x1c:0xe5d3240b,
        a-0x18:0xe5c3240a,
        a-0x14:mov_half(s.staging,5,False),
        a-0x10:mov_half(s.staging,5,True),
        a-0xc:0xe3002000|size,
        a-8:0xe5941000,
        a-4:0xe1a00005,
        a:bl(a,s.memcpy),
        a+4:0xe50b5020,
        a+8:0xe5943004,
        a+12:0xe50b301c,
        a+16:0xe300320b,
        a+20:0xe14b31b8,
        a+0x20:0xe3a00007,
        a+0x24:0xe54b0015,
        a+0x28:0xe3a03008,
        a+0x2c:0xe50b3014,
        a+0x30:0xe24b3020,
        a+0x34:0xe50b3010,
        a+0x38:0xe24b1018,
        s.enqueue_bl:bl(s.enqueue_bl,s.enqueue),
        s.registry_header_literal:s.registry_header,
        s.registry_payload_literal:s.registry_payload,
        s.recv_type_site:0xe300320b,
        s.recv_type_site+4:0xe1520003,
        s.recv_ptr_site:0xe593100c,
        s.recv_ptr_site+4:0xe3510000,
        s.recv_memcpy_site-8:0xe3002000|size,
        s.recv_memcpy_site:bl(s.recv_memcpy_site,s.memcpy),
    })
    c={
        'caller':'local_18 = &DAT_%08x; local_14 = FUN_%08x(0x20c0000);'
                 'iVar2 = FUN_%08x(&local_18); rec_setparam;'%(gui,s.seq_gen,s.tx),
        'tx':('param_1[0x40a] = param_1[0x40b]; FUN_%08x(0x%x,*param_1,0x%x);'
              'local_1c = 0x20b; FUN_%08x(7,&local_1c);'%
              (s.memcpy,s.staging,size,s.enqueue)),
        'queue':('if (*(int *)(param_2 + 2) != 0) FUN_%08x('
                 'local_1c[0] + 4,*(undefined4 *)(param_2 + 4));'
                 ' func_0x0004f440(...)'%s.memcpy),
        'head':('if (param_1 == 0x20b) { return DAT_%08x; }'%s.registry_header_literal),
        'payload':('if (param_1 == 0x20b) { return DAT_%08x; }'%s.registry_payload_literal),
        'recv':('_DAT_%08x == 0x20b; _DAT_%08x != 0;'
                '_DAT_%08x = _DAT_%08x;'
                'FUN_%08x(DAT_0xdead,_DAT_%08x,0x%x);'%
                (desc,desc+12,st31.SPECS[s.model].export_slot,ptr,
                 s.memcpy,desc+12,size)),
        'clone':('FUN_%08x(param_1,param_2,0x%x);'% (s.memcpy,size)),
        'backup':('FUN_%08x(DAT_ABC,&DAT_%08x);'
                  'FUN_%08x(&DAT_%08x,DAT_ABC);'%
                  (s.gui_clone,gui,s.gui_clone,gui)),
    }
    return {'w1':word1,'w2':word2,'c':c}


def run_part(s,part,d):
    w=d['w2'].__getitem__
    c=d['c']
    if part=='caller':return p.caller(s,w,c['caller'])
    if part=='tx':return p.tx(s,w,c['tx'],c['queue'])
    if part=='registry':return p.registry(s,w,c['head'],c['payload'])
    if part=='receiver':return p.receiver(s,w,c['recv'],c['head'])
    if part=='clone':return p.alias_copy(s,d['w1'].__getitem__,c['clone'],c['backup'])
    raise ValueError('unknown synthetic group')

class PositiveSynthetic(unittest.TestCase):
    def test_both_model_groups(self):
        for s in p.SPECS.values():
            d=artificial(s)
            for group in ('caller','tx','registry','receiver','clone'):
                with self.subTest(model=s.model,group=group):
                    out=run_part(s,group,d)
                    self.assertTrue(out)
            self.assertEqual(p.tx(s,d['w2'].__getitem__,d['c']['tx'],d['c']['queue'])['packet_body_size_bytes'],8)
            self.assertFalse(p.receiver(s,d['w2'].__getitem__,d['c']['recv'],d['c']['head'])['sender_staging_pointer_into_descriptor_plus_0C_proven'])
    def test_counterfactual_buffers_are_not_same_address(self):
        for s in p.SPECS.values():
            n=prev.SPECS[s.model].gui_record_len
            gui=bytearray(n)
            staged=bytearray(n)
            receiver=bytearray(n)
            gui[0x581]=1;gui[0x5b0]=2
            staged[:]=gui
            self.assertEqual(staged[0x581],1)
            self.assertEqual(staged[0x5b0],2)
            self.assertEqual(receiver[0x581],0)
            self.assertEqual(receiver[0x5b0],0)
            self.assertNotEqual(id(staged),id(receiver))
    def test_different_identities(self):
        for s in p.SPECS.values():
            self.assertNotEqual(s.staging,s.registry_payload)
            self.assertNotEqual(s.staging,st31.SPECS[s.model].current_slot)
            self.assertNotEqual(s.staging,prev.SPECS[s.model].gui_base)
            self.assertGreater(prev.SPECS[s.model].gui_record_len,0x5b0)

class NegativeFaultInjection(unittest.TestCase):
    pass

for model,spec in p.SPECS.items():
    caller_offsets=list(range(-0x1c,4,4))
    tx_offsets=[-0x1c,-0x18,-0x14,-0x10,-0xc,-8,-4,0,4,8,12,16,20,
                0x20,0x24,0x28,0x2c,0x30,0x34,0x38]
    recv_offsets=[0,4]
    cases=[]
    cases += [('caller','w2',spec.caller+o,o) for o in caller_offsets]
    cases += [('tx','w2',spec.copy_bl+o,o) for o in tx_offsets]
    cases += [('tx','w2',spec.enqueue_bl,99)]
    cases += [('registry','w2',spec.registry_header_literal,1),
              ('registry','w2',spec.registry_payload_literal,2)]
    cases += [('receiver','w2',spec.recv_type_site+o,o+200) for o in recv_offsets]
    cases += [('receiver','w2',spec.recv_ptr_site+o,o+300) for o in recv_offsets]
    cases += [('receiver','w2',spec.recv_memcpy_site-8,400),
              ('receiver','w2',spec.recv_memcpy_site,404)]
    cases += [('clone','w1',spec.clone_bl-4,500),
              ('clone','w1',spec.clone_bl,504)]
    for group,wname,addr,ordinal in cases:
        def testfn(group,wname,addr,model):
            def test(self):
                d=artificial(p.SPECS[model])
                d[wname][addr]^=0x4
                with self.assertRaises(ValueError):run_part(p.SPECS[model],group,d)
            return test
        setattr(NegativeFaultInjection,'test_modified_A32_%s_%s_%s_%d'%
                (model,group,hex(addr)[2:],ordinal),testfn(group,wname,addr,model))
    for group,field,needle in [
        ('caller','caller','rec_setparam'),
        ('caller','caller','&DAT_%08x'%prev.SPECS[model].gui_base),
        ('caller','caller','0x20c0000'),
        ('caller','caller','&local_18'),
        ('tx','tx','0x40a'),
        ('tx','tx','0x40b'),
        ('tx','tx','0x20b'),
        ('tx','tx','0x%x'%spec.staging),
        ('tx','tx','0x%x'%prev.SPECS[model].gui_record_len),
        ('tx','tx','7,&local_1c'),
        ('tx','queue','local_1c[0] + 4'),
        ('tx','queue','*(undefined4 *)(param_2 + 4)'),
        ('tx','queue','*(int *)(param_2 + 2)'),
        ('tx','queue','func_0x0004'),
        ('registry','head','0x20b'),
        ('registry','payload','0x20b'),
        ('receiver','recv','0x20b'),
        ('receiver','recv','_DAT_%08x != 0'%(st29.SPECS[model].destination_header+12)),
        ('receiver','recv','FUN_%08x(DAT_'%spec.memcpy),
        ('clone','clone','param_1,param_2'),
        ('clone','backup','&DAT_%08x'%prev.SPECS[model].gui_base),
    ]:
        def remove_text(group,field,needle,model):
            def test(self):
                d=artificial(p.SPECS[model])
                self.assertIn(needle,d['c'][field])
                d['c'][field]=d['c'][field].replace(needle,'BAD')
                with self.assertRaises(ValueError):run_part(p.SPECS[model],group,d)
            return test
        setattr(NegativeFaultInjection,
                'test_missing_synthetic_C_%s_%s_%s_%s'%
                (model,group,field,needle.encode('utf-8').hex()),
                remove_text(group,field,needle,model))

if __name__=='__main__':unittest.main()
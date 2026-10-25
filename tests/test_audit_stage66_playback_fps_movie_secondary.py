"""Phase66 synthetic-only eMoviePlayFps -> +5C7 data edge and HS selector tests.

Only fake A32 words, generated strings and artificial settings; no vendor ROM.
"""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage66_playback_fps_movie_secondary as s


def movhalf(r,v,high):
    v=(v>>16 if high else v)&0xffff
    return (0xe3400000 if high else 0xe3000000)|r<<12|((v>>12)<<16)|(v&0xfff)

def bl(site,target):
    d=(target-site-8)//4
    return 0xeb000000|(d&0xffffff)

def toy(sp):
    a=sp.play_getter
    t=s.s32.MODELS[sp.name].template_base
    w={sp.setter_write:0xe5c3406f,sp.adapter_load:0xe5d5306f,
       sp.adapter_store:0xe5c4301f,a+8:movhalf(3,t,False),
       a+12:movhalf(3,t,True),sp.getter_load:0xe5d3001f}
    for site in sp.setBLs:w[site]=bl(site,sp.setter)
    gui=f's__INPUT_eMoviePlayFps_ DAT_{sp.gui_play:08x} = (char)param_1; FUN_0102d4a8(param_1);'
    load=(f'GET(0x{sp.read_id:x},0); GET(0x{sp.secondary_id:x},0);'
       f'GET(0x{sp.selector_id:x},0); CHECK(0x2d,0x{sp.fps_id:x},uVar3);'
       f'GET_DEFAULT(0x2d,0x{sp.fps_id:x});'
       f'FUN_{sp.setter:08x}(uVar3 & 0xff);'
       f'FUN_{sp.setter:08x}(uVar1);FUN_{sp.setter:08x}(4);')
    adapter='*(undefined1 *)(param_1 + 0x1f) = param_2[0x6f];'
    getter=f'undefined1 F(){{return DAT_{sp.active_play:08x};}}'
    cls='switch(x) {'+' '.join('case %d:'%n for n in (1,2,3,4,5,6,7))+' return 0; return 1;}'
    init=(f'FUN_{sp.mode_class_fn:08x}(cVar1);'
          "if (cVar1 == '\\x03'){}"
          '*(undefined1 *)(p + 0x5f5) = 0;')
    matcher=('cVar2 = *(char *)(param_1 + 0x5c7);'
             'cVar2 = *(char *)(param_1 + 0x5c6);'
             'if ((byte)(cVar1 - 1U) < 2){}')
    consumer=(f'FUN_{sp.mode_class_fn:08x}(cVar1);'
              f'FUN_{sp.play_getter:08x}();'
              f'FUN_{s.s65.st64.SPECS[sp.name].getter:08x}();')
    refs=(f'PROBE_TARGET addr={sp.gui_play:08x} refs={sp.setter_xrefs}\n'
          f'PROBE_REF from={sp.setter_write:08x} to={sp.gui_play:08x} type=WRITE\n'
          f'PROBE_TARGET addr={sp.active_play:08x} refs=2\n'
          f'PROBE_REF from={sp.getter_load:08x} to={sp.active_play:08x} type=READ')
    return {'w':w,'data':[gui,load,adapter,getter,cls,init,matcher,consumer,refs]}

def inspect(sp,x,part):
    if part=='arm':return s.arm(sp,x['w'].__getitem__,lambda a:0)
    if part=='data':return s.data(sp,*x['data'])
    raise ValueError(part)

class Good(unittest.TestCase):
    def test_both(self):
        for m,sp in s.SPECS.items():
            with self.subTest(model=m):
                for part in ('arm','data'):self.assertTrue(inspect(sp,toy(sp),part))
                self.assertTrue(inspect(sp,toy(sp),'data')['GUI_normal_FPS_and_playback_FPS_are_distinct'])
                self.assertFalse(inspect(sp,toy(sp),'data')['actual_Main10_or_4K60_output_proven'])
    def test_classifier_static_model(self):
        for mode in (1,2,3,4,5,6,7):
            HS=mode in (2,3)
            cls=1 if mode==2 else (2 if mode==3 else 0)
            self.assertEqual(HS,cls in (1,2))
            self.assertEqual('playFps' if HS else 'recordFps',
                             'playFps' if cls in (1,2) else 'recordFps')
    def test_no_alias_even_adjacent_addresses(self):
        for sp in s.SPECS.values():
            self.assertEqual(sp.gui_play,s.s63.SPECS[sp.name].setter_RAM_addr+1)
            self.assertNotEqual(sp.gui_play,s.s63.SPECS[sp.name].setter_RAM_addr)
            self.assertNotEqual(sp.active_play,s.s65.st64.SPECS[sp.name].active_fps_ram)

class Bad(unittest.TestCase):pass
for m,sp in s.SPECS.items():
    sites=sorted(set([sp.setter_write,sp.adapter_load,sp.adapter_store,
                      sp.play_getter+8,sp.play_getter+12,sp.getter_load,*sp.setBLs]))
    for i,addr in enumerate(sites):
        for bit in (1,0x100):
            def fn(m,addr,bit):
                def test(self):
                    sp=s.SPECS[m];x=toy(sp);x['w'][addr]^=bit
                    with self.assertRaises(ValueError):inspect(sp,x,'arm')
                return test
            setattr(Bad,f'test_corrupt_ARM_{m}_{i}_{bit}',fn(m,addr,bit))
    for i,loc in enumerate(range(9)):
        def fn(m,loc):
            def test(self):
                sp=s.SPECS[m];x=toy(sp)
                x['data'][loc]='INVALID'
                with self.assertRaises(ValueError):inspect(sp,x,'data')
            return test
        setattr(Bad,f'test_corrupt_data_{m}_{i}',fn(m,loc))
    for i,text in enumerate(('0x2d','FUN_'+format(sp.setter,'08x'),'uVar3 & 0xff',
             f'0x{sp.read_id:x}',f'0x{sp.secondary_id:x}',f'0x{sp.selector_id:x}',
             f'0x{sp.fps_id:x}')):
        def fn(m,text):
            def test(self):
                sp=s.SPECS[m];x=toy(sp)
                self.assertIn(text,x['data'][1])
                x['data'][1]=x['data'][1].replace(text,'BROKEN')
                with self.assertRaises(ValueError):inspect(sp,x,'data')
            return test
        setattr(Bad,f'test_corrupt_loader_{m}_{i}',fn(m,text))

if __name__=='__main__':unittest.main()
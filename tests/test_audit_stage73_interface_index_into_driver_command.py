"""Phase73 fully artificial 36-row ROM, BL, fake decomp and pack-bit tests.

No original camera ROM, Ghidra source, sensor traffic, HEVC or flashing.
"""
import itertools,struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage73_interface_index_into_driver_command as s
from test_audit_stage70_interface_reverse_resolver_response import fake_records


def fake_bl(at,dest):
    assert (dest-at-8)%4==0
    return 0xeb000000 | (((dest-at-8)//4)&0xffffff)


def fake_rom(spec):
    base=s.s59.BASE
    end=max(spec.record_base+36*16,spec.index_ptr_literal+4,spec.driver_call+4,
            spec.builder_marshaller_BL+4,spec.builder_finalize_BL+4)
    rom=bytearray(end-base+8)
    r=fake_records()
    for i in range(24,36):r[i*16+8]=1
    rom[spec.record_base-base:spec.record_base-base+len(r)]=r
    struct.pack_into('<I',rom,spec.index_ptr_literal-base,spec.index_byte+1)
    for a,target in ((spec.driver_call,spec.command_builder),
            (spec.builder_marshaller_BL,spec.marshaller),
            (spec.builder_finalize_BL,spec.finalize)):
        struct.pack_into('<I',rom,a-base,fake_bl(a,target))
    return rom


def fake_decomp(spec):
    f=f'DAT_{spec.second_gate:08x}'
    src=(f'iVar6 = DAT_{spec.index_ptr_literal:08x};\n'
         f'iVar7 = FUN_{spec.reverse:08x}(a,b);\n'
         '*(char *)(iVar6 + -1) = (char)iVar7;\n'
         f'if ({spec.first_read_count} == 0) {{\n{f} = 0;\n}}\n'
         f'if ({spec.packet_tag} == 0x302) {{\n'
         'else if (bVar3 == 3) {\n'
         f"if (*(char *)(uVar15 + {spec.gate_packet_name}) == '\\x03') {{\n"
         f"if (({spec.gate_packet_sig12} == '\\f') && "
         f"({spec.gate_packet_sig0} == '\\0') && ({f} = 1, 7 < uVar14)) {{}}\n"
         '}}}')
    dr=(f"if ({f} == '\\x01') {{}}\n"
        f"if ((&DAT_{spec.record_field8:08x})[(uint)DAT_{spec.index_byte:08x} * 0x10] == '\\0') {{\n"
        'local_68 = 2;\n}\nelse { local_68 = 0; }\n'
        f'FUN_{spec.command_builder:08x}(0xfff7b000,&local_7c,&local_6c,other);')
    builder=(f'if (param_3 != 0) FUN_{spec.marshaller:08x}(param_1,param_3);\n'
             f'uVar1 = FUN_{spec.finalize:08x}(param_1);')
    marsh=(f'uVar2 = (param_2[4] & 3) << 0x14;\n{spec.mirror} = uVar2;\n'
            '*(uint *)(param_1 + 0x624) = uVar2;')
    fin=('if (iVar1 == 0xf) return 0xffffffff;\n'
         '*(uint *)(param_1 + 0x828) = 0;')
    refs='\n'.join(f'PROBE_REF from={a:08x} to={b:08x} type={tp}' for b,a,tp in (
         (spec.index_byte,spec.reverse_store,'WRITE'),
         (spec.index_byte,spec.driver_index_load,'READ'),
         (spec.record_field8,spec.driver_record_load,'DATA'),
         (spec.second_gate,spec.ready_set_site,'WRITE'),
         (spec.second_gate,spec.ready_reset_site,'WRITE'),
         (spec.command_builder,spec.driver_call,'UNCONDITIONAL_CALL'),
         (spec.marshaller,spec.builder_marshaller_BL,'UNCONDITIONAL_CALL')))
    return [src,dr,builder,marsh,fin,refs]

class Good(unittest.TestCase):
    def test_two_synthetic_original_layouts(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                a=s.original_bytes(sp,fake_rom(sp))
                self.assertEqual(a['numeric60_rows'],8)
                self.assertTrue(a['row8_first24_zero_last12_one'])
                self.assertEqual(a['id97_command_word_bits20_to21'],hex(0x200000))
                self.assertEqual(a['id102_command_word_bits20_to21'],hex(0))
    def test_two_fake_Ghidra_Ghidra_edges(self):
        for model,sp in s.SPECS.items():
            with self.subTest(model=model):
                v=s.text_audit(sp,*fake_decomp(sp))
                self.assertTrue(v['driver_config_byte_local_68_as_param3_offset4_to_word20_21'])
                self.assertTrue(v['other_index_or_readiness_writers_exist_and_can_override'])
    def test_numeric60_ID97_and_ID102_pack_different_bits(self):
        for field,expected in [(0,0x200000),(1,0)]:
            self.assertEqual(s.word_20_21_from_byte(field),expected)
            self.assertEqual(s.command_mode_from_byte(field),expected>>20)
        self.assertEqual(s.word_20_21_from_byte(2),0)
        self.assertEqual(s.word_20_21_from_byte(255),0)
    def test_full_0_to_255_single_byte_bit_logic(self):
        for v in range(256):
            self.assertEqual(s.word_20_21_from_byte(v),
                             (0x200000 if v==0 else 0))
    def test_type3_specific_response_sets_second_gate(self):
        for prior in (0,1):
            for length in (0,1,7,8,9,31):
                gate,parsed=s.readiness_after_response(prior,False,0x302,3,3,12,0,length)
                self.assertEqual(gate,1)
                self.assertEqual(parsed,length>7)
    def test_first_read_resets_status_even_if_matching_response(self):
        for prior in (0,1):
            r=s.readiness_after_response(prior,True,0x302,3,3,12,0,8)
            self.assertEqual(r,(0,False))
    def test_nonmatching_response_preserves_previous_readiness(self):
        for prior in (0,1):
            for f in ((0x301,3,3,12,0),(0x302,2,3,12,0),
                      (0x302,3,4,12,0),(0x302,3,3,11,0),(0x302,3,3,12,1)):
                self.assertEqual(s.readiness_after_response(prior,False,*f,8),
                                 (prior,False))
    def test_synthetic_two_id_choices_from_previous_resolver(self):
        from test_audit_stage70_interface_reverse_resolver_response import fake_records as f
        rows=s.s70.decode_rows(f())
        for ident,expected_idx,bit in ((97,22,0x200000),(102,34,0)):
            i=s.s70.select_reverse(rows,[],ident,0)
            self.assertEqual(i,expected_idx)
            self.assertEqual(s.word_20_21_from_byte(fake_rom(s.SPECS['xs10'])[
                s.SPECS['xs10'].record_field8-s.s59.BASE+16*i]),bit)
    def test_command_bit_is_not_hardware_main10_capability(self):
        self.assertEqual(s.word_20_21_from_byte(1),0)
        self.assertEqual(s.word_20_21_from_byte(0),0x200000)
        for spec in s.SPECS.values():
            self.assertNotEqual(spec.index_byte,s.s70.SPECS[spec.model].record_start)

class Bad(unittest.TestCase):pass
for model,sp in s.SPECS.items():
    for idx in range(36):
        def make(model,idx):
            def test(self):
                p=s.SPECS[model];rom=fake_rom(p)
                rom[p.record_field8-s.s59.BASE+idx*16]^=1
                with self.assertRaises(ValueError):s.original_bytes(p,rom)
            return test
        setattr(Bad,f'test_corrupt_ROM_field8_{model}_{idx}',make(model,idx))
    for addr in (sp.index_ptr_literal,sp.driver_call,
                 sp.builder_marshaller_BL,sp.builder_finalize_BL):
        for bit in (1,0x100):
            def make(model,addr,bit):
                def test(self):
                    p=s.SPECS[model];rom=fake_rom(p)
                    rom[addr-s.s59.BASE+(1 if bit==0x100 else 0)]^=1
                    with self.assertRaises(ValueError):s.original_bytes(p,rom)
                return test
            setattr(Bad,f'test_bad_ROM_word_{model}_{addr:08x}_{bit}',make(model,addr,bit))
    d=fake_decomp(sp)
    for which,tokens in enumerate((
          (f'iVar6 = DAT_{sp.index_ptr_literal:08x};',
           f'iVar7 = FUN_{sp.reverse:08x}(',
           '*(char *)(iVar6 + -1) = (char)iVar7;',
           f'if ({sp.first_read_count} == 0)',
           f'DAT_{sp.second_gate:08x} = 0;',
           f'if ({sp.packet_tag} == 0x302)',
           'else if (bVar3 == 3)',
           f'({sp.gate_packet_sig12} == \'\\f\')',
           f'({sp.gate_packet_sig0} == \'\\0\')',
           f'(DAT_{sp.second_gate:08x} = 1, 7 < uVar14)'),
          (f"if (DAT_{sp.second_gate:08x} == '\\x01')",
           f'(&DAT_{sp.record_field8:08x})[(uint)DAT_{sp.index_byte:08x} * 0x10]',
           'local_68 = 2;', 'local_68 = 0;',
           f'FUN_{sp.command_builder:08x}(0xfff7b000,&local_7c,&local_6c,'),
          ('if (param_3 != 0)',f'FUN_{sp.marshaller:08x}(param_1,param_3);',
           f'uVar1 = FUN_{sp.finalize:08x}(param_1);'),
          ('(param_2[4] & 3) << 0x14',f'{sp.mirror} = uVar2;',
           '*(uint *)(param_1 + 0x624) = uVar2;'),
          ('if (iVar1 == 0xf)','return 0xffffffff;',
           '*(uint *)(param_1 + 0x828)'),
          (f'PROBE_REF from={sp.reverse_store:08x} to={sp.index_byte:08x} type=WRITE',
           f'PROBE_REF from={sp.driver_index_load:08x} to={sp.index_byte:08x} type=READ',
           f'PROBE_REF from={sp.driver_record_load:08x} to={sp.record_field8:08x} type=DATA'))):
        for j,token in enumerate(tokens):
            def make(model,which,token):
                def test(self):
                    p=s.SPECS[model];tmp=fake_decomp(p)
                    self.assertIn(token,tmp[which]);tmp[which]=tmp[which].replace(token,'MUTATED')
                    with self.assertRaises(ValueError):s.text_audit(p,*tmp)
                return test
            setattr(Bad,f'test_mutate_decomp_{model}_{which}_{j}',make(model,which,token))
    def ordering(model):
        def test(self):
            p=s.SPECS[model];tmp=fake_decomp(p)
            tmp[0]=tmp[0].replace('*(char *)(iVar6 + -1) = (char)iVar7;','TEMP')
            tmp[0]=tmp[0].replace(f'iVar7 = FUN_{p.reverse:08x}(a,b);',
                '*(char *)(iVar6 + -1) = (char)iVar7;')
            tmp[0]=tmp[0].replace('TEMP',f'iVar7 = FUN_{p.reverse:08x}(a,b);')
            with self.assertRaises(ValueError):s.text_audit(p,*tmp)
        return test
    setattr(Bad,f'test_reverse_lookup_store_order_{model}',ordering(model))


def fake_poll_data(spec, pollspec):
    rom=fake_rom(spec)
    for site,target in ((pollspec.driver_call,pollspec.func),
                        (pollspec.helper_call,pollspec.helper),
                        (pollspec.check_call,pollspec.check)):
        struct.pack_into('<I',rom,site-s.s59.BASE,fake_bl(site,target))
    driver=fake_decomp(spec)[1]+f'\niVar1 = FUN_{pollspec.func:08x}();\nif (iVar1 == 0) {{}}'
    poll=(f'iVar2 = 0x2a;\n'
          f'iVar1 = FUN_{pollspec.helper:08x}(0xfff7b000);\n'
          'if (iVar1 == 0) return 0;\n'
          f'FUN_{pollspec.delay:08x}(5);\n'
          'return 0xffffffce;')
    helper=(f'if(param_1==0) return 0xffffffff;\n'
            'if(flag) uVar1 = 0xff00;\nelse uVar1 = 0x9500;\n'
            f'uVar1 = FUN_{pollspec.check:08x}(param_1,uVar1);')
    check=('if (param_1 == 0) return -1;\n'
           'return -(uint)(iVar1 == -1);')
    refs='\n'.join(f'PROBE_REF from={at:08x} to={to:08x} type=UNCONDITIONAL_CALL' for at,to in (
        (pollspec.driver_call,pollspec.func),(pollspec.helper_call,pollspec.helper),
        (pollspec.check_call,pollspec.check)))
    return rom,[driver,poll,helper,check,refs]

class PollGood(unittest.TestCase):
    def test_two_generated_original_poll_guard_branches(self):
        for m,sp in s.SPECS.items():
            with self.subTest(model=m):
                pp=s.POLL[m];rom,fields=fake_poll_data(sp,pp)
                result=s.audit_poll(pp,rom,*fields)
                self.assertEqual(result['post_build_ARM_BL_verified'],3)
                self.assertFalse(result['successful_REAL_hardware_readout_or_2160p60_ever_observed'])
    def test_success_at_each_of_42_synthetic_try_positions(self):
        for i in range(42):
            self.assertEqual(s.synthetic_poll_status([1]*i+[0]+[1]*41),0)
    def test_timeout_at_42_or_43_nonzero_readbacks(self):
        self.assertEqual(s.synthetic_poll_status([1]*42),-0x32)
        self.assertEqual(s.synthetic_poll_status([1]*43),-0x32)
        self.assertEqual(s.synthetic_poll_status([0]),0)
    def test_negative_error_code_is_not_hardware_acceptance_proof(self):
        for vals in ([1]*42,[255]*42,[-1]*42):
            self.assertEqual(s.synthetic_poll_status(vals),-0x32)

class PollBad(unittest.TestCase):pass
for m,sp in s.SPECS.items():
    ps=s.POLL[m]
    for site in (ps.driver_call,ps.helper_call,ps.check_call):
        for bit in (1,0x100):
            def make(m,site,bit):
                def test(self):
                    sp=s.SPECS[m];ps=s.POLL[m];rom,fields=fake_poll_data(sp,ps)
                    rom[site-s.s59.BASE+(1 if bit==0x100 else 0)]^=1
                    with self.assertRaises(ValueError):s.audit_poll(ps,rom,*fields)
                return test
            setattr(PollBad,f'test_bad_poll_ARM_{m}_{site:08x}_{bit}',make(m,site,bit))
    cases=[
       (0,f'iVar1 = FUN_{ps.func:08x}();'),
       (0,'if (iVar1 == 0)'),
       (1,'iVar2 = 0x2a;'),
       (1,f'FUN_{ps.helper:08x}(0xfff7b000)'),
       (1,f'FUN_{ps.delay:08x}(5);'),
       (1,'return 0xffffffce;'),
       (2,'return 0xffffffff;'),
       (2,'uVar1 = 0xff00;'),
       (2,'uVar1 = 0x9500;'),
       (2,f'FUN_{ps.check:08x}(param_1,uVar1);'),
       (3,'return -(uint)(iVar1 == -1);'),
       (4,f'PROBE_REF from={ps.check_call:08x} to={ps.check:08x} type=UNCONDITIONAL_CALL'),
    ]
    for j,(n,token) in enumerate(cases):
        def make(m,n,token):
            def test(self):
                sp=s.SPECS[m];ps=s.POLL[m];rom,fields=fake_poll_data(sp,ps)
                self.assertIn(token,fields[n]);fields[n]=fields[n].replace(token,'MUTATED')
                with self.assertRaises(ValueError):s.audit_poll(ps,rom,*fields)
            return test
        setattr(PollBad,f'test_fake_status_poll_guard_{m}_{j}',make(m,n,token))

if __name__=='__main__':unittest.main()

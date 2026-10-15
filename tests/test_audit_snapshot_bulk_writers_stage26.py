"""Phase 26 synthetic-only tests. No original Fujifilm firmware is embedded."""
from dataclasses import replace
from pathlib import Path
from unittest import TestCase, main, mock
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
import audit_snapshot_bulk_writers_stage26 as mod


def make_bl(at,target):
    delta=target-at-8
    if delta%4 or not -(1<<25)<=delta<(1<<25):
        raise ValueError("BL offset out of A32 signed 24-bit range")
    return 0xeb000000|((delta>>2)&0xffffff)


def make_b(at,target,cond=0):
    delta=target-at-8
    return (cond<<28)|0x0a000000|((delta>>2)&0xffffff)


def make_ldr(rn,rd,offset):
    return 0xe5900000 | (rn<<16) | (rd<<12) | offset


def make_movhalf(rd,val,top=False):
    return ((0xe3400000 if top else 0xe3000000) |
            (((val>>12)&15)<<16)|(rd<<12)|(val&4095))


def block(entry,lines):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
            "void FUN_%08x(void) {\n%s\n}\n" %
            (entry,lines)+"TRACE_DECOMP_END (GhidraScript)\n")


def fixture(spec):
    inst={}
    writers_c=[]
    xrefs=[]
    for w in spec.writers:
        inst[w.dest_load_site] = make_ldr(
            15,0,w.dest_literal-w.dest_load_site-8)
        inst[w.dest_literal] = spec.snapshot
        inst[w.size_mov_site] = make_movhalf(2,w.copy_size)
        inst[w.call_site] = make_bl(w.call_site,spec.memcpy_entry)
        if w.source_kind=="literal_owner":
            inst[w.owner_load_site]=make_ldr(
                15,3,w.owner_literal-w.owner_load_site-8)
            inst[w.owner_literal]=spec.owner
            inst[w.source_load_site]=make_ldr(3,1,0xac4)
            c=("_DAT_02f5b294 = *(undefined4 *)(DAT_02216b24 + 0xac4);\n"
               "FUN_012a9148(DAT_02216b28,_DAT_02f5b294,0x5dc);")
        elif w.source_kind=="constructed_owner":
            before=spec.owner-0x3000
            inst[w.owner_movw_site]=make_movhalf(4,before&0xffff)
            inst[w.owner_movt_site]=make_movhalf(
                4,(before>>16)&0xffff,top=True)
            inst[w.owner_add_site]=0xe2843a03
            inst[w.source_load_site]=make_ldr(3,1,0xac4)
            if spec.name=="xs10":
                c="FUN_012a9148(DAT_0221239c,_DAT_02d9c2ac,0x5dc);"
            else:
                c="FUN_01281848(DAT_02184fd4,_DAT_02d0fa0c,0x5d8);"
        else:
            inst[w.source_load_site]=0xe2501000
            inst[w.source_load_site+4]=make_b(
                w.source_load_site+4,w.source_load_site+0x9c)
            c=("if (param_1 == 0) { return; }\n"
               "FUN_012a9148(DAT_02206a7c,param_1,0x5dc);")
        writers_c.append(block(w.entry,c))
        for addr in w.callers:
            inst[addr]=make_bl(addr,w.entry)
            xrefs.append(
                "PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL" %
                (addr,w.entry))
    memcpy=block(spec.memcpy_entry,
                 "*puVar2 = *(undefined1 *)puVar1;\n"
                 "*param_1 = *param_2;")
    source_addr="%08x"%spec.snapshot
    refs=("\n".join(
        "SRC_REF target=%s from=%08x type=%s func=00000000" %
        (source_addr,0x20000000+n*4,tp)
        for n,tp in enumerate(("PARAM","READ","DATA"))
    )+"\nSRC_SCAN target=%s xrefs=3 funcs=1\n"%source_addr)
    live="LIVE_SUMMARY addr=%08x funcs=1 decompiled=1 field_functions=%d capped=0"%(
        spec.buffer_pointer_global,int(spec.name=="xt4"))
    return [inst,memcpy,"\n".join(writers_c),"\n".join(xrefs),refs,live]


def run(spec,mutate=None):
    parts=fixture(spec)
    if mutate:mutate(*parts)
    inst,helper,writers,xrefs,refs,live=parts
    with mock.patch.object(mod,"word_at",
                           side_effect=lambda content,base,at:inst[at]):
        return mod.audit(spec,b"",helper,writers,xrefs,refs,live)


class A32Tests(TestCase):
    def test_movw_and_movt(self):
        self.assertEqual(mod.decode_move_half(
            make_movhalf(4,0xbeef),False,4),0xbeef)
        self.assertEqual(mod.decode_move_half(
            make_movhalf(4,0x2d9,True),True,4),0x2d9)

    def test_movhalf_wrong_rd(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            mod.decode_move_half(make_movhalf(3,0x5dc),False,2)

    def test_movhalf_wrong_kind(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            mod.decode_move_half(make_movhalf(2,0x5dc,True),False,2)

    def test_add_rotated_imm_3000(self):
        self.assertEqual(mod.decode_add_imm(0xe2843a03,4,3),0x3000)

    def test_add_wrong_reg(self):
        with self.assertRaisesRegex(ValueError,"ADD"):
            mod.decode_add_imm(0xe2843a03,3,4)

    def test_add_zero_rotation(self):
        self.assertEqual(mod.decode_add_imm(0xe284300c,4,3),12)

    def test_ldr_pc_positive_offset(self):
        self.assertEqual(mod.decode_load_word(
            make_ldr(15,0,0x90)),(15,0,0x90))

    def test_ldr_source_indirect(self):
        self.assertEqual(mod.decode_load_word(
            make_ldr(3,1,0xac4)),(3,1,0xac4))

    def test_ldr_wrong_class(self):
        with self.assertRaisesRegex(ValueError,"LDR"):
            mod.decode_load_word(0xe30025dc)

    def test_ldr_byte_not_word(self):
        with self.assertRaisesRegex(ValueError,"positive LDR"):
            mod.decode_load_word(make_ldr(3,1,0xac4)|(1<<22))

    def test_ldr_wrong_mode(self):
        with self.assertRaisesRegex(ValueError,"positive LDR"):
            mod.decode_load_word(make_ldr(3,1,0xac4)&~(1<<24))

    def test_bl_forward(self):
        self.assertEqual(mod.decode_bl(make_bl(0x1000,0x1010),0x1000),
                         0x1010)

    def test_bl_backward(self):
        self.assertEqual(mod.decode_bl(make_bl(0x100020,0x0f0000),
                                        0x100020),0x0f0000)

    def test_bl_wrong_link(self):
        with self.assertRaisesRegex(ValueError,"A32 BL"):
            mod.decode_bl(0xea000000,0x1000)

    def test_bl_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"A32 BL"):
            mod.decode_bl(0x0b000000,0x1000)

    def test_read_little_endian(self):
        d=struct.pack("<I",0xe30025dc)
        self.assertEqual(mod.word_at(d,0x1000,0x1000),0xe30025dc)

    def test_read_out_of_section(self):
        with self.assertRaisesRegex(ValueError,"original section"):
            mod.word_at(bytes(4),0x1000,0x1004)

    def test_read_unaligned(self):
        with self.assertRaisesRegex(ValueError,"original section"):
            mod.word_at(bytes(4),0x1000,0x1002)

    def test_decompiler_does_not_select_caller(self):
        log=block(0x01000000,"FUN_012a9148();")+block(
            0x012a9148,"*param_1 = *param_2;")
        self.assertIn("*param_1",mod.decompiled(log,0x012a9148))

    def test_decompiler_missing(self):
        with self.assertRaisesRegex(ValueError,"missing"):
            mod.decompiled("",0x012a9148)


class WriterTests(TestCase):
    def test_two_models_positive(self):
        for s in mod.SPECS.values():
            with self.subTest(model=s.name):
                out=run(s)
                self.assertEqual(out["original_arm_bulk_writer_count"],
                                 len(s.writers))
                self.assertEqual(out["snapshot_codec"],
                                 "0x%08x"%(s.snapshot+0x5b0))
                self.assertFalse(out["gui_to_runtime_input_buffer_codec_value_proven"])
                self.assertFalse(out["hevc_main10_internal_encoding_proven"])
                self.assertFalse(out["4k60_sensor_pipeline_proven"])
                self.assertFalse(out["camera_or_firmware_modified"])

    def test_xs10_three_entries(self):
        result=run(mod.SPECS["xs10"])
        self.assertEqual([w["site"] for w in result["verified_bulk_writers"]],
                          ["current_profile_clone",
                           "callers_buffer_clone","runtime_profile_clone"])

    def test_xt4_one_verified_entry_not_only_entry(self):
        result=run(mod.SPECS["xt4"])
        self.assertEqual(result["original_arm_bulk_writer_count"],1)
        self.assertEqual(result["verified_bulk_writers"][0]["copied_bytes"],
                         "0x5d8")

    def test_same_profile_pointer_for_two_xs10_writers(self):
        result=run(mod.SPECS["xs10"])
        self.assertEqual(result["runtime_input_buffer_pointer_global"],
                         "0x02d9c2ac")
        self.assertEqual(result["runtime_input_buffer_pointer_value"],
                         "UNKNOWN")

    def test_xs10_parameter_copy_has_nonzero_guard(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[0x022069d8]=0xe1a01000
        with self.assertRaisesRegex(ValueError,"SUBS"):
            run(s,mutate)

    def test_xs10_zero_arg_branch_must_skip_copy(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[0x022069dc]=make_b(0x022069dc,0x022069e8)
        with self.assertRaisesRegex(ValueError,"bypass copy"):
            run(s,mutate)

    def test_missing_parameter_decomp_guard(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            c=c.replace("if (param_1 == 0)","if (param_1 == 2)")
            parts=fixture(s)
            # mutate is only able to mutate mutable objects; use direct writer check
        inst,helper,writerlog,xrefs,base,live=fixture(s)
        writerlog=writerlog.replace("if (param_1 == 0)","if (param_1 == 2)")
        with mock.patch.object(mod,"word_at",
                               side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"conditional parameter"):
                mod.audit(s,b"",helper,writerlog,xrefs,base,live)

    def test_wrong_destination_literal(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].dest_literal]=0xdeadbeef
        with self.assertRaisesRegex(ValueError,"destination"):
            run(s,mutate)

    def test_wrong_destination_ldr(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].dest_load_site]=make_ldr(15,1,0x10)
        with self.assertRaisesRegex(ValueError,"PC literal"):
            run(s,mutate)

    def test_wrong_owner_literal(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].owner_literal]=0xbeef0000
        with self.assertRaisesRegex(ValueError,"owner address"):
            run(s,mutate)

    def test_wrong_source_indirection(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].source_load_site]=make_ldr(3,1,0xab4)
        with self.assertRaisesRegex(ValueError,"indirection"):
            run(s,mutate)

    def test_wrong_memcpy_target(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].call_site]=make_bl(
                s.writers[0].call_site,s.memcpy_entry+4)
        with self.assertRaisesRegex(ValueError,"BL target"):
            run(s,mutate)

    def test_wrong_copysize_immediate(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].size_mov_site]=make_movhalf(2,0x5ac)
        with self.assertRaisesRegex(ValueError,"copy length"):
            run(s,mutate)

    def test_copy_size_less_than_codec_pair_rejected(self):
        s=mod.SPECS["xt4"]
        old=s.writers[0]
        bad=replace(s,writers=(replace(old,copy_size=0x5b1),))
        def mutate(d,h,c,x,r,l):
            d[old.size_mov_site]=make_movhalf(2,0x5b1)
        with self.assertRaisesRegex(ValueError,"misses Codec"):
            run(bad,mutate)

    def test_wrong_owner_movt(self):
        s=mod.SPECS["xt4"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].owner_movt_site]=make_movhalf(4,0x2d1,True)
        with self.assertRaisesRegex(ValueError,"owner mismatch"):
            run(s,mutate)

    def test_wrong_owner_add(self):
        s=mod.SPECS["xt4"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].owner_add_site]=0xe2843a02
        with self.assertRaisesRegex(ValueError,"owner mismatch"):
            run(s,mutate)

    def test_wrong_owner_add_reg(self):
        s=mod.SPECS["xt4"]
        def mutate(d,h,c,x,r,l):
            d[s.writers[0].owner_add_site]=0xe2853a03
        with self.assertRaisesRegex(ValueError,"ADD"):
            run(s,mutate)

    def test_wrong_xt4_source_kind(self):
        s=mod.SPECS["xt4"]
        bad=replace(s,writers=(replace(s.writers[0],source_kind="unknown"),))
        inst,h,c,x,b,l=fixture(s)
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"source_kind"):
                mod.audit(bad,b"",h,c,x,b,l)

    def test_event_caller_wrong_bl(self):
        s=mod.SPECS["xs10"]
        def mutate(d,h,c,x,r,l):
            d[0x021e29c0]=make_bl(0x021e29c0,0x02216adc)
        with self.assertRaisesRegex(ValueError,"event caller"):
            run(s,mutate)

    def test_event_xref_missing(self):
        s=mod.SPECS["xs10"]
        inst,h,c,x,b,l=fixture(s)
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"missing private Ghidra"):
                mod.audit(s,b"",h,c,x.replace("from=021e29c0",
                                             "from=021e29c4"),b,l)

    def test_wrong_memcpy_helper_semantics(self):
        s=mod.SPECS["xs10"]
        inst,h,c,x,b,l=fixture(s)
        h=h.replace("*param_1 = *param_2;","*param_2 = *param_1;")
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"destination-first"):
                mod.audit(s,b"",h,c,x,b,l)

    def test_wrong_decompiler_copy_dest(self):
        s=mod.SPECS["xt4"]
        inst,h,c,x,b,l=fixture(s)
        c=c.replace("DAT_02184fd4,_DAT_02d0fa0c","DAT_02184fd0,_DAT_02d0fa0c")
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"current config pointer"):
                mod.audit(s,b"",h,c,x,b,l)

    def test_source_owner_pointer_arithmetic_mismatch(self):
        s=replace(mod.SPECS["xs10"],owner=0x02d9b7ec)
        with self.assertRaisesRegex(ValueError,"owner"):
            run(s)

    def test_baseline_reference_count_corrupt(self):
        s=mod.SPECS["xs10"]
        inst,h,c,x,b,l=fixture(s)
        b=b.replace("xrefs=3","xrefs=2")
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"xref count"):
                mod.audit(s,b"",h,c,x,b,l)

    def test_no_direct_write_xref_doesnt_mean_no_writers(self):
        s=mod.SPECS["xs10"]
        result=run(s)
        self.assertEqual(result["source_base_xrefs"]["direct_base_address_write_xrefs"],0)
        self.assertFalse(result["source_base_xrefs"]["absence_of_writers_inferred_from_xrefs"])
        self.assertEqual(len(result["verified_bulk_writers"]),3)

    def test_live_buffer_scan_not_complete_graph(self):
        r=run(mod.SPECS["xt4"])["bounded_live_buffer_field_reference_scan"]
        self.assertFalse(r["exhaustive_dataflow_proof"])

    def test_live_scan_must_not_be_truncated(self):
        s=mod.SPECS["xt4"]
        inst,h,c,x,b,l=fixture(s)
        l=l.replace("capped=0","capped=1")
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"truncated"):
                mod.audit(s,b"",h,c,x,b,l)

    def test_invalid_current_buffer_scan(self):
        s=mod.SPECS["xs10"]
        inst,h,c,x,b,l=fixture(s)
        l=l.replace("decompiled=1","decompiled=0")
        with mock.patch.object(mod,"word_at",side_effect=lambda _,__,at:inst[at]):
            with self.assertRaisesRegex(ValueError,"incomplete"):
                mod.audit(s,b"",h,c,x,b,l)


if __name__=="__main__":
    main()

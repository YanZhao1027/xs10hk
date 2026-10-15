"""Fully synthetic A32 and configuration-copy test fixtures for Phase 25.

The positive unit fixtures model the READ-COPY-EXPORT chain. They do not
prove any camera can encode Main10 or read 4K60 sensor video.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
import audit_codec_roundtrip_stage25 as mod


def a32_byte(*, load:bool, rn:int, rd:int, offset:int):
    return (0xe4000000 | (1<<24) | (1<<23) | (1<<22) |
            (int(load)<<20) | (rn<<16) | (rd<<12) | offset)


def a32_bl(call:int, target:int):
    disp=target-call-8
    if disp%4 or not -(1<<25)<=disp<(1<<25):
        raise ValueError("branch target out of A32 range")
    return 0xeb000000 | ((disp>>2)&0xffffff)


def fixture(spec: mod.Spec):
    code={}
    for site in (*spec.forward_sites, *spec.reverse_sites):
        code[site.address]=a32_byte(
            load=site.load,rn=site.rn,rd=site.rd,offset=site.offset)
    for call,target in spec.parent_calls:
        code[call]=a32_bl(call,target)
    producer=(
        "void FUN_%08x(void) {\n"
        "  %s = OUTPUT_ADDRESS;\n"
        "  iVar1 = WORKING_ADDRESS;\n"
        "  DAT_%08x;\n"
        "  FUN_%08x(DAT_%08x,SOURCE_POINTER,0x2d);\n"
        "  FUN_%08x(iVar1);\n"
        "  FUN_%08x(%s);\n"
        "  *(undefined4 *)(%s + 0x5ac) = SOURCE_NEIGHBOR;\n"
        "  FUN_%08x(%s + 0x5b2,0x%x,3);\n"
        "}\n" %
        (spec.producer,spec.dest_var,spec.snapshot_literal,
         spec.translator,spec.snapshot_literal,spec.commit_wrapper,
         spec.reverse_exporter,spec.dest_var,spec.dest_var,
         spec.copy_function,spec.dest_var,spec.subsequent_start)
    )
    translator=("void FUN_%08x(void){\n" % spec.translator)
    reverse=("void FUN_%08x(void){\n" % spec.reverse_exporter)
    for n in (0,1):
        translator+=(
            "*(undefined1 *)(param_1 + 0x%x) = param_2[0x%x];\n" %
            (spec.working_offset+n,0x5b0+n)
        )
        reverse+=(
            "param_1[0x%x] = DAT_%08x;\n" %
            (0x5b0+n,spec.active+spec.working_offset+n)
        )
    translator+="}\n";reverse+="}\n"
    memcpy=("void FUN_%08x(void){\n" % spec.commit)
    for base in (spec.active,spec.mirror):
        memcpy+=("func_0x00059108(0x%x,param_1,0x%x);\n" %
                 (base,spec.copy_bytes))
    memcpy+="}\n"
    getter=("return DAT_%08x;" %
            (spec.active+spec.working_offset))
    return code,[producer,translator,reverse,memcpy,getter]


def run(spec,changes=None):
    code,parts=fixture(spec)
    if changes is not None:
        changes(code,parts)
    with patch.object(mod,"get_word",side_effect=lambda d,b,a:code[a]):
        return mod.audit(spec,b"",b"",*parts)


class BytesDecoderTests(unittest.TestCase):
    def test_byte_pair_for_both_models(self):
        for spec in mod.SPECS.values():
            with self.subTest(model=spec.model):
                sites=(*spec.forward_sites,*spec.reverse_sites)
                self.assertEqual(len(sites),8)
                for s in sites:
                    self.assertEqual(
                        mod.decode_byte_transfer(
                            a32_byte(load=s.load,rn=s.rn,rd=s.rd,
                                     offset=s.offset)),
                        (s.load,s.rn,s.rd,s.offset)
                    )

    def test_wrong_class(self):
        with self.assertRaisesRegex(ValueError,"byte"):
            mod.decode_byte_transfer(0xe3a00000)

    def test_wrong_condition(self):
        w=a32_byte(load=True,rn=5,rd=3,offset=0x5b0)
        with self.assertRaisesRegex(ValueError,"byte"):
            mod.decode_byte_transfer((w&0xfffffff)|0x10000000)

    def test_postindex_rejected(self):
        w=a32_byte(load=True,rn=5,rd=3,offset=0x5b0)
        with self.assertRaisesRegex(ValueError,"addressing"):
            mod.decode_byte_transfer(w & ~(1<<24))

    def test_writeback_rejected(self):
        w=a32_byte(load=True,rn=5,rd=3,offset=0x5b0)
        with self.assertRaisesRegex(ValueError,"addressing"):
            mod.decode_byte_transfer(w | (1<<21))

    def test_wrong_signed_offset_rejected(self):
        w=a32_byte(load=True,rn=5,rd=3,offset=0x5b0)
        with self.assertRaisesRegex(ValueError,"addressing"):
            mod.decode_byte_transfer(w & ~(1<<23))

    def test_branch_forward(self):
        self.assertEqual(mod.decode_branch(
            a32_bl(0x2000,0x2500),0x2000),0x2500)

    def test_branch_backward(self):
        self.assertEqual(mod.decode_branch(
            a32_bl(0x2500,0x2000),0x2500),0x2000)

    def test_branch_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"AL BL"):
            mod.decode_branch(0x0b000000,0x2500)

    def test_branch_wrong_link(self):
        with self.assertRaisesRegex(ValueError,"AL BL"):
            mod.decode_branch(0xea000000,0x2500)

    def test_raw_getword(self):
        self.assertEqual(mod.get_word(struct.pack("<I",0xe5d535b0),
                                      0x1000,0x1000),0xe5d535b0)

    def test_raw_getword_unaligned(self):
        with self.assertRaisesRegex(ValueError,"original section"):
            mod.get_word(struct.pack("<I",0xe5d535b0),0x1000,0x1002)

    def test_bounded_spans(self):
        self.assertFalse(mod.write_span_touches_pair(0x5ac,4))
        self.assertFalse(mod.write_span_touches_pair(0x5b2,3))
        self.assertTrue(mod.write_span_touches_pair(0x5ac,5))
        self.assertTrue(mod.write_span_touches_pair(0x5af,4))
        self.assertTrue(mod.write_span_touches_pair(0x5b0,1))
        self.assertTrue(mod.write_span_touches_pair(0x5b1,1))
        self.assertFalse(mod.write_span_touches_pair(0x5b2,0))

    def test_negative_span_rejected(self):
        with self.assertRaisesRegex(ValueError,"invalid"):
            mod.write_span_touches_pair(0x5b0,-1)

    def test_function_only_definition(self):
        body=("TRACE_DECOMP_BEGIN (GhidraScript)\n"
              "void FUN_01000000(void) { FUN_012be684(); }\n"
              "TRACE_DECOMP_END (GhidraScript)\n"
              "TRACE_DECOMP_BEGIN (GhidraScript)\n"
              "void FUN_012be684(void) { actual_reverse(); }\n"
              "TRACE_DECOMP_END (GhidraScript)")
        self.assertIn("actual_reverse",mod.function_c(body,0x012be684))

    def test_function_missing(self):
        with self.assertRaisesRegex(ValueError,"missing Ghidra"):
            mod.function_c("",0x012be684)


class RoundtripTests(unittest.TestCase):
    def test_both_models_pass(self):
        for s in mod.SPECS.values():
            with self.subTest(model=s.model):
                r=run(s)
                self.assertTrue(r["roundtrip_source_to_runtime_to_export_function_order"])
                self.assertEqual(r["original_a32_codec_format_sites_verified"],8)
                self.assertEqual(r["original_a32_parent_calls_verified"],3)
                self.assertFalse(r["gui_to_recorder_source_writer_proven"])
                self.assertFalse(r["bitstream_main10_proven"])
                self.assertFalse(r["sensor_4k60_proven"])

    def test_codec_source_distinct_from_gui(self):
        for spec in mod.SPECS.values():
            with self.subTest(spec=spec.model):
                r=run(spec)
                self.assertNotEqual(r["config_snapshot_codec"],r["gui_codec"])
                self.assertNotEqual(r["recorder_active_config_codec"],r["gui_codec"])

    def test_wrong_raw_forward_offset(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            d[s.forward_sites[0].address]=a32_byte(load=True,rn=5,rd=3,
                                                   offset=0x5b1)
        with self.assertRaisesRegex(ValueError,"012c9a40"):
            run(s,bad)

    def test_wrong_raw_reverse_offset(self):
        s=mod.SPECS["xt4"]
        def bad(d,p):
            d[s.reverse_sites[1].address]=a32_byte(load=False,rn=4,rd=3,
                                                   offset=0x5b1)
        with self.assertRaisesRegex(ValueError,"01297254"):
            run(s,bad)

    def test_wrong_raw_parent_call_target(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            d[0x0221d298]=a32_bl(0x0221d298,0x012be688)
        with self.assertRaisesRegex(ValueError,"unexpected call"):
            run(s,bad)

    def test_wrong_decompiler_order(self):
        s=mod.SPECS["xt4"]
        def bad(d,p):
            p[0]=p[0].replace("  FUN_%08x(iVar1);" % s.commit_wrapper,
                               "  IGNORE();",1)
        with self.assertRaisesRegex(ValueError,"Ghidra C forward"):
            run(s,bad)

    def test_wrong_exporter_param(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[0]=p[0].replace("FUN_%08x(iVar3)"%s.reverse_exporter,
                               "FUN_%08x(other)"%s.reverse_exporter)
        with self.assertRaisesRegex(ValueError,"output buffer"):
            run(s,bad)

    def test_wrong_working_commit(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[0]=p[0].replace("FUN_%08x(iVar1)" % s.commit_wrapper,
                               "FUN_%08x(iVar2)" % s.commit_wrapper)
        with self.assertRaisesRegex(ValueError,"working-pointer"):
            run(s,bad)

    def test_reverse_must_precede_copy(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            call="  FUN_%08x(%s);\n" % (s.reverse_exporter,s.dest_var)
            p[0]=p[0].replace(call,"")
            p[0]=p[0].replace("  FUN_%08x(%s + 0x5b2"%
                              (s.copy_function,s.dest_var),
                              call+"  FUN_%08x(%s + 0x5b2"%
                              (s.copy_function,s.dest_var))
        with self.assertRaisesRegex(ValueError,"reverse export must precede"):
            run(s,bad)

    def test_adjacent_copy_gap_missing(self):
        s=mod.SPECS["xt4"]
        def bad(d,p):
            p[0]=p[0].replace(s.dest_var+" + 0x5ac",
                               s.dest_var+" + 0x5b0")
        with self.assertRaisesRegex(ValueError,"adjacent source copies"):
            run(s,bad)

    def test_neighboring_copy_cannot_clobber_pair(self):
        s=mod.SPECS["xt4"]
        def bad(d,p):
            p[0]+="*(undefined1 *)(iVar4 + 0x5b0) = 7;\n"
        with self.assertRaisesRegex(ValueError,"overwrite"):
            run(s,bad)

    def test_missing_forward_codec_assignment(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[1]=p[1].replace("param_2[0x5b0]","param_2[0x5b1]")
        with self.assertRaisesRegex(ValueError,"snapshot-to-working"):
            run(s,bad)

    def test_missing_reverse_format_assignment(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[2]=p[2].replace("param_1[0x5b1]","param_1[0x5b3]")
        with self.assertRaisesRegex(ValueError,"active-to-export"):
            run(s,bad)

    def test_missing_mirror_memcpy(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[3]=p[3].replace("0x%x,param_1" % s.mirror,
                               "0x0,param_1")
        with self.assertRaisesRegex(ValueError,"mirror"):
            run(s,bad)

    def test_memcpy_size_under_codec_offset(self):
        s=replace(mod.SPECS["xt4"],copy_bytes=0x430)
        with self.assertRaisesRegex(ValueError,"bulk memcpy"):
            run(s)

    def test_runtime_getter_wrong_byte(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[4]=p[4].replace("DAT_%08x"%(s.active+s.working_offset),
                               "DAT_%08x"%(s.active+s.working_offset+1))
        with self.assertRaisesRegex(ValueError,"getter"):
            run(s,bad)

    def test_gui_alias_fails(self):
        s=replace(mod.SPECS["xs10"],gui_codec=0x01c25208)
        with self.assertRaisesRegex(ValueError,"conflated"):
            run(s)

    def test_source_pointer_literal_missing(self):
        s=mod.SPECS["xs10"]
        def bad(d,p):
            p[0]=p[0].replace("DAT_%08x"%s.snapshot_literal,
                               "DAT_DEADBEEF")
        with self.assertRaisesRegex(ValueError,"snapshot pointer"):
            run(s,bad)


if __name__=="__main__":
    unittest.main()

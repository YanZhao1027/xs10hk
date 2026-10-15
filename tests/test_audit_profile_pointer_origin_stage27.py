"""Synthetic A32 negative and positive tests for Phase27 profile-pointer audit.

No Fujifilm ROM bytes, keys, hardware access, live memory, or firmware patches.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_profile_pointer_origin_stage27 as mod


def movhalf(reg,value,top=False):
    return ((0xe3400000 if top else 0xe3000000) |
            (((value>>12)&15)<<16)|(reg<<12)|(value&0xfff))


def strldr(load,rn,rd,offset):
    return ((0xe5900000 if load else 0xe5800000) |
            (rn<<16)|(rd<<12)|offset)


def branch(at,target,cond=14,link=True):
    d=target-at-8
    if d%4 or not -(1<<25)<=d<(1<<25):
        raise ValueError("unencodable target")
    return ((cond<<28)|0x0a000000|
            (int(link)<<24)|((d>>2)&0xffffff))


def source_c(s):
    d=s.descriptor
    c="void FUN_%08x(void){\n"%s.init
    c+=("if (_DAT_%08x != 0x200) {error();}\n"%d)
    for dst,src in ((s.current_slot-4,d+0xc),
                    (s.current_slot,d+0x10),
                    (s.companion_slot,d+0x14)):
        c+=("_DAT_%08x = _DAT_%08x;\n"%(dst,src))
    if s.model=="xs10":
        c+="FUN_022b6de0(1,_DAT_02d9c2b0 + 0x34c);\n"
    else:
        c+="iVar5 = *(int *)(iVar3 + 0xac8);\n"
        c+="FUN_022235a0(1,iVar5 + 0x5b0,OTHER());\n"
    return c+"}\n"


def wrapped(c):
    return "TRACE_DECOMP_BEGIN (GhidraScript)\n"+c+"TRACE_DECOMP_END (GhidraScript)\n"


def fixture(s):
    a=s.init
    i={a:0xe92d4870,a+0x4:0xe28db010,a+0x8:0xe24dd014,
       a+0x20:movhalf(0,0x901c)}
    for off in (0xc,0x2c):
        i[a+off]=movhalf(3,s.descriptor&0xffff)
        i[a+off+4]=movhalf(3,(s.descriptor>>16)&0xffff,top=True)
    i[a+0x14]=0xe1d310b0
    i[a+0x18]=0xe3510c02
    i[a+0x1c]=branch(a+0x1c,a+0x2c,cond=0,link=False)
    # Both compared bodies differ in their error handler BL displacement.
    i[a+0x24]=branch(a+0x24,a+(0x100 if s.model=="xs10" else 0x104))
    i[a+0x28]=0xeafffffe
    i[a+0x34]=strldr(True,3,0,0xc)
    i[a+0x38]=0xe2832a03
    i[a+0x3c]=strldr(False,2,0,0xac0)
    i[a+0x40]=strldr(True,3,1,0x10)
    i[a+0x44]=strldr(False,2,1,0xac4)
    i[a+0x48]=strldr(True,3,3,0x14)
    i[a+0x4c]=strldr(False,2,3,0xac8)
    i[a+0x50]=0xe5d03028
    call_log=""
    call_ref=""
    for address,parent in s.callers:
        i[address]=branch(address,a)
        call_log+=wrapped("void FUN_%08x(void){\nFUN_%08x();\n}\n"%
                          (parent,a))
        call_ref+=("PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n"%
                   (address,a))
    slot=("SLOT_WRITE_CAND addr=%08x from=%08x type=WRITE func=%08x "
          "insn=str r1,[r2,#0xac4]\n"%
          (s.current_slot,a+0x44,a)
         )+("SLOT_SUMMARY addr=%08x refs=3 functions=3 "
             "types={READ=2, WRITE=1} mnemonic_counts={ldr=2, str=1}\n"%
             s.current_slot)
    origin=("SLOT_SUMMARY addr=%08x refs=111 functions=82 "
            "types={READ=111} mnemonic_counts={ldr=111}\n"%
            (s.descriptor+0x10))
    return {
        "words":i,
        "init":wrapped(source_c(s)),
        "callers":call_log,
        "callrefs":call_ref,
        "slotrefs":slot,
        "headerrefs":origin,
    }


def evaluate(s,mutate=None):
    f=fixture(s)
    if mutate:mutate(f)
    with patch.object(mod,"raw_word",
                      side_effect=lambda data,base,addr:f["words"][addr]):
        return mod.audit(s,bytes(12),f["init"],f["callers"],
                         f["callrefs"],f["slotrefs"],f["headerrefs"])


class A32Tests(unittest.TestCase):
    def test_movw_low_half(self):
        self.assertEqual(mod.mov_half(movhalf(3,0xb7e8),False,3),0xb7e8)
    def test_movt_high_half(self):
        self.assertEqual(mod.mov_half(movhalf(3,0x2d9,True),True,3),0x2d9)
    def test_mov_half_wrong_register(self):
        with self.assertRaisesRegex(ValueError,"MOVT/MOVW"):
            mod.mov_half(movhalf(4,0x2d9,True),True,3)
    def test_mov_half_wrong_kind(self):
        with self.assertRaisesRegex(ValueError,"MOVT/MOVW"):
            mod.mov_half(movhalf(3,0x2d9,False),True,3)
    def test_add_rotation(self):
        self.assertEqual(mod.dp_add(0xe2832a03,3,2),0x3000)
    def test_add_wrong_register(self):
        with self.assertRaisesRegex(ValueError,"ADD"):
            mod.dp_add(0xe2832a03,2,3)
    def test_immediate_decode_simple(self):
        self.assertEqual(mod.imm_decode(0xe2800008),8)
    def test_halfword_guard_branch(self):
        self.assertEqual(mod.arm_branch(branch(
            0x1000,0x1010,cond=0,link=False),0x1000,0,False),0x1010)
    def test_bl_backwards(self):
        self.assertEqual(mod.arm_branch(branch(
            0x2000,0x1100),0x2000,14,True),0x1100)
    def test_reject_wrong_condition(self):
        with self.assertRaisesRegex(ValueError,"opcode"):
            mod.arm_branch(branch(0x2000,0x1100),0x2000,0,True)
    def test_little_endian_original_word(self):
        self.assertEqual(mod.raw_word(struct.pack("<I",0xe2832a03),
                                      0x1000,0x1000),0xe2832a03)
    def test_unaligned_original_word(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            mod.raw_word(bytes(8),0x1000,0x1001)
    def test_outside_original_section(self):
        with self.assertRaisesRegex(ValueError,"original"):
            mod.raw_word(bytes(8),0x1000,0x1008)
    def test_memword_read(self):
        mod.memword(strldr(True,3,1,0x10),True,3,1,0x10)
    def test_memword_write(self):
        mod.memword(strldr(False,2,1,0xac4),False,2,1,0xac4)
    def test_memword_wrong_access(self):
        with self.assertRaisesRegex(ValueError,"LDR/STR"):
            mod.memword(strldr(True,3,1,0x10),False,3,1,0x10)
    def test_memword_wrong_offset(self):
        with self.assertRaisesRegex(ValueError,"LDR/STR"):
            mod.memword(strldr(False,2,1,0xac8),False,2,1,0xac4)
    def test_grep_c_function_definition_not_call(self):
        s=mod.SPECS["xs10"]
        code=wrapped("void FUN_10000000(void){FUN_02214738();}\n")
        code+=wrapped(source_c(s))
        self.assertIn("_DAT_02d987f8",mod.decompile_function(code,s.init))
    def test_missing_decompiled_function(self):
        with self.assertRaisesRegex(ValueError,"missing private"):
            mod.decompile_function("",0x02214738)
    def test_raw_strb_immediate_scanner(self):
        data=bytearray(20)
        struct.pack_into("<I",data,0,0xe5c325b0)
        struct.pack_into("<I",data,4,0xe5c325b1)
        struct.pack_into("<I",data,8,0xe5d325b0) # load byte, not store
        struct.pack_into("<I",data,12,0xe5c325b0)
        self.assertEqual(mod.scan_immediate_strb(data,0x1000,0x5b0),
                         [0x1000,0x100c])
    def test_strb_offset_no_structure_identity(self):
        s=mod.SPECS["xt4"]
        result=evaluate(s)
        self.assertFalse(result["STRB_candidates_equated_to_recorder_writers"])


class ProvenanceTests(unittest.TestCase):
    def test_xs10_and_xt4_synthetic_pointer_chain(self):
        for spec in mod.SPECS.values():
            with self.subTest(model=spec.model):
                r=evaluate(spec)
                self.assertTrue(r["exact_direct_slot_writer_verified"])
                self.assertEqual(r["bootstrap_event_hook_Bls_verified"],2)
                self.assertEqual(r["current_buffer_pointer_runtime_value"],
                                 "UNKNOWN")
                self.assertEqual(r["input_buffer_codec_at_offset_0x5b0"],
                                 "UNKNOWN")
                self.assertFalse(r["gui_to_input_buffer_codec_assignment_proven"])
                self.assertFalse(r["firmware_patch_created"])
                self.assertFalse(r["camera_modified"])

    def test_source_descriptor_header_xs10(self):
        r=evaluate(mod.SPECS["xs10"])
        self.assertEqual(r["input_buffer_pointer_header_field"],"0x02d987f8")
        self.assertEqual(r["current_buffer_pointer_slot"],"0x02d9c2ac")
        self.assertEqual(r["secondary_buffer_pointer_slot"],"0x02d9c2b0")

    def test_source_descriptor_header_xt4(self):
        r=evaluate(mod.SPECS["xt4"])
        self.assertEqual(r["input_buffer_pointer_header_field"],"0x02d0bf58")
        self.assertEqual(r["current_buffer_pointer_slot"],"0x02d0fa0c")

    def test_invalid_guard_signature(self):
        spec=mod.SPECS["xs10"]
        def mutate(f):f["words"][spec.init+0x18]=0xe3510c03
        with self.assertRaisesRegex(ValueError,"magic check"):
            evaluate(spec,mutate)

    def test_wrong_guard_condition(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["words"][s.init+0x1c]=branch(
            s.init+0x1c,s.init+0x2c,cond=1,link=False)
        with self.assertRaisesRegex(ValueError,"opcode"):
            evaluate(s,mutate)

    def test_invalid_signature_halfword_load(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["words"][s.init+0x14]=0xe1d300b0
        with self.assertRaisesRegex(ValueError,"halfword"):
            evaluate(s,mutate)

    def test_reject_changed_signature_failure_branch(self):
        s=mod.SPECS["xt4"]
        def mutate(f):f["words"][s.init+0x28]=0xeafffffd
        with self.assertRaisesRegex(ValueError,"self-loop"):
            evaluate(s,mutate)

    def test_descriptor_low_half_wrong(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["words"][s.init+0xc]=movhalf(
            3,(s.descriptor+4)&0xffff)
        with self.assertRaisesRegex(ValueError,"base MOV"):
            evaluate(s,mutate)

    def test_descriptor_high_half_wrong(self):
        s=mod.SPECS["xt4"]
        def mutate(f):f["words"][s.init+0x30]=movhalf(
            3,(s.descriptor>>16)+1,top=True)
        with self.assertRaisesRegex(ValueError,"base MOV"):
            evaluate(s,mutate)

    def test_reject_copy_from_plus14_instead_of_plus10(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["words"][s.init+0x40]=strldr(
            True,3,1,0x14)
        with self.assertRaisesRegex(ValueError,"LDR/STR"):
            evaluate(s,mutate)

    def test_reject_ac8_destination_instead_of_ac4(self):
        s=mod.SPECS["xt4"]
        def mutate(f):f["words"][s.init+0x44]=strldr(
            False,2,1,0xac8)
        with self.assertRaisesRegex(ValueError,"LDR/STR"):
            evaluate(s,mutate)

    def test_reject_wrong_second_buffer_write(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["words"][s.init+0x4c]=strldr(
            False,2,3,0xacc)
        with self.assertRaisesRegex(ValueError,"LDR/STR"):
            evaluate(s,mutate)

    def test_reject_bad_owner_3000(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["words"][s.init+0x38]=0xe2832a04
        with self.assertRaisesRegex(ValueError,"owner base offset"):
            evaluate(s,mutate)

    def test_missing_c_writer_edge(self):
        s=mod.SPECS["xs10"]
        def mutate(f):
            f["init"]=f["init"].replace(
                "_DAT_02d9c2ac = _DAT_02d987f8",
                "_DAT_02d9c2ac = UNKNOWN")
        with self.assertRaisesRegex(ValueError,"assignment"):
            evaluate(s,mutate)

    def test_missing_garbage_magic_guard(self):
        s=mod.SPECS["xt4"]
        def mutate(f):
            f["init"]=f["init"].replace(
                "_DAT_02d0bf48 != 0x200",
                "_DAT_02d0bf48 != 0x100")
        with self.assertRaisesRegex(ValueError,"magic guard"):
            evaluate(s,mutate)

    def test_github_gui_address_not_pointer(self):
        s=replace(mod.SPECS["xs10"],gui_codec=0x02d9c2ac)
        with self.assertRaisesRegex(ValueError,"GUI value"):
            evaluate(s)

    def test_upstream_call_target_reject(self):
        s=mod.SPECS["xs10"]
        addr=s.callers[0][0]
        def mutate(f):f["words"][addr]=branch(addr,s.init+4)
        with self.assertRaisesRegex(ValueError,"event hook BL"):
            evaluate(s,mutate)

    def test_upstream_ghidra_call_missing(self):
        s=mod.SPECS["xt4"]
        def mutate(f):f["callrefs"]=f["callrefs"].replace(
            "from=02143f14","from=02143f18")
        with self.assertRaisesRegex(ValueError,"xref absent"):
            evaluate(s,mutate)

    def test_missing_event_caller_definition(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["callers"]=""
        with self.assertRaisesRegex(ValueError,"Ghidra function"):
            evaluate(s,mutate)

    def test_direct_pointer_slot_writer_xref_missing(self):
        s=mod.SPECS["xs10"]
        def mutate(f):f["slotrefs"]=f["slotrefs"].replace(
            "from=0221477c","from=02214780")
        with self.assertRaisesRegex(ValueError,"direct slot writer"):
            evaluate(s,mutate)

    def test_slot_extra_write_requires_rescan(self):
        s=mod.SPECS["xs10"]
        def mutate(f):
            f["slotrefs"]=f["slotrefs"].replace(
                "refs=3","refs=4").replace(
                "READ=2, WRITE=1","READ=2, WRITE=2")
        with self.assertRaisesRegex(ValueError,"more than one"):
            evaluate(s,mutate)

    def test_descriptor_new_direct_write_forces_review(self):
        s=mod.SPECS["xs10"]
        def mutate(f):
            f["headerrefs"]=f["headerrefs"].replace(
                "READ=111","READ=110, WRITE=1")
        with self.assertRaisesRegex(ValueError,"new direct source"):
            evaluate(s,mutate)

    def test_xref_summary_counts_corrupt(self):
        s=mod.SPECS["xt4"]
        def mutate(f):
            f["slotrefs"]=f["slotrefs"].replace(
                "refs=3","refs=4")
        with self.assertRaisesRegex(ValueError,"aggregation"):
            evaluate(s,mutate)

    def test_secondary_buffer_offsets_not_codec(self):
        s=mod.SPECS["xs10"]
        def mutate(f):
            f["init"]=f["init"].replace(
                "_DAT_02d9c2b0 + 0x34c",
                "_DAT_02d9c2b0 + 0x5b0")
        with self.assertRaisesRegex(ValueError,"secondary-buffer offsets"):
            evaluate(s,mutate)

    def test_xt4_secondary_pointer_must_not_be_primary(self):
        s=mod.SPECS["xt4"]
        def mutate(f):
            f["init"]=f["init"].replace(
                "iVar3 + 0xac8","iVar3 + 0xac4")
        with self.assertRaisesRegex(ValueError,"secondary pointer"):
            evaluate(s,mutate)

    def test_header_xref_missing(self):
        s=mod.SPECS["xt4"]
        def mutate(f):f["headerrefs"]=""
        with self.assertRaisesRegex(ValueError,"summary absent"):
            evaluate(s,mutate)

    def test_unknown_gui_path_not_overclaimed(self):
        r=evaluate(mod.SPECS["xt4"])
        self.assertFalse(r["gui_to_input_buffer_codec_assignment_proven"])
        self.assertTrue(r["cannot_exclude_alias_or_external_header_initializers"])


class HomologyTests(unittest.TestCase):
    def test_exactly_five_differences(self):
        x=fixture(mod.SPECS["xs10"])["words"]
        y=fixture(mod.SPECS["xt4"])["words"]
        with patch.object(mod,"raw_word",
                side_effect=lambda data,base,addr:(x if base==0x01eaf000
                                                  else y)[addr]):
            out=mod.crosscheck_homologous_blocks(b"",b"")
        self.assertEqual(out["identical_words"],16)
        self.assertEqual(out["relocation_or_address_differences"],
                         ["0xc","0x10","0x24","0x2c","0x30"])

    def test_extra_new_instruction_difference_fails(self):
        x=fixture(mod.SPECS["xs10"])["words"]
        y=fixture(mod.SPECS["xt4"])["words"]
        s=mod.SPECS["xt4"]
        y[s.init+0x40]=strldr(True,3,1,0x14)
        with patch.object(mod,"raw_word",
                side_effect=lambda data,base,addr:(x if base==0x01eaf000
                                                  else y)[addr]):
            with self.assertRaisesRegex(ValueError,"diverged"):
                mod.crosscheck_homologous_blocks(b"",b"")

    def test_header_guard_cross_model_same(self):
        x=fixture(mod.SPECS["xs10"])["words"]
        y=fixture(mod.SPECS["xt4"])["words"]
        for off in (0x14,0x18,0x1c,0x28,0x34,0x38,0x3c,
                    0x40,0x44,0x48,0x4c,0x50):
            with self.subTest(off=off):
                self.assertEqual(x[mod.SPECS["xs10"].init+off],
                                 y[mod.SPECS["xt4"].init+off])


if __name__=="__main__":
    unittest.main()

"""Stage46 all-synthetic original-ROM/mode-record audits.

No vendor bytes or decompilation is included: fake Section1/2 literals are
synthetic short b'TOY_*' markers, toy record payload bytes are 0xA5, and the
toy 37x5 dimension LUT is constructed from scratch. Exercises the auditor,
not an actual camera, sensor, firmware patch or V61 ISA.
"""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage46_joint_movie_mode_matrix as a

def mk_record(frame_class=0,mode_key=0x0207,fps=6,variant=1):
    v=bytearray(b"\xa5"*a.STRIDE)
    v[0]=frame_class
    v[1]=mode_key&0xff
    v[2]=(mode_key>>8)&0xff
    v[3]=fps
    v[4]=variant
    return bytes(v)

def mk_dims():
    wa=bytearray(a.DIM_BYTES)
    ha=bytearray(a.DIM_BYTES)
    # All 37x5 entries synthetic nonzero (not vendor LUT values).
    for row in range(a.DIM_BYTES//4):
        struct.pack_into("<I",wa,row*4,16)
        struct.pack_into("<I",ha,row*4,16)
    for category,column,w,h in (
       (7,4,4096,2160),(7,2,3840,2160),
       (6,4,2048,1080),(6,2,1920,1080)):
        struct.pack_into("<I",wa,(category*5+column)*4,w)
        struct.pack_into("<I",ha,(category*5+column)*4,h)
    return bytes(wa),bytes(ha)

def mk_matrix():
    out=[]
    # Six independent mock groups: 18 4096x2160, 18 3840x2160,
    # 18 2048x1080, 42 1920x1080. All 96 rows fake 0xA5-padded.
    for dims_idx,(category,second,count,cls,variants) in enumerate((
       (7,7,18,0,(1,2,3)),
       (7,2,18,0,(1,2,3)),
       (6,7,18,0,(0,1,2)),
       (6,2,18,0,(0,1,2)),
       (6,2,18,1,(0,1,2)),
       (6,2,6,2,(2,)),
    )):
        del dims_idx
        for fps in range(1,7):
            for variant in variants:
                out.append(mk_record(cls,category|(second<<8),fps,variant))
    assert len(out)==96
    return b"".join(out)+b"\xff"

def fn(entry,body="return 0;",returns="void"):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"+
        "%s FUN_%08x(void)\n{\n%s\n}\n"%(returns,entry,body)+
        "TRACE_DECOMP_END (GhidraScript)\n")

def g_fake(m):
    f=(
       "if (DAT_%08x != -1) { }\n"%m.movie_table+
       "pcVar10 = &DAT_%08x;\n"%m.movie_table+
       "pcVar10 = pcVar10 + 0x40;\n"
       "cVar1 = *(char *)(*(int *)(param_1 + 0x6018) + 0x5f5);\n"
       "if ((byte)(cVar1 - 1U) < 2) cVar2=*(char *)(param_1 + 0x5c7);\n"
       "else cVar2=*(char *)(param_1 + 0x5c6);\n"
       "if ((((cVar1 == cVar9) && (*(short *)(param_1 + 0xadd8) == *(short *)(pcVar10 + 1))) &&\n"
       "     (pcVar10[3] == cVar2)) && (*(char *)(param_1 + 0x%x) == pcVar10[4])) {\n"%m.fps_variant_offset+
       "uVar4 = FUN_%08x(pcVar10[1],pcVar10[2]);\n"%m.width_lookup+
       "*(short *)(*(int *)(param_1 + 0x6018) + 0x600) = uVar4;\n"
       "uVar4 = FUN_%08x(pcVar10[1],pcVar10[2]);\n"%m.height_lookup+
       "*(short *)(*(int *)(param_1 + 0x6018) + 0x602) = uVar4;\n"
       "}\n")
    # Fake classes include BOTH classifiers with real signatures only; none
    # of the original OEM instruction bytes or Ghidra C are included.
    initer=(
      "x=(iVar8 + 0x6018) = _DAT_%08x + 8;\n"%m.source_mode_global+
      "FUN_%08x(cVar1);\n"%m.highspeed_classifier+
      "*(int *)(iVar8 + 0x5f5) = 0;\n"
      "*(int *)(iVar8 + 0x5f5) = uVar4;\n"
      "FUN_%08x(iVar8);\n"%m.frame_matcher
    )
    lookups=(
      fn(m.width_lookup,
        "if (param_2 == 3) iVar1=3;\nelse iVar1 = 4;\n"
        "return *(&DAT_%08x + (param_1 * 5 + iVar1) * 4);\n"%m.widths,
        "undefined4")+
      fn(m.height_lookup,
        "if (param_2 == 3) iVar1=3;\nelse iVar1 = 4;\n"
        "return *(&DAT_%08x + (param_1 * 5 + iVar1) * 4);\n"%m.heights,
        "undefined4")+
      fn(m.highspeed_classifier,
        "switch(a) {case 2:case 3: return 1; case 4:case 7:return 0;}",
        "undefined4")+
      fn(m.movie4k_classifier,
        "switch(a) {case 1:case 4:case 5:case 6:case 7:return 1;}",
        "undefined4")
    )
    # The function exactly matches source offsets but not real body/bytecode.
    setup=(
      "w=(iVar7 + 0x602); h=(iVar7 + 0x600);\n"
      "if (*(char *)(param_1 + 0xadda) == 1) src=0xca0000;\n"
      "else src=0xd08000;\n"
      "fpa=(param_1 + 0x5c6); fpb=(param_1 + 0x5c7);\n"
    )
    xrefs=(
      "PROBE_TARGET addr=%08x refs=4\n"%m.movie_table+
      "PROBE_TARGET addr=%08x refs=1\n"%m.widths+
      "PROBE_TARGET addr=%08x refs=1\n"%m.heights+
      "PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n"%(
          m.resolver_caller_bl,m.frame_matcher))
    return {
        "candidates":fn(m.frame_matcher,f)+fn(m.mode_initializer,initer),
        "lookups":lookups,
        "movie":fn(m.movie_setup,setup,"undefined4"),
        "xref":xrefs,
    }

class SourceParsing(unittest.TestCase):
    def test_default_boundaries(self):
        self.assertEqual((a.RECORDS,a.STRIDE,a.DIM_BYTES),(96,64,740))
    def test_records_head_known_fake(self):
        t=mk_matrix()
        self.assertEqual(t[0],0)
        self.assertEqual(t[-1],0xff)
        self.assertEqual(t[5],0xa5)  # synthetic marker, never vendor
    def test_no_vendor_sha_artificial_matrix(self):
        self.assertNotEqual(hashlib.sha256(mk_matrix()[:-1]).hexdigest(),a.BODY_SHA)
    def test_reader_exact_count(self):
        self.assertEqual(len(a.read_records(mk_matrix())),96)
    def test_short_records_rejected(self):
        with self.assertRaisesRegex(ValueError,"short"):
            a.read_records(mk_matrix()[:-2])
    def test_bad_count_0(self):
        with self.assertRaisesRegex(ValueError,"count"):
            a.read_records(b"",0)
    def test_bad_count_1025(self):
        with self.assertRaisesRegex(ValueError,"count"):
            a.read_records(b"",1025)
    def test_early_sentinel(self):
        r=bytearray(mk_matrix());r[64]=255
        with self.assertRaisesRegex(ValueError,"early"):
            a.read_records(bytes(r))
    def test_missing_terminal(self):
        r=bytearray(mk_matrix());r[-1]=0
        with self.assertRaisesRegex(ValueError,"sentinel"):
            a.read_records(bytes(r))
    def test_no_terminal_when_opt_out(self):
        r=mk_matrix()[:-1]
        self.assertEqual(len(a.read_records(r,require_terminal=False)),96)
    def test_mode_key_endianness(self):
        rows=a.read_records(mk_matrix())
        self.assertEqual(rows[33][1]|rows[33][2]<<8,0x0207)
        self.assertEqual(rows[15][1]|rows[15][2]<<8,0x0707)
    def test_lookup_3840_key(self):
        w,h=mk_dims()
        self.assertEqual(a.lookup_width_height(mk_record(mode_key=0x0207),w,h),(3840,2160))
    def test_lookup_4096_key(self):
        w,h=mk_dims()
        self.assertEqual(a.lookup_width_height(mk_record(mode_key=0x0707),w,h),(4096,2160))
    def test_lookup_1920_key(self):
        w,h=mk_dims()
        self.assertEqual(a.lookup_width_height(mk_record(mode_key=0x0206),w,h),(1920,1080))
    def test_lookup_2048_key(self):
        w,h=mk_dims()
        self.assertEqual(a.lookup_width_height(mk_record(mode_key=0x0706),w,h),(2048,1080))
    def test_lookup_7_maps_to_column4(self):
        w,h=mk_dims()
        self.assertEqual(a.lookup_width_height(mk_record(mode_key=0x0707),w,h),(4096,2160))
    def test_lookup_2_maps_to_column2(self):
        w,h=mk_dims()
        self.assertEqual(a.lookup_width_height(mk_record(mode_key=0x0207),w,h),(3840,2160))
    def test_zero_width_fails(self):
        w,h=mk_dims();w=bytearray(w);struct.pack_into("<I",w,(7*5+2)*4,0)
        with self.assertRaisesRegex(ValueError,"zero"):
            a.lookup_width_height(mk_record(mode_key=0x0207),bytes(w),h)
    def test_zero_height_fails(self):
        w,h=mk_dims();h=bytearray(h);struct.pack_into("<I",h,(7*5+2)*4,0)
        with self.assertRaisesRegex(ValueError,"zero"):
            a.lookup_width_height(mk_record(mode_key=0x0207),w,bytes(h))
    def test_bad_width_table_size(self):
        w,h=mk_dims()
        with self.assertRaisesRegex(ValueError,"size"):
            a.lookup_width_height(mk_record(),w[:-1],h)
    def test_bad_height_table_size(self):
        w,h=mk_dims()
        with self.assertRaisesRegex(ValueError,"size"):
            a.lookup_width_height(mk_record(),w,h[:-1])
    def test_bad_record_size(self):
        w,h=mk_dims()
        with self.assertRaisesRegex(ValueError,"size"):
            a.lookup_width_height(b"",w,h)
    def test_out_of_range_width_row(self):
        w,h=mk_dims()
        with self.assertRaisesRegex(ValueError,"beyond"):
            a.lookup_width_height(mk_record(mode_key=0x02ff),w,h)
    def test_good_minimal_row_framing(self):
        self.assertEqual(a.read_records(mk_record()+b"\xff",count=1)[0][:5],
                         mk_record()[:5])
    def test_zero_length_section_slice_rejects_oob(self):
        with self.assertRaisesRegex(ValueError,"out-of-bounds"):
            a.section_slice(b"\x00"*4,0x1000,0x1010,2)
    def test_extract_span(self):
        self.assertEqual(a.section_slice(b"ABCDEFG",0x1000,0x1002,3),b"CDE")

class LookupMatch(unittest.TestCase):
    def setUp(self):
        self.rows=a.read_records(mk_matrix())
    def test_3840_59_94_variant1(self):
        self.assertEqual(a.match_record(self.rows,0,0x0207,6,1),[33])
    def test_3840_59_94_variant2(self):
        self.assertEqual(a.match_record(self.rows,0,0x0207,6,2),[34])
    def test_3840_59_94_variant3(self):
        self.assertEqual(a.match_record(self.rows,0,0x0207,6,3),[35])
    def test_4096_59_94_variant1(self):
        self.assertEqual(a.match_record(self.rows,0,0x0707,6,1),[15])
    def test_4096_59_94_variant2(self):
        self.assertEqual(a.match_record(self.rows,0,0x0707,6,2),[16])
    def test_4096_59_94_variant3(self):
        self.assertEqual(a.match_record(self.rows,0,0x0707,6,3),[17])
    def test_wrong_frame_class(self):
        self.assertEqual(a.match_record(self.rows,1,0x0207,6,1),[])
    def test_wrong_fps(self):
        self.assertEqual(a.match_record(self.rows,0,0x0207,5,1),[30])
    def test_wrong_mode_key(self):
        self.assertEqual(a.match_record(self.rows,0,0x0206,6,1),[70])
    def test_wrong_variant(self):
        self.assertEqual(a.match_record(self.rows,0,0x0207,6,0),[])
    def test_sentinel_never_matches(self):
        self.assertEqual(a.match_record(self.rows,255,0x0207,6,1),[])
    def test_bad_input_negative(self):
        with self.assertRaisesRegex(ValueError,"invalid"):
            a.match_record(self.rows,-1,0x0207,6,1)
    def test_bad_key_overflow(self):
        with self.assertRaisesRegex(ValueError,"invalid"):
            a.match_record(self.rows,0,65536,6,1)
    def test_bad_fps_overflow(self):
        with self.assertRaisesRegex(ValueError,"invalid"):
            a.match_record(self.rows,0,0x0207,256,1)
    def test_bad_variant(self):
        with self.assertRaisesRegex(ValueError,"invalid"):
            a.match_record(self.rows,0,0x0207,6,999)
    def test_16_fps6_records(self):
        self.assertEqual(sum(r[3]==6 for r in self.rows),16)
    def test_6_4k59_94_records(self):
        w,h=mk_dims()
        self.assertEqual(sum(r[3]==6 and a.lookup_width_height(r,w,h)[1]==2160 for r in self.rows),6)
    def test_modes_do_not_contain_HEVC_bit(self):
        self.assertEqual({r[4] for r in self.rows[:18]},{1,2,3})
        # The 4-match lookup has NO read of MovieSetup+0xADDA codec.

class FakeGhidra(unittest.TestCase):
    def test_both_model_fake_ghidra_positive(self):
        for m in a.MODELS.values():
            with self.subTest(m=m.name):
                v=a.audit_ghidra(m,g_fake(m))
                self.assertTrue(v["movie_HEVC_selector_0xADDA_not_a_direct_table_match_key"])
                self.assertFalse(v["upstream_GUI_or_sensor_gate_excluded"])
    def test_public_no_generated_camera_4k60_claim(self):
        for m in a.MODELS.values():
            v=a.audit_ghidra(m,g_fake(m))
            self.assertFalse(v["upstream_GUI_or_sensor_gate_excluded"])

def mutated_decomp(model,part,old,new):
    def t(self):
        m=a.MODELS[model]
        logs=g_fake(m)
        assert old in logs[part],(part,old)
        logs[part]=logs[part].replace(old,new)
        with self.assertRaises(ValueError):
            a.audit_ghidra(m,logs)
    return t

mutations=(
 ("candidates"," != -1"," != 0"),
 ("candidates","pcVar10 = &DAT_","pcVar10 = &WRONG_"),
 ("candidates","pcVar10 = pcVar10 + 0x40;","pcVar10 = pcVar10 + 0x48;"),
 ("candidates","param_1 + 0x6018","param_1 + 0x6014"),
 ("candidates","+ 0x5f5","+ 0x5f4"),
 ("candidates","cVar1 - 1U","cVar1 - 2U"),
 ("candidates","param_1 + 0x5c7","param_1 + 0x5c9"),
 ("candidates","param_1 + 0x5c6","param_1 + 0x5c9"),
 ("candidates","cVar1 == cVar9","cVar1 != cVar9"),
 ("candidates","param_1 + 0xadd8","param_1 + 0xadda"),
 ("candidates","pcVar10 + 1","pcVar10 + 2"),
 ("candidates","pcVar10[3] == cVar2","pcVar10[2] == cVar2"),
 ("candidates","pcVar10[4]","pcVar10[5]"),
 ("candidates","+ 0x600","+ 0x606"),
 ("candidates","+ 0x602","+ 0x608"),
 ("lookups","iVar1 = 4;","iVar1 = 5;"),
 ("lookups","param_2 == 3","param_2 == 4"),
 ("lookups","param_1 * 5","param_1 * 6"),
 ("lookups"," * 4"," * 8"),
 ("lookups","case 2:","case 9:"),
 ("lookups","case 3:","case 10:"),
 ("lookups","case 7:","case 8:"),
 ("movie","iVar7 + 0x600","iVar7 + 0x610"),
 ("movie","iVar7 + 0x602","iVar7 + 0x612"),
 ("movie","param_1 + 0xadda","param_1 + 0xadd8"),
 ("movie","0xca0000","0xca1000"),
 ("movie","0xd08000","0xd09000"),
 ("movie","param_1 + 0x5c6","param_1 + 0x5b6"),
 ("movie","param_1 + 0x5c7","param_1 + 0x5b7"),
 ("xref","type=UNCONDITIONAL_CALL","type=WRITE"),
 ("xref","refs=4","refs=3"),
)
for j,(section,old,new) in enumerate(mutations):
    m=list(a.MODELS)[j%2]
    setattr(FakeGhidra,"test_fake_Ghidra_mutation_%02d_%s"%(j,m),
            mutated_decomp(m,section,old,new))

# Crossproduct synthetic 96 entries: every row's decoded resolution, FPS,
# class and variant must match the records generated in the test, never vendor.
def build_row_test(i):
    def test(self):
        rows=a.read_records(mk_matrix())
        row=rows[i]
        widths,heights=mk_dims()
        w,h=a.lookup_width_height(row,widths,heights)
        if i<18:expected=(4096,2160)
        elif i<36:expected=(3840,2160)
        elif i<54:expected=(2048,1080)
        else:expected=(1920,1080)
        self.assertEqual((w,h),expected)
        self.assertEqual(a.match_record(rows,row[0],row[1]|row[2]<<8,row[3],row[4]),[i])
        self.assertEqual(row[3],((i%18)//3+1) if i<90 else i-89)
    return test
for row in range(a.RECORDS):
    setattr(LookupMatch,"test_fictional_mode_matrix_%02d"%row,build_row_test(row))

if __name__=="__main__": unittest.main()

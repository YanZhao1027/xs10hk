"""Stage47 synthetic-only fault injection: one-bit key override and codec origin.

No original vendor ROM bytes, live X-S10 video, firmware patch, device, RAM
or Ghidra proprietary database. All ARM words are per-site toy fixtures;
all mode records and decomp-like snippets are generated inside this test.
"""
from pathlib import Path
from unittest.mock import patch
import hashlib
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage47_mode_key_codec_ingress as a
import audit_stage46_joint_movie_mode_matrix as b

def fake_bl(src,dest):
    d=dest-src-8
    assert d%4==0 and abs(d)<0x2000000
    return 0xeb000000 | ((d//4)&0xffffff)

def test_words(m):
    out={}
    for name,val in a.COMMON_WORDS.items():
        if name=="store_six":site=m.low_cond
        elif name=="store_low":site=m.low_src
        elif name=="store_high":site=m.high_src
        elif name=="store_codec":site=m.codec_store
        else:site=a.MORE_SITES[m.name][name]
        out[site]=val
    out.update(a.GETTER_WORDS[m.name])
    out[m.classifier_bl]=fake_bl(m.classifier_bl,m.classifier)
    out[m.getter_bl]=fake_bl(m.getter_bl,m.getter_fn)
    return out

def fake_function(fn,body):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
            "void FUN_%08x(void)\n{\n%s\n}\n"%(fn,body)+
            "TRACE_DECOMP_END (GhidraScript)\n")

def gh(m):
    globalsrc="_DAT_%08x"%m.mode_global
    writer=(
      "iVar6 = FUN_%08x(*(undefined1 *)(%s + 0xa8c));\n"%(
         m.classifier,globalsrc)+
      "if ((iVar6 == 0) || (*(char *)(%s + 0xa8e) != '\\x01')) {\n"%globalsrc+
      "*(undefined1 *)(iVar8 + 0xadd8) = *(undefined1 *)(iVar8 + 0x5bd);\n"
      "} else { *(undefined1 *)(iVar8 + 0xadd8) = 6; }\n"
      "*(undefined1 *)(iVar8 + 0xadd9) = *(undefined1 *)(iVar8 + 0x5be);\n"
      "uVar4 = FUN_%08x();\n"%m.getter_fn+
      "*(undefined1 *)(iVar8 + 0xadda) = uVar4;\n"
      "switch(cVar2) { case '\\x06': uVar7 = 0x3c; break; }\n")
    classifier=(
     "switch(param_1) { case 1: case 2: case 3: return 0;\n"
     "case 4: case 5: case 6: case 7: return 1; }\n")
    getter="return DAT_%08x;\n"%m.codec_global
    movie="v=*(char *)(param_1 + 0xadda); src=0xca0000; other=0xd08000;\n"
    insns={
      m.low_cond:"strbeq r2,[r3,#0xdd8]",
      m.low_src:"strb r2,[r3,#0xdd8]",
      m.high_src:"strb r3,[r5,#0xdd9]",
      m.getter_bl:"bl 0x%08x"%m.getter_fn,
      m.codec_store:"strb r0,[r5,#0xdda]",
    }
    asm="".join("TRACE_INSN %08x %s\n"%(site,text) for site,text in insns.items())
    return {
      "mode":fake_function(m.writer_fn,writer)+fake_function(m.getter_fn,getter),
      "lookup":fake_function(m.classifier,classifier),
      "setup":fake_function(0x00000000,movie).replace(
           "FUN_00000000","FUN_%08x"%a.st45.MODELS[m.name].movie_fn),
      "asm":asm,
    }

def make_row(low,high,fps=6,variant=1):
    row=bytearray(b"\xa5"*b.STRIDE)
    row[0]=0;row[1]=low;row[2]=high;row[3]=fps;row[4]=variant
    return bytes(row)

def make_table():
    allrows=[make_row(0,0,1,0) for _ in range(b.RECORDS)]
    allrows[15]=make_row(7,7)
    allrows[33]=make_row(7,2)
    allrows[52]=make_row(6,7)
    allrows[70]=make_row(6,2)
    return b"".join(allrows)+b"\xff"

def make_dim():
    w=bytearray(b.DIM_BYTES)
    h=bytearray(b.DIM_BYTES)
    for idx in range(b.DIM_BYTES//4):
        struct.pack_into("<I",w,idx*4,16)
        struct.pack_into("<I",h,idx*4,16)
    for r,c,width,height in ((7,2,3840,2160),(7,4,4096,2160),
                              (6,2,1920,1080),(6,4,2048,1080)):
        struct.pack_into("<I",w,(r*5+c)*4,width)
        struct.pack_into("<I",h,(r*5+c)*4,height)
    return bytes(w),bytes(h)

def test_table(m,mutation=None):
    toy_records=make_table()
    w,h=make_dim()
    old=b.MODELS[m.name]
    arrays={
      (old.movie_table,b.STRIDE*b.RECORDS+1):toy_records,
      (old.widths,b.DIM_BYTES):w,
      (old.heights,b.DIM_BYTES):h,
    }
    if mutation:mutation(arrays)
    def extract(_binary,_base,at,n):
        return arrays[(at,n)]
    def sha(blob):
        digest=hashlib.sha256(blob).hexdigest()
        if blob==toy_records[:b.STRIDE*b.RECORDS]:digest=b.BODY_SHA
        if blob==w:digest=b.WIDTH_SHA
        if blob==h:digest=b.HEIGHT_SHA
        return type("Hash",(),{"hexdigest":lambda self:digest})()
    with patch.object(a.st46,"section_slice",side_effect=extract),\
         patch.object(a,"sha256",side_effect=sha):
        return a.check_table_crossing(m,b"TOY-S1",b"TOY-S2")

def toy_gh(m,mutate=None):
    logs=gh(m)
    if mutate:mutate(logs)
    return a.validate_ghidra(m,logs)

class Semantics(unittest.TestCase):
    def test_codec_global_distinct_xs10_xt4(self):
        self.assertNotEqual(a.MODELS["xs10"].codec_global,a.MODELS["xt4"].codec_global)
    def test_4k_and_flag1_force_six(self):
        self.assertEqual(a.compute_key(True,1,7,2),0x0206)
    def test_4k_and_flag2_preserves_low7(self):
        self.assertEqual(a.compute_key(True,2,7,2),0x0207)
    def test_4k_and_flag0_preserves_low7(self):
        self.assertEqual(a.compute_key(True,0,7,7),0x0707)
    def test_non4k_and_flag1_preserves_original(self):
        self.assertEqual(a.compute_key(False,1,7,2),0x0207)
    def test_override_ignores_source_low_when_4k_flag1(self):
        for x in (0,1,3,6,7,0xff):
            self.assertEqual(a.compute_key(True,1,x,2),0x0206)
    def test_override_never_changes_high_byte(self):
        for hi in (0,1,2,6,7,64,255):
            self.assertEqual(a.compute_key(True,1,7,hi)>>8,hi)
    def test_validate_bad_class_negative(self):
        with self.assertRaisesRegex(ValueError,"byte"):
            a.compute_key(True,1,-1,2)
    def test_validate_bad_high_overflow(self):
        with self.assertRaisesRegex(ValueError,"byte"):
            a.compute_key(True,1,7,256)
    def test_validate_bad_flag_overflow(self):
        with self.assertRaisesRegex(ValueError,"byte"):
            a.compute_key(True,256,7,2)
    def test_validate_bad_nonint(self):
        with self.assertRaisesRegex(ValueError,"byte"):
            a.compute_key(True,1,7.5,2)
    def test_model_flags_unproven(self):
        for m in a.MODELS.values():
            out=toy_gh(m)
            self.assertFalse(out["X_S10_GUI_4K60_or_HEVC_joint_access_proven"])
            self.assertFalse(out["mode_flag_A8E_hardware_or_menu_semantics_resolved"])
            self.assertFalse(out["real_Main10_SPS_observed"])
            self.assertFalse(out["camera_or_ROM_modified"])
    def test_2_models_core_toy_A32_positive(self):
        for m in a.MODELS.values():
            words=test_words(m)
            x=a.check_a32(m,words.__getitem__)
            self.assertTrue(x["codec_getter_3_A32_source_words_verified"])
    def test_2_models_core_Ghidra_positive(self):
        for m in a.MODELS.values():
            result=toy_gh(m)
            self.assertTrue(result["4K_type_and_flag1_forces_low_mode_key_6"])
    def test_2_models_source_crossing_4k_to_1080_toy(self):
        for m in a.MODELS.values():
            out=test_table(m)
            self.assertEqual(out["high_key_2"]["preserve_low7"]["size"],[3840,2160])
            self.assertEqual(out["high_key_2"]["flag1_force_low6"]["size"],[1920,1080])
            self.assertEqual(out["high_key_7"]["preserve_low7"]["size"],[4096,2160])
            self.assertEqual(out["high_key_7"]["flag1_force_low6"]["size"],[2048,1080])
    def test_no_HEVC_key_in_mode_table_mandate(self):
        self.assertTrue(a.compute_key(True,1,7,2)==0x206)

class A32Failures(unittest.TestCase):
    pass

def break_site(m,site):
    def t(self):
        src=test_words(m)
        src[site]^=1
        with self.assertRaisesRegex(ValueError,"A32|BL"):
            a.check_a32(m,src.__getitem__)
    return t
for m in a.MODELS.values():
    sites=set(test_words(m))
    for site in sorted(sites):
        setattr(A32Failures,"test_flip_A32_%s_%08x"%(m.name,site),
                break_site(m,site))

class GhidraFailures(unittest.TestCase):
    pass

mutations=(
 ("mode","+ 0xa8c","+ 0xa8d"),
 ("mode","+ 0xa8e","+ 0xa8f"),
 ("mode","iVar6 == 0","iVar6 == 1"),
 ("mode"," != '\\x01'"," != '\\x02'"),
 ("mode"," + 0xadd8"," + 0xadd7"),
 ("mode"," + 0x5bd"," + 0x5bc"),
 ("mode"," = 6;"," = 7;"),
 ("mode"," + 0xadd9"," + 0xadd8"),
 ("mode"," + 0x5be"," + 0x5bd"),
 ("mode"," + 0xadda"," + 0xadd9"),
 ("mode"," = 0x3c;"," = 0x1e;"),
 ("lookup","case 4:","case 9:"),
 ("lookup","case 7:","case 8:"),
 ("lookup","return 0;","return 7;"),
 ("lookup","return 1;","return 7;"),
 ("setup"," + 0xadda"," + 0xaddb"),
 ("setup","0xca0000","0xcb0000"),
 ("setup","0xd08000","0xd09000"),
 ("asm","0xdd8","0xdd0"),
 ("asm","0xdd9","0xdd8"),
 ("asm","0xdda","0xddc"),
)
for m in a.MODELS.values():
    for n,(scope,source,replacement) in enumerate(mutations):
        def build_test(m,scope,source,replacement):
            def t(self):
                def mutate(logs):
                    self.assertIn(source,logs[scope])
                    logs[scope]=logs[scope].replace(source,replacement)
                with self.assertRaises(ValueError):
                    toy_gh(m,mutate)
            return t
        setattr(GhidraFailures,"test_mutate_Ghidra_%s_%02d"%(m.name,n),
                build_test(m,scope,source,replacement))

class TableFailures(unittest.TestCase):
    def test_bad_record_id(self):
        rows=b.read_records(make_table())
        self.assertEqual(b.match_record(rows,0,0x0207,6,1),[33])
        self.assertEqual(b.match_record(rows,0,0x0206,6,1),[70])
    def test_bad_high_class(self):
        rows=b.read_records(make_table())
        self.assertEqual(b.match_record(rows,1,0x0207,6,1),[])
    def test_bad_fps(self):
        rows=b.read_records(make_table())
        self.assertEqual(b.match_record(rows,0,0x0207,5,1),[])
    def test_bad_variant(self):
        rows=b.read_records(make_table())
        self.assertEqual(b.match_record(rows,0,0x0207,6,2),[])

if __name__=="__main__":
    unittest.main()

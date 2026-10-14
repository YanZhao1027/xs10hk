"""Synthetic-only tests for paired ordered movie setting permissions."""
import pathlib
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from codec_setting_permissions import ModelLayout, SENTINEL
from compare_movie_perm_groups import PAIRS, ordered_mode_options, compare


def fixture(model, change=False):
    base=0x1000
    cat_count = 9 if model=="xt4" else 24
    cats=list(range(cat_count-1))+[0x2D]
    ids=[pair[0] if model=="xt4" else pair[1] for pair in PAIRS]
    b=bytearray(0x4000)
    b[0x100:0x100+cat_count+1]=bytes(cats+[0x2E])
    stride=4+((cat_count+3)//4)*4
    for i,key in enumerate(ids):
        ptr=0x1400+i*0x380
        struct.pack_into("<II",b,0x200+i*8,key,ptr)
        vals=[(0,2),(1,1)]
        if i==1:
            vals=[(0,0),(4,2),(4,0),(7,1)] # duplicates intentional
        for j,(val,flag) in enumerate(vals):
            struct.pack_into("<I",b,ptr-base+j*stride,val)
            b[ptr-base+j*stride+4+cat_count-1]=flag
        struct.pack_into("<I",b,ptr-base+len(vals)*stride,SENTINEL)
    if change and model=="xs10":
        ptr=0x1400+1*0x380
        b[ptr-base+3*stride+4+cat_count-1]=0
    layout=ModelLayout(base,0x1100,0x1200,ids[-1],ids[-2])
    return bytes(b),layout


class PairedPermissionsTests(unittest.TestCase):
    def test_five_lists_equal_and_duplicates_preserved(self):
        xb, xl=fixture("xt4")
        sb, sl=fixture("xs10")
        with patch.dict("codec_setting_permissions.LAYOUTS",
                        {"xt4":xl,"xs10":sl}):
            res=compare(xb,sb)
        self.assertTrue(res["all_equal"])
        self.assertEqual(res["total_checked_rows"], 12)
        self.assertEqual(res["pairs"][1]["xt4_rows"],
                         [(0,0),(4,2),(4,0),(7,1)])

    def test_modified_category_permission_is_detected(self):
        xb, xl=fixture("xt4")
        sb, sl=fixture("xs10",change=True)
        with patch.dict("codec_setting_permissions.LAYOUTS",
                        {"xt4":xl,"xs10":sl}):
            res=compare(xb,sb)
        self.assertFalse(res["all_equal"])
        self.assertFalse(res["pairs"][1]["equal"])
        self.assertTrue(res["pairs"][0]["equal"])

    def test_unknown_key_is_rejected(self):
        xb, xl=fixture("xt4")
        with patch.dict("codec_setting_permissions.LAYOUTS",
                        {"xt4":xl}):
            with self.assertRaisesRegex(ValueError,"absent"):
                ordered_mode_options(xb,"xt4",0x123)

    def test_paired_ids_are_distinct_per_model(self):
        self.assertEqual(len(PAIRS),5)
        for xtid,xsid in PAIRS:
            self.assertEqual(xsid-xtid,0x17)


if __name__=="__main__":
    unittest.main()

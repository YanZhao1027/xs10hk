"""Purely synthetic negative/positive ARM evidence tests for Stage32.

No Fujifilm original bytes, user/camera data, modified ROM or device I/O.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_recorder_codec_forward_stage32 as a


def half(rd,val,high=False):
    return (0xe3400000 if high else 0xe3000000) | (((val>>12)&15)<<16) | (rd<<12) | (val&0xfff)

def bl(frm,to):
    diff=to-frm-8
    if diff%4 or not -(1<<25)<=diff<(1<<25):
        raise ValueError("unencodable synthetic A32 BL")
    return 0xeb000000|((diff>>2)&0xffffff)

def decomp(function,contents,kind="void"):
    return "TRACE_DECOMP_BEGIN (GhidraScript)\n"+kind+" FUN_%08x(void) {\n"%(function)+contents+"\n}\nTRACE_DECOMP_END (GhidraScript)\n"


def fixture(m):
    h=m.header_site
    co=m.intermediate_codec_offset
    words={
        h:half(3,m.descriptor&0xffff),h+4:half(3,m.descriptor>>16,True),
        h+8:0xe3a02044,h+12:0xe5832004,
        h+16:0xe283200c,h+20:0xe5832008,
        m.intermediate_literal:m.intermediate_base,
        m.adapter_call:bl(m.adapter_call,m.adapter),
        m.updater_call:bl(m.updater_call,m.updater),
        m.copy_wrapper_call:bl(m.copy_wrapper_call,m.copy_wrapper),
        m.copy_base:half(5,m.template_base&0xffff),
        m.copy_base+4:half(5,m.template_base>>16,True),
        m.copy_base+8:half(6,m.copy_len),
        m.copy_base+12:0xe1a02006,
        m.copy_base+16:0xe1a01004,
        m.copy_base+20:0xe1a00005,
        m.copy_base+24:bl(m.copy_base+24,m.copy_engine),
        m.copy_base+28:0xe1a02006,
        m.copy_base+32:0xe1a01004,
        m.copy_base+36:0xe2850d1b,
        m.copy_base+40:bl(m.copy_base+40,m.copy_engine),
    }
    for loc,val in zip(m.adapter_byte_stores,
            (0xe5d535b0,0xe5c43000|co,0xe5d535b1,0xe5c43000|(co+1))):
        words[loc]=val

    header=decomp(m.header_owner,
        "_DAT_%08x = 0x44;\n_DAT_%08x = &DAT_%08x;"%
           (m.descriptor+4,m.descriptor+8,m.descriptor+12))
    ptr_var="iVar2" if m.name=="xs10" else "iVar3"
    parent=decomp(m.parent,
        "%s = _DAT_%08x;\n"%(ptr_var,m.descriptor+16)+
        "_DAT_%08x = _DAT_%08x;\n"%(m.input_ptr_slot,m.descriptor+16)+
        "FUN_%08x(DAT_%08x,%s,1);\n"%
            (m.adapter,m.intermediate_literal,ptr_var)+
        "FUN_%08x(DAT_%08x,p2,p3,p4);"%
            (m.updater,m.intermediate_literal))
    adapter=decomp(m.adapter,
        "*(undefined1 *)(param_1 + 0x%x) = param_2[0x5b0];\n"%co+
        "*(undefined1 *)(param_1 + 0x%x) = param_2[0x5b1];"%(co+1))
    updater=decomp(m.updater,"FUN_%08x(param_1);"%m.copy_wrapper)
    template=decomp(m.copy_wrapper,
        "func_0x%08x(0x%x,param_1,0x%x);\n"%(m.copy_engine,m.template_base,m.copy_len)+
        "func_0x%08x(0x%x,param_1,0x%x);"%
            (m.copy_engine,m.template_base+0x6c0,m.copy_len))
    xrefs=("SLOT_SUMMARY addr=%08x refs=2 functions=2 types={READ=2}"%
           m.template_active_codec)
    return {"w":words,"h":header,"p":parent,"a":adapter,
            "u":updater,"t":template,"xr":xrefs}

def run_model(m,change=None):
    f=fixture(m)
    if change:change(f)
    with patch.object(a,"rom_word",side_effect=lambda blob,base,addr:f["w"][addr]):
        return a.audit(m,b"",b"",f["h"],f["p"],f["a"],f["u"],f["t"],f["xr"])

class DecodeTests(unittest.TestCase):
    def test_movw_low(self):
        self.assertEqual(a.movpart(half(5,0x4dd8),5),0x4dd8)
    def test_movt_high(self):
        self.assertEqual(a.movpart(half(5,0x1c2,True),5,True),0x1c2)
    def test_wrong_dest_register(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movpart(half(4,0x4dd8),5)
    def test_wrong_mov_variant(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movpart(half(5,0x4dd8,True),5)
    def test_bl_forward(self):
        self.assertEqual(a.a32_bl(bl(0x1000,0x2000),0x1000),0x2000)
    def test_bl_backward(self):
        self.assertEqual(a.a32_bl(bl(0x2000,0x1000),0x2000),0x1000)
    def test_bl_conditional_not_allowed(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.a32_bl(0x0b000000,0x1000)
    def test_bl_class_not_allowed(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            a.a32_bl(0xe3a02044,0x1000)
    def test_literal_rom_le(self):
        self.assertEqual(a.rom_word(bytes.fromhex("60cc d902"),0,0),0x02d9cc60)
    def test_literal_rom_alignment(self):
        with self.assertRaisesRegex(ValueError,"bad ROM"):
            a.rom_word(b"\0"*8,0,1)
    def test_literal_rom_bounds(self):
        with self.assertRaisesRegex(ValueError,"bad ROM"):
            a.rom_word(b"\0"*4,0,8)
    def test_finder_positive(self):
        m=a.MODELS["xs10"]
        self.assertIn("X",a.c_function(decomp(m.parent,"X"),m.parent))
    def test_finder_negative(self):
        with self.assertRaisesRegex(ValueError,"missing local"):
            a.c_function("",0x1234)

class FlowTests(unittest.TestCase):
    def test_success_both_models(self):
        for m in a.MODELS.values():
            with self.subTest(model=m.name):
                r=run_model(m)
                self.assertTrue(r["input_to_active_static_data_flow_edges_proven"])
                self.assertTrue(r["header_length_initialized_to_0x44"])
                self.assertEqual(r["original_A32_BL_edges_verified"],4)
                self.assertEqual(r["original_A32_template_copy_words_verified"],11)
                self.assertFalse(r["actual_GUI_to_Recorder_input_codec_initial_assignment_proven"])
                self.assertFalse(r["HEVC_Main10_internal_bitstream_proven"])
                self.assertFalse(r["camera_or_firmware_modified"])
    def test_fixed_intermediate_addresses(self):
        x=run_model(a.MODELS["xs10"])
        y=run_model(a.MODELS["xt4"])
        self.assertEqual(x["intermediate_codec_address"],"0x02d9d090")
        self.assertEqual(y["intermediate_codec_address"],"0x02d107e4")
    def test_fixed_active_addresses(self):
        x=run_model(a.MODELS["xs10"])
        y=run_model(a.MODELS["xt4"])
        self.assertEqual(x["active_Recorder_Codec_byte"],"0x01c25208")
        self.assertEqual(y["active_Recorder_Codec_byte"],"0x01b83974")
    def test_both_dont_claim_runtime_value(self):
        for m in a.MODELS.values():
            r=run_model(m)
            self.assertEqual(r["runtime_current_buffer_numeric_pointer_value"],"UNKNOWN")
            self.assertFalse(r["runtime_mutations_during_intervening_calls_excluded"])
    def test_no_third_party_proprietary_bytes(self):
        self.assertFalse(hasattr(a,"FIRMWARE_PATCH"))
        for m in a.MODELS.values():
            self.assertFalse(run_model(m)["4K60_internal_sensor_ISP_pipeline_proven"])
    def test_header_wrong_base(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.header_site]=half(3,0x87e4)
        with self.assertRaisesRegex(ValueError,"descriptor head"):
            run_model(m,ch)
    def test_header_wrong_high(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.header_site+4]=half(3,0x2d1,True)
        with self.assertRaisesRegex(ValueError,"descriptor head"):
            run_model(m,ch)
    def test_header_missing_len_44(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.header_site+8]=0xe3a02008
        with self.assertRaisesRegex(ValueError,"payload length"):
            run_model(m,ch)
    def test_header_wrong_store_target(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.header_site+12]=0xe5832008
        with self.assertRaisesRegex(ValueError,"header length STR"):
            run_model(m,ch)
    def test_header_wrong_payload_address(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.header_site+16]=0xe2832008
        with self.assertRaisesRegex(ValueError,"payload address"):
            run_model(m,ch)
    def test_header_wrong_payload_slot(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.header_site+20]=0xe5832010
        with self.assertRaisesRegex(ValueError,"payload-address"):
            run_model(m,ch)
    def test_header_c_length_mismatch(self):
        m=a.MODELS["xs10"]
        def ch(f):f["h"]=f["h"].replace("0x44","0x08")
        with self.assertRaisesRegex(ValueError,"Ghidra 0x44"):
            run_model(m,ch)
    def test_header_c_payload_address_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["h"]=f["h"].replace("&DAT_02d0bf54","&DAT_02d0bf58")
        with self.assertRaisesRegex(ValueError,"payload pointer"):
            run_model(m,ch)
    def test_parent_wrong_current_source(self):
        m=a.MODELS["xt4"]
        def ch(f):f["p"]=f["p"].replace("_DAT_02d0bf58","_DAT_02d0bf5c")
        with self.assertRaisesRegex(ValueError,"buffer pointer origin"):
            run_model(m,ch)
    def test_parent_wrong_current_slot(self):
        m=a.MODELS["xs10"]
        def ch(f):f["p"]=f["p"].replace("_DAT_02d9c2ac","_DAT_02d9c2b0")
        with self.assertRaisesRegex(ValueError,"input pointer slot"):
            run_model(m,ch)
    def test_parent_adapter_wrong_pointer_param(self):
        m=a.MODELS["xs10"]
        def ch(f):f["p"]=f["p"].replace("DAT_02214ca4,iVar2","DAT_02214ca4,iVar1")
        with self.assertRaisesRegex(ValueError,"pointer/ordering"):
            run_model(m,ch)
    def test_parent_adapter_not_first(self):
        m=a.MODELS["xs10"]
        def ch(f):f["p"]=f["p"].replace(
            "FUN_012c9500(DAT_02214ca4,iVar2,1);\nFUN_012c1ce8(DAT_02214ca4,p2,p3,p4);",
            "FUN_012c1ce8(DAT_02214ca4,p2,p3,p4);\nFUN_012c9500(DAT_02214ca4,iVar2,1);")
        with self.assertRaisesRegex(ValueError,"pointer/ordering"):
            run_model(m,ch)
    def test_parent_updater_other_buffer(self):
        m=a.MODELS["xt4"]
        def ch(f):f["p"]=f["p"].replace("FUN_0129a4d0(DAT_02181278","FUN_0129a4d0(DAT_0218127c")
        with self.assertRaisesRegex(ValueError,"pointer/ordering"):
            run_model(m,ch)
    def test_intermediate_literal_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.intermediate_literal]+=4
        with self.assertRaisesRegex(ValueError,"intermediate buffer"):
            run_model(m,ch)
    def test_adapter_bl_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.adapter_call]=bl(m.adapter_call,m.adapter+4)
        with self.assertRaisesRegex(ValueError,"conversion BL"):
            run_model(m,ch)
    def test_updater_bl_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.updater_call]=bl(m.updater_call,m.updater+4)
        with self.assertRaisesRegex(ValueError,"conversion BL"):
            run_model(m,ch)
    def test_adapter_codec_read_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.adapter_byte_stores[0]]=0xe5d535b1
        with self.assertRaisesRegex(ValueError,"Codec/Format"):
            run_model(m,ch)
    def test_adapter_codec_write_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.adapter_byte_stores[1]]=0xe5c43430
        with self.assertRaisesRegex(ValueError,"Codec/Format"):
            run_model(m,ch)
    def test_adapter_format_read_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.adapter_byte_stores[2]]=0xe5d535b0
        with self.assertRaisesRegex(ValueError,"Codec/Format"):
            run_model(m,ch)
    def test_adapter_format_write_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.adapter_byte_stores[3]]=0xe5c43430
        with self.assertRaisesRegex(ValueError,"Codec/Format"):
            run_model(m,ch)
    def test_adapter_c_codec_wrong_input(self):
        m=a.MODELS["xs10"]
        def ch(f):f["a"]=f["a"].replace("param_2[0x5b0]","param_2[0x5a0]")
        with self.assertRaisesRegex(ValueError,"Codec assignment"):
            run_model(m,ch)
    def test_adapter_c_format_wrong_target(self):
        m=a.MODELS["xt4"]
        def ch(f):f["a"]=f["a"].replace("0x435","0x436")
        with self.assertRaisesRegex(ValueError,"Format assignment"):
            run_model(m,ch)
    def test_updater_no_template_copy(self):
        m=a.MODELS["xs10"]
        def ch(f):f["u"]=f["u"].replace("FUN_012bd110","FUN_012bd114")
        with self.assertRaisesRegex(ValueError,"updater not calling"):
            run_model(m,ch)
    def test_updater_template_copy_bl_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.copy_wrapper_call]=bl(m.copy_wrapper_call,m.copy_wrapper+4)
        with self.assertRaisesRegex(ValueError,"updater->template"):
            run_model(m,ch)
    def test_template_base_low_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.copy_base]=half(5,(m.template_base&0xffff)+4)
        with self.assertRaisesRegex(ValueError,"template base"):
            run_model(m,ch)
    def test_template_base_high_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.copy_base+4]=half(5,(m.template_base>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"template base"):
            run_model(m,ch)
    def test_template_copy_length_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.copy_base+8]=half(6,m.copy_len-4)
        with self.assertRaisesRegex(ValueError,"copy size"):
            run_model(m,ch)
    def test_template_copy_source_register_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.copy_base+16]=0xe1a01005
        with self.assertRaisesRegex(ValueError,"copy ABI"):
            run_model(m,ch)
    def test_template_copy_dest_register_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.copy_base+20]=0xe1a00004
        with self.assertRaisesRegex(ValueError,"copy ABI"):
            run_model(m,ch)
    def test_template_copy_engine_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.copy_base+24]=bl(m.copy_base+24,m.copy_engine+4)
        with self.assertRaisesRegex(ValueError,"copy engine"):
            run_model(m,ch)
    def test_template_second_size_register_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.copy_base+28]=0xe1a02004
        with self.assertRaisesRegex(ValueError,"second copy"):
            run_model(m,ch)
    def test_template_second_source_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.copy_base+32]=0xe1a01005
        with self.assertRaisesRegex(ValueError,"second copy"):
            run_model(m,ch)
    def test_template_second_dest_wrong(self):
        m=a.MODELS["xs10"]
        def ch(f):f["w"][m.copy_base+36]=0xe2850d1a
        with self.assertRaisesRegex(ValueError,"second copy"):
            run_model(m,ch)
    def test_template_second_engine_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["w"][m.copy_base+40]=bl(m.copy_base+40,m.copy_engine+4)
        with self.assertRaisesRegex(ValueError,"second raw BL"):
            run_model(m,ch)
    def test_template_c_wrong_direction(self):
        m=a.MODELS["xs10"]
        def ch(f):f["t"]=f["t"].replace("0x1c24dd8,param_1","param_1,0x1c24dd8")
        with self.assertRaisesRegex(ValueError,"C copy"):
            run_model(m,ch)
    def test_template_c_second_base_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["t"]=f["t"].replace("0x1b83c00","0x1b83bfc")
        with self.assertRaisesRegex(ValueError,"second template C"):
            run_model(m,ch)
    def test_template_c_copy_size_wrong(self):
        m=a.MODELS["xt4"]
        def ch(f):f["t"]=f["t"].replace("0x47c","0x470")
        with self.assertRaisesRegex(ValueError,"template C copy"):
            run_model(m,ch)
    def test_direct_write_xref_does_not_prove_no_copy(self):
        for m in a.MODELS.values():
            self.assertTrue(run_model(m)["input_to_active_static_data_flow_edges_proven"])
    def test_active_direct_write_change_requests_review(self):
        m=a.MODELS["xs10"]
        def ch(f):f["xr"]=f["xr"].replace("{READ=2}","{READ=1, WRITE=1}")
        with self.assertRaisesRegex(ValueError,"read-reference baseline"):
            run_model(m,ch)
    def test_active_codec_identity_mismatch(self):
        m=a.MODELS["xs10"]
        with self.assertRaisesRegex(ValueError,"arithmetic identity"):
            run_model(a.Model(**{**m.__dict__,"template_active_codec":m.template_active_codec+1}))
    def test_active_format_identity_mismatch(self):
        m=a.MODELS["xt4"]
        with self.assertRaisesRegex(ValueError,"arithmetic identity"):
            run_model(a.Model(**{**m.__dict__,"template_active_format":m.template_active_format+1}))
    def test_wrong_copy_length_cannot_cover_codec(self):
        m=a.MODELS["xs10"]
        with self.assertRaisesRegex(ValueError,"cannot contain"):
            run_model(a.Model(**{**m.__dict__,"copy_len":0x430}))

if __name__=="__main__":unittest.main()

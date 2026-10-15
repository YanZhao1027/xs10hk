"""Synthetic-only tests for Stage30 profile-ring and Codec-copy directions.

No vendor firmware, private Ghidra logs, or device state included.
The generated fake A32 instructions verify positive/negative audit behavior;
their passing does NOT establish any camera's encoding capabilities.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_profile_ring_codec_direction_stage30 as mod


def make_bl(at,target):
    rel=target-at-8
    if rel%4 or not -(1<<25)<=rel<(1<<25):raise ValueError("BL unreachable")
    return 0xeb000000|((rel>>2)&0xffffff)


def make_mov_half(rd,value,top):
    return ((0xe3400000 if top else 0xe3000000) |
            (((value>>12)&15)<<16)|(rd<<12)|(value&0xfff))


def block(entry,c):
    return "TRACE_DECOMP_BEGIN (GhidraScript)\nvoid FUN_%08x(void){\n%s\n}\nTRACE_DECOMP_END (GhidraScript)\n"%(entry,c)


def fixture(s):
    w={}
    for at,target in [(s.header_copy,s.memcpy),
                      (s.payload_copy,s.memcpy),
                      (s.serializer_caller_bl,s.active_export_function)]:
        w[at]=make_bl(at,target)
    for at,top in [(s.header_movw,False),(s.header_movt,True),
                   (s.payload_movw,False),(s.payload_movt,True)]:
        w[at]=make_mov_half(1,(s.descriptor>>16)&0xffff if top else
                           s.descriptor&0xffff,top)
    w[s.header_copy-16]=0xe3a0200c
    w[s.header_copy-4]=0xe1a00005
    w[s.payload_copy-12]=0xe5912004
    w[s.payload_copy-8]=0xe281100c
    w[s.payload_copy-4]=0xe1a00004
    w[s.counter_store]=0xe5812abc
    for at,val in (
       (s.ring_header_literal,s.ring_header),
       (s.ring_payload_literal,s.ring_payload),
       (s.ordinary_206_payload_literal,s.ordinary_206_payload),
       (s.type207_write_payload_literal,s.type207_payload),
       (s.type207_read_payload_literal,s.type207_payload),
       (s.type207_read_header_literal,s.type207_header),
       (s.counter_owner_literal,s.counter_addr-0xabc)
    ):w[at]=val
    w[s.raw_export_codec_load]=0xe5d53000|s.raw_export_codec_baseoffset
    w[s.raw_export_codec_store]=0xe5c435b0
    w[s.raw_export_format_load]=(0xe5d53000|s.raw_export_codec_baseoffset)+1
    w[s.raw_export_format_store]=0xe5c435b1
    writer=block(s.save_fn,(
      "if (_DAT_%08x == 0x206) {\n"
      "if (_DAT_%08x != 0x11b && _DAT_%08x != 0x11e) {\n"
      "puVar3 = %s + -0xc; }\n"
      "iVar1 = _DAT_%08x * 0x50;\n"
      "puVar3 = &DAT_%08x + iVar1;\n"
      "_DAT_%08x = _DAT_%08x + 1;\n"
      "puVar2 = (undefined1 *)(iVar1 + 0x%x);\n"
      "}\n"
      "if (_DAT_%08x != 0x207) {...}\n"
      "FUN_%08x(puVar3,&DAT_%08x,0xc);\n"
      "FUN_%08x(puVar2,&DAT_%08x,_DAT_%08x);\n" %
      (s.descriptor,s.descriptor+0xc,s.descriptor+0xc,
       s.ordinary_206_fallback_symbol,
       s.counter_addr,s.ring_header,
       s.counter_addr,s.counter_addr,
       s.ring_payload,s.descriptor,
       s.memcpy,s.descriptor,
       s.memcpy,s.descriptor+0xc,s.descriptor+4)
    ))
    reader_h=block(0x021f893c if s.name=="xs10" else 0x021649b8,
                   "if (param_2 == 0x8c && param_3 == 1) {\n"
                   "return (*(int *)(DAT_12345678 + 0xabc) - 1) * 0x50 + base;\n}")
    reader_p=block(0x021f8d64 if s.name=="xs10" else 0x02164de0,
                   "if (param_1 == 0x206 && param_2 == 0x8c) {\n"
                   "return (_DAT_%08x + -1) * 0x50 + 0x%x;\n}"%
                   (s.counter_addr,s.ring_payload))
    clear=block(s.counter_mutator_functions[0],
                "if (param_1 == 0x206) {zero(record,0x44); count = count + -1;}")
    collapse=block(s.counter_mutator_functions[1],
                   "if(param_1 == 0x206) {memcpy(rec,rec + 0x50,0x18); "
                   "count = count + -1; }")
    drop=block(s.counter_mutator_functions[2],
               "if (index >= 0) {clear(0x44); iVar2 += 0x50; "
               "_DAT_%08x = count - 1;}"%s.counter_addr)
    export=block(s.active_export_function,
                 "param_1[0x5b0] = DAT_%08x;\n"
                 "param_1[0x5b1] = DAT_%08x;"%
                 (s.active_codec,s.active_format))
    outvar="iVar3" if s.name=="xs10" else "iVar4"
    caller=block(s.serializer_caller_function,
                 "%s = _DAT_%08x;\nFUN_%08x(%s);"%
                 (outvar,s.serializer_global,s.active_export_function,outvar))
    ref=("SLOT_WRITE_CAND addr=%08x from=%08x type=WRITE func=%08x "
         "insn=str r2,[r1,#0xabc]\nSLOT_SUMMARY addr=%08x refs=8 "
         "functions=4 types={READ=3, WRITE=5}\n"%
         (s.counter_addr,s.counter_store,s.save_fn,s.counter_addr))
    triad=(
       "TRIAD_PAIR a=gui b=active functions=0 entries=[]\n"
       "TRIAD_PAIR a=gui b=current_ptr_slot functions=0 entries=[]\n"
       "TRIAD_PAIR a=active b=current_ptr_slot functions=0 entries=[]\n"
    )
    return dict(words=w,registry=writer+reader_h+reader_p,
                counter=clear+collapse+drop,
                serializer=export,caller=caller,refs=ref,triad=triad)


def run(s,change=None):
    data=fixture(s)
    if change:change(data)
    with patch.object(mod,"rom_word",
                      side_effect=lambda b,base,addr:data["words"][addr]):
        return mod.audit(s,b"",b"",data["registry"],data["registry"],
                         data["counter"],data["serializer"],data["caller"],
                         data["refs"],data["triad"])


class OpcodeTests(unittest.TestCase):
    def test_a32_bl_forward(self):
        self.assertEqual(mod.decode_bl(make_bl(0x1000,0x2000),0x1000),0x2000)

    def test_a32_bl_backward(self):
        self.assertEqual(mod.decode_bl(make_bl(0x2000,0x1000),0x2000),0x1000)

    def test_reject_b_without_link(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            mod.decode_bl(0xea000004,0x1000)

    def test_reject_conditional_bl(self):
        with self.assertRaisesRegex(ValueError,"unconditional"):
            mod.decode_bl(0x0b000004,0x1000)

    def test_read_original_word(self):
        self.assertEqual(mod.rom_word(struct.pack("<I",0xe5812abc),0x1000,0x1000),
                         0xe5812abc)

    def test_raw_word_unaligned(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            mod.rom_word(b"\x00"*8,0x1000,0x1001)

    def test_raw_word_out_of_bounds(self):
        with self.assertRaisesRegex(ValueError,"outside original"):
            mod.rom_word(b"\x00"*4,0x1000,0x1004)

    def test_movw_half(self):
        self.assertEqual(mod.movhalf(make_mov_half(1,0xb7e8,False),False,1),
                         0xb7e8)

    def test_movt_half(self):
        self.assertEqual(mod.movhalf(make_mov_half(1,0x2d9,True),True,1),0x2d9)

    def test_movhalf_wrong_rd(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            mod.movhalf(make_mov_half(2,0x2d9,True),True,1)

    def test_movhalf_wrong_op(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            mod.movhalf(make_mov_half(1,0x2d9,True),False,1)

    def test_pointer_payload_size_threshold(self):
        self.assertEqual([mod.includes_full_pointer(n) for n in
                          [0,1,4,7,8,9,0x44]],[False]*4+[True]*3)

    def test_negative_payload_size(self):
        with self.assertRaisesRegex(ValueError,"negative"):
            mod.includes_full_pointer(-1)

    def test_function_c_must_select_definition(self):
        c=block(0x12345000,"FUN_012a9148();")+block(
            0x012a9148,"*param_1 = *param_2;")
        self.assertIn("*param_1",mod.function_c(c,0x012a9148))

    def test_missing_decompiler_def(self):
        with self.assertRaisesRegex(ValueError,"missing Ghidra"):
            mod.function_c("",0x012a9148)


class ProfileProvenanceTests(unittest.TestCase):
    def test_both_model_positive(self):
        for s in mod.SPECS.values():
            with self.subTest(s.name):
                r=run(s)
                self.assertEqual(r["original_ARM_memcpy_and_serializer_BLs_checked"],3)
                self.assertTrue(r["verified_active_codec_to_export_buffer_byte_0x5b0"])
                self.assertTrue(r["verified_active_format_to_export_buffer_byte_0x5b1"])
                self.assertFalse(r["GUI_codec_to_recorder_input_buffer_assignment_proven"])
                self.assertFalse(r["runtime_ring_entry_pointer_value_known"])
                self.assertFalse(r["HEVC_Main10_internal_10bit_proven"])
                self.assertFalse(r["4K60_internal_sensor_pipeline_proven"])
                self.assertFalse(r["camera_or_firmware_modified"])

    def test_registry_compares_distinct_206_paths(self):
        for s in mod.SPECS.values():
            r=run(s)
            self.assertNotEqual(r["type206_selector_8c_normal_save_payload"],
                                "0x%08x"%s.ring_payload)
            self.assertFalse(r["type206_selector_8c_normal_save_is_same_as_latest_ring"])

    def test_type207_read_and_save_coincide(self):
        for s in mod.SPECS.values():
            r=run(s)
            self.assertEqual(r["type207_static_save_and_read_payload"],
                             "0x%08x"%s.type207_payload)

    def test_wrong_source_header_first_movw(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.header_movw]=make_mov_half(
            1,(s.descriptor+4)&0xffff,False)
        with self.assertRaisesRegex(ValueError,"not current descriptor"):
            run(s,bad)

    def test_wrong_source_header_second_movt(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.payload_movt]=make_mov_half(
            1,(s.descriptor>>16)+1,True)
        with self.assertRaisesRegex(ValueError,"not current descriptor"):
            run(s,bad)

    def test_wrong_header_bl_target(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.header_copy]=make_bl(
            s.header_copy,s.memcpy+4)
        with self.assertRaisesRegex(ValueError,"profile-ring copy"):
            run(s,bad)

    def test_wrong_payload_bl_target(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.payload_copy]=make_bl(
            s.payload_copy,s.memcpy+4)
        with self.assertRaisesRegex(ValueError,"profile-ring copy"):
            run(s,bad)

    def test_wrong_export_bl_target(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.serializer_caller_bl]=make_bl(
            s.serializer_caller_bl,s.active_export_function+4)
        with self.assertRaisesRegex(ValueError,"active-export"):
            run(s,bad)

    def test_header_size_wrong(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.header_copy-16]=0xe3a02010
        with self.assertRaisesRegex(ValueError,"header copy length"):
            run(s,bad)

    def test_header_destination_register_wrong(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.header_copy-4]=0xe1a00004
        with self.assertRaisesRegex(ValueError,"destination registers"):
            run(s,bad)

    def test_payload_size_from_wrong_field(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.payload_copy-12]=0xe5912008
        with self.assertRaisesRegex(ValueError,"source descriptor"):
            run(s,bad)

    def test_payload_source_not_plus_0c(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.payload_copy-8]=0xe2811010
        with self.assertRaisesRegex(ValueError,"source descriptor"):
            run(s,bad)

    def test_counter_store_instruction_changed(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.counter_store]=0xe5812ac0
        with self.assertRaisesRegex(ValueError,"increment"):
            run(s,bad)

    def test_dynamic_header_rom_pointer_mismatch(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.ring_header_literal]+=4
        with self.assertRaisesRegex(ValueError,"header table pointer"):
            run(s,bad)

    def test_dynamic_payload_rom_pointer_mismatch(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.ring_payload_literal]+=4
        with self.assertRaisesRegex(ValueError,"payload table pointer"):
            run(s,bad)

    def test_wrong_normal_206_record_rom_pointer(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.ordinary_206_payload_literal]+=4
        with self.assertRaisesRegex(ValueError,"ordinary-write"):
            run(s,bad)

    def test_ordinary_saver_cannot_be_equated_to_latest_ring(self):
        s=replace(mod.SPECS["xs10"],ordinary_206_payload=
                  mod.SPECS["xs10"].ring_payload)
        with self.assertRaisesRegex(ValueError,"falsely equals"):
            run(s)

    def test_type207_payload_writer_rom_pointer_changed(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.type207_write_payload_literal]+=4
        with self.assertRaisesRegex(ValueError,"0x207 static"):
            run(s,bad)

    def test_type207_reader_rom_pointer_changed(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.type207_read_header_literal]+=4
        with self.assertRaisesRegex(ValueError,"0x207 static"):
            run(s,bad)

    def test_dynamic_counter_owner_pointer_changed(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.counter_owner_literal]+=4
        with self.assertRaisesRegex(ValueError,"reader's last-entry"):
            run(s,bad)

    def test_missing_special_11b_writer_branch(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["registry"]=f["registry"].replace("!= 0x11b","!= 0x121")
        with self.assertRaisesRegex(ValueError,"special-subtype"):
            run(s,bad)

    def test_missing_special_11e_writer_branch(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["registry"]=f["registry"].replace("!= 0x11e","!= 0x122")
        with self.assertRaisesRegex(ValueError,"special-subtype"):
            run(s,bad)

    def test_wrong_type207_branch(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["registry"]=f["registry"].replace("!= 0x207","!= 0x208")
        with self.assertRaisesRegex(ValueError,"ordinary type206"):
            run(s,bad)

    def test_missing_reverse_payload_copy(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["registry"]=f["registry"].replace(
            ("FUN_%08x(puVar2,&DAT_%08x,_DAT_%08x)"%
             (s.memcpy,s.descriptor+0xc,s.descriptor+4)),
            "FUN_00000000(unknown())")
        with self.assertRaisesRegex(ValueError,"save direction"):
            run(s,bad)

    def test_reader_wrong_latest_index(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["registry"]=f["registry"].replace(
            "_DAT_02d9c2a4 + -1","_DAT_02d9c2a4 + 1")
        with self.assertRaisesRegex(ValueError,"latest ring"):
            run(s,bad)

    def test_reader_wrong_counter_offset(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["registry"]=f["registry"].replace(
            " + 0xabc"," + 0xac4")
        with self.assertRaisesRegex(ValueError,"latest ring"):
            run(s,bad)

    def test_clear_missing_44_bytes(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["counter"]=f["counter"].replace("0x44","0x40")
        with self.assertRaisesRegex(ValueError,"record-clear"):
            run(s,bad)

    def test_compaction_missing_0x18_copy(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["counter"]=f["counter"].replace("0x18","0x10")
        with self.assertRaisesRegex(ValueError,"compaction"):
            run(s,bad)

    def test_wrong_counter_direct_write_count(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["refs"]=f["refs"].replace("WRITE=5","WRITE=4").replace(
            "refs=8","refs=7")
        with self.assertRaisesRegex(ValueError,"WRITE count"):
            run(s,bad)

    def test_missing_counter_store_ghidra_xref(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["refs"]=f["refs"].replace(
            "from=021644f0","from=021644f4")
        with self.assertRaisesRegex(ValueError,"not in Ghidra"):
            run(s,bad)

    def test_new_gui_active_shared_direct_function_forces_review(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["triad"]=f["triad"].replace(
            "a=gui b=active functions=0","a=gui b=active functions=1")
        with self.assertRaisesRegex(ValueError,"new same-function"):
            run(s,bad)

    def test_missing_xref_triads(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["triad"]=""
        with self.assertRaisesRegex(ValueError,"missing triad"):
            run(s,bad)

    def test_export_codec_source_load_changed(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["words"][s.raw_export_codec_load]+=4
        with self.assertRaisesRegex(ValueError,"LDRB->STRB"):
            run(s,bad)

    def test_export_format_source_load_changed(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.raw_export_format_load]+=4
        with self.assertRaisesRegex(ValueError,"LDRB->STRB"):
            run(s,bad)

    def test_export_codec_destination_store_changed(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["words"][s.raw_export_codec_store]=0xe5c435b4
        with self.assertRaisesRegex(ValueError,"LDRB->STRB"):
            run(s,bad)

    def test_export_C_wrong_direction(self):
        s=mod.SPECS["xs10"]
        def bad(f):f["serializer"]=f["serializer"].replace(
            "param_1[0x5b0] = DAT_01c25208;",
            "DAT_01c25208 = param_1[0x5b0];")
        with self.assertRaisesRegex(ValueError,"export buffer direction"):
            run(s,bad)

    def test_export_caller_wrong_destination_global(self):
        s=mod.SPECS["xt4"]
        def bad(f):f["caller"]=f["caller"].replace(
            "_DAT_03672078","_DAT_03672074")
        with self.assertRaisesRegex(ValueError,"output pointer origin"):
            run(s,bad)

    def test_output_pointer_global_must_not_equal_input_slot(self):
        s=replace(mod.SPECS["xs10"],serializer_global=
                  mod.SPECS["xs10"].current_ptr_slot)
        with self.assertRaisesRegex(ValueError,"unexpectedly share"):
            run(s)


if __name__=="__main__":
    unittest.main()

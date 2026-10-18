"""Stage38 synthetic-only tests: original A32 VPU TX control-write audit.

Constructed ROM instruction vectors and fictional C strings, no proprietary
ROM/firmware/debug secrets. No device access, patching, firmware flashing.
The 'doorbell' hardware identity is explicitly unverified.
"""
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage38_vpu_mmio_notify as a

def movw(reg,n,upper=False):
    return (0xe3400000 if upper else 0xe3000000)|\
         (((n>>12)&15)<<16)|(reg<<12)|(n&0xfff)

def synthetic_function(at,body):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"+
            "void FUN_%08x(void)\n{\n"%at+body+
            "\n}\nTRACE_DECOMP_END (GhidraScript)\n")

def initial_rom_words(model):
    m=model
    w={}
    for site in (m.control_initializer,m.control_initializer_again):
        w[site]=movw(3,m.control_base_slot&0xffff)
        w[site+4]=movw(3,m.control_base_slot>>16,True)
        for j,inst in enumerate(a.INIT_CONST_WORDS):w[site+8+4*j]=inst
    s=m.selector_initializer
    for offset,reg,val in ((0,3,m.selector_ptr_slot),(8,2,m.selector_scalar_location)):
        w[s+offset]=movw(reg,val&0xffff)
        w[s+offset+4]=movw(reg,val>>16,True)
    w[s+16]=0xe5832000
    for site in (m.notify_primary,m.notify_secondary):
        w[site]=movw(3,m.control_base_slot&0xffff)
        w[site+4]=movw(3,m.control_base_slot>>16,True)
        w[site+12]=movw(2,m.selector_ptr_slot&0xffff)
        w[site+16]=movw(2,m.selector_ptr_slot>>16,True)
        for j,val in enumerate(a.EFFECTIVE_CONST_REG_WORDS):
            at=site+8 if j==0 else site+20+(j-1)*4
            w[at]=val
    h=a.HANDSHAKES[m.name]
    for addr,value in (
       (h["map_write"]-8,0xe0813303),
       (h["map_write"]-4,0xe3a02001),
       (h["map_write"],0xe583220c),
       (h["map_write_218"],0xe5832218),
       (h["unmap_read"],0xe593320c),
       (h["unmap_read"]+4,0xe3530000),
       (h["unmap_clear_214"],0xe582c214)
    ):w[addr]=value
    return w

def get_fixture(m):
    control="_DAT_%08x"%m.control_base_slot
    selector="_DAT_%08x"%m.selector_ptr_slot
    initial=synthetic_function(m.control_init_fn,
       "%s = 0x%x;\n"%(selector,m.selector_scalar_location)+
       "%s = 0xffe00000;"%control)
    secondary=synthetic_function(m.second_init_fn,
        "%s = 0xffe00000;"%control)
    sender=(
         "uVar4 = uVar4 %% 0x3fc;\n"
         "*(uint *)(ptr + idx * 4) = param_2 | param_3 << 0x10;\n"
         "*(short *)(_DAT_12345678 + 2) = (short)uVar3;\n"
         "*(undefined4 *)(%s + *%s * 0x40 + 0x220) = 1;\n"%(control,selector)+
         "FUN_%08x(&DAT_01234567);\n"%m.dbg_string_logger+
         "FUN_%08x(123,0);"%m.dbg_hex_logger
    )
    debug=synthetic_function(m.dbg_string_logger,
       "char *pcVar1;\nwhile (*pcVar1 != '\\0') {pcVar1++;}\n") + \
       synthetic_function(m.dbg_hex_logger,
       "uVar1 = 0x1c;\nputhex(0x5b);\nuVar1 = uVar1 - 4;")
    xrefs=""
    for addr,count,writes in (
         (m.control_base_slot,62,2),(m.selector_ptr_slot,64,1),
         (m.shared_packet_ptr_slot,55,1)):
        xrefs+="STAGE38_XREF_SUMMARY addr=%08x n=%d WRITEs=%d READs=0 computed=0\n"%(addr,count,writes)
    for addr,site in (
         (m.selector_ptr_slot,m.selector_initializer+16),
         (m.control_base_slot,m.control_initializer+16),
         (m.control_base_slot,m.control_initializer_again+16)):
        xrefs+="STAGE38_WRITE to=%08x from=%08x func=01234567 inst=STR\n"%(addr,site)
    h=a.HANDSHAKES[m.name]
    mapbody=(
        "h265_MapSession_start\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x20c) = 1;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x218) = 1;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x230) = 0x33;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x220) = 0;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x214) = 1;\n"
        "iVar3 = 24000;\n"
        "if (*(int *)(somebase + index * 0x40 + 0x218) == 0) return 0;")
    unmapbody=(
        "if (*(int *)(somebase + index * 0x40 + 0x20c) == 0) return 0;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x214) = 0;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x218) = 1;\n"
        "*(undefined4 *)(somebase + index * 0x40 + 0x20c) = 0;\n"
        "iVar3 = 0x4b0;")
    return {
      "word":initial_rom_words(m),
      "logs":{
         "init":initial,
         "alt":secondary,
         "send":synthetic_function(m.TX_primary,sender)+
                synthetic_function(m.TX_secondary,sender),
         "debug":debug,
         "xrefs":xrefs,
         "handshake":synthetic_function(h["map_fn"],mapbody)+
                     synthetic_function(h["unmap_fn"],unmapbody),
      },
      "prior":{
        "model":m.name,
        "frame_sender_0xBB9_payload_bytes":72,
        "primary_tx_packet_location":"W+0x92010",
        "secondary_tx_packet_location":"W+0x94010",
        "0xBB9_direct_VPU_hardware_consumer_observed":False,
      },
    }

def verify(m,mutator=None):
    o=get_fixture(m)
    if mutator:mutator(o)
    return a.validate_original(m,lambda site:o["word"][site],o["logs"],o["prior"])

class InstructionDecoders(unittest.TestCase):
    def test_movw(self):
        self.assertEqual(a.movpart(movw(3,0xabcd),3),0xabcd)
    def test_movt(self):
        self.assertEqual(a.movpart(movw(3,0xffe0,True),3,True),0xffe0)
    def test_bad_mov_variant(self):
        with self.assertRaisesRegex(ValueError,"MOVW/MOVT"):
            a.movpart(movw(3,0x1234,True),3)
    def test_bad_mov_reg(self):
        with self.assertRaisesRegex(ValueError,"MOVW/MOVT"):
            a.movpart(movw(2,0x1234),3)
    def test_bad_mov_cond(self):
        with self.assertRaisesRegex(ValueError,"MOVW/MOVT"):
            a.movpart(0x03000000|0x1234,3)
    def test_original_rom_le(self):
        self.assertEqual(a.romword(bytes.fromhex("78563412"),a.ROM_BASE),0x12345678)
    def test_original_rom_oob(self):
        with self.assertRaisesRegex(ValueError,"out of range"):
            a.romword(b"\0"*8,a.ROM_BASE+9)
    def test_original_rom_misaligned(self):
        with self.assertRaisesRegex(ValueError,"out of range"):
            a.romword(b"\0"*8,a.ROM_BASE+1)
    def test_mov32_static_selector(self):
        m=a.MODELS["xs10"];o=get_fixture(m)
        self.assertEqual(a.mov32(lambda x:o["word"][x],m.selector_initializer+8,2),
                         m.selector_scalar_location)
    def test_extract_g_id(self):
        m=a.MODELS["xs10"]
        self.assertIn("ff",a.extract_c(
           synthetic_function(m.control_init_fn,"ff;"),m.control_init_fn))
    def test_extract_missing(self):
        with self.assertRaisesRegex(ValueError,"Ghidra C"):
            a.extract_c("",0x12345678)
    def test_control_const_32(self):
        self.assertEqual(a.CONTROL_BASE,0xffe00000)
        self.assertEqual(a.REGISTER_ADDEND,0x220)
        self.assertEqual(a.CHANNEL_STRIDE,0x40)

class SignalBranch(unittest.TestCase):
    def test_positive_both_models(self):
        for m in a.MODELS.values():
            with self.subTest(m=m.name):
                r=verify(m)
                self.assertEqual(r["notification_register_value"],1)
                self.assertEqual(len(r["sender_original_ARM_verified"]),2)
                self.assertEqual(r["registered_control_range_base"],"0xffe00000")
                self.assertTrue(r["cross_camera_MMIO_base_and_register_offset_same"])
    def test_unknown_runtime_selector_and_hardware_identity(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertEqual(r["channel_scalar_runtime_value"],"UNKNOWN")
            self.assertEqual(r["hardware_register_is_a_VPU_doorbell_definition"],"UNKNOWN")
            self.assertFalse(r["silicon_or_coprocessor_receipt_observed"])
    def test_never_claim_unlock(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertFalse(r["HEVC_10bit_Main10_or_4K60_proven"])
            self.assertFalse(r["firmware_modified_or_camera_contacted"])
    def test_map_session_control_offsets_and_wait(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertTrue(r["MapSession_static_software_handshake"]["polls_0x218_equal_zero"])
            self.assertEqual(r["MapSession_static_software_handshake"]["writes_control_0x230"],0x33)
            self.assertEqual(r["A32_readonly_MMIO_map_unmap_words_checked"],7)
    def test_unmap_checks_and_clears_session_control(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertTrue(r["unmap_or_ack_static_software_handshake"]["checks_control_0x20c_nonzero"])
            self.assertTrue(r["unmap_or_ack_static_software_handshake"]["clears_control_0x20c"])
    def test_reject_missing_map_session_timeout(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("iVar3 = 24000","iVar3 = 999")
        with self.assertRaisesRegex(ValueError,"MapSession"):verify(m,edit)
    def test_reject_wrong_map_0x20c(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("+ 0x20c) = 1;","+ 0x210) = 1;")
        with self.assertRaisesRegex(ValueError,"MapSession"):verify(m,edit)
    def test_reject_wrong_map_0x230(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("+ 0x230) = 0x33","+ 0x230) = 0x32")
        with self.assertRaisesRegex(ValueError,"MapSession"):verify(m,edit)
    def test_reject_wrong_map_0x218_wait(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("+ 0x218) == 0)","+ 0x214) == 0)")
        with self.assertRaisesRegex(ValueError,"MapSession"):verify(m,edit)
    def test_reject_wrong_unmap_0x20c_check(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("+ 0x20c) == 0)","+ 0x214) == 0)")
        with self.assertRaisesRegex(ValueError,"unmap"):verify(m,edit)
    def test_reject_wrong_unmap_clear_0x214(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("+ 0x214) = 0;","+ 0x214) = 1;")
        with self.assertRaisesRegex(ValueError,"unmap"):verify(m,edit)
    def test_reject_wrong_unmap_timeout(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["handshake"]=o["logs"]["handshake"].replace("iVar3 = 0x4b0","iVar3 = 0x4b1")
        with self.assertRaisesRegex(ValueError,"unmap"):verify(m,edit)

    def test_other_logger_remains_distinct(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertTrue(r["producer_TX_debug_string_and_hex_formatters_separate_from_control_write"])
    def test_stage37_wrong_model(self):
        m=a.MODELS["xs10"]
        def edit(o):o["prior"]["model"]="xt4"
        with self.assertRaisesRegex(ValueError,"stage37"):verify(m,edit)
    def test_stage37_wrong_tx_ring(self):
        m=a.MODELS["xt4"]
        def edit(o):o["prior"]["primary_tx_packet_location"]="W+0x93010"
        with self.assertRaisesRegex(ValueError,"stage37"):verify(m,edit)
    def test_stage37_wrong_secondary_ring(self):
        m=a.MODELS["xs10"]
        def edit(o):o["prior"]["secondary_tx_packet_location"]="W+0x95010"
        with self.assertRaisesRegex(ValueError,"stage37"):verify(m,edit)
    def test_stage37_invalid_receiver_claim(self):
        m=a.MODELS["xt4"]
        def edit(o):o["prior"]["0xBB9_direct_VPU_hardware_consumer_observed"]=True
        with self.assertRaisesRegex(ValueError,"stage37"):verify(m,edit)
    def test_stage37_bad_payload_len(self):
        m=a.MODELS["xs10"]
        def edit(o):o["prior"]["frame_sender_0xBB9_payload_bytes"]=68
        with self.assertRaisesRegex(ValueError,"stage37"):verify(m,edit)
    def test_initializer_wrong_base(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["init"]=o["logs"]["init"].replace("0xffe00000","0xfff00000")
        with self.assertRaisesRegex(ValueError,"initial assignments"):verify(m,edit)
    def test_initializer_wrong_selector_ptr(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["init"]=o["logs"]["init"].replace(
             "0x%x"%m.selector_scalar_location,"0x00000000")
        with self.assertRaisesRegex(ValueError,"initial assignments"):verify(m,edit)
    def test_second_init_base_wrong(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["alt"]=o["logs"]["alt"].replace("0xffe00000","0xffe00100")
        with self.assertRaisesRegex(ValueError,"secondary initializer"):verify(m,edit)
    def test_sender_wrong_control_global(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace(
             "_DAT_%08x"%m.control_base_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"computed control"):verify(m,edit)
    def test_sender_wrong_selector_ptr(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace(
             "_DAT_%08x"%m.selector_ptr_slot,"_DAT_00000000")
        with self.assertRaisesRegex(ValueError,"computed control"):verify(m,edit)
    def test_sender_wrong_stride(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace("* 0x40","* 0x20")
        with self.assertRaisesRegex(ValueError,"computed control"):verify(m,edit)
    def test_sender_wrong_MMIO_register_offset(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace("+ 0x220","+ 0x224")
        with self.assertRaisesRegex(ValueError,"computed control"):verify(m,edit)
    def test_sender_wrong_store_value(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace("= 1;","= 2;")
        with self.assertRaisesRegex(ValueError,"computed control"):verify(m,edit)
    def test_sender_wrong_queue_header(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace("param_3 << 0x10","param_3 << 0x08")
        with self.assertRaisesRegex(ValueError,"index update"):verify(m,edit)
    def test_sender_no_logger1(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace(
               "FUN_%08x"%m.dbg_string_logger,"FUN_00000000")
        with self.assertRaisesRegex(ValueError,"index update"):verify(m,edit)
    def test_sender_no_logger2(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["send"]=o["logs"]["send"].replace(
               "FUN_%08x"%m.dbg_hex_logger,"FUN_00000000")
        with self.assertRaisesRegex(ValueError,"index update"):verify(m,edit)
    def test_missing_debug_string(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["debug"]=o["logs"]["debug"].replace("char *pcVar1;","uint v1;")
        with self.assertRaisesRegex(ValueError,"format text"):verify(m,edit)
    def test_missing_debug_hex(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["debug"]=o["logs"]["debug"].replace("uVar1 = 0x1c;","uVar1 = 0x10;")
        with self.assertRaisesRegex(ValueError,"format text"):verify(m,edit)
    def test_debug_unexpected_register_access(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["debug"]=o["logs"]["debug"].replace(
             "puthex(0x5b);","puthex(0x5b); notify(0x220);")
        with self.assertRaisesRegex(ValueError,"unexpected control"):verify(m,edit)
    def test_xref_wrong_control_count(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["xrefs"]=o["logs"]["xrefs"].replace(
            "addr=%08x n=62 WRITEs=2"%m.control_base_slot,
            "addr=%08x n=62 WRITEs=1"%m.control_base_slot)
        with self.assertRaisesRegex(ValueError,"xrefs"):verify(m,edit)
    def test_xref_wrong_selector_count(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["xrefs"]=o["logs"]["xrefs"].replace(
            "addr=%08x n=64 WRITEs=1"%m.selector_ptr_slot,
            "addr=%08x n=64 WRITEs=2"%m.selector_ptr_slot)
        with self.assertRaisesRegex(ValueError,"xrefs"):verify(m,edit)
    def test_xref_missing_one_init_write(self):
        m=a.MODELS["xs10"]
        def edit(o):o["logs"]["xrefs"]=o["logs"]["xrefs"].replace(
            "from=%08x"%(m.control_initializer_again+16),
            "from=ffffffff")
        with self.assertRaisesRegex(ValueError,"direct-writer"):verify(m,edit)
    def test_xref_wrong_packet_pointer_baseline(self):
        m=a.MODELS["xt4"]
        def edit(o):o["logs"]["xrefs"]=o["logs"]["xrefs"].replace(
            "addr=%08x n=55 WRITEs=1"%m.shared_packet_ptr_slot,
            "addr=%08x n=54 WRITEs=1"%m.shared_packet_ptr_slot)
        with self.assertRaisesRegex(ValueError,"xrefs"):verify(m,edit)

def mutate_original_word(test_n,kind,rel,m_name):
    def test(self):
        m=a.MODELS[m_name]
        if kind=="notify1":site=m.notify_primary+rel
        elif kind=="notify2":site=m.notify_secondary+rel
        elif kind=="sel_init":site=m.selector_initializer+rel
        elif kind=="base_init":site=m.control_initializer+rel
        elif kind=="base_alt":site=m.control_initializer_again+rel
        elif kind.startswith("h_"):site=rel(m)
        else:raise AssertionError(kind)
        def edit(o):o["word"][site]^=1
        with self.assertRaises(ValueError):
            verify(m,edit)
    test.__name__="test_mutate_original_%03d"%test_n
    return test

mutations=[]
for kind in ("notify1","notify2"):
    for rel in range(0,40,4):mutations.append((kind,rel))
for kind in ("sel_init",):
    for rel in range(0,20,4):mutations.append((kind,rel))
for kind in ("base_init","base_alt"):
    for rel in range(0,20,4):mutations.append((kind,rel))
for tag,field,deltas in (
        ("map_write", "map_write", (-8,-4,0)),
        ("map218", "map_write_218", (0,)),
        ("unmap_read","unmap_read",(0,4)),
        ("unmap_214","unmap_clear_214",(0,))
    ):
    for relative in deltas:
        def addr_of_handshake(m,field=field,relative=relative):
            return a.HANDSHAKES[m.name][field]+relative
        mutations.append(("h_"+tag,addr_of_handshake))

for i,(kind,rel) in enumerate(mutations):
    m_name="xs10" if i%2==0 else "xt4"
    setattr(SignalBranch,"test_mutate_original_%03d"%i,
            mutate_original_word(i,kind,rel,m_name))

if __name__=="__main__":
    unittest.main()

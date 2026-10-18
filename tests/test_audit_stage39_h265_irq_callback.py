"""Stage39 synthetic tests for H.265 IRQ registration, handler, CPU wake loop.

All instructions, decompiler-like strings, and status callbacks below are
fabricated toy fixtures. They contain NO Fuji ROM or local private Ghidra log.
Verifies provenance and avoids falsely inferring Main10, a 0xBB9 hardware
consumer, or genuine hardware completion.
"""
import sys
from pathlib import Path
import struct
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_stage39_h265_irq_callback as a

def synth_movh(reg,imm,hi=False,cond=14):
    return ((cond<<28) | (0x03400000 if hi else 0x03000000) |
            (((imm>>12)&15)<<16)|(reg<<12)|(imm&0xfff))

def synth_bl(site,target):
    disp=target-site-8
    if disp%4 or disp<-(1<<25) or disp>=(1<<25):
        raise ValueError("invalid synthetic BL displacement")
    return 0xeb000000 | ((disp//4)&0xffffff)

def mkc(at,body):
    return ("TRACE_DECOMP_BEGIN (GhidraScript)\n"
            "void FUN_%08x(void)\n{\n"%(at)+body+
            "\n}\nTRACE_DECOMP_END (GhidraScript)\n")

def synthetic(m):
    words={}
    def pair(site,reg,target):
        words[site]=synth_movh(reg,target&0xffff)
        words[site+4]=synth_movh(reg,(target>>16),hi=True)

    st=m.irq_token_site
    words[st]=0xe3a04001
    words[st+4]=0xe34d4ef0
    words[st+8]=0xe1a00004
    words[m.irq_start_bl]=synth_bl(m.irq_start_bl,m.irq_start_api)
    pair(m.handler_addr_pair_site,1,m.isr)
    words[m.handler_addr_pair_site+8]=0xe1a00004
    words[m.irq_register_bl]=synth_bl(m.irq_register_bl,m.irq_register_api)

    h=m.isr
    pair(h,3,m.control_ptr_slot)
    for relative,word in (
        (8,0xe5933000),(12,0xe5932018),(16,0xe3120001),
        (20,0x012fff1e),(24,0xe92d4830),(28,0xe28db00c),
        (32,0xe3a02000),(36,0xe583221c),
        (48,0xe5930000),(56,0xe2504000),(92,0xe8bd8830)
    ):words[h+relative]=word
    pair(h+40,3,m.event_handle_global)
    words[m.isr_event_bl]=synth_bl(m.isr_event_bl,m.isr_event_api)

    words[m.event_create_bl]=synth_bl(m.event_create_bl,m.event_create_api)
    words[m.event_handle_store]=0xc5830000
    words[m.rx_task_wait_bl]=synth_bl(m.rx_task_wait_bl,m.rx_task_wait_api)
    words[m.rx_dispatch_bl]=synth_bl(m.rx_dispatch_bl,m.rx_dispatch)
    words[m.rsp_output_bl]=synth_bl(m.rsp_output_bl,m.frame_sender)
    for site,bl in (
        (m.encoder_channel_store,m.encoder_map_bl),
        (m.decoder_channel_store,m.decoder_map_bl)
    ):
        pair(site-16,3,m.channel_ptr_slot)
        words[site-8]=0xe5932000
        words[site-4]=0xe3a01000
        words[site]=0xe5821000
        words[bl]=synth_bl(bl,m.map_session)

    irq=(mkc(m.irq_setup_func,
        "call_mali_start_interrupt;\n"
        "FUN_%08x(0xdef00001);\n"%m.irq_start_api+
        "iVar6 = FUN_%08x(0xdef00001,&LAB_%08x);"%
        (m.irq_register_api,m.isr)))
    isr=(
      "STAGE38_PROBE addr=%08x disassemble=true function=%08x\n"%(h,h)+
      "STAGE38_DECOMP_COMPLETED %08x true\n"%h+
      "STAGE38_C_BEGIN %08x\n"%h+
      "void Stage38_probe_%08x(void)\n{\n"%h+
      "if ((*(uint *)(_DAT_%08x + 0x18) & 1) == 0) return;\n"%m.control_ptr_slot+
      "*(undefined4 *)(_DAT_%08x + 0x21c) = 0;\n"%m.control_ptr_slot+
      "iVar1 = FUN_%08x(_DAT_%08x);\n"%(m.isr_event_api,m.event_handle_global)+
      "h265Int_Handler_err;\n}\n"+
      "STAGE38_C_END %08x\n"%h)
    task=(
     mkc(m.event_handle_create_func,
       "iVar1 = FUN_%08x(0,1,1,0x14);\n"%m.event_create_api+
       "if (iVar1 < 1) return -1;\n"
       "_DAT_%08x = iVar1;"%m.event_handle_global)+
     mkc(m.rx_task_create,
       "local_20 = FUN_%08x;\n"%m.rx_task+
       "s_VpuReceive;\n")
    )
    worker=(mkc(m.rx_task,
       "VpuReceive_task;\n"
       "while (iVar1 = FUN_%08x(_DAT_%08x,0xffffffff),iVar1==-0x31) {};\n"%
        (m.rx_task_wait_api,m.event_handle_global)+
       "FUN_%08x();"%m.rx_dispatch))
    chan="_DAT_%08x"%m.channel_ptr_slot
    encoder=mkc(m.encoder_setup,
       "*%s = 0;\n"%chan+
       "iVar2 = FUN_%08x();"%m.map_session)
    decoder=mkc(m.decoder_setup,
       "*%s = 0;\n"%chan+
       "iVar2 = FUN_%08x();"%m.map_session)
    response=mkc(m.rx_dispatch,
      "if (uVar4 == 0x7d5) FUN_%08x(&DAT_12345678);\n"%m.rsp_input_reader+
      "if (uVar4 == 0x7d8) {\n"
      "if (state[0xc] == 1) {\n"
      "FUN_%08x();\n}\n}"%m.frame_sender)

    logs={
     "setup":irq,
     "isr":isr,
     "runtime":encoder,
     "task":task,
     "task_loop":worker+decoder,
     "response":response,
     "response_xrefs":"PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL\n"%
            (m.rsp_output_bl,m.frame_sender),
    }
    prev37={
        "model":m.model,
        "frame_sender_0xBB9_payload_bytes":72,
        "primary_tx_packet_location":"W+0x92010",
        "primary_rx_packet_location":"W+0x93010",
        "0xBB9_paired_to_0x7D5":"UNPROVEN",
        "0xBB9_direct_VPU_hardware_consumer_observed":False
    }
    prev38={
        "model":m.model,
        "registered_control_range_base":"0xffe00000",
        "notification_register_value":1,
        "channel_scalar_runtime_value":"UNKNOWN",
        "hardware_register_is_a_VPU_doorbell_definition":"UNKNOWN",
        "HEVC_10bit_Main10_or_4K60_proven":False,
    }
    return {"words":words,"gh":logs,
            "prev37":prev37,"prev38":prev38,
            "callback_sites":(m.handler_addr_pair_site,)}

def verify(m,edit=None):
    f=synthetic(m)
    if edit:edit(f)
    return a.verify_irq(m,lambda site:f["words"][site],f["gh"],
                        f["prev37"],f["prev38"],f["callback_sites"])

class ARMSynthetics(unittest.TestCase):
    def test_movw_half(self):
        self.assertEqual(a.movhalf(synth_movh(1,0x887c),1),0x887c)
    def test_movt_half(self):
        self.assertEqual(a.movhalf(synth_movh(3,0xffe0,True),3,True),0xffe0)
    def test_bad_movw_register(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movhalf(synth_movh(0,0x1234),1)
    def test_bad_movw_type(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movhalf(synth_movh(1,0x1234,True),1)
    def test_bad_movt_type(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movhalf(synth_movh(1,0x1234),1,True)
    def test_bad_arm_condition(self):
        with self.assertRaisesRegex(ValueError,"MOVW"):
            a.movhalf(synth_movh(1,0x1234,cond=1),1)
    def test_bl_forward(self):
        self.assertEqual(a.a32_bl(synth_bl(0x123000,0x124000),0x123000),0x124000)
    def test_bl_backward(self):
        self.assertEqual(a.a32_bl(synth_bl(0x124000,0x123000),0x124000),0x123000)
    def test_wrong_bl_cond(self):
        with self.assertRaisesRegex(ValueError,"not a full"):
            a.a32_bl(0x1b000001,0x123000)
    def test_wrong_bl_opcode(self):
        with self.assertRaisesRegex(ValueError,"not a full"):
            a.a32_bl(0xe3a00000,0x123000)
    def test_bad_rom_word_oob(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            a.romword(b"\0"*8,a.SECTION1_BASE+8)
    def test_bad_rom_word_misaligned(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            a.romword(b"\0"*8,a.SECTION1_BASE+1)
    def test_rom_word_little_endian(self):
        self.assertEqual(a.romword(bytes.fromhex("efbeadde"),a.SECTION1_BASE),0xdeadbeef)
    def test_expected_irq_token(self):
        self.assertEqual(a.EVENT_TOKEN,0xdef00001)
    def test_expected_status_offset(self):
        self.assertEqual((a.ISR_FLAG_OFFSET,a.ISR_CLEAR_OFFSET,a.TX_NOTIFY_OFFSET),
                         (0x18,0x21c,0x220))
    def test_full_handler_pair_scanner_synthetic(self):
        m=a.MODELS["xs10"];v=m.isr
        b=synth_movh(1,v&0xffff).to_bytes(4,"little")+\
          synth_movh(1,v>>16,True).to_bytes(4,"little")
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),(0x1000,))
    def test_handler_pair_scanner_reject_wrong_reg(self):
        m=a.MODELS["xt4"];v=m.isr
        b=synth_movh(1,v&0xffff).to_bytes(4,"little")+\
          synth_movh(2,v>>16,True).to_bytes(4,"little")
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),())
    def test_handler_pair_scanner_reject_movw_only(self):
        m=a.MODELS["xt4"];v=m.isr
        b=synth_movh(1,v&0xffff).to_bytes(4,"little")+\
          synth_movh(1,0x0,True).to_bytes(4,"little")
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),())
    def test_handler_pair_scanner_reject_movt_only(self):
        m=a.MODELS["xt4"];v=m.isr
        b=synth_movh(1,0x1234).to_bytes(4,"little")+\
          synth_movh(1,v>>16,True).to_bytes(4,"little")
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),())
    def test_handler_pair_scanner_reject_bad_condition(self):
        m=a.MODELS["xs10"];v=m.isr
        b=synth_movh(1,v&0xffff,cond=1).to_bytes(4,"little")+\
          synth_movh(1,v>>16,True).to_bytes(4,"little")
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),())
    def test_handler_pair_scanner_reject_unaligned_word(self):
        m=a.MODELS["xt4"];v=m.isr
        b=b"\xff"+synth_movh(1,v&0xffff).to_bytes(4,"little")+\
          synth_movh(1,v>>16,True).to_bytes(4,"little")+b"\xee\x00\x00"
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),())
    def test_handler_pair_scanner_many(self):
        m=a.MODELS["xt4"];v=m.isr
        pair=(synth_movh(1,v&0xffff).to_bytes(4,"little")+
              synth_movh(1,v>>16,True).to_bytes(4,"little"))
        b=pair+b"\x00\x00\x00\x00"+pair
        self.assertEqual(a.scan_direct_callback_movw_movt(b,0x1000,v),
                         (0x1000,0x100c))
    def test_bad_decomp_no_marker(self):
        with self.assertRaisesRegex(ValueError,"Ghidra C"):
            a.decomp_c("",0xdeadbeef)
    def test_bad_transient_isr_no_marker(self):
        with self.assertRaisesRegex(ValueError,"not decompiled"):
            a.transient_isr_c("",0xdeadbeef)

class IRQTraceFixture(unittest.TestCase):
    def test_positive_both_models(self):
        for m in a.MODELS.values():
            with self.subTest(m=m.model):
                r=verify(m)
                self.assertEqual(r["interrupt_registration_id"],"0xdef00001")
                self.assertEqual(r["encoder_setup_notification_target_if_unchanged"],
                                 "0xFFE00220")
                self.assertTrue(r["cpu_isr"]["readOnly_ghidra_transient_function_confirmed"])
    def test_channel_zero_encoding_decoding(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertEqual(r["encoding_setup_channel_zero_ARM_store"],
                             "0x%08x"%m.encoder_channel_store)
            self.assertEqual(r["decoding_setup_channel_zero_ARM_store"],
                             "0x%08x"%m.decoder_channel_store)
    def test_independent_cpu_rx_wakeup(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertEqual(r["cpu_isr"]["event_signal_static_slot"],
                             r["event_handle_created_in_CPU_code"])
            self.assertEqual(r["cpu_rx_task"],"FUN_%08x"%m.rx_task)
    def test_0x7d5_and_0x7d8_not_synonymous(self):
        for m in a.MODELS.values():
            r=verify(m)
            self.assertEqual(r["software_rsp_0x7D5_uses_rx_queue_reader"],
                             "FUN_%08x"%m.rsp_input_reader)
            self.assertFalse(r["software_rsp_0x7D8_may_submit_next_0xBB9_frame"][
                               "request_response_pair_0xBB9_to_0x7D8_proven"])
    def test_never_claim_physically_observed_or_unlock(self):
        for m in a.MODELS.values():
            r=verify(m)
            for key in ("hardware_side_0xBB9_receiver_known",
                        "chip_IRQ_ID_official_definition_known",
                        "physical_VPU_interruption_or_Main10_bitdepth_verified",
                        "internal_XS10_10bit_or_4K60_enabled",
                        "camera_contacted_or_firmware_modified"):
                self.assertFalse(r[key])
    def test_stage37_wrong_tx_ring(self):
        m=a.MODELS["xs10"]
        def edit(f):f["prev37"]["primary_tx_packet_location"]="W+0x93010"
        with self.assertRaisesRegex(ValueError,"Stage37"):verify(m,edit)
    def test_stage37_wrong_rx_ring(self):
        m=a.MODELS["xt4"]
        def edit(f):f["prev37"]["primary_rx_packet_location"]="W+0x92010"
        with self.assertRaisesRegex(ValueError,"Stage37"):verify(m,edit)
    def test_stage37_wrong_message_size(self):
        m=a.MODELS["xs10"]
        def edit(f):f["prev37"]["frame_sender_0xBB9_payload_bytes"]=80
        with self.assertRaisesRegex(ValueError,"Stage37"):verify(m,edit)
    def test_stage37_false_rx_pair(self):
        m=a.MODELS["xt4"]
        def edit(f):f["prev37"]["0xBB9_paired_to_0x7D5"]="PROVEN"
        with self.assertRaisesRegex(ValueError,"Stage37"):verify(m,edit)
    def test_stage38_wrong_MMIO_base(self):
        m=a.MODELS["xs10"]
        def edit(f):f["prev38"]["registered_control_range_base"]="0xffe10000"
        with self.assertRaisesRegex(ValueError,"Stage38"):verify(m,edit)
    def test_stage38_wrong_derived_channel_claim(self):
        m=a.MODELS["xt4"]
        def edit(f):f["prev38"]["channel_scalar_runtime_value"]=0
        with self.assertRaisesRegex(ValueError,"Stage38"):verify(m,edit)
    def test_stage38_premature_hw_doorbell_claim(self):
        m=a.MODELS["xs10"]
        def edit(f):f["prev38"]["hardware_register_is_a_VPU_doorbell_definition"]="PROVEN"
        with self.assertRaisesRegex(ValueError,"Stage38"):verify(m,edit)
    def test_callback_site_moved(self):
        m=a.MODELS["xt4"]
        def edit(f):f["callback_sites"]=(0x12345678,)
        with self.assertRaisesRegex(ValueError,"bounded"):verify(m,edit)
    def test_callback_site_duplicate(self):
        m=a.MODELS["xs10"]
        def edit(f):f["callback_sites"]=(m.handler_addr_pair_site,)*2
        with self.assertRaisesRegex(ValueError,"bounded"):verify(m,edit)
    def test_callback_site_missing(self):
        m=a.MODELS["xt4"]
        def edit(f):f["callback_sites"]=()
        with self.assertRaisesRegex(ValueError,"bounded"):verify(m,edit)
    def test_irq_setup_wrong_registration_token(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["setup"]=f["gh"]["setup"].replace("0xdef00001","0xdef00002")
        with self.assertRaisesRegex(ValueError,"Ghidra setup"):verify(m,edit)
    def test_irq_setup_wrong_callback_name(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["setup"]=f["gh"]["setup"].replace(
               "&LAB_%08x"%m.isr,"&LAB_12345678")
        with self.assertRaisesRegex(ValueError,"Ghidra setup"):verify(m,edit)
    def test_irq_setup_bad_start_marker(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["setup"]=f["gh"]["setup"].replace(
               "call_mali_start_interrupt","fictional_start")
        with self.assertRaisesRegex(ValueError,"same interrupt"):verify(m,edit)
    def test_isr_missing_valid_status_bit(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["isr"]=f["gh"]["isr"].replace(" + 0x18) & 1"," + 0x18) & 2")
        with self.assertRaisesRegex(ValueError,"missing status"):verify(m,edit)
    def test_isr_missing_clear_register(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["isr"]=f["gh"]["isr"].replace(" + 0x21c) = 0;"," + 0x220) = 0;")
        with self.assertRaisesRegex(ValueError,"missing status"):verify(m,edit)
    def test_isr_wrong_event_handle(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["isr"]=f["gh"]["isr"].replace(
             "_DAT_%08x"%m.event_handle_global,"_DAT_12345678")
        with self.assertRaisesRegex(ValueError,"missing status"):verify(m,edit)
    def test_isr_missing_decomp(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["isr"]=f["gh"]["isr"].replace(
             "STAGE38_DECOMP_COMPLETED","STAGE38_DECOMP_DID_NOT_COMPLETE")
        with self.assertRaisesRegex(ValueError,"not decompiled"):verify(m,edit)
    def test_no_receive_handle_created(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["task"]=f["gh"]["task"].replace("0,1,1,0x14","0,1,1,0x15")
        with self.assertRaisesRegex(ValueError,"event handle"):verify(m,edit)
    def test_create_handle_returns_not_checked(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["task"]=f["gh"]["task"].replace("if (iVar1 < 1)","if (iVar1 > 1)")
        with self.assertRaisesRegex(ValueError,"event handle"):verify(m,edit)
    def test_wrong_handle_saved(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["task"]=f["gh"]["task"].replace(
            "_DAT_%08x = iVar1"%m.event_handle_global,"_DAT_12345678 = iVar1")
        with self.assertRaisesRegex(ValueError,"event handle"):verify(m,edit)
    def test_missing_worker_registration(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["task"]=f["gh"]["task"].replace(
             "local_20 = FUN_%08x;"%m.rx_task,"local_20 = FUN_12345678;")
        with self.assertRaisesRegex(ValueError,"worker task"):verify(m,edit)
    def test_missing_worker_name(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["task"]=f["gh"]["task"].replace("s_VpuReceive","s_other_task")
        with self.assertRaisesRegex(ValueError,"worker task"):verify(m,edit)
    def test_worker_waits_wrong_handle(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["task_loop"]=f["gh"]["task_loop"].replace(
              "_DAT_%08x,0xffffffff"%m.event_handle_global,
              "_DAT_12345678,0xffffffff")
        with self.assertRaisesRegex(ValueError,"no event wait"):verify(m,edit)
    def test_worker_does_not_dispatch(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["task_loop"]=f["gh"]["task_loop"].replace(
           "FUN_%08x();"%m.rx_dispatch,"FUN_00000000();")
        with self.assertRaisesRegex(ValueError,"no event wait"):verify(m,edit)
    def test_worker_not_debug_label(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["task_loop"]=f["gh"]["task_loop"].replace(
            "VpuReceive_task","VpuMain_task")
        with self.assertRaisesRegex(ValueError,"no event wait"):verify(m,edit)
    def test_wrong_dispatched_response_code(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["response"]=f["gh"]["response"].replace("0x7d5","0x7d4")
        with self.assertRaisesRegex(ValueError,"branches"):verify(m,edit)
    def test_missing_dispatch_reader(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["response"]=f["gh"]["response"].replace(
            "FUN_%08x("%m.rsp_input_reader,"FUN_11111111(")
        with self.assertRaisesRegex(ValueError,"branches"):verify(m,edit)
    def test_wrong_output_frame_response_id(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["response"]=f["gh"]["response"].replace("0x7d8","0x7da")
        with self.assertRaisesRegex(ValueError,"branches"):verify(m,edit)
    def test_wrong_next_frame_sender(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["response"]=f["gh"]["response"].replace(
            "FUN_%08x();"%m.frame_sender,"FUN_11111111();")
        with self.assertRaisesRegex(ValueError,"branches"):verify(m,edit)
    def test_missing_condition_for_rearm(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["response"]=f["gh"]["response"].replace("[0xc] == 1","[0xc] == 0")
        with self.assertRaisesRegex(ValueError,"branches"):verify(m,edit)
    def test_rsp_frame_source_xref_wrong(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["response_xrefs"]=f["gh"]["response_xrefs"].replace(
           "from=%08x"%m.rsp_output_bl,"from=12345678")
        with self.assertRaisesRegex(ValueError,"xref"):verify(m,edit)
    def test_encoder_missing_channel_reset(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["runtime"]=f["gh"]["runtime"].replace(" = 0;"," = 1;")
        with self.assertRaisesRegex(ValueError,"zero-channel"):verify(m,edit)
    def test_decoder_missing_channel_reset(self):
        m=a.MODELS["xt4"]
        def edit(f):f["gh"]["task_loop"]=f["gh"]["task_loop"].replace(" = 0;"," = 1;")
        with self.assertRaisesRegex(ValueError,"zero-channel"):verify(m,edit)
    def test_decoder_missing_MapSession(self):
        m=a.MODELS["xs10"]
        def edit(f):f["gh"]["task_loop"]=f["gh"]["task_loop"].replace(
           "FUN_%08x();"%m.map_session,"FUN_00000000();")
        with self.assertRaisesRegex(ValueError,"zero-channel"):verify(m,edit)

def word_mutator(m_name,site_fn,index):
    def test(self):
        m=a.MODELS[m_name]
        addr=site_fn(m)
        def edit(f):f["words"][addr]^=1
        with self.assertRaises(ValueError):
            verify(m,edit)
    test.__name__="test_mutated_arm_%03d"%index
    return test

sites=[]
for offset in (0,4,8,12,16,20,24,28):
    sites.append(lambda m,offset=offset:m.irq_token_site+offset)
for offset in (0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,92):
    sites.append(lambda m,offset=offset:m.isr+offset)
for name in (
    "event_create_bl","event_handle_store","rx_task_wait_bl",
    "rx_dispatch_bl","rsp_output_bl"
):
    sites.append(lambda m,name=name:getattr(m,name))
for prefix in ("encoder","decoder"):
    key=prefix+"_channel_store"
    for offset in (-16,-12,-8,-4,0):
        sites.append(lambda m,key=key,offset=offset:getattr(m,key)+offset)
    mapkey=prefix+"_map_bl"
    sites.append(lambda m,mapkey=mapkey:getattr(m,mapkey))
for i,site in enumerate(sites):
    for m_name in ("xs10","xt4"):
        setattr(IRQTraceFixture,"test_mutated_arm_%03d_%s"%(i,m_name),
                word_mutator(m_name,site,i))

if __name__=="__main__":
    unittest.main()

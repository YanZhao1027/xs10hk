#!/usr/bin/env python3
"""Stage32 X-S10/X-T4 offline audit of Recorder INPUT Codec -> ACTIVE Codec.

Original Fujifilm X6 Section1/Section2 and Ghidra logs are PRIVATE to the
user's authorized Ubuntu. This script does NOT patch firmwares, execute code
on a camera, read camera RAM or presume HEVC Main10/4K60 availability.

Proven static data edges (when these functions execute):
  descriptor +0x10 -> current input pointer
  input[0x5B0,0x5B1] -> intermediate[0x430/0x434, +1]
  memcpy(intermediate, active template, 0x478/0x47C)
  active template + codec offset == observed Recorder active Codec global
The runtime initial value of input[0x5B0], as well as the GUI path into it,
is still UNKNOWN. The middle call chain is not claimed atomic: intervening
functions can alter intermediate data; indirect write hazards remain.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json,re,struct

@dataclass(frozen=True)
class Model:
    name: str
    sec2base: int
    descriptor: int
    header_site: int
    header_owner: int
    header_len: int
    parent: int
    input_ptr_slot: int
    adapter: int
    adapter_call: int
    adapter_byte_stores: tuple[int,int,int,int]
    intermediate_literal: int
    intermediate_base: int
    intermediate_codec_offset: int
    updater: int
    updater_call: int
    copy_wrapper: int
    copy_wrapper_call: int
    copy_engine: int
    copy_base: int
    copy_len: int
    template_base: int
    template_active_codec: int
    template_active_format: int
    gui_byte: int

MODELS={
 "xs10":Model("xs10",0x01eaf000,0x02d987e8,
    0x021b84c0,0x021b8344,0x44,0x02214738,0x02d9c2ac,
    0x012c9500,0x022147ac,(0x012c9a40,0x012c9a44,0x012c9a48,0x012c9a4c),
    0x02214ca4,0x02d9cc60,0x430,
    0x012c1ce8,0x022148c8,0x012bd110,0x012c1d28,0x00059328,
    0x012bd120,0x478,0x01c24dd8,0x01c25208,0x01c25209,0x01b88650),
 "xt4":Model("xt4",0x01e0f000,0x02d0bf48,
    0x02120d9c,0x02120c20,0x44,0x02180d0c,0x02d0fa0c,
    0x012a313c,0x02180d80,(0x012a3690,0x012a3694,0x012a3698,0x012a369c),
    0x02181278,0x02d103b0,0x434,
    0x0129a4d0,0x02180ea8,0x01295780,0x0129a510,0x00059108,
    0x01295790,0x47c,0x01b83540,0x01b83974,0x01b83975,0x01af2db8)
}

def must(ok,why):
    if not ok:raise ValueError("Stage32 original-ROM audit: "+why)

def rom_word(blob,base,addr):
    at=addr-base
    if at<0 or at%4 or at+4>len(blob):raise ValueError("bad ROM offset")
    return struct.unpack_from("<I",blob,at)[0]

def movpart(word,rd,high=False):
    expected=0x03400000 if high else 0x03000000
    must(word>>28==14 and (word&0x0ff00000)==expected and
         ((word>>12)&15)==rd,"wrong MOVW/MOVT register or instruction")
    return (((word>>16)&15)<<12)|(word&0xfff)

def a32_bl(word,site):
    must(word>>28==14 and (word>>25)&7==5 and (word>>24)&1==1,
         "not unconditional A32 BL")
    disp=word&0xffffff
    if disp&0x800000:disp-=0x1000000
    return (site+8+(disp<<2))&0xffffffff

def c_function(log,addr):
    marker="FUN_%08x"%addr
    for p in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=p.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|uint|int|undefined\d+|char)"
                     r"\s+(?:\*\s*)?"+marker+r"\s*\(",c):
            return c
    raise ValueError("missing local read-only Ghidra C "+marker)

def audit(m,rom1,rom2,header_log,parent_log,adapter_log,
          updater_log,template_log,alias_xrefs):
    s1=lambda at:rom_word(rom1,0x01021000,at)
    s2=lambda at:rom_word(rom2,m.sec2base,at)
    # Initialization sets header payload LENGTH 0x44; separate from actual
    # data pointer at descriptor+0x10. This length may later be overwritten.
    h=m.header_site
    descriptor=movpart(s2(h),3)|(movpart(s2(h+4),3,True)<<16)
    must(descriptor==m.descriptor,"descriptor head address")
    must(s2(h+8)==0xe3a02044,"initial payload length 0x44")
    must(s2(h+12)==0xe5832004,"header length STR [r3,#4]")
    must(s2(h+16)==0xe283200c,"payload address descriptor+0x0c")
    must(s2(h+20)==0xe5832008,"header payload-address STR [r3,#8]")
    header=c_function(header_log,m.header_owner)
    must(("_DAT_%08x = 0x44;"%(m.descriptor+4)) in header,
         "Ghidra 0x44 assignment is absent")
    must(("_DAT_%08x = &DAT_%08x;"%(m.descriptor+8,m.descriptor+12)) in header,
         "payload pointer setup not present")

    # Same Recorder parent uses the pointer value from current descriptor
    # +0x10, calls byte-field adapter, then calls updater later.
    p=c_function(parent_log,m.parent)
    ptr_var="iVar2" if m.name=="xs10" else "iVar3"
    src="_DAT_%08x"% (m.descriptor+0x10)
    must((ptr_var+" = "+src+";") in p,
         "Recorder source buffer pointer origin missing")
    must(("_DAT_%08x = "%m.input_ptr_slot+src+";") in p,
         "Recorder current input pointer slot not copied")
    adapter_name="FUN_%08x"%m.adapter
    updater_name="FUN_%08x"%m.updater
    literal="DAT_%08x"%m.intermediate_literal
    expected_adapter=adapter_name+"("+literal+","+ptr_var+","
    expected_updater=updater_name+"("+literal+","
    must(expected_adapter in p and expected_updater in p and
         p.index(expected_adapter)<p.index(expected_updater),
         "parent active conversion: pointer/ordering mismatch")
    must(s2(m.intermediate_literal)==m.intermediate_base,
         "intermediate buffer original ROM literal mismatch")
    must(m.intermediate_base+m.intermediate_codec_offset <
         m.intermediate_base+0x1000,
         "incorrect intermediate offset")
    for site,target in ((m.adapter_call,m.adapter),
                        (m.updater_call,m.updater)):
        must(a32_bl(s2(site),site)==target,
             "bad original Recorder conversion BL site")

    adapter=c_function(adapter_log,m.adapter)
    co=m.intermediate_codec_offset
    must(("param_1 + 0x%x) = param_2[0x5b0];"%co) in adapter,
         "input+0x5b0 -> intermediate Codec assignment absent")
    must(("param_1 + 0x%x) = param_2[0x5b1];"%(co+1)) in adapter,
         "input+0x5b1 -> intermediate Format assignment absent")
    for at,expected in zip(m.adapter_byte_stores,
          (0xe5d535b0,0xe5c43000|co,0xe5d535b1,0xe5c43000|(co+1))):
        must(s1(at)==expected,
             "original A32 LDRB/STRB Codec/Format 4-word transfer differs")

    updater=c_function(updater_log,m.updater)
    must(("FUN_%08x(param_1);"%m.copy_wrapper) in updater,
         "updater not calling the template copy with its first argument")
    must(a32_bl(s1(m.copy_wrapper_call),m.copy_wrapper_call)==m.copy_wrapper,
         "updater->template-copy original BL target")

    template=c_function(template_log,m.copy_wrapper)
    base=movpart(s1(m.copy_base),5)|(movpart(s1(m.copy_base+4),5,True)<<16)
    must(base==m.template_base,"template base from original MOVW/MOVT")
    must(m.copy_len<0x10000 and
         movpart(s1(m.copy_base+8),6)==m.copy_len,
         "template original MOVW copy size changed")
    must(s1(m.copy_base+12)==0xe1a02006 and
         s1(m.copy_base+16)==0xe1a01004 and
         s1(m.copy_base+20)==0xe1a00005,
         "template copy ABI r2=size,r1=source,r0=destination differs")
    must(a32_bl(s1(m.copy_base+24),m.copy_base+24)==m.copy_engine,
         "template raw BL copy engine target")
    must(s1(m.copy_base+28)==0xe1a02006 and
         s1(m.copy_base+32)==0xe1a01004 and
         s1(m.copy_base+36)==0xe2850d1b,
         "template second copy size/source/dest changed")
    must(a32_bl(s1(m.copy_base+40),m.copy_base+40)==m.copy_engine,
         "template second raw BL copy engine target")
    must(("func_0x%08x(0x%x,param_1,0x%x);" %
          (m.copy_engine,m.template_base,m.copy_len)) in template,
         "template C copy source/destination/length absent")
    must(("func_0x%08x(0x%x,param_1,0x%x);" %
          (m.copy_engine,m.template_base+0x6c0,m.copy_len)) in template,
         "second template C copy source/destination/length absent")

    must(co+1<m.copy_len,
         "template copy cannot contain both Codec and Format offsets")
    must(m.template_base+co==m.template_active_codec and
         m.template_base+co+1==m.template_active_format,
         "direct arithmetic identity with active Recorder bytes failed")
    # The old direct xref probe sees READ but no direct WRITE. The memcpy is
    # precisely why treating WRITE xref=0 as no writer is incorrect.
    match=re.search(r"SLOT_SUMMARY addr=%08x refs=(\d+) functions=(\d+) "
                    r"types=\{([^}]*)\}"%m.template_active_codec,alias_xrefs)
    must(match is not None and "WRITE=" not in match.group(3) and
         "READ=2" in match.group(3),
         "active Codec static read-reference baseline changed")

    return {
      "model":m.name,
      "header_length_initialized_to_0x44":True,
      "descriptor_main_pointer_field":"0x%08x"%(m.descriptor+0x10),
      "current_buffer_pointer_slot":"0x%08x"%m.input_ptr_slot,
      "original_A32_descriptor_header_words_verified":6,
      "original_A32_Codec_and_Format_byte_transfer_words_verified":4,
      "original_A32_template_copy_words_verified":11,
      "original_A32_BL_edges_verified":4,
      "input_offset_codec":"0x5b0","input_offset_format":"0x5b1",
      "intermediate_codec_address":"0x%08x"%(m.intermediate_base+co),
      "intermediate_format_address":"0x%08x"%(m.intermediate_base+co+1),
      "intermediate_to_active_template_copy_size":m.copy_len,
      "active_Recorder_Codec_byte":"0x%08x"%m.template_active_codec,
      "active_Recorder_Format_byte":"0x%08x"%m.template_active_format,
      "input_to_active_static_data_flow_edges_proven":True,
      "external_copy_engine_implementation_decompiled":False,
      "runtime_mutations_during_intervening_calls_excluded":False,
      "runtime_current_buffer_numeric_pointer_value":"UNKNOWN",
      "actual_GUI_to_Recorder_input_codec_initial_assignment_proven":False,
      "GUI_cache_byte_is_not_active_codec_byte":
             m.gui_byte!=m.template_active_codec,
      "HEVC_Main10_internal_bitstream_proven":False,
      "4K60_internal_sensor_ISP_pipeline_proven":False,
      "camera_or_firmware_modified":False
    }

def main():
    ap=ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    root=ap.parse_args().output
    output=[]
    for m in MODELS.values():
        read=lambda f:(root/f).read_text(encoding="utf-8")
        output.append(audit(m,(root/f"x6-{m.name}/section-1.bin").read_bytes(),
               (root/f"x6-{m.name}/section-2.bin").read_bytes(),
               read(f"{m.name}_stage32_descriptor_header_len_writer.log"),
               read(f"{m.name}_stage32_current_to_active_parent.log"),
               read(f"{m.name}_stage32_current_to_template_adapter.log"),
               read(f"{m.name}_stage32_template_update_callers.log"),
               read(f"{m.name}_stage32_template_copy_init.log"),
               read(f"{m.name}_stage32_bridge_field_xrefs.log")))
    print(json.dumps(output,indent=2,ensure_ascii=False))
    print("ORIGINAL OFFLINE ARM: input->intermediate->active field chain found.")
    print("NOT claimed: live Codec value, GUI->input producer, Main10 or 4K60.")

if __name__=="__main__":main()

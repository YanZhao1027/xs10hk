#!/usr/bin/env python3
"""Offline Phase27: trace Recorder profile descriptor -> current-buffer slots.

Two different models share an almost identical 21-word ARM bootstrap.
Verify raw A32 instruction semantics, bootstrap callers and independent
Ghidra address references. NO camera access, patch, codec unlock, or upload
of original proprietary firmware. The ultimate Codec VALUE remains unknown.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json
import re
import struct


@dataclass(frozen=True)
class Spec:
    model: str
    section2_base: int
    init: int
    descriptor: int
    current_slot: int
    companion_slot: int
    gui_codec: int
    callers: tuple[tuple[int,int], ...]


SPECS={
 "xs10":Spec("xs10",0x01eaf000,0x02214738,0x02d987e8,
             0x02d9c2ac,0x02d9c2b0,0x01b88650,
             ((0x021da66c,0x021da63c),(0x021e844c,0x021e842c))),
 "xt4": Spec("xt4",0x01e0f000,0x02180d0c,0x02d0bf48,
             0x02d0fa0c,0x02d0fa10,0x01af2db8,
             ((0x02143f14,0x02143ee4),(0x021529d8,0x021529b8))),
}


def need(cond:bool,desc:str):
    if not cond:raise ValueError("stage27 descriptor provenance: "+desc)


def raw_word(data:bytes,base:int,addr:int)->int:
    off=addr-base
    if off<0 or off+4>len(data) or off%4:
        raise ValueError("unaligned/outside original firmware section")
    return struct.unpack_from("<I",data,off)[0]


def mov_half(word:int,top:bool,reg:int)->int:
    op=(word>>20)&0xff
    need(word>>28==14 and op==(0x34 if top else 0x30) and
         ((word>>12)&15)==reg,
         "MOVT/MOVW operation or register mismatch")
    return (((word>>16)&15)<<12)|(word&0xfff)


def imm_decode(word:int)->int:
    imm=word&255
    shift=((word>>8)&15)*2
    if shift==0:return imm
    return ((imm>>shift)|(imm<<(32-shift)))&0xffffffff


def dp_add(word:int,rn:int,rd:int)->int:
    need(word>>28==14 and ((word>>25)&7)==1 and
         ((word>>21)&15)==4 and ((word>>20)&1)==0 and
         ((word>>16)&15)==rn and ((word>>12)&15)==rd,
         "ADD immediate or registers mismatch")
    return imm_decode(word)


def memword(word:int,load:bool,rn:int,rd:int,offset:int):
    fixed=((word>>26)&3)==1 and ((word>>25)&1)==0 and \
          ((word>>24)&1)==1 and ((word>>23)&1)==1 and \
          ((word>>22)&1)==0 and ((word>>21)&1)==0
    need(word>>28==14 and fixed and
         bool((word>>20)&1)==load and
         ((word>>16)&15)==rn and ((word>>12)&15)==rd and
         (word&0xfff)==offset,
         "LDR/STR expected register or offset changed")


def arm_branch(word:int,at:int,cond:int,link:bool)->int:
    need((word>>28)==cond and ((word>>25)&7)==5 and
         bool((word>>24)&1)==link,
         "A32 B/BL opcode/condition mismatch")
    rel=word&0xffffff
    if rel&0x800000:rel-=0x1000000
    return (at+8+(rel<<2))&0xffffffff


def decompile_function(log:str,addr:int)->str:
    fname="FUN_%08x"%addr
    for seg in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        c=seg.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|byte|char)"
                     r"\s+(?:\*\s*)?"+fname+r"\s*\(",c):
            return c
    raise ValueError("missing private Ghidra function "+fname)


def summarize_ref(log:str,address:int,expect_type:str):
    key="%08x"%address
    match=re.search(r"SLOT_SUMMARY addr=%s refs=(\d+) functions=(\d+) "
                    r"types=\{([^}]*)\}"%key,log)
    need(match is not None,"slot or source header xref summary absent")
    fields=dict((k.strip(),int(v)) for k,v in
                re.findall(r"([A-Z]+)=(\d+)",match.group(3)))
    need(sum(fields.values())==int(match.group(1)),
         "Ghidra reference type aggregation mismatch")
    need(fields.get(expect_type,0)>0,"slot expected Ghidra reference type")
    return {"reference_total":int(match.group(1)),
            "functions":int(match.group(2)),
            "reference_types":fields}


def scan_immediate_strb(section2:bytes,base:int,offset:int)->list[int]:
    """Candidates ONLY: no assertion about which structure Rn points to."""
    out=[]
    for i in range(0,len(section2)-3,4):
        w=struct.unpack_from("<I",section2,i)[0]
        if ((w>>28)==15 or ((w>>26)&3)!=1 or (w>>25)&1 or
            (w>>24)&1==0 or (w>>23)&1==0 or (w>>22)&1==0 or
            (w>>21)&1 or (w>>20)&1 or (w&0xfff)!=offset):
            continue
        out.append(base+i)
    return out


def audit(spec:Spec,section2:bytes,init_log:str,
          caller_log:str,call_refs:str,
          slot_refs:str,header_refs:str):
    # Concrete X-S10/X-T4 bootstrap, not merely common symbol names.
    entry=spec.init
    w=lambda off:raw_word(section2,spec.section2_base,entry+off)
    d1=(mov_half(w(0xc),False,3)|
        (mov_half(w(0x10),True,3)<<16))
    d2=(mov_half(w(0x2c),False,3)|
        (mov_half(w(0x30),True,3)<<16))
    need(d1==spec.descriptor and d2==spec.descriptor,
         "profile descriptor base MOVW/MOVT pair")

    need(w(0x14)==0xe1d310b0,
         "header signature halfword load LDRH R1,[R3]")
    need(w(0x18)==0xe3510c02,
         "bootstrap magic check CMP R1,#0x200")
    need(arm_branch(w(0x1c),entry+0x1c,0,False)==entry+0x2c,
         "bootstrap signature-gated success branch")
    need(w(0x28)==0xeafffffe,
         "signature failure path expected self-loop")
    memword(w(0x34),True,3,0,0xc)
    need(dp_add(w(0x38),3,2)==0x3000,"profile owner base offset")
    memword(w(0x3c),False,2,0,0xac0)
    memword(w(0x40),True,3,1,0x10)
    memword(w(0x44),False,2,1,0xac4)
    memword(w(0x48),True,3,3,0x14)
    memword(w(0x4c),False,2,3,0xac8)
    need(w(0x50)==0xe5d03028,
         "bootstrap following profile-mode field must be same")

    need(spec.descriptor+0x3000+0xac4==spec.current_slot,
         "resolved current slot address mismatch")
    need(spec.descriptor+0x3000+0xac8==spec.companion_slot,
         "resolved companion slot address mismatch")
    need(spec.current_slot+4==spec.companion_slot,
         "primary / secondary pointer layout mismatch")
    need(spec.gui_codec not in (spec.current_slot,spec.descriptor+0x10),
         "GUI value wrongly identified as Recorder profile pointer")

    c=decompile_function(init_log,entry)
    upper=spec.descriptor+0xc
    current=spec.descriptor+0x10
    comp=spec.descriptor+0x14
    for dest,src in ((spec.current_slot-4,upper),
                     (spec.current_slot,current),
                     (spec.companion_slot,comp)):
        need(("_DAT_%08x = _DAT_%08x" %(dest,src)) in c,
             "Ghidra descriptor to pointer slot assignment missing")
    need(("_DAT_%08x != 0x200"%spec.descriptor) in c,
         "Ghidra magic guard missing")
    if spec.model=="xs10":
        need("_DAT_02d9c2b0 + 0x34c" in c,
             "X-S10 secondary-buffer offsets changed")
    else:
        need("iVar5 = *(int *)(iVar3 + 0xac8);" in c
             and "FUN_022235a0(1,iVar5 + 0x5b0" in c,
             "X-T4 +0x5b0 secondary pointer disambiguation changed")

    xref=summarize_ref(slot_refs,spec.current_slot,"WRITE")
    need(xref["reference_types"].get("WRITE")==1,
         "current slot has more than one direct Ghidra writer")
    pattern=(r"SLOT_WRITE_CAND addr=%08x from=%08x type=WRITE "
             r"func=%08x insn=str r1,\[r2,#0xac4\]"%
             (spec.current_slot,entry+0x44,entry))
    need(re.search(pattern,slot_refs) is not None,
         "direct slot writer Ghidra xref does not match A32")
    before=summarize_ref(header_refs,spec.descriptor+0x10,"READ")
    need(before["reference_types"].get("WRITE",0)==0,
         "new direct source-descriptor WRITE reference; investigate")
    need(before["reference_total"]==111,
         "profile descriptor reference baseline changed")
    call_sites=[]
    for address,parent in spec.callers:
        target=arm_branch(raw_word(section2,spec.section2_base,address),
                          address,14,True)
        need(target==entry,"event hook BL changed")
        expected=(r"PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL"%
                  (address,entry))
        need(re.search(expected,call_refs) is not None,
             "event hook Ghidra xref absent")
        cb=decompile_function(caller_log,parent)
        need(("FUN_%08x();"%entry) in cb,
             "event caller Ghidra function missing init call")
        call_sites.append("0x%08x"%address)
    strb=scan_immediate_strb(section2,spec.section2_base,0x5b0)
    return {
        "model":spec.model,
        "original_section2_bootstrap":"0x%08x"%entry,
        "descriptor_header":"0x%08x"%spec.descriptor,
        "descriptor_magic_expected":"0x0200",
        "input_buffer_pointer_header_field":"0x%08x"%(spec.descriptor+0x10),
        "current_buffer_pointer_slot":"0x%08x"%spec.current_slot,
        "secondary_buffer_pointer_slot":"0x%08x"%spec.companion_slot,
        "current_buffer_pointer_runtime_value":"UNKNOWN",
        "input_buffer_codec_at_offset_0x5b0":"UNKNOWN",
        "exact_direct_slot_writer_verified":True,
        "header_direct_writes_in_selected_ghidra_image":before["reference_types"].get("WRITE",0),
        "cannot_exclude_alias_or_external_header_initializers":True,
        "bootstrap_event_hook_Bls":call_sites,
        "bootstrap_event_hook_Bls_verified":len(call_sites),
        "section2_imm_STRB_plus_0x5b0_candidate_count":len(strb),
        "STRB_candidates_equated_to_recorder_writers":False,
        "gui_codec_value":"0x%08x"%spec.gui_codec,
        "gui_to_input_buffer_codec_assignment_proven":False,
        "internal_hevc_main10_proven":False,
        "internal_4k60_proven":False,
        "firmware_patch_created":False,
        "camera_modified":False,
    }


def crosscheck_homologous_blocks(data_xs:bytes,data_xt:bytes):
    """Both originals: exactly five relocation/absolute-data differences."""
    a,b=SPECS["xs10"],SPECS["xt4"]
    offsets=list(range(0,0x54,4))
    diffs=[off for off in offsets if
           raw_word(data_xs,a.section2_base,a.init+off)!=
           raw_word(data_xt,b.section2_base,b.init+off)]
    need(diffs==[0xc,0x10,0x24,0x2c,0x30],
         "homologous 21-word bootstrap changes diverged unexpectedly")
    return {"compared_a32_words":21,"identical_words":21-len(diffs),
            "relocation_or_address_differences":[hex(x) for x in diffs]}


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    root=p.parse_args().output
    txt=lambda name:(root/name).read_text(encoding="utf-8")
    binaries={}
    audits=[]
    for model,spec in SPECS.items():
        binary=(root/f"x6-{model}/section-2.bin").read_bytes()
        binaries[model]=binary
        audits.append(audit(
            spec,binary,
            txt(f"{model}_stage27_initializer_helpers.log"),
            txt(f"{model}_stage27_pointer_init_callsite_context.log"),
            txt(f"{model}_stage27_pointer_init_callers.log"),
            txt(f"{model}_stage27_buffer_slot_access.log"),
            txt(f"{model}_stage27_profile_header_xrefs.log"),
        ))
    result={"per_model":audits,"homologous_bootstrap":
            crosscheck_homologous_blocks(binaries["xs10"],binaries["xt4"])}
    print(json.dumps(result,indent=2,ensure_ascii=False))
    print("OFFLINE ONLY: bootstrap pointer proven, codec VALUE remains UNKNOWN.")


if __name__=="__main__":
    main()

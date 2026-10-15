#!/usr/bin/env python3
"""Offline evidence audit: find bulk writers into Fuji Recorder source snapshots.

This script does not load, modify, or communicate with camera hardware.
It requires the user's private *original* unpacked X6 section-2 and Ghidra logs.
Confirmed: bulk copies COVER the codec+format bytes.
Unconfirmed: where the input buffer's codec byte came from, Main10, 4K60.
"""
from dataclasses import dataclass
from pathlib import Path
from argparse import ArgumentParser
from collections import Counter
import json
import re
import struct


@dataclass(frozen=True)
class Writer:
    name: str
    entry: int
    call_site: int
    dest_load_site: int
    dest_literal: int
    size_mov_site: int
    copy_size: int
    source_load_site: int
    source_kind: str
    owner_load_site: int = 0
    owner_literal: int = 0
    owner_movw_site: int = 0
    owner_movt_site: int = 0
    owner_add_site: int = 0
    callers: tuple[int, ...] = ()


@dataclass(frozen=True)
class Model:
    name: str
    section2_base: int
    snapshot: int
    owner: int
    buffer_pointer_global: int
    memcpy_entry: int
    gui_codec: int
    writers: tuple[Writer, ...]


SPECS = {
    "xs10": Model(
        "xs10",0x01eaf000,0x02d9d284,0x02d9b7e8,0x02d9c2ac,
        0x012a9148,0x01b88650,(
            Writer("current_profile_clone",0x02216ad8,0x02216b1c,
                   0x02216b10,0x02216b28,0x02216b18,0x5dc,
                   0x02216b08,"literal_owner",0x02216b04,0x02216b24,
                   callers=(0x021e29c0,)),
            Writer("callers_buffer_clone",0x022069d0,0x022069e8,
                   0x022069e4,0x02206a7c,0x022069e0,0x5dc,
                   0x022069d8,"parameter",callers=(0x0220626c,)),
            Writer("runtime_profile_clone",0x02212304,0x02212338,
                   0x02212334,0x0221239c,0x0221232c,0x5dc,
                   0x02212330,"constructed_owner",
                   owner_movw_site=0x02212320,
                   owner_movt_site=0x02212324,
                   owner_add_site=0x02212328,
                   callers=(0x021da584,0x021da5d4)),
        )),
    "xt4": Model(
        "xt4",0x01e0f000,0x02d109d4,0x02d0ef48,0x02d0fa0c,
        0x01281848,0x01af2db8,(
            Writer("live_profile_update",0x02184f00,0x02184f34,
                   0x02184f30,0x02184fd4,0x02184f28,0x5d8,
                   0x02184f2c,"constructed_owner",
                   owner_movw_site=0x02184f1c,
                   owner_movt_site=0x02184f20,
                   owner_add_site=0x02184f24,
                   callers=(0x02139c80,0x02139de8)),
        )),
}


def require(ok, what):
    if not ok:
        raise ValueError("stage26 bulk writer: " + what)


def word_at(section: bytes, base: int, address: int) -> int:
    pos=address-base
    if pos<0 or pos%4 or pos+4>len(section):
        raise ValueError("unaligned/outside original section")
    return struct.unpack_from("<I",section,pos)[0]


def decode_bl(word: int, at: int) -> int:
    if word>>28!=14 or ((word>>25)&7)!=5 or ((word>>24)&1)!=1:
        raise ValueError("not an unconditional A32 BL")
    delta=word&0xffffff
    if delta&0x800000:delta-=0x1000000
    return (at+8+(delta<<2))&0xffffffff


def decode_load_word(word:int):
    """LDR Rd,[Rn,+immediate] with P=U=L=1, I=B=W=0, AL."""
    if word>>28!=14 or ((word>>26)&3)!=1 or ((word>>25)&1)!=0:
        raise ValueError("not A32 LDR immediate")
    need=(1<<24)|(1<<23)|(1<<20)
    if (word&need)!=need or (word&(1<<22)) or (word&(1<<21)):
        raise ValueError("not standard positive LDR")
    return ((word>>16)&15,(word>>12)&15,word&4095)


def decode_move_half(word:int,top:bool,rd:int)->int:
    mask=word&0x0ff00000
    require(word>>28==14 and
            mask==(0x03400000 if top else 0x03000000) and
            ((word>>12)&15)==rd,"MOVW/MOVT register or operation")
    return (((word>>16)&15)<<12)|(word&0xfff)


def decode_add_imm(word:int,rn:int,rd:int)->int:
    require(word>>28==14 and ((word>>25)&7)==1 and
            ((word>>21)&15)==4 and ((word>>20)&1)==0 and
            ((word>>16)&15)==rn and ((word>>12)&15)==rd,
            "ADD instruction does not use expected registers")
    imm=word&255
    rot=((word>>8)&15)*2
    return ((imm>>rot)|(imm<<(32-rot)))&0xffffffff if rot else imm


def decompiled(log: str, entry: int) -> str:
    target="FUN_%08x"%entry
    for b in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        body=b.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|char|byte)\s+"
                     +target+r"\s*\(",body):
            return body
    raise ValueError("Ghidra decompilation missing "+target)


def count_base_references(log:str,model:Model)->dict:
    a="%08x"%model.snapshot
    m=re.search(r"SRC_SCAN target=%s xrefs=(\d+) funcs=(\d+)"%a,log)
    require(m is not None,"missing source baseline scanner summary")
    rows=re.findall(r"SRC_REF target=%s from=[0-9a-f]+ type=([A-Z]+) "%a,log)
    cnt=Counter(rows)
    require(len(rows)==int(m.group(1)),"source xref count mismatch")
    # A raw Ghidra memory-reference WRITE search is insufficient for memcpy!
    require(cnt.get("WRITE",0)==0,"new direct source WRITE candidate detected")
    return {"xref_count":len(rows),
            "referencing_functions":int(m.group(2)),
            "xref_reference_types":dict(sorted(cnt.items())),
            "direct_base_address_write_xrefs":cnt.get("WRITE",0),
            "absence_of_writers_inferred_from_xrefs":False}


def audit_writer(model:Model,site:Writer,original:bytes,c:str,
                 xrefs:str)->dict:
    base=model.section2_base
    at=lambda addr:word_at(original,base,addr)
    # Raw LDR PC literal at the call site must point to a data literal,
    # and the literal must contain the actual source snapshot base.
    ldr=decode_load_word(at(site.dest_load_site))
    require(ldr==(15,0,site.dest_literal-(site.dest_load_site+8)),
            "%s: destination PC literal LDR"%site.name)
    require(word_at(original,base,site.dest_literal)==model.snapshot,
            "%s: destination is not source snapshot base"%site.name)
    require(decode_move_half(at(site.size_mov_site),False,2)==site.copy_size,
            "%s: literal copy length mismatch"%site.name)
    require(decode_bl(at(site.call_site),site.call_site)==model.memcpy_entry,
            "%s: BL target not memcpy function"%site.name)
    require(site.copy_size>0x5b1,
            "%s: copy misses Codec/Format pair"%site.name)
    if site.source_kind=="literal_owner":
        value=decode_load_word(at(site.owner_load_site))
        require(value==(15,3,site.owner_literal-(site.owner_load_site+8)),
                "owner PC literal LDR")
        require(word_at(original,base,site.owner_literal)==model.owner,
                "owner address literal mismatch")
        require(decode_load_word(at(site.source_load_site))==(3,1,0xac4),
                "current buffer pointer indirection changed")
    elif site.source_kind=="constructed_owner":
        lo=decode_move_half(at(site.owner_movw_site),False,4)
        hi=decode_move_half(at(site.owner_movt_site),True,4)
        add=decode_add_imm(at(site.owner_add_site),4,3)
        require(((hi<<16)|lo)+add==model.owner,
                "constructed current-buffer owner mismatch")
        require(decode_load_word(at(site.source_load_site))==(3,1,0xac4),
                "constructed owner +0xAC4 indirection changed")
    elif site.source_kind=="parameter":
        require(at(site.source_load_site)==0xe2501000,
                "SUBS R1,R0,#0 source-argument preservation missing")
        skip=word_at(original,base,site.source_load_site+4)
        require((skip>>28)==0 and ((skip>>25)&7)==5 and
                ((skip>>24)&1)==0,
                "nonzero argument conditional skip missing")
        relative=skip&0xffffff
        if relative&0x800000:relative-=0x1000000
        branch_dest=(site.source_load_site+12+(relative<<2))&0xffffffff
        require(branch_dest==0x02206a74,
                "zero-argument skip does not bypass copy")
        require(site.copy_size==0x5dc,"unexpected argument clone width")
    else:
        raise ValueError("unknown writer source_kind")

    expected="FUN_%08x("%model.memcpy_entry
    require(expected in c and "0x%x"%site.copy_size in c,
            "%s: Ghidra C misses bulk copy"%site.name)
    if site.source_kind=="parameter":
        require("if (param_1 == 0)" in c and
                "FUN_%08x(DAT_%08x,param_1,0x%x)" %
                (model.memcpy_entry,site.dest_literal,site.copy_size) in c,
                "conditional parameter-to-snapshot copy absent")
    elif model.name=="xs10" and site.source_kind=="literal_owner":
        require("_DAT_02f5b294 = *(undefined4 *)(DAT_02216b24 + 0xac4)" in c
                and ("FUN_%08x(DAT_02216b28,_DAT_02f5b294,0x5dc)"%
                     model.memcpy_entry) in c,
                "current-buffer owner to source snapshot link absent")
    elif model.name=="xs10":
        require("FUN_012a9148(DAT_0221239c,_DAT_02d9c2ac,0x5dc)" in c,
                "runtime config pointer to source snapshot link absent")
    else:
        require("FUN_01281848(DAT_02184fd4,_DAT_02d0fa0c,0x5d8)" in c,
                "XT4 current config pointer to source snapshot link absent")

    for call in site.callers:
        require(decode_bl(at(call),call)==site.entry,
                "%s: event caller BL target"%site.name)
        require(re.search(r"PROBE_REF from=%08x to=%08x type=UNCONDITIONAL_CALL" %
                          (call,site.entry),xrefs) is not None,
                "%s: missing private Ghidra call xref"%site.name)

    return {
        "site":site.name,
        "writer_function":"0x%08x"%site.entry,
        "memcpy_call":"0x%08x"%site.call_site,
        "copied_bytes":"0x%x"%site.copy_size,
        "covered_offsets":["0x5b0","0x5b1"],
        "source_kind":site.source_kind,
        "input_buffer_codec_offset":"0x5b0",
        "runtime_input_codec_value_known":False,
        "upstream_calls_verified":len(site.callers),
    }


def audit(model:Model,section2:bytes,helper_log:str,writers_log:str,
          xrefs:str,base_refs:str,live_scan:str)->dict:
    helper=decompiled(helper_log,model.memcpy_entry)
    require("*puVar2 = *(undefined1 *)puVar1;" in helper and
            "*param_1 = *param_2;" in helper,
            "copy helper's destination-first semantics not verified")
    results=[]
    for site in model.writers:
        c=decompiled(writers_log,site.entry)
        results.append(audit_writer(model,site,section2,c,xrefs))
    pointer_match=re.search(
        r"LIVE_SUMMARY addr=%08x funcs=(\d+) decompiled=(\d+) "
        r"field_functions=(\d+) capped=(\d+)"%model.buffer_pointer_global,
        live_scan)
    require(pointer_match is not None,"missing bounded pointer xref scan")
    funcs,decompiled_count,found,truncated=map(int,pointer_match.groups())
    require(funcs==decompiled_count,"current pointer scan incomplete")
    require(truncated==0,"field scan results were truncated")
    require(model.owner+0xac4==model.buffer_pointer_global,
            "current-buffer owner pointer +AC4 wrong")
    return {
        "model":model.name,
        "snapshot_base":"0x%08x"%model.snapshot,
        "snapshot_codec":"0x%08x"%(model.snapshot+0x5b0),
        "snapshot_format":"0x%08x"%(model.snapshot+0x5b1),
        "runtime_input_buffer_pointer_global":"0x%08x"%
                                             model.buffer_pointer_global,
        "runtime_input_buffer_pointer_value":"UNKNOWN",
        "runtime_input_buffer_codec_value":"UNKNOWN",
        "gui_moviecodec_byte":"0x%08x"%model.gui_codec,
        "verified_bulk_writers":results,
        "original_arm_bulk_writer_count":len(results),
        "original_arm_writer_and_caller_BL_verified":
                    len(results)+sum(len(w.callers) for w in model.writers),
        "source_base_xrefs":count_base_references(base_refs,model),
        "bounded_live_buffer_field_reference_scan":{
            "functions":funcs,"decompiled":decompiled_count,
            "with_literal_field_matches":found,
            "exhaustive_dataflow_proof":False,
        },
        "gui_to_runtime_input_buffer_codec_value_proven":False,
        "hevc_main10_internal_encoding_proven":False,
        "4k60_sensor_pipeline_proven":False,
        "camera_or_firmware_modified":False,
    }


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=Path("output"))
    o=p.parse_args().output
    data=lambda name:(o/name).read_text(encoding="utf-8")
    records=[]
    for m,s in SPECS.items():
        records.append(audit(
            s,(o/f"x6-{m}/section-2.bin").read_bytes(),
            data(f"{m}_stage26_memcpy_source_ops.log"),
            data(f"{m}_stage26_memcpy_source_ops.log"),
            data(f"{m}_stage26_writer_upstream_refs.log"),
            data(f"{m}_stage26_source_base_writer_candidates.log"),
            data(f"{m}_stage26_live_buffer_codec_field_scan.log"),
        ))
    print(json.dumps(records,indent=2,ensure_ascii=False))
    print("OFFLINE ONLY: confirmed bulk SOURCE SNAPSHOT writes; "
          "unknown GUI source, Main10, 4K60.")


if __name__=="__main__":
    main()

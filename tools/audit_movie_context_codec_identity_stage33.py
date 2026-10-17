#!/usr/bin/env python3
"""Stage33 offline provenance audit: ACTIVE video config -> movie context -> control.

Source: private original X6 Section1/2 + read-only Ghidra C logs on the
authorized Ubuntu machine. No camera commands, firmware patches, or ROM bytes
embedded in this public tool.

Be precise about field identity: movie context +0x5b0 copies template +8,
not template Codec at +0x430 (X-S10) / +0x434 (X-T4).
The real GUI->Recorder INPUT +0x5b0 initial assignment is not proven.
"""
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
import json,re,struct

@dataclass(frozen=True)
class Specs:
    name: str
    s2base: int
    active: int
    active_codec: int
    codec_off: int
    copy_length: int
    primary: int
    primary_movw: int
    primary_copy: int
    primary_normalize: int
    backup: int
    backup_literal: int
    backup_copy: int
    backup_normalize: int
    memcpy: int
    codec_reader: int
    codec_reader_site: int
    format_reader: int
    format_reader_site: int
    mov_label: int
    mp4_label: int
    gui_pair_global: int
    gui_reader: int

SPECS={
"xs10": Specs("xs10",0x01eaf000,0x01c24dd8,0x01c25208,0x430,0x478,
    0x012bd150,0x012bd160,0x012bd178,0x012bd17c,
    0x012c1ef4,0x012c1f60,0x012c1f18,0x012c1f1c,
    0x012a9148,0x022b6230,0x022b6784,0x022cf30c,0x022cf318,
    0x0269723c,0x02697240,0x01b88650,0x01182820),
"xt4": Specs("xt4",0x01e0f000,0x01b83540,0x01b83974,0x434,0x47c,
    0x012957c0,0x012957d0,0x012957e8,0x012957ec,
    0x0129a6dc,0x0129a748,0x0129a700,0x0129a704,
    0x01281848,0x02222a00,0x02222f44,0x0223b8fc,0x0223b908,
    0x025f5f70,0x025f5f74,0x01af2db8,0x0115663c),
}

def must(value,reason):
    if not value:raise ValueError("stage33 X6 evidence audit: "+reason)

def word(data,base,addr):
    k=addr-base
    if k<0 or k+4>len(data) or k%4:raise ValueError("ROM address invalid")
    return struct.unpack_from("<I",data,k)[0]

def rom_four(blob,base,address):
    k=address-base
    if k<0 or k+4>len(blob):raise ValueError("ROM literal outside region")
    return blob[k:k+4]

def movw_part(insn,register,high=False):
    required=0x03400000 if high else 0x03000000
    must(insn>>28==14 and insn&0x0ff00000==required and
         insn>>12&15==register,"MOVW/MOVT register/op mismatch")
    return (((insn>>16)&15)<<12)|(insn&0xfff)

def bl(insn,addr):
    must(insn>>28==14 and insn>>25&7==5 and insn>>24&1==1,"not A32 BL")
    off=insn&0xffffff
    if off&0x800000:off-=0x1000000
    return (addr+8+(off<<2))&0xffffffff

def c_function(log,addr):
    needle="FUN_%08x"%addr
    for part in log.split("TRACE_DECOMP_BEGIN (GhidraScript)")[1:]:
        body=part.split("TRACE_DECOMP_END (GhidraScript)")[0]
        if re.search(r"(?m)^\s*(?:void|int|uint|undefined\d+|byte|char)"
                     r"\s+(?:\*\s*)?"+needle+r"\s*\(",body):
            return body
    raise ValueError("Ghidra function absent "+needle)

def conditional_default(src1,normalize_at):
    # Original ARM LDRB [r5,#8], CMP #0x25, MOVEQ #0x21,
    # STRBEQ [r4,#0x5b0] is not a GUI-mode assignment.
    for i,expected in enumerate((0xe5d53008,0xe3530025,
                                 0x03a03021,0x05c435b0)):
        must(src1(normalize_at+4*i)==expected,
             "movie-context +0x5b0 normalization instruction changed")

def audit(s,seg1,seg2,primary_log,backup_log,codec_log,format_log,
          gui_log,phase32):
    s1=lambda p:word(seg1,0x01021000,p)
    s2=lambda p:word(seg2,s.s2base,p)
    must(phase32.get("model")==s.name and
         phase32.get("input_to_active_static_data_flow_edges_proven") is True and
         phase32.get("active_Recorder_Codec_byte")=="0x%08x"%s.active_codec,
         "parent Stage32 original-ROM proof mismatch")
    active_codec=s.active+s.codec_off
    must(active_codec==s.active_codec and
         s.codec_off+1<s.copy_length,"active codec offset/size mismatch")
    must(s.codec_off!=8,"movie context +0x5b0 is NOT the Codec")
    must(s.active+0x6c0 == s1(s.backup_literal),
         "ROM literal for backup +0x6c0 does not match copy source")

    # primary template -> movie context +0x5a8
    primary_base=(movw_part(s1(s.primary_movw),5) |
                 movw_part(s1(s.primary_movw+4),5,True)<<16)
    must(primary_base==s.active,"primary MOVW/MOVT wrong")
    must(movw_part(s1(s.primary_movw+8),2)==s.copy_length,
         "primary movie-context copy length wrong")
    must(bl(s1(s.primary_copy),s.primary_copy)==s.memcpy,
         "primary movie-context copy BL changed")
    conditional_default(s1,s.primary_normalize)

    # backup template -> same context +0x5a8 (other recording flow)
    must(bl(s1(s.backup_copy),s.backup_copy)==s.memcpy,
         "backup movie-context copy BL changed")
    conditional_default(s1,s.backup_normalize)

    primary=c_function(primary_log,s.primary)
    backup=c_function(backup_log,s.backup)
    ccopy="FUN_%08x"%s.memcpy
    expr="%s(param_1 + 0x5a8,0x%x,0x%x);"%(ccopy,s.active,s.copy_length)
    must(expr in primary,
         "Ghidra primary copy is not template -> movie context+0x5a8")
    expr="%s(param_1 + 0x5a8,DAT_%08x,0x%x);"%(ccopy,s.backup_literal,s.copy_length)
    must(expr in backup,
         "Ghidra backup copy is not template -> movie context+0x5a8")
    for c in (primary,backup):
        must("param_1 + 0x5b0) = 0x21;" in c and
             (" == '%'" in c),
             "normalization context or source test absent")

    # When the prior ACTIVE codec is copied into a context, its offset
    # changes to +0x5a8+CodecOffset, not +0x5b0.
    context_codec=0x5a8+s.codec_off
    context_format=context_codec+1
    must(context_codec in (0x9d8,0x9dc),"context codec address derivation")
    c=c_function(codec_log,s.codec_reader)
    must("param_1 + 0x%x) == '\\x01'"%context_codec in c and
         "uVar8 = 4;" in c and "uVar8 = 5;" in c and
         "*(uint *)(param_4 + 0x220) = uVar8 | 0x10000;" in c,
         "recording-context byte -> output param_4+0x220 mapping absent")
    for i,expected in enumerate((0xe5d43000|context_codec,
                                 0xe3530001,0x03a03004,0x13a03005,
                                 0xe3403001,0xe5853220)):
        must(s2(s.codec_reader_site+4*i)==expected,
             "packet codec A32 compare/selector/store mismatch")

    f=c_function(format_log,s.format_reader)
    must("param_1 + 0x%x) == '\\x01'"%context_format in f and
         ("&DAT_%08x"%s.mp4_label) in f and
         ("&DAT_%08x"%s.mov_label) in f,
         "MOV/MP4 format branch or literal identity changed")
    must(s2(s.format_reader_site)==(0xe5d02000|context_format) and
         s2(s.format_reader_site+4)==0xe3520001,
         "movie format byte and CMP #1 A32 changed")
    # conditional MOVW/MOVT selects MOV when !1, MP4 when ==1.
    for idx,(dest,cc) in enumerate(((s.mov_label,1),(s.mp4_label,0))):
        l=s2(s.format_reader_site+8+8*idx)
        h=s2(s.format_reader_site+12+8*idx)
        must(l>>28==cc and h>>28==cc,
             "MOV/MP4 condition-code selector mismatch")
        must((movw_part((l&0x0fffffff)|(0xe<<28),1) |
             movw_part((h&0x0fffffff)|(0xe<<28),1,True)<<16)==dest,
             "MOV/MP4 selected string address wrong")
    for at,payload in ((s.mov_label,b"MOV\x00"),(s.mp4_label,b"MP4\x00")):
        must(rom_four(seg2,s.s2base,at)==payload,
             "MOV or MP4 original Section2 string mismatch")

    gui=c_function(gui_log,s.gui_reader)
    for val,option in ((1,0),(0,1),(0x101,2),(0x100,3)):
        literal=hex(val) if val>1 else str(val)
        pattern=(r"(?:if|else if)\s*\(_DAT_%08x == %s\)\s*\{\s*"
                 r"param_1\[0xa1\] = %d;" %
                 (s.gui_pair_global,re.escape(literal),option))
        must(re.search(pattern,gui) is not None,
             "UI Codec+Format 16-bit 4-way status map changed")

    return {
        "model":s.name,
        "original_ROM_A32_and_literal_words_checked":26,
        "original_ROM_ASCII_labels_checked":2,
        "primary_active_template":"0x%08x"%s.active,
        "second_backup_template":"0x%08x"%(s.active+0x6c0),
        "movie_copy_target_offset":"0x5a8",
        "movie_copy_bytes":s.copy_length,
        "movie_context_plus_0x5b0_reads_active_template_field":"0x08",
        "movie_context_plus_0x5b0_is_Recorder_Codec":False,
        "movie_context_codec_offset":"0x%x"%context_codec,
        "movie_context_format_offset":"0x%x"%context_format,
        "codec_control_if_byte_equals_1":"0x10004",
        "codec_control_otherwise":"0x10005",
        "codec_control_values_means_HEVC_or_Main10":"UNKNOWN",
        "format_byte_1":"MP4",
        "format_other_byte":"MOV",
        "ui_combined_codec_format_status_map":{"0x0001":0,"0x0000":1,
                                                "0x0101":2,"0x0100":3},
        "source_backup_normalization_if_field_8_is_0x25":"0x21",
        "movie_copy_engine_runtime_execution_proven":False,
        "same_runtime_context_object_across_callers_proven":False,
        "GUI_MovieCodec_to_Recorder_initial_0x5b0_assignment_proven":False,
        "Main10_bitstream_proven":False,
        "4K60_internal_pipeline_proven":False,
        "camera_touched":False
    }

def main():
    ap=ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    root=ap.parse_args().output
    rawphase=(root/"stage32_codec_forward_audit_result.jsonlog").read_text()
    p32=json.loads(rawphase.split("\nORIGINAL OFFLINE ARM:")[0])
    results=[]
    for s in SPECS.values():
        log=lambda x:(root/x).read_text()
        primarylog=(f"{s.name}_stage29_codec_buffer_init_deep.log" if s.name=="xs10"
                    else f"{s.name}_stage33_context_copy_sources.log")
        backuplog=(f"{s.name}_stage33_codec_default_validator.log" if s.name=="xs10"
                   else f"{s.name}_stage33_context_copy_sources.log")
        results.append(audit(s,
         (root/f"x6-{s.name}/section-1.bin").read_bytes(),
         (root/f"x6-{s.name}/section-2.bin").read_bytes(),
         log(primarylog),log(backuplog),
         log(f"{s.name}_stage33_movie_context_fields_consumers.log"),
         log(f"{s.name}_stage33_movie_context_fields_consumers.log"),
         log(f"{s.name}_stage33_gui_readers_decomp.log"),
         next(v for v in p32 if v["model"]==s.name)))
    print(json.dumps(results,indent=2,ensure_ascii=False))
    print("Stage33 is READ-ONLY static program analysis. No initial GUI->Recorder assignment, Main10 or 4K60 proof.")

if __name__=="__main__":main()

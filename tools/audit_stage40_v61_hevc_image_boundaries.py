#!/usr/bin/env python3
"""Stage40 OFFLINE original payload audit: V61 HEVC encode/decode image split.

Read-only audit of FUJI X-T3 5.11, X-T4 2.12, X-S10 3.11 original decoded
local payloads. No physical camera use, writes/patches, flashing, USB/FF80.
Private firmware and any raw V61 instructions remain ONLY in ignored output/.
Only the derived original audit method + synthetic tests are publishable.

Important correction: the 0x68000 region previously called H.265 'encoder'
contains an independent HEVC encoder 0x39000 AND HEVC decoder 0x2F000.
Shared diagnostic STRINGS are evidence of embedded diagnostics, not that
their branches are reached on any specific device. Proprietary V61 command
decoder & pixel-format enum semantics remain UNVERIFIED.
"""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import struct

SIGNATURE=bytes.fromhex("5eeb000004020000")+b"56610002"
BUNDLE_BYTES=0xB5000
HEVC_BUNDLE_BYTES=0x68000
HEVC_DEC_OFFSET=0x39000
ENC_CODE_WINDOW=(0x140,0xDF00)
RAW_FRAME_COMMAND=0xBB9

@dataclass(frozen=True)
class Camera:
    name:str
    version:str
    module_region_payload_offset:int

CAMERAS=(
  Camera("xt3","5.11",0x02C60000),
  Camera("xt4","2.12",0x02C40000),
  Camera("xs10","3.11",0x02DA0000),
)

@dataclass(frozen=True)
class Image:
    key:str
    start:int
    end:int
    name:str
    sha256:str
    metadata:tuple

IMAGES=(
 Image("hevc_encoder",0x0,0x39000,"H.265 MP Encoder",
       "37b04b1a4b2a97ce7d77200eadb2164be949b0fbd7390c241af00a82ba750880",
       (0x38080,0x3A000,0x12,0x3FBF9)),
 Image("hevc_decoder",0x39000,0x68000,"HEVC Decoder",
       "1e7f6bcfa080f1ec70a52319ef559d7efd5c4c0df935bd31db45c99dd05e563e",
       (0x2EA00,0x30000,0x39,0xFFFFF7FF)),
 Image("h264_encoder",0x68000,0xA1000,"H.264 BP/MP/HP Encoder",
       "3baf997561ea106e831bd9107acb7476997492a36df886dedfe275fb31c74243",
       (0x38F00,0x3A000,0x12,0x3F7B9)),
 Image("h264_decoder",0xA1000,0xB5000,"H.264 BP/MP/HP Decoder",
       "58ec013d91c20f673f55131fc43840d8a65d8c72fb63dff76f9846547bac9508",
       (0x43200,0x45000,0x25,0xFFFFFBFF)),
)

HEVC_ENC_STRINGS={
 "source_stream_bitdepths_disallowed":(0xE0C7,"set-opt different stream bitdepths not supported"),
 "source_stream_bitdepth_value_invalid":(0xE0F8,"set-opt encode stream bitdepth: unsupported value"),
 "hevc_profile_rejected":(0xF1E4,"set-opt: Unsupported HEVC profile"),
 "hevc_level_rejected":(0xF206,"set-opt: Unsupported HEVC level"),
 "firmware_hw_version_mismatch":(0xE2ED,"Firmware version does not match hardware!"),
 "encoding_hw_unsupported":(0xE395,"hardware does not support encoding"),
 "hevc_hw_unsupported":(0xE3B8,"hardware does not support hevc"),
 "10bit_input_not_accepted":(0xFCFA,"encoding not supported of this 10-bit input format"),
 "p010_not_supported":(0xFD2D,"hardware does not support MVE_FORMAT_YUV420_P010"),
 "received_set_option":(0xF0D1,"Recieved SET_OPTION data_size"),
 "unsupported_message_code":(0xFBCA,"Unsupported message code."),
 "frame_format_diagnostic":(0xF579,"    format 0x%04x visible %ux%u"),
 "frame_format_flag_check":(0xFD5E,"MVE_BUFFER_FRAME_FLAG_INTERLACE set:"),
 "unsupported_encoded_param":(0xEE7C,"Unsupported encode param in MVE_COMM_BUF_INQ_ADDR."),
}
HEVC_DEC_STRINGS={
 "10bit_decoded_stream_output":(0x4B5B1,"Bitdepth of AFBC output buffer must be 10-bit because of decoded stream."),
 "8bit_decoded_stream_output":(0x4B5FA,"Bitdepth of AFBC output buffer must be 8-bit because of decoded stream."),
 "decoder_hw_depth_unspecified":(0x4BE0E,"stream bitdepth not supported by hardware"),
 "decoder_sps_warning":(0x4BE9B,"SPS: Warning: Stream uses more reference frames than profile permits"),
 "decoder_p010_not_supported":(0x4B506,"hardware does not support MVE_FORMAT_YUV420_P010"),
}

# Bounded aligned HALF-WORD coincidences in opaque V61 instruction/data zone.
# These are NOT accepted as executable xrefs or as CPU A32 fields.
V61_IMM16_OBSERVATIONS={
  "nalu_format_unknown":(0xE00D,((0x73B8,0x81CD),(0x742C,0x01CD))),
  "unsupported_encode_bitdepth":(0xE0F8,((0x7DCE,0x81CD),(0x7E66,0x21CD))),
  "encoding_10bit_input_refusal":(0xFCFA,((0x2842,0x0127),)),
}
V61_CODE_VALEQ_COUNTS={0x121:None,0x201:None,0xBB9:None}

def need(ok,message):
    if not ok: raise ValueError("Stage40 V61 image/provenance: "+message)

def validate_layout(images=IMAGES):
    need(len(images)==4 and
         tuple(x.key for x in images)==
         ("hevc_encoder","hevc_decoder","h264_encoder","h264_decoder"),
         "exact expected image sequence absent")
    cur=0
    for im in images:
        need(im.start==cur and im.end>im.start and im.end<=BUNDLE_BYTES and
             im.start%0x1000==0 and im.end%0x1000==0,
             "image boundary not contiguous 4K pages")
        cur=im.end
    need(cur==BUNDLE_BYTES and
         images[0].end==HEVC_DEC_OFFSET and
         images[1].end==HEVC_BUNDLE_BYTES,
         "HEVC Encoder/Decoder internal image boundary corrupted")
    return True

def read_u16(blob,off):
    need(0<=off<=len(blob)-2,"u16 outside bounded image")
    return struct.unpack_from("<H",blob,off)[0]

def read_u32(blob,off):
    need(0<=off<=len(blob)-4,"u32 outside bounded image")
    return struct.unpack_from("<I",blob,off)[0]

def check_four_images(data,images=IMAGES,require_hash=True):
    validate_layout(images)
    need(len(data)==BUNDLE_BYTES,
         "4-image firmware payload region changed/short")
    facts={}
    for im in images:
        sub=data[im.start:im.end]
        need(sub[0x60:0x60+len(SIGNATURE)]==SIGNATURE,
             "V61 image signature/version mismatch "+im.key)
        label=im.name.encode()
        need(sub[0x70:0x70+len(label)]==label and
             sub[0x70+len(label)]==0,
             "V61 image descriptor name differs "+im.key)
        actual=tuple(read_u32(sub,i) for i in (0xc0,0xc4,0xc8,0xcc))
        need(actual==im.metadata,
             "original V61 independent image metadata words differ "+im.key)
        sha=sha256(sub).hexdigest()
        if require_hash:
            need(sha==im.sha256,
                 "unmodified V61 image SHA256 differs "+im.key)
        facts[im.key]={
            "slot_file_offset":"0x%x"%im.start,
            "bytes":len(sub),
            "sha256":sha,
            "descriptor":im.name,
            "four_header_words_raw_no_semantic_inference":
                ["0x%08x"%x for x in actual],
        }
    return facts

def diagnostics(data,images=IMAGES):
    en_start=images[0].start
    de_start=images[1].start
    en=data[en_start:images[0].end]
    de=data[de_start:images[1].end]
    assertions={}
    for key,(absolute,text) in HEVC_ENC_STRINGS.items():
        relative=absolute-en_start
        encoded=text.encode("ascii")
        need(en[relative:relative+len(encoded)]==encoded and
             en.count(encoded)==1,
             "HEVC encoder diagnostic missing or moved "+key)
        assertions[key]={
           "which_image":"hevc_encoder",
           "slot_relative_offset":"0x%x"%relative,
           "present_in_original_static_bytes":True,
           "rejection_path_reachable_at_runtime":"UNKNOWN",
        }
    for key,(absolute,text) in HEVC_DEC_STRINGS.items():
        relative=absolute-de_start
        encoded=text.encode("ascii")
        need(de[relative:relative+len(encoded)]==encoded and
             de.count(encoded)==1,
             "HEVC decoder diagnostic missing or moved "+key)
        assertions[key]={
           "which_image":"hevc_decoder",
           "slot_relative_offset":"0x%x"%relative,
           "present_in_original_static_bytes":True,
           "rejection_path_reachable_at_runtime":"UNKNOWN",
        }
    # Guard against a particular false-positive: decoder-side bitdepth
    # messages are NOT evidence that the encoder can emit 10bit Main10.
    enc_only=(
       "set-opt: Unsupported HEVC profile",
       "encoding not supported of this 10-bit input format"
    )
    dec_only=(
       "Bitdepth of AFBC output buffer must be 10-bit because of decoded stream.",
       "SPS: Warning: Stream uses more reference frames than profile permits"
    )
    for line in enc_only:
        need(line.encode() not in de,
             "encoder-only diagnostic unexpectedly in decoder")
    for line in dec_only:
        need(line.encode() not in en,
             "decoder-only SPS/10bit diagnostic found in HEVC encoder")
    h264en=data[images[2].start:images[2].end]
    h264dec=data[images[3].start:images[3].end]
    for label in (
         b"encoding not supported of this 10-bit input format",
         b"hardware does not support MVE_FORMAT_YUV420_P010"
    ):
        need(label in h264en,
             "similar 10bit/P010 rejection text missing from H264 encode control")
    need(b"Bitdepth of AFBC output buffer must be 10-bit" in h264dec,
         "decoder 10bit diagnostic cross-codec control absent")
    return assertions

def scan_aligned_u16(blob,target,start=0,end=None):
    """Raw aligned 16-bit coincidences: explicitly NOT V61 instruction xrefs."""
    if end is None:end=len(blob)
    need(start>=0 and end<=len(blob) and start<=end and start%2==0,
         "unaligned/bad bounded raw16 scan range")
    return tuple(i for i in range(start,end-1,2) if
                 read_u16(blob,i)==target)

def audit_bounded_opaque_code(data,images=IMAGES):
    encode=data[images[0].start:images[0].end]
    decode=data[images[1].start:images[1].end]
    lo,hi=ENC_CODE_WINDOW
    require_refs={}
    for key,(value,expected) in V61_IMM16_OBSERVATIONS.items():
        matches=scan_aligned_u16(encode,value,lo,hi)
        need(matches==tuple(x[0] for x in expected),
             "opaque V61 aligned literal candidate array changed "+key)
        for addr,follow in expected:
            need(read_u16(encode,addr+2)==follow,
                 "opaque V61 post-immediate word differs "+key)
        require_refs[key]={
            "raw_aligned_16bit_immediate":"0x%04x"%value,
            "bounded_candidate_file_offsets":
                ["0x%x"%x for x in matches],
            "following_u16_machine_words":
                ["0x%04x"%h for _,h in expected],
            "true_V61_instruction_xref_verified":False,
        }
    # Header plus text and code plus other image: an aligned u16=0x121
    # is NOT equivalent to the ARM descriptor value 0x121.
    rawcounts={}
    for label,section in (("encoder",encode),("decoder",decode)):
        rawcounts[label]={}
        for val in (0x121,0x201,RAW_FRAME_COMMAND):
            matches=scan_aligned_u16(section,val)
            expected={"encoder":{0x121:13,0x201:12,0xbb9:5},
                      "decoder":{0x121:6,0x201:6,0xbb9:3}}[label][val]
            need(len(matches)==expected,
                 "opaque V61 16-bit literal coincidence frequency changed")
            rawcounts[label]["0x%x"%val]=len(matches)
    need(encode.count((0x48<<16|RAW_FRAME_COMMAND).to_bytes(4,"little"))==0 and
         decode.count((0x48<<16|RAW_FRAME_COMMAND).to_bytes(4,"little"))==0,
         "unexpected exact little-endian ARM software frame message header literal")
    return {"two_byte_candidate_sites":require_refs,
            "raw_16bit_coincidences_by_HEVC_image":rawcounts,
            "format_0x121_equated_to_p010_or_10bit":False,
            "format_0x201_equated_to_p010_or_10bit":False,
            "V61_instruction_set_decoder_or_cfg_verified":False,
            "V61_0xBB9_consumer_address_verified":False,
            "no_0xBB9_consumer_anywhere_proven":False}

def previous_cpu_evidence(result):
    need(len(result)==2 and
         {x["model"] for x in result}=={"xs10","xt4"},
         "Stage39 CPU static evidence model set altered")
    for item in result:
        need(item["interrupt_registration_id"]=="0xdef00001" and
             item["hardware_side_0xBB9_receiver_known"]==False and
             item["physical_VPU_interruption_or_Main10_bitdepth_verified"]==False and
             item["internal_XS10_10bit_or_4K60_enabled"]==False,
             "Stage39 CPU path should not be promoted into hardware proof")

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output",type=Path,default=Path("output"))
    opt=ap.parse_args().output
    priortext=(opt/"stage39_h265_irq_callback_original_audit.jsonlog").read_text()
    earlier=json.loads(priortext.split("\nSTAGE39 ORIGINAL X6 IRQ")[0])
    previous_cpu_evidence(earlier)
    rows=[]
    for camera in CAMERAS:
        payload=(opt/f"{camera.name}-payload.bin").read_bytes()
        off=camera.module_region_payload_offset
        need(0<=off and off+BUNDLE_BYTES<=len(payload),
             "raw original decoded payload image quartet out of bounds")
        b=payload[off:off+BUNDLE_BYTES]
        images=check_four_images(b)
        diags=diagnostics(b)
        opaque=audit_bounded_opaque_code(b)
        rows.append({
           "camera":camera.name,
           "official_firmware_sample":camera.version,
           "privately_decoded_payload_relative_start":"0x%x"%off,
           "images":images,
           "static_v61_diagnostics":diags,
           "opaque_code_candidate_checks":opaque,
        })
    # Three positive-control samples are BIT IDENTICAL: no per-camera
    # VPU microcode differences. Hardware and runtime setup may still differ.
    for image in IMAGES:
        need(len({x["images"][image.key]["sha256"] for x in rows})==1,
             "original three-camera V61 image mismatch")
    for key in ("static_v61_diagnostics","opaque_code_candidate_checks"):
        need(all(row[key]==rows[0][key] for row in rows[1:]),
             "same original image cannot give differing diagnostics")
    print(json.dumps({
       "cameras":rows,
       "corrected_HEVC_0x68000_container_ownership":[
         "0x00000..0x38FFF HEVC encoder 0x39000",
         "0x39000..0x67FFF HEVC decoder 0x2F000",
       ],
       "verified": {
         "three_camera_encoder_decoder_image_boundaries_and_sha256":True,
         "messages_refer_to_original_encoded_error_strings":True,
         "V61_real_instruction_disassembly":False,
         "V61_silicon_capability_map":False,
         "HEVC_Main10_SPS_or_10bit_internal_recording_proven":False,
         "X_S10_4K60_proven":False,
         "camera_contacted_or_FF80_or_flash_writes":False,
       },
    },indent=2,ensure_ascii=False))
    print("STAGE40 OFFLINE ORIGINAL V61 IMAGE SPLIT/PROFILE/BITDEPTH DIAGNOSTICS: THREE CAMERAS PASS")
    print("No decoder-only 10bit diagnostics promoted to encoder support; hardware V61 ISA remains unknown.")
if __name__=="__main__":
    main()

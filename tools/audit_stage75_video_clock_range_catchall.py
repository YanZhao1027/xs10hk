#!/usr/bin/env python3
"""Phase75: original X-S10/X-T4 command +0x828 numerical-range finalizer.

Offline ROM/Ghidra only. The 15th [0, 0xFFFFFFFF] row makes the numeric
range-scan rejection unreachable for a valid 32-bit result, while unsupported
class values and other upstream arithmetic may still fail. Near-standard
HDMI pixel-clock numerical centers are circumstantial, not a hardware proof.
"""
import argparse,hashlib,json,struct,sys
from pathlib import Path
from dataclasses import dataclass
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage74_driver_command_multi_source_bitfield as s74
import audit_stage73_interface_index_into_driver_command as s73
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_mode_profile_registry_stage29 as s29
import audit_recorder_codec_forward_stage32 as s32

ROWS=15
STRIDE=20
SHA='7670399720422b89e5d7dde5f44382ad87da3b018841b9723e246841d4deb236'
CATEGORIES=(0,2,3,8,10,12,14)
ORIGINAL_ANCHORS=((594000,13),(25175,0),(0,14),(0xffffffff,14))

@dataclass(frozen=True)
class Spec:
    model:str
    finalizer:int
    builder:int
    BL:int
    literal_ptr:int
    ratio_start:int
    table_start:int
    word828_read:int
    word828_write:int

SPECS={
    'xs10':Spec('xs10',0x0126e804,0x0126d1fc,0x0126d298,
        0x0126e9ec,0x0162e4a8,0x0162e4c0,0x0126e900,0x0126e908),
    'xt4':Spec('xt4',0x01244a1c,0x01243414,0x012434b0,
        0x01244c04,0x016063cc,0x016063e4,0x01244b18,0x01244b20),
}


def need(ok,msg):
    if not ok:raise ValueError('STAGE75 command numerical catch-all: '+msg)


def rows_from_bytes(raw):
    need(len(raw)==ROWS*STRIDE,'expected 15 x 5 uint32 ROM table')
    return [tuple(struct.unpack_from('<5I',raw,i*STRIDE)) for i in range(ROWS)]


def verify_shape(rows):
    need(len(rows)==ROWS,'range list length changed')
    need(all(len(r)==5 for r in rows),'range row width changed')
    need(rows[-1][0]==0 and rows[-1][1]==0xffffffff,
         'final fallback no longer spans entire unsigned 32-bit domain')
    need(all(0<=r[0]<=r[1]<0x100000000 for r in rows),'invalid range bounds')
    need(all(rows[i][1]<rows[i+1][0] for i in range(ROWS-2)),
         'first fourteen specific windows not sorted/disjoint')
    need(all(0<r[j]<0x20000000 for r in rows for j in (2,3,4)),
         'generated profiles contain non-positive/oversized values')
    return True


def range_index(rows,clock):
    """Model first matching row, not actual HDMI or sensor hardware."""
    need(0<=clock<=0xffffffff,'calculated metric is not u32')
    for i,(lo,hi,*_) in enumerate(rows):
        if lo<=clock<=hi:return i
    return None


def profile_code(rows,clock,category):
    """Model the Ghidra switch table; None corresponds to -1 return."""
    k=range_index(rows,clock)
    if k is None:return None
    if category not in CATEGORIES:return None
    r=rows[k]
    col={0:3,2:4,3:2,8:3,10:4,12:3,14:4}[category]
    shift={0:0,2:0,3:0,8:1,10:1,12:2,14:2}[category]
    value=(r[col]<<shift)&0xffffffff
    return value if value<0x80000000 else None


def original_rom(spec,rom):
    base=s59.BASE
    W=lambda a:s32.rom_word(rom,base,a)
    need(W(spec.literal_ptr)==spec.table_start+4,
         'literal pointer no longer points to upper bound in first row')
    raw=rom[spec.table_start-base:spec.table_start-base+ROWS*STRIDE]
    need(hashlib.sha256(raw).hexdigest()==SHA,
         'original 300-byte 15x5 range table SHA differs')
    rows=rows_from_bytes(raw);verify_shape(rows)
    ratios=[(W(spec.ratio_start+8*i),W(spec.ratio_start+8*i+4)) for i in range(3)]
    need(ratios==[(1,1),(5,4),(3,2)],
         'first three arithmetic numerator/denominator pairs differ')
    need(s29.bl_target(W(spec.BL),spec.BL)==spec.finalizer,
         'builder to numerical profile finalizer A32 BL destination differs')
    for site,read in ((spec.word828_read,True),(spec.word828_write,False)):
        w=W(site)
        need(w&0x0c000000==0x04000000 and w&0xfff==0x828 and
            ((w>>20)&1)==int(read) and ((w>>16)&0xf)==0,
            'original A32 +0x828 load/store access is not same context')
    need(all(range_index(rows,n) is not None for n in (
         0,1,25175,27000,74250,148500,297000,594000,0xffffffff)),
         'numerical domain catch-all missing one of synthetic probes')
    need(all(range_index(rows,metric)==idx for metric,idx in ORIGINAL_ANCHORS),
         'known original narrow windows and catchall change')
    values=[profile_code(rows,v,c) for v in (0,25175,27000,74250,148500,297000,594000,0xffffffff)
            for c in CATEGORIES]
    need(all(v is not None and v>=0 for v in values),
         'supported category has rejected computed code within tested ROM windows')
    return {'original_range_table_SHA256':SHA,
            'ROM_15_rows_and_20byte_stride':True,
            'first14_narrow_windows_disjoint':True,
            'row14_universal_u32_catchall':True,
            'clock_like_centers':[25175,25200,27000,27027,54000,54054,74175,74250,
                                  148352,148500,296704,297000,593407,594000],
            'first_three_ratio_pairs':ratios,
            'clock_numeric_window_miss_alone_cannot_reach_15_iteration_failure':True,
            'original_builder_finalizer_A32_BL_verified':hex(spec.BL),
            'same_base_828_direct_A32_load_and_store_verified':True}


def original_function(spec,root):
    m=spec.model
    t=(root/f'{m}_stage75_finalizer_source_fields.log').read_text()
    c=s59.function_c_any(t,spec.finalizer)
    builder=s59.function_c_any((root/f'{m}_stage73_driver_command_pack.log').read_text(),spec.builder)
    for text in (
      '(*(uint *)(param_1 + 8) & 0x3ff) >> 8',
      '*(uint *)(param_1 + 0xc) & 0xfffff',
      '*(uint *)(param_1 + 0x50) & 0xfffff',
      '*(uint *)(param_1 + 0x4b0) & 0xfffffff',
      'puVar2[-1]', '*puVar2 < uVar3','puVar2 = puVar2 + 5;',
      'if (iVar1 == 0xf)', 'return 0xffffffff;',
      'case 0:', 'case 2:', 'case 3:', 'case 8:', 'case 10:', 'case 0xc:', 'case 0xe:',
      'default:', '*(uint *)(param_1 + 0x828)', 'return 0;'):
        need(text in c,'finalizer arithmetic, switch or +828 store no longer present: '+text)
    need(f'puVar2 = DAT_{spec.literal_ptr:08x};' in c and
         f'uVar1 = FUN_{spec.finalizer:08x}(param_1);' in builder and
         builder.find(f'FUN_{s73.SPECS[m].marshaller:08x}(param_1,param_3);')<
         builder.find(f'FUN_{spec.finalizer:08x}(param_1);'),
         'original driver builder no longer packs interface before final numerical profile')
    return {'original_C_builder_uses_same_context_after_marshaller':True,
            'finalizer_dependent_fields':['+0x8','+0x0C','+0x50','+0x4B0'],
            'allowed_switch_category_cases':list(CATEGORIES),
            'unsupported_switch_category_still_returns_failure':True,
            'real_sensor_4K60_or_Main10_hardware_confirmation':False}


def analyze(root):
    s74.analyze(root)
    result=[];raw=[]
    for m,s in SPECS.items():
        rom=(root/f'x6-{m}/section-1.bin').read_bytes()
        result.append({'model':m,**original_rom(s,rom),**original_function(s,root)})
        raw.append(rom[s.table_start-s59.BASE:s.table_start-s59.BASE+ROWS*STRIDE])
    need(raw[0]==raw[1],'original two-model 15-bin table differs')
    return {'models':result,'same_two_model_15x5_numerical_profile_table':True,
      'original_SHA_pinned_Phase74_and_all_prior_audits_pass':True,
      'no_proof_video_clock_field_is_real_HW_or_Movie_2160p60_encoder_gate':True,
      'no_camera_USB_FF80_RAM_flash_ROM_DAT_writes':True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(analyze(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE75 ORIGINAL 15-BIN VIDEO-CLOCK-LIKE TABLE UNIVERSAL FALLBACK PASS')
    print('UNKNOWN: physical clock interpretation, interface hardware or Movie/VPU Main10.')
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Phase67: pin all four GUI fields composing original 2160p/fps6 mode tuple.

Both Fujifilm X-S10 FW3.11 and X-T4 FW2.12 ROMs: GUI pixel/aspect/fps/
bitrate -> conditional GUI-to-P send -> Recorder adapter -> active template
-> Movie context+5BD/5BE/5C6/9B8 or 9BC; classify movie type and conditional
4K-out flag rewrite before 96*0x40 ROM mode table. The static 4K candidates
are NOT proof of reachable physical X-S10 4K60 or HEVC Main10 bitstream.
"""
from dataclasses import dataclass
from pathlib import Path
import json,argparse,sys,re
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage66_playback_fps_movie_secondary as s66
import audit_stage46_joint_movie_mode_matrix as s46
import audit_recorder_codec_forward_stage32 as s32
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_mode_profile_registry_stage29 as s29

@dataclass(frozen=True)
class Spec:
    model:str
    low_pair:tuple[int,int]
    high_pair:tuple[int,int]
    alt_low_pair:tuple[int,int]
    alt_high_pair:tuple[int,int]
    bitrate_pair:tuple[int,int]
    bitrate_intermediate:int
    movie_bitrate_offset:int
    pixel_setter:int
    aspect_setter:int
    bitrate_setter:int
    pixel_ram:int
    aspect_ram:int
    bitrate_ram:int
    movie_constructor:int
    HS_class:int
    is4k_class:int

SPECS={
 'xs10':Spec('xs10',(0x012c958c,0x012c9590),(0x012c9594,0x012c9598),
  (0x012c9a7c,0x012c9a80),(0x012c9a70,0x012c9a74),
  (0x012c999c,0x012c99a0),0x410,0x9b8,
  0x011539e4,0x01153ea4,0x01153e0c,
  0x01b8810c,0x01b88110,0x01b88636,
  0x022d5fec,0x022d171c,0x022d1674),
 'xt4':Spec('xt4',(0x012a31c8,0x012a31cc),(0x012a31d0,0x012a31d4),
  (0x012a36cc,0x012a36d0),(0x012a36c0,0x012a36c4),
  (0x012a35e8,0x012a35ec),0x414,0x9bc,
  0x011280bc,0x0112857c,0x011284e4,
  0x01af2874,0x01af2878,0x01af2d9e,
  0x022425bc,0x0223dcac,0x0223dc04),
}

def require(ok,msg):
    if not ok:raise ValueError('STAGE67 original joint tuple: '+msg)

def original_arm(s,w1):
    for src,dst,sw,dw in (
        (0x6c,0x15,0xe5d1306c,0xe5c03015),
        (0x70,0x16,0xe5d13070,0xe5c03016)):
        pair=(s.low_pair if src==0x6c else s.high_pair)
        require(w1(pair[0])==sw and w1(pair[1])==dw and pair[1]==pair[0]+4,
                f'original first adapter mapping P+{src:x} -> intermediate+{dst:x} changed')
    # Second branch high-byte transfer is conditionally encoded with a different
    # register allocation. We verify those raw original instructions separately.
    require(w1(s.alt_low_pair[0])==0xe5d1306c and
            w1(s.alt_low_pair[1])==0xe5c03015 and
            w1(s.alt_high_pair[0])==0xe5d12070 and
            w1(s.alt_high_pair[1])==0xe5c02016,
            'alternate adapter mode-key low/high transfer changed')
    require(w1(s.bitrate_pair[0])==0xe5d53596 and
            w1(s.bitrate_pair[1])==(0xe5c43000|s.bitrate_intermediate) and
            s.bitrate_pair[1]==s.bitrate_pair[0]+4,
            'bitrate P+596 -> intermediate variant byte A32 mismatch')
    require(s.movie_bitrate_offset==0x5a8+s.bitrate_intermediate and
            0x5a8+0x15==0x5bd and 0x5a8+0x16==0x5be and
            0x5a8+0x1e==0x5c6 and
            s.movie_bitrate_offset==s46.MODELS[s.model].fps_variant_offset and
            s.bitrate_intermediate<s66.s65.SPECS[s.model].length,
            'Movie byte field identity/Recorder copy range differs')
    return {'GUI_to_P_fields':['pixel+0x6C','aspect+0x70','fps+0x6E','bps+0x596'],
      'adapter_source_to_intermediate':{'pixel':['0x6C','0x15'],
        'aspect':['0x70','0x16'],'fps':['0x6E','0x1E'],
        'bps':['0x596',hex(s.bitrate_intermediate)]},
      'Movie_four_ROM_keys':{'pixel_mode_low':'+0x5BD',
         'aspect_mode_high':'+0x5BE','recording_fps':'+0x5C6',
         'bitrate_variant':hex(s.movie_bitrate_offset)},
      'original_two_branches_mode_key_and_variant_ARM_verified':True}

def enum_names(s,pixel,aspect,bps,set_pixel,set_aspect,set_bps,converter,mode_initializer,class_hs,class_4k):
    for entry,loc,expected in ((set_pixel,s.pixel_ram,'eaPixel_Movie'),
       (set_aspect,s.aspect_ram,'eAspect'),
       (set_bps,s.bitrate_ram,'eMovieBps')):
        require('s__INPUT_'+expected in entry and
               f'DAT_{loc:08x} = (char)param_1;' in entry,
               'GUI setter source/identity not pinned '+expected)
    require('param_1 == 7' in pixel and
            's_MODE_PIXEL_4K_' in pixel and
            'param_1 == 6' in pixel and
            's_MODE_PIXEL_FULLHD_' in pixel and
            'param_1 == 2' in aspect and
            's_MODE_ASPECT_WIDE_' in aspect and
            'param_1 == 7' in aspect and
            's_MODE_ASPECT_17_9_' in aspect,
            'pixel7=4K/6=FHD, aspect2=WIDE or7=17:9 ROM enum labels not crossverified')
    for n,mbps in ((1,100),(2,200),(3,400)):
        require(f'param_1 == {n}' in bps and
                f's_MODE_BPS_{mbps}_' in bps,
                f'original BPS enum{n} value no longer {mbps}')
    require('s_MODE_BPS_50_' in bps and
            'param_1 == 0' in bps,
            'bitrate enum0 fallback symbolic mapping missing')
    for snippet in (
        '*(undefined1 *)(param_1 + 0x15) = param_2[0x6c];',
        '*(undefined1 *)(param_1 + 0x16) = param_2[0x70];',
        f'*(undefined1 *)(param_1 + 0x{s.bitrate_intermediate:x}) = param_2[0x596];'):
        require(snippet in converter,'original parameter-field mapping missing '+snippet)
    require(all(f'case {mode}:' in class_hs for mode in (1,2,3,4,5,6,7)) and
            'case 2:\n  case 3:\n    return 1;' in class_hs and
            'case 1:\n  case 4:\n  case 5:\n  case 6:\n  case 7:\n    return 0;' in class_hs,
            'mode class0/1,2 classifier branches changed')
    require('case 4:\n  case 5:\n  case 6:\n  case 7:\n    return 1;' in class_4k and
            'case 1:\n  case 2:\n  case 3:\n    return 0;' in class_4k,
            'original 4K-movie type classifier changed')
    require(f'FUN_{s.HS_class:08x}(cVar1);' in mode_initializer and
            f'FUN_{s.is4k_class:08x}(' in mode_initializer and
            f'FUN_{s66.s65.SPECS[s.model].table_matcher:08x}(iVar8);' in mode_initializer and
            '0x12294) == 0)' in mode_initializer and
            '(iVar8 + 0xadd8) = 6;' in mode_initializer and
            '0xa8e)' in mode_initializer and
            '0x5f5) = 0;' in mode_initializer,
            'first-frame class assignment, conditional 4K mode low7 rewrite or LUT call differs')
    return {'original_GUI_names':{
       'pixel':'eaPixel_Movie','aspect':'eAspect','fps':'eMovieFps','bps':'eMovieBps'},
       'ROM_enum_7_pixel':'4K','ROM_enum_6_pixel':'FullHD',
       'ROM_aspect_2':'WIDE','ROM_aspect_7':'17:9',
       'ROM_bps_mbps':{'0':50,'1':100,'2':200,'3':400},
       'first_frame_class0_movie_types':[1,4,5,6,7],
       'first_frame_class1_2_movie_types':[2,3],
       'flag_equals1_in_4K_type_rewrites_pixel7_to6':True,
       'mode_class_persists_in_noninitial_frames_proven':False}

def joint(s,section1,section2):
    m=s46.MODELS[s.model]
    mode=s32.MODELS[s.model]
    rows=s46.read_records(s46.section_slice(section2,mode.sec2base,m.movie_table,
                     s46.RECORDS*s46.STRIDE+1))
    widths=s46.section_slice(section1,s59.BASE,m.widths,s46.DIM_BYTES)
    heights=s46.section_slice(section1,s59.BASE,m.heights,s46.DIM_BYTES)
    found=[]
    for aspect,targetres,smallres in ((2,(3840,2160),(1920,1080)),
                                      (7,(4096,2160),(2048,1080))):
        for bps in (1,2,3):
            big=s46.match_record(rows,0,(aspect<<8)|7,6,bps)
            small=s46.match_record(rows,0,(aspect<<8)|6,6,bps)
            require(len(big)==1 and (len(small)==1 if bps in (1,2) else small==[]),
                    f'four-key mode candidate mismatch aspect={aspect} bps={bps}')
            require(s46.lookup_width_height(rows[big[0]],widths,heights)==targetres and
                    (s46.lookup_width_height(rows[small[0]],widths,heights)==smallres
                     if small else bps==3),
                    '4K/1080/no-match alternative differs from original ROM')
            found.append({'aspect_enum':aspect,'bps_enum':bps,
                'bps_mbps':(100,200,400)[bps-1],
                'pixel4K_enum':7,'normal_fps_enum':6,
                'class':0,'mode_key':hex((aspect<<8)|7),
                '2160_candidate_row':big[0],'2160_resolution':list(targetres),
                'flag1_coerced_row':small[0] if small else None,
                'flag1_resolution':list(smallres) if small else None})
    for aspect in (2,7):
        require(not s46.match_record(rows,0,(aspect<<8)|7,6,0),
                'new BPS0(50Mbps) 2160 FPS6 row appeared')
        for cl in (1,2):
            for bps in (1,2,3):
                require(not s46.match_record(rows,cl,(aspect<<8)|7,6,bps),
                        'highspeed class1/2 unexpectedly has 4Kfps6 candidate')
    return {'six_2160p_fps6_with_bitrate_specific_GUI_tuple':found,
       'ROM_matrix_shared_software_superset_only':True,
       'actual_device_2160p_59_94fps_HEVC_Main10_joint_reachability_proven':False,
       'mode_pixel_low7_requires_4K_gate_false_for_movietypes4_7':True}

def fun(log,addr):return s59.function_c_any(log,addr)

def run(root):
    s66.run(root)
    out=[]
    for name,s in SPECS.items():
        b1=(root/f'x6-{name}/section-1.bin').read_bytes()
        b2=(root/f'x6-{name}/section-2.bin').read_bytes()
        w1=lambda a:s32.rom_word(b1,s59.BASE,a)
        conv=fun((root/f'{name}_stage64_recorder_converter_movie_fps.log').read_text(),s32.MODELS[name].adapter)
        setters=(root/f'{name}_stage67_joint_GUI_setters_mode_class.log').read_text()
        names=(root/f'{name}_stage67_joint_mode_class_names.log').read_text()
        cons=fun((root/f'{name}_stage65_fps_to_movie_mode_chain.log').read_text(),s.movie_constructor)
        out.append({'model':name,**original_arm(s,w1),
          **enum_names(s,*(fun(names,a) for a in (
             0x0102d17c if name=='xs10' else 0x0102d3ac,
             0x0102d620 if name=='xs10' else 0x0102d850,
             0x010343c8 if name=='xs10' else 0x0103467c)),
            *(fun(setters,a) for a in (s.pixel_setter,s.aspect_setter,s.bitrate_setter)),
            conv,cons,fun(names,s.HS_class),fun(setters,s.is4k_class)),
          **joint(s,b1,b2),
          'real_camera_USB_FF80_ROM_RAM_flash_modifications':False})
    return {'models':out,
      'all_prior_original_SHA_pinned_ROM_audits_including_Stage66_pass':True,
      'separate_XS10_specific_4K60_hardware_eligibility_gate_proven':False,
      'hardware_4K60_HEVC_Main10_bitstream_or_file_observed':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(run(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE67 ORIGINAL FOUR GUI FIELDS -> 6 STATIC 2160p FPS6 LUT ROWS PASS')
    print('UNKNOWN: every device runtime gate, sensor/ISP, VPU Main10 output and video file.')
if __name__=='__main__':main()
#!/usr/bin/env python3
"""Phase66: original playFPS GUI -> P+6F -> active+1F -> Movie+5C7.

Separate eMovieFps/regular and eMoviePlayFps/playback control original X6
arm, selector class 1/2 for latter; no live 4K60 Main10 assertion. Reuses
Stage65 and SHA-pinned original read-only Fuji X-S10 3.11/X-T4 2.12 audits.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse,json,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_stage65_active_fps_movie_context_joint_lut as s65
import audit_recorder_codec_forward_stage32 as s32
import audit_mode_profile_registry_stage29 as s29
import audit_stage59_movie_menu_ROM_allowlist as s59
import audit_stage63_real_movie_fps_menu_eligibility as s63

@dataclass(frozen=True)
class Spec:
    name:str
    setter:int
    gui_play:int
    setter_write:int
    play_loader:int
    play_getter:int
    getter_load:int
    adapter_load:int
    adapter_store:int
    setBLs:tuple[int,int,int]
    setter_xrefs:int
    active_play:int
    mode_class_fn:int
    mode_parent:int
    read_id:int
    secondary_id:int
    selector_id:int
    fps_id:int

SPECS={
 'xs10':Spec('xs10',0x01153d74,0x01b8810f,0x01153dd0,
    0x011769d4,0x012bd590,0x012bd5a0,0x012c95a4,0x012c95a8,
    (0x01176a6c,0x01176a8c,0x01176a98),11,0x01c24df7,
    0x022d171c,0x022d5fec,0x3f7,0x403,0x400,0x3f6),
 'xt4':Spec('xt4',0x0112844c,0x01af2877,0x011284a8,
    0x0114a8c8,0x01295c04,0x01295c14,0x012a31e0,0x012a31e4,
    (0x0114a960,0x0114a980,0x0114a98c),11,0x01b8355f,
    0x0223dcac,0x022425bc,0x3e0,0x3ec,0x3e9,0x3df)
}

def require(ok,msg):
    if not ok:raise ValueError('STAGE66 Playback FPS: '+msg)

def arm(s,w1,w2):
    require(w1(s.setter_write)==0xe5c3406f,
        'GUI dedicated playFPS setter original STRB missing')
    require(w1(s.adapter_load)==0xe5d5306f and
            w1(s.adapter_store)==0xe5c4301f and
            s.adapter_store==s.adapter_load+4,
        'Recorder input P+0x6F to intermediate+0x1F ARM pair changed')
    get=s.play_getter
    ram=s32.movpart(w1(get+8),3) | s32.movpart(w1(get+12),3,True)<<16
    require(ram==s32.MODELS[s.name].template_base and
            w1(s.getter_load)==0xe5d3001f and
            get+16==s.getter_load and
            ram+0x1f==s.active_play,
        'separate active playFPS getter RAM and LDRB identity changed')
    for a in s.setBLs:
        require(s29.bl_target(w1(a),a)==s.setter,
                'original playFPS service loader BL target diverged')
    require(s.gui_play==s63.SPECS[s.name].setter_RAM_addr+1 and
            s.active_play==s65.SPECS[s.name].template+0x1f and
            0x5a8+0x1f==0x5c7,
            'separate playFPS GUI/active/Movie arithmetic shifted')
    return {'gui_playback_fps_byte':hex(s.gui_play),
        'recorder_source_offset':'P+0x6F',
        'intermediate_offset':'+0x1F',
        'active_playback_fps_byte':hex(s.active_play),
        'movie_playback_fps_offset':'Movie+0x5C7',
        'loader_original_BLs_to_GUI_play_setter_verified':3,
        'all_original_ARM_input_to_template_getter_verified':True}

def data(s,gui_c,loader_c,adapter_c,playgetter_c,class_c,init_c,matcher_c,consumer_c,refs):
    require('s__INPUT_eMoviePlayFps_' in gui_c and
            f'DAT_{s.gui_play:08x} = (char)param_1;' in gui_c and
            'FUN_0102d' in gui_c,
            'GUI +0x6F is not independently named eMoviePlayFps in firmware')
    require(f'0x{s.read_id:x},0)' in loader_c and
            f'0x{s.secondary_id:x},0)' in loader_c and
            f'0x{s.selector_id:x},0)' in loader_c and
            f'0x2d,0x{s.fps_id:x},uVar3' in loader_c and
            f'0x2d,0x{s.fps_id:x})' in loader_c and
            f'FUN_{s.setter:08x}(uVar3 & 0xff);' in loader_c and
            f'FUN_{s.setter:08x}(uVar1);' in loader_c and
            f'FUN_{s.setter:08x}(4);' in loader_c,
            'separate playFPS ID load and normal FPS allowlist shared validation missing')
    require(adapter_c.count('*(undefined1 *)(param_1 + 0x1f) = param_2[0x6f];')==1,
            'P+6F/active+1F converter source not present or duplicated')
    require(f'return DAT_{s.active_play:08x};' in playgetter_c,
            'playFPS active getter does not read separate byte')
    require(all(f'case {x}:' in class_c for x in (1,2,3,4,5,6,7)) and
            'return 0;' in class_c and 'return 1;' in class_c,
            'Movie HS class discriminator altered')
    require(f'FUN_{s.play_getter:08x}()' in consumer_c and
            f'FUN_{s.mode_class_fn:08x}(' in consumer_c and
            ('FUN_%08x()'%s65.st64.SPECS[s.name].getter) in consumer_c,
            'alternate Movie FPS getters not selected by HS category')
    require('cVar2 = *(char *)(param_1 + 0x5c7);' in matcher_c and
            'cVar2 = *(char *)(param_1 + 0x5c6);' in matcher_c and
            '(byte)(cVar1 - 1U) < 2' in matcher_c,
            'class 1/2 no longer chooses play FPS and class0 regular FPS')
    require('FUN_%08x'%s.mode_class_fn in init_c and
            "cVar1 == '\\x03'" in init_c and
            '0x5f5) = 0;' in init_c,
            'first-frame runtime class0/1/2 placement diverges')
    require(f'PROBE_TARGET addr={s.gui_play:08x} refs={s.setter_xrefs}' in refs and
            f'PROBE_REF from={s.setter_write:08x} to={s.gui_play:08x} type=WRITE' in refs and
            f'PROBE_TARGET addr={s.active_play:08x} refs=2' in refs and
            f'PROBE_REF from={s.getter_load:08x} to={s.active_play:08x} type=READ' in refs,
            'original direct Ghidra refs to GUI/active playback FPS changed')
    return {'actual_GUI_name':'eMoviePlayFps',
        'GUI_normal_FPS_and_playback_FPS_are_distinct':True,
        'source_settings_service_id_is_not_normal_fps_id':s.read_id!=s.fps_id,
        'playFPS_candidate_checked_against_normal_fps_0x2D_ROM_allowlist':True,
        'runtime_first_frame_HS_class1_2_uses_playback_FPS':True,
        'physical_high_speed_capture_rate_and_playback_rate_observed':False,
        'GUI_user_playback_rate_stable_under_reload_proven':False,
        'actual_Main10_or_4K60_output_proven':False}

def f(log,addr):return s59.function_c_any(log,addr)

def run(root):
    s65.analyze(root)
    rows=[]
    for name,s in SPECS.items():
        b1=(root/f'x6-{name}/section-1.bin').read_bytes()
        b2=(root/f'x6-{name}/section-2.bin').read_bytes()
        w1=lambda a:s32.rom_word(b1,s59.BASE,a)
        w2=lambda a:s32.rom_word(b2,s32.MODELS[name].sec2base,a)
        t=(root/f'{name}_stage66_GUI_mode_second_fps_setter.log').read_text()
        loader=(root/f'{name}_stage67_joint_GUI_setters_mode_class.log').read_text()
        playsetter=f(t,s.setter)
        loader_c=f(loader,s.play_loader)
        adapter=f((root/f'{name}_stage64_recorder_converter_movie_fps.log').read_text(),
                  s32.MODELS[name].adapter)
        class_c=f((root/f'{name}_stage67_joint_mode_class_names.log').read_text(),s.mode_class_fn)
        getter=f((root/f'{name}_stage67_joint_mode_class_names.log').read_text(),s.play_getter)
        init_match=(root/f'{name}_stage65_fps_to_movie_mode_chain.log').read_text()
        init=f(init_match,s.mode_parent)
        match=f(init_match,s65.SPECS[name].table_matcher)
        refs=(root/f'{name}_stage66_GUI_secondary_FPS_field_xrefs.log').read_text()
        c_log=(root/f'{name}_stage64_active_FPS_getter_consumers.log').read_text()
        consumer=f(c_log,s65.st64.SPECS[name].movie_parent_func)
        rows.append({'model':name,**arm(s,w1,w2),
            **data(s,playsetter,loader_c,adapter,getter,class_c,init,match,consumer,refs),
            'actual_camera_USB_FF80_ROM_or_flash_write':False})
    return {'models':rows,
      'prior_original_SHA_pinned_Stage65_and_all_ancestors_pass':True,
      'independent_playFPS_producer_into_Movie_class1_or2_is_static_only':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('output'))
    print(json.dumps(run(p.parse_args().output),indent=2,ensure_ascii=False))
    print('STAGE66 ORIGINAL eMoviePlayFps P+6F -> Movie+5C7, HS CLASS1/2 PASS')
    print('UNKNOWN: live highspeed user choice, encoder Main10 SPS, 4K59.94 device.')
if __name__=='__main__':main()
#!/usr/bin/env bash
# Inspect metadata of a locally recorded video file (read-only, host-side).
# This cannot prove the bit depth of the *incoming HDMI signal*.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  printf 'Usage: %s /path/to/clip.mov\n' "$0" >&2
  exit 2
fi
if ! command -v ffprobe >/dev/null 2>&1; then
  printf 'ffprobe is missing (package: ffmpeg)\n' >&2
  exit 2
fi
if [[ ! -f "$1" ]]; then
  printf 'Not a readable local recording: %s\n' "$1" >&2
  exit 2
fi

ffprobe -v error -select_streams v:0 \
  -show_entries stream=codec_name,profile,pix_fmt,bits_per_raw_sample,width,height,avg_frame_rate \
  -of default=noprint_wrappers=1 "$1"
printf '\nNOTE: The file codec/bit depth reflects the recorder output; it does NOT by itself\n'
printf 'prove the raw HDMI link bit depth or whether the camera has a Main10 encoder.\n'

#!/usr/bin/env bash
# Standard Fujifilm USB PTP GetDeviceInfo with temporary desktop mount release.
# Changes only desktop mount state; restores on exit. No photo access, no
# vendor-specific PTP ops, no firmware, calibration or device-setting writes.
set -euo pipefail

base="$(cd "$(dirname "$0")/.." && pwd)"
count="$(lsusb -d 04cb:02ea | wc -l)"
if [[ "$count" -ne 1 ]]; then
  printf 'Expected one Fujifilm USB PTP Camera (04cb:02ea); found %s.\n' "$count" >&2
  exit 1
fi

runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export XDG_RUNTIME_DIR="$runtime"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$runtime/bus}"

mount_path=""
if [[ -d "$runtime/gvfs" ]]; then
  mount_path="$(find "$runtime/gvfs" -mindepth 1 -maxdepth 1 \
    -type d -name 'gphoto2:host=04cb_USB_PTP_Camera_*' -print -quit)"
fi

if [[ -n "$mount_path" ]]; then
  name="${mount_path##*/}"
  host="${name#gphoto2:host=}"
  uri="gphoto2://$host/"
  if ! gio mount -u "$uri" >/dev/null 2>&1; then
    printf 'Camera is being used by the desktop; no PTP request sent.\n' >&2
    exit 1
  fi
  printf 'Desktop camera mount temporarily released.\n'
  restore() {
    if gio mount "$uri" >/dev/null 2>&1; then
      printf 'Desktop camera mount restored.\n'
    else
      printf 'Camera mount restore not confirmed. Reopen Camera in Files.\n' >&2
    fi
  }
  trap restore EXIT
fi

python3 "$base/tools/ptp_device_info.py"

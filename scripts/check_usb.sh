#!/usr/bin/env bash
set -u
printf '== USB devices (read-only) ==\n'
if command -v lsusb >/dev/null 2>&1; then
  lsusb
  printf '\n== Fujifilm USB vendor 04cb (if present) ==\n'
  lsusb -d 04cb: || true
else
  printf 'lsusb not installed. Install usbutils if needed.\n'
fi
printf '\n== Removable block devices ==\n'
lsblk -o NAME,TRAN,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINTS
printf '\n== Recent kernel USB messages ==\n'
journalctl -k -b --no-pager -n 160 2>/dev/null | grep -Ei 'usb|fuji|camera|ptp|mass storage' | tail -n 30 || true
printf '\nNOTE: This script does not communicate with camera endpoints.\n'

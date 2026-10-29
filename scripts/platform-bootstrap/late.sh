#!/system/bin/sh
set -eu
directory=/data/misc/device-lab
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
[ -f "$directory/platform-early-ready" ] || exit 2
if [ -f "$directory/network-adb-only-enabled" ]; then
    result=$(settings put global adb_enabled 0 2>&1)
    setprop sys.usb.config mtp
    stop adbd
    "$directory/resetprop" -n service.adb.root 0
    sleep 5
    setprop persist.sys.usb.config mtp
    start adbd
fi
cat /proc/sys/kernel/random/boot_id > "$directory/platform-late-ready"
chmod 0600 "$directory/platform-late-ready"
log -t DeviceLabPlatform 'Authenticated network operating mode restored.'

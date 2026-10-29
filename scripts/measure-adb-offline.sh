#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
[ "$(id -Z)" = u:r:su:s0 ] || exit 1
directory=/data/misc/device-lab/offline-v12
mkdir -p "$directory"
chmod 0700 "$directory"
adb_setting=$(settings get global adb_enabled 2>&1)
persist_usb=$(getprop persist.sys.usb.config)
runtime_usb=$(getprop sys.usb.config)
mdns_state=$(getprop init.svc.mdnsd)
case "$adb_setting" in 0|1) ;; *) exit 2 ;; esac
case "$mdns_state" in stopped|running) ;; *) exit 2 ;; esac

record() {
    printf '{"time_s":%s,"adb_enabled":"%s","adbd":"%s","persist_usb":"%s","runtime_usb":"%s","usb_state":"%s","adb_root":"%s","adb_secure":"%s","mdnsd":"%s"}\n' \
        "$(date +%s)" "$(settings get global adb_enabled 2>&1)" "$(getprop init.svc.adbd)" \
        "$(getprop persist.sys.usb.config)" "$(getprop sys.usb.config)" "$(getprop sys.usb.state)" "$(getprop service.adb.root)" "$(getprop ro.adb.secure)" "$(getprop init.svc.mdnsd)"
}
restore() {
    setting_result=$(settings put global adb_enabled "$adb_setting" 2>&1)
    setprop persist.sys.usb.config "$persist_usb"
    setprop sys.usb.config "$runtime_usb"
    setprop service.adb.root 0
    if [ "$mdns_state" = running ]; then start mdnsd; fi
    start adbd
    record > "$directory/restored.json"
    touch "$directory/done"
    sync
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
rm -f "$directory/done" "$directory/failed"
record > "$directory/before.json"
setting_result=$(settings put global adb_enabled 0 2>&1)
setprop persist.sys.usb.config mtp
setprop sys.usb.config mtp
stop adbd
# Android 14 adbd registers cleanup with atexit; init's hard stop can leave
# its legacy mDNS announcement alive. Pause this guest's legacy advertiser too.
stop mdnsd
if [ -x /data/misc/device-lab/resetprop ]; then
    /data/misc/device-lab/resetprop -n service.adb.root 0
else
    magisk resetprop -n service.adb.root 0
fi
sleep 5
if [ "$(getprop init.svc.adbd)" != stopped ] || [ "$(getprop init.svc.mdnsd)" != stopped ]; then
    echo 'adbd or its legacy advertiser did not stop' > "$directory/failed"
    exit 3
fi
# UsbDeviceManager clears the persistent function list when debugging changes.
# Set the actual non-debug default after that transition has settled.
setprop persist.sys.usb.config mtp
[ "$(getprop persist.sys.usb.config)" = mtp ] || exit 6
# A stopped init service can leave its unused filesystem socket behind.
rm -f /dev/socket/adbd
record > "$directory/offline.json"
launch_result=$(am force-stop com.eltavine.duckdetector 2>&1)
launch_result=$(am start -n com.eltavine.duckdetector/android.app.NativeActivity 2>&1)
printf '%s\n' "$launch_result" > "$directory/launch.txt"
attempt=0
while ! pidof com.eltavine.duckdetector > "$directory/app-pid.txt"; do
    sleep 1
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 15 ]; then
        echo 'The offline detector did not start' > "$directory/failed"
        exit 5
    fi
done
: > "$directory/samples.jsonl"
round=0
while [ "$round" -lt 36 ]; do
    sleep 5
    record >> "$directory/samples.jsonl"
    if [ "$(getprop init.svc.adbd)" != stopped ] || [ "$(getprop init.svc.mdnsd)" != stopped ] || [ "$(settings get global adb_enabled 2>&1)" != 0 ]; then
        echo 'ADB or its legacy advertiser became active during the measurement' > "$directory/failed"
        exit 4
    fi
    round=$((round + 1))
done

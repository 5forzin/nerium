#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
[ "$(id -Z)" = u:r:su:s0 ] || exit 1
[ "$(getprop ro.adb.secure)" = 1 ] || exit 1
directory=/data/misc/device-lab/network-adb-v12
mkdir -p "$directory"
chmod 0700 "$directory"
rm -f "$directory/ack" "$directory/committed"
adb_setting=$(settings get global adb_enabled 2>&1)
persist_usb=$(getprop persist.sys.usb.config)
runtime_usb=$(getprop sys.usb.config)
case "$adb_setting" in 0|1) ;; *) exit 2 ;; esac
printf '%s\n%s\n%s\n' "$adb_setting" "$persist_usb" "$runtime_usb" > "$directory/before.txt"
restore() {
    result=$(settings put global adb_enabled "$adb_setting" 2>&1)
    setprop persist.sys.usb.config "$persist_usb"
    setprop sys.usb.config "$runtime_usb"
    setprop service.adb.root 0
    start adbd
    touch "$directory/rolled-back"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
result=$(settings put global adb_enabled 0 2>&1)
setprop sys.usb.config mtp
stop adbd
if [ -x /data/misc/device-lab/resetprop ]; then
    /data/misc/device-lab/resetprop -n service.adb.root 0
else
    magisk resetprop -n service.adb.root 0
fi
sleep 5
setprop persist.sys.usb.config mtp
start adbd
sleep 5
round=0
while [ "$round" -lt 24 ]; do
    if [ -f "$directory/ack" ] && [ "$(cat "$directory/ack")" = accept ]; then
        touch "$directory/committed"
        trap - EXIT
        sync
        exit 0
    fi
    sleep 5
    round=$((round + 1))
done
exit 3

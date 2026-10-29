#!/system/bin/sh
set -eu
directory=/data/misc/device-lab
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
[ "$(getprop ro.kernel.qemu)" = 1 ] || exit 2
[ ! -e /system/bin/magisk ] || exit 3
# Stock init.usb.rc recreates this reserved directory before our service.
# Configuration now lives elsewhere; rmdir refuses to remove unexpected data.
if [ -d "$directory/legacy-v012/adb" ] && [ -d /data/adb ]; then
    rmdir /data/adb
fi
rm -f "$directory/platform-supervisor-boot" "$directory/platform-early-ready" "$directory/platform-late-ready"
candidate_library="$directory/bootstrap/tricky-candidate/libTrickyStoreOSS.so"
if [ -L "$candidate_library" ] && [ ! -e "$candidate_library" ]; then
    rm -f "$candidate_library"
fi
chcon u:object_r:system_file:s0 "$directory"
chmod 0755 "$directory"
chcon -R u:object_r:system_file:s0 "$directory/bootstrap" "$directory/modules" "$directory/zygisk"
chmod 0700 "$directory/bootstrap" "$directory/modules" "$directory/zygisk"
"$directory/resetprop" -n ro.adb.secure 1
"$directory/resetprop" -n service.adb.root 0
"$directory/bootstrap/policy-context-check" > "$directory/bootstrap/boot-policy.json"
"$directory/platform-seccomp-check" --feature
cat /proc/sys/kernel/random/boot_id > "$directory/platform-supervisor-boot"
chmod 0600 "$directory/platform-supervisor-boot"
[ -f "$directory/modules/device_lab_cpu/zygisk/x86_64.so" ] || exit 4
chmod 0644 "$directory/modules/device_lab_cpu/zygisk/x86_64.so"
chcon u:object_r:system_file:s0 "$directory/modules/device_lab_cpu/zygisk/x86_64.so"
cp "$directory/bootstrap/module.prop.base" "$directory/bootstrap/module.prop"
sh "$directory/bootstrap/launch.sh"
cat /proc/sys/kernel/random/boot_id > "$directory/platform-early-ready"
chmod 0600 "$directory/platform-early-ready"
log -t DeviceLabPlatform 'Platform bootstrap ready before zygote startup.'

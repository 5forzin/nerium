#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
[ "$(getprop ro.kernel.qemu)" = 1 ] && [ ! -e /system/bin/magisk ] || exit 2
[ "$(cat /data/misc/device-lab/platform-bootstrap-enabled)" = device-lab-platform-v1 ] || exit 3
directory=/data/misc/device-lab
canonical=$directory/modules/device_lab_cpu
archive=$directory/legacy-v012
case "${1:-}" in
    prepare)
        [ -d /data/adb/modules/device_lab_cpu ] && [ ! -e "$archive" ] || exit 4
        while IFS= read -r package; do
            case "$package" in ''|*[!a-zA-Z0-9_.]*) exit 5 ;; esac
            result=$(am force-stop "$package" 2>&1)
        done < /data/adb/modules/device_lab_cpu/scope
        mkdir -p "$canonical"
        for source in /data/adb/modules/device_lab_cpu/*; do
            name=${source##*/}
            [ "$name" = zygisk ] && continue
            cp -a "$source" "$canonical/"
        done
        cp /data/adb/magisk/busybox "$directory/busybox"
        chmod 0700 "$directory/busybox" "$directory/modules" "$canonical"
        chcon u:object_r:system_file:s0 "$directory/busybox"
        chcon -R u:object_r:system_file:s0 "$canonical"
        cmp /data/adb/modules/device_lab_cpu/scope "$canonical/scope"
        ;;
    archive)
        [ -d /data/adb ] && [ ! -e "$archive" ] || exit 6
        grep -Eqx 'version=0\.12\.[12]' "$canonical/module.prop" || exit 7
        [ -s "$canonical/runtime-library" ] && [ -x "$directory/busybox" ] || exit 8
        mkdir "$archive"
        chmod 0700 "$archive"
        chcon u:object_r:system_file:s0 "$archive"
        mv /data/adb "$archive/adb"
        [ ! -e /data/adb ] && [ -d "$archive/adb/modules/device_lab_cpu" ] || exit 9
        ;;
    *) exit 10 ;;
esac
sync

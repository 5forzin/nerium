#!/system/bin/sh
set -eu

[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
[ "$(getprop sys.boot_completed)" = 1 ] || exit 1
[ -f /data/adb/modules/zygisk_vector/disable ] || exit 1
[ "$(getprop ro.adb.secure)" = 1 ] || exit 1
magiskpolicy --live 'deny system_server system_server process execmem' 'deny * magisk binder call'
touch /data/misc/device-lab/hardening-enabled /data/misc/device-lab/adb-auth-enabled
chmod 0600 /data/misc/device-lab/hardening-enabled /data/misc/device-lab/adb-auth-enabled
sync

#!/system/bin/sh
set -eu

if [ "$(id -u)" != 0 ] || [ "$(getprop ro.kernel.qemu)" != 1 ]; then
    echo "Use root on the dedicated lab emulator."
    exit 1
fi
if [ "$#" != 1 ] || [ ! -s "$1" ]; then
    echo "Provide the host's ADB public key file."
    exit 2
fi
key=$(tr -d '\r\n' < "$1")
mkdir -p /data/misc/adb
touch /data/misc/adb/adb_keys
if ! grep -qxF "$key" /data/misc/adb/adb_keys; then
    printf '\n%s\n' "$key" >> /data/misc/adb/adb_keys
fi
chown system:shell /data/misc/adb/adb_keys
chmod 0640 /data/misc/adb/adb_keys
restorecon /data/misc/adb/adb_keys
if [ -x /data/misc/device-lab/resetprop ]; then
    /data/misc/device-lab/resetprop -n ro.adb.secure 1
else
    magisk resetprop -n ro.adb.secure 1
fi
sync
echo "Host public key authorized; adbd authentication configured."

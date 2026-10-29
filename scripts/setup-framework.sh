#!/system/bin/sh
set -eu

if [ "$(id -u)" != "0" ] || [ "$(getprop ro.kernel.qemu)" != "1" ]; then
    echo "Run this script as root on the dedicated Android Emulator."
    exit 1
fi
if [ "$#" -ne 1 ]; then
    echo "Usage: setup-framework.sh /data/local/tmp/vector.zip"
    exit 2
fi

magisk --sqlite "INSERT OR REPLACE INTO settings (key,value) VALUES ('zygisk',1)"
magisk --sqlite "SELECT key,value FROM settings WHERE key='zygisk'"
magisk --install-module "$1"

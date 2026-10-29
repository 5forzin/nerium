#!/system/bin/sh
set -e
result=$(settings put global adb_enabled 1 2>&1)
sleep 3
setprop persist.sys.usb.config mtp,adb
setprop sys.usb.config mtp,adb
sync

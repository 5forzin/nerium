#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
directory=/data/misc/device-lab/detached-worker-v12
mkdir -p "$directory"
chmod 0700 "$directory"
echo "$$" > "$directory/pid"
cat /proc/self/attr/current > "$directory/context"
setting=$(settings get global adb_enabled 2>&1)
printf '%s\n' "$setting" > "$directory/adb-setting"
cat /proc/self/status > "$directory/status-before.txt"
date +%s > "$directory/started"
sleep 12
cat /proc/self/status > "$directory/status-after.txt"
date +%s > "$directory/done"

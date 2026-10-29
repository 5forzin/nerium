#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
[ "$#" = 2 ] || exit 2
case "$1" in
    /data/misc/device-lab/bootstrap/workers/network-adb.sh|/data/misc/device-lab/bootstrap/workers/offline.sh|/data/misc/device-lab/bootstrap/workers/tricky-candidate.sh) ;;
    *) exit 3 ;;
esac
case "$2" in /data/misc/device-lab/bootstrap/*.log) ;; *) exit 4 ;; esac
[ ! -L "$1" ] && [ "$(stat -c '%u %a' "$1")" = '0 700' ] || exit 5
mkdir -p /sys/fs/cgroup/device-lab-platform
chmod 0700 /sys/fs/cgroup/device-lab-platform
echo "$$" > /sys/fs/cgroup/device-lab-platform/cgroup.procs
nohup setsid sh "$1" > "$2" 2>&1 < /dev/null &
worker=$!
printf '%s\n' "$worker" > "$2.pid"
chmod 0600 "$2" "$2.pid"
printf 'Independent platform worker: %s\n' "$worker"

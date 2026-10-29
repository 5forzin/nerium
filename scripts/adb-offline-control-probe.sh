#!/system/bin/sh
# Verify autonomous process ownership without changing debugging services.
set -eu
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
request=/data/misc/device-lab/adb-control-probe-request
[ ! -L "$request" ] && [ "$(stat -c '%u:%a' "$request")" = 0:600 ] || exit 2
run_id=$(cat "$request")
case "$run_id" in ''|*[!0-9a-f]*) exit 3 ;; esac
[ "${#run_id}" = 32 ] || exit 3
directory=/data/misc/device-lab/offline-v43/probe-$run_id
mkdir -p "$directory"
chmod 0700 "$directory"
grep -qx '0::/device-lab-platform' /proc/self/cgroup || exit 4
stat_line=$(cat /proc/$$/stat)
stat_body=${stat_line##*) }
mode=${1:-worker}
set -- $stat_body
parent=$2
group=$3
session=$4
[ "$group" = "$$" ] && [ "$session" = "$$" ] || exit 5
adbd_state=$(getprop init.svc.adbd)
mdns_state=$(getprop init.svc.mdnsd)
policy=$(sha256sum /sys/fs/selinux/policy)
policy=${policy%% *}
[ "$(getenforce)" = Enforcing ] || exit 6
if [ "$mode" = watchdog ]; then
    sleep 3
    printf '{"role":"watchdog","run_id":"%s","pid":%s,"parent":%s,"process_group":%s,"session":%s,"cgroup_verified":true,"adbd_before":"%s","adbd_after":"%s","mdns_before":"%s","mdns_after":"%s","policy_sha256":"%s","services_changed":false}\n' \
        "$run_id" "$$" "$parent" "$group" "$session" "$adbd_state" "$(getprop init.svc.adbd)" "$mdns_state" "$(getprop init.svc.mdnsd)" "$policy" > "$directory/watchdog.json"
    exit 0
fi
[ "$mode" = worker ] || exit 7
[ "$adbd_state" = running ] || exit 8
adbd_pid=$(pidof adbd)
case "$adbd_pid" in ''|*[!0-9]*) exit 8 ;; esac
adbd_stat=$(cat /proc/$adbd_pid/stat)
adbd_body=${adbd_stat##*) }
set -- $adbd_body
adbd_group=$3
[ "$group" != "$adbd_group" ] || exit 9
setsid sh "$0" watchdog > "$directory/watchdog.log" 2>&1 < /dev/null &
watchdog=$!
wait "$watchdog"
[ -s "$directory/watchdog.json" ] || exit 10
[ "$(getprop init.svc.adbd)" = "$adbd_state" ] && [ "$(getprop init.svc.mdnsd)" = "$mdns_state" ] || exit 11
after=$(sha256sum /sys/fs/selinux/policy)
after=${after%% *}
[ "$policy" = "$after" ] || exit 12
printf '{"role":"worker","run_id":"%s","pid":%s,"parent":%s,"process_group":%s,"session":%s,"adbd_pid":%s,"adbd_group":%s,"cgroup_verified":true,"independent_watchdog_verified":true,"policy_sha256":"%s","enforcing":true,"services_changed":false}\n' \
    "$run_id" "$$" "$parent" "$group" "$session" "$adbd_pid" "$adbd_group" "$policy" > "$directory/worker.json"
printf '%s\n' "$run_id" > "$directory/done"

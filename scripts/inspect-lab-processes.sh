#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
seen=" "
round=0
while [ "$round" -lt 90 ]; do
    for target in $(pidof com.eltavine.duckdetector) $(ps -A -o PID,NAME | awk '/com[.]eltavine[.]duckdetector[:_]/ {print $1}'); do
        case "$seen" in *" $target "*) continue ;; esac
        [ -r "/proc/$target/mountinfo" ] || continue
        seen="$seen$target "
        echo "PROCESS $target $(tr '\0' ' ' < /proc/$target/cmdline)"
        grep -E '^(Uid|Gid|Groups|CapEff):' "/proc/$target/status"
        cat "/proc/$target/attr/current" || true
        grep -E 'magisk|/adb/modules' "/proc/$target/mountinfo" || true
    done
    sleep 0.5
    round=$((round + 1))
done

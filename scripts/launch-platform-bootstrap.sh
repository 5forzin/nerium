#!/system/bin/sh
set -e
cd /data/misc/device-lab/bootstrap
./bin/zygiskd64 platform-check

# Move the worker out of adbd's service group before its children are created.
mkdir -p /sys/fs/cgroup/device-lab-platform
chmod 0700 /sys/fs/cgroup/device-lab-platform
echo "$$" > /sys/fs/cgroup/device-lab-platform/cgroup.procs
grep -q '^0::/device-lab-platform$' /proc/self/cgroup
if [ -s monitor.pid ] && kill -0 "$(cat monitor.pid)" 2>/dev/null; then
    echo 'A platform monitor is already running' >&2
    exit 1
fi
tracer=$(awk '/^TracerPid:/ {print $2}' /proc/1/status)
[ "$tracer" = 0 ] || exit 1
rm -f /data/misc/device-lab/zygisk/init_monitor
nohup setsid ./bin/zygisk-ptrace64 monitor > monitor.log 2>&1 < /dev/null &
monitor=$!
printf '%s\n' "$monitor" > monitor.pid
chmod 0600 monitor.pid monitor.log
sleep 1
kill -0 "$monitor"
tracer=$(awk '/^TracerPid:/ {print $2}' /proc/1/status)
if [ "$tracer" != "$monitor" ]; then
    echo 'The platform monitor did not acquire init tracing' >&2
    kill "$monitor" 2>/dev/null || true
    exit 1
fi
printf 'Platform monitor ready: %s\n' "$monitor"

#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
tracefs=/sys/kernel/tracing
instance=$tracefs/instances/device_lab_package_opens
[ -w "$tracefs/kprobe_events" ] || { echo 'Kprobe tracing is unavailable.'; exit 2; }
[ ! -d "$instance" ] || { echo 'A package-open trace is already active.'; exit 2; }

cleanup() {
    echo 0 > "$instance/events/device_lab/package_open/enable" 2>/dev/null || true
    rmdir "$instance" 2>/dev/null || true
    echo '-:device_lab/package_open' >> "$tracefs/kprobe_events" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
mkdir "$instance"
# Pinned x86_64 Linux 6.1: do_filp_open's second argument is struct filename*,
# whose first field points to the resolved input name. This only observes opens.
echo 'p:device_lab/package_open do_filp_open path=+0(+0(%si)):string' >> "$tracefs/kprobe_events"
echo 'path ~ "*com.eltavine.duckdetector*"' > "$instance/events/device_lab/package_open/filter"
echo 1 > "$instance/events/device_lab/package_open/enable"
echo 1 > "$instance/tracing_on"
echo 'Package-open tracing enabled for 60 seconds.'
sleep 60
cat "$instance/trace"

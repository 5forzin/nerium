#!/system/bin/sh
# Measure unchanged applications with the actual debugging services stopped.
set -eu
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
grep -qx '0::/device-lab-platform' /proc/self/cgroup || exit 2
command -v timeout >/dev/null || exit 2
request=/data/misc/device-lab/adb-offline-request
[ ! -L "$request" ] && [ "$(stat -c '%u:%a' "$request")" = 0:600 ] || exit 3
run_id=$(sed -n '1p' "$request")
original_root=$(sed -n '2p' "$request")
case "$run_id" in ''|*[!0-9a-f]*) exit 4 ;; esac
[ "${#run_id}" = 32 ] || exit 4
case "$original_root" in 0|1) ;; *) exit 4 ;; esac
directory=/data/misc/device-lab/offline-v43/measure-$run_id
mode=${1:-worker}
stat_line=$(cat /proc/$$/stat)
stat_body=${stat_line##*) }
set -- $stat_body
[ "$3" = "$$" ] && [ "$4" = "$$" ] || exit 5

read_original() {
    saved_adb=$(sed -n '1p' "$directory/original.txt")
    saved_wifi=$(sed -n '2p' "$directory/original.txt")
    saved_persist=$(sed -n '3p' "$directory/original.txt")
    saved_runtime=$(sed -n '4p' "$directory/original.txt")
    saved_mdns=$(sed -n '5p' "$directory/original.txt")
    case "$saved_adb:$saved_wifi:$saved_mdns" in *[!0-9a-z:]*) return 1 ;; esac
}
put_setting() {
    if [ "$2" = null ]; then
        capture_command "$directory/settings-$1.log" 5 settings delete global "$1"
    else
        capture_command "$directory/settings-$1.log" 5 settings put global "$1" "$2"
    fi
}
capture_command() {
    command_output_file=$1
    command_timeout=$2
    shift 2
    # Binder shellCommand delegates its stdio descriptors to the service.
    # Pass pipes, never the controller's private system_file log descriptor.
    if command_output=$(timeout "$command_timeout" "$@" 2>&1); then command_status=0; else command_status=$?; fi
    printf '%s\n' "$command_output" > "$command_output_file"
    return "$command_status"
}
setting_get() {
    timeout 5 settings get global "$1" 2>/dev/null || printf 'unknown\n'
}
record() {
    read uptime remainder < /proc/uptime
    printf '{"time_s":%s,"uptime_s":%s,"adbd":"%s","adbd_pid":"%s","mdnsd":"%s","adb_enabled":"%s","adb_wifi_enabled":"%s","root_request":"%s","persist_usb":"%s","runtime_usb":"%s","usb_state":"%s"}\n' \
        "$(date +%s)" "$uptime" "$(getprop init.svc.adbd)" "$(pidof adbd || true)" "$(getprop init.svc.mdnsd)" \
        "$(setting_get adb_enabled)" "$(setting_get adb_wifi_enabled)" "$(getprop service.adb.root)" \
        "$(getprop persist.sys.usb.config)" "$(getprop sys.usb.config)" "$(getprop sys.usb.state)"
}
restore() {
    set +e
    touch "$directory/sampling.finished"
    # Recover the transport before invoking potentially stalled Binder services.
    timeout 5 setprop service.adb.root "$original_root"
    timeout 5 start adbd
    read_original
    put_setting adb_enabled "$saved_adb" || touch "$directory/restore.failed"
    put_setting adb_wifi_enabled "$saved_wifi" || touch "$directory/restore.failed"
    timeout 5 setprop persist.sys.usb.config "$saved_persist"
    timeout 5 setprop sys.usb.config "$saved_runtime"
    if [ "$saved_mdns" = running ]; then timeout 5 start mdnsd; else timeout 5 stop mdnsd; fi
    timeout 5 start adbd
    round=0
    while [ "$(getprop init.svc.adbd)" != running ] && [ "$round" -lt 15 ]; do sleep 1; round=$((round + 1)); done
    record > "$directory/restored-$$.json"
    [ "$(getprop init.svc.adbd)" = running ] && [ "$(getprop service.adb.root)" = "$original_root" ] &&
        [ "$(setting_get adb_enabled)" = "$saved_adb" ] && [ "$(setting_get adb_wifi_enabled)" = "$saved_wifi" ] &&
        [ "$(getprop persist.sys.usb.config)" = "$saved_persist" ] && [ "$(getprop sys.usb.config)" = "$saved_runtime" ] &&
        [ "$(getprop init.svc.mdnsd)" = "$saved_mdns" ] || touch "$directory/restore.failed"
    sync
}
publish_status() {
    complete=false
    [ -f "$directory/measurement.complete" ] && complete=true
    [ ! -f "$directory/restore.failed" ] || complete=false
    printf '{"run_id":"%s","role":"%s","exit_code":%s,"measurement_complete":%s}\n' "$run_id" "$1" "$2" "$complete" > "/data/local/tmp/device-lab-offline-$run_id.status"
    chmod 0644 "/data/local/tmp/device-lab-offline-$run_id.status"
}
finish_control() {
    status=$?
    restore
    printf '%s\n' "$status" > "$directory/controller.exit"
    touch "$directory/controller.finished"
    publish_status worker "$status"
}
off_gate() {
    [ "$(getprop init.svc.adbd)" = stopped ] && [ -z "$(pidof adbd || true)" ] || return 1
    [ ! -e /dev/socket/adbd ] && [ ! -L /dev/socket/adbd ] || return 1
    ! grep -q '@jdwp-control' /proc/net/unix || return 1
    [ "$(getprop service.adb.root)" = 0 ] || return 1
    case "$(setting_get adb_enabled):$(setting_get adb_wifi_enabled)" in 0:0|0:null) ;; *) return 1 ;; esac
    case "$(getprop sys.usb.state),$(getprop sys.usb.config),$(getprop persist.sys.usb.config)" in *adb*) return 1 ;; esac
    for table in /proc/net/tcp /proc/net/tcp6; do
        while read slot local remote state rest; do
            case "$local:$state" in *:15B3:0A) return 1 ;; esac
        done < "$table"
    done
    return 0
}
if [ "$mode" = watchdog ]; then
    read_original
    printf '%s\n' "$$" > "$directory/watchdog.pid"
    round=0
    while [ "$round" -lt 270 ]; do
        if [ -f "$directory/controller.finished" ]; then touch "$directory/watchdog.finished"; exit 0; fi
        sleep 1
        round=$((round + 1))
    done
    if ! mkdir "$directory/terminal-decision" 2>/dev/null; then
        round=0
        while [ "$round" -lt 5 ]; do
            if [ -f "$directory/controller.finished" ]; then touch "$directory/watchdog.finished"; exit 0; fi
            sleep 1
            round=$((round + 1))
        done
    fi
    touch "$directory/recovery.started"
    restore
    touch "$directory/watchdog.recovered" "$directory/watchdog.finished"
    publish_status watchdog 124
    exit 0
fi
[ "$mode" = worker ] || exit 6
[ ! -e "$directory" ] || exit 7
mkdir -p "$directory"
chmod 0700 "$directory"
saved_adb=$(setting_get adb_enabled)
saved_wifi=$(setting_get adb_wifi_enabled)
saved_persist=$(getprop persist.sys.usb.config)
saved_runtime=$(getprop sys.usb.config)
saved_mdns=$(getprop init.svc.mdnsd)
case "$saved_adb" in 0|1) ;; *) exit 8 ;; esac
case "$saved_wifi" in 0|1|null) ;; *) exit 8 ;; esac
case "$saved_mdns" in stopped|running) ;; *) exit 8 ;; esac
[ "$(getprop init.svc.adbd)" = running ] && [ "$(getenforce)" = Enforcing ] || exit 9
printf '%s\n%s\n%s\n%s\n%s\n' "$saved_adb" "$saved_wifi" "$saved_persist" "$saved_runtime" "$saved_mdns" > "$directory/original.txt"
chmod 0600 "$directory/original.txt"
sha256sum /sys/fs/selinux/policy > "$directory/policy-before.txt"
cat /proc/sys/kernel/random/boot_id > "$directory/boot-id.txt"
record > "$directory/before.json"
setsid sh "$0" watchdog > "$directory/watchdog.log" 2>&1 < /dev/null &
watchdog=$!
printf '%s\n' "$watchdog" > "$directory/expected-watchdog.pid"
trap finish_control EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sleep 1
kill -0 "$watchdog"
printf '%s\n' "$$" > "$directory/worker.pid"
touch "$directory/armed"
# Do not disconnect the host until it has verified both live recovery processes.
round=0
while [ ! -f "$directory/control.go" ] && [ "$round" -lt 30 ]; do sleep 1; round=$((round + 1)); done
[ -f "$directory/control.go" ] && [ "$(cat "$directory/control.go")" = "$run_id" ] || exit 16
set -x
printf 'phase=disable-adb-setting\n' >> "$directory/stages.log"
put_setting adb_enabled 0
printf 'phase=disable-wifi-setting\n' >> "$directory/stages.log"
if [ "$saved_wifi" != null ]; then put_setting adb_wifi_enabled 0; fi
printf 'phase=drop-debug-root-request\n' >> "$directory/stages.log"
setprop service.adb.root 0
sleep 2
printf 'phase=usb-without-debugging\n' >> "$directory/stages.log"
setprop persist.sys.usb.config mtp
setprop sys.usb.config mtp
printf 'phase=stop-debug-daemon\n' >> "$directory/stages.log"
stop adbd
# adbd's hard-stop path may leave a legacy announcement in this guest's mDNS
# daemon. Restarting discovery later cannot retain that dead registration.
stop mdnsd
set +x
sleep 5
[ "$(getprop init.svc.mdnsd)" = stopped ] && [ -z "$(pidof mdnsd || true)" ] || exit 10
setprop persist.sys.usb.config mtp
off_gate || { echo 'The real debug endpoints are not fully stopped' > "$directory/failed"; exit 10; }
record > "$directory/offline.json"
sample_loop() {
    while [ ! -f "$directory/sampling.finished" ]; do
        record >> "$directory/samples.jsonl"
        if ! off_gate; then echo 'A debugging endpoint returned during measurement' > "$directory/failed"; fi
        sleep 1
    done
}
sample_loop > "$directory/sampler.log" 2>&1 &
sampler=$!
printf '%s\n' "$sampler" > "$directory/sampler.pid"

capture_probe() {
    package=$1
    label=$2
    capture_command "$directory/$label-stop.txt" 15 am force-stop "$package"
    capture_command "$directory/$label-reset.txt" 5 run-as "$package" rm -f files/report.json
    started=$(date +%s)
    capture_command "$directory/$label-launch.txt" 20 am start -W -n "$package/.MainActivity"
    round=0
    while [ "$round" -lt 30 ]; do
        modified=$(timeout 5 run-as "$package" stat -c %Y files/report.json 2>/dev/null || true)
        case "$modified" in ''|*[!0-9]*) ;; *)
            if [ "$modified" -ge "$started" ]; then
                sleep 1
                capture_command "$directory/$label.json" 5 run-as "$package" cat files/report.json
                [ -s "$directory/$label.json" ] && break
            fi ;;
        esac
        sleep 1
        round=$((round + 1))
    done
    [ -s "$directory/$label.json" ] || return 1
    pidof "$package" > "$directory/$label.pid"
    capture_command "$directory/$label-apk-path.txt" 5 pm path "$package"
    capture_command "$directory/$label-package.txt" 10 dumpsys package "$package"
    off_gate
}
capture_probe dev.androidlab.probe arm54
capture_probe dev.androidlab.rawprobe raw79
capture_probe dev.androidlab.procprobe proc99
capture_command "$directory/reveny-stop.txt" 15 am force-stop com.reveny.emulator.detection.sample
capture_command "$directory/reveny-launch.txt" 20 am start -W -n com.reveny.emulator.detection.sample/com.reveny.emulatordetector.ui.activity.MainActivity
sleep 2
capture_command "$directory/reveny-ui.log" 15 uiautomator dump "$directory/reveny.xml"
pidof com.reveny.emulator.detection.sample > "$directory/reveny.pid"
timeout 5 logcat -d -t 300 -s EmulatorDetection:V '*:S' > "$directory/reveny.log"
off_gate
capture_command "$directory/duck-stop.txt" 15 am force-stop com.eltavine.duckdetector
date +%s > "$directory/duck-launch-time.txt"
capture_command "$directory/duck-launch.txt" 20 am start -W -n com.eltavine.duckdetector/.MainActivity
pidof com.eltavine.duckdetector > "$directory/duck.pid"
ui_serial=0
dump_ui() {
    ui_attempt=0
    while [ "$ui_attempt" -lt 3 ]; do
        ui_serial=$((ui_serial + 1))
        fresh="$directory/duck-ui-$ui_serial.xml"
        if capture_command "$directory/duck-ui.log" 15 uiautomator dump "$fresh" && [ -s "$fresh" ] && grep -q '<hierarchy' "$fresh"; then
            cp "$fresh" "$directory/duck-ui.xml"
            return 0
        fi
        sleep 1
        ui_attempt=$((ui_attempt + 1))
    done
    return 1
}
tap_observed() {
    node=$1
    bounds=$(printf '%s\n' "$node" | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p')
    set -- $bounds
    [ "$#" = 4 ] || return 1
    capture_command "$directory/input.log" 5 input tap "$((($1 + $3) / 2))" "$((($2 + $4) / 2))"
}
round=0
while [ "$round" -lt 30 ]; do
    dump_ui
    if grep -q 'text="User Agreement"' "$directory/duck-ui.xml"; then echo 'A new agreement requires review' > "$directory/failed"; exit 11; fi
    later=$(tr '<' '\n' < "$directory/duck-ui.xml" | grep 'text="Later"' | grep 'package="com.eltavine.duckdetector"' || true)
    if [ -n "$later" ]; then
        tap_observed "$later" || exit 12
    elif grep -q 'text="Tap to export full report"' "$directory/duck-ui.xml" && grep -q 'text="Scanned at ' "$directory/duck-ui.xml"; then
        scanned=$(tr '<' '\n' < "$directory/duck-ui.xml" | sed -n 's/.*text="Scanned at \([0-9-]* [0-9:]*\).*/\1/p')
        scan_epoch=$(date -d "$scanned" +%s 2>/dev/null || true)
        launched=$(cat "$directory/duck-launch-time.txt")
        case "$scan_epoch" in ''|*[!0-9]*) ;; *)
            if [ "$scan_epoch" -ge "$launched" ]; then date +%s > "$directory/duck-complete-time.txt"; break; fi ;;
        esac
    fi
    off_gate
    sleep 2
    round=$((round + 1))
done
[ -s "$directory/duck-complete-time.txt" ] || { echo 'Duck did not complete within the offline window' > "$directory/failed"; exit 13; }
off_gate
cp "$directory/duck-ui.xml" "$directory/duck-offline-home.xml"
export_button=$(tr '<' '\n' < "$directory/duck-ui.xml" | grep 'text="Tap to export full report"' | grep 'package="com.eltavine.duckdetector"')
tap_observed "$export_button"
sleep 1
dump_ui
title=$(tr '<' '\n' < "$directory/duck-ui.xml" | grep 'resource-id="android:id/title"' | grep 'class="android.widget.EditText"' | grep 'package="com.google.android.documentsui"')
tap_observed "$title"
capture_command "$directory/input.log" 5 input keycombination 113 29
capture_command "$directory/input.log" 5 input text "keymint-v43-offline-$run_id.txt"
capture_command "$directory/input.log" 5 input keyevent 4
dump_ui
grep -q "text=\"keymint-v43-offline-$run_id.txt\"" "$directory/duck-ui.xml"
save=$(tr '<' '\n' < "$directory/duck-ui.xml" | grep 'resource-id="android:id/button1"' | grep 'text="SAVE"')
tap_observed "$save"
round=0
while [ ! -s "/sdcard/Download/keymint-v43-offline-$run_id.txt" ] && [ "$round" -lt 10 ]; do sleep 1; round=$((round + 1)); done
[ -s "/sdcard/Download/keymint-v43-offline-$run_id.txt" ] || exit 15
cp "/sdcard/Download/keymint-v43-offline-$run_id.txt" "$directory/duck-export.txt"
grep -q 'END OF REPORT' "$directory/duck-export.txt"
grep -Eq 'Pending[[:space:]]*:[[:space:]]*0$' "$directory/duck-export.txt"
grep -Eq 'Ready[[:space:]]*:[[:space:]]*20$' "$directory/duck-export.txt"
date +%s > "$directory/duck-export-time.txt"
off_gate
sleep 2
touch "$directory/sampling.finished"
wait "$sampler"
off_gate
record > "$directory/offline-complete.json"
sha256sum /sys/fs/selinux/policy > "$directory/policy-after.txt"
cmp "$directory/policy-before.txt" "$directory/policy-after.txt"
[ ! -f "$directory/failed" ] && [ ! -f "$directory/recovery.started" ] || exit 14
mkdir "$directory/terminal-decision" || exit 14
[ ! -f "$directory/recovery.started" ] || exit 14
touch "$directory/measurement.complete"

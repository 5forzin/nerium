#!/system/bin/sh

[ "$(getprop ro.kernel.qemu)" = 1 ] || exit 0
while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 2; done

rm -f /data/misc/device-lab/platform-supervisor-boot
if [ -f /data/misc/device-lab/platform-supervisor-requested ]; then
    if su -Z u:r:su:s0 -c '/data/misc/device-lab/platform-seccomp-check --feature'; then
        cat /proc/sys/kernel/random/boot_id > /data/misc/device-lab/platform-supervisor-boot
        chmod 0600 /data/misc/device-lab/platform-supervisor-boot
    else
        log -t DeviceLabPlatform 'Platform notifier unavailable; legacy backend remains active.'
    fi
fi

if [ -f /data/misc/device-lab/hardening-enabled ]; then
    magiskpolicy --live 'deny system_server system_server process execmem' 'deny * magisk binder call' || exit 1
fi
if [ -f /data/misc/device-lab/adb-auth-enabled ]; then
    magisk resetprop -n ro.adb.secure 1 || exit 1
    setprop ctl.restart adbd
fi
if [ -f /data/misc/device-lab/network-adb-only-enabled ]; then
    # Keep the existing authenticated emulator transport while disabling USB ADB.
    su -Z u:r:su:s0 -c 'result=$(settings put global adb_enabled 0 2>&1)' || exit 1
    setprop sys.usb.config mtp
    stop adbd
    magisk resetprop -n service.adb.root 0 || exit 1
    sleep 5
    setprop persist.sys.usb.config mtp
    start adbd
fi
if [ -f /data/misc/device-lab/remove-manager-enabled ]; then
    # Magisk's boot-complete stage may reinstall its manager; let that finish first.
    sleep 10
    su -Z u:r:su:s0 -c 'result=$(pm uninstall -k com.topjohnwu.magisk 2>&1); printf "%s\n" "$result"'
fi

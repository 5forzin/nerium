param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\research-v14"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
function Read-Adb([string[]]$Arguments) {
    $value = & $adb -s emulator-5556 @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Platform boot check failed: $($Arguments -join ' ')" }
    return ($value -join "`n").Trim()
}
if ((Read-Adb @('emu', 'avd', 'name')).Split("`n")[0].Trim() -ne 'device-lab-numa') { throw 'Wrong AVD.' }
$registered = (Get-Content (Join-Path $env:USERPROFILE '.android\avd\device-lab-numa.ini') | Where-Object { $_ -match '^path=' }) -replace '^path=', ''
if ([IO.Path]::GetFullPath($registered) -ne [IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))) { throw 'Use the independent prototype AVD.' }
& $adb -s emulator-5556 root | Out-Null
& $adb -s emulator-5556 wait-for-device
try {
    $bootId = Read-Adb @('shell', 'cat', '/proc/sys/kernel/random/boot_id')
    $markers = [ordered]@{}
    foreach ($marker in @('platform-early-ready', 'platform-late-ready', 'platform-supervisor-boot')) {
        $markers[$marker] = Read-Adb @('shell', 'cat', "/data/misc/device-lab/$marker")
        if ($markers[$marker] -ne $bootId) { throw "Stale or incomplete boot marker: $marker" }
    }
    $monitor = Read-Adb @('shell', 'cat', '/data/misc/device-lab/bootstrap/monitor.pid')
    if ($monitor -notmatch '^\d+$') { throw 'Invalid monitor identity.' }
    $status = Read-Adb @('shell', 'grep', 'TracerPid', '/proc/1/status')
    if ($status -notmatch "TracerPid:\s+$monitor$") { throw 'The bootstrap monitor is not tracing init.' }
    $group = Read-Adb @('shell', 'cat', "/proc/$monitor/cgroup")
    if ($group -notmatch '(?m)^0::/device-lab-platform$') { throw 'The monitor did not escape the temporary service cgroup.' }
    $policyHash = (Read-Adb @('shell', 'sha256sum', '/sys/fs/selinux/policy')).Split(' ')[0]
    if ($policyHash -ne '725322b8bb21c399e222db65bd9e0ee307a3b603d19d9a3d5f47a93cc8f369c0') { throw 'The loaded stock SELinux policy changed.' }
    $policy = (Read-Adb @('shell', '/data/misc/device-lab/bootstrap/policy-context-check')) | ConvertFrom-Json
    if ($policy.passed -ne 5 -or $policy.failed -ne 0 -or -not $policy.controls_passed) { throw 'The real SELinux context controls failed.' }
    $contract = (Read-Adb @('shell', '/data/misc/device-lab/platform-seccomp-check', '--require-platform')) | ConvertFrom-Json
    if ($contract.passed -ne 12 -or $contract.failed -ne 0 -or $contract.unavailable -ne 0) { throw 'The platform syscall contract failed.' }
    $provider = Read-Adb @('shell', '/data/misc/device-lab/bootstrap/bin/zygiskd64', 'platform-check')
    Read-Adb @('shell', 'test ! -e /system/bin/magisk && test ! -e /debug_ramdisk/magisk') | Out-Null
    & $adb -s emulator-5556 shell test -d /data/misc/device-lab/legacy-v012/adb
    $storageMigrated = $LASTEXITCODE -eq 0
    if ($storageMigrated) {
        Read-Adb @('shell', 'test ! -e /data/adb') | Out-Null
        $storageArchive = Read-Adb @('shell', 'stat -c "%i %u %a" /data/misc/device-lab/legacy-v012/adb')
        if ($storageArchive -ne '319489 0 700') { throw 'The archived baseline directory changed identity or protection.' }
    }
    $binaries = [ordered]@{}
    foreach ($pair in @(@('zygiskd64', 'bin/zygiskd64'), @('zygisk-ptrace64', 'bin/zygisk-ptrace64'), @('libzygisk.so', 'lib64/libzygisk.so'))) {
        $remote = "/data/misc/device-lab/bootstrap/$($pair[1])"
        $hash = (Read-Adb @('shell', 'sha256sum', $remote)).Split(' ')[0]
        if ($hash -ne (Get-FileHash (Join-Path $CacheRoot "build-upstream\$($pair[0])")).Hash.ToLowerInvariant()) { throw 'Installed bootstrap binary mismatch.' }
        $binaries[$remote] = $hash
    }
    $report = [ordered]@{
        captured_at = [DateTimeOffset]::UtcNow.ToString('o')
        boot_id = $bootId
        boot_markers = $markers
        monitor_pid = [int]$monitor
        init_tracer = $status
        monitor_cgroup = $group
        platform_backend = $provider
        loaded_selinux_policy_sha256 = $policyHash
        selinux_controls = $policy
        platform_contract = $contract
        bootstrap_binary_sha256 = $binaries
        magisk_bootstrap_binaries_absent = $true
        legacy_storage_migrated = $storageMigrated
        legacy_storage_archive = if ($storageMigrated) { $storageArchive } else { $null }
    }
} finally {
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device
}
$operating = (Read-Adb @('shell', 'id -u; settings get global adb_enabled; getprop ro.adb.secure; getprop service.adb.root; getprop persist.sys.usb.config; getprop sys.usb.config; getprop sys.usb.state; getprop init.svc.adbd')) -split '\r?\n'
if (($operating -join '|') -ne '2000|0|1|0|mtp|mtp|mtp|running') { throw 'Authenticated network operating mode was not restored.' }
$report.operating_mode = @{ shell_uid = 2000; usb_debugging = $false; adb_authenticated = $true; adb_root = $false; usb_persistent = 'mtp'; usb_runtime = 'mtp'; usb_applied = 'mtp'; adbd = 'running' }
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $PSScriptRoot "..\reports\$Name.json") -Encoding utf8
Write-Output 'Fresh boot markers, unchanged stock policy, five SELinux controls and twelve syscall contracts verified.'

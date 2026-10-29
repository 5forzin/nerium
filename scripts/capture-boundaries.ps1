param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5554',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
function Read-Adb([string[]]$Arguments) {
    $result = & $adb -s $Serial @Arguments
    if ($LASTEXITCODE -ne 0) { throw "ADB boundary read failed: $($Arguments -join ' ')" }
    return ($result -join "`n").Trim()
}
& $adb -s $Serial root | Out-Null
& $adb -s $Serial wait-for-device
try {
    $targetId = Read-Adb @('shell', 'pidof', 'dev.androidlab.probe')
    if ($targetId -notmatch '^\d+$') { throw 'Expected one running probe process.' }
    $status = Read-Adb @('shell', 'cat', "/proc/$targetId/status")
    if ($status -notmatch '(?m)^PPid:\s+(\d+)') { throw 'Could not read the probe parent process.' }
    $zygoteId = $Matches[1]
    if (-not (Read-Adb @('shell', 'cat', "/proc/$zygoteId/cmdline")).StartsWith('zygote64')) { throw 'Probe parent is not the expected zygote.' }
    $outside = Read-Adb @('shell', 'cat', '/proc/cpuinfo')
    # /proc/PID/root resolves paths through that process's mount namespace.
    $inside = Read-Adb @('shell', 'cat', "/proc/$targetId/root/proc/cpuinfo")
    $kernelMaps = Read-Adb @('shell', 'cat', "/proc/$targetId/maps")
    $kernelMounts = Read-Adb @('shell', 'cat', "/proc/$targetId/mountinfo")
    $busybox = '/data/misc/device-lab/busybox'
    & $adb -s $Serial shell test -x $busybox
    if ($LASTEXITCODE -ne 0) { $busybox = '/data/adb/magisk/busybox' }
    $report = [ordered]@{
        captured_at = [DateTime]::UtcNow.ToString('o')
        process_id = [int]$targetId
        app_mount_namespace = Read-Adb @('shell', 'readlink', "/proc/$targetId/ns/mnt")
        zygote_mount_namespace = Read-Adb @('shell', 'readlink', "/proc/$zygoteId/ns/mnt")
        outside_has_hypervisor = $outside.Contains('hypervisor')
        app_namespace_has_hypervisor = $inside.Contains('hypervisor')
        outside_hardware = Read-Adb @('shell', 'getprop', 'ro.hardware')
        outside_qemu = Read-Adb @('shell', 'getprop', 'ro.kernel.qemu')
        outside_uname = Read-Adb @('shell', 'uname', '-m')
        unhooked_namespace_uname = Read-Adb @('shell', $busybox, 'nsenter', '-t', $targetId, '-m', '--', '/system/bin/uname', '-m')
        no_new_privs = if ($status -match '(?m)^NoNewPrivs:\s+(\d+)') { [int]$Matches[1] } else { $null }
        seccomp_filters = if ($status -match '(?m)^Seccomp_filters:\s+(\d+)') { [int]$Matches[1] } else { $null }
        kernel_maps_translation_visible = $kernelMaps.Contains('libndk_translation')
        kernel_maps_module_visible = $kernelMaps.Contains('dev.androidlab.module')
        kernel_maps_staged_runtime_visible = $kernelMaps.Contains('/misc/device-lab/runtime-')
        kernel_mountinfo_profile_visible = $kernelMounts.Contains('/adb/modules/device_lab_cpu/') -or $kernelMounts.Contains('/misc/device-lab/')
        kernel_mountinfo_magisk_visible = $kernelMounts -match '(?m)(/adb/modules/| - [^ ]+ (magisk|worker) )'
        outside_properties = [ordered]@{}
        app_namespace_hardware = Read-Adb @('shell', $busybox, 'nsenter', '-t', $targetId, '-m', '--', '/system/bin/getprop', 'ro.hardware')
        selinux = Read-Adb @('shell', 'getenforce')
        namespace_log = Read-Adb @('logcat', '-d', "--pid=$targetId", '-s', 'DeviceLabNamespace:V', '*:S')
    }
    foreach ($property in @('ro.product.cpu.abilist', 'ro.dalvik.vm.native.bridge', 'ro.dalvik.vm.isa.arm64', 'ro.build.fingerprint')) {
        $report.outside_properties[$property] = Read-Adb @('shell', 'getprop', $property)
    }
    $reports = Join-Path $PSScriptRoot '..\reports'
    New-Item -ItemType Directory -Path $reports -Force | Out-Null
    $report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $reports "$Name.json") -Encoding utf8
    $report | ConvertTo-Json -Depth 4
} finally {
    & $adb -s $Serial unroot | Out-Null
    & $adb -s $Serial wait-for-device
}

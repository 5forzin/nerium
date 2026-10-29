param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Serial,
    [ValidateRange(30, 300)][int]$TimeoutSeconds = 120,
    [string]$ApkPath,
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

# Collects one merged hardware snapshot from a streamed physical device or a
# local emulator: the app-visible view from Hardware Probe plus the shell-side
# view (properties, kernel, cpufreq topology, input devices, dumpsys). Device
# identity is verified before and after collection; any mismatch fails.

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name without a file extension.' }
$package = 'dev.androidlab.hardwareprobe'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
if (-not (Test-Path -LiteralPath $adb)) { throw 'Android platform tools are not installed.' }
if (-not $ApkPath) { $ApkPath = Join-Path $PSScriptRoot '..\hardwareprobe\build\outputs\apk\debug\hardwareprobe-debug.apk' }
if (-not (Test-Path -LiteralPath $ApkPath)) { throw 'Build the Hardware Probe APK first.' }

if ($Serial -match '^(localhost|127\.0\.0\.1):\d+$') {
    & $adb connect $Serial | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not connect to the streamed device at $Serial." }
}

function Get-DeviceProp([string]$Key) {
    $value = (& $adb -s $Serial shell getprop $Key) -join ''
    if ($LASTEXITCODE -ne 0) { throw "Could not read $Key from the device." }
    return $value.Trim()
}

function Get-ShellOutput([string]$Command) {
    $value = (& $adb -s $Serial shell $Command) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "Shell collection failed: $Command" }
    return $value
}

function Get-DeviceIdentity {
    [ordered]@{
        model           = Get-DeviceProp 'ro.product.model'
        manufacturer    = Get-DeviceProp 'ro.product.manufacturer'
        device          = Get-DeviceProp 'ro.product.device'
        hardware        = Get-DeviceProp 'ro.hardware'
        boot_hardware   = Get-DeviceProp 'ro.boot.hardware'
        fingerprint     = Get-DeviceProp 'ro.build.fingerprint'
        build_id        = Get-DeviceProp 'ro.build.id'
        sdk             = Get-DeviceProp 'ro.build.version.sdk'
        release         = Get-DeviceProp 'ro.build.version.release'
        security_patch  = Get-DeviceProp 'ro.build.version.security_patch'
        abi             = Get-DeviceProp 'ro.product.cpu.abi'
    }
}

$identityBefore = Get-DeviceIdentity
if ([string]::IsNullOrWhiteSpace($identityBefore.model)) { throw 'Could not identify the device before collection.' }

& $adb -s $Serial install -r $ApkPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not install Hardware Probe.' }
$apkPath = ((& $adb -s $Serial shell pm path $package) -join "`n").Trim() -replace '^package:', ''
if ($LASTEXITCODE -ne 0 -or $apkPath -notmatch '^/.*\.apk$' -or $apkPath.Contains("`n")) { throw 'Expected one installed Hardware Probe APK.' }
$checksum = ((& $adb -s $Serial shell sha256sum $apkPath) -join ' ').Split(' ')[0]
if ($LASTEXITCODE -ne 0 -or $checksum -notmatch '^[0-9a-f]{64}$') { throw 'Could not checksum the installed Hardware Probe APK.' }

& $adb -s $Serial shell am force-stop $package | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not stop Hardware Probe.' }
$removed = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    & $adb -s $Serial shell run-as $package rm -f files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) { $removed = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $removed) { throw 'Could not remove the previous Hardware Probe report. Application storage may still be locked.' }
& $adb -s $Serial shell am start -W -n "$package/.MainActivity" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not start Hardware Probe.' }

$app = $null
for ($attempt = 0; $attempt -lt $TimeoutSeconds * 2; $attempt++) {
    Start-Sleep -Milliseconds 500
    $raw = & $adb -s $Serial exec-out run-as $package cat files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $candidate = ($raw -join "`n") | ConvertFrom-Json
            if ($candidate.schema_version -eq 1 -and $candidate.kind -eq 'hardware-snapshot' -and $null -ne $candidate.identity) {
                $app = $candidate
                break
            }
        } catch { }
    }
}
if ($null -eq $app) { throw "No complete hardware snapshot was produced within $TimeoutSeconds seconds." }

$shellGetprop = Get-ShellOutput 'getprop'
$shellCpuinfo = Get-ShellOutput 'cat /proc/cpuinfo'
$shellVersion = Get-ShellOutput 'cat /proc/version'
$shellMeminfo = Get-ShellOutput 'cat /proc/meminfo'
$shellOnline = Get-ShellOutput 'cat /sys/devices/system/cpu/online /sys/devices/system/cpu/present /sys/devices/system/cpu/possible'
$shellCpufreq = Get-ShellOutput 'for p in /sys/devices/system/cpu/cpufreq/policy*; do echo "== $p"; for f in related_cpus cpuinfo_min_freq cpuinfo_max_freq scaling_driver cpuinfo_cur_freq; do echo "-- $f"; cat "$p/$f" 2>/dev/null; done; done'
$shellInput = Get-ShellOutput 'cat /proc/bus/input/devices'
$shellAsound = Get-ShellOutput 'cat /proc/asound/cards'
$dumpsysSensors = Get-ShellOutput 'dumpsys sensorservice'
$dumpsysDisplay = Get-ShellOutput 'dumpsys display'
$dumpsysCamera = Get-ShellOutput 'dumpsys media.camera'

$identityAfter = Get-DeviceIdentity
foreach ($key in $identityBefore.Keys) {
    if ($identityBefore[$key] -ne $identityAfter[$key]) {
        throw "Device identity changed during collection ($key). Discarding the snapshot."
    }
}

$report = [ordered]@{
    schema_version = 1
    kind           = 'hardware-snapshot'
    captured_at    = (Get-Date).ToUniversalTime().ToString('o')
    serial         = $Serial
    identity       = $identityBefore
    apk_sha256     = $checksum
    app            = $app
    shell          = [ordered]@{
        getprop          = $shellGetprop
        cpuinfo          = $shellCpuinfo
        version          = $shellVersion
        meminfo          = $shellMeminfo
        cpu_lists        = $shellOnline
        cpufreq_policies = $shellCpufreq
        input_devices    = $shellInput
        asound_cards     = $shellAsound
        dumpsys          = [ordered]@{
            sensorservice = $dumpsysSensors
            display       = $dumpsysDisplay
            media_camera  = $dumpsysCamera
        }
    }
}

$reports = Join-Path $PSScriptRoot '..\reports'
New-Item -ItemType Directory -Path $reports -Force | Out-Null
$destination = Join-Path $reports "$Name.json"
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output $destination
"model=$($identityBefore.model) device=$($identityBefore.device) api=$($identityBefore.sdk) abi=$($identityBefore.abi)"
"sensors=$($app.sensors.count) cameras=$($app.cameras.count) codecs=$($app.codecs.count)"

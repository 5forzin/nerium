param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5556',
    [ValidateSet('dev.androidlab.probe', 'dev.androidlab.rawprobe', 'dev.androidlab.procprobe')]
    [string]$Package = 'dev.androidlab.probe',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
function Read-Adb([string[]]$Arguments) {
    $value = & $adb -s $Serial @Arguments
    if ($LASTEXITCODE -ne 0) { throw "CPU observation unavailable: $($Arguments -join ' ')" }
    return ($value -join "`n").Trim()
}
function Expand-CpuList([string]$Value) {
    if ($Value -notmatch '^\d+(-\d+)?(,\d+(-\d+)?)*$') { throw 'Invalid kernel CPU list.' }
    return @($Value.Split(',') | ForEach-Object {
        $range = $_.Split('-')
        if ($range.Count -eq 1) { [int]$range[0] } else { [int]$range[0]..[int]$range[1] }
    } | Sort-Object -Unique)
}
if ((Read-Adb @('emu', 'avd', 'name')).Split("`n")[0].Trim() -ne 'device-lab-numa') { throw 'Wrong AVD.' }
& $adb -s $Serial root | Out-Null
& $adb -s $Serial wait-for-device
try {
    $targetId = Read-Adb @('shell', 'pidof', $Package)
    if ($targetId -notmatch '^\d+$') { throw 'Start one target probe before this observation.' }
    $cpuinfo = Read-Adb @('shell', 'cat', "/proc/$targetId/root/proc/cpuinfo")
    $outside = Read-Adb @('shell', 'cat', '/proc/cpuinfo')
    $onlineText = Read-Adb @('shell', 'cat', "/proc/$targetId/root/sys/devices/system/cpu/online")
    $presentText = Read-Adb @('shell', 'cat', "/proc/$targetId/root/sys/devices/system/cpu/present")
    $status = Read-Adb @('shell', 'cat', "/proc/$targetId/status")
    if ($status -notmatch '(?m)^Cpus_allowed_list:\s*([^\r\n]+)') { throw 'Missing process affinity.' }
    $affinity = Expand-CpuList $Matches[1].Trim()
    $online = Expand-CpuList $onlineText
    $present = Expand-CpuList $presentText
    $ids = @([regex]::Matches($cpuinfo, '(?m)^processor\s*:\s*(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
    $outsideIds = @([regex]::Matches($outside, '(?m)^processor\s*:\s*(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
    $checks = @(
        @{ name = 'namespace_cpuinfo_matches_online'; passed = ($ids -join ',') -eq ($online -join ',') },
        @{ name = 'unscoped_kernel_cpuinfo_matches_online_control'; passed = ($outsideIds -join ',') -eq ($online -join ',') },
        @{ name = 'online_cpus_present_control'; passed = @($online | Where-Object { $_ -notin $present }).Count -eq 0 },
        @{ name = 'affinity_subset_of_online_control'; passed = @($affinity | Where-Object { $_ -notin $online }).Count -eq 0 }
    )
    $report = [ordered]@{
        captured_at = [DateTimeOffset]::UtcNow.ToString('o')
        observer = 'External root observer of the running target mount namespace; not an in-app detector.'
        package = $Package
        process_id = [int]$targetId
        namespace_cpuinfo_processor_ids = $ids
        unscoped_kernel_processor_ids = $outsideIds
        online = $onlineText
        present = $presentText
        process_affinity = $affinity
        namespace_cpuinfo = $cpuinfo
        checks = $checks
        summary = @{ total = 4; detected = @($checks | Where-Object { -not $_.passed }).Count; unavailable = 0 }
        scope = 'Processor enumeration coherence only. ARM labels remain a native-bridge reference and do not prove physical ARM hardware.'
    }
} finally {
    & $adb -s $Serial unroot | Out-Null
    & $adb -s $Serial wait-for-device
}
$report | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $PSScriptRoot "..\reports\$Name.json") -Encoding utf8
$report.summary | ConvertTo-Json -Compress

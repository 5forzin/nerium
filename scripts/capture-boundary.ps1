param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedApkSha256,
    [string]$Serial = 'emulator-5576',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$' -or $Serial -notmatch '^emulator-\d+$') { throw 'Use a laboratory report name and emulator serial.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$package = 'dev.androidlab.boundaryprobe'
$apkPath = ((& $adb -s $Serial shell -T pm path $package) -join '').Trim() -replace '^package:', ''
if ($LASTEXITCODE -ne 0 -or $apkPath -notmatch '^/data/app/[A-Za-z0-9_~=/+.-]+/base\.apk$') { throw 'Expected one installed Boundary Probe APK.' }
$checksum = ((& $adb -s $Serial shell -T sha256sum $apkPath) -join '').Split(' ')[0]
if ($LASTEXITCODE -ne 0 -or $checksum -ne $ExpectedApkSha256) { throw 'Installed APK does not match the intended build.' }
$requestId = [Guid]::NewGuid().ToString('N')
& $adb -s $Serial shell am force-stop $package | Out-Null
& $adb -s $Serial shell -T run-as $package rm -f files/report.json
if ($LASTEXITCODE -ne 0) { throw 'Could not clear the old report.' }
$bootId = ((& $adb -s $Serial shell -T cat /proc/sys/kernel/random/boot_id) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $bootId -notmatch '^[a-f0-9-]{36}$') { throw 'Could not identify the emulator boot.' }
& $adb -s $Serial shell am start -W -n "$package/.MainActivity" --es request_id $requestId | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Boundary Probe launch failed.' }
$report = $null
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
do {
    $raw = & $adb -s $Serial shell -T run-as $package cat files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $candidate = ($raw -join "`n") | ConvertFrom-Json
            if ($candidate.schema_version -eq 1 -and $candidate.request_id -eq $requestId -and $candidate.observations.Count -eq 14) { $report = $candidate; break }
        } catch { }
    }
    Start-Sleep -Milliseconds 500
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if ($null -eq $report) { throw 'No fresh complete report container was produced; individual operation failures are not clean results.' }
$nativePid = ((& $adb -s $Serial shell -T pidof $package) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $nativePid -ne "$($report.process_id)") { throw 'Report process does not match the running APK.' }
$bootAfter = ((& $adb -s $Serial shell -T cat /proc/sys/kernel/random/boot_id) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $bootAfter -ne $bootId) { throw 'Emulator rebooted during collection.' }
$selinux = ((& $adb -s $Serial shell -T getenforce) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $selinux -ne 'Enforcing') { throw 'The measurement requires SELinux Enforcing.' }
$mounts = @(& $adb -s $Serial shell -T cat /proc/mounts)
if ($LASTEXITCODE -ne 0) { throw 'Could not observe the proc mount.' }
$procMount = @($mounts | Where-Object { ($_ -split '\s+')[1] -eq '/proc' })
if ($procMount.Count -ne 1) { throw 'Expected one proc mount.' }
$report | Add-Member -NotePropertyName host -NotePropertyValue ([ordered]@{ captured_at = [DateTimeOffset]::UtcNow.ToString('o'); serial = $Serial; boot_id = $bootId; selinux = $selinux; proc_mount = $procMount[0]; apk_sha256 = $checksum })
$output = Join-Path $PSScriptRoot "..\reports\$Name.json"
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $output -Encoding utf8
Write-Output $output
foreach ($entry in $report.observations) { Write-Output "$($entry.operation) dumpable=$($entry.requested_dumpable) completed=$($entry.completed) return=$($entry.return) errno=$($entry.errno) open_errno=$($entry.open_errno) signal=$($entry.exit_signal) stage=$($entry.last_stage)" }

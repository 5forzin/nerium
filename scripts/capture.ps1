param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5554',
    [ValidateSet('dev.androidlab.probe', 'dev.androidlab.rawprobe', 'dev.androidlab.procprobe')][string]$Package = 'dev.androidlab.probe',
    [ValidateRange(15, 60)][int]$TimeoutSeconds = 15,
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name without a file extension.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$reports = Join-Path $PSScriptRoot '..\reports'
New-Item -ItemType Directory -Path $reports -Force | Out-Null
& $adb -s $Serial shell am force-stop $package | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not stop Device Probe.' }
$removed = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    & $adb -s $Serial shell run-as $package rm -f files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) { $removed = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $removed) { throw 'Could not remove the previous probe report. Application storage may still be locked.' }
& $adb -s $Serial shell am start -W -n "$package/.MainActivity" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not start Device Probe.' }
$report = $null
for ($attempt = 0; $attempt -lt $TimeoutSeconds * 2; $attempt++) {
    Start-Sleep -Milliseconds 500
    $raw = & $adb -s $Serial exec-out run-as $package cat files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $candidate = ($raw -join "`n") | ConvertFrom-Json
            if ($candidate.schema_version -eq 1 -and $candidate.checks.Count -gt 0) {
                $report = $candidate
                break
            }
        } catch { }
    }
}
if ($null -eq $report) { throw "No complete report was produced within $TimeoutSeconds seconds." }
$apkPath = ((& $adb -s $Serial shell pm path $package) -join "`n").Trim() -replace '^package:', ''
if ($LASTEXITCODE -ne 0 -or $apkPath -notmatch '^/.*\.apk$' -or $apkPath.Contains("`n")) { throw 'Expected one installed probe APK.' }
$checksum = ((& $adb -s $Serial shell sha256sum $apkPath) -join ' ').Split(' ')[0]
if ($LASTEXITCODE -ne 0 -or $checksum -notmatch '^[0-9a-f]{64}$') { throw 'Could not checksum the installed probe APK.' }
$report | Add-Member -NotePropertyName apk_sha256 -NotePropertyValue $checksum
$packageState = (& $adb -s $Serial shell dumpsys package $package) -join "`n"
if ($LASTEXITCODE -ne 0 -or $packageState -notmatch 'primaryCpuAbi=([\w-]+)') { throw 'Could not determine the installed probe ABI.' }
$report | Add-Member -NotePropertyName installed_abi -NotePropertyValue $Matches[1]
$destination = Join-Path $reports "$Name.json"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output $destination
$report.summary | ConvertTo-Json -Compress

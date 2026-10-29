#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Name,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedApkSha256,
    [string]$Serial = 'emulator-5586',
    [string]$SdkRoot = (Join-Path $env:LOCALAPPDATA 'Android\Sdk'),
    [ValidateRange(10, 300)][int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Serial -eq 'emulator-5554' -or $Serial -notmatch '^emulator-[0-9]+$') {
    throw 'Use the isolated KeyMint experiment emulator; emulator-5554 is prohibited.'
}
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$package = 'dev.androidlab.keymintcontrol'
$expectedAvd = 'device-lab-keymint-v42'
$destination = Join-Path $PSScriptRoot "..\reports\$Name.json"
if (Test-Path -LiteralPath $destination) { throw 'The requested report already exists; select a new report name.' }

function Invoke-Adb([string[]]$Arguments) {
    $output = & $adb -s $Serial @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Device command failed: $($Arguments[0])" }
    return ($output -join "`n").Trim()
}

function Read-Result {
    $raw = & $adb -s $Serial exec-out run-as $package cat files/result.json 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    try { return (($raw -join "`n") | ConvertFrom-Json) } catch { return $null }
}

$avdLines = (Invoke-Adb @('emu', 'avd', 'name')) -split "`r?`n"
if ($avdLines[0].Trim() -ne $expectedAvd) { throw "The target emulator must be $expectedAvd." }
$installedPath = Invoke-Adb @('shell', 'pm', 'path', $package)
if ($installedPath -notmatch '^package:(/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk)$') {
    throw 'The installed control package path is unexpected or has splits.'
}
$apkPath = $Matches[1]
$hashLine = Invoke-Adb @('shell', 'sha256sum', $apkPath)
$installedHash = ($hashLine -split '\s+')[0].ToLowerInvariant()
if ($installedHash -notmatch '^[a-f0-9]{64}$' -or $installedHash -ne $ExpectedApkSha256.ToLowerInvariant()) {
    throw 'The installed APK differs from the frozen before/after control APK.'
}
$previous = Read-Result
$previousRun = if ($null -eq $previous) { '' } else { [string]$previous.run_id }
Invoke-Adb @('shell', 'am', 'start', '-W', '-n', "$package/.MainActivity") | Out-Null

$button = $null
for ($attempt = 0; $attempt -lt 15; $attempt++) {
    Invoke-Adb @('shell', 'uiautomator', 'dump', '/sdcard/keymint-control-window.xml') | Out-Null
    $rawXml = Invoke-Adb @('shell', 'cat', '/sdcard/keymint-control-window.xml')
    try {
        [xml]$window = $rawXml
        $buttonNodes = @($window.SelectNodes('//node') | Where-Object {
            $_.GetAttribute('package') -eq $package -and $_.GetAttribute('text') -eq 'Run checks' -and
            $_.GetAttribute('clickable') -eq 'true' -and $_.GetAttribute('enabled') -eq 'true'
        })
        if ($buttonNodes.Count -eq 1) { $button = $buttonNodes[0]; break }
    } catch { }
    Start-Sleep -Milliseconds 250
}
if ($null -eq $button) { throw 'The visible, enabled Run checks button was not found in the observed UI.' }
if ($button.GetAttribute('bounds') -notmatch '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$') { throw 'The observed button bounds are invalid.' }
$x = [int]([int]$Matches[1] + ([int]$Matches[3] - [int]$Matches[1]) / 2)
$y = [int]([int]$Matches[2] + ([int]$Matches[4] - [int]$Matches[2]) / 2)
$startedAt = [DateTimeOffset]::UtcNow
Invoke-Adb @('shell', 'input', 'tap', [string]$x, [string]$y) | Out-Null
$deadline = $startedAt.AddSeconds($TimeoutSeconds)
$report = $null
while ([DateTimeOffset]::UtcNow -lt $deadline) {
    Start-Sleep -Milliseconds 500
    $candidate = Read-Result
    if ($null -ne $candidate -and $candidate.schema_version -eq 1 -and
        $candidate.run_id -match '^[a-f0-9]{32}$' -and $candidate.run_id -ne $previousRun -and
        $candidate.status -in @('passed', 'failed')) {
        $report = $candidate
        break
    }
}
if ($null -eq $report) { throw 'No fresh completed control run was collected before the deadline.' }
$finalHash = ((Invoke-Adb @('shell', 'sha256sum', $apkPath)) -split '\s+')[0].ToLowerInvariant()
if ($finalHash -ne $installedHash) { throw 'The installed APK changed during the control run.' }
$report | Add-Member -NotePropertyName capture -NotePropertyValue ([ordered]@{
    apk_sha256 = $installedHash
    expected_apk_sha256 = $ExpectedApkSha256.ToLowerInvariant()
    package = $package
    avd_name = $expectedAvd
    serial = $Serial
    button_text = 'Run checks'
    button_bounds = $button.GetAttribute('bounds')
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
})
New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
[IO.File]::WriteAllText($destination, ($report | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
Write-Output $destination
Write-Output "Control status: $($report.status); cleanup: $($report.cleanup.all_removed)."
if ($report.status -ne 'passed' -or -not $report.cleanup.all_removed) {
    throw "The control did not pass. Evidence retained at $destination."
}

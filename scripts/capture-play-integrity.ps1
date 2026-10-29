param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][ValidateRange(1, [long]::MaxValue)][long]$ProjectNumber,
    [string]$Serial = 'emulator-5556',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$package = 'dev.androidlab.integrityprobe'
$nonceBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($nonceBytes) } finally { $random.Dispose() }
$nonce = [Convert]::ToBase64String($nonceBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$challengePath = Join-Path $PSScriptRoot "..\reports\$Name-challenge.json"
@{ nonce_base64url = $nonce; generated_at = [DateTimeOffset]::UtcNow.ToString('o'); source = 'host' } |
    ConvertTo-Json | Set-Content -LiteralPath $challengePath -Encoding utf8

& $adb -s $Serial shell am force-stop $package | Out-Null
& $adb -s $Serial shell run-as $package rm -f files/report.json files/token.txt
if ($LASTEXITCODE -ne 0) { throw 'Could not remove the previous Play Integrity result.' }
& $adb -s $Serial shell am start -W -n "$package/.MainActivity" --es nonce_base64url $nonce --el cloud_project_number $ProjectNumber | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not start the Play Integrity probe.' }

$report = $null
for ($attempt = 0; $attempt -lt 120; $attempt++) {
    Start-Sleep -Milliseconds 500
    $raw = & $adb -s $Serial exec-out run-as $package cat files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) {
        try { $report = ($raw -join "`n") | ConvertFrom-Json; break } catch { }
    }
}
if (-not $report) { throw 'No complete Play Integrity result was collected.' }
if ($report.nonce_base64url -ne $nonce -or $report.cloud_project_number -ne $ProjectNumber) {
    throw 'The probe result does not match the host request.'
}

$apkPath = ((& $adb -s $Serial shell pm path $package) -join '').Trim() -replace '^package:', ''
if ($apkPath -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') { throw 'Unexpected installed probe path.' }
$apkHash = ((& $adb -s $Serial shell sha256sum $apkPath) -split '\s+')[0]
if ($LASTEXITCODE -ne 0 -or $apkHash -notmatch '^[a-f0-9]{64}$') { throw 'Could not verify the installed APK hash.' }
$report | Add-Member -NotePropertyName apk_sha256 -NotePropertyValue $apkHash
$playStoreState = (& $adb -s $Serial shell dumpsys package com.android.vending) -join "`n"
$playServicesState = (& $adb -s $Serial shell dumpsys package com.google.android.gms) -join "`n"
$playStorePaths = @(& $adb -s $Serial shell pm path com.android.vending)
$playStorePath = if ($playStorePaths.Count -gt 0) { $playStorePaths[0].Trim() } else { $null }
$environment = [ordered]@{
    android_api = ((& $adb -s $Serial shell getprop ro.build.version.sdk) -join '').Trim()
    build_fingerprint = ((& $adb -s $Serial shell getprop ro.build.fingerprint) -join '').Trim()
    play_store_path = $playStorePath
    play_store_version = if ($playStoreState -match 'versionName=([^\r\n]+)') { $Matches[1] } else { $null }
    play_services_version = if ($playServicesState -match 'versionName=([^\r\n]+)') { $Matches[1] } else { $null }
}
$report | Add-Member -NotePropertyName environment -NotePropertyValue $environment

if ($report.status -eq 'token_received') {
    $privatePath = "files/token-$Name.txt"
    & $adb -s $Serial shell run-as $package cp files/token.txt $privatePath
    if ($LASTEXITCODE -ne 0) { throw 'Could not retain the app-private token for this report.' }
    $token = ((& $adb -s $Serial exec-out run-as $package cat $privatePath 2>$null) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $token.Length -ne $report.token_length) {
        throw 'The private token could not be checked against the probe result.'
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($token)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $tokenHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $report | Add-Member -NotePropertyName token_sha256 -NotePropertyValue $tokenHash
    $report | Add-Member -NotePropertyName token_private_path -NotePropertyValue $privatePath
    $report | Add-Member -NotePropertyName compact_jwe_shape -NotePropertyValue (($token.ToCharArray() | Where-Object { $_ -eq '.' }).Count -eq 4)
}

$destination = Join-Path $PSScriptRoot "..\reports\$Name.json"
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output $destination
Write-Output "Status: $($report.status); error code: $($report.error_code)."
if ($report.status -eq 'token_received') { Write-Output 'Token retained only in app-private storage.' }

param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5556',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$package = 'dev.androidlab.attestationprobe'
$challenge = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($challenge) } finally { $random.Dispose() }
$challengeBase64 = [Convert]::ToBase64String($challenge)
$challengePath = Join-Path $PSScriptRoot "..\reports\$Name-challenge.json"
@{ challenge_base64 = $challengeBase64; generated_at = [DateTimeOffset]::UtcNow.ToString('o'); source = 'host' } |
    ConvertTo-Json | Set-Content -LiteralPath $challengePath -Encoding utf8
& $adb -s $Serial shell am force-stop $package | Out-Null
& $adb -s $Serial shell run-as $package rm -f files/report.json
if ($LASTEXITCODE -ne 0) { throw 'Could not remove the previous attestation report.' }
& $adb -s $Serial shell am start -W -n "$package/.MainActivity" --es challenge_base64 $challengeBase64 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not start the independent attestation probe.' }
$report = $null
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    Start-Sleep -Milliseconds 500
    $raw = & $adb -s $Serial exec-out run-as $package cat files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) {
        try { $report = ($raw -join "`n") | ConvertFrom-Json; break } catch { }
    }
}
if (-not $report) { throw 'No complete independent attestation report was collected.' }
$path = ((& $adb -s $Serial shell pm path $package) -join '').Trim() -replace '^package:', ''
if ($path -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') { throw 'Unexpected installed probe path.' }
$hash = ((& $adb -s $Serial shell sha256sum $path) -split '\s+')[0]
if ($LASTEXITCODE -ne 0 -or $hash -notmatch '^[a-f0-9]{64}$') { throw 'Could not verify the installed probe hash.' }
$report | Add-Member -NotePropertyName apk_sha256 -NotePropertyValue $hash
$report | Add-Member -NotePropertyName package -NotePropertyValue $package
$destination = Join-Path $PSScriptRoot "..\reports\$Name.json"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $destination -Encoding utf8
if ($report.challenge_source -ne 'external' -or $report.default_keystore.challenge_base64 -ne $challengeBase64) {
    throw "The probe did not echo the externally supplied challenge; install attestationprobe 0.2.0 or newer. Unaccepted evidence retained at $destination."
}
Write-Output $destination
Write-Output "Keystore: $($report.default_keystore.status); security level: $($report.default_keystore.keyinfo_security_level); StrongBox: $($report.strongbox.status)."

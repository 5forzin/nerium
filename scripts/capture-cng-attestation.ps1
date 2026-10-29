#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Name,
    [ValidateSet('complete', 'failed')][string]$ExpectedStatus = 'complete',
    [string]$Serial = 'emulator-5586',
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedApkSha256 = '5927efb39af0f7ab5c8959a1652680d8df73e4f211a46fbb18c19a7415d25747',
    [string]$ExpectedLabRootSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Serial -ne 'emulator-5586') { throw 'Use the dedicated isolated KeyMint emulator.' }
if ($ExpectedStatus -eq 'complete' -and $ExpectedLabRootSha256 -notmatch '^[a-f0-9]{64}$') { throw 'Supply the issuer fingerprint from the host backend startup log.' }
$package = 'dev.androidlab.cngattestationcontrol'
$adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$reports = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\reports'))
$reportPath = Join-Path $reports "$Name.json"
$challengePath = Join-Path $reports "$Name-challenge.json"
if ((Test-Path -LiteralPath $reportPath) -or (Test-Path -LiteralPath $challengePath)) { throw 'Report name already used.' }
function Device([string[]]$Arguments) {
    $output = (& $adb -s $Serial @Arguments) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "Device command failed: $($Arguments[0])" }
    $output.Trim()
}
$avdLines = @((Device @('emu', 'avd', 'name')) -split '\r?\n' | Where-Object { $_ })
if ($avdLines.Count -ne 2 -or $avdLines[0] -cne 'device-lab-keymint-v42' -or $avdLines[1] -cne 'OK') { throw 'Unexpected AVD identity.' }
$path = (Device @('shell', 'pm', 'path', $package)) -replace '^package:', ''
if ($path -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') { throw 'Expected the installed control APK.' }
function Check-Apk {
    $hash = ((Device @('shell', 'sha256sum', $path)) -split '\s+')[0]
    if ($hash -cne $ExpectedApkSha256) { throw 'The frozen control APK changed.' }
}
Check-Apk
$challenge = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$encoded = [Convert]::ToBase64String($challenge)
[IO.File]::WriteAllText($challengePath, (@{challenge_base64 = $encoded; source = 'host'; generated_at = [DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Device @('shell', 'am', 'force-stop', $package) | Out-Null
Device @('shell', 'am', 'start', '-W', '-n', "$package/.MainActivity", '--es', 'challenge_base64', $encoded) | Out-Null
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
$report = $null
do {
    $raw = & $adb -s $Serial exec-out run-as $package cat files/report.json 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $candidate = ($raw -join "`n") | ConvertFrom-Json
            if ($candidate.challenge_base64 -ceq $encoded -and $candidate.run_id -match '^[a-f0-9]{32}$' -and
                $candidate.status -in @('complete', 'failed')) { $report = $candidate; break }
        } catch { }
    }
    Start-Sleep -Milliseconds 500
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if ($null -eq $report) { throw 'No fresh completed control report.' }
Check-Apk
$report | Add-Member -NotePropertyName apk_sha256 -NotePropertyValue $ExpectedApkSha256
$report | Add-Member -NotePropertyName package -NotePropertyValue $package
$report | Add-Member -NotePropertyName expected_control_status -NotePropertyValue $ExpectedStatus
[IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 18), [Text.UTF8Encoding]::new($false))
if ($report.status -cne $ExpectedStatus -or -not $report.default_keystore.cleanup.verified) { throw "Unexpected control result; evidence retained: $reportPath" }
if ($ExpectedStatus -eq 'complete') {
    $apk = Join-Path $PSScriptRoot '..\cngattestationcontrol\build\outputs\apk\debug\cngattestationcontrol-debug.apk'
    if ((Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedApkSha256) { throw 'The local APK differs from the installed frozen APK.' }
    $java = Join-Path $env:ProgramFiles 'Java\jdk-21\bin\java.exe'
    $signer = Join-Path $env:LOCALAPPDATA 'Android\Sdk\build-tools\35.0.0\lib\apksigner.jar'
    $signerOutput = (& $java -jar $signer verify --print-certs $apk) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'APK signature verification failed.' }
    $certificate = [regex]::Match($signerOutput, '(?m)^Signer #1 certificate SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$')
    if (-not $certificate.Success) { throw 'The APK signing-certificate digest is unavailable.' }
    $python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    $roots = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v16\official-attestation-roots.json'
    & $python -B (Join-Path $PSScriptRoot 'verify-cng-attestation.py') $reportPath --expected-challenge $challengePath `
        --expected-app-certificate-sha256 $certificate.Groups[1].Value --expected-lab-root-sha256 $ExpectedLabRootSha256 `
        --roots $roots --output (Join-Path $reports "$Name-verified.json")
    if ($LASTEXITCODE -ne 0) { throw 'Independent host verification failed.' }
}
Write-Output "$reportPath ($ExpectedStatus; own alias cleanup verified)."

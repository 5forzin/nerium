#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Name,
    [string]$Serial = 'emulator-5586',
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedApkSha256 = '06feb66b5ea7a8b801afb57b242efe07e014118e92a45aac0d6fbf6f864ccbdc',
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedLabRootSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Serial -ne 'emulator-5586') { throw 'Use the dedicated isolated KeyMint emulator.' }
$adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$roots = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v16\official-attestation-roots.json'
$reports = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\reports'))
foreach ($suffix in @('.json', '-challenge.json', '-verified.json', '-trust.json', '-evaluation.json')) {
    if (Test-Path -LiteralPath (Join-Path $reports ($Name + $suffix))) { throw 'The requested report name is already in use.' }
}
$avd = (& $adb -s $Serial emu avd name) -join "`n"
$avdLines = @($avd -split '\r?\n' | Where-Object { $_ })
if ($LASTEXITCODE -ne 0 -or $avdLines.Count -ne 2 -or $avdLines[0] -cne 'device-lab-keymint-v42' -or $avdLines[1] -cne 'OK') { throw 'The emulator identity differs from the isolated clone.' }
$path = ((& $adb -s $Serial shell pm path dev.androidlab.attestationprobe) -join '').Trim() -replace '^package:', ''
if ($LASTEXITCODE -ne 0 -or $path -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') { throw 'Expected one installed independent attestation APK.' }
function Check-Apk {
    $hash = ((& $adb -s $Serial shell sha256sum $path) -split '\s+')[0]
    if ($LASTEXITCODE -ne 0 -or $hash -cne $ExpectedApkSha256) { throw 'The installed independent probe APK changed.' }
}
Check-Apk
& (Join-Path $PSScriptRoot 'capture-attestation.ps1') -Serial $Serial -Name $Name | Out-Null
Check-Apk
$reportPath = Join-Path $reports "$Name.json"
$challengePath = Join-Path $reports "$Name-challenge.json"
$verifiedPath = Join-Path $reports "$Name-verified.json"
$trustPath = Join-Path $reports "$Name-trust.json"
& $python -B (Join-Path $PSScriptRoot 'verify-attestation.py') $reportPath --expected-challenge $challengePath --output $verifiedPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Independent public signature or challenge verification failed.' }
& $python -B (Join-Path $PSScriptRoot 'audit-attestation-trust.py') $reportPath --roots $roots --expected-challenge $challengePath --output $trustPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Independent external-root audit failed to run.' }
$report = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
$verified = Get-Content -Raw -LiteralPath $verifiedPath | ConvertFrom-Json
$trust = Get-Content -Raw -LiteralPath $trustPath | ConvertFrom-Json
if ($verified.root_sha256 -cne $ExpectedLabRootSha256) { throw 'The EC issuer differs from the root published directly by the host backend.' }
$sample = $report.default_keystore
if ($sample.status -ne 'complete' -or $sample.certificates.Count -ne 2 -or
    $sample.keyinfo_security_level -ne 0 -or $sample.keyinfo_inside_secure_hardware -or
    -not $sample.chain_signatures_valid -or
    -not $sample.leaf_matches_generated_key -or -not $sample.key_possession_verified -or
    -not $verified.certificate_signatures_verified -or -not $verified.key_possession_verified -or
    -not $verified.external_nonce_binding_verified) { throw 'The software attestation control did not complete.' }
# The frozen older APK omits chain_valid_now; the unchanged host verifier
# always checks every certificate's validity interval before returning.
if ($sample.PSObject.Properties.Name -contains 'chain_valid_now' -and -not $sample.chain_valid_now) { throw 'The APK reported an invalid certificate interval.' }
if ($verified.signed_claims.attestation_security_level -ne 0 -or $verified.signed_claims.keymaster_security_level -ne 0 -or
    $verified.signed_claims.PSObject.Properties.Name -contains 'root_of_trust') { throw 'Unexpected hardware or boot claims were signed.' }
if ($trust.root_subject -notmatch 'CN=AndroidLab Software Attestation Root' -or
    $trust.prerequisites.root_certificate_in_external_snapshot -or $trust.prerequisites.root_public_key_in_external_snapshot -or
    $trust.manufacturer_trust -ne 'not_established') { throw 'The laboratory issuer or trust classification is unexpected.' }
$evaluation = [ordered]@{
    schema_version = 1
    recorded_at = [DateTimeOffset]::UtcNow.ToString('o')
    status = 'passed_software_lab_attestation'
    apk_sha256 = $ExpectedApkSha256
    software_security_levels_verified = $true
    chain_signatures_and_key_possession_verified = $true
    certificate_validity_verified_by_host = $true
    externally_supplied_challenge_verified = $true
    certificate_count = $sample.certificates.Count
    root_subject = $trust.root_subject
    root_of_trust_omitted = $true
    manufacturer_trust = $trust.manufacturer_trust
    root_matches_host_backend = $true
    root_sha256 = $ExpectedLabRootSha256
    hardware_trust_established = $false
    external_root_snapshot_sha256 = $trust.external_root_snapshot_sha256
    independent_probe_report = "$Name.json"
    independent_verifier_report = "$Name-verified.json"
    external_trust_report = "$Name-trust.json"
}
$destination = Join-Path $reports "$Name-evaluation.json"
[IO.File]::WriteAllText($destination, ($evaluation | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Write-Output $destination

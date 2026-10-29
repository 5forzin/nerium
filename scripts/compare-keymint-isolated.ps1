#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$Before = 'keymint-v42-baseline',
    [string]$After = 'keymint-v42-final',
    [string]$Name = 'keymint-v42-comparison'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
foreach ($value in @($Before, $After, $Name)) {
    if ($value -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use simple report prefixes.' }
}
$reports = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\reports'))
$destination = Join-Path $reports "$Name.json"
if (Test-Path -LiteralPath $destination) { throw 'The comparison report already exists.' }
function Read-Report([string]$Prefix, [string]$Suffix) {
    Get-Content -Raw -LiteralPath (Join-Path $reports "$Prefix-$Suffix.json") | ConvertFrom-Json
}
function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
$suites = [ordered]@{}
foreach ($entry in @(@('arm54', 54), @('raw79', 79), @('proc99', 99))) {
    $old = Read-Report $Before $entry[0]
    $new = Read-Report $After $entry[0]
    Require ($old.apk_sha256 -ceq $new.apk_sha256) "The $($entry[0]) APK changed."
    Require ($old.installed_abi -ceq $new.installed_abi) "The $($entry[0]) ABI changed."
    Require (($old.checks.id -join "`n") -ceq ($new.checks.id -join "`n")) "The $($entry[0]) check list changed."
    foreach ($report in @($old, $new)) {
        Require ($report.summary.total -eq $entry[1] -and $report.checks.Count -eq $entry[1]) 'A suite is incomplete.'
        Require ($report.summary.detected -eq 0 -and $report.summary.unavailable -eq 0) 'A detector suite regressed.'
    }
    $suites[$entry[0]] = [ordered]@{before = $old.summary; after = $new.summary; same_apk_abi_checks = $true}
}
$oldReveny = Read-Report $Before 'reveny'
$newReveny = Read-Report $After 'reveny'
Require ($oldReveny.apk_sha256 -ceq $newReveny.apk_sha256) 'Reveny APK changed.'
Require (-not $oldReveny.detected -and -not $newReveny.detected -and
    $oldReveny.finding_count -eq 0 -and $newReveny.finding_count -eq 0) 'Reveny regressed.'
$oldKeys = Read-Report $Before 'keystore'
$newKeys = Read-Report $After 'keystore'
Require ($oldKeys.capture.apk_sha256 -ceq $newKeys.capture.apk_sha256) 'The control APK changed.'
Require ($oldKeys.run_id -cne $newKeys.run_id) 'The control report was reused.'
foreach ($report in @($oldKeys, $newKeys)) {
    Require ($report.status -eq 'passed' -and $report.cleanup.all_removed) 'Keystore controls failed.'
    foreach ($control in @('rsa_pss_sha256', 'ec_p256_sha256', 'aes_256_gcm', 'hmac_sha256')) {
        Require ($report.controls.$control.status -eq 'passed') "The $control control failed."
        Require ($report.controls.$control.key_info.security_level -eq 0) 'The software security level changed.'
    }
}
$oldPolicy = Read-Report $Before 'policy'
$newPolicy = Read-Report $After 'policy'
Require ($oldPolicy.loaded_policy_sha256 -ceq $newPolicy.loaded_policy_sha256) 'Loaded SELinux policy changed.'
Require ($oldPolicy.context_controls.enforcing -and $newPolicy.context_controls.enforcing -and
    $oldPolicy.context_controls.controls_passed -and $newPolicy.context_controls.controls_passed) 'SELinux controls failed.'
$window = Read-Report $After 'gateway-window'
$generated = @($window.events | Where-Object { $_.event -eq 'generated_key' -and $_.storage -eq 'cng_reference' })
$signatures = @($window.events | Where-Object { $_.event -eq 'protected_signature' -and $_.bytes -eq 256 })
Require ($window.control_run_id -ceq $newKeys.run_id -and $generated.Count -ge 1 -and $signatures.Count -ge 1) 'Protected RSA signing was not observed during the control run.'
$oldDuck = Read-Report $Before 'duck-complete'
$newDuck = Read-Report $After 'duck-complete'
Require ($oldDuck.status -eq 'complete' -and $newDuck.status -eq 'complete' -and
    $oldDuck.apk_sha256 -ceq $newDuck.apk_sha256) 'Duck comparison is incomplete or uses a different APK.'
$oldCounts = $oldDuck.duck.scan_statistics
$newCounts = $newDuck.duck.scan_statistics
Require ($oldCounts.Pending -eq 0 -and $newCounts.Pending -eq 0) 'Duck has pending checks.'
$severity = @{CLEAR = 0; INFO = 1; WARNING = 2; DANGER = 3}
$moduleComparison = @()
Require ($oldDuck.duck.module_verdicts.Count -eq $newDuck.duck.module_verdicts.Count) 'Duck module coverage changed.'
foreach ($oldModule in $oldDuck.duck.module_verdicts) {
    $matchingModules = @($newDuck.duck.module_verdicts | Where-Object detector -CEQ $oldModule.detector)
    Require ($matchingModules.Count -eq 1) 'Duck module identities changed.'
    $newModule = $matchingModules[0]
    Require ($severity.ContainsKey($oldModule.severity) -and $severity.ContainsKey($newModule.severity)) 'Unexpected Duck severity.'
    Require ($severity[$newModule.severity] -le $severity[$oldModule.severity]) "Duck severity increased for $($oldModule.detector)."
    $moduleComparison += @{module = $oldModule.detector; before = $oldModule.severity; after = $newModule.severity}
}
$attestation = @()
foreach ($report in @($oldDuck, $newDuck)) {
    $exportName = [string]$report.duck.export_report
    Require ([IO.Path]::GetFileName($exportName) -ceq $exportName) 'Unexpected Duck export path.'
    $exportPath = Join-Path $reports $exportName
    Require ((Get-FileHash -LiteralPath $exportPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $report.duck.export_sha256) 'The Duck export changed.'
    $text = Get-Content -Raw -LiteralPath $exportPath
    $match = [regex]::Match($text, 'Key attestation:\s*([^\r\n]+)')
    Require ($match.Success) 'Duck attestation coverage could not be compared.'
    $attestation += $match.Groups[1].Value.Trim()
}
$coverageRegressed = ($attestation[0] -notmatch '^Unavailable' -and $attestation[1] -match '^Unavailable')
$bootClaimCoverageReduced = ($attestation[0] -match 'RootOfTrust availability:\s*true' -and $attestation[1] -notmatch 'RootOfTrust availability:\s*true')
$labEvidence = $null
$rsaEvidencePath = Join-Path $reports "$After-rsa-verified.json"
$ecEvidencePath = Join-Path $reports "$After-ec-evaluation.json"
if ((Test-Path -LiteralPath $rsaEvidencePath) -or (Test-Path -LiteralPath $ecEvidencePath)) {
    $rsaEvidence = Read-Report $After 'rsa-verified'
    $ecEvidence = Read-Report $After 'ec-evaluation'
    Require ($rsaEvidence.root_matches_host_backend -and $ecEvidence.root_matches_host_backend -and
        $rsaEvidence.root_sha256 -ceq $ecEvidence.root_sha256 -and
        $rsaEvidence.root_sha256 -ceq $window.host_startup.lab_root_sha256) 'Attestation issuer provenance differs from the host startup record.'
    Require ($rsaEvidence.rsa_pss_key_possession_verified -and $rsaEvidence.externally_supplied_challenge_verified -and
        $rsaEvidence.signed_package_and_apk_certificate_verified -and $ecEvidence.externally_supplied_challenge_verified -and
        -not $rsaEvidence.root_matches_external_snapshot -and -not $rsaEvidence.root_of_trust_present -and
        $rsaEvidence.attestation_security_level -eq 0 -and $rsaEvidence.keymaster_security_level -eq 0) 'Laboratory attestation validation failed.'
    $labEvidence = @{
        root_sha256 = $rsaEvidence.root_sha256
        root_matches_host_backend = $true
        rsa_pss_and_ec_public_verification = $true
        external_challenge_and_application_binding_verified = $true
        security_level = 'SOFTWARE'
        root_of_trust_present = $false
        manufacturer_trust = 'not_established'
        rsa_report = "$After-rsa-verified.json"
        ec_report = "$After-ec-evaluation.json"
    }
}
$result = [ordered]@{
    schema_version = 1
    recorded_at = [DateTimeOffset]::UtcNow.ToString('o')
    status = $(if ($coverageRegressed) { 'passed_core_controls_with_attestation_regression' } elseif ($bootClaimCoverageReduced) { 'passed_core_controls_boot_claims_unavailable' } else { 'passed_measured_controls' })
    core_controls_passed = $true
    before_prefix = $Before
    after_prefix = $After
    suites = $suites
    reveny = @{before = 0; after = 0; same_apk = $true}
    keystore = @{before = '4/4'; after = '4/4'; same_apk = $true; protected_rsa_generations = $generated.Count; protected_signatures = $signatures.Count}
    selinux = @{loaded_policy_sha256 = $newPolicy.loaded_policy_sha256; unchanged = $true; enforcing = $true; context_controls_passed = $true}
    duck = @{
        before = $oldCounts; after = $newCounts; same_apk = $true
        attestation_before = $attestation[0]; attestation_after = $attestation[1]
        attestation_collection_regressed = $coverageRegressed
        original_boot_claims_not_reproduced = $bootClaimCoverageReduced
        lower_bootloader_signal_count_is_not_a_fix = ($coverageRegressed -or $bootClaimCoverageReduced)
        severity_per_module = $moduleComparison
    }
    android_tee_verified = $false
    google_attestation_established = $false
    laboratory_attestation = $labEvidence
    zero_detections_achieved = ($newCounts.Danger -eq 0 -and $newCounts.Warning -eq 0)
}
[IO.File]::WriteAllText($destination, ($result | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
Write-Output $destination

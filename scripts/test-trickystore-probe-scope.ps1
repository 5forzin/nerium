param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\research-v17",
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$registered = (Get-Content "$env:USERPROFILE\.android\avd\device-lab-numa.ini" | Where-Object { $_ -match '^path=' }) -replace '^path=', ''
if ([IO.Path]::GetFullPath($registered) -ne [IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))) {
    throw 'Use the independent attestation sandbox.'
}
if (@(& $adb -s emulator-5556 emu avd name)[0].Trim() -ne 'device-lab-numa') { throw 'Wrong emulator.' }
$baseline = Get-Content "$PSScriptRoot\..\reports\strict-v17-direct-before-boot.json" -Raw | ConvertFrom-Json
$trial = Get-Content "$PSScriptRoot\..\reports\strict-v17-tricky-direct.json" -Raw | ConvertFrom-Json
if ($trial.launch -notmatch '^Independent platform worker: (\d+)$') { throw 'The candidate controller is unknown.' }
$expectedController = $Matches[1]
$candidate = Get-Content (Join-Path $CacheRoot 'candidate-direct\manifest.json') -Raw | ConvertFrom-Json
$synthetic = Get-Content (Join-Path $CacheRoot 'candidate-lab-ca\manifest.json') -Raw | ConvertFrom-Json
$target = '/data/misc/tricky_lab1/target.txt'
$original = Join-Path $CacheRoot 'candidate-direct\target.txt'
$temporary = Join-Path $CacheRoot 'candidate-lab-ca\target-with-probe.txt'
[IO.File]::WriteAllText($temporary, "com.eltavine.duckdetector!`ndev.androidlab.attestationprobe!`n", [Text.UTF8Encoding]::new($false))
if ((Get-FileHash $original).Hash.ToLowerInvariant() -ne $candidate.files.'target.txt') { throw 'Original target scope changed.' }

function Read-Adb([string[]]$Arguments) {
    $value = & $adb -s emulator-5556 @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Sandbox control unavailable: $($Arguments -join ' ')" }
    return ($value -join "`n").Trim()
}
function Root-Device {
    & $adb -s emulator-5556 root | Out-Null
    & $adb -s emulator-5556 wait-for-device | Out-Null
}
function Unroot-Device {
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device | Out-Null
}
function Replace-Target([string]$Source) {
    & $adb -s emulator-5556 push $Source /data/misc/tricky_lab1/target.next.txt | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Target transfer failed.' }
    Read-Adb @('shell','chown 0:0 /data/misc/tricky_lab1/target.next.txt; chmod 0600 /data/misc/tricky_lab1/target.next.txt; chcon u:object_r:system_file:s0 /data/misc/tricky_lab1/target.next.txt; mv -f /data/misc/tricky_lab1/target.next.txt /data/misc/tricky_lab1/target.txt') | Out-Null
}

$changed = $false
$scopeHash = (Get-FileHash $temporary).Hash.ToLowerInvariant()
Root-Device
try {
    if ((Read-Adb @('shell','cat','/proc/sys/kernel/random/boot_id')) -ne $baseline.boot_id -or
        (Read-Adb @('shell','pidof','keystore2')) -ne [string]$trial.keystore_after -or
        (Read-Adb @('shell','pidof','DeviceLabAttestationCandidate')) -ne $expectedController -or
        (Read-Adb @('shell','getenforce')) -ne 'Enforcing') { throw 'Sandbox identity or SELinux changed.' }
    $policy = (Read-Adb @('shell','sha256sum','/sys/fs/selinux/policy')).Split(' ')[0]
    if ($policy -ne $baseline.loaded_selinux_policy_sha256) { throw 'The loaded policy changed.' }
    if ((Read-Adb @('shell','sha256sum',$target)).Split(' ')[0] -ne $candidate.files.'target.txt') {
        throw 'The original target scope is not active.'
    }
    if ((Read-Adb @('shell','sha256sum','/data/misc/tricky_lab1/keybox.xml')).Split(' ')[0] -ne $synthetic.keybox_sha256) {
        throw 'The synthetic test keybox is not active.'
    }
    $changed = $true
    Replace-Target $temporary
    Start-Sleep -Seconds 2
    if ((Read-Adb @('shell','sha256sum',$target)).Split(' ')[0] -ne $scopeHash) { throw 'Temporary target scope did not persist.' }
    Unroot-Device
    & "$PSScriptRoot\capture-attestation.ps1" -Name $Name -Serial emulator-5556 -SdkRoot $SdkRoot
    if (-not (Test-Path "$PSScriptRoot\..\reports\$Name.json")) { throw 'Attestation report missing.' }
    $roots = "$env:LOCALAPPDATA\android-device-lab\research-v16\official-attestation-roots.json"
    python "$PSScriptRoot\audit-attestation-trust.py" "$PSScriptRoot\..\reports\$Name.json" --roots $roots --expected-challenge "$PSScriptRoot\..\reports\$Name-challenge.json" --output "$PSScriptRoot\..\reports\$Name-trust.json"
    if ($LASTEXITCODE -ne 0) { throw 'Independent trust audit failed.' }
} finally {
    if ($changed) {
        Root-Device
        try {
            Replace-Target $original
            Start-Sleep -Seconds 2
            if ((Read-Adb @('shell','sha256sum',$target)).Split(' ')[0] -ne $candidate.files.'target.txt' -or
                (Read-Adb @('shell','sha256sum','/sys/fs/selinux/policy')).Split(' ')[0] -ne $baseline.loaded_selinux_policy_sha256) {
                throw 'Failed to restore the original scope and policy.'
            }
        } finally { Unroot-Device }
    } else { Unroot-Device }
}
$audit = Get-Content "$PSScriptRoot\..\reports\$Name-trust.json" -Raw | ConvertFrom-Json
if ($audit.root_sha256 -ne $synthetic.entries[0].root_certificate_sha256) { throw 'The scoped root did not match the synthetic EC certificate.' }
$result = [ordered]@{
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    boot_id = $baseline.boot_id
    scoped_probe = 'dev.androidlab.attestationprobe'
    original_scope_restored = $true
    synthetic_root_sha256 = $audit.root_sha256
    certificate_signatures_verified = $audit.certificate_signatures_verified
    external_nonce_binding_verified = $audit.external_nonce_binding_verified
    manufacturer_trust = $audit.manufacturer_trust
    failed_prerequisites = $audit.failed_prerequisites
    loaded_selinux_policy_sha256 = $baseline.loaded_selinux_policy_sha256
}
$result | ConvertTo-Json -Depth 6 | Set-Content "$PSScriptRoot\..\reports\$Name-scope.json" -Encoding utf8
$result | ConvertTo-Json -Depth 6

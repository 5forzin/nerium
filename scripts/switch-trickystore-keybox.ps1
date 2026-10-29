param(
    [Parameter(Mandatory = $true)][ValidateSet('Synthetic', 'Aosp')][string]$Variant,
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$BeforeBootName = 'strict-v17-direct-before-boot',
    [string]$TrialName = 'strict-v17-tricky-direct',
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
$aosp = Get-Content (Join-Path $CacheRoot 'candidate-direct\manifest.json') -Raw | ConvertFrom-Json
$synthetic = Get-Content (Join-Path $CacheRoot 'candidate-lab-ca\manifest.json') -Raw | ConvertFrom-Json
$aospHash = $aosp.files.'keybox.xml'
$syntheticHash = $synthetic.keybox_sha256
$expectedBefore = if ($Variant -eq 'Synthetic') { $aospHash } else { $syntheticHash }
$expectedAfter = if ($Variant -eq 'Synthetic') { $syntheticHash } else { $aospHash }
$source = if ($Variant -eq 'Synthetic') { Join-Path $CacheRoot 'candidate-lab-ca\keybox.xml' } else { Join-Path $CacheRoot 'candidate-direct\keybox.xml' }
if ((Get-FileHash $source).Hash.ToLowerInvariant() -ne $expectedAfter) { throw 'Candidate keybox hash mismatch.' }
$baseline = Get-Content "$PSScriptRoot\..\reports\$BeforeBootName.json" -Raw | ConvertFrom-Json
$trial = Get-Content "$PSScriptRoot\..\reports\$TrialName.json" -Raw | ConvertFrom-Json
if ($trial.launch -notmatch '^Independent platform worker: (\d+)$') { throw 'The pinned candidate worker is unknown.' }
$expectedController = $Matches[1]
$remote = '/data/misc/tricky_lab1'
function Read-Adb([string[]]$Arguments) {
    $value = & $adb -s emulator-5556 @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Sandbox control unavailable: $($Arguments -join ' ')" }
    return ($value -join "`n").Trim()
}
& $adb -s emulator-5556 root | Out-Null
& $adb -s emulator-5556 wait-for-device
try {
    $bootId = Read-Adb @('shell','cat','/proc/sys/kernel/random/boot_id')
    if ($bootId -ne $baseline.boot_id) { throw 'The baseline boot changed.' }
    $keystore = Read-Adb @('shell','pidof','keystore2')
    $controller = Read-Adb @('shell','pidof','DeviceLabAttestationCandidate')
    if ($keystore -ne [string]$trial.keystore_after -or $controller -ne $expectedController) { throw 'The running candidate changed.' }
    $policy = (Read-Adb @('shell','sha256sum','/sys/fs/selinux/policy')).Split(' ')[0]
    if ($policy -ne $baseline.loaded_selinux_policy_sha256 -or (Read-Adb @('shell','getenforce')) -ne 'Enforcing') {
        throw 'SELinux is not at the stock enforced baseline.'
    }
    $before = (Read-Adb @('shell','sha256sum',"$remote/keybox.xml")).Split(' ')[0]
    if ($before -ne $expectedBefore) { throw 'Unexpected keybox before the switch.' }
    if ($Variant -eq 'Synthetic') {
        Read-Adb @('shell',"cp -p $remote/keybox.xml $remote/keybox-aosp-preserved.xml") | Out-Null
    }
    & $adb -s emulator-5556 push $source "$remote/keybox.next.xml" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Keybox transfer failed.' }
    Read-Adb @('shell',"chown 0:0 $remote/keybox.next.xml; chmod 0600 $remote/keybox.next.xml; chcon u:object_r:system_file:s0 $remote/keybox.next.xml; mv -f $remote/keybox.next.xml $remote/keybox.xml") | Out-Null
    Start-Sleep -Seconds 3
    $after = (Read-Adb @('shell','sha256sum',"$remote/keybox.xml")).Split(' ')[0]
    if ($after -ne $expectedAfter) { throw 'Keybox switch did not persist.' }
    if ((Read-Adb @('shell','pidof','keystore2')) -ne $keystore -or
        (Read-Adb @('shell','pidof','DeviceLabAttestationCandidate')) -ne $controller) {
        throw 'The candidate restarted after the keybox switch.'
    }
    $afterPolicy = (Read-Adb @('shell','sha256sum','/sys/fs/selinux/policy')).Split(' ')[0]
    if ($afterPolicy -ne $policy) { throw 'The loaded SELinux policy changed.' }
    $logcat = Read-Adb @('logcat','-d','-s','TrickyStoreOSS:V','*:S')
    $report = [ordered]@{
        captured_at = [DateTimeOffset]::UtcNow.ToString('o')
        boot_id = $bootId
        variant = $Variant.ToLowerInvariant()
        keybox_sha256_before = $before
        keybox_sha256_after = $after
        keystore_pid_unchanged = $true
        controller_pid_unchanged = $true
        loaded_selinux_policy_sha256 = $afterPolicy
        enforcing = $true
        manufacturer_trust_supplied = $false
        logcat = "$Name-logcat.txt"
    }
    $report | ConvertTo-Json -Depth 4 | Set-Content "$PSScriptRoot\..\reports\$Name.json" -Encoding utf8
    $logcat | Set-Content "$PSScriptRoot\..\reports\$Name-logcat.txt" -Encoding utf8
    $report | ConvertTo-Json -Depth 4
} finally {
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device
}

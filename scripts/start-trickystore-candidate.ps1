param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$BeforeBootName = 'strict-v17-before-boot',
    [ValidateSet('candidate-aosp', 'candidate-direct', 'candidate-mgf', 'candidate-mgf-private', 'candidate-mgf-aes', 'candidate-mgf-aes-origin', 'candidate-mgf-aes-aad', 'candidate-mgf-aes-aad-forward')][string]$CandidateDirectory = 'candidate-aosp',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\research-v17"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$registered = (Get-Content "$env:USERPROFILE\.android\avd\device-lab-numa.ini" | Where-Object { $_ -match '^path=' }) -replace '^path=', ''
$expected = [IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))
if ([IO.Path]::GetFullPath($registered) -ne $expected) { throw 'Use the independent attestation sandbox.' }
if (@(& $adb -s emulator-5556 emu avd name)[0].Trim() -ne 'device-lab-numa') { throw 'Wrong emulator.' }
$before = Get-Content "$PSScriptRoot\..\reports\$BeforeBootName.json" -Raw | ConvertFrom-Json
$candidate = Join-Path $CacheRoot $CandidateDirectory
$manifest = Get-Content (Join-Path $candidate 'manifest.json') -Raw | ConvertFrom-Json
$remote = '/data/misc/device-lab/bootstrap/tricky-candidate'
$direct = $manifest.transport -eq 'target-open'
$publicDirectory = '/dev/device-lab-attestation'
$publicLibrary = "$publicDirectory/libTrickyStoreOSS.so"
if ($CandidateDirectory -in @('candidate-direct', 'candidate-mgf', 'candidate-mgf-private', 'candidate-mgf-aes', 'candidate-mgf-aes-origin', 'candidate-mgf-aes-aad', 'candidate-mgf-aes-aad-forward') -and -not $direct) { throw 'The direct candidate manifest is missing its transport declaration.' }
function Read-Adb([string[]]$Arguments) {
    $value = & $adb -s emulator-5556 @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Candidate control unavailable: $($Arguments -join ' ')" }
    return ($value -join "`n").Trim()
}
& $adb -s emulator-5556 root | Out-Null
& $adb -s emulator-5556 wait-for-device
try {
    $bootId = Read-Adb @('shell','cat','/proc/sys/kernel/random/boot_id')
    if ($bootId -ne $before.boot_id) { throw 'Collect a baseline for this boot first.' }
    $keystoreBefore = Read-Adb @('shell','pidof','keystore2')
    if ($keystoreBefore -notmatch '^\d+$') { throw 'Expected one Keystore process.' }
    $mapsBefore = Read-Adb @('shell','cat',"/proc/$keystoreBefore/maps")
    if ($mapsBefore -match 'libTrickyStoreOSS') { throw 'The candidate is already loaded.' }
    if ((Read-Adb @('shell','getenforce')) -ne 'Enforcing') { throw 'SELinux must remain enforcing.' }
    Read-Adb @('shell',"mkdir -p $remote /data/misc/tricky_lab1 /data/misc/device-lab/bootstrap/workers; chmod 0700 $remote /data/misc/tricky_lab1") | Out-Null
    if ($direct) { Read-Adb @('shell',"mkdir -p $publicDirectory; chmod 0755 $publicDirectory") | Out-Null }
    $libraryDestination = if ($direct) { $publicLibrary } else { "$remote/libTrickyStoreOSS.so" }
    foreach ($pair in @(@('classes.dex',"$remote/classes.dex"),@('inject',"$remote/inject"),@('libTrickyStoreOSS.so',$libraryDestination),@('keybox.xml','/data/misc/tricky_lab1/keybox.xml'),@('target.txt','/data/misc/tricky_lab1/target.txt'))) {
        $local = Join-Path $candidate $pair[0]
        if ((Get-FileHash $local).Hash.ToLowerInvariant() -ne $manifest.files.($pair[0])) { throw 'Staged candidate hash mismatch.' }
        & $adb -s emulator-5556 push $local $pair[1] | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Candidate transfer failed.' }
    }
    & $adb -s emulator-5556 push "$PSScriptRoot\run-trickystore-candidate.sh" /data/misc/device-lab/bootstrap/workers/tricky-candidate.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Worker transfer failed.' }
    & $adb -s emulator-5556 push "$PSScriptRoot\run-platform-worker.sh" /data/misc/device-lab/bootstrap/run-worker.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Worker launcher transfer failed.' }
    Read-Adb @('shell',"chmod 0444 $remote/classes.dex; chmod 0700 $remote/inject /data/misc/device-lab/bootstrap/workers/tricky-candidate.sh; chmod 0600 /data/misc/tricky_lab1/keybox.xml /data/misc/tricky_lab1/target.txt; chcon -R u:object_r:system_file:s0 $remote /data/misc/tricky_lab1 /data/misc/device-lab/bootstrap/workers") | Out-Null
    if ($direct) {
        Read-Adb @('shell',"rm -f $remote/libTrickyStoreOSS.so; chmod 0444 $publicLibrary; chcon u:object_r:system_file:s0 $publicDirectory; chcon u:object_r:system_lib_file:s0 $publicLibrary; ln -s $publicLibrary $remote/libTrickyStoreOSS.so") | Out-Null
        $label = Read-Adb @('shell','ls','-Zd',$publicDirectory,$publicLibrary)
        if ($label -notmatch 'u:object_r:system_lib_file:s0') { throw 'The public library label was not applied.' }
    } else {
        Read-Adb @('shell',"chmod 0444 $remote/libTrickyStoreOSS.so") | Out-Null
    }
    $startedAt = [DateTimeOffset]::UtcNow
    $launch = Read-Adb @('shell','sh','/data/misc/device-lab/bootstrap/run-worker.sh','/data/misc/device-lab/bootstrap/workers/tricky-candidate.sh','/data/misc/device-lab/bootstrap/tricky-candidate.log')
    Start-Sleep -Seconds 8
    $log = Read-Adb @('shell','cat','/data/misc/device-lab/bootstrap/tricky-candidate.log')
    $logcat = Read-Adb @('logcat','-d','-s','TrickyStoreOSS:V','*:S')
    $keystoreAfter = Read-Adb @('shell','pidof','keystore2')
    $mapsAfter = Read-Adb @('shell','cat',"/proc/$keystoreAfter/maps")
    $policyHash = (Read-Adb @('shell','sha256sum','/sys/fs/selinux/policy')).Split(' ')[0]
    if ($policyHash -ne $before.loaded_selinux_policy_sha256) { throw 'The loaded policy changed.' }
    $report = [ordered]@{
        started_at = $startedAt.ToString('o')
        captured_at = [DateTimeOffset]::UtcNow.ToString('o')
        boot_id = $bootId
        launch = $launch
        repository_revision = $manifest.revision
        candidate_directory = $CandidateDirectory
        transport = if ($direct) { 'target-open' } else { 'fd-transfer' }
        keystore_before = [int]$keystoreBefore
        keystore_after = [int]$keystoreAfter
        keystore_restarted = $keystoreBefore -ne $keystoreAfter
        candidate_library_loaded = $mapsAfter -match 'libTrickyStoreOSS'
        interceptors_initialized = $logcat -match 'Interceptors initialized successfully'
        policy_unchanged = $true
        loaded_selinux_policy_sha256 = $policyHash
        enforcing = Read-Adb @('shell','getenforce')
        hardware_trust_supplied = $false
        log = "$Name.log"
        logcat = "$Name-logcat.txt"
    }
    $log | Set-Content "$PSScriptRoot\..\reports\$Name.log" -Encoding utf8
    $logcat | Set-Content "$PSScriptRoot\..\reports\$Name-logcat.txt" -Encoding utf8
    $report | ConvertTo-Json -Depth 5 | Set-Content "$PSScriptRoot\..\reports\$Name.json" -Encoding utf8
    $report | ConvertTo-Json -Depth 3
} finally {
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device
}

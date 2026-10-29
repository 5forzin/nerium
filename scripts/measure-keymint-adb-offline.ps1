#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Name)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$serial = 'emulator-5586'
$adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$project = Split-Path $PSScriptRoot -Parent
$reports = Join-Path $project 'reports'
$destination = Join-Path $reports "$Name-state"
if (Test-Path -LiteralPath $destination) { throw 'Measurement name already used.' }
function Device([string[]]$Arguments) {
    $value = (& $adb -s $serial @Arguments) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "Device command failed: $($Arguments[0])" }
    $value.Trim()
}
$identity = @((Device @('emu','avd','name')) -split '\r?\n' | Where-Object { $_ })
if ($identity.Count -ne 2 -or $identity[0] -cne 'device-lab-keymint-v42' -or $identity[1] -cne 'OK') { throw 'The isolated AVD identity differs.' }
$originalRoot = Device @('shell','getprop','service.adb.root')
if ($originalRoot -notin @('0','1')) { throw 'The current debugging root request is unavailable.' }
$expectedBootId = Device @('shell','cat','/proc/sys/kernel/random/boot_id')
$runId = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()
$cache = Join-Path $env:LOCALAPPDATA "android-device-lab\research-v43\measurement-$runId"
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$request = Join-Path $cache 'request.txt'
[IO.File]::WriteAllText($request, "$runId`n$originalRoot`n", [Text.UTF8Encoding]::new($false))
$remoteWorker = '/data/misc/device-lab/bootstrap/workers/offline.sh'
$remoteLauncher = '/data/misc/device-lab/bootstrap/run-worker.sh'
$remoteStage = "/data/misc/device-lab/bootstrap/workers/measurement-$runId.staging"
$remoteDirectory = "/data/misc/device-lab/offline-v43/measure-$runId"
$remoteStatus = "/data/local/tmp/device-lab-offline-$runId.status"
$remoteExport = "/sdcard/Download/keymint-v43-offline-$runId.txt"
$backup = Join-Path $cache 'original-offline.sh'
$pendingStatus = Join-Path $cache 'pending-status.json'
[IO.File]::WriteAllText($pendingStatus, (@{run_id=$runId;role='pending'}|ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
Device @('push',$pendingStatus,$remoteStatus) | Out-Null
Device @('shell','chmod','0644',$remoteStatus) | Out-Null
if (((Device @('shell','cat',$remoteStatus))|ConvertFrom-Json).role -cne 'pending') { throw 'The recovery notification is not readable by the original transport user.' }
$beforeMetadata = [ordered]@{}
foreach ($entry in @(@('arm54','dev.androidlab.probe'),@('raw79','dev.androidlab.rawprobe'),@('proc99','dev.androidlab.procprobe'),@('reveny','com.reveny.emulator.detection.sample'),@('duck','com.eltavine.duckdetector'))) {
    $path = (Device @('shell','pm','path',$entry[1])) -replace '^package:', ''
    if ($path -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') { throw 'Expected one installed APK.' }
    $hash = ((Device @('shell','sha256sum',$path)) -split '\s+')[0]
    $state = Device @('shell','dumpsys','package',$entry[1])
    if ($state -notmatch 'primaryCpuAbi=([\w-]+)') { throw 'APK ABI is unavailable.' }
    $beforeMetadata[$entry[0]] = @{package=$entry[1];path=$path;sha256=$hash;abi=$Matches[1]}
}
if ($beforeMetadata.reveny.sha256 -cne '9f064f3968e9a224612810ec2b6078872f479930ce4dd0fc1f7132b08c6b3f5b' -or
    $beforeMetadata.reveny.abi -cne 'x86_64' -or
    $beforeMetadata.duck.sha256 -cne '9d0bbdab9c0b14334c9ec0d319758c5f9085260a09388486482b2ac497c81ffc' -or
    $beforeMetadata.duck.abi -cne 'x86_64') { throw 'An independent detector differs from its frozen release.' }
$staged = $false
$launched = $false
$controllerFinished = $false
$measurementStatus = $null
$hostObservations = @()
Device @('root') | Out-Null
Device @('wait-for-device') | Out-Null
try {
    if ((Device @('shell','id','-Z')) -cne 'u:r:su:s0') { throw 'Unexpected root control context.' }
    $beforeHash = ((Device @('shell','sha256sum',$remoteWorker)) -split '\s+')[0]
    $beforeLabel = Device @('shell','ls','-Z',$remoteWorker)
    $beforeInode = Device @('shell','stat','-c','%i',$remoteWorker)
    Device @('pull',$remoteWorker,$backup) | Out-Null
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant() -cne $beforeHash) { throw 'Worker backup differs.' }
    Device @('push',(Join-Path $PSScriptRoot 'measure-keymint-adb-offline.sh'),$remoteStage) | Out-Null
    Device @('shell',"cat $remoteStage > $remoteWorker") | Out-Null
    $staged = $true
    Device @('push',$request,'/data/misc/device-lab/adb-offline-request') | Out-Null
    Device @('shell','chmod','0600','/data/misc/device-lab/adb-offline-request') | Out-Null
    Device @('shell','sh','-n',$remoteWorker) | Out-Null
    if ((Device @('shell','ls','-Z',$remoteWorker)) -cne $beforeLabel -or
        (Device @('shell','stat','-c','%i',$remoteWorker)) -cne $beforeInode) { throw 'Worker metadata changed.' }
    $workerHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'measure-keymint-adb-offline.sh') -Algorithm SHA256).Hash.ToLowerInvariant()
    if (((Device @('shell','sha256sum',$remoteWorker)) -split '\s+')[0] -cne $workerHash) { throw 'The staged worker differs.' }
    $launched = $true
    $launch = Device @('shell','sh',$remoteLauncher,$remoteWorker,"/data/misc/device-lab/bootstrap/measurement-$runId.log")
    if ($launch -notmatch '^Independent platform worker: ([0-9]+)$') { throw 'No controller PID.' }
    $workerPid = [int]$Matches[1]
    $armed = $false
    for ($attempt=0; $attempt -lt 120; $attempt++) {
        & $adb -s $serial shell test -f "$remoteDirectory/armed" 2>$null
        if ($LASTEXITCODE -eq 0) { $armed=$true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $armed) { throw 'The recovery watchdog was not armed.' }
    $watchdogPid = [int](Device @('shell','cat',"$remoteDirectory/watchdog.pid"))
    foreach ($processId in @($workerPid,$watchdogPid)) {
        Device @('shell','kill','-0',[string]$processId) | Out-Null
        if ((Device @('shell','cat',"/proc/$processId/cgroup")) -notmatch '(?m)^0::/device-lab-platform$') { throw 'Recovery process did not escape the debugging cgroup.' }
    }
    Device @('shell',"printf '%s' '$runId' > $remoteDirectory/control.go") | Out-Null
    Write-Output "Armed controller $workerPid and independent watchdog $watchdogPid; waiting for genuine ADB shutdown."
    $seenOffline = $false
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(400)
    $lastState = ''
    do {
        $state = ((& $adb -s $serial get-state 2>$null) -join '').Trim()
        $hostObservations += @{time=[DateTimeOffset]::UtcNow.ToString('o');state=$state}
        if ($state -ne 'device') { $seenOffline=$true }
        if ($state -cne $lastState) { Write-Output "Selected transport state: $state"; $lastState=$state }
        if ($state -eq 'device') {
            $raw = & $adb -s $serial shell cat $remoteStatus 2>$null
            if ($LASTEXITCODE -eq 0) {
                try {
                    $candidate = ($raw -join "`n") | ConvertFrom-Json
                    if ($candidate.run_id -ceq $runId -and $candidate.role -in @('worker','watchdog') -and
                        ($seenOffline -or $candidate.exit_code -ne 0 -or -not $candidate.measurement_complete)) { $measurementStatus=$candidate; break }
                } catch { }
            }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -eq $measurementStatus) { throw 'No authoritative recovery status; do not restart the experiment automatically.' }
    Device @('root') | Out-Null
    Device @('wait-for-device') | Out-Null
    $watchdogExited = $false
    for ($attempt=0; $attempt -lt 20; $attempt++) {
        & $adb -s $serial shell test -f "$remoteDirectory/watchdog.finished" 2>$null
        if ($LASTEXITCODE -eq 0) {
            & $adb -s $serial shell kill -0 $watchdogPid 2>$null
            if ($LASTEXITCODE -ne 0) { $watchdogExited=$true; break }
        }
        Start-Sleep -Milliseconds 250
    }
    $otherProcessesExited = $false
    if ($watchdogExited) {
        $tracked = @($workerPid)
        $samplerRaw = & $adb -s $serial shell cat "$remoteDirectory/sampler.pid" 2>$null
        if ($LASTEXITCODE -eq 0 -and ($samplerRaw -join '').Trim() -match '^[0-9]+$') { $tracked += [int](($samplerRaw -join '').Trim()) }
        for ($attempt=0; $attempt -lt 30; $attempt++) {
            $live = 0
            foreach ($processId in $tracked) {
                & $adb -s $serial shell kill -0 $processId 2>$null
                if ($LASTEXITCODE -eq 0) { $live++ }
            }
            if ($live -eq 0) { $otherProcessesExited=$true; break }
            Start-Sleep -Seconds 1
        }
    }
    $controllerFinished = $watchdogExited -and $otherProcessesExited
    if (-not $controllerFinished) { throw 'The recovery watchdog is still live; retain its source file.' }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Device @('pull',$remoteDirectory,$destination) | Out-Null
    Device @('pull',"/data/misc/device-lab/bootstrap/measurement-$runId.log",(Join-Path $destination 'controller.log')) | Out-Null
    $local = Join-Path $destination "measure-$runId"
    $hostState = @{schema_version=1;run_id=$runId;worker_sha256=$workerHash;status=$measurementStatus;host_transport_observations=$hostObservations;frozen_apks=$beforeMetadata}
    [IO.File]::WriteAllText((Join-Path $destination 'host.json'),($hostState|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    if ($measurementStatus.role -ne 'worker' -or $measurementStatus.exit_code -ne 0 -or -not $measurementStatus.measurement_complete) { throw "The offline worker failed; evidence retained at $destination." }
    foreach ($invalid in @('recovery.started','watchdog.recovered','failed','restore.failed')) {
        if (Test-Path -LiteralPath (Join-Path $local $invalid)) { throw "The offline run has an invalidating marker: $invalid" }
    }
    $offlineEnd = Get-Content -Raw -LiteralPath (Join-Path $local 'offline-complete.json') | ConvertFrom-Json
    $offlineStart = Get-Content -Raw -LiteralPath (Join-Path $local 'offline.json') | ConvertFrom-Json
    if ((Get-Content -Raw -LiteralPath (Join-Path $local 'boot-id.txt')).Trim() -cne $expectedBootId -or
        (Device @('shell','cat','/proc/sys/kernel/random/boot_id')) -cne $expectedBootId) { throw 'The guest restarted during measurement.' }
    if ($offlineEnd.adbd -ne 'stopped' -or $offlineEnd.adbd_pid -ne '' -or $offlineEnd.root_request -ne '0') { throw 'The scan ended after debugging returned.' }
    $policyBefore = (Get-Content -Raw -LiteralPath (Join-Path $local 'policy-before.txt')).Trim()
    $policyAfter = (Get-Content -Raw -LiteralPath (Join-Path $local 'policy-after.txt')).Trim()
    if ($policyBefore -cne $policyAfter -or $policyBefore -notmatch '^725322b8bb21c399e222db65bd9e0ee307a3b603d19d9a3d5f47a93cc8f369c0\s' -or
        (Device @('shell','getenforce')) -cne 'Enforcing') { throw 'SELinux invariants changed.' }
    foreach ($metadata in $beforeMetadata.Values) {
        if (((Device @('shell','sha256sum',$metadata.path)) -split '\s+')[0] -cne $metadata.sha256) { throw 'A measured APK changed.' }
    }
    $samples = @(Get-Content -LiteralPath (Join-Path $local 'samples.jsonl')|ForEach-Object {$_|ConvertFrom-Json})
    if ($samples.Count -lt 5 -or @($samples|Where-Object {$_.adbd -ne 'stopped' -or $_.adbd_pid -ne '' -or $_.root_request -ne '0' -or $_.adb_enabled -ne '0' -or $_.adb_wifi_enabled -notin @('0','null') -or $_.usb_state -match 'adb'}).Count) { throw 'The trace does not prove an inactive debugging window.' }
    foreach ($label in @('arm54','raw79','proc99')) {
        $probe = Get-Content -Raw -LiteralPath (Join-Path $local "$label.json") | ConvertFrom-Json
        $metadata = $beforeMetadata[$label]
        $expectedTotals = @{arm54=54;raw79=79;proc99=99}
        $baseline = Get-Content -Raw -LiteralPath (Join-Path $reports "keymint-v43-before-$label.json") | ConvertFrom-Json
        if ($probe.schema_version -ne 1 -or $probe.summary.total -ne $expectedTotals[$label] -or
            $probe.checks.Count -ne $expectedTotals[$label] -or $probe.summary.detected -ne 0 -or
            $probe.summary.unavailable -ne 0 -or ($probe.checks.id -join "`n") -cne ($baseline.checks.id -join "`n") -or
            $metadata.sha256 -cne $baseline.apk_sha256 -or $metadata.abi -cne $baseline.installed_abi) { throw 'An offline core suite regressed or changed coverage.' }
        if (((Device @('shell','sha256sum',$metadata.path)) -split '\s+')[0] -cne $metadata.sha256) { throw 'A measured APK changed.' }
        $probe | Add-Member -NotePropertyName apk_sha256 -NotePropertyValue $metadata.sha256
        $probe | Add-Member -NotePropertyName installed_abi -NotePropertyValue $metadata.abi
        $probe | Add-Member -NotePropertyName measurement_run_id -NotePropertyValue $runId
        [IO.File]::WriteAllText((Join-Path $reports "$Name-$label.json"),($probe|ConvertTo-Json -Depth 14),[Text.UTF8Encoding]::new($false))
    }
    [xml]$revenyUi = Get-Content -Raw -LiteralPath (Join-Path $local 'reveny.xml')
    $texts = @($revenyUi.SelectNodes('//*[@text]')|ForEach-Object {$_.GetAttribute('text')})
    if ($texts -notcontains 'Nothing detected!') { throw 'The offline Reveny UI did not report a clear result.' }
    $reveny = @{captured_at=[DateTimeOffset]::UtcNow.ToString('o');package=$beforeMetadata.reveny.package;apk_sha256=$beforeMetadata.reveny.sha256;detected=$false;finding_count=0;findings=@();ui_result='Nothing detected!';measurement_run_id=$runId;source='Fresh offline UI from the unchanged APK'}
    [IO.File]::WriteAllText((Join-Path $reports "$Name-reveny.json"),($reveny|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    $detectorPid = (Get-Content -Raw -LiteralPath (Join-Path $local 'duck.pid')).Trim()
    if ((Device @('shell','pidof','com.eltavine.duckdetector')) -cne $detectorPid) { throw 'Duck changed process after the offline scan.' }
    & (Join-Path $PSScriptRoot 'capture-external.ps1') -Name "$Name-duck-complete" -Serial $serial -Detector duck -CurrentProcessId ([int]$detectorPid) -ExportedReport $remoteExport
    if (-not $?) { throw 'The built-in offline Duck export was not accepted.' }
    $duckReport = Get-Content -Raw -LiteralPath (Join-Path $reports "$Name-duck-complete.json") | ConvertFrom-Json
    if ($duckReport.status -ne 'complete' -or $duckReport.duck.scan_statistics.Pending -ne 0 -or
        [long]$duckReport.duck.exported_report_mtime -lt [long]$offlineStart.time_s -or
        [long]$duckReport.duck.exported_report_mtime -gt [long]$offlineEnd.time_s) { throw 'Duck export was not completed inside the inactive-debugging window.' }
    Write-Output "Offline measurement collected: $Name."
} finally {
    if ($staged -and ($controllerFinished -or -not $launched)) {
        Device @('push',$backup,$remoteStage) | Out-Null
        Device @('shell',"cat $remoteStage > $remoteWorker") | Out-Null
        if (((Device @('shell','sha256sum',$remoteWorker)) -split '\s+')[0] -cne $beforeHash -or
            (Device @('shell','ls','-Z',$remoteWorker)) -cne $beforeLabel -or
            (Device @('shell','stat','-c','%i',$remoteWorker)) -cne $beforeInode) { throw 'Original worker restoration failed.' }
    }
    if ($controllerFinished -or -not $launched) {
        $rootCommand = if ($originalRoot -eq '0') { 'unroot' } else { 'root' }
        Device @($rootCommand) | Out-Null
        Device @('wait-for-device') | Out-Null
    }
}

#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Name)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$serial = 'emulator-5586'
$project = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $project "reports\$Name.json"
if (Test-Path -LiteralPath $destination) { throw 'The requested report already exists.' }
function Device([string[]]$Arguments) {
    $value = (& $adb -s $serial @Arguments) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "Device command failed: $($Arguments[0])" }
    $value.Trim()
}
$avd = @((Device @('emu','avd','name')) -split '\r?\n' | Where-Object { $_ })
if ($avd.Count -ne 2 -or $avd[0] -cne 'device-lab-keymint-v42' -or $avd[1] -cne 'OK') { throw 'The isolated AVD differs.' }
$runId = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()
$cache = Join-Path $env:LOCALAPPDATA "android-device-lab\research-v43\controller-$runId"
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$request = Join-Path $cache 'request.txt'
[IO.File]::WriteAllText($request, "$runId`n", [Text.UTF8Encoding]::new($false))
$remoteWorker = '/data/misc/device-lab/bootstrap/workers/offline.sh'
$remoteLauncher = '/data/misc/device-lab/bootstrap/run-worker.sh'
$remoteLog = "/data/misc/device-lab/bootstrap/controller-$runId.log"
$remoteStage = "/data/misc/device-lab/bootstrap/workers/control-$runId.staging"
$remoteResult = "/data/misc/device-lab/offline-v43/probe-$runId"
$backup = Join-Path $cache 'original-offline.sh'
$staged = $false
$workerPid = $null
$workerDone = $false
Device @('root') | Out-Null
Device @('wait-for-device') | Out-Null
try {
    if ((Device @('shell','id','-Z')) -cne 'u:r:su:s0') { throw 'The existing root control context differs.' }
    $beforeHash = ((Device @('shell','sha256sum',$remoteWorker)) -split '\s+')[0]
    $beforeLabel = Device @('shell','ls','-Z',$remoteWorker)
    $beforeInode = Device @('shell','stat','-c','%i',$remoteWorker)
    Device @('pull',$remoteWorker,$backup) | Out-Null
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant() -cne $beforeHash) { throw 'The worker backup differs.' }
    Device @('push',(Join-Path $PSScriptRoot 'adb-offline-control-probe.sh'),$remoteStage) | Out-Null
    Device @('shell',"cat $remoteStage > $remoteWorker") | Out-Null
    $staged = $true
    Device @('push',$request,'/data/misc/device-lab/adb-control-probe-request') | Out-Null
    Device @('shell','chmod','0600','/data/misc/device-lab/adb-control-probe-request') | Out-Null
    Device @('shell','chmod','0700',$remoteWorker) | Out-Null
    Device @('shell','sh','-n',$remoteWorker) | Out-Null
    $localHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'adb-offline-control-probe.sh') -Algorithm SHA256).Hash.ToLowerInvariant()
    if (((Device @('shell','sha256sum',$remoteWorker)) -split '\s+')[0] -cne $localHash) { throw 'The staged controller differs.' }
    if ((Device @('shell','ls','-Z',$remoteWorker)) -cne $beforeLabel) { throw 'The existing worker label changed.' }
    if ((Device @('shell','stat','-c','%i',$remoteWorker)) -cne $beforeInode) { throw 'The existing worker inode changed.' }
    $launch = Device @('shell','sh',$remoteLauncher,$remoteWorker,$remoteLog)
    if ($launch -notmatch '^Independent platform worker: ([0-9]+)$') { throw 'The controller PID is unavailable.' }
    $workerPid = [int]$Matches[1]
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        & $adb -s $serial shell test -s "$remoteResult/done" 2>$null
        if ($LASTEXITCODE -eq 0) { $workerDone = $true; break }
        & $adb -s $serial shell kill -0 $workerPid 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'The controller exited before producing its evidence.' }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $workerDone) { throw 'The live controller did not finish within the observation window.' }
    $worker = (Device @('exec-out','cat',"$remoteResult/worker.json")) | ConvertFrom-Json
    $watchdog = (Device @('exec-out','cat',"$remoteResult/watchdog.json")) | ConvertFrom-Json
    if ($worker.run_id -cne $runId -or $watchdog.run_id -cne $runId -or
        -not $worker.cgroup_verified -or -not $watchdog.cgroup_verified -or
        $worker.session -ne $worker.pid -or $watchdog.session -ne $watchdog.pid -or
        $worker.process_group -eq $worker.adbd_group -or $worker.services_changed -or
        $watchdog.services_changed -or $watchdog.adbd_before -cne $watchdog.adbd_after -or
        $watchdog.mdns_before -cne $watchdog.mdns_after -or
        $worker.policy_sha256 -cne '725322b8bb21c399e222db65bd9e0ee307a3b603d19d9a3d5f47a93cc8f369c0') { throw 'Autonomous control invariants failed.' }
    $report = @{schema_version=1; recorded_at=[DateTimeOffset]::UtcNow.ToString('o'); status='passed_control_preflight'; worker=$worker; watchdog=$watchdog; controller_sha256=$localHash; debugging_services_changed=$false; selinux_changed=$false}
    [IO.File]::WriteAllText($destination, ($report | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Write-Output $destination
} finally {
    if ($staged) {
        $alive = $false
        if ($null -ne $workerPid -and -not $workerDone) {
            & $adb -s $serial shell kill -0 $workerPid 2>$null
            $alive = $LASTEXITCODE -eq 0
        }
        if (-not $alive) {
            Device @('push',$backup,$remoteStage) | Out-Null
            Device @('shell',"cat $remoteStage > $remoteWorker") | Out-Null
            Device @('shell','chmod','0700',$remoteWorker) | Out-Null
            if (((Device @('shell','sha256sum',$remoteWorker)) -split '\s+')[0] -cne $beforeHash) { throw 'The original worker was not restored.' }
            if ((Device @('shell','ls','-Z',$remoteWorker)) -cne $beforeLabel -or
                (Device @('shell','stat','-c','%i',$remoteWorker)) -cne $beforeInode) { throw 'The restored worker metadata changed.' }
        }
    }
    Device @('unroot') | Out-Null
    Device @('wait-for-device') | Out-Null
}

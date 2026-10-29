param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5556',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple measurement name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$avdName = @(& $adb -s $Serial emu avd name)[0].Trim()
if ($avdName -ne 'device-lab-numa') { throw 'This measurement is restricted to the dedicated NUMA AVD.' }
& $adb -s $Serial root
& $adb -s $Serial wait-for-device
& $adb -s $Serial shell 'rm -f /data/misc/device-lab/offline-v12/done /data/misc/device-lab/offline-v12/failed'
& $adb -s $Serial shell test -f /data/misc/device-lab/platform-bootstrap-enabled
if ($LASTEXITCODE -eq 0) {
    & $adb -s $Serial shell 'mkdir -p /data/misc/device-lab/bootstrap/workers; chmod 0700 /data/misc/device-lab/bootstrap/workers'
    & $adb -s $Serial push "$PSScriptRoot\measure-adb-offline.sh" /data/misc/device-lab/bootstrap/workers/offline.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the platform offline worker.' }
    & $adb -s $Serial push "$PSScriptRoot\run-platform-worker.sh" /data/misc/device-lab/bootstrap/run-worker.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the platform worker launcher.' }
    & $adb -s $Serial shell 'chmod 0700 /data/misc/device-lab/bootstrap/run-worker.sh /data/misc/device-lab/bootstrap/workers/offline.sh; chown 0:0 /data/misc/device-lab/bootstrap/workers/offline.sh; chcon -R u:object_r:system_file:s0 /data/misc/device-lab/bootstrap/workers; sh /data/misc/device-lab/bootstrap/run-worker.sh /data/misc/device-lab/bootstrap/workers/offline.sh /data/misc/device-lab/bootstrap/offline.log'
} else {
    & $adb -s $Serial push "$PSScriptRoot\measure-adb-offline.sh" /data/local/tmp/device-lab-offline.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the offline measurement helper.' }
    & $adb -s $Serial shell 'su -Z u:r:su:s0 -c ''nohup setsid sh /data/local/tmp/device-lab-offline.sh > /data/local/tmp/device-lab-offline.log 2>&1 < /dev/null &'''
}
if ($LASTEXITCODE -ne 0) { throw 'Could not launch the independent root worker.' }
Start-Sleep -Seconds 15
$complete = $false
for ($attempt = 0; $attempt -lt 72; $attempt++) {
    Start-Sleep -Seconds 5
    $state = (& $adb -s $Serial get-state 2>$null) -join ''
    if ($state -ne 'device') { continue }
    & $adb -s $Serial root 2>$null | Out-Null
    & $adb -s $Serial shell test -f /data/misc/device-lab/offline-v12/done 2>$null
    if ($LASTEXITCODE -eq 0) { $complete = $true; break }
}
if (-not $complete) { throw 'Offline measurement did not reconnect within its recovery deadline.' }
$destination = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\reports\$Name-state"))
New-Item -ItemType Directory -Path $destination -Force | Out-Null
foreach ($file in @('before.json','offline.json','restored.json','samples.jsonl','launch.txt','app-pid.txt')) {
    & $adb -s $Serial pull "/data/misc/device-lab/offline-v12/$file" (Join-Path $destination $file) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not collect offline evidence: $file" }
}
& $adb -s $Serial shell test -f /data/misc/device-lab/offline-v12/failed
$failed = $LASTEXITCODE -eq 0
& $adb -s $Serial unroot
& $adb -s $Serial wait-for-device
if ($failed) { throw 'The offline window failed its state controls.' }
$samples = @(Get-Content -LiteralPath (Join-Path $destination 'samples.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
if ($samples.Count -ne 36 -or @($samples | Where-Object { $_.adb_enabled -ne '0' -or $_.adbd -ne 'stopped' -or $_.mdnsd -ne 'stopped' -or $_.adb_root -ne '0' -or $_.adb_secure -ne '1' -or $_.persist_usb -ne 'mtp' -or $_.runtime_usb -ne 'mtp' -or $_.usb_state -ne 'mtp' }).Count) {
    throw 'The offline samples do not prove a complete inactive-ADB window with the actual MTP configuration.'
}
$measuredPid = (Get-Content -LiteralPath (Join-Path $destination 'app-pid.txt') -Raw).Trim()
$currentPid = ((& $adb -s $Serial shell pidof com.eltavine.duckdetector) -join '').Trim()
if ($measuredPid -notmatch '^\d+$' -or $measuredPid -ne $currentPid) { throw 'The offline detector process did not survive until export.' }
& "$PSScriptRoot\export-duck.ps1" -Serial $Serial -SdkRoot $SdkRoot -Name $Name

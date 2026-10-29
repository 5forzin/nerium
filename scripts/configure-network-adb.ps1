param([string]$Serial = 'emulator-5556', [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk", [string]$Name = 'strict-v12-network-adb-state')

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple measurement name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$avdName = @(& $adb -s $Serial emu avd name)[0].Trim()
if ($avdName -ne 'device-lab-numa') { throw 'This configuration is restricted to the dedicated NUMA AVD.' }
& $adb -s $Serial root
& $adb -s $Serial wait-for-device
& $adb -s $Serial shell test -f /data/misc/device-lab/platform-bootstrap-enabled
if ($LASTEXITCODE -eq 0) {
    & $adb -s $Serial shell 'mkdir -p /data/misc/device-lab/bootstrap/workers; chmod 0700 /data/misc/device-lab/bootstrap/workers'
    & $adb -s $Serial push "$PSScriptRoot\configure-network-adb.sh" /data/misc/device-lab/bootstrap/workers/network-adb.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the platform network worker.' }
    & $adb -s $Serial push "$PSScriptRoot\run-platform-worker.sh" /data/misc/device-lab/bootstrap/run-worker.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the platform worker launcher.' }
    & $adb -s $Serial shell 'chmod 0700 /data/misc/device-lab/bootstrap/run-worker.sh /data/misc/device-lab/bootstrap/workers/network-adb.sh; chown 0:0 /data/misc/device-lab/bootstrap/workers/network-adb.sh; chcon -R u:object_r:system_file:s0 /data/misc/device-lab/bootstrap/workers; sh /data/misc/device-lab/bootstrap/run-worker.sh /data/misc/device-lab/bootstrap/workers/network-adb.sh /data/misc/device-lab/bootstrap/network-adb.log'
} else {
    & $adb -s $Serial push "$PSScriptRoot\configure-network-adb.sh" /data/local/tmp/configure-network-adb.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the network ADB helper.' }
    & $adb -s $Serial shell 'su -Z u:r:su:s0 -c ''nohup setsid sh /data/local/tmp/configure-network-adb.sh > /data/local/tmp/configure-network-adb.log 2>&1 < /dev/null &'''
}
if ($LASTEXITCODE -ne 0) { throw 'Could not launch the network ADB worker.' }
Start-Sleep -Seconds 15
$connected = $false
for ($attempt = 0; $attempt -lt 12; $attempt++) {
    if (((& $adb -s $Serial get-state 2>$null) -join '') -eq 'device') { $connected = $true; break }
    Start-Sleep -Seconds 5
}
if (-not $connected) { throw 'Network ADB did not reconnect; the worker will restore its previous configuration.' }
& $adb -s $Serial root | Out-Null
& $adb -s $Serial wait-for-device
$values = @(& $adb -s $Serial shell 'settings get global adb_enabled; getprop persist.sys.usb.config; getprop sys.usb.config; getprop sys.usb.state; getprop init.svc.adbd; getprop ro.adb.secure') | ForEach-Object { $_.Trim() }
if (($values -join '|') -ne '0|mtp|mtp|mtp|running|1') { throw "Network ADB state was not established: $($values -join '|'). The worker will restore its previous configuration." }
& $adb -s $Serial shell 'printf accept > /data/misc/device-lab/network-adb-v12/ack'
if ($LASTEXITCODE -ne 0) { throw 'Could not acknowledge the verified configuration.' }
Start-Sleep -Seconds 6
& $adb -s $Serial shell test -f /data/misc/device-lab/network-adb-v12/committed
if ($LASTEXITCODE -ne 0) { throw 'The network-only configuration was not committed.' }
& $adb -s $Serial pull /data/misc/device-lab/network-adb-v12 "$PSScriptRoot\..\reports\$Name" | Out-Null
& $adb -s $Serial unroot
& $adb -s $Serial wait-for-device
& $adb -s $Serial shell 'id; settings get global adb_enabled; getprop persist.sys.usb.config; getprop sys.usb.state; getprop init.svc.adbd; getprop ro.adb.secure; getprop service.adb.root' |
    Set-Content "$PSScriptRoot\..\reports\$Name\verified.txt" -Encoding utf8

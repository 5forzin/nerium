param([string]$SdkRoot="$env:LOCALAPPDATA\Android\Sdk",[string]$CacheRoot="$env:LOCALAPPDATA\android-device-lab\research-v14")
$ErrorActionPreference='Stop'
$adb=Join-Path $SdkRoot 'platform-tools\adb.exe'
$registered=(Get-Content (Join-Path $env:USERPROFILE '.android\avd\device-lab-numa.ini') | Where-Object {$_ -match '^path='}) -replace '^path=',''
if([IO.Path]::GetFullPath($registered) -ne [IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))){throw 'Restart is restricted to the independent prototype.'}
if(@(& $adb -s emulator-5556 emu avd name)[0].Trim() -ne 'device-lab-numa'){throw 'Wrong emulator.'}
& $adb -s emulator-5556 root | Out-Null
& $adb -s emulator-5556 wait-for-device
try {
    $pidText=((& $adb -s emulator-5556 shell cat /sys/fs/cgroup/device-lab-platform/cgroup.procs) -join ' ').Trim()
    $pids=if($pidText){@($pidText -split '\s+')}else{@()}
    foreach($targetId in $pids){
        if($targetId -notmatch '^\d+$'){throw 'Unexpected platform process identity.'}
        $executable=((& $adb -s emulator-5556 shell readlink "/proc/$targetId/exe") -join '').Trim()
        if($executable -notmatch '^/data/misc/device-lab/bootstrap/bin/zygisk(d|\-ptrace)64( \(deleted\))?$') {throw "Refusing to stop an unrecognized platform process: $targetId"}
    }
    foreach($targetId in $pids){ & $adb -s emulator-5556 shell kill -TERM $targetId }
    Start-Sleep -Seconds 1
    $tracer=((& $adb -s emulator-5556 shell grep TracerPid /proc/1/status) -join '').Trim()
    if($tracer -notmatch 'TracerPid:\s+0$'){throw 'The previous init tracer is still active.'}
    & $adb -s emulator-5556 shell 'rm -f /data/misc/device-lab/bootstrap/monitor.pid /data/misc/device-lab/zygisk/cp64.sock'
    foreach($item in @(@('zygiskd64','bin/zygiskd64'),@('zygisk-ptrace64','bin/zygisk-ptrace64'),@('libzygisk.so','lib64/libzygisk.so'))){
        $local=Join-Path $CacheRoot "build-upstream\$($item[0])"
        $remote="/data/misc/device-lab/bootstrap/$($item[1])"
        & $adb -s emulator-5556 push $local "$remote.new" | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Could not stage a replacement bootstrap artifact.'}
        & $adb -s emulator-5556 shell "chown 0:0 $remote.new; chmod 0700 $remote.new; chcon u:object_r:system_file:s0 $remote.new; mv $remote.new $remote"
        if($LASTEXITCODE -ne 0){throw 'Could not activate a replacement bootstrap artifact.'}
        $hash=((& $adb -s emulator-5556 shell sha256sum $remote) -split '\s+')[0]
        if($hash -ne (Get-FileHash $local).Hash.ToLowerInvariant()){throw 'Replacement hash mismatch.'}
    }
    & $adb -s emulator-5556 push (Join-Path $CacheRoot 'bootstrap-stage\bootstrap.prop') /data/misc/device-lab/bootstrap/module.prop | Out-Null
    & $adb -s emulator-5556 push (Join-Path $PSScriptRoot 'launch-platform-bootstrap.sh') /data/misc/device-lab/bootstrap/launch.sh | Out-Null
    & $adb -s emulator-5556 shell 'chmod 0600 /data/misc/device-lab/bootstrap/module.prop; sh /data/misc/device-lab/bootstrap/launch.sh'
    if($LASTEXITCODE -ne 0){throw 'The replacement platform monitor did not start.'}
    & $adb -s emulator-5556 shell setprop ctl.restart zygote
    if($LASTEXITCODE -ne 0){throw 'Could not restart the prototype zygote.'}
}finally{
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device
}
$ready=$false
for($attempt=0;$attempt -lt 30;$attempt++){
    $state=((& $adb -s emulator-5556 shell 'dumpsys activity processes | grep -E "mSystemReady|mBooted"' 2>$null) -join ' ')
    if($state -match 'mSystemReady=true' -and $state -match 'mBooted=true'){$ready=$true;break}
    Start-Sleep -Seconds 2
}
if(-not $ready){throw 'The restarted framework is not ready for fresh measurements.'}

param(
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\research-v14"
)

$ErrorActionPreference='Stop'
$adb=Join-Path $SdkRoot 'platform-tools\adb.exe'
$registration=Get-Content -LiteralPath (Join-Path $env:USERPROFILE '.android\avd\device-lab-numa.ini')
$registered=($registration | Where-Object {$_ -match '^path='}) -replace '^path=',''
$expected=[IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))
if([IO.Path]::GetFullPath($registered) -ne $expected){throw 'This installer is restricted to the independent prototype AVD.'}
if(@(& $adb -s emulator-5556 emu avd name)[0].Trim() -ne 'device-lab-numa'){throw 'Wrong emulator.'}
$project=Split-Path $PSScriptRoot
$apk=Join-Path $project 'module\build\outputs\apk\debug\module-debug.apk'
$stage=Join-Path $CacheRoot 'bootstrap-stage'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead((Join-Path $project 'module\build\namespace-module.zip'))
try {
    foreach($entry in @(@('zygisk/x86_64.so','x86_64.so'),@('module.prop','module.prop'))) {
        $stream=$archive.GetEntry($entry[0]).Open()
        $target=[IO.File]::Create((Join-Path $stage $entry[1]))
        try{$stream.CopyTo($target)}finally{$target.Dispose();$stream.Dispose()}
    }
}finally{$archive.Dispose()}
$utf8=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $stage 'platform-bootstrap-enabled'),"device-lab-platform-v1`n",$utf8)
[IO.File]::WriteAllText((Join-Path $stage 'bootstrap.prop'),"id=device_lab_platform`nname=Device Lab Platform`nversion=0.1.0`nversionCode=1`ndescription=Root-owned userdebug bootstrap for the dedicated AVD.`n",$utf8)
& $adb -s emulator-5556 root | Out-Null
& $adb -s emulator-5556 wait-for-device
try {
    & $adb -s emulator-5556 shell 'test ! -e /system/bin/magisk'
    if($LASTEXITCODE -ne 0){throw 'The prototype still exposes the Magisk bootstrap binary.'}
    $raw=& $adb -s emulator-5556 shell /data/local/tmp/device-lab-v14/policy-context-check
    $status=$LASTEXITCODE
    $policy=($raw -join "`n") | ConvertFrom-Json
    if($status -ne 0 -or $policy.passed -ne 5 -or -not $policy.controls_passed){throw 'Verify real stock SELinux context absence before installation.'}
    & $adb -s emulator-5556 install -r $apk | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Prototype runtime installation failed.'}
    & $adb -s emulator-5556 shell 'mkdir -p /data/misc/device-lab/bootstrap/bin /data/misc/device-lab/bootstrap/lib64 /data/misc/device-lab/zygisk /data/misc/device-lab/modules/device_lab_cpu/zygisk; chmod 0700 /data/misc/device-lab/bootstrap /data/misc/device-lab/bootstrap/bin /data/misc/device-lab/bootstrap/lib64 /data/misc/device-lab/zygisk /data/misc/device-lab/modules /data/misc/device-lab/modules/device_lab_cpu /data/misc/device-lab/modules/device_lab_cpu/zygisk; chcon -R u:object_r:system_file:s0 /data/misc/device-lab/modules'
    if($LASTEXITCODE -ne 0){throw 'Could not create private bootstrap directories.'}
    $files=@(
        @((Join-Path $CacheRoot 'build-upstream\zygiskd64'),'/data/misc/device-lab/bootstrap/bin/zygiskd64','0700'),
        @((Join-Path $CacheRoot 'build-upstream\zygisk-ptrace64'),'/data/misc/device-lab/bootstrap/bin/zygisk-ptrace64','0700'),
        @((Join-Path $CacheRoot 'build-upstream\libzygisk.so'),'/data/misc/device-lab/bootstrap/lib64/libzygisk.so','0700'),
        @((Join-Path $CacheRoot 'resetprop'),'/data/misc/device-lab/resetprop','0700'),
        @((Join-Path $stage 'x86_64.so'),'/data/misc/device-lab/modules/device_lab_cpu/zygisk/x86_64.so','0644'),
        @((Join-Path $stage 'module.prop'),'/data/misc/device-lab/modules/device_lab_cpu/module.prop','0644'),
        @((Join-Path $stage 'bootstrap.prop'),'/data/misc/device-lab/bootstrap/module.prop','0600'),
        @((Join-Path $stage 'bootstrap.prop'),'/data/misc/device-lab/bootstrap/module.prop.base','0600'),
        @((Join-Path $CacheRoot 'policy-context-check'),'/data/misc/device-lab/bootstrap/policy-context-check','0700'),
        @((Join-Path $PSScriptRoot 'platform-bootstrap\early.sh'),'/data/misc/device-lab/bootstrap/early.sh','0700'),
        @((Join-Path $PSScriptRoot 'platform-bootstrap\late.sh'),'/data/misc/device-lab/bootstrap/late.sh','0700'),
        @((Join-Path $stage 'platform-bootstrap-enabled'),'/data/misc/device-lab/platform-bootstrap-enabled','0600'),
        @((Join-Path $PSScriptRoot 'launch-platform-bootstrap.sh'),'/data/misc/device-lab/bootstrap/launch.sh','0700')
    )
    $hashes=[ordered]@{}
    foreach($item in $files){
        & $adb -s emulator-5556 push $item[0] "$($item[1]).new" | Out-Null
        if($LASTEXITCODE -ne 0){throw "Could not transfer prototype artifact: $($item[1])"}
        & $adb -s emulator-5556 shell "chown 0:0 $($item[1]).new; chmod $($item[2]) $($item[1]).new; chcon u:object_r:system_file:s0 $($item[1]).new; mv $($item[1]).new $($item[1])"
        if($LASTEXITCODE -ne 0){throw 'Could not secure a prototype artifact.'}
        $local=(Get-FileHash -LiteralPath $item[0]).Hash.ToLowerInvariant()
        $remote=((& $adb -s emulator-5556 shell sha256sum $item[1]) -split '\s+')[0]
        if($remote -ne $local){throw 'Installed prototype hash mismatch.'}
        $hashes[$item[1]]=$local
    }
    & $adb -s emulator-5556 shell 'chcon -R u:object_r:system_file:s0 /data/misc/device-lab/bootstrap /data/misc/device-lab/zygisk; /data/misc/device-lab/bootstrap/bin/zygiskd64 platform-check; sync'
    if($LASTEXITCODE -ne 0){throw 'The prototype platform backend did not select successfully.'}
    $hashes | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $CacheRoot 'installed-prototype-artifacts.json') -Encoding utf8
}finally{
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device
}
Write-Output 'Prototype files installed. Reapply scope, validate the platform notifier, then launch the monitor explicitly.'

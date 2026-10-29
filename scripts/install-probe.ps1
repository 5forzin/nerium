param(
    [ValidateSet('arm64-v8a', 'x86_64')][string]$Abi = 'arm64-v8a',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$apk = Join-Path $PSScriptRoot '..\probe\build\outputs\apk\debug\probe-debug.apk'
if (-not (Test-Path -LiteralPath $apk)) { throw 'Build the probe APK first.' }
& $adb -s emulator-5554 install -r --abi $Abi $apk
if ($LASTEXITCODE -ne 0) { throw "Could not install the probe for $Abi." }
$state = (& $adb -s emulator-5554 shell dumpsys package dev.androidlab.probe) -join "`n"
if ($LASTEXITCODE -ne 0 -or $state -notmatch 'primaryCpuAbi=([\w-]+)' -or $Matches[1] -ne $Abi) {
    throw 'Package manager did not select the requested ABI.'
}
Write-Output "Installed probe ABI: $Abi"

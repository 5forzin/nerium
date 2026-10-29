param(
    [string]$Serial = 'emulator-5556',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$PublicKey = "$env:USERPROFILE\.android\adbkey.pub"
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $PublicKey -PathType Leaf)) { throw 'ADB public key is unavailable.' }
$key = (Get-Content -LiteralPath $PublicKey -Raw).Trim()
if ($key -notmatch '^[A-Za-z0-9+/]+=*\s+[^\r\n]+$') { throw 'Expected an ADB public key, never a private key.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$backupDirectory = Join-Path $env:LOCALAPPDATA 'android-device-lab\backups'
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
$backup = Join-Path $backupDirectory "$Serial-adb_keys.before-auth"
& $adb -s $Serial root
& $adb -s $Serial wait-for-device
if ((& $adb -s $Serial shell getprop ro.kernel.qemu).Trim() -ne '1') { throw 'This helper is restricted to the lab emulator.' }
& $adb -s $Serial shell test -f /data/misc/adb/adb_keys
if ($LASTEXITCODE -eq 0 -and -not (Test-Path -LiteralPath $backup)) {
    & $adb -s $Serial pull /data/misc/adb/adb_keys $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not back up the existing public-key authorization list.' }
}
& $adb -s $Serial push $PublicKey /data/local/tmp/device-lab-adbkey.pub | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not transfer public key.' }
& $adb -s $Serial push (Join-Path $PSScriptRoot 'enable-adb-auth.sh') /data/local/tmp/device-lab-adb-auth.sh | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not transfer authentication helper.' }
& $adb -s $Serial shell sh /data/local/tmp/device-lab-adb-auth.sh /data/local/tmp/device-lab-adbkey.pub
if ($LASTEXITCODE -ne 0) { throw 'Could not configure authentication.' }
& $adb -s $Serial unroot
& $adb -s $Serial wait-for-device
$identity = (& $adb -s $Serial shell id) -join ''
if ($identity -notmatch 'uid=2000\(shell\)' -or ((& $adb -s $Serial shell getprop ro.adb.secure).Trim() -ne '1')) {
    throw 'Authenticated shell validation failed.'
}
Write-Output 'Authenticated ADB reconnected as shell UID 2000.'

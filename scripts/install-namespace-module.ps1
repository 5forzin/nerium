param([string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk", [string]$Serial = 'emulator-5554', [switch]$PackageOnly)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$project = Split-Path $PSScriptRoot
$apk = Join-Path $project 'module\build\outputs\apk\debug\module-debug.apk'
$destination = Join-Path $project 'module\build\namespace-module.zip'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$inputZip = [IO.Compression.ZipFile]::OpenRead($apk)
if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination }
$outputZip = [IO.Compression.ZipFile]::Open($destination, [IO.Compression.ZipArchiveMode]::Create)
try {
    $library = $inputZip.GetEntry('lib/x86_64/libcpunamespace.so')
    if ($null -eq $library) { throw 'Build the module APK before installing the namespace module.' }
    $entry = $outputZip.CreateEntry('zygisk/x86_64.so')
    $source = $library.Open()
    $target = $entry.Open()
    try { $source.CopyTo($target) } finally { $source.Dispose(); $target.Dispose() }
    $metadata = $outputZip.CreateEntry('module.prop').Open()
    $writer = [IO.StreamWriter]::new($metadata, [Text.UTF8Encoding]::new($false))
    try {
        $writer.Write("id=device_lab_cpu`nname=Device Lab Namespace`nversion=0.12.2`nversionCode=15`nauthor=Android Device Lab`ndescription=Scoped CPU, properties, uname and proc compatibility for the configured laboratory apps.`n")
    } finally { $writer.Dispose() }
    $service = $outputZip.CreateEntry('service.sh')
    $service.ExternalAttributes = -2115174400
    $source = [IO.File]::OpenRead((Join-Path $project 'module\service.sh'))
    $target = $service.Open()
    try { $source.CopyTo($target) } finally { $source.Dispose(); $target.Dispose() }
} finally { $inputZip.Dispose(); $outputZip.Dispose() }

if ($PackageOnly) { Write-Output $destination; return }

& $adb -s $Serial root
& $adb -s $Serial wait-for-device
$qemu = (& $adb -s $Serial shell getprop ro.kernel.qemu).Trim()
if ($qemu -ne '1') { throw 'This installer is restricted to the lab emulator.' }
& $adb -s $Serial push $destination /data/local/tmp/device-lab-namespace.zip
if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the module.' }
& $adb -s $Serial shell magisk --install-module /data/local/tmp/device-lab-namespace.zip
if ($LASTEXITCODE -ne 0) { throw 'Magisk module installation failed.' }
& $adb -s $Serial shell sync
if ($LASTEXITCODE -ne 0) { throw 'Could not flush the staged module before reboot.' }
& $adb -s $Serial unroot
Write-Output 'Namespace module installed. Reboot the emulator, then use set-module.ps1 to enable the experiment.'

param(
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$Name = 'device-lab-api34',
    [ValidateRange(5554, 5682)][int]$Port = 5554,
    [ValidateRange(1, 16)][int]$Cores = 2,
    [string]$KernelImage,
    [string]$RamdiskImage,
    [string]$SystemImage,
    [string]$VendorImage,
    [switch]$DiagnosticLogging,
    [switch]$Visible
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$emulator = Join-Path $SdkRoot 'emulator\emulator.exe'
if (-not (Test-Path -LiteralPath $emulator)) { throw 'Android Emulator is not installed.' }
$devices = & $adb devices
if ($Port % 2 -ne 0) { throw 'Use an even emulator console port.' }
if ($devices -match "^emulator-$Port\s") { throw "Port $Port is already in use by an emulator." }
$logDirectory = Join-Path $env:LOCALAPPDATA 'android-device-lab'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$emulatorArguments = @('-avd', $Name, '-memory', '1536', '-cores', "$Cores", '-gpu', 'host', '-no-audio', '-no-snapshot', '-no-boot-anim', '-camera-back', 'none', '-camera-front', 'none', '-port', "$Port")
if (-not $Visible) { $emulatorArguments += '-no-window' }
if ($DiagnosticLogging) { $emulatorArguments += @('-verbose', '-show-kernel') }
if ($KernelImage) {
    if (-not (Test-Path -LiteralPath $KernelImage -PathType Leaf)) { throw 'Kernel image does not exist.' }
    $emulatorArguments += @('-kernel', ('"' + [IO.Path]::GetFullPath($KernelImage) + '"'))
}
foreach ($image in @(@('ramdisk', $RamdiskImage), @('system', $SystemImage), @('vendor', $VendorImage))) {
    if (-not $image[1]) { continue }
    if (-not (Test-Path -LiteralPath $image[1] -PathType Leaf)) { throw "$($image[0]) image does not exist." }
    $emulatorArguments += @("-$($image[0])", ('"' + [IO.Path]::GetFullPath($image[1]) + '"'))
}
$windowStyle = if ($Visible) { 'Normal' } else { 'Hidden' }
$process = Start-Process -FilePath $emulator -ArgumentList $emulatorArguments -WindowStyle $windowStyle -PassThru -RedirectStandardOutput "$logDirectory\emulator-stdout.log" -RedirectStandardError "$logDirectory\emulator-stderr.log"
Write-Output "Emulator process: $($process.Id)"
Write-Output "Boot status: & '$adb' -s emulator-$Port shell getprop sys.boot_completed"

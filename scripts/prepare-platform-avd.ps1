param(
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\research-v14"
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$qemuImage = Join-Path $SdkRoot 'emulator\qemu-img.exe'
$registration = Join-Path $env:USERPROFILE '.android\avd\device-lab-numa.ini'
$baseline = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'android-device-lab\numa-kernel\avd\device-lab-numa.avd'))
$destination = [IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))
if (Test-Path -LiteralPath $destination) { throw 'The prototype AVD already exists; inspect it instead of overwriting.' }
$registered = (Get-Content -LiteralPath $registration | Where-Object { $_ -match '^path=' }) -replace '^path=', ''
if ([IO.Path]::GetFullPath($registered) -ne $baseline) { throw 'Expected the preserved baseline AVD registration.' }
if (@(& $adb -s emulator-5556 emu avd name)[0].Trim() -ne 'device-lab-numa') { throw 'The dedicated baseline is not running.' }
foreach ($item in @(@('proc99',99),@('raw79',79),@('probe54',54))) {
    $report = Get-Content -LiteralPath "$PSScriptRoot\..\reports\strict-v14-before-$($item[0]).json" -Raw | ConvertFrom-Json
    if ($report.summary.total -ne $item[1] -or $report.summary.detected -ne 0 -or $report.summary.unavailable -ne 0) { throw 'Collect passing fresh baseline regressions first.' }
}
New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
Copy-Item -LiteralPath $registration -Destination (Join-Path $CacheRoot 'baseline-registration.ini')
& $adb -s emulator-5556 root | Out-Null
& $adb -s emulator-5556 wait-for-device
try {
    $before = [ordered]@{}
    foreach ($property in @('persist.sys.usb.config','sys.usb.config','ro.adb.secure')) {
        $before[$property] = ((& $adb -s emulator-5556 shell getprop $property) -join '').Trim()
    }
    $before.adb_enabled = ((& $adb -s emulator-5556 shell settings get global adb_enabled) -join '').Trim()
    if (-not (Test-Path (Join-Path $CacheRoot 'baseline-before-clone-settings.json'))) {
        $before | ConvertTo-Json | Set-Content (Join-Path $CacheRoot 'baseline-before-clone-settings.json') -Encoding utf8
    }
    # The stock ramdisk has no laboratory boot service to start network-only adbd.
    if ($before.adb_enabled -ne '1') {
        & $adb -s emulator-5556 push "$PSScriptRoot\prepare-platform-clone-settings.sh" /data/local/tmp/device-lab-v14/prepare-clone.sh | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not stage the independent settings worker.' }
        & $adb -s emulator-5556 shell 'su -Z u:r:su:s0 -c ''nohup setsid sh /data/local/tmp/device-lab-v14/prepare-clone.sh > /data/local/tmp/device-lab-v14/prepare-clone.log 2>&1 < /dev/null &'''
        if ($LASTEXITCODE -ne 0) { throw 'Could not launch the independent settings worker.' }
        Start-Sleep -Seconds 8
        $connected = $false
        for ($attempt=0; $attempt -lt 20; $attempt++) {
            if ((& $adb -s emulator-5556 get-state 2>$null) -eq 'device') { $connected=$true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $connected) { throw 'The owned emulator has not reconnected after its USB transition.' }
        if (((& $adb -s emulator-5556 shell settings get global adb_enabled) -join '').Trim() -ne '1') { throw 'The prototype snapshot still has debugging disabled.' }
    }
    & $adb -s emulator-5556 shell sync
} finally {
    & $adb -s emulator-5556 unroot | Out-Null
    & $adb -s emulator-5556 wait-for-device
}
& "$PSScriptRoot\invoke-emulator-console.ps1" -Command kill
for ($attempt=0; $attempt -lt 30; $attempt++) {
    if (-not (Get-NetTCPConnection -LocalPort 5556 -State Listen -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 500
}
if (Get-NetTCPConnection -LocalPort 5556 -State Listen -ErrorAction SilentlyContinue) { throw 'The baseline emulator is still running.' }
$unlocked = & $qemuImage info --output=json (Join-Path $baseline 'userdata-qemu.img.qcow2')
if ($LASTEXITCODE -ne 0) { throw 'The baseline disk is still locked; do not copy a live AVD.' }
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($entry in Get-ChildItem -LiteralPath $baseline -Force) {
    if ($entry.Name -match '\.lock$') { continue }
    Copy-Item -LiteralPath $entry.FullName -Destination $destination -Recurse
}
$files = @('userdata-qemu.img','userdata-qemu.img.qcow2','encryptionkey.img','encryptionkey.img.qcow2','cache.img','cache.img.qcow2')
$copied = [ordered]@{}
foreach ($name in $files) {
    $sourceHash = (Get-FileHash -LiteralPath (Join-Path $baseline $name)).Hash.ToLowerInvariant()
    $copiedHash = (Get-FileHash -LiteralPath (Join-Path $destination $name)).Hash.ToLowerInvariant()
    if ($sourceHash -ne $copiedHash) { throw "Copied AVD file differs: $name" }
    $copied[$name] = $sourceHash
}
$rebased = @()
foreach ($name in @('userdata-qemu.img.qcow2','encryptionkey.img.qcow2','cache.img.qcow2')) {
    $overlay = Join-Path $destination $name
    $raw = & $qemuImage info --output=json $overlay
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect copied overlay: $name" }
    $info = ($raw -join "`n") | ConvertFrom-Json
    if (-not $info.'backing-filename') { throw "Expected an explicit backing image: $name" }
    $backing = Join-Path $destination ([IO.Path]::GetFileName($info.'backing-filename'))
    if (-not (Test-Path -LiteralPath $backing -PathType Leaf)) { throw "Missing copied backing image: $backing" }
    $backingInfo = ((& $qemuImage info --output=json $backing) -join "`n") | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $backingInfo.'backing-filename') { throw 'Expected a self-contained copied base image.' }
    if ([IO.Path]::GetFullPath($info.'full-backing-filename') -ne [IO.Path]::GetFullPath($backing) -or $info.'backing-filename-format' -ne $backingInfo.format) {
        & $qemuImage rebase -u -f qcow2 -F $backingInfo.format -b $backing $overlay
        if ($LASTEXITCODE -ne 0) { throw "Could not detach the copied overlay from its original backing: $name" }
    }
    $verified = ((& $qemuImage info --output=json $overlay) -join "`n") | ConvertFrom-Json
    if ([IO.Path]::GetFullPath($verified.'full-backing-filename') -ne [IO.Path]::GetFullPath($backing) -or $verified.'backing-filename-format' -ne $backingInfo.format) { throw 'Overlay still references an incorrect backing image or format.' }
    $rebased += $name
}
$manifest = [ordered]@{ captured_at=[DateTimeOffset]::UtcNow.ToString('o'); baseline=$baseline; prototype=$destination; copied_hashes=$copied; detached_overlays=$rebased; original_images_preserved=$true }
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $CacheRoot 'avd-clone-manifest.json') -Encoding utf8
$contents = "avd.ini.encoding=UTF-8`npath=$destination`ntarget=android-34`n"
[IO.File]::WriteAllText($registration,$contents,[Text.UTF8Encoding]::new($false))
Write-Output "Independent prototype AVD registered: $destination"

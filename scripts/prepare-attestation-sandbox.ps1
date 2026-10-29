param(
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\research-v17"
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$qemuImage = Join-Path $SdkRoot 'emulator\qemu-img.exe'
$registration = Join-Path $env:USERPROFILE '.android\avd\device-lab-numa.ini'
$baselineRoot = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v14'
$baseline = [IO.Path]::GetFullPath((Join-Path $baselineRoot 'avd\device-lab-numa.avd'))
$destination = [IO.Path]::GetFullPath((Join-Path $CacheRoot 'avd\device-lab-numa.avd'))
if (Test-Path -LiteralPath $destination) { throw 'The attestation sandbox already exists.' }
$registered = (Get-Content -LiteralPath $registration | Where-Object { $_ -match '^path=' }) -replace '^path=', ''
if ([IO.Path]::GetFullPath($registered) -ne $baseline) { throw 'Expected the accepted version 0.12.2 AVD registration.' }
if (@(& $adb -s emulator-5556 emu avd name)[0].Trim() -ne 'device-lab-numa') { throw 'The owned baseline is not running.' }
foreach ($pair in @(@('proc99',99), @('raw79',79), @('probe54',54))) {
    $report = Get-Content "$PSScriptRoot\..\reports\strict-v15-fourcore-c-$($pair[0]).json" -Raw | ConvertFrom-Json
    if ($report.summary.total -ne $pair[1] -or $report.summary.detected -ne 0 -or $report.summary.unavailable -ne 0) {
        throw 'The accepted frozen regression results are missing.'
    }
}
New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
Copy-Item -LiteralPath $registration -Destination (Join-Path $CacheRoot 'accepted-registration.ini')
& $adb -s emulator-5556 shell sync
if ($LASTEXITCODE -ne 0) { throw 'Could not synchronize the owned emulator.' }
& "$PSScriptRoot\invoke-emulator-console.ps1" -Port 5556 -Command kill
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if (-not (Get-NetTCPConnection -LocalPort 5556 -State Listen -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 1
}
if (Get-NetTCPConnection -LocalPort 5556 -State Listen -ErrorAction SilentlyContinue) { throw 'The owned emulator did not stop.' }

New-Item -ItemType Directory -Path $destination | Out-Null
$disks = @('userdata-qemu.img','userdata-qemu.img.qcow2','encryptionkey.img','encryptionkey.img.qcow2','cache.img','cache.img.qcow2')
$hashes = [ordered]@{}
foreach ($name in @($disks + @('config.ini','userdata.img','version_num.cache','qemu-version.txt','hardware-qemu.ini','emulator-user.ini','netsim.ini','quickbootChoice.ini'))) {
    $source = Join-Path $baseline $name
    $copy = Join-Path $destination $name
    Copy-Item -LiteralPath $source -Destination $copy
    $sourceHash = (Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant()
    if ($sourceHash -ne (Get-FileHash -LiteralPath $copy).Hash.ToLowerInvariant()) { throw "Clone mismatch: $name" }
    $hashes[$name] = $sourceHash
}
foreach ($name in @('data','modem_simulator')) {
    $source = Join-Path $baseline $name
    if (Test-Path -LiteralPath $source -PathType Container) {
        Copy-Item -LiteralPath $source -Destination (Join-Path $destination $name) -Recurse
    }
}
foreach ($name in @('userdata-qemu.img.qcow2','encryptionkey.img.qcow2','cache.img.qcow2')) {
    $overlay = Join-Path $destination $name
    $info = ((& $qemuImage info --output=json $overlay) -join "`n") | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $info.'backing-filename') { throw 'Expected an explicit overlay backing image.' }
    $backing = Join-Path $destination ([IO.Path]::GetFileName($info.'backing-filename'))
    $baseInfo = ((& $qemuImage info --output=json $backing) -join "`n") | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $baseInfo.'backing-filename') { throw 'Expected a self-contained copied base image.' }
    & $qemuImage rebase -u -f qcow2 -F $baseInfo.format -b $backing $overlay
    if ($LASTEXITCODE -ne 0) { throw 'Could not detach the copied overlay.' }
    $verified = ((& $qemuImage info --output=json $overlay) -join "`n") | ConvertFrom-Json
    if ([IO.Path]::GetFullPath($verified.'full-backing-filename') -ne [IO.Path]::GetFullPath($backing)) {
        throw 'The sandbox overlay still references another checkout.'
    }
}
New-Item -ItemType Directory -Path (Join-Path $CacheRoot 'build-upstream') | Out-Null
foreach ($name in @('zygiskd64','zygisk-ptrace64','libzygisk.so')) {
    Copy-Item -LiteralPath (Join-Path $baselineRoot "build-upstream\$name") -Destination (Join-Path $CacheRoot "build-upstream\$name")
}
[ordered]@{
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    accepted_avd = $baseline
    sandbox_avd = $destination
    baseline_file_sha256 = $hashes
    independent_overlay_backings = $true
    shared_immutable_system_images = $true
    accepted_registration_backup = Join-Path $CacheRoot 'accepted-registration.ini'
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $CacheRoot 'sandbox-manifest.json') -Encoding utf8
[IO.File]::WriteAllText($registration, "avd.ini.encoding=UTF-8`npath=$destination`ntarget=android-34`n", [Text.UTF8Encoding]::new($false))
Write-Output "Independent attestation sandbox registered: $destination"

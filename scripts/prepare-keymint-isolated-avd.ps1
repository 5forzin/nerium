#Requires -Version 7.2
[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) '.local\keymint-v42'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sdkRoot = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$qemuImage = Join-Path $sdkRoot 'emulator\qemu-img.exe'
$sourceAvd = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v14\avd\device-lab-numa.avd'
$sourceImages = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v14\system-images-platform'
$runtime = [IO.Path]::GetFullPath($RuntimeRoot)
$destinationAvd = Join-Path $runtime 'avd\device-lab-keymint-v42.avd'
$destinationImages = Join-Path $runtime 'system-images'
$manifestPath = Join-Path $runtime 'clone-manifest.json'
$registration = Join-Path $env:USERPROFILE '.android\avd\device-lab-keymint-v42.ini'
if (Test-Path -LiteralPath $runtime) { throw 'The isolated runtime already exists; inspect its owner and state before resuming.' }
if (Test-Path -LiteralPath $registration) { throw 'The isolated AVD name is already registered.' }
if ($runtime -eq [IO.Path]::GetFullPath($sourceAvd) -or $runtime -eq [IO.Path]::GetFullPath($sourceImages)) { throw 'Source and destination overlap.' }
$sourceActive = @(Get-CimInstance Win32_Process -Filter "Name='qemu-system-x86_64.exe' OR Name='qemu-system-x86_64-headless.exe'" | Where-Object {
    $_.CommandLine -and ($_.CommandLine.Contains($sourceAvd) -or $_.CommandLine.Contains('device-lab-platform-v25'))
})
if ($sourceActive.Count) { throw 'The preserved source AVD is currently active.' }
& $qemuImage info --output=json (Join-Path $sourceAvd 'userdata-qemu.img.qcow2') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'The preserved source disk cannot be inspected safely.' }
$dataFiles = @('userdata-qemu.img','userdata-qemu.img.qcow2','encryptionkey.img','encryptionkey.img.qcow2','cache.img','cache.img.qcow2','config.ini','initrd','userdata.img','version_num.cache','qemu-version.txt','quickbootChoice.ini')
$imageFiles = @(Get-ChildItem -LiteralPath $sourceImages -File)
$required = ($imageFiles | Measure-Object Length -Sum).Sum
foreach ($name in $dataFiles) { $required += (Get-Item -LiteralPath (Join-Path $sourceAvd $name)).Length }
$driveName = [IO.Path]::GetPathRoot($runtime).TrimEnd('\').TrimEnd(':')
if ((Get-PSDrive $driveName).Free -lt $required + 2GB) { throw 'Insufficient space for an independent clone and a 2 GiB working margin.' }
New-Item -ItemType Directory -Path $destinationAvd,$destinationImages -Force | Out-Null
$manifest = [ordered]@{schema_version=1;state='copying';creator_pid=$PID;created_at=[DateTimeOffset]::UtcNow.ToString('o');source_avd=$sourceAvd;source_images=$sourceImages;runtime=$runtime;files=[ordered]@{};rebased_overlays=@();original_images_modified=$false}
function Save-CloneManifest { [IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
Save-CloneManifest
try {
    foreach ($entry in $imageFiles) {
        $destination = Join-Path $destinationImages $entry.Name
        Copy-Item -LiteralPath $entry.FullName -Destination $destination -ErrorAction Stop
        $sourceHash = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceHash) { throw 'Copied system image differs from source.' }
        $manifest.files['system-images/'+$entry.Name] = $sourceHash
        Save-CloneManifest
    }
    if ($manifest.files['system-images/system.img'] -cne '4806fbc745cd9abbfacc358496508f0ce420010e0ddaccef11e52e5da8e92f0a') { throw 'The preserved system image differs from the audited platform baseline.' }
    foreach ($name in $dataFiles) {
        $source = Join-Path $sourceAvd $name
        $destination = Join-Path $destinationAvd $name
        Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceHash) { throw 'Copied data image differs from source.' }
        $manifest.files['avd/'+$name] = $sourceHash
        Save-CloneManifest
    }
    foreach ($name in @('userdata-qemu.img.qcow2','encryptionkey.img.qcow2','cache.img.qcow2')) {
        $overlay = Join-Path $destinationAvd $name
        $info = (& $qemuImage info --output=json $overlay) | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $info.'backing-filename') { throw 'Expected an explicit copied backing image.' }
        $backing = Join-Path $destinationAvd ([IO.Path]::GetFileName($info.'backing-filename'))
        $inside = [IO.Path]::GetFullPath($backing).StartsWith($destinationAvd + '\',[StringComparison]::OrdinalIgnoreCase)
        if (-not $inside -or -not (Test-Path -LiteralPath $backing -PathType Leaf)) { throw 'Backing image is outside the isolated AVD.' }
        $base = (& $qemuImage info --output=json $backing) | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or $base.PSObject.Properties.Name -contains 'backing-filename') { throw 'Copied base image must be self-contained.' }
        if ([IO.Path]::GetFullPath($info.'full-backing-filename') -ne [IO.Path]::GetFullPath($backing) -or $info.'backing-filename-format' -cne $base.format) {
            & $qemuImage rebase -u -f qcow2 -F $base.format -b $backing $overlay
            if ($LASTEXITCODE -ne 0) { throw 'Could not rebase the isolated overlay.' }
            $manifest.rebased_overlays += $name
        }
        $verified = (& $qemuImage info --output=json $overlay) | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($verified.'full-backing-filename') -ne [IO.Path]::GetFullPath($backing)) { throw 'Overlay still references an external backing image.' }
    }
    $configPath = Join-Path $destinationAvd 'config.ini'
    $config = Get-Content -Raw -LiteralPath $configPath
    $config = $config -replace '(?m)^\s*image\.sysdir\.1\s*=.*$', ('image.sysdir.1=' + $destinationImages.Replace('\','/') + '/')
    $config = $config -replace '(?m)^\s*AvdId\s*=.*$', 'AvdId=device-lab-keymint-v42'
    [IO.File]::WriteAllText($configPath,$config,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($registration,"avd.ini.encoding=UTF-8`npath=$destinationAvd`ntarget=android-34`n",[Text.UTF8Encoding]::new($false))
    $manifest.state = 'prepared'
    $manifest.registration = $registration
    $manifest.config_sha256 = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
} catch {
    $manifest.state = 'failed'
    $manifest.error_type = $_.Exception.GetType().Name
    throw
} finally { Save-CloneManifest }
[pscustomobject]@{state=$manifest.state;avd='device-lab-keymint-v42';runtime=$runtime;copied_files=$manifest.files.Count}

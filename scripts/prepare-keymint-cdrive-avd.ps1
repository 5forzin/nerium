#Requires -Version 7.2
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = Split-Path $PSScriptRoot -Parent
$sourceRuntime = [IO.Path]::GetFullPath((Join-Path $project '.local\keymint-v42'))
$sourceAvd = Join-Path $sourceRuntime 'avd\device-lab-keymint-v42.avd'
$cache = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v42'))
$runtime = [IO.Path]::GetFullPath((Join-Path $cache 'runtime-c'))
$destination = Join-Path $runtime 'avd\device-lab-keymint-v42.avd'
$registration = Join-Path $env:USERPROFILE '.android\avd\device-lab-keymint-v42.ini'
$qemuImage = Join-Path $env:LOCALAPPDATA 'Android\Sdk\emulator\qemu-img.exe'
if (-not $runtime.StartsWith($cache + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected runtime root.' }
if (Test-Path -LiteralPath $runtime) { throw 'The new C-drive runtime already exists.' }
$owned = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match '^qemu-system-' -and $_.CommandLine -match 'device-lab-keymint-v42'
})
if ($owned.Count) { throw 'The dedicated emulator must be stopped before copying its disks.' }
$manifest = Get-Content -Raw -LiteralPath (Join-Path $sourceRuntime 'clone-manifest.json') | ConvertFrom-Json -AsHashtable
if ($manifest.state -cne 'prepared') { throw 'The source clone is incomplete.' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$manifest.state = 'preparing'
$manifest.runtime = $runtime
$manifest.storage_copy_created_at = [DateTimeOffset]::UtcNow.ToString('o')
$manifest.retained_source_runtime = $sourceRuntime
$manifest.copy_verifications = @()
$manifestPath = Join-Path $runtime 'clone-manifest.json'
try {
    foreach ($name in @('userdata-qemu.img.qcow2', 'encryptionkey.img', 'encryptionkey.img.qcow2',
        'cache.img', 'cache.img.qcow2', 'userdata.img', 'config.ini', 'initrd',
        'version_num.cache', 'qemu-version.txt', 'quickbootChoice.ini')) {
        $source = Join-Path $sourceAvd $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required source is missing: $name" }
        $target = Join-Path $destination $name
        $before = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $source -Destination $target
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $before) { throw 'A copied disk or marker differs.' }
        $manifest.copy_verifications += @{name = $name; sha256 = $before; byte_identical = $true}
    }
    $base = Join-Path $sourceAvd 'userdata-qemu.img'
    $thinBase = Join-Path $destination 'userdata-qemu.img'
    $baseHash = (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant()
    & $qemuImage create -f qcow2 -F qcow2 -b $base $thinBase | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The new thin base could not be created.' }
    & $qemuImage compare -f qcow2 -F qcow2 $base $thinBase | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The thin base differs from its retained backing image.' }
    & $qemuImage compare -f qcow2 -F qcow2 (Join-Path $sourceAvd 'userdata-qemu.img.qcow2') (Join-Path $destination 'userdata-qemu.img.qcow2') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The copied Android data differs logically.' }
    if ((Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baseHash) { throw 'The retained backing image changed.' }
    $manifest.retained_read_only_backing = @{path = $base; sha256 = $baseHash; must_be_kept = $true}
    $manifest.virtual_disk_compare_passed = $true
    $manifest.snapshots_copied = $false
    $manifest.source_files_removed = $false
    Copy-Item -LiteralPath $registration -Destination (Join-Path $runtime 'registration-before-cdrive.ini')
    [IO.File]::WriteAllText($registration, "avd.ini.encoding=UTF-8`npath=$destination`ntarget=android-34`n", [Text.UTF8Encoding]::new($false))
    $manifest.registration = $registration
    $manifest.state = 'prepared'
} catch {
    $manifest.state = 'failed'
    $manifest.error = $_.Exception.Message
    throw
} finally {
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $project 'reports\keymint-v42-cdrive-copy.json'), ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
[pscustomobject]@{state = $manifest.state; runtime = $runtime; logical_data_identical = $true; retained_old_clone = $true}

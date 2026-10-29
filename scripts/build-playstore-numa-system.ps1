$ErrorActionPreference = 'Stop'
$scriptRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$cache = [IO.Path]::GetFullPath("$env:LOCALAPPDATA\android-device-lab\playstore-numa-hybrid")
$modules = [IO.Path]::GetFullPath("$env:LOCALAPPDATA\android-device-lab\numa-kernel\modules")
if (-not (Test-Path -LiteralPath $modules -PathType Container)) { throw 'Rebuilt kernel modules are missing.' }
foreach ($name in @('vendor-stock-partition.img', 'vendor-numa-partition.img', 'system-playstore-numa.img')) {
    if (Test-Path -LiteralPath (Join-Path $cache $name)) { throw "Existing isolated output: $name" }
}

& python (Join-Path $scriptRoot 'extract-playstore-numa-vendor.py')
if ($LASTEXITCODE -ne 0) { throw 'Vendor extraction failed.' }
& docker run --rm -v "${cache}:/work" -v "${modules}:/modules:ro" -v "${scriptRoot}:/scripts:ro" android-device-lab-tools:v12 python3 /scripts/patch-playstore-numa-vendor.py
if ($LASTEXITCODE -ne 0) { throw 'Vendor module patch failed.' }
& python (Join-Path $scriptRoot 'patch-playstore-numa-system.py')
if ($LASTEXITCODE -ne 0) { throw 'System image patch failed.' }

Write-Output (Join-Path $cache 'system-playstore-numa.img')

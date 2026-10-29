param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateSet('helper', 'zygote')][string]$Target = 'helper',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
$compiler = Join-Path $SdkRoot 'ndk\27.0.12077973\toolchains\llvm\prebuilt\windows-x86_64\bin\x86_64-linux-android34-clang.cmd'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'The pinned Android NDK compiler is missing.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$source = Join-Path $PSScriptRoot 'platform-bootstrap\exec-probe'
$common = @('-D_GNU_SOURCE', '-std=c17', '-Os', '-Wall', '-Wextra', '-Werror')
$wrapper = @()
if ($Target -eq 'zygote') { $wrapper += '-DDEVICE_LAB_REAL_ZYGOTE=1' }
& $compiler @common @wrapper (Join-Path $source 'wrapper.c') -llog -ldl -o (Join-Path $OutputDirectory 'device-lab-exec-wrapper')
if ($LASTEXITCODE -ne 0) { throw 'Wrapper build failed.' }
& $compiler @common -fPIC -shared (Join-Path $source 'library.c') -llog -ldl -o (Join-Path $OutputDirectory 'libdevice_lab_boot_probe.so')
if ($LASTEXITCODE -ne 0) { throw 'Constructor library build failed.' }
& $compiler @common (Join-Path $source 'helper.c') -llog -ldl -o (Join-Path $OutputDirectory 'device-lab-exec-helper')
if ($LASTEXITCODE -ne 0) { throw 'Helper build failed.' }
$manifest = [ordered]@{ target = $Target; abi = 'x86_64'; android_api = 34; ndk_version = '27.0.12077973'; sources = [ordered]@{}; artifacts = [ordered]@{} }
foreach ($file in (Get-ChildItem -LiteralPath $source -File)) {
    $manifest.sources[$file.Name] = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
}
foreach ($name in @('device-lab-exec-wrapper', 'device-lab-exec-helper', 'libdevice_lab_boot_probe.so')) {
    $manifest.artifacts[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $OutputDirectory $name)).Hash.ToLowerInvariant()
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8
Get-ChildItem -LiteralPath $OutputDirectory -File | Select-Object Name, Length

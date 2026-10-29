#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$CacheRoot = (Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v41'),
    [string]$BuildRoot,
    [ValidateSet('native_keymaster_baseline', 'cng_protocol_tests', 'keymint3_certificate_tests', 'keymint_pipe_backend', 'hybrid_keymint_tests', 'lab_attestation_tests')]
    [string]$Target = 'native_keymaster_baseline',
    [switch]$SkipPrepare,
    [switch]$SkipRun
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path $PSScriptRoot -Parent
$nativeRoot = Join-Path $projectRoot 'nativekeymint'
$cmakeBin = Join-Path $env:LOCALAPPDATA 'Android\Sdk\cmake\3.22.1\bin'
$cmake = Join-Path $cmakeBin 'cmake.exe'
$ninja = Join-Path $cmakeBin 'ninja.exe'
$python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$toolchainName = 'llvm-mingw-20240619-ucrt-x86_64'
$toolchain = Join-Path $CacheRoot $toolchainName
$cc = Join-Path $toolchain 'bin\x86_64-w64-mingw32-clang.exe'
$cxx = Join-Path $toolchain 'bin\x86_64-w64-mingw32-clang++.exe'
$build = if ($BuildRoot) { [IO.Path]::GetFullPath($BuildRoot) } else { Join-Path $CacheRoot 'build-windows-llvm18' }
$receiptPath = Join-Path (Split-Path $build -Parent) "$Target-build.json"
$receipt = [ordered]@{schema_version=1;target=$Target;status='running';run=$false;recorded_at=[DateTimeOffset]::UtcNow.ToString('o')}
New-Item -ItemType Directory -Force -Path $CacheRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $receiptPath -Parent) | Out-Null
function Save-Receipt {
    [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
Save-Receipt
$phase = 'tools'
try {
if ($Target -ceq 'keymint_pipe_backend' -and -not $SkipRun) { throw 'Pipe backend requires explicit -SkipRun and a separately owned launch' }
foreach ($tool in @($cmake, $ninja, $python)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Required local build tool missing: $tool" }
}
$phase = 'toolchain'
if (-not (Test-Path -LiteralPath $cxx)) {
    & gh release download 20240619 --repo mstorsjo/llvm-mingw --pattern "$toolchainName.zip" --dir $CacheRoot --skip-existing
    if ($LASTEXITCODE -ne 0) { throw 'Official portable toolchain download failed' }
    Expand-Archive -LiteralPath (Join-Path $CacheRoot "$toolchainName.zip") -DestinationPath $CacheRoot
}
if (-not $SkipPrepare) {
    $phase = 'sources'
    & $python -B (Join-Path $nativeRoot 'prepare_sources.py') $CacheRoot
    if ($LASTEXITCODE -ne 0) { throw 'Pinned AOSP source preparation failed' }
}
$cc = $cc.Replace('\', '/')
$cxx = $cxx.Replace('\', '/')
$ninja = $ninja.Replace('\', '/')
$phase = 'configure'
& $cmake -S $nativeRoot -B $build -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" `
    "-DCMAKE_C_COMPILER=$cc" "-DCMAKE_CXX_COMPILER=$cxx" '-DCMAKE_BUILD_TYPE=Release' `
    "-DAOSP_SOURCE_DIR=$(Join-Path $CacheRoot 'sources')"
if ($LASTEXITCODE -ne 0) { throw 'Native CMake configuration failed' }
$phase = 'compile'
& $cmake --build $build --target $Target --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'Native AndroidKeymaster compilation failed' }
$executable = Join-Path $build "$Target.exe"
$sourceManifest = Join-Path $CacheRoot 'source-manifest.json'
$metadata = [ordered]@{
    schema_version = 1
    target = $Target
    platform = 'native_windows_x86_64'
    keymaster_revision = '8729d4dd86c0bfec54c34610aa1c35f3d109b8a6'
    toolchain_release = 'mstorsjo/llvm-mingw/20240619'
    compiler_sha256 = (Get-FileHash -LiteralPath $cxx -Algorithm SHA256).Hash.ToLowerInvariant()
    source_manifest_sha256 = (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    executable_sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    run = $false
}
foreach ($entry in $metadata.GetEnumerator()) { $receipt[$entry.Key] = $entry.Value }
$receipt.build_script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$inputs = [ordered]@{}
foreach ($inputFile in (Get-ChildItem -LiteralPath $nativeRoot -File -Recurse | Sort-Object FullName)) {
    $relative = $inputFile.FullName.Substring($nativeRoot.Length + 1).Replace('\', '/')
    $inputs[$relative] = (Get-FileHash -LiteralPath $inputFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$receipt.project_input_sha256 = $inputs
$receipt.toolchain_archive_sha256 = (Get-FileHash -LiteralPath (Join-Path $CacheRoot "$toolchainName.zip") -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt.port_header_sha256 = (Get-FileHash -LiteralPath (Join-Path $build 'port_include\keymaster\contexts\pure_soft_keymaster_context.h') -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt.port_source_sha256 = (Get-FileHash -LiteralPath (Join-Path $build 'pure_soft_keymaster_context.cpp') -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $SkipRun) {
    $phase = 'harness'
    $oldPath = $env:PATH
    try {
        $env:PATH = (Join-Path $toolchain 'bin') + [IO.Path]::PathSeparator + $oldPath
        $output = & $executable
        $harnessExit = $LASTEXITCODE
        $receipt.harness_exit_code = $harnessExit
        $receipt.run = $true
        $result = ($output -join "`n") | ConvertFrom-Json
        $receipt.result = $result
        if ($harnessExit -ne 0) { throw 'Native AndroidKeymaster harness failed' }
    } finally { $env:PATH = $oldPath }
}
$receipt.status = if ($SkipRun) { 'compiled_only' } else { 'passed' }
} catch {
    $receipt.status = 'failed'
    $receipt.error = [ordered]@{code='NATIVE_BUILD_OR_TEST_FAILED';stage=$phase;exception_type=$_.Exception.GetType().Name}
    throw
} finally {
    $receipt.completed_at = [DateTimeOffset]::UtcNow.ToString('o')
    Save-Receipt
}
$receipt | ConvertTo-Json -Depth 12

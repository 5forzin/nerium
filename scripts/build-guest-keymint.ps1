#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$CacheRoot = (Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v42'),
    [string]$KeymasterSourceDir = (Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v41\sources'),
    [switch]$SkipPrepare
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path $PSScriptRoot -Parent
$sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$ndk = Join-Path $sdk 'ndk\27.0.12077973'
$cmake = Join-Path $sdk 'cmake\3.22.1\bin\cmake.exe'
$ninja = Join-Path $sdk 'cmake\3.22.1\bin\ninja.exe'
$aidl = Join-Path $sdk 'build-tools\35.0.0\aidl.exe'
$readelf = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe'
$compiler = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe'
$python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$hal = Join-Path $CacheRoot 'hal-research'
$generated = Join-Path $CacheRoot 'guest-aidl'
$build = Join-Path $CacheRoot 'build-guest-x86_64'
$receiptPath = Join-Path $CacheRoot 'guest-keymint-build.json'
$receipt = [ordered]@{schema_version=1;status='running';runtime_tested=$false;recorded_at=[DateTimeOffset]::UtcNow.ToString('o')}
New-Item -ItemType Directory -Force -Path $CacheRoot | Out-Null
function Save-Receipt {
    [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
Save-Receipt
$phase = 'prerequisites'
try {
    foreach ($tool in @($cmake, $ninja, $aidl, $readelf, $python, (Join-Path $hal 'libbinder_ndk.so'), (Join-Path $KeymasterSourceDir 'keymaster\include\keymaster\android_keymaster_messages.h'))) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Required build prerequisite missing: $tool" }
    }
    $binderHash = (Get-FileHash -LiteralPath (Join-Path $hal 'libbinder_ndk.so') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($binderHash -ne '9d9a0b1b066f5af79ea373b0b03b119db41dff5bedf42364c49b9c3fc2176b57') {
        throw 'Platform Binder library differs from the audited Android 14 system image'
    }
    if (-not $SkipPrepare) {
        $phase = 'sources'
        & $python -B (Join-Path $projectRoot 'guestkeymint\prepare_sources.py') $CacheRoot
        if ($LASTEXITCODE -ne 0) { throw 'Pinned guest source preparation failed' }
    }
    $phase = 'aidl'
    New-Item -ItemType Directory -Force -Path (Join-Path $generated 'include'), (Join-Path $generated 'src') | Out-Null
    $includeFlags = @(("-I$(Join-Path $hal 'aidl\keymint')"), ("-I$(Join-Path $hal 'aidl\secureclock')"), ("-I$(Join-Path $hal 'aidl\sharedsecret')"), ("-I$(Join-Path $hal 'aidl\rkp')"))
    $aidlHashes = [ordered]@{}
    foreach ($package in @('secureclock', 'sharedsecret', 'keymint', 'rkp')) {
        $source = Join-Path $hal "aidl\$package"
        $version = if ($package -in @('keymint', 'rkp')) { 3 } else { 1 }
        $hash = (Get-Content -LiteralPath (Join-Path $source '.hash') | Select-Object -Last 1).Trim()
        $aidlHashes[$package] = $hash
        $inputs = @(Get-ChildItem -LiteralPath $source -Filter '*.aidl' -File -Recurse | Sort-Object FullName | ForEach-Object FullName)
        & $aidl '--lang=ndk' '--structured' '--stability=vintf' '--min_sdk_version=34' "--version=$version" "--hash=$hash" @includeFlags "-h$(Join-Path $generated 'include')" "-o$(Join-Path $generated 'src')" @inputs
        if ($LASTEXITCODE -ne 0) { throw "Frozen $package NDK AIDL generation failed" }
    }
    $phase = 'configure'
    & $cmake -S (Join-Path $projectRoot 'guestkeymint') -B $build -G Ninja "-DCMAKE_MAKE_PROGRAM=$($ninja.Replace('\','/'))" `
        "-DCMAKE_TOOLCHAIN_FILE=$(Join-Path $ndk 'build\cmake\android.toolchain.cmake')" '-DANDROID_ABI=x86_64' '-DANDROID_PLATFORM=34' '-DANDROID_STL=c++_static' `
        '-DCMAKE_BUILD_TYPE=Release' "-DGUEST_SOURCE_DIR=$(Join-Path $CacheRoot 'guest-prepared')" "-DKEYMASTER_SOURCE_DIR=$KeymasterSourceDir" "-DPLATFORM_BINDER_DIR=$hal" "-DGENERATED_AIDL_DIR=$generated"
    if ($LASTEXITCODE -ne 0) { throw 'Guest CMake configuration failed' }
    $phase = 'compile'
    & $cmake --build $build --parallel 4
    if ($LASTEXITCODE -ne 0) { throw 'Guest KeyMint compilation failed' }
    $binary = Join-Path $build 'androidlab-keymint-service'
    $phase = 'elf-verification'
    $elfOutput = (& $readelf --file-header --dynamic-table --dyn-syms --wide $binary) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Guest ELF inspection failed' }
    if ($elfOutput -notmatch 'Advanced Micro Devices X86-64' -or $elfOutput -notmatch 'AServiceManager_addService' -or $elfOutput -notmatch 'ABinderProcess_joinThreadPool' -or $elfOutput -notmatch 'AIBinder_markVintfStability') { throw 'Guest ELF lacks expected architecture or real Binder registration and VINTF stability imports' }
    if ($elfOutput -match 'libc\+\+_shared.so') { throw 'Guest ELF unexpectedly depends on undeployed NDK shared STL' }
    [IO.File]::WriteAllText((Join-Path $CacheRoot 'guest-keymint-elf.txt'), $elfOutput, [Text.UTF8Encoding]::new($false))
    $receipt.status = 'compiled_and_elf_verified'
    $receipt.platform = 'android_x86_64_api34'
    $receipt.executable = $binary
    $receipt.executable_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.platform_binder_sha256 = $binderHash
    $receipt.ndk_compiler_sha256 = (Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.aidl_compiler_sha256 = (Get-FileHash -LiteralPath $aidl -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.source_manifest_sha256 = (Get-FileHash -LiteralPath (Join-Path $CacheRoot 'guest-source-manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.aidl_hashes = $aidlHashes
    $receipt.message_version = 4
    $receipt.security_level = 'SOFTWARE'
    $receipt.build_script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $projectInputs = [ordered]@{}
    foreach ($item in (Get-ChildItem -LiteralPath (Join-Path $projectRoot 'guestkeymint') -File -Recurse | Sort-Object FullName)) {
        $projectInputs[$item.FullName.Substring($projectRoot.Length + 1).Replace('\','/')] = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $receipt.project_input_sha256 = $projectInputs
    $dependencyInputs = [ordered]@{}
    $dependencyFiles = @(Get-ChildItem -LiteralPath (Join-Path $KeymasterSourceDir 'keymaster\include'), (Join-Path $KeymasterSourceDir 'hardware\include') -File -Recurse)
    foreach ($name in @('android_keymaster_messages', 'android_keymaster_utils', 'authorization_set', 'keymaster_tags', 'logger', 'serializable')) {
        $dependencyFiles += Get-Item -LiteralPath (Join-Path $KeymasterSourceDir "keymaster\android_keymaster\$name.cpp")
    }
    foreach ($item in ($dependencyFiles | Sort-Object FullName)) {
        $dependencyInputs[$item.FullName.Substring($KeymasterSourceDir.Length + 1).Replace('\','/')] = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $receipt.keymaster_dependency_sha256 = $dependencyInputs
} catch {
    $receipt.status = 'failed'
    $receipt.error = [ordered]@{stage=$phase;exception_type=$_.Exception.GetType().Name;message=$_.Exception.Message}
    throw
} finally {
    $receipt.completed_at = [DateTimeOffset]::UtcNow.ToString('o')
    Save-Receipt
}
$receipt | ConvertTo-Json -Depth 12

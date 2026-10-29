param(
    [ValidateSet('enable', 'disable')][string]$State = 'enable',
    [switch]$IncludeIndependentDetector,
    [switch]$IncludeExtendedDetectors,
    [switch]$IncludeRawProbe,
    [switch]$IncludeProcProbe,
    [string[]]$ExcludeDetector = @(),
    [string[]]$NativeOnlyPackage = @(),
    [switch]$NativeOnly = $true,
    [switch]$RestrictIsolatedProc,
    [string]$Serial = 'emulator-5554',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$cli = '/data/adb/lspd/cli'
$module = 'dev.androidlab.module'
for ($attempt = 0; $attempt -lt 3; $attempt++) {
    & $adb -s $serial root
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 2
}
if ($LASTEXITCODE -ne 0) { throw 'Could not request root ADB on the lab emulator.' }
& $adb -s $serial wait-for-device
if ($State -eq 'enable') {
    $scope = @('dev.androidlab.probe/0')
    if ($IncludeRawProbe) { $scope += 'dev.androidlab.rawprobe/0' }
    if ($IncludeProcProbe) { $scope += 'dev.androidlab.procprobe/0' }
    if ($IncludeExtendedDetectors) {
        $catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'detectors.json') -Raw | ConvertFrom-Json
        foreach ($id in $ExcludeDetector) {
            if ($id -notin $catalog.id) { throw "Unknown detector exclusion: $id" }
        }
        $scope += @($catalog | Where-Object { $_.id -notin $ExcludeDetector } | ForEach-Object { "$($_.package)/0" })
    } elseif ($IncludeIndependentDetector) { $scope += 'com.reveny.emulator.detection.sample/0' }
    foreach ($entry in $scope) {
        if ($entry -notmatch '^[a-zA-Z][a-zA-Z0-9_.]+/0$') { throw 'Invalid laboratory package scope.' }
    }
    if ($NativeOnly) { $NativeOnlyPackage = @($scope -replace '/0$', '') }
    $armRuntimeScope = @()
    foreach ($package in $NativeOnlyPackage) {
        if ("$package/0" -notin $scope) { throw "Native-only package is not in the configured laboratory scope: $package" }
        $details = (& $adb -s $serial shell dumpsys package $package) -join "`n"
        if ($details -match '(?m)^\s*primaryCpuAbi=arm64-v8a\s*$') { $armRuntimeScope += $package }
        elseif ($details -notmatch '(?m)^\s*primaryCpuAbi=(x86_64|null)\s*$') { throw "Unsupported runtime ABI: $package" }
    }
    $frameworkScope = @($scope | Where-Object { ($_ -replace '/0$', '') -notin $NativeOnlyPackage })
    if ($frameworkScope.Count -gt 0) {
        & $adb -s $serial shell sh $cli scope set $module @frameworkScope
        if ($LASTEXITCODE -ne 0) { throw 'Could not update module scope.' }
    }
}
if (-not $NativeOnly) {
    & $adb -s $serial shell sh $cli modules $State $module
    if ($LASTEXITCODE -ne 0) { throw "Could not $State the module." }
}
$cpuModule = '/data/adb/modules/device_lab_cpu'
& $adb -s $serial shell test -f /data/misc/device-lab/modules/device_lab_cpu/module.prop
if ($LASTEXITCODE -eq 0) { $cpuModule = '/data/misc/device-lab/modules/device_lab_cpu' }
& $adb -s $serial shell test -d $cpuModule
if ($LASTEXITCODE -eq 0) {
    if ($State -eq 'enable') {
        $scopeFile = Join-Path $PSScriptRoot '..\module\build\namespace-scope.txt'
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($scopeFile), (($scope -replace '/0$', '') -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
        & $adb -s $serial push $scopeFile "$cpuModule/scope.new" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not transfer namespace scope.' }
        & $adb -s $serial shell chmod 0644 "$cpuModule/scope.new"
        if ($LASTEXITCODE -ne 0) { throw 'Could not set namespace scope permissions.' }
        & $adb -s $serial shell chcon u:object_r:system_file:s0 "$cpuModule/scope.new"
        if ($LASTEXITCODE -ne 0) { throw 'Could not label namespace scope.' }
        & $adb -s $serial shell mv "$cpuModule/scope.new" "$cpuModule/scope"
        if ($LASTEXITCODE -ne 0) { throw 'Could not activate namespace scope.' }
        $runtimeScopeFile = Join-Path $PSScriptRoot '..\module\build\runtime-scope.txt'
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($runtimeScopeFile), ($NativeOnlyPackage -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
        $runtimeArmFile = Join-Path $PSScriptRoot '..\module\build\runtime-arm-scope.txt'
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($runtimeArmFile), ($armRuntimeScope -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
        $moduleApk = ((& $adb -s $serial shell pm path $module) -join '').Trim() -replace '^package:', ''
        if ($moduleApk -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') { throw 'Module APK path is unavailable.' }
        $runtimeLibraryFile = Join-Path $PSScriptRoot '..\module\build\runtime-library.txt'
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($runtimeLibraryFile), "$moduleApk!/lib/x86_64/libruntimeprofile.so", [Text.UTF8Encoding]::new($false))
        foreach ($entry in @(@($runtimeScopeFile, 'runtime-scope'), @($runtimeLibraryFile, 'runtime-library'), @($runtimeArmFile, 'runtime-arm-scope'))) {
            & $adb -s $serial push $entry[0] "$cpuModule/$($entry[1])" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not transfer runtime profile configuration.' }
            & $adb -s $serial shell chmod 0644 "$cpuModule/$($entry[1])"
            & $adb -s $serial shell chcon u:object_r:system_file:s0 "$cpuModule/$($entry[1])"
            if ($LASTEXITCODE -ne 0) { throw 'Could not label runtime profile configuration.' }
        }
        & $adb -s $serial shell touch "$cpuModule/enabled"
        & $adb -s $serial shell touch "$cpuModule/uname-enabled"
        & $adb -s $serial shell touch "$cpuModule/proc-enabled"
        & $adb -s $serial shell touch "$cpuModule/openat2-enabled"
        if ($RestrictIsolatedProc) {
            & $adb -s $serial shell touch "$cpuModule/restrict-isolated-proc-enabled"
        } else {
            & $adb -s $serial shell rm -f "$cpuModule/restrict-isolated-proc-enabled"
        }
        if ($IncludeIndependentDetector -or $IncludeExtendedDetectors) {
            & $adb -s $serial shell touch "$cpuModule/detector-enabled"
        } else {
            & $adb -s $serial shell rm -f "$cpuModule/detector-enabled"
        }
    } else {
        & $adb -s $serial shell rm -f "$cpuModule/enabled" "$cpuModule/detector-enabled" "$cpuModule/uname-enabled" "$cpuModule/proc-enabled" "$cpuModule/openat2-enabled" "$cpuModule/restrict-isolated-proc-enabled"
    }
    if ($LASTEXITCODE -ne 0) { throw 'Could not update CPU namespace scope.' }
}
& $adb -s $serial shell sync
if ($LASTEXITCODE -ne 0) { throw 'Could not flush laboratory profile configuration.' }
& $adb -s $serial unroot
& $adb -s $serial wait-for-device

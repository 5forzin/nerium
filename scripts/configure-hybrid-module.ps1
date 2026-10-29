param(
    [string]$Serial = 'emulator-5558',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [switch]$IncludeDuck,
    [switch]$RestrictIsolatedProc
)

$ErrorActionPreference = 'Stop'
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$avd = @(& $adb -s $Serial emu avd name)
if ($avd.Count -eq 0 -or $avd[0].Trim() -ne 'device-lab-playstore-numa-hybrid') {
    throw 'The target is not the isolated Play Store NUMA AVD.'
}
if ((@(& $adb -s $Serial shell getenforce) -join '').Trim() -ne 'Enforcing') {
    throw 'SELinux must be enforcing.'
}
if ((@(& $adb -s $Serial shell su -c id) -join '') -notmatch 'uid=0\(root\)') {
    throw 'Magisk root is unavailable.'
}

$module = '/data/adb/modules/device_lab_cpu'
& $adb -s $Serial shell su -c "test -f $module/module.prop"
if ($LASTEXITCODE -ne 0) { throw 'The namespace module is not installed.' }

$runtimeApk = ((& $adb -s $Serial shell pm path dev.androidlab.module) -join '').Trim() -replace '^package:', ''
if ($runtimeApk -notmatch '^/data/app/[a-zA-Z0-9_~=/+.-]+/base\.apk$') {
    throw 'The runtime APK is not installed.'
}
$packages = @(
    'dev.androidlab.probe',
    'dev.androidlab.rawprobe',
    'dev.androidlab.procprobe',
    'com.reveny.emulator.detection.sample',
    'dev.androidlab.integrityprobe'
)
if ($IncludeDuck) { $packages += 'com.eltavine.duckdetector' }
$armPackages = @()
foreach ($package in $packages) {
    $details = (& $adb -s $Serial shell dumpsys package $package) -join "`n"
    if ($details -match '(?m)^\s*primaryCpuAbi=arm64-v8a\s*$') { $armPackages += $package }
    elseif ($details -notmatch '(?m)^\s*primaryCpuAbi=(x86_64|null)\s*$') {
        throw "Unsupported or missing ABI for $package."
    }
}

$files = @()
try {
    $config = [ordered]@{
        scope = ($packages -join "`n") + "`n"
        'runtime-scope' = ($packages -join "`n") + "`n"
        'runtime-arm-scope' = if ($armPackages.Count -gt 0) { ($armPackages -join "`n") + "`n" } else { '' }
        'runtime-library' = "$runtimeApk!/lib/x86_64/libruntimeprofile.so"
    }
    foreach ($name in $config.Keys) {
        $file = New-TemporaryFile
        $files += $file
        [IO.File]::WriteAllText($file.FullName, $config[$name], [Text.UTF8Encoding]::new($false))
        & $adb -s $Serial push $file.FullName "/data/local/tmp/device-lab-$name" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not transfer $name." }
    }

    $script = New-TemporaryFile
    $files += $script
    $source = @'
#!/system/bin/sh
set -eu
module=/data/adb/modules/device_lab_cpu
for name in scope runtime-scope runtime-arm-scope runtime-library; do
    cp "/data/local/tmp/device-lab-$name" "$module/$name"
    chmod 0644 "$module/$name"
    chcon u:object_r:system_file:s0 "$module/$name"
done
touch "$module/enabled" "$module/uname-enabled" "$module/proc-enabled" "$module/openat2-enabled" "$module/detector-enabled"
__ISOLATED_PROC__
sync
'@
    $restriction = if ($RestrictIsolatedProc) {
        'touch "$module/restrict-isolated-proc-enabled"'
    } else {
        'rm -f "$module/restrict-isolated-proc-enabled"'
    }
    $source = $source.Replace('__ISOLATED_PROC__', $restriction)
    [IO.File]::WriteAllText($script.FullName, $source.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    & $adb -s $Serial push $script.FullName /data/local/tmp/device-lab-configure.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the configuration script.' }
    & $adb -s $Serial shell su -c 'sh /data/local/tmp/device-lab-configure.sh'
    if ($LASTEXITCODE -ne 0) { throw 'Could not activate the laboratory profile.' }
} finally {
    foreach ($file in $files) { Remove-Item -LiteralPath $file.FullName -ErrorAction SilentlyContinue }
}

Write-Output "Configured $($packages.Count) laboratory packages on $Serial."

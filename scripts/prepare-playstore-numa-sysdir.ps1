param(
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CacheRoot = "$env:LOCALAPPDATA\android-device-lab\playstore-numa-hybrid",
    [string]$NumaRoot = "$env:LOCALAPPDATA\android-device-lab\numa-kernel"
)

$ErrorActionPreference = 'Stop'
$avdName = 'device-lab-playstore-numa-hybrid'
$configPath = Join-Path $env:USERPROFILE ".android\avd\$avdName.avd\config.ini"
$stock = Join-Path $SdkRoot 'system-images\android-34\google_apis_playstore\x86_64'
$destination = Join-Path $CacheRoot 'system-images'
$patchedSystem = Join-Path $CacheRoot 'system-playstore-numa.img'
if (-not (Test-Path -LiteralPath $configPath)) { throw 'The isolated Google Play AVD is missing.' }
if (Test-Path -LiteralPath $destination) { throw 'The hybrid system directory already exists.' }
$config = [IO.File]::ReadAllText($configPath)
if ($config -notmatch '(?m)^avd\.id\s*=\s*device-lab-playstore-numa-hybrid\s*$' -or
    $config -notmatch '(?m)^PlayStore\.enabled\s*=\s*yes\s*$' -or
    $config -notmatch '(?m)^image\.sysdir\.1\s*=\s*system-images\\android-34\\google_apis_playstore\\x86_64\\\s*$') {
    throw 'Unexpected isolated AVD configuration.'
}
$sources = [ordered]@{
    'system.img' = $patchedSystem
    'vendor.img' = Join-Path $NumaRoot 'vendor-numa.img'
    'ramdisk.img' = Join-Path $NumaRoot 'ramdisk-numa.img'
    'kernel-ranchu' = Join-Path $NumaRoot 'kernel-numa'
}
foreach ($file in @('advancedFeatures.ini', 'build.prop', 'package.xml', 'source.properties', 'userdata.img', 'encryptionkey.img', 'VerifiedBootParams.textproto')) {
    if (-not (Test-Path -LiteralPath (Join-Path $stock $file))) { throw "Missing stock file: $file" }
}
foreach ($source in $sources.Values) {
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing source image: $source" }
}
New-Item -ItemType Directory -Path $destination -Force | Out-Null
foreach ($file in @('advancedFeatures.ini', 'build.prop', 'package.xml', 'source.properties', 'userdata.img', 'encryptionkey.img', 'VerifiedBootParams.textproto')) {
    Copy-Item -LiteralPath (Join-Path $stock $file) -Destination (Join-Path $destination $file)
}
foreach ($name in $sources.Keys) {
    New-Item -ItemType HardLink -Path (Join-Path $destination $name) -Target $sources[$name] | Out-Null
}
$config = $config -replace '(?m)^image\.sysdir\.1\s*=.*$', ('image.sysdir.1=' + $destination.Replace('\', '/') + '/')
[IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
Write-Output $destination

param([string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk")
$ErrorActionPreference = 'Stop'
$cache = Join-Path $env:LOCALAPPDATA 'android-device-lab\numa-kernel'
$destination = Join-Path $cache 'system-images'
$stock = Join-Path $SdkRoot 'system-images\android-34\google_apis\x86_64'
$configPath = Join-Path $cache 'avd\device-lab-numa.avd\config.ini'
if (Test-Path -LiteralPath $destination) { throw 'The experimental system directory already exists.' }
foreach ($file in @('kernel-numa', 'ramdisk-numa.img', 'system-numa.img', 'vendor-numa.img')) {
    if (-not (Test-Path -LiteralPath (Join-Path $cache $file))) { throw "Missing built image: $file" }
}
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($file in @('advancedFeatures.ini', 'build.prop', 'package.xml', 'source.properties', 'userdata.img', 'encryptionkey.img', 'VerifiedBootParams.textproto')) {
    Copy-Item -LiteralPath (Join-Path $stock $file) -Destination (Join-Path $destination $file)
}
foreach ($pair in @(@('system.img', 'system-numa.img'), @('vendor.img', 'vendor-numa.img'), @('ramdisk.img', 'ramdisk-numa.img'), @('kernel-ranchu', 'kernel-numa'))) {
    New-Item -ItemType HardLink -Path (Join-Path $destination $pair[0]) -Target (Join-Path $cache $pair[1]) | Out-Null
}
$config = [IO.File]::ReadAllText($configPath)
if ($config -notmatch '(?m)^avd\.id\s*=\s*device-lab-numa\s*$') { throw 'Unexpected experimental AVD configuration.' }
$config = $config -replace '(?m)^image\.sysdir\.1\s*=.*$', ('image.sysdir.1 = ' + $destination.Replace('\', '/') + '/')
[IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
Write-Output $destination

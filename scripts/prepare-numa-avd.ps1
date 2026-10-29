param([string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk")
$ErrorActionPreference = 'Stop'
$source = Join-Path $env:USERPROFILE '.android\avd\device-lab-api34.avd'
$destination = Join-Path $env:LOCALAPPDATA 'android-device-lab\numa-kernel\avd\device-lab-numa.avd'
$registration = Join-Path $env:USERPROFILE '.android\avd\device-lab-numa.ini'
if (Test-Path -LiteralPath $destination) { throw 'The experimental AVD already exists; inspect it before reusing it.' }
if (Test-Path -LiteralPath $registration) { throw 'An AVD with this name is already registered.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
foreach ($line in (& $adb devices)) {
    if ($line -match '^(emulator-\d+)\s+device') {
        $serial = $Matches[1]
        $name = @(& $adb -s $serial emu avd name)
        if ($name[0].Trim() -eq 'device-lab-api34') { throw 'Stop the source laboratory AVD before cloning its data.' }
    }
}
$qemuImg = Join-Path $SdkRoot 'emulator\qemu-img.exe'
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($file in @('userdata.img', 'version_num.cache')) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $destination $file)
}
foreach ($file in @('userdata-qemu.img', 'encryptionkey.img', 'cache.img')) {
    # Materialize each original overlay as the clone's base disk. The emulator
    # creates its own overlays and would discard a standalone .qcow2 overlay.
    & $qemuImg convert -O qcow2 (Join-Path $source ($file + '.qcow2')) (Join-Path $destination $file)
    if ($LASTEXITCODE -ne 0) { throw "Could not create a standalone copy of $file." }
}
foreach ($directory in @('data', 'modem_simulator')) {
    Copy-Item -LiteralPath (Join-Path $source $directory) -Destination (Join-Path $destination $directory) -Recurse
}
$config = [IO.File]::ReadAllText((Join-Path $source 'config.ini'))
$config = $config -replace '(?m)^avd\.id\s*=.*$', 'avd.id = device-lab-numa'
$config = $config -replace '(?m)^avd\.name\s*=.*$', 'avd.name = device-lab-numa'
[IO.File]::WriteAllText((Join-Path $destination 'config.ini'), $config, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($registration, "avd.ini.encoding=UTF-8`npath=$destination`ntarget=android-34`n", [Text.UTF8Encoding]::new($false))
Write-Output $destination

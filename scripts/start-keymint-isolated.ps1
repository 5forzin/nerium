#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{1,50}$')][string]$Name,
    [string]$RuntimeRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) '.local\keymint-v42'),
    [switch]$LabSoftwareAttestation,
    [string]$BackendPath = (Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v44\build-windows-llvm18\keymint_pipe_backend.exe'),
    [ValidateRange(1, 600)][int]$StartupTimeoutSeconds = 180
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runtime = [IO.Path]::GetFullPath($RuntimeRoot)
$ownerPath = Join-Path $runtime ($Name+'-owner.json')
$pendingPath = Join-Path $runtime ($Name+'-starting.json')
$failurePath = Join-Path $runtime ($Name+'-failed.json')
$emulatorOutput = Join-Path $runtime ($Name+'-emulator.stdout.log')
$emulatorError = Join-Path $runtime ($Name+'-emulator.stderr.log')
$backendOutput = Join-Path $runtime ($Name+'-backend.stdout.log')
$backendError = Join-Path $runtime ($Name+'-backend.stderr.log')
foreach ($path in @($ownerPath, $pendingPath, $failurePath, $emulatorOutput, $emulatorError, $backendOutput, $backendError)) {
    if (Test-Path -LiteralPath $path) { throw 'The launch name has already been used.' }
}
$backend = [IO.Path]::GetFullPath($BackendPath)
if (-not (Test-Path -LiteralPath $backend -PathType Leaf)) { throw 'The readiness-enabled KeyMint backend is missing.' }
$manifest = Get-Content -Raw -LiteralPath (Join-Path $runtime 'clone-manifest.json') | ConvertFrom-Json
if ($manifest.state -cne 'prepared') { throw 'The isolated clone has not been prepared.' }
$registration = Join-Path $env:USERPROFILE '.android\avd\device-lab-keymint-v42.ini'
$registeredPath = [regex]::Match((Get-Content -Raw -LiteralPath $registration), '(?m)^path=(.+)\r?$').Groups[1].Value.Trim()
$expectedAvdPath = Join-Path $runtime 'avd\device-lab-keymint-v42.avd'
if (-not $registeredPath -or [IO.Path]::GetFullPath($registeredPath) -cne [IO.Path]::GetFullPath($expectedAvdPath)) {
    throw 'Select the RuntimeRoot matching the registered isolated AVD.'
}
$sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$devices = (& (Join-Path $sdk 'platform-tools\adb.exe') devices) -join "`n"
if ($LASTEXITCODE -ne 0 -or $devices -match '(?m)^emulator-5586\s') { throw 'The isolated emulator port is unavailable.' }
if (Get-NetTCPConnection -LocalPort 5586 -State Listen -ErrorAction SilentlyContinue) { throw 'The isolated console port is already bound.' }
$launchRoot = Join-Path $runtime 'launch'
New-Item -ItemType Directory -Path $launchRoot -Force | Out-Null
$kernelSource = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v13\kernel-platform'
$ramdiskSource = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v14\ramdisk-platform.img'
$launchInputs = [ordered]@{}
foreach ($entry in @(@('kernel-platform',$kernelSource),@('ramdisk-platform.img',$ramdiskSource))) {
    $destination = Join-Path $launchRoot $entry[0]
    if (-not (Test-Path -LiteralPath $destination)) { Copy-Item -LiteralPath $entry[1] -Destination $destination }
    $sourceHash = (Get-FileHash -LiteralPath $entry[1] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceHash) { throw 'A copied launch input differs from the preserved platform input.' }
    $launchInputs[$entry[0]]=$sourceHash
}
$pipe = 'adl-keymint-v42-' + [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(8)).ToLowerInvariant()
$arguments = @('-avd','device-lab-keymint-v42','-port','5586','-no-window','-no-snapshot','-no-audio','-no-boot-anim',
    '-feature','-QuickbootFileBacked',
    '-cores','4','-memory','1536','-gpu','host','-camera-back','none','-camera-front','none',
    '-kernel',('"'+(Join-Path $launchRoot 'kernel-platform')+'"'),
    '-ramdisk',('"'+(Join-Path $launchRoot 'ramdisk-platform.img')+'"'),
    '-qemu','-chardev',('pipe,id=kmbridge,path='+$pipe),'-device','virtio-serial-pci,id=kmbridge,ioeventfd=off',
    '-device','virtserialport,bus=kmbridge.0,chardev=kmbridge,nr=1,name=org.android-device-lab.keymint')
$emulator = $null
$client = $null
$owner = [ordered]@{schema_version=1;name=$Name;started_at=[DateTimeOffset]::UtcNow.ToString('o');
    pipe_name=$pipe;serial='emulator-5586';avd='device-lab-keymint-v42';runtime=$runtime;launch_input_sha256=$launchInputs;
    lab_software_attestation=[bool]$LabSoftwareAttestation;quickboot_file_backed=$false;startup_state='starting'}
try {
    $emulator = Start-Process -FilePath (Join-Path $sdk 'emulator\emulator.exe') -ArgumentList $arguments -WindowStyle Hidden `
        -RedirectStandardOutput $emulatorOutput -RedirectStandardError $emulatorError -PassThru
    $owner.emulator_pid = $emulator.Id
    [IO.File]::WriteAllText($pendingPath,($owner|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    $savedPath = $env:PATH
    try {
        $env:PATH = (Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v41\llvm-mingw-20240619-ucrt-x86_64\bin')+';'+$savedPath
        $backendArguments = @($pipe)
        if ($LabSoftwareAttestation) { $backendArguments += '--lab-software-attestation' }
        $client = Start-Process -FilePath $backend -ArgumentList $backendArguments -WindowStyle Hidden `
            -RedirectStandardOutput $backendOutput -RedirectStandardError $backendError -PassThru
    } finally { $env:PATH=$savedPath }
    $owner.backend_pid = $client.Id
    $owner.backend_sha256 = (Get-FileHash -LiteralPath $backend -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($pendingPath,($owner|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $serving = $false
    while ($deadline.Elapsed.TotalSeconds -lt $StartupTimeoutSeconds) {
        $emulator.Refresh()
        $client.Refresh()
        if ($emulator.HasExited -or $client.HasExited) { throw 'The isolated emulator or KeyMint backend exited before readiness.' }
        if (Test-Path -LiteralPath $backendOutput) {
            $serving = @(
                Get-Content -LiteralPath $backendOutput -ErrorAction SilentlyContinue |
                    Where-Object { $_ -ceq '{"state":"serving","completed_frames":1,"security_level":"SOFTWARE"}' }
            ).Count -eq 1
            if ($serving) { break }
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $serving) { throw 'The KeyMint backend did not complete a guest request before the deadline.' }
    $emulator.Refresh()
    $client.Refresh()
    if ($emulator.HasExited -or $client.HasExited) { throw 'The isolated emulator or KeyMint backend exited after the first response.' }
    $owner.startup_state = 'ready'
    $owner.completed_frames_at_ready = 1
    [IO.File]::WriteAllText($pendingPath,($owner|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($pendingPath,$ownerPath)
    [pscustomobject]@{emulator_pid=$emulator.Id;backend_pid=$client.Id;serial='emulator-5586';owner_path=$ownerPath;startup_state='ready'}
} catch {
    $failure = $_.Exception.Message
    foreach ($process in @($client, $emulator)) {
        if ($null -eq $process) { continue }
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(5000)
            }
        } catch {}
    }
    $owner.startup_state = 'failed'
    $owner.error = $failure
    [IO.File]::WriteAllText($failurePath,($owner|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    throw
}

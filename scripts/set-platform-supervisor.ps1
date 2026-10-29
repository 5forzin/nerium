param(
    [ValidateSet('enable','disable')][string]$State = 'enable',
    [string]$Name = 'strict-v13-platform-contract-enabled',
    [string]$Serial = 'emulator-5556',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$BinaryPath = "$env:LOCALAPPDATA\android-device-lab\research-v13\platform-seccomp-check"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$avd = @(& $adb -s $Serial emu avd name)[0].Trim()
if ($avd -ne 'device-lab-numa') { throw 'This experiment is restricted to the dedicated NUMA AVD.' }
& $adb -s $Serial root
& $adb -s $Serial wait-for-device
try {
    & $adb -s $Serial shell 'rm -f /data/misc/device-lab/platform-supervisor-requested /data/misc/device-lab/platform-supervisor-boot'
    if ($LASTEXITCODE -ne 0) { throw 'Could not clear the previous platform activation.' }
    if ($State -eq 'disable') { Write-Output 'Platform domain disabled; restart measured applications.'; return }
    $modulePath = '/data/adb/modules/device_lab_cpu'
    & $adb -s $Serial shell test -f /data/misc/device-lab/modules/device_lab_cpu/module.prop
    if ($LASTEXITCODE -eq 0) { $modulePath = '/data/misc/device-lab/modules/device_lab_cpu' }
    $metadata = (& $adb -s $Serial shell cat "$modulePath/module.prop") -join "`n"
    if ($LASTEXITCODE -ne 0 -or $metadata -notmatch '(?m)^version=0\.(11\.0|12\.[0-2])\s*$') { throw 'Install a supported namespace package before enabling this backend.' }
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) { throw 'Build the independent platform-seccomp-check fixture first.' }
    $hash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    & $adb -s $Serial push $BinaryPath /data/misc/device-lab/platform-seccomp-check | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not transfer the platform contract fixture.' }
    & $adb -s $Serial shell 'chown 0:0 /data/misc/device-lab/platform-seccomp-check; chmod 0700 /data/misc/device-lab/platform-seccomp-check; chcon u:object_r:system_file:s0 /data/misc/device-lab/platform-seccomp-check'
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure the platform contract fixture.' }
    $remoteHash = ((& $adb -s $Serial shell sha256sum /data/misc/device-lab/platform-seccomp-check) -split '\s+')[0]
    if ($LASTEXITCODE -ne 0 -or $remoteHash -ne $hash) { throw 'The installed platform fixture does not match the built binary.' }
    $raw = & $adb -s $Serial shell /data/misc/device-lab/platform-seccomp-check --require-platform
    $status = $LASTEXITCODE
    $report = ($raw -join "`n") | ConvertFrom-Json
    $report | Add-Member -NotePropertyName binary_sha256 -NotePropertyValue $hash
    $destination = Join-Path $PSScriptRoot "..\reports\$Name.json"
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $destination -Encoding utf8
    if ($status -ne 0 -or -not $report.platform_domain_supported -or $report.failed -ne 0 -or $report.unavailable -ne 0 -or $report.passed -ne 12) {
        throw 'The complete platform contract did not pass; activation remains disabled.'
    }
    & $adb -s $Serial shell 'touch /data/misc/device-lab/platform-supervisor-requested; chmod 0600 /data/misc/device-lab/platform-supervisor-requested; cat /proc/sys/kernel/random/boot_id > /data/misc/device-lab/platform-supervisor-boot; chmod 0600 /data/misc/device-lab/platform-supervisor-boot; sync'
    if ($LASTEXITCODE -ne 0) { throw 'Could not bind platform activation to this boot.' }
    Write-Output 'Platform domain enabled after all 12 independent contract checks; restart measured applications.'
} finally {
    & $adb -s $Serial unroot | Out-Null
    & $adb -s $Serial wait-for-device
}

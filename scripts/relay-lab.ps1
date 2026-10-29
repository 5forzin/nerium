#requires -Version 7.0
param(
    [Parameter(Mandatory = $true)][ValidateSet('Pair', 'Invoke', 'Revoke', 'Status')][string]$Action,
    [string]$ConfigPath = "$env:LOCALAPPDATA\android-device-lab\research-v36\cloud-config.json",
    [string]$SessionPath = "$env:LOCALAPPDATA\android-device-lab\research-v36\session.json",
    [string]$Serial,
    [ValidateSet('echo_sha256', 'play_integrity')][string]$Operation = 'echo_sha256',
    [string]$Name,
    [ValidateRange(30,300)][int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\relay\RelayHost.psm1') -Force
try {
    switch ($Action) {
        'Pair' {
            if (-not $Serial) { throw 'Relay error: ADB_SERIAL_REQUIRED' }
            New-RelayPair -ConfigPath $ConfigPath -SessionPath $SessionPath -Serial $Serial `
                -ApkPath (Join-Path $PSScriptRoot '..\relayworker\build\outputs\apk\debug\relayworker-debug.apk')
        }
        'Invoke' {
            if (-not $Name) { throw 'Relay error: REPORT_NAME_REQUIRED' }
            $result = Invoke-RelayJob -ConfigPath $ConfigPath -SessionPath $SessionPath -Operation $Operation `
                -Name $Name -TimeoutSeconds $TimeoutSeconds -ReportsDirectory (Join-Path $PSScriptRoot '..\reports')
            $result
            if ($result.status -ne 'completed') { exit 1 }
        }
        'Revoke' { Revoke-RelaySession -ConfigPath $ConfigPath -SessionPath $SessionPath }
        'Status' { Get-RelayStatus -ConfigPath $ConfigPath -SessionPath $SessionPath }
    }
} catch {
    if ($_.Exception.Message -cmatch '^Relay error: [A-Z0-9_]+$') { Write-Error $_.Exception.Message }
    else { Write-Error 'Relay error: OPERATION_FAILED' }
    exit 1
}

#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$SessionPath,
    [Parameter(Mandatory)][string]$ReportsDirectory,
    [Parameter(Mandatory)][ValidatePattern('^requester_[a-f0-9]{32}$')][string]$Name,
    [Parameter(Mandatory)][ValidateSet('echo_sha256','play_integrity')][string]$Operation,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ChallengeBase64Url,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$JobId,
    [Parameter(Mandatory)][ValidateRange(30,120)][int]$TimeoutSeconds,
    [Parameter(Mandatory)][ValidateRange(1,9007199254740991)][long]$DeadlineAtMs
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
try {
    if ($Name -cne ('requester_' + $JobId)) { throw 'RUNNER_NAME_MISMATCH' }
    $bytes = [Convert]::FromBase64String($ChallengeBase64Url.Replace('-', '+').Replace('_', '/') + '=')
    $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    if ($bytes.Length -ne 32 -or $canonical -cne $ChallengeBase64Url) { throw 'RUNNER_CHALLENGE_INVALID' }
    Import-Module (Join-Path $PSScriptRoot '..\relay\RelayHost.psm1') -Force -WarningAction SilentlyContinue
    $command = Get-Command Invoke-RelayJob -ErrorAction Stop
    if (!$command.Parameters.ContainsKey('ChallengeBase64Url') -or !$command.Parameters.ContainsKey('JobId') -or !$command.Parameters.ContainsKey('DeadlineAtMs')) { throw 'RUNNER_HOST_INTERFACE_MISSING' }
    $result = Invoke-RelayJob -ConfigPath $ConfigPath -SessionPath $SessionPath -ReportsDirectory $ReportsDirectory `
        -Name $Name -Operation $Operation -ChallengeBase64Url $ChallengeBase64Url -JobId $JobId -TimeoutSeconds $TimeoutSeconds -DeadlineAtMs $DeadlineAtMs
    $expected = [IO.Path]::GetFullPath((Join-Path $ReportsDirectory ($Name + '.json')))
    if ($null -eq $result -or [IO.Path]::GetFullPath([string]$result.report_path) -cne $expected) { throw 'RUNNER_REPORT_PATH_MISMATCH' }
    if (!(Test-Path -LiteralPath $expected -PathType Leaf) -or (Get-Item -LiteralPath $expected).Length -gt 65536) { throw 'RUNNER_REPORT_INVALID' }
    $report = [IO.File]::ReadAllText($expected, [Text.Encoding]::UTF8) | ConvertFrom-Json -AsHashtable -Depth 30
    if ($report.ContainsKey('token') -or $report.ContainsKey('idToken') -or $report.ContainsKey('refreshToken')) { throw 'RUNNER_UNSANITIZED_REPORT' }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $report -Depth 30 -Compress))
    exit 0
} catch {
    $code = if ($_.Exception.Message -cmatch '^(?:Relay error: )?([A-Z0-9_]+)$') { $Matches[1] } else { 'RUNNER_FAILED' }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{schema_version = 1; status = 'failed'; error = @{code = $code}} -Compress))
    exit 1
}

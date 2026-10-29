#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Generation
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false,$true)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$startup = [Diagnostics.Stopwatch]::StartNew()
$hostModule = $null
$config = $null
$count = 0L

function Require([bool]$Condition,[string]$Code) { if(!$Condition){throw $Code} }
function Read-PrivateJson([string]$Path) {
    $file = Get-Item -LiteralPath $Path
    Require ($file.Length -gt 0 -and $file.Length -le 65536 -and !($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'SERVICE_PRIVATE_FILE'
    [IO.File]::ReadAllText($file.FullName,[Text.UTF8Encoding]::new($false,$true)) | ConvertFrom-Json -AsHashtable -Depth 30
}
function Read-LineBounded {
    $line = [Text.StringBuilder]::new()
    while(($value=[Console]::In.Read()) -ne -1) {
        if($value -eq 10) { return $line.ToString().TrimEnd([char]13) }
        Require ($value -ne 0 -and $line.Length -lt 8192) 'SERVICE_INPUT_LIMIT'
        [void]$line.Append([char]$value)
    }
    Require ($line.Length -eq 0) 'SERVICE_INPUT_TRUNCATED'
    return $null
}
function Send-Frame($Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 35 -Compress
    Require ([Text.Encoding]::UTF8.GetByteCount($json) -le 65536) 'SERVICE_OUTPUT_LIMIT'
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}
function Frame([string]$Type) {
    [ordered]@{schema_version=1;type=$Type;generation=$Generation;pair_id=$config.pair_id;session_id=$config.session_id;pid=$PID}
}
function Safe-Code($ErrorRecord) {
    if($ErrorRecord.Exception.Message -cmatch '^(?:Relay (?:session(?: error)?|error): )?([A-Z0-9_]{1,80})$'){return $Matches[1]}
    return 'SERVICE_EXECUTION_FAILED'
}
function Integer($Value) {
    Require (($Value -is [int] -or $Value -is [long]) -and $Value -ge 0 -and $Value -le 9007199254740991L) 'SERVICE_INTEGER'
    [long]$Value
}
function Hash([byte[]]$Bytes) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function Metrics {
    $result = Get-RelayHostSessionMetrics
    $result['service_requests_completed'] = $count
    $result
}

try {
    $ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
    $privateRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'android-device-lab')) + [IO.Path]::DirectorySeparatorChar
    Require ($ConfigPath.StartsWith($privateRoot,[StringComparison]::OrdinalIgnoreCase)) 'SERVICE_CONFIG_LOCATION'
    $config = Read-PrivateJson $ConfigPath
    Require ($config.schema_version -eq 1 -and $config.pair_id -cmatch '^[a-f0-9]{32}$' -and $config.session_id -cmatch '^[a-f0-9]{32}$') 'SERVICE_CONFIG_IDENTITY'
    $cloudPath = [IO.Path]::GetFullPath($config.cloud_config_path)
    $sessionPath = [IO.Path]::GetFullPath($config.worker_session_path)
    foreach($path in @($cloudPath,$sessionPath)) { Require ($path.StartsWith($privateRoot,[StringComparison]::OrdinalIgnoreCase)) 'SERVICE_CREDENTIAL_LOCATION' }
    $cloudHash = (Get-FileHash -LiteralPath $cloudPath -Algorithm SHA256).Hash
    $sessionHash = (Get-FileHash -LiteralPath $sessionPath -Algorithm SHA256).Hash
    $session = Read-PrivateJson $sessionPath
    Require ($session.session_id -ceq $config.session_id -and !$session.revoked -and $config.expires_at_ms -le $session.expires_at_ms) 'SERVICE_SESSION_IDENTITY'
    $hostModule = Import-Module (Join-Path $PSScriptRoot '..\relay\RelayHost.psm1') -Force -PassThru
    Initialize-RelayHostContext -ConfigPath $cloudPath -SessionPath $sessionPath -Account $config.auth_account -ConfigurationName $config.auth_configuration
    $ready = Frame 'ready'
    $ready.service_metrics = Metrics
    $ready.startup_metrics = @{service_startup_ms=$startup.ElapsedMilliseconds;service_imports=1L}
    Send-Frame $ready

    while($null -ne ($line=Read-LineBounded)) {
        $rpc = $line | ConvertFrom-Json -AsHashtable -Depth 5
        Require ($rpc -is [Collections.IDictionary]) 'SERVICE_REQUEST_OBJECT'
        $keys = @('schema_version','type','generation','rpc_id','pair_id','session_id','request_id','request_sha256','operation','challenge_base64url','timeout_ms','deadline_at_ms')
        Require ($rpc.Count -eq $keys.Count -and @([regex]::Matches($line,'"(?:[^"\\]|\\.)*"\s*:')).Count -eq $keys.Count) 'SERVICE_REQUEST_FIELDS'
        foreach($key in $keys) { Require (@($rpc.Keys) -ccontains $key) 'SERVICE_REQUEST_FIELDS' }
        Require ($rpc.schema_version -eq 1 -and $rpc.type -ceq 'execute' -and $rpc.generation -ceq $Generation -and $rpc.pair_id -ceq $config.pair_id -and $rpc.session_id -ceq $config.session_id) 'SERVICE_REQUEST_BINDING'
        Require ($rpc.rpc_id -cmatch '^[a-f0-9]{32}$' -and $rpc.request_id -cmatch '^[a-f0-9]{32}$' -and $rpc.request_sha256 -cmatch '^[a-f0-9]{64}$') 'SERVICE_REQUEST_ID'
        Require ($rpc.operation -cin @('echo_sha256','play_integrity') -and $rpc.challenge_base64url -cmatch '^[A-Za-z0-9_-]{43}$') 'SERVICE_REQUEST_OPERATION'
        $challenge = [Convert]::FromBase64String($rpc.challenge_base64url.Replace('-','+').Replace('_','/')+'=')
        Require ($challenge.Length -eq 32 -and [Convert]::ToBase64String($challenge).TrimEnd('=').Replace('+','-').Replace('/','_') -ceq $rpc.challenge_base64url) 'SERVICE_CHALLENGE'
        $timeout = Integer $rpc.timeout_ms
        $deadline = Integer $rpc.deadline_at_ms
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Require ($timeout -ge 30000 -and $timeout -le 120000 -and $deadline -gt $now -and $deadline -le $config.expires_at_ms -and $deadline -le $now+$timeout) 'SERVICE_DEADLINE'
        $canonical = @('r1',$config.pair_id,$rpc.request_id,$rpc.operation,$rpc.challenge_base64url,[string]$timeout) -join "`n"
        Require ((Hash ([Text.Encoding]::UTF8.GetBytes($canonical))) -ceq $rpc.request_sha256) 'SERVICE_REQUEST_HASH'
        Require ((Get-FileHash -LiteralPath $cloudPath -Algorithm SHA256).Hash -ceq $cloudHash -and (Get-FileHash -LiteralPath $sessionPath -Algorithm SHA256).Hash -ceq $sessionHash) 'SERVICE_CONFIGURATION_CHANGED'
        $frame = Frame 'result'
        foreach($key in @('rpc_id','request_id','request_sha256')) { $frame[$key] = $rpc[$key] }
        try {
            $name = 'requester_'+$rpc.request_id
            $seconds = [int][Math]::Max(30,[Math]::Min(120,[Math]::Ceiling(($deadline-$now)/1000)))
            $result = Invoke-RelayJob -ConfigPath $cloudPath -SessionPath $sessionPath -ReportsDirectory $config.reports_directory `
                -Name $name -Operation $rpc.operation -ChallengeBase64Url $rpc.challenge_base64url -JobId $rpc.request_id -TimeoutSeconds $seconds -DeadlineAtMs $deadline
            $expected = [IO.Path]::GetFullPath((Join-Path $config.reports_directory ($name+'.json')))
            Require ($null -ne $result -and [IO.Path]::GetFullPath($result.report_path) -ceq $expected) 'SERVICE_REPORT_PATH'
            $report = Read-PrivateJson $expected
            $allowed = @('schema_version','operation','job_id','session_id','worker_uid','request_sha256','origin','requester_integrity_verified','worker_package','created_at_ms','expires_at_ms','status','challenge_sha256','broker_observed_elapsed_ms','broker_observed_completed_at_ms','lease_id','attempt','worker_execution_state','worker_version_code','worker_apk_cert_sha256','execution_elapsed_ms','completed_at_ms','token_sha256','request_binding','nonce_matches','request_timestamp_ms','worker_verdict','error','cleanup_state','host_timings')
            foreach($key in $report.Keys) { Require ($allowed -ccontains $key) 'SERVICE_REPORT_FIELDS' }
            $frame.report = $report
        } catch { $frame.error = @{code=(Safe-Code $_)} }
        $count++
        $frame.service_metrics = Metrics
        Send-Frame $frame
    }
} catch {
    $code = Safe-Code $_
    if($config -and $config.ContainsKey('pair_id') -and $config.ContainsKey('session_id')) {
        try { $failure=Frame 'error'; $failure.error=@{code=$code}; Send-Frame $failure } catch {}
    }
    [Console]::Error.WriteLine('Relay service: '+$code)
    exit 1
} finally {
    if($hostModule) { try { Close-RelayHostContext } catch {} }
}

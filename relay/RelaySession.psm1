#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Context = $null
$script:PlayScope = 'https://www.googleapis.com/auth/playintegrity'

function Get-SessionMonotonic { [Environment]::TickCount64 }
function Get-SessionEpoch { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
function Assert-Session([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw "Relay session: $Code" }
}
function Require-Context {
    Assert-Session ($null -ne $script:Context) 'NOT_INITIALIZED'
    Assert-Session ((Get-SessionMonotonic) -lt $script:Context.deadline) 'SESSION_EXPIRED'
    $script:Context
}

function Initialize-RelaySessionTransport {
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$ConfigurationName,
        [Parameter(Mandatory)][string]$ProjectId, [Parameter(Mandatory)][string]$SignerServiceAccount,
        [Parameter(Mandatory)][long]$ExpiresAtMs)
    Assert-Session ($null -eq $script:Context) 'ALREADY_INITIALIZED'
    Assert-Session ($Account -cmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,126}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$') 'ACCOUNT_FORMAT'
    Assert-Session ($ConfigurationName -cmatch '^[a-z][a-z0-9_-]{0,62}$') 'CONFIGURATION_FORMAT'
    Assert-Session ($ProjectId -cmatch '^[a-z][a-z0-9-]{4,61}[a-z0-9]$') 'PROJECT_FORMAT'
    Assert-Session ($SignerServiceAccount -cmatch '^[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com$') 'SIGNER_FORMAT'
    $remaining = $ExpiresAtMs - (Get-SessionEpoch)
    Assert-Session ($remaining -gt 0 -and $remaining -le 1800000) 'SESSION_TTL'
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $script:Context = @{account=$Account; configuration=$ConfigurationName; project=$ProjectId;
        signer=$SignerServiceAccount; deadline=(Get-SessionMonotonic)+$remaining; client=$client; handler=$handler;
        cache=@{}; metrics=[ordered]@{cache_hits=0L;cache_misses=0L;source_fetches=0L;source_fetch_ms=0L;
            introspections=0L;introspection_ms=0L;exchanges=0L;exchange_ms=0L;invalidations=0L;
            http_requests=0L;http_failures=0L}}
}

function Get-TokenKey([string]$ServiceAccount, [string]$Scope) {
    $context = Require-Context
    if ($ServiceAccount) {
        Assert-Session ($ServiceAccount -ceq $context.signer -and $Scope -ceq $script:PlayScope) 'TARGET_SCOPE_NOT_ALLOWED'
    } else { Assert-Session (-not $Scope) 'SOURCE_SCOPE_NOT_ALLOWED' }
    @($context.account,$context.configuration,$context.project,$context.signer,$ServiceAccount,$Scope) -join "`n"
}

function Get-RelaySessionHttpClient {
    (Require-Context).client
}

function Invalidate-RelaySessionToken {
    param([string]$ServiceAccount, [string]$Scope)
    $key = Get-TokenKey $ServiceAccount $Scope
    $context = Require-Context
    if ($context.cache.ContainsKey($key)) {
        $context.cache[$key].token = $null
        $context.cache.Remove($key)
        $context.metrics.invalidations++
    }
}

function Invoke-SessionJson {
    param([string]$Uri, [string]$Json, [string]$AccessToken, [string]$InvalidationAccount,
        [string]$InvalidationScope, [switch]$Form, [int]$MaxBytes=65536)
    $context = Require-Context
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,$Uri)
    $remaining = [Math]::Min(20000,$context.deadline-(Get-SessionMonotonic))
    Assert-Session ($remaining -gt 0) 'SESSION_EXPIRED'
    $cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromMilliseconds($remaining))
    try {
        if ($AccessToken) { $null = $request.Headers.TryAddWithoutValidation('x-goog-user-project',$context.project) }
        if ($AccessToken) { $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$AccessToken) }
        $type = if ($Form) {'application/x-www-form-urlencoded'} else {'application/json'}
        $request.Content=[Net.Http.StringContent]::new($Json,[Text.Encoding]::UTF8,$type)
        $context.metrics.http_requests++
        try {
            $response=$context.client.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
            try {
                $received=Get-SessionMonotonic
                $date=if($null -ne $response.Headers.Date){([DateTimeOffset]$response.Headers.Date).ToUnixTimeMilliseconds()}else{0L}
                $status=[int]$response.StatusCode
                if($status -eq 401){Invalidate-RelaySessionToken -ServiceAccount $InvalidationAccount -Scope $InvalidationScope}
                Assert-Session ($status -ge 200 -and $status -lt 300) ("HTTP_"+$status)
                $stream=$response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
                $memory=[IO.MemoryStream]::new()
                try {
                    $buffer=[byte[]]::new(4096)
                    while(($count=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
                        Assert-Session ($memory.Length+$count -le $MaxBytes) 'RESPONSE_SIZE'
                        $memory.Write($buffer,0,$count)
                    }
                    $body=[Text.Encoding]::UTF8.GetString($memory.ToArray())|ConvertFrom-Json -Depth 12
                }finally{$stream.Dispose();$memory.Dispose()}
                @{body=$body;server_date_ms=$date;received_at_ms=$received}
            }finally{$response.Dispose()}
        }catch{
            $context.metrics.http_failures++
            if($_.Exception.Message -cmatch '^Relay session: [A-Z0-9_]+$'){throw $_.Exception.Message}
            throw 'Relay session: HTTP_TRANSPORT_FAILED'
        }
    }finally{$request.Dispose();$cancel.Dispose()}
}

function Fetch-SessionSourceToken {
    param($Context)
    $gcloud=Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
    Assert-Session (Test-Path -LiteralPath $gcloud -PathType Leaf) 'GCLOUD_MISSING'
    Assert-Session ($gcloud -notmatch '["%\r\n]') 'GCLOUD_PATH_FORMAT'
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $Context.metrics.source_fetches++
    try {
        $info=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\cmd.exe'))
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        # cmd.exe parses its command string itself; validated flags contain no shell metacharacters.
        $info.Arguments='/d /s /c ""'+$gcloud+'" auth print-access-token --quiet --account='+$Context.account+' --configuration='+$Context.configuration+'"'
        $process=[Diagnostics.Process]::new();$process.StartInfo=$info
        try{
            Assert-Session ($process.Start()) 'SOURCE_FETCH_START'
            $output=$process.StandardOutput.ReadToEndAsync();$errorOutput=$process.StandardError.ReadToEndAsync()
            $timeout=[int][Math]::Max(1,[Math]::Min(20000,$Context.deadline-(Get-SessionMonotonic)))
            if(-not $process.WaitForExit($timeout)){$process.Kill($true);throw 'Relay session: SOURCE_FETCH_TIMEOUT'}
            $token=$output.GetAwaiter().GetResult().Trim();$null=$errorOutput.GetAwaiter().GetResult()
            Assert-Session ($process.ExitCode -eq 0 -and $token.Length -gt 0 -and $token.Length -le 32768) 'SOURCE_FETCH_FAILED'
        }finally{$process.Dispose()}
    }finally{$watch.Stop();$Context.metrics.source_fetch_ms+=$watch.ElapsedMilliseconds}
    $watch.Restart()
    $Context.metrics.introspections++
    try {
        $result=Invoke-SessionJson -Uri 'https://oauth2.googleapis.com/tokeninfo' -Json ('access_token='+[Uri]::EscapeDataString($token)) -Form
        $info=$result.body
        Assert-Session ($info.email -ieq $Context.account) 'SOURCE_IDENTITY_MISMATCH'
        $seconds=0L
        Assert-Session ([long]::TryParse([string]$info.expires_in,[ref]$seconds) -and $seconds -gt 60 -and $seconds -le 43200) 'SOURCE_EXPIRY_INVALID'
        @{token=$token;deadline=[Math]::Min($Context.deadline,$result.received_at_ms+($seconds-60)*1000L)}
    }finally{$token=$null;$watch.Stop();$Context.metrics.introspection_ms+=$watch.ElapsedMilliseconds}
}

function Exchange-SessionSignerToken {
    param($Context,[string]$SourceToken,[string]$Scope)
    $Context.metrics.exchanges++
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $uri='https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/'+$Context.signer+':generateAccessToken'
        $body=@{scope=@($Scope);lifetime='3600s'}|ConvertTo-Json -Compress
        $result=Invoke-SessionJson -Uri $uri -Json $body -AccessToken $SourceToken
        Assert-Session ($result.server_date_ms -gt 0) 'SIGNER_SERVER_DATE_MISSING'
        $expiry=[DateTimeOffset]::MinValue
        Assert-Session ([DateTimeOffset]::TryParse([string]$result.body.expireTime,[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,[ref]$expiry)) 'SIGNER_EXPIRY_INVALID'
        $remaining=$expiry.ToUnixTimeMilliseconds()-$result.server_date_ms-60000L
        Assert-Session ($remaining -gt 0 -and $remaining -le 3600000) 'SIGNER_EXPIRY_INVALID'
        $token=[string]$result.body.accessToken
        Assert-Session ($token.Length -gt 0 -and $token.Length -le 32768) 'SIGNER_TOKEN_INVALID'
        @{token=$token;deadline=[Math]::Min($Context.deadline,$result.received_at_ms+$remaining)}
    }finally{$watch.Stop();$Context.metrics.exchange_ms+=$watch.ElapsedMilliseconds}
}

function Get-RelaySessionToken {
    param([string]$ServiceAccount,[string]$Scope)
    $context=Require-Context
    $key=Get-TokenKey $ServiceAccount $Scope
    if($context.cache.ContainsKey($key) -and $context.cache[$key].deadline -gt (Get-SessionMonotonic)){
        $context.metrics.cache_hits++
        return $context.cache[$key].token
    }
    $context.metrics.cache_misses++
    if($context.cache.ContainsKey($key)){$context.cache[$key].token=$null;$context.cache.Remove($key)}
    $entry=if($ServiceAccount){
        $source=Get-RelaySessionToken
        try{Exchange-SessionSignerToken $context $source $Scope}finally{$source=$null}
    }else{Fetch-SessionSourceToken $context}
    Assert-Session ($entry.token -and $entry.deadline -gt (Get-SessionMonotonic)) 'TOKEN_ALREADY_EXPIRED'
    $context.cache[$key]=$entry
    $entry.token
}

function Get-RelaySessionMetrics {
    Assert-Session ($null -ne $script:Context) 'NOT_INITIALIZED'
    $context=$script:Context
    $result=[ordered]@{}
    foreach($key in $context.metrics.Keys){$result[$key]=[long]$context.metrics[$key]}
    $result.cache_entries=[long]$context.cache.Count
    [pscustomobject]$result
}

function Close-RelaySessionTransport {
    if($null -eq $script:Context){return}
    $context=$script:Context
    $script:Context=$null
    foreach($entry in $context.cache.Values){$entry.token=$null}
    $context.cache.Clear()
    $context.client.Dispose()
    $context.handler.Dispose()
    $context.account=$null;$context.configuration=$null;$context.project=$null;$context.signer=$null
}

Export-ModuleMember -Function Initialize-RelaySessionTransport,Get-RelaySessionToken,Get-RelaySessionHttpClient,
    Get-RelaySessionMetrics,Invalidate-RelaySessionToken,Close-RelaySessionTransport

#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:RelaySessionModule = $null
$script:RelayContextProject = $null
$script:RelayContextSigner = $null
$script:RelayJobMetrics = $null
$script:RelayLastJobMetrics = @{}

function Initialize-RelayHostContext {
    param([string]$ConfigPath,[string]$SessionPath,[string]$Account,[string]$ConfigurationName)
    $config = Read-RelayConfig $ConfigPath
    $session = Read-RelaySession $config $SessionPath
    Assert-Relay (-not $session.revoked) 'SESSION_REVOKED'
    $script:RelaySessionModule = Import-Module (Join-Path $PSScriptRoot 'RelaySession.psm1') -Force -PassThru
    & $script:RelaySessionModule {
        param($account,$configuration,$project,$signer,$expires)
        Initialize-RelaySessionTransport -Account $account -ConfigurationName $configuration -ProjectId $project -SignerServiceAccount $signer -ExpiresAtMs $expires
    } $Account $ConfigurationName $config.project_id $config.signer_service_account $session.expires_at_ms
    $script:RelayContextProject = $config.project_id
    $script:RelayContextSigner = $config.signer_service_account
    $null = Get-RelayOAuth
}

function Get-RelayHostSessionMetrics {
    $metrics = [ordered]@{}
    if ($script:RelaySessionModule) {
        $cached = & $script:RelaySessionModule { Get-RelaySessionMetrics }
        if($cached -is [Collections.IDictionary]) {
            foreach($key in $cached.Keys) { $metrics[$key] = [long]$cached[$key] }
        } else {
            foreach($property in $cached.PSObject.Properties) { $metrics[$property.Name] = [long]$property.Value }
        }
    }
    foreach($key in $script:RelayLastJobMetrics.Keys) { $metrics[$key] = [long]$script:RelayLastJobMetrics[$key] }
    $metrics
}

function Close-RelayHostContext {
    if ($script:RelaySessionModule) { & $script:RelaySessionModule { Close-RelaySessionTransport } }
    $script:RelaySessionModule = $null
    $script:RelayContextProject = $null
    $script:RelayContextSigner = $null
}

function ConvertTo-RelayBase64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-RelaySha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [Convert]::ToHexString($sha.ComputeHash($Bytes)).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-RelayNow { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }

function Assert-Relay([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw "Relay error: $Code" }
}

function Read-RelayJson([string]$Path, [int]$Limit = 262144) {
    Assert-Relay (Test-Path -LiteralPath $Path -PathType Leaf) 'FILE_MISSING'
    Assert-Relay ((Get-Item -LiteralPath $Path).Length -le $Limit) 'FILE_SIZE'
    try { Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 20 }
    catch { throw 'Relay error: INVALID_JSON' }
}

function Get-RelayInteger($Value) {
    Assert-Relay ($Value -is [int] -or $Value -is [long]) 'INTEGER_REQUIRED'
    Assert-Relay ([long]$Value -ge 0 -and [long]$Value -le 9007199254740991L) 'INTEGER_RANGE'
    [long]$Value
}

function Read-RelayConfig([string]$Path) {
    $config = Read-RelayJson $Path
    Assert-Relay ($config.project_id -cmatch '^[a-z][a-z0-9-]{4,61}[a-z0-9]$') 'PROJECT_ID'
    $number = Get-RelayInteger $config.project_number
    Assert-Relay ($number -gt 0) 'PROJECT_NUMBER'
    $url = $null
    Assert-Relay ([Uri]::TryCreate([string]$config.database_url, [UriKind]::Absolute, [ref]$url)) 'DATABASE_URL'
    Assert-Relay ($url.Scheme -eq 'https' -and $url.IsDefaultPort -and -not $url.UserInfo -and
        -not $url.Query -and -not $url.Fragment -and $url.AbsolutePath -eq '/' -and
        $url.Host -cmatch '^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(firebaseio\.com|firebasedatabase\.app)$') 'DATABASE_URL'
    Assert-Relay ($config.api_key -cmatch '^[A-Za-z0-9_-]{20,256}$') 'API_KEY_FORMAT'
    Assert-Relay ($config.signer_service_account -cmatch '^[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com$') 'SIGNER_FORMAT'
    Assert-Relay ($config.worker_package -ceq 'dev.androidlab.relayworker') 'WORKER_PACKAGE'
    Assert-Relay ($config.app_id -cmatch '^1:[0-9]+:android:[A-Za-z0-9]+$') 'APP_ID'
    $config.database_url = $url.GetLeftPart([UriPartial]::Authority)
    $config
}

function Get-RelayOAuth([string]$ServiceAccount, [string]$Scope) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
    if ($script:RelaySessionModule) {
        return & $script:RelaySessionModule { param($sa,$scope) Get-RelaySessionToken -ServiceAccount $sa -Scope $scope } $ServiceAccount $Scope
    }
    $gcloud = Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
    if (-not (Test-Path -LiteralPath $gcloud)) {
        $command = Get-Command gcloud.cmd -ErrorAction SilentlyContinue
        Assert-Relay ($null -ne $command) 'GCLOUD_MISSING'
        $gcloud = $command.Source
    }
    $arguments = @('auth', 'print-access-token', '--quiet')
    if ($ServiceAccount) { $arguments += "--impersonate-service-account=$ServiceAccount" }
    if ($Scope) { $arguments += "--scopes=$Scope" }
    $token = ((& $gcloud @arguments 2>$null) -join '').Trim()
    Assert-Relay ($LASTEXITCODE -eq 0 -and $token.Length -gt 0 -and $token.Length -le 32768) 'OAUTH_FAILED'
    $token
    } finally {
        if ($script:RelayJobMetrics) {
            $name = if($ServiceAccount){'oauth_decoder_ms'}else{'oauth_admin_ms'}
            $script:RelayJobMetrics[$name] += $watch.ElapsedMilliseconds
        }
    }
}

function Invoke-RelayHttp($Config, [string]$OAuth, [string]$Method, [string]$Uri, $Body,
    [hashtable]$ExtraHeaders = @{}, [int]$TimeoutSeconds = 20, [switch]$WithMetadata) {
    $httpWatch = [Diagnostics.Stopwatch]::StartNew()
    $handler = $null
    $ownsClient = -not [bool]$script:RelaySessionModule
    $decoder = ([Uri]$Uri).Host -ceq 'playintegrity.googleapis.com'
    if (!$ownsClient) {
        Assert-Relay ($Config.project_id -ceq $script:RelayContextProject -and $Config.signer_service_account -ceq $script:RelayContextSigner) 'OAUTH_CONTEXT_MISMATCH'
        $OAuth = if($decoder){Get-RelayOAuth $script:RelayContextSigner 'https://www.googleapis.com/auth/playintegrity'}else{Get-RelayOAuth}
        $client = & $script:RelaySessionModule { Get-RelaySessionHttpClient }
    } else {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    }
    $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Uri)
    try {
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $OAuth)
        # Integrity attributes usage through its token; the scoped decoder has no quota-project role.
        if (([Uri]$Uri).Host -cne 'playintegrity.googleapis.com') {
            $null = $request.Headers.TryAddWithoutValidation('x-goog-user-project', [string]$Config.project_id)
        }
        foreach ($key in $ExtraHeaders.Keys) { $null = $request.Headers.TryAddWithoutValidation($key, $ExtraHeaders[$key]) }
        if ($null -ne $Body) {
            $json = ConvertTo-Json -InputObject $Body -Depth 20 -Compress
            Assert-Relay ([Text.Encoding]::UTF8.GetByteCount($json) -le 262144) 'HTTP_REQUEST_SIZE'
            $request.Content = [Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
        }
        try {
            $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
            try {
                $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                try {
                    $buffer = [byte[]]::new(4096)
                    $memory = [IO.MemoryStream]::new()
                    try {
                        while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -gt 0) {
                            Assert-Relay ($memory.Length + $count -le 262144) 'HTTP_RESPONSE_SIZE'
                            $memory.Write($buffer, 0, $count)
                        }
                        $text = [Text.Encoding]::UTF8.GetString($memory.ToArray())
                    } finally { $memory.Dispose() }
                } finally { $stream.Dispose() }
                $code = [int]$response.StatusCode
                if ($code -eq 401 -and $script:RelaySessionModule) {
                    & $script:RelaySessionModule {
                        param($sa,$scope) Invalidate-RelaySessionToken -ServiceAccount $sa -Scope $scope
                    } $(if($decoder){$script:RelayContextSigner}else{''}) $(if($decoder){'https://www.googleapis.com/auth/playintegrity'}else{''})
                }
                if ($code -lt 200 -or $code -ge 300) { throw "Relay error: HTTP_$code" }
                $value = $null
                if ($text.Trim()) {
                    try { $value = ConvertFrom-Json -InputObject $text -Depth 20 }
                    catch { throw 'Relay error: HTTP_INVALID_JSON' }
                }
                if ($WithMetadata) {
                    $rawEtags = @($response.Headers.NonValidated | Where-Object {$_.Key -ieq 'ETag'})
                    $etag = if ($rawEtags.Count -eq 1) { $rawEtags[0].Value.ToString() } else { $null }
                    return [pscustomobject]@{status=$code;body=$value;etag=$etag}
                }
                return $value
            } finally { $response.Dispose() }
        } catch {
            if ($_.Exception.Message -cmatch '^Relay error: [A-Z0-9_]+$') { throw $_.Exception.Message }
            throw 'Relay error: HTTP_TRANSPORT_FAILED'
        }
    } finally {
        $request.Dispose(); $deadline.Dispose()
        if ($ownsClient) { $client.Dispose(); $handler.Dispose() }
        if ($script:RelayJobMetrics) {
            $script:RelayJobMetrics.http_total_ms += $httpWatch.ElapsedMilliseconds
            $script:RelayJobMetrics.http_requests++
        }
    }
}

function Invoke-RelayDatabase($Config, [string]$OAuth, [string]$Method, [string]$Path, $Body) {
    Assert-Relay ($Path -cmatch '^/relay/v1/(sessions|inboxes|executions)(/[A-Za-z0-9_-]+)+$') 'DATABASE_PATH'
    Invoke-RelayHttp $Config $OAuth $Method ($Config.database_url + $Path + '.json') $Body
}

function Set-RelayPrivateAccess([IO.FileSystemInfo]$Item) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    # Load and persist only the DACL; owner and SACL updates require unrelated privileges.
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl($Item, [Security.AccessControl.AccessControlSections]::Access)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existing in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
        $acl.RemoveAccessRuleSpecific($existing)
    }
    if ($Item -is [IO.DirectoryInfo]) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
    } else {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow')
    }
    $acl.AddAccessRule($rule)
    [IO.FileSystemAclExtensions]::SetAccessControl($Item, $acl)
    $verified = [IO.FileSystemAclExtensions]::GetAccessControl($Item, [Security.AccessControl.AccessControlSections]::Access)
    $rules = @($verified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-Relay ($verified.AreAccessRulesProtected -and $rules.Count -eq 1 -and
        $rules[0].IdentityReference -eq $identity -and
        $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl) 'PRIVATE_DACL_VERIFICATION'
}

function Protect-RelayDirectory([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    Set-RelayPrivateAccess ([IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path)))
}

function Save-RelayPrivate([string]$Path, $Value) {
    $absolute = [IO.Path]::GetFullPath($Path)
    Protect-RelayDirectory ([IO.Path]::GetDirectoryName($absolute))
    $temp = $absolute + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temp, (ConvertTo-Json -InputObject $Value -Depth 15), [Text.UTF8Encoding]::new($false))
        Set-RelayPrivateAccess ([IO.FileInfo]::new($temp))
        [IO.File]::Move($temp, $absolute, $true)
        Set-RelayPrivateAccess ([IO.FileInfo]::new($absolute))
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Invoke-RelayAdb([string]$Serial, [string[]]$Arguments, [string]$InputText) {
    Assert-Relay ($Serial -cmatch '^[A-Za-z0-9_.:-]{1,128}$') 'ADB_SERIAL'
    $adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
    Assert-Relay (Test-Path -LiteralPath $adb) 'ADB_MISSING'
    $info = [Diagnostics.ProcessStartInfo]::new($adb)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in (@('-s', $Serial) + $Arguments)) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        Assert-Relay ($process.Start()) 'ADB_START'
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($null -ne $InputText) { $process.StandardInput.Write($InputText) }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(60000)) { $process.Kill($true); throw 'Relay error: ADB_TIMEOUT' }
        $null = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        Assert-Relay ($process.ExitCode -eq 0) 'ADB_FAILED'
    } catch {
        if ($_.Exception.Message -cmatch '^Relay error: [A-Z0-9_]+$') { throw $_.Exception.Message }
        throw 'Relay error: ADB_TRANSPORT_FAILED'
    } finally { $process.Dispose() }
}

function New-RelayCustomToken($Config, [string]$OAuth, $Session) {
    $iat = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{alg = 'RS256'; typ = 'JWT'}
    $body = @{iss = $Config.signer_service_account; sub = $Config.signer_service_account;
        aud = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';
        iat = $iat; exp = $iat + 300; uid = $Session.worker_uid;
        claims = @{role = 'worker'; session_id = $Session.session_id; session_expires_at_ms = $Session.expires_at_ms}}
    $encodedHeader = ConvertTo-RelayBase64Url ([Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress)))
    $encodedBody = ConvertTo-RelayBase64Url ([Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 5 -Compress)))
    $unsigned = $encodedHeader + '.' + $encodedBody
    $uri = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + $Config.signer_service_account + ':signBlob'
    $signed = Invoke-RelayHttp $Config $OAuth POST $uri @{payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($unsigned))}
    try { $signature = [Convert]::FromBase64String($signed.signedBlob) }
    catch { throw 'Relay error: SIGNATURE_FORMAT' }
    $unsigned + '.' + (ConvertTo-RelayBase64Url $signature)
}

function Read-RelaySession($Config, [string]$SessionPath, [switch]$AllowExpired) {
    $session = Read-RelayJson $SessionPath
    Assert-Relay ($session.schema_version -eq 1 -and $session.session_id -cmatch '^[a-f0-9]{32}$' -and
        $session.worker_uid -cmatch '^worker_[a-f0-9]{24}$' -and $session.project_id -ceq $Config.project_id -and
        $session.database_url -ceq $Config.database_url -and $session.worker_package -ceq $Config.worker_package) 'SESSION_IDENTITY'
    $expiry = Get-RelayInteger $session.expires_at_ms
    if (-not $AllowExpired) { Assert-Relay ($expiry -gt (Get-RelayNow)) 'SESSION_EXPIRED' }
    $session
}

function New-RelayPair {
    param([string]$ConfigPath, [string]$SessionPath, [string]$Serial, [string]$ApkPath)
    $config = Read-RelayConfig $ConfigPath
    Assert-Relay ($Serial.Length -gt 0) 'ADB_SERIAL_REQUIRED'
    Assert-Relay (Test-Path -LiteralPath $ApkPath -PathType Leaf) 'WORKER_APK_MISSING'
    if (Test-Path -LiteralPath $SessionPath) {
        $previous = Read-RelaySession $config $SessionPath -AllowExpired
        Assert-Relay ($previous.expires_at_ms -le (Get-RelayNow) -or $previous.revoked) 'REVOKE_EXISTING_SESSION_FIRST'
    }
    $oauth = Get-RelayOAuth
    $now = Get-RelayNow
    $session = [ordered]@{schema_version = 1; session_id = [Guid]::NewGuid().ToString('N');
        worker_uid = 'worker_' + [Guid]::NewGuid().ToString('N').Substring(0,24); created_at_ms = $now;
        expires_at_ms = $now + 900000L; revoked = $false; project_id = $config.project_id;
        database_url = $config.database_url; worker_package = $config.worker_package}
    $path = '/relay/v1/sessions/' + $session.session_id
    try {
        Save-RelayPrivate $SessionPath $session
        $null = Invoke-RelayDatabase $config $oauth PUT $path @{worker_uid = $session.worker_uid;
            created_at_ms = $session.created_at_ms; expires_at_ms = $session.expires_at_ms; revoked = $false}
        $custom = New-RelayCustomToken $config $oauth $session
        $workerConfig = @{schema_version = 1; database_url = $config.database_url; api_key = $config.api_key;
            custom_token = $custom; session_id = $session.session_id; worker_uid = $session.worker_uid;
            session_expires_at_ms = $session.expires_at_ms; cloud_project_number = [long]$config.project_number}
        Invoke-RelayAdb $Serial @('install', '-r', [IO.Path]::GetFullPath($ApkPath))
        Invoke-RelayAdb $Serial @('shell', 'am', 'force-stop', $config.worker_package)
        Invoke-RelayAdb $Serial @('shell', 'run-as', $config.worker_package, 'mkdir', '-p', 'files')
        $privateJson = ConvertTo-Json -InputObject $workerConfig -Compress -Depth 5
        Invoke-RelayAdb $Serial @('shell', '-T', 'run-as', $config.worker_package, 'dd', 'of=files/relay-config.json') $privateJson
        Invoke-RelayAdb $Serial @('shell', 'run-as', $config.worker_package, 'chmod', '600', 'files/relay-config.json')
        Invoke-RelayAdb $Serial @('shell', 'am', 'start', '-W', '-n', ($config.worker_package + '/.MainActivity'), '--ez', 'auto_start', 'true')
        [pscustomobject]@{status = 'paired'; session_id = $session.session_id; worker_uid = $session.worker_uid; expires_at_ms = $session.expires_at_ms}
    } catch {
        try {
            $null = Invoke-RelayDatabase $config $oauth PATCH $path @{revoked = $true}
            $session.revoked = $true
            Save-RelayPrivate $SessionPath $session
        } catch { }
        throw 'Relay error: PAIR_FAILED_SESSION_REVOCATION_ATTEMPTED'
    } finally { $custom = $null; $privateJson = $null; $workerConfig = $null; $oauth = $null }
}

function Get-RelayStatus {
    param([string]$ConfigPath, [string]$SessionPath)
    $config = Read-RelayConfig $ConfigPath
    $session = Read-RelaySession $config $SessionPath -AllowExpired
    $oauth = Get-RelayOAuth
    $remote = Invoke-RelayDatabase $config $oauth GET ('/relay/v1/sessions/' + $session.session_id) $null
    Assert-Relay ($null -ne $remote -and $remote.worker_uid -ceq $session.worker_uid) 'SESSION_REMOTE_IDENTITY'
    [pscustomobject]@{session_id = $session.session_id; worker_uid = $session.worker_uid;
        expires_at_ms = $remote.expires_at_ms; revoked = $remote.revoked; expired = $remote.expires_at_ms -le (Get-RelayNow)}
}

function Revoke-RelaySession {
    param([string]$ConfigPath, [string]$SessionPath)
    $config = Read-RelayConfig $ConfigPath
    $session = Read-RelaySession $config $SessionPath -AllowExpired
    $oauth = Get-RelayOAuth
    $null = Invoke-RelayDatabase $config $oauth PATCH ('/relay/v1/sessions/' + $session.session_id) @{revoked = $true}
    $session.revoked = $true
    Save-RelayPrivate $SessionPath $session
    foreach ($collection in @('inboxes', 'executions')) {
        $null = Invoke-RelayDatabase $config $oauth DELETE ("/relay/v1/$collection/" + $session.worker_uid + '/' + $session.session_id) $null
    }
    [pscustomobject]@{status = 'revoked'; session_id = $session.session_id; worker_uid = $session.worker_uid}
}

function Assert-RelayExecution($Execution, $Job) {
    foreach ($key in @('job_id', 'session_id', 'worker_uid', 'operation', 'request_sha256')) {
        Assert-Relay ($Execution.$key -ceq $Job[$key]) 'EXECUTION_IDENTITY'
    }
    Assert-Relay ($Execution.lease_id -cmatch '^[a-f0-9]{32}$') 'LEASE_ID'
    $attempt = Get-RelayInteger $Execution.attempt
    $started = Get-RelayInteger $Execution.started_at_ms
    $until = Get-RelayInteger $Execution.lease_until_ms
    Assert-Relay ($attempt -ge 1 -and $attempt -le 2147483647 -and $started -ge $Job.created_at_ms -and
        $started -le (Get-RelayNow) + 30000 -and $until -gt $started -and
        $until -le $Job.expires_at_ms -and $until -le $started + 150000) 'LEASE_METADATA'
    Assert-Relay ($Execution.state -cin @('leased', 'completed', 'failed')) 'EXECUTION_STATE'
}

function Invoke-RelayJob {
    param([string]$ConfigPath, [string]$SessionPath,
        [ValidateSet('echo_sha256', 'play_integrity')][string]$Operation,
        [string]$Name, [ValidateRange(30,300)][int]$TimeoutSeconds = 120, [string]$ReportsDirectory,
        [string]$ChallengeBase64Url, [string]$JobId, [long]$DeadlineAtMs = 0)
    $jobWatch = [Diagnostics.Stopwatch]::StartNew()
    $script:RelayJobMetrics = [ordered]@{host_total_ms=0L;oauth_admin_ms=0L;oauth_decoder_ms=0L;http_total_ms=0L;http_requests=0L;decode_api_ms=0L;cleanup_ms=0L}
    try {
    Assert-Relay ($Name -cmatch '^[A-Za-z0-9_-]{1,100}$') 'REPORT_NAME'
    $config = Read-RelayConfig $ConfigPath
    $session = Read-RelaySession $config $SessionPath
    Assert-Relay (-not $session.revoked) 'SESSION_REVOKED'
    $oauth = Get-RelayOAuth
    $remote = Invoke-RelayDatabase $config $oauth GET ('/relay/v1/sessions/' + $session.session_id) $null
    Assert-Relay ($null -ne $remote -and -not $remote.revoked -and $remote.worker_uid -ceq $session.worker_uid -and
        $remote.expires_at_ms -eq $session.expires_at_ms) 'SESSION_REMOTE_IDENTITY'
    if ($ChallengeBase64Url) {
        Assert-Relay ($ChallengeBase64Url -cmatch '^[A-Za-z0-9_-]{43}$') 'CHALLENGE_FORMAT'
        try { $challenge = [Convert]::FromBase64String($ChallengeBase64Url.Replace('-', '+').Replace('_', '/') + '=') }
        catch { throw 'Relay error: CHALLENGE_FORMAT' }
        Assert-Relay ($challenge.Length -eq 32 -and (ConvertTo-RelayBase64Url $challenge) -ceq $ChallengeBase64Url) 'CHALLENGE_FORMAT'
    } else {
        $challenge = [byte[]]::new(32)
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($challenge) } finally { $rng.Dispose() }
    }
    if ($JobId) { Assert-Relay ($JobId -cmatch '^[a-f0-9]{32}$') 'JOB_ID_FORMAT' }
    else { $JobId = [Guid]::NewGuid().ToString('N') }
    $now = Get-RelayNow
    $job = [ordered]@{schema_version = 1; job_id = $JobId;
        session_id = $session.session_id; worker_uid = $session.worker_uid; operation = $Operation;
        challenge_base64url = ConvertTo-RelayBase64Url $challenge; cloud_project_number = [long]$config.project_number;
        created_at_ms = $now; expires_at_ms = [Math]::Min($now + $TimeoutSeconds * 1000L, [long]$session.expires_at_ms)}
    if ($DeadlineAtMs -ne 0) {
        Assert-Relay ($DeadlineAtMs -gt $now -and $DeadlineAtMs -le 9007199254740991L) 'REQUEST_DEADLINE'
        $job.expires_at_ms = [Math]::Min($job.expires_at_ms, $DeadlineAtMs)
    }
    Assert-Relay ($job.expires_at_ms -gt $now + 1000) 'SESSION_NEAR_EXPIRY'
    $canonical = @('v1', $job.session_id, $job.worker_uid, $job.job_id, $job.operation,
        $job.challenge_base64url, ([string]$job.cloud_project_number), ([string]$job.created_at_ms), ([string]$job.expires_at_ms)) -join "`n"
    $job.request_sha256 = Get-RelaySha256 ([Text.Encoding]::UTF8.GetBytes($canonical))
    $tail = $session.worker_uid + '/' + $session.session_id + '/' + $job.job_id
    $inbox = '/relay/v1/inboxes/' + $tail
    $executionPath = '/relay/v1/executions/' + $tail
    $report = [ordered]@{schema_version = 1; operation = $Operation; job_id = $job.job_id;
        session_id = $session.session_id; worker_uid = $session.worker_uid; request_sha256 = $job.request_sha256;
        origin = 'cooperative_remote_worker'; requester_integrity_verified = $false;
        worker_package = $config.worker_package; created_at_ms = $job.created_at_ms; expires_at_ms = $job.expires_at_ms;
        status = 'pending'; challenge_sha256 = Get-RelaySha256 $challenge}
    $posted = $false
    $roundTrip = [Diagnostics.Stopwatch]::new()
    $leaseIds = @{}
    $lastAttempt = 0L
    try {
        $posted = $true
        $roundTrip.Start()
        try {
            $null = Invoke-RelayHttp $config $oauth PUT ($config.database_url + $inbox + '.json') $job @{'If-Match' = 'null_etag'}
        } catch {
            # A collision belongs to a previous invocation and must not be removed by this one.
            if ($_.Exception.Message -ceq 'Relay error: HTTP_412') { $posted = $false }
            throw
        }
        $terminal = $null
        while ((Get-RelayNow) -lt $job.expires_at_ms) {
            $current = Invoke-RelayDatabase $config $oauth GET $executionPath $null
            if ($null -ne $current) {
                Assert-RelayExecution $current $job
                Assert-Relay ($current.attempt -ge $lastAttempt) 'LEASE_ATTEMPT_REGRESSION'
                $attemptKey = [string]$current.attempt
                if ($leaseIds.ContainsKey($attemptKey)) { Assert-Relay ($leaseIds[$attemptKey] -ceq $current.lease_id) 'LEASE_CHANGED' }
                else { $leaseIds[$attemptKey] = $current.lease_id }
                $lastAttempt = [long]$current.attempt
                if ($current.state -cin @('completed', 'failed')) { $terminal = $current; break }
            }
            Start-Sleep -Milliseconds 250
        }
        $roundTrip.Stop()
        $report.broker_observed_elapsed_ms = $roundTrip.ElapsedMilliseconds
        $report.broker_observed_completed_at_ms = Get-RelayNow
        if ($null -eq $terminal) { $report.status = 'timeout'; return Write-RelayReport $ReportsDirectory $Name $report }
        $report.lease_id = $terminal.lease_id
        $report.attempt = $terminal.attempt
        $report.worker_execution_state = $terminal.state
        if ($terminal.state -ceq 'failed') {
            Assert-Relay ($terminal.error.code -cmatch '^[A-Z][A-Z0-9_]{0,63}$') 'WORKER_ERROR_FORMAT'
            $report.status = 'worker_failed'
            $report.error = @{code = $terminal.error.code; message = 'Worker operation failed'}
            if ($null -ne $terminal.error.PSObject.Properties['error_code']) {
                Assert-Relay ($terminal.error.error_code -is [int] -or ($terminal.error.error_code -is [long] -and
                    $terminal.error.error_code -ge [int]::MinValue -and $terminal.error.error_code -le [int]::MaxValue)) 'WORKER_ERROR_NUMBER'
                $report.error.error_code = $terminal.error.error_code
            }
            return Write-RelayReport $ReportsDirectory $Name $report
        }
        $result = $terminal.result
        Assert-Relay ($result.worker_package -ceq $config.worker_package -and $result.worker_apk_cert_sha256 -cmatch '^[a-f0-9]{64}$') 'WORKER_IDENTITY'
        $version = Get-RelayInteger $result.worker_version_code
        $completed = Get-RelayInteger $result.completed_at_ms
        $elapsed = Get-RelayInteger $result.execution_elapsed_ms
        Assert-Relay ($version -gt 0 -and $completed -ge $terminal.started_at_ms -and $completed -le (Get-RelayNow) + 30000 -and
            $completed -le $terminal.lease_until_ms -and $elapsed -le 150000) 'RESULT_TIMING'
        $report.worker_version_code = $version
        $report.worker_apk_cert_sha256 = $result.worker_apk_cert_sha256
        $report.execution_elapsed_ms = $elapsed
        $report.completed_at_ms = $completed
        if ($Operation -ceq 'echo_sha256') {
            Assert-Relay ($result.challenge_sha256 -ceq $report.challenge_sha256) 'ECHO_HASH'
            $report.status = 'completed'
        } else {
            $token = [string]$result.token
            Assert-Relay ($token.Length -ge 1 -and $token.Length -le 32768 -and $result.token_length -eq $token.Length -and
                $result.nonce_base64url -ceq $job.challenge_base64url) 'TOKEN_METADATA'
            $tokenHash = Get-RelaySha256 ([Text.Encoding]::UTF8.GetBytes($token))
            Assert-Relay ($tokenHash -ceq $result.token_sha256) 'TOKEN_HASH'
            $report.token_sha256 = $tokenHash
            $decodeOAuth = Get-RelayOAuth $config.signer_service_account 'https://www.googleapis.com/auth/playintegrity'
            $uri = 'https://playintegrity.googleapis.com/v1/' + $config.worker_package + ':decodeIntegrityToken'
            $decodeWatch = [Diagnostics.Stopwatch]::StartNew()
            $decoded = Invoke-RelayHttp $config $decodeOAuth POST $uri @{integrity_token = $token}
            $script:RelayJobMetrics.decode_api_ms = $decodeWatch.ElapsedMilliseconds
            $payload = $decoded.tokenPayloadExternal
            $details = $payload.requestDetails
            $requestTime = [long]::Parse([string]$details.timestampMillis, [Globalization.CultureInfo]::InvariantCulture)
            # Classic requests may return a padded Base64 nonce; bind its decoded bytes.
            $returnedNonce = ([string]$details.nonce).Replace('-', '+').Replace('_', '/')
            Assert-Relay ($returnedNonce -cmatch '^[A-Za-z0-9+/]+={0,2}$') 'DECODE_NONCE_FORMAT'
            try {
                $nonceBytes = [Convert]::FromBase64String($returnedNonce.PadRight(
                    $returnedNonce.Length + ((4 - $returnedNonce.Length % 4) % 4), '='))
            } catch { throw 'Relay error: DECODE_NONCE_FORMAT' }
            $report.request_binding = @{package_matches = $details.requestPackageName -ceq $config.worker_package;
                nonce_bytes_match = $nonceBytes.Length -eq 32 -and (Get-RelaySha256 $nonceBytes) -ceq $report.challenge_sha256;
                timestamp_in_window = $requestTime -ge $job.created_at_ms - 30000 -and
                    $requestTime -le (Get-RelayNow) + 30000 -and (Get-RelayNow) - $requestTime -le 300000}
            Assert-Relay ($details.requestPackageName -ceq $config.worker_package -and
                $report.request_binding.nonce_bytes_match -and $requestTime -ge $job.created_at_ms - 30000 -and
                $requestTime -le (Get-RelayNow) + 30000 -and (Get-RelayNow) - $requestTime -le 300000) 'DECODE_REQUEST_MISMATCH'
            $report.status = 'completed'
            $report.token_sha256 = $tokenHash
            $report.nonce_matches = $true
            $report.request_timestamp_ms = $requestTime
            $report.worker_verdict = @{app_integrity = $payload.appIntegrity; device_integrity = $payload.deviceIntegrity;
                account_details = $payload.accountDetails}
        }
        Write-RelayReport $ReportsDirectory $Name $report
    } catch {
        $report.status = 'failed'
        $report.error = @{code = if ($_.Exception.Message -cmatch '^Relay (?:error|session): ([A-Z0-9_]+)$') { $Matches[1] } else { 'BROKER_FAILED' }}
        Write-RelayReport $ReportsDirectory $Name $report
    } finally {
        $cleanupWatch = [Diagnostics.Stopwatch]::StartNew()
        $token = $null; $decodeOAuth = $null
        if ($posted) {
            $cleanupFailed = $false
            try {
                $owned = Invoke-RelayHttp $config $oauth GET ($config.database_url + $inbox + '.json') $null @{'X-Firebase-ETag'='true'} -WithMetadata
                Assert-Relay ($null -ne $owned.body -and $owned.etag -and
                    $owned.body.request_sha256 -ceq $job.request_sha256 -and $owned.body.job_id -ceq $job.job_id -and
                    $owned.body.session_id -ceq $job.session_id -and $owned.body.worker_uid -ceq $job.worker_uid) 'CLEANUP_OWNERSHIP_UNCONFIRMED'
                # A lost create response cannot authorize deleting a different invocation's job.
                $null = Invoke-RelayHttp $config $oauth DELETE ($config.database_url + $inbox + '.json') $null @{'If-Match'=$owned.etag}
                $null = Invoke-RelayDatabase $config $oauth DELETE $executionPath $null
            } catch {
                $cleanupFailed = $true
            }
            $report.cleanup_state = if($cleanupFailed){'not_confirmed'}else{'completed'}
            $script:RelayJobMetrics.cleanup_ms = $cleanupWatch.ElapsedMilliseconds
            $script:RelayJobMetrics.host_total_ms = $jobWatch.ElapsedMilliseconds
            $report.host_timings = $script:RelayJobMetrics
            $script:RelayLastJobMetrics = $script:RelayJobMetrics
            $null = Write-RelayReport $ReportsDirectory $Name $report
            if ($cleanupFailed) { Write-Warning 'Relay cleanup failed for this job; revoke the session to remove its restricted records.' }
        }
        $oauth = $null
    }
    } finally { $script:RelayJobMetrics = $null }
}

function Write-RelayReport([string]$Directory, [string]$Name, $Report) {
    $null = New-Item -ItemType Directory -Path $Directory -Force
    $path = Join-Path $Directory ($Name + '.json')
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($path), (ConvertTo-Json -InputObject $Report -Depth 20), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{status = $Report.status; report_path = [IO.Path]::GetFullPath($path); job_id = $Report.job_id;
        origin = $Report.origin; requester_integrity_verified = $false}
}

Export-ModuleMember -Function New-RelayPair, Invoke-RelayJob, Revoke-RelaySession, Get-RelayStatus, Initialize-RelayHostContext, Get-RelayHostSessionMetrics, Close-RelayHostContext

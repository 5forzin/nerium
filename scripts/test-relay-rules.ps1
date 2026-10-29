#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ConfigPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Records = [System.Collections.Generic.List[object]]::new()
$script:CleanupPaths = [System.Collections.Generic.HashSet[string]]::new()
$script:OwnedSessions = [System.Collections.Generic.HashSet[string]]::new()
$script:OwnedUids = [System.Collections.Generic.HashSet[string]]::new()
$script:CreatedAuthUsers = @{}
$script:Client = [System.Net.Http.HttpClient]::new()
$script:Client.Timeout = [TimeSpan]::FromSeconds(25)
$script:Deadline = [DateTimeOffset]::UtcNow.AddMinutes(5)
$script:AdminToken = $null
$script:Config = $null
$script:RulesMatched = $false
$script:Failure = $false
$reportPath = Join-Path $PSScriptRoot '..\reports\relay-v36-rules-tests.json'

function Get-NowMs { return [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
function Get-HexHash([string]$Text) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}
function ConvertTo-CanonicalValue($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        [string[]]$keys = @($Value.Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        foreach ($key in $keys) { $result[$key] = ConvertTo-CanonicalValue $Value[$key] }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value | ForEach-Object { ConvertTo-CanonicalValue $_ })
        return ,$items
    }
    return $Value
}
function Get-CanonicalJson($Value) {
    return ConvertTo-Json -InputObject (ConvertTo-CanonicalValue $Value) -Depth 100 -Compress
}
function Copy-Record($Value) { return (Get-CanonicalJson $Value | ConvertFrom-Json -AsHashtable) }
function ConvertTo-Base64Url([byte[]]$Bytes) { return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function New-HexId { return [Guid]::NewGuid().ToString('N') }

function Invoke-PrivateHttp {
    param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers = @{}, [switch]$Cleanup)
    if (!$Cleanup -and [DateTimeOffset]::UtcNow -gt $script:Deadline) { throw 'TEST_DEADLINE_EXCEEDED' }
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Url)
    $response = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        # Client Auth exchanges use an API key, not a Google IAM principal for quota attribution.
        if ($Headers.ContainsKey('Authorization')) {
            [void]$request.Headers.TryAddWithoutValidation('x-goog-user-project', [string]$script:Config.project_id)
        }
        foreach ($key in $Headers.Keys) { [void]$request.Headers.TryAddWithoutValidation($key, [string]$Headers[$key]) }
        if ($null -ne $Body -and $Body.Length -gt 0) { $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json') }
        $response = $script:Client.SendAsync($request).GetAwaiter().GetResult()
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        # Firebase uses an unquoted null_etag sentinel that the typed HTTP parser rejects.
        $rawEtags = @($response.Headers.NonValidated | Where-Object { $_.Key -ieq 'ETag' })
        $etag = if ($rawEtags.Count -eq 1) { $rawEtags[0].Value.ToString() } else { $null }
        $serverDateMs = $null
        $rawDates = @($response.Headers.NonValidated | Where-Object { $_.Key -ieq 'Date' })
        if ($rawDates.Count -eq 1) {
            $parsedDate = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($rawDates[0].Value.ToString(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsedDate)) {
                $serverDateMs = $parsedDate.ToUnixTimeMilliseconds()
            }
        }
        return @{ Status = [int]$response.StatusCode; Body = $content; ETag = $etag; ElapsedMs = $watch.ElapsedMilliseconds; ServerDateMs = $serverDateMs }
    } catch { throw 'HTTP_TRANSPORT_FAILURE' }
    finally { $watch.Stop(); if ($null -ne $response) { $response.Dispose() }; $request.Dispose() }
}
function Invoke-Database {
    param([string]$Method, [string]$Path, [string]$Identity = 'admin', [string]$Body, [hashtable]$Headers = @{}, [switch]$Cleanup)
    if ($Path -notmatch '^[A-Za-z0-9_./-]+$' -or $Path.Contains('..')) { throw 'INVALID_DATABASE_PATH' }
    $url = $script:Config.database_url.TrimEnd('/') + '/' + $Path + '.json'
    $httpHeaders = @{}
    foreach ($key in $Headers.Keys) { $httpHeaders[$key] = $Headers[$key] }
    if ($Identity -eq 'admin') { $httpHeaders.Authorization = 'Bearer ' + $script:AdminToken }
    elseif ($Identity -ne 'none') { $url += '?auth=' + [Uri]::EscapeDataString($Identity) }
    return Invoke-PrivateHttp -Method $Method -Url $url -Body $Body -Headers $httpHeaders -Cleanup:$Cleanup
}
function Add-Test {
    param([string]$Name, $Response, [int[]]$Expected, [string]$RequestBody = '', [bool]$ExtraPass = $true)
    $passed = ($Response.Status -in $Expected) -and $ExtraPass
    $script:Records.Add([ordered]@{ name = $Name; status_code = $Response.Status; expected_codes = $Expected; passed = $passed; elapsed_ms = $Response.ElapsedMs; request_sha256 = Get-HexHash $RequestBody; response_sha256 = Get-HexHash $Response.Body })
    if (!$passed) { $script:Failure = $true; throw ('TEST_FAILED_' + $Name) }
}
function Assert-Status([string]$Name, $Response, [int[]]$Expected, [string]$RequestBody = '') { Add-Test $Name $Response $Expected $RequestBody }
function Add-GoogleFailure([string]$Name, $Response) {
    $safe = [ordered]@{}
    try {
        $document = $Response.Body | ConvertFrom-Json -AsHashtable
        if ($document -is [System.Collections.IDictionary] -and $document.Contains('error')) {
            $googleError = $document['error']
            if ($googleError -is [System.Collections.IDictionary]) {
                if ($googleError.Contains('status') -and $googleError['status'] -is [string] -and $googleError['status'] -cmatch '^[A-Z0-9_]+$') {
                    $safe['status'] = $googleError['status']
                }
                if ($googleError.Contains('message') -and $googleError['message'] -is [string] -and $googleError['message'] -cmatch '^[A-Z0-9_]+$') {
                    $safe['message'] = $googleError['message']
                }
                if ($googleError.Contains('details')) {
                    foreach ($detail in $googleError['details']) {
                        if ($detail -isnot [System.Collections.IDictionary] -or !$detail.Contains('@type') -or $detail['@type'] -cne 'type.googleapis.com/google.rpc.ErrorInfo') { continue }
                        if ($detail.Contains('reason') -and $detail['reason'] -is [string] -and $detail['reason'] -cmatch '^[A-Z0-9_]+$') {
                            $safe['reason'] = $detail['reason']
                        }
                        if ($detail.Contains('metadata') -and $detail['metadata'] -is [System.Collections.IDictionary]) {
                            $metadata = $detail['metadata']
                            if ($metadata.Contains('service') -and $metadata['service'] -is [string] -and $metadata['service'] -cmatch '^[a-z][a-z0-9.-]*\.googleapis\.com$') {
                                $safe['service'] = $metadata['service']
                            }
                        }
                    }
                }
            }
        }
    } catch {
        # Unparseable or unexpected service errors yield HTTP metadata only.
    }
    $script:Records.Add([ordered]@{ name = $Name; status_code = $Response.Status; passed = $false; elapsed_ms = $Response.ElapsedMs; google_error = $safe })
}
function New-WorkerIdToken([string]$Uid, [string]$Sid, [long]$Expiry) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}'))
    $payload = @{ iss = $script:Config.signer_service_account; sub = $script:Config.signer_service_account; aud = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit'; iat = $now; exp = $now + 3600; uid = $Uid; claims = @{ role = 'worker'; session_id = $Sid; session_expires_at_ms = $Expiry } }
    $jwtUnsigned = $header + '.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes((Get-CanonicalJson $payload))))
    $signBody = Get-CanonicalJson @{ payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtUnsigned)) }
    $signer = [Uri]::EscapeDataString($script:Config.signer_service_account)
    $signed = Invoke-PrivateHttp -Method POST -Url ('https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + $signer + ':signBlob') -Body $signBody -Headers @{ Authorization = 'Bearer ' + $script:AdminToken }
    if ($signed.Status -ne 200) { Add-GoogleFailure 'google_sign_blob_failure' $signed; throw ('SIGN_BLOB_HTTP_' + $signed.Status) }
    $signedJson = $signed.Body | ConvertFrom-Json -AsHashtable
    $customToken = $jwtUnsigned + '.' + (ConvertTo-Base64Url ([Convert]::FromBase64String($signedJson.signedBlob)))
    $exchange = Invoke-PrivateHttp -Method POST -Url ('https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=' + [Uri]::EscapeDataString($script:Config.api_key)) -Body (Get-CanonicalJson @{ token = $customToken; returnSecureToken = $true })
    if ($exchange.Status -ne 200) { Add-GoogleFailure 'google_custom_token_exchange_failure' $exchange; throw ('CUSTOM_TOKEN_EXCHANGE_HTTP_' + $exchange.Status) }
    $json = $exchange.Body | ConvertFrom-Json -AsHashtable
    if (!$json.ContainsKey('idToken') -or $json['idToken'] -isnot [string] -or !$json['idToken'] -or $json['idToken'].Length -gt 32768) { throw 'CUSTOM_TOKEN_EXCHANGE_TOKEN_MISSING' }
    if ($Uid -notmatch '^[a-f0-9]{32}$' -or !$script:OwnedUids.Contains($Uid)) { throw 'UNOWNED_AUTH_FIXTURE_REFUSED' }
    $idToken = [string]$json['idToken']
    $segments = $idToken.Split('.')
    if ($segments.Length -ne 3 -or $segments[1] -notmatch '^[A-Za-z0-9_-]+$') { throw 'ID_TOKEN_PAYLOAD_INVALID' }
    try {
        $encodedPayload = $segments[1].Replace('-', '+').Replace('_', '/')
        $encodedPayload += '=' * ((4 - $encodedPayload.Length % 4) % 4)
        $idClaims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedPayload)) | ConvertFrom-Json -AsHashtable
    } catch { throw 'ID_TOKEN_PAYLOAD_INVALID' }
    if (!$idClaims.ContainsKey('sub') -or $idClaims['sub'] -cne $Uid) { throw 'CUSTOM_TOKEN_EXCHANGE_SUBJECT_MISMATCH' }
    if (!$script:CreatedAuthUsers.ContainsKey($Uid) -and (!$json.ContainsKey('isNewUser') -or $json['isNewUser'] -ne $true)) { throw 'AUTH_UID_NOT_CREATED_BY_THIS_TEST' }
    # The ID token came from the TLS-protected exchange for our issued custom token.
    # Track a confirmed new subject before lookup so lookup failure cannot skip cleanup.
    $script:CreatedAuthUsers[$Uid] = $idToken
    $lookup = Invoke-PrivateHttp -Method POST -Url ('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + [Uri]::EscapeDataString($script:Config.api_key)) -Body (Get-CanonicalJson @{ idToken = $idToken })
    if ($lookup.Status -ne 200) { Add-GoogleFailure 'google_account_lookup_failure' $lookup; throw ('ACCOUNT_LOOKUP_HTTP_' + $lookup.Status) }
    $account = $lookup.Body | ConvertFrom-Json -AsHashtable
    if (!$account.ContainsKey('users') -or @($account['users']).Count -ne 1 -or $account['users'][0] -isnot [System.Collections.IDictionary] -or !$account['users'][0].Contains('localId') -or $account['users'][0]['localId'] -cne $Uid) {
        [void]$script:CreatedAuthUsers.Remove($Uid)
        throw 'ACCOUNT_LOOKUP_IDENTITY_MISMATCH'
    }
    $account = $null
    return $idToken
}
function New-Session([string]$Sid, [string]$Uid, [long]$Expiry) {
    if ($Sid -notmatch '^[a-f0-9]{32}$' -or $Uid -notmatch '^[a-f0-9]{32}$') { throw 'INVALID_FIXTURE_ID' }
    $body = Get-CanonicalJson @{ worker_uid = $Uid; expires_at_ms = $Expiry; revoked = $false }
    $response = Invoke-Database PUT ('relay/v1/sessions/' + $Sid) -Body $body -Headers @{ 'If-Match' = 'null_etag' }
    Assert-Status 'fixture_session_create' $response @(200) $body
    [void]$script:OwnedSessions.Add($Sid); [void]$script:OwnedUids.Add($Uid)
    [void]$script:CleanupPaths.Add('relay/v1/sessions/' + $Sid)
    [void]$script:CleanupPaths.Add('relay/v1/inboxes/' + $Uid + '/' + $Sid)
    [void]$script:CleanupPaths.Add('relay/v1/executions/' + $Uid + '/' + $Sid)
}
function New-Job([string]$Sid, [string]$Uid, [long]$Expiry) {
    $jobId = New-HexId
    $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $challenge = ConvertTo-Base64Url $bytes
    $created = Get-NowMs
    $project = [long]$script:Config.project_number
    $canonical = 'v1' + "`n" + $Sid + "`n" + $Uid + "`n" + $jobId + "`n" + 'echo_sha256' + "`n" + $challenge + "`n" + $project.ToString([Globalization.CultureInfo]::InvariantCulture) + "`n" + $created.ToString([Globalization.CultureInfo]::InvariantCulture) + "`n" + $Expiry.ToString([Globalization.CultureInfo]::InvariantCulture)
    $job = @{ schema_version = 1; job_id = $jobId; session_id = $Sid; worker_uid = $Uid; operation = 'echo_sha256'; challenge_base64url = $challenge; cloud_project_number = $project; created_at_ms = $created; expires_at_ms = $Expiry; request_sha256 = Get-HexHash $canonical }
    $body = Get-CanonicalJson $job
    $response = Invoke-Database PUT ('relay/v1/inboxes/' + $Uid + '/' + $Sid + '/' + $jobId) -Body $body -Headers @{ 'If-Match' = 'null_etag' }
    Assert-Status 'fixture_job_create' $response @(200) $body
    return $job
}
function Get-ExecutionPath($Job) { return 'relay/v1/executions/' + $Job.worker_uid + '/' + $Job.session_id + '/' + $Job.job_id }
function Get-InboxPath($Job) { return 'relay/v1/inboxes/' + $Job.worker_uid + '/' + $Job.session_id + '/' + $Job.job_id }
function New-Lease($Job) {
    $now = Get-NowMs
    return @{ state = 'leased'; job_id = $Job.job_id; session_id = $Job.session_id; worker_uid = $Job.worker_uid; operation = $Job.operation; request_sha256 = $Job.request_sha256; lease_id = New-HexId; lease_until_ms = [Math]::Min($now + 90000, [long]$Job.expires_at_ms); attempt = 1; started_at_ms = $now }
}
function New-Completion($Lease, $Job) {
    $done = Copy-Record $Lease
    $done.state = 'completed'
    $rawChallenge = $Job.challenge_base64url.Replace('-', '+').Replace('_', '/') + '='
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($rawChallenge))).ToLowerInvariant()
    $done.result = @{ worker_package = 'dev.androidlab.synthetic.rules'; worker_version_code = 1; worker_apk_cert_sha256 = ('a' * 64); execution_elapsed_ms = [Math]::Max(0, (Get-NowMs) - [long]$Lease.started_at_ms); completed_at_ms = Get-NowMs; challenge_sha256 = $hash }
    return $done
}
function Remove-OwnedPath([string]$Path) {
    $parts = $Path.Split('/')
    $valid = $false
    if ($parts.Length -eq 4 -and $parts[0] -eq 'relay' -and $parts[1] -eq 'v1' -and $parts[2] -eq 'sessions') {
        $valid = $parts[3] -match '^[a-f0-9]{32}$' -and $script:OwnedSessions.Contains($parts[3])
    } elseif ($parts.Length -eq 5 -and $parts[0] -eq 'relay' -and $parts[1] -eq 'v1' -and $parts[2] -in @('inboxes','executions')) {
        $valid = $parts[3] -match '^[a-f0-9]{32}$' -and $parts[4] -match '^[a-f0-9]{32}$' -and $script:OwnedUids.Contains($parts[3]) -and $script:OwnedSessions.Contains($parts[4])
    }
    if (!$valid -or !$script:CleanupPaths.Contains($Path)) { throw 'UNOWNED_CLEANUP_PATH_REFUSED' }
    $response = Invoke-Database DELETE $Path -Cleanup
    Add-Test 'cleanup_owned_fixture' $response @(200)
}

try {
    $resolved = (Resolve-Path -LiteralPath $ConfigPath).Path
    $privateRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\') + '\'
    if (!$resolved.StartsWith($privateRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'CONFIG_MUST_BE_UNDER_LOCALAPPDATA' }
    $script:Config = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -AsHashtable
    foreach ($field in @('project_id','project_number','database_url','api_key','signer_service_account')) { if (!$script:Config.ContainsKey($field)) { throw 'MISSING_CONFIG_FIELD' } }
    if ($script:Config.project_id -notmatch '^[a-z][a-z0-9-]{4,61}[a-z0-9]$') { throw 'INVALID_PROJECT_ID' }
    $number = [string]$script:Config.project_number
    if ($number -notmatch '^[0-9]{1,16}$' -or [long]$number -lt 1 -or [long]$number -gt 9007199254740991) { throw 'INVALID_PROJECT_NUMBER' }
    $database = [Uri]$script:Config.database_url
    if ($database.Scheme -ne 'https' -or $database.UserInfo -or $database.Query -or $database.Fragment -or $database.AbsolutePath -ne '/' -or $database.Host -notmatch '^[a-z0-9-]+(?:\.[a-z0-9-]+)?\.(?:firebaseio\.com|firebasedatabase\.app)$') { throw 'INVALID_DATABASE_URL' }
    if ($script:Config.signer_service_account -notmatch '^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$') { throw 'INVALID_SIGNER' }
    $gcloud = Get-Command gcloud.cmd -ErrorAction Stop
    $tokenProcess = [Diagnostics.Process]::new()
    $tokenStart = [Diagnostics.ProcessStartInfo]::new()
    $tokenStart.FileName = $env:ComSpec
    $tokenStart.Arguments = '/d /s /c ""' + $gcloud.Source + '" auth print-access-token"'
    $tokenStart.UseShellExecute = $false
    $tokenStart.CreateNoWindow = $true
    $tokenStart.RedirectStandardOutput = $true
    $tokenStart.RedirectStandardError = $true
    $tokenProcess.StartInfo = $tokenStart
    try {
        [void]$tokenProcess.Start()
        $tokenOutput = $tokenProcess.StandardOutput.ReadToEndAsync()
        $tokenError = $tokenProcess.StandardError.ReadToEndAsync()
        if (!$tokenProcess.WaitForExit(30000)) { $tokenProcess.Kill($true); throw 'OAUTH_TOKEN_TIMEOUT' }
        $script:AdminToken = $tokenOutput.GetAwaiter().GetResult().Trim()
        [void]$tokenError.GetAwaiter().GetResult()
        if ($tokenProcess.ExitCode -ne 0 -or !$script:AdminToken) { throw 'OAUTH_TOKEN_UNAVAILABLE' }
    } finally { $tokenProcess.Dispose() }
    $localRules = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\relay\database.rules.json') -Raw | ConvertFrom-Json -AsHashtable
    $deployed = Invoke-Database GET '.settings/rules'
    if ($deployed.Status -ne 200) { throw ('RULES_READ_HTTP_' + $deployed.Status) }
    $remoteRules = $deployed.Body | ConvertFrom-Json -AsHashtable
    $localHash = Get-HexHash (Get-CanonicalJson $localRules)
    $remoteHash = Get-HexHash (Get-CanonicalJson $remoteRules)
    Add-Test 'deployed_rules_match_local' $deployed @(200) '' ($localHash -eq $remoteHash)
    $script:RulesMatched = $true

    $sidA = New-HexId; $sidB = New-HexId; $uidA = New-HexId; $uidB = New-HexId
    $expiry = (Get-NowMs) + 600000
    New-Session $sidA $uidA $expiry; New-Session $sidB $uidB $expiry
    $workerA = New-WorkerIdToken $uidA $sidA $expiry
    $workerB = New-WorkerIdToken $uidB $sidB $expiry
    $wrongSession = New-WorkerIdToken $uidA $sidB $expiry
    $expiredClaim = New-WorkerIdToken $uidA $sidA ((Get-NowMs) - 60000)
    $job = New-Job $sidA $uidA ((Get-NowMs) + 300000)
    $inbox = Get-InboxPath $job; $execution = Get-ExecutionPath $job
    $deny = @(401,403)
    Assert-Status 'unauthenticated_read_denied' (Invoke-Database GET $inbox -Identity none) $deny
    Assert-Status 'wrong_uid_read_denied' (Invoke-Database GET $inbox -Identity $workerB) $deny
    Assert-Status 'correct_worker_read_allowed' (Invoke-Database GET $inbox -Identity $workerA) @(200)
    $jobBody = Get-CanonicalJson $job
    Assert-Status 'worker_inbox_write_denied' (Invoke-Database PUT $inbox -Identity $workerA -Body $jobBody) $deny $jobBody
    Assert-Status 'worker_session_write_denied' (Invoke-Database PATCH ('relay/v1/sessions/' + $sidA) -Identity $workerA -Body '{"revoked":true}') $deny '{"revoked":true}'
    Assert-Status 'wrong_session_claim_denied' (Invoke-Database GET $inbox -Identity $wrongSession) $deny
    Assert-Status 'expired_session_claim_denied' (Invoke-Database GET $inbox -Identity $expiredClaim) $deny
    $r = Invoke-Database PATCH ('relay/v1/sessions/' + $sidB) -Body '{"revoked":true}'
    Assert-Status 'fixture_revoke_session' $r @(200) '{"revoked":true}'
    $revokedJob = New-Job $sidB $uidB ((Get-NowMs) + 300000)
    Assert-Status 'revoked_session_read_denied' (Invoke-Database GET (Get-InboxPath $revokedJob) -Identity $workerB) $deny

    $clockJob = New-Job $sidA $uidA ((Get-NowMs) + 300000)
    $clockPath = Get-ExecutionPath $clockJob
    $clockSnapshot = Invoke-Database GET $clockPath -Identity $workerA -Headers @{ 'X-Firebase-ETag' = 'true'; 'Cache-Control' = 'no-cache' }
    Add-Test 'clock_fixture_absent_with_https_date' $clockSnapshot @(200) '' ($clockSnapshot.Body.Trim() -eq 'null' -and !!$clockSnapshot.ETag -and $null -ne $clockSnapshot.ServerDateMs)
    $clockLease = New-Lease $clockJob
    $clockLease.lease_until_ms = [Math]::Min([long]$clockSnapshot.ServerDateMs + 90000, [long]$clockJob.expires_at_ms)
    $naiveClockLease = Copy-Record $clockLease
    $naiveClockLease.started_at_ms = [long]$clockJob.created_at_ms - 1500
    $body = Get-CanonicalJson $naiveClockLease
    Assert-Status 'clock_naive_start_before_job_creation_denied' (Invoke-Database PUT $clockPath -Identity $workerA -Body $body -Headers @{ 'If-Match' = $clockSnapshot.ETag }) $deny $body
    $clockFuture = Copy-Record $clockLease
    $clockFuture.started_at_ms = @{ '.sv' = 'timestamp' }
    $clockFuture.lease_until_ms = [long]$clockSnapshot.ServerDateMs + 180000
    $body = Get-CanonicalJson $clockFuture
    Assert-Status 'clock_excessive_future_lease_denied' (Invoke-Database PUT $clockPath -Identity $workerA -Body $body -Headers @{ 'If-Match' = $clockSnapshot.ETag }) $deny $body
    $clockLease.started_at_ms = @{ '.sv' = 'timestamp' }
    $body = Get-CanonicalJson $clockLease
    $clockAcquired = Invoke-Database PUT $clockPath -Identity $workerA -Body $body -Headers @{ 'If-Match' = $clockSnapshot.ETag }
    Assert-Status 'clock_server_timestamp_lease_allowed' $clockAcquired @(200) $body
    $resolvedClockLease = $clockAcquired.Body | ConvertFrom-Json -AsHashtable
    $startResolved = $resolvedClockLease.ContainsKey('started_at_ms') -and ($resolvedClockLease['started_at_ms'] -is [long] -or $resolvedClockLease['started_at_ms'] -is [int])
    Add-Test 'clock_lease_response_resolved_numeric_start' $clockAcquired @(200) $body ($startResolved -and $resolvedClockLease['started_at_ms'] -ge $clockJob.created_at_ms -and $resolvedClockLease['started_at_ms'] -lt $resolvedClockLease['lease_until_ms'])
    $clockComplete = New-Completion $resolvedClockLease $clockJob
    $clockComplete.result.execution_elapsed_ms = 0
    $clockComplete.result.completed_at_ms = @{ '.sv' = 'timestamp' }
    $body = Get-CanonicalJson $clockComplete
    $clockCurrent = Invoke-Database GET $clockPath -Identity $workerA -Headers @{ 'X-Firebase-ETag' = 'true' }
    Add-Test 'clock_lease_completion_snapshot_read' $clockCurrent @(200) '' (!!$clockCurrent.ETag)
    $clockCompleted = Invoke-Database PUT $clockPath -Identity $workerA -Body $body -Headers @{ 'If-Match' = $clockCurrent.ETag }
    Assert-Status 'clock_server_timestamp_completion_allowed' $clockCompleted @(200) $body
    $resolvedClockComplete = $clockCompleted.Body | ConvertFrom-Json -AsHashtable
    $completionResolved = $resolvedClockComplete.ContainsKey('result') -and $resolvedClockComplete['result'].ContainsKey('completed_at_ms') -and ($resolvedClockComplete['result']['completed_at_ms'] -is [long] -or $resolvedClockComplete['result']['completed_at_ms'] -is [int])
    Add-Test 'clock_completion_response_resolved_numeric_time' $clockCompleted @(200) $body ($completionResolved -and $resolvedClockComplete['result']['completed_at_ms'] -ge $resolvedClockLease['started_at_ms'])

    Assert-Status 'cleanup_race_remove_inbox_first' (Invoke-Database DELETE (Get-InboxPath $clockJob)) @(200)
    $executionRemoval = Invoke-Database DELETE $clockPath
    Assert-Status 'cleanup_race_remove_execution_after_inbox' $executionRemoval @(200)
    if ($null -eq $executionRemoval.ServerDateMs -or [long]$clockJob.expires_at_ms -le [long]$executionRemoval.ServerDateMs + 5000) { throw 'CLEANUP_RACE_CLOCK_FIXTURE_UNAVAILABLE' }
    $recreatedLease = New-Lease $clockJob
    $recreatedLease.started_at_ms = @{ '.sv' = 'timestamp' }
    $recreatedLease.lease_until_ms = [Math]::Min([long]$executionRemoval.ServerDateMs + 90000, [long]$clockJob.expires_at_ms)
    $body = Get-CanonicalJson $recreatedLease
    Assert-Status 'cleanup_race_reacquire_without_inbox_denied' (Invoke-Database PUT $clockPath -Identity $workerA -Body $body -Headers @{ 'If-Match' = 'null_etag' }) $deny $body
    $removedExecution = Invoke-Database GET $clockPath
    Add-Test 'cleanup_race_execution_remains_absent' $removedExecution @(200) '' ($removedExecution.Body.Trim() -eq 'null')

    $lease = New-Lease $job
    $leaseBody = Get-CanonicalJson $lease
    $snapshot = Invoke-Database GET $execution -Identity $workerA -Headers @{ 'X-Firebase-ETag' = 'true' }
    Add-Test 'execution_initially_absent' $snapshot @(200) '' ($snapshot.Body.Trim() -eq 'null' -and !!$snapshot.ETag)
    Assert-Status 'acquire_lease_allowed' (Invoke-Database PUT $execution -Identity $workerA -Body $leaseBody -Headers @{ 'If-Match' = $snapshot.ETag }) @(200) $leaseBody
    $renew = Copy-Record $lease
    $renew.lease_until_ms = [Math]::Min((Get-NowMs) + 90000, [long]$job.expires_at_ms)
    $renewBody = Get-CanonicalJson $renew
    Assert-Status 'stale_etag_compare_and_set_rejected' (Invoke-Database PUT $execution -Identity $workerA -Body $renewBody -Headers @{ 'If-Match' = $snapshot.ETag }) @(412) $renewBody
    $fresh = Invoke-Database GET $execution -Identity $workerA -Headers @{ 'X-Firebase-ETag' = 'true' }
    Add-Test 'lease_snapshot_read_allowed' $fresh @(200) '' (!!$fresh.ETag)
    Assert-Status 'matching_lease_renewal_allowed' (Invoke-Database PUT $execution -Identity $workerA -Body $renewBody -Headers @{ 'If-Match' = $fresh.ETag }) @(200) $renewBody
    $lease = $renew
    $complete = New-Completion $lease $job
    $completeBody = Get-CanonicalJson $complete
    Assert-Status 'wrong_uid_completion_denied' (Invoke-Database PUT $execution -Identity $workerB -Body $completeBody) $deny $completeBody
    $wrongHash = Copy-Record $complete; $wrongHash.request_sha256 = ('0' * 64)
    $body = Get-CanonicalJson $wrongHash
    Assert-Status 'wrong_job_hash_completion_denied' (Invoke-Database PUT $execution -Identity $workerA -Body $body) $deny $body
    $wrongLease = Copy-Record $complete; $wrongLease.lease_id = New-HexId
    $body = Get-CanonicalJson $wrongLease
    Assert-Status 'wrong_lease_completion_denied' (Invoke-Database PUT $execution -Identity $workerA -Body $body) $deny $body
    $future = Copy-Record $lease; $future.lease_until_ms = (Get-NowMs) + 150000
    $body = Get-CanonicalJson $future
    Assert-Status 'future_lease_bound_denied' (Invoke-Database PUT $execution -Identity $workerA -Body $body) $deny $body
    $expiredJob = New-Job $sidA $uidA ((Get-NowMs) - 1000)
    $expiredLease = New-Lease $expiredJob
    $body = Get-CanonicalJson $expiredLease
    Assert-Status 'expired_job_acquire_denied' (Invoke-Database PUT (Get-ExecutionPath $expiredJob) -Identity $workerA -Body $body) $deny $body
    $complete = New-Completion $lease $job; $completeBody = Get-CanonicalJson $complete
    Assert-Status 'correct_terminal_completion_allowed' (Invoke-Database PUT $execution -Identity $workerA -Body $completeBody) @(200) $completeBody
    Assert-Status 'terminal_rewrite_denied' (Invoke-Database PUT $execution -Identity $workerA -Body $completeBody) $deny $completeBody
    Assert-Status 'terminal_delete_denied' (Invoke-Database DELETE $execution -Identity $workerA) $deny
} catch {
    $script:Failure = $true
    $code = if ($_.Exception.Message -match '^[A-Z0-9_]+$') { $_.Exception.Message } else { 'LOCAL_OR_SERVICE_FAILURE' }
    $safeFrames = @()
    foreach ($frame in ($_.ScriptStackTrace -split "`r?`n")) {
        if ($frame -match '^at ([A-Za-z0-9_<>.-]+), (.+): line ([0-9]+)$') {
            $functionName = $Matches[1]
            $sourceName = [IO.Path]::GetFileName($Matches[2])
            $lineNumber = $Matches[3]
            if ($sourceName -notmatch '^[A-Za-z0-9_.-]+\.ps1$') { $sourceName = '[script]' }
            $safeFrames += 'at ' + $functionName + ', ' + $sourceName + ': line ' + $lineNumber
        }
    }
    $script:Records.Add([ordered]@{ name = $code; status_code = 0; expected_codes = @(); passed = $false; elapsed_ms = 0; request_sha256 = Get-HexHash ''; response_sha256 = Get-HexHash ''; exception_type = $_.Exception.GetType().FullName; script_stack_trace = $safeFrames })
} finally {
    if ($script:RulesMatched -and $script:AdminToken) {
        foreach ($path in @($script:CleanupPaths | Sort-Object)) {
            try { Remove-OwnedPath $path }
            catch {
                $script:Failure = $true
                $script:Records.Add([ordered]@{ name = 'CLEANUP_FAILED'; status_code = 0; expected_codes = @(200); passed = $false; elapsed_ms = 0; request_sha256 = Get-HexHash ''; response_sha256 = Get-HexHash '' })
            }
        }
    }
    foreach ($uid in @($script:CreatedAuthUsers.Keys)) {
        $response = $null
        try {
            if ($uid -notmatch '^[a-f0-9]{32}$' -or !$script:OwnedUids.Contains($uid)) { throw 'UNOWNED_AUTH_CLEANUP_REFUSED' }
            $deleteBody = Get-CanonicalJson @{ idToken = $script:CreatedAuthUsers[$uid] }
            $response = Invoke-PrivateHttp -Method POST -Url ('https://identitytoolkit.googleapis.com/v1/accounts:delete?key=' + [Uri]::EscapeDataString($script:Config.api_key)) -Body $deleteBody -Cleanup
            $deleted = $response.Status -eq 200
            $script:Records.Add([ordered]@{ name = 'cleanup_synthetic_auth_user'; count = 1; status_code = $response.Status; passed = $deleted; elapsed_ms = $response.ElapsedMs; uid_sha256 = Get-HexHash $uid })
            if (!$deleted) { $script:Failure = $true }
        } catch {
            $script:Failure = $true
            $script:Records.Add([ordered]@{ name = 'AUTH_SELF_DELETE_FAILED'; count = 1; status_code = 0; passed = $false; elapsed_ms = 0; uid_sha256 = Get-HexHash $uid })
        } finally {
            $script:CreatedAuthUsers[$uid] = $null
            $deleteBody = $null
        }
    }
    $script:CreatedAuthUsers.Clear()
    $directory = Split-Path -Parent $reportPath
    if (!(Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory) }
    $report = [ordered]@{ name = 'synthetic_protocol_rules_fixtures_not_apk_execution_or_attestation'; passed = !$script:Failure; tests = @($script:Records.ToArray()) }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding utf8
    $script:AdminToken = $null
    $workerA = $null; $workerB = $null; $wrongSession = $null; $expiredClaim = $null
    $script:Client.Dispose()
}
if ($script:Failure) { Write-Output 'Relay Rules verification failed; see the sanitized report.'; exit 1 }
Write-Output 'Relay Rules verification passed; synthetic database paths and newly created Auth users were removed.'

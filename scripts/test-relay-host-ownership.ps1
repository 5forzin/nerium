#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourcePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\relay\RelayHost.psm1'))
$module = New-Module -Name ('RelayOwnershipTest_' + [Guid]::NewGuid().ToString('N')) `
    -ScriptBlock ([scriptblock]::Create([IO.File]::ReadAllText($sourcePath)))

try {
    & $module {
        $names = @('Read-RelayConfig', 'Read-RelaySession', 'Get-RelayOAuth', 'Get-RelayNow',
            'Invoke-RelayHttp', 'Invoke-RelayDatabase', 'Write-RelayReport')
        $originals = @{}
        foreach ($name in $names) { $originals[$name] = (Get-Command $name -CommandType Function).ScriptBlock }
        try {
            $script:ownershipTest = @{}
            function Read-RelayConfig {
                param($Path)
                [pscustomobject]@{project_id = 'offline-fixture'; project_number = 123456789L;
                    database_url = 'https://fixture.invalid'; worker_package = 'dev.androidlab.relayworker'}
            }
            function Read-RelaySession {
                param($Config, $SessionPath)
                [pscustomobject]@{schema_version = 1; session_id = ('a' * 32); worker_uid = ('worker_' + ('b' * 24));
                    expires_at_ms = 1700000900000L; revoked = $false}
            }
            function Get-RelayOAuth { 'offline-placeholder-not-a-credential' }
            function Get-RelayNow { 1700000000000L }
            function Write-RelayReport {
                param($Directory, $Name, $Report)
                $script:ownershipTest.report = $Report
                [pscustomobject]@{status = $Report.status; job_id = $Report.job_id}
            }
            function Invoke-RelayHttp {
                param($Config, $OAuth, $Method, $Uri, $Body, [hashtable]$ExtraHeaders = @{},
                    [int]$TimeoutSeconds = 20, [switch]$WithMetadata)
                $test = $script:ownershipTest
                $test.httpCalls.Add([pscustomobject]@{method = $Method; uri = $Uri; headers = $ExtraHeaders.Clone()})
                if ($Method -ceq 'PUT') {
                    if ($ExtraHeaders['If-Match'] -cne 'null_etag') { throw 'Missing conditional create' }
                    $test.job = $Body
                    if ($test.scenario -ceq 'explicit_412') { throw 'Relay error: HTTP_412' }
                    if ($test.scenario -cin @('lost_foreign', 'lost_owned')) { throw 'Relay error: HTTP_TRANSPORT_FAILED' }
                    return $null
                }
                if ($Method -ceq 'GET' -and $WithMetadata) {
                    if ($ExtraHeaders['X-Firebase-ETag'] -cne 'true') { throw 'Missing metadata request' }
                    $test.metadataReads++
                    $identity = [pscustomobject]@{request_sha256 = $test.job.request_sha256; job_id = $test.job.job_id;
                        session_id = $test.job.session_id; worker_uid = $test.job.worker_uid}
                    if ($test.scenario -ceq 'lost_foreign') { $identity.request_sha256 = 'f' * 64 }
                    return [pscustomobject]@{body = $identity; etag = '"offline-owned-etag"'}
                }
                if ($Method -ceq 'DELETE') {
                    if ($ExtraHeaders['If-Match'] -cne '"offline-owned-etag"') { throw 'Missing conditional delete' }
                    $test.deletes.Add([pscustomobject]@{scope = 'inbox'; conditional = $true})
                    return $null
                }
                throw 'Unexpected offline HTTP call'
            }
            function Invoke-RelayDatabase {
                param($Config, $OAuth, $Method, $Path, $Body)
                $test = $script:ownershipTest
                if ($Method -ceq 'GET' -and $Path -like '/relay/v1/sessions/*') {
                    return Read-RelaySession $Config 'unused'
                }
                if ($Method -ceq 'DELETE') {
                    if ($Path -notlike '/relay/v1/executions/*') { throw 'Unexpected deletion path' }
                    $test.deletes.Add([pscustomobject]@{scope = 'execution'; conditional = $false})
                    return $null
                }
                if ($Method -ceq 'GET' -and $Path -like '/relay/v1/executions/*') {
                    $test.executionReads++
                    $job = $test.job
                    $challenge = [Convert]::FromBase64String($job.challenge_base64url.Replace('-', '+').Replace('_', '/') + '=')
                    return [pscustomobject]@{job_id = $job.job_id; session_id = $job.session_id; worker_uid = $job.worker_uid;
                        operation = $job.operation; request_sha256 = $job.request_sha256; lease_id = ('c' * 32);
                        attempt = 1; started_at_ms = 1700000000000L; lease_until_ms = 1700000030000L; state = 'completed';
                        result = [pscustomobject]@{worker_package = 'dev.androidlab.relayworker'; worker_version_code = 1;
                            worker_apk_cert_sha256 = ('d' * 64); completed_at_ms = 1700000000000L;
                            execution_elapsed_ms = 0; challenge_sha256 = Get-RelaySha256 $challenge}}
                }
                throw 'Unexpected offline database call'
            }

            foreach ($name in $names) {
                if ((Get-Command $name -CommandType Function).ScriptBlock -eq $originals[$name]) {
                    throw 'Module-private isolation failed; no broker invocation was attempted'
                }
            }
            $records = [Collections.Generic.List[object]]::new()
            foreach ($scenario in @('lost_foreign', 'lost_owned', 'owned_success', 'explicit_412')) {
                $script:ownershipTest = @{scenario = $scenario; job = $null; report = $null;
                    metadataReads = 0; executionReads = 0;
                    httpCalls = [Collections.Generic.List[object]]::new(); deletes = [Collections.Generic.List[object]]::new()}
                $null = Invoke-RelayJob -ConfigPath 'offline-no-config-read' -SessionPath 'offline-no-session-read' `
                    -Operation echo_sha256 -Name ('ownership_' + $scenario) -TimeoutSeconds 30 -ReportsDirectory 'offline-no-output' 3>$null
                $test = $script:ownershipTest
                if ($scenario -ceq 'lost_foreign') {
                    if ($test.deletes.Count -ne 0 -or $test.metadataReads -ne 1 -or $test.executionReads -ne 0 -or
                        $test.report.status -cne 'failed' -or $test.report.error.code -cne 'HTTP_TRANSPORT_FAILED' -or
                        $test.report.cleanup_state -cne 'not_confirmed') { throw 'Lost PUT ownership regression' }
                } elseif ($scenario -cin @('lost_owned', 'owned_success')) {
                    if ($test.deletes.Count -ne 2 -or $test.deletes[0].scope -cne 'inbox' -or
                        -not $test.deletes[0].conditional -or $test.deletes[1].scope -cne 'execution' -or
                        $test.report.cleanup_state -cne 'completed' -or $test.metadataReads -ne 1) {
                        throw 'Owned cleanup regression'
                    }
                    if ($scenario -ceq 'owned_success') {
                        if ($test.report.status -cne 'completed' -or $test.executionReads -ne 1) { throw 'Completed job regression' }
                    } elseif ($test.report.status -cne 'failed' -or $test.report.error.code -cne 'HTTP_TRANSPORT_FAILED' -or
                        $test.executionReads -ne 0) { throw 'Lost owned PUT regression' }
                } else {
                    if ($test.deletes.Count -ne 0 -or $test.metadataReads -ne 0 -or $test.executionReads -ne 0 -or
                        $test.report.status -cne 'failed' -or $test.report.error.code -cne 'HTTP_412' -or
                        $test.report.Contains('cleanup_state')) { throw 'Explicit conflict regression' }
                }
                $records.Add([pscustomobject]@{scenario = $scenario; passed = $true;
                    delete_count = $test.deletes.Count; metadata_reads = $test.metadataReads})
            }
            $records | ConvertTo-Json -Depth 5
        } finally {
            foreach ($name in $names) { Set-Item -Path ('Function:' + $name) -Value $originals[$name] }
            $script:ownershipTest = $null
        }
    }
} finally {
    Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
}

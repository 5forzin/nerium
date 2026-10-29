#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Start','Stop','Status')][string]$Action,
    [string]$ConfigPath = "$env:LOCALAPPDATA\android-device-lab\research-v36\cloud-config.json",
    [string]$WorkerSessionPath = "$env:LOCALAPPDATA\android-device-lab\research-v37\worker-session.json",
    [string]$PairRoot = "$env:LOCALAPPDATA\android-device-lab\research-v37\requester",
    [string]$RequesterSerial,
    [ValidateSet('once','persistent')][string]$ExecutionMode = 'persistent'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$relayModule = Import-Module (Join-Path $PSScriptRoot '..\relay\RelayHost.psm1') -Force -PassThru
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$PairRoot = [IO.Path]::GetFullPath($PairRoot)
$privateBase = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'android-device-lab')) + [IO.Path]::DirectorySeparatorChar
if (!$PairRoot.StartsWith($privateBase,[StringComparison]::OrdinalIgnoreCase)) { throw 'REQUESTER_PRIVATE_ROOT_REQUIRED' }
$currentPath = Join-Path $PairRoot 'current-pair.json'

function Private-Directory([string]$Path) {
    & $relayModule { param($p) Protect-RelayDirectory $p } $Path
}
function Private-Json([string]$Path, $Value) {
    & $relayModule { param($p,$v) Save-RelayPrivate $p $v } $Path $Value
}
function Adb([string]$Serial, [string[]]$Arguments, [string]$InputText) {
    & $relayModule { param($s,$a,$i) Invoke-RelayAdb $s $a $i } $Serial $Arguments $InputText
}
function Owned-Process($Record) {
    $process = Get-Process -Id $Record.pid -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    $start = [DateTimeOffset]::new($process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()
    if ($process.Path -cne $Record.node_path -or [Math]::Abs($start - [long]$Record.process_started_at_ms) -gt 1000) {
        throw 'REQUESTER_PROCESS_IDENTITY'
    }
    return $process
}

try {
    if ($Action -ne 'Start') {
        if (!(Test-Path -LiteralPath $currentPath -PathType Leaf)) { throw 'REQUESTER_PAIR_MISSING' }
        $record = Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
        if ($record.schema_version -ne 1 -or $record.pair_id -cnotmatch '^[a-f0-9]{32}$' -or
            $record.port -lt 1 -or $record.port -gt 65535) { throw 'REQUESTER_PAIR_INVALID' }
        $process = Owned-Process $record
        if ($Action -eq 'Status') {
            [pscustomobject]@{pair_id=$record.pair_id; running=($null -ne $process);
                expires_at_ms=$record.expires_at_ms; port=$record.port; requester_serial=$record.requester_serial}
            exit 0
        }
        $brokerConfig = Get-Content -LiteralPath (Join-Path $record.pair_directory 'broker-config.json') -Raw | ConvertFrom-Json
        $revoked = $false
        try {
            $null = Revoke-RelaySession -ConfigPath $brokerConfig.cloud_config_path -SessionPath $brokerConfig.worker_session_path
            $revoked = $true
        } catch { Write-Warning 'Worker session revocation could not be confirmed.' }
        if ($null -ne $process) {
            $process.Kill($true)
            if (!$process.WaitForExit(5000)) { throw 'REQUESTER_PROCESS_TERMINATION_UNCONFIRMED' }
        }
        try { Adb $record.requester_serial @('shell','am','force-stop','dev.androidlab.relayrequester') }
        catch { Write-Warning 'Requester is unavailable; its application could not be stopped.' }
        if ($record.tunnel_created) {
            try { Adb $record.requester_serial @('reverse','--remove',('tcp:'+$record.port)) }
            catch { Write-Warning 'Requester tunnel is unavailable; its removal could not be confirmed.' }
        }
        [pscustomobject]@{status='stopped';pair_id=$record.pair_id;worker_session_revoked=$revoked}
        if (!$revoked) { exit 1 }
        exit 0
    }

    if (!$RequesterSerial -or $RequesterSerial -cnotmatch '^[A-Za-z0-9_.:-]{1,128}$') { throw 'REQUESTER_SERIAL_REQUIRED' }
    if (Test-Path -LiteralPath $currentPath) {
        $previous = Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
        if ($null -ne (Owned-Process $previous)) { throw 'REQUESTER_BROKER_ALREADY_RUNNING' }
    }
    $cloud = & $relayModule { param($p) Read-RelayConfig $p } $ConfigPath
    $session = & $relayModule { param($c,$p) Read-RelaySession $c $p } $cloud $WorkerSessionPath
    $status = Get-RelayStatus -ConfigPath $ConfigPath -SessionPath $WorkerSessionPath
    if ($status.revoked -or $status.expired -or $status.expires_at_ms -lt [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+30000) {
        throw 'WORKER_SESSION_UNAVAILABLE'
    }
    $apkPath = Join-Path $projectRoot 'relayrequester\build\outputs\apk\debug\relayrequester-debug.apk'
    if (!(Test-Path -LiteralPath $apkPath -PathType Leaf)) { throw 'REQUESTER_APK_MISSING' }
    $gcloud = Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
    $hostAccount = ((& $gcloud config get-value account --quiet 2>$null) -join '').Trim()
    if($LASTEXITCODE -ne 0 -or $hostAccount -cnotmatch '^[^\s@]+@[^\s@]+$'){throw 'REQUESTER_HOST_ACCOUNT'}
    $hostConfiguration = ((& $gcloud config configurations list '--filter=is_active:true' '--format=value(name)' --quiet 2>$null) -join '').Trim()
    if($LASTEXITCODE -ne 0 -or $hostConfiguration -cnotmatch '^[a-z][a-z0-9_-]{0,62}$'){throw 'REQUESTER_HOST_CONFIGURATION'}
    Private-Directory $PairRoot
    $pairId = [Guid]::NewGuid().ToString('N')
    $pairDirectory = Join-Path $PairRoot $pairId
    Private-Directory $pairDirectory
    $stateDirectory = Join-Path $pairDirectory 'state'
    Private-Directory $stateDirectory
    $bearer = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    $certificate = $null
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Android Device Lab local broker', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddIpAddress([Net.IPAddress]::Loopback)
        $request.CertificateExtensions.Add($san.Build())
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,$true))
        $usages = [Security.Cryptography.OidCollection]::new()
        [void]$usages.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages,$true))
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::FromUnixTimeMilliseconds($session.expires_at_ms).AddMinutes(5))
        $certificatePem = $certificate.ExportCertificatePem()
        $certificatePath = Join-Path $pairDirectory 'server-certificate.pem'
        $keyPath = Join-Path $pairDirectory 'server-key.pem'
        [IO.File]::WriteAllText($certificatePath,$certificatePem,[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($keyPath,$rsa.ExportPkcs8PrivateKeyPem(),[Text.UTF8Encoding]::new($false))
        $spki = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rsa.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
    } finally { if($certificate){$certificate.Dispose()}; $rsa.Dispose() }

    $nodePath = (Get-Command node.exe -ErrorAction Stop).Source
    $pwshPath = Join-Path $PSHOME 'pwsh.exe'
    $brokerPath = Join-Path $projectRoot 'relay\requester-broker.mjs'
    $brokerConfigPath = Join-Path $pairDirectory 'broker-config.json'
    $readyPath = Join-Path $pairDirectory 'transport.json'
    Private-Json $brokerConfigPath ([ordered]@{schema_version=1;pair_id=$pairId;bearer_token=$bearer;
        session_id=$session.session_id;expires_at_ms=$session.expires_at_ms;port=0;
        certificate_path=$certificatePath;key_path=$keyPath;state_directory=$stateDirectory;
        cloud_config_path=[IO.Path]::GetFullPath($ConfigPath);worker_session_path=[IO.Path]::GetFullPath($WorkerSessionPath);
        pwsh_path=$pwshPath;job_script_path=(Join-Path $PSScriptRoot 'relay-broker-job.ps1');
        reports_directory=(Join-Path $projectRoot 'reports');readiness_file=$readyPath;
        execution_mode=$ExecutionMode;service_script_path=(Join-Path $PSScriptRoot 'relay-broker-service.ps1');
        auth_account=$hostAccount;auth_configuration=$hostConfiguration})
    $process = Start-Process -FilePath $nodePath -ArgumentList @(('"'+$brokerPath+'"'),'--config',('"'+$brokerConfigPath+'"')) `
        -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $pairDirectory 'broker-stdout.log') `
        -RedirectStandardError (Join-Path $pairDirectory 'broker-stderr.log') -PassThru
    $startMs = [DateTimeOffset]::new($process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()
    $readyWatch = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $readyPath)) {
        $process.Refresh()
        if ($process.HasExited -or $readyWatch.ElapsedMilliseconds -gt $(if($ExecutionMode -eq 'persistent'){35000}else{10000})) { throw 'REQUESTER_BROKER_START_FAILED' }
        Start-Sleep -Milliseconds 100
    }
    $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    if ($ready.pair_id -cne $pairId -or $ready.pid -ne $process.Id -or $ready.state -cne 'listening' -or $ready.port -lt 1 -or $ready.port -gt 65535 -or
        $ready.spki_sha256 -cne [Convert]::ToBase64String([Convert]::FromHexString($spki))) {
        throw 'REQUESTER_BROKER_READINESS'
    }
    $clientConfig = [ordered]@{schema_version=1;pair_id=$pairId;broker_url=('https://127.0.0.1:'+$ready.port);
        server_certificate_pem=$certificatePem;server_spki_sha256=$spki;bearer_token=$bearer;expires_at_ms=$session.expires_at_ms}
    Private-Json (Join-Path $pairDirectory 'requester-config.json') $clientConfig
    $record = [ordered]@{schema_version=1;pair_id=$pairId;pair_directory=$pairDirectory;requester_serial=$RequesterSerial;
        port=$ready.port;pid=$process.Id;node_path=$process.Path;process_started_at_ms=$startMs;expires_at_ms=$session.expires_at_ms;tunnel_created=$false;execution_mode=$ExecutionMode}
    Private-Json $currentPath $record
    Adb $RequesterSerial @('install','-r',$apkPath)
    Adb $RequesterSerial @('shell','am','force-stop','dev.androidlab.relayrequester')
    Adb $RequesterSerial @('shell','run-as','dev.androidlab.relayrequester','mkdir','-p','files')
    Adb $RequesterSerial @('shell','-T','run-as','dev.androidlab.relayrequester','dd','of=files/requester-config.json') ($clientConfig | ConvertTo-Json -Compress)
    Adb $RequesterSerial @('shell','run-as','dev.androidlab.relayrequester','chmod','600','files/requester-config.json')
    Adb $RequesterSerial @('reverse','--no-rebind',('tcp:'+$ready.port),('tcp:'+$ready.port))
    $record.tunnel_created = $true
    Private-Json $currentPath $record
    Adb $RequesterSerial @('shell','am','start','-W','-n','dev.androidlab.relayrequester/.MainActivity')
    [pscustomobject]@{status='paired';pair_id=$pairId;port=$ready.port;expires_at_ms=$session.expires_at_ms;requester_serial=$RequesterSerial}
} catch {
    if ($Action -eq 'Start' -and $null -ne (Get-Variable record -ValueOnly -ErrorAction SilentlyContinue) -and $record.tunnel_created) {
        try { Adb $record.requester_serial @('reverse','--remove',('tcp:'+$record.port)); $record.tunnel_created=$false; Private-Json $currentPath $record } catch {}
    }
    if ($Action -eq 'Start' -and $null -ne (Get-Variable process -ValueOnly -ErrorAction SilentlyContinue)) {
        try { if (!$process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(5000) } } catch {}
    }
    $code = if ($_.Exception.Message -cmatch '^(?:Relay error: )?([A-Z0-9_]+)$') { $Matches[1] } else { 'REQUESTER_SETUP_FAILED' }
    Write-Error $code
    exit 1
} finally { $bearer=$null; $clientConfig=$null }

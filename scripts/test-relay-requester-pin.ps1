#requires -Version 7.2
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.:-]{1,128}$')][string]$Serial,
    [string]$PairRoot = "$env:LOCALAPPDATA\android-device-lab\research-v37\requester",
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_-]{1,80}$')][string]$Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'dev.androidlab.relayrequester'
$module = Import-Module (Join-Path $PSScriptRoot '..\relay\RelayHost.psm1') -Force -PassThru
$summary = [ordered]@{schema_version = 1; test = 'requester_tls_pin_rejection'; passed = $false;
    code = 'NOT_RUN'; receipts_before = $null; receipts_after = $null; restored_hash_match = $false}
$original = $null
$restoreRequired = $false

function Adb([string[]]$Arguments, [string]$InputText) {
    & $module { param($serial,$arguments,$text) Invoke-RelayAdb $serial $arguments $text } $Serial $Arguments $InputText
}

function Write-PrivateBytes([byte[]]$Bytes) {
    # Only ASCII travels through Windows shell stdin; Android decodes the original bytes.
    $encoded = [Convert]::ToBase64String($Bytes)
    Adb @('shell','-T','run-as','dev.androidlab.relayrequester','sh','-c',
        "'base64 -d > files/requester-config.json'") $encoded
}

function Set-PrivateConfig([byte[]]$Bytes) {
    Adb @('shell','am','force-stop',$package)
    Write-PrivateBytes $Bytes
    Adb @('shell','run-as',$package,'chmod','600','files/requester-config.json')
    $expected = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
    $confirmed = $false
    for ($attempt=0; $attempt -lt 5; $attempt++) {
        if ((Get-DeviceConfigHash) -ceq $expected) { $confirmed = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $confirmed) { throw 'PIN_PROVISION_HASH' }
    Adb @('shell','am','start','-W','-n',($package+'/.MainActivity'))
}

function Get-DeviceConfigHash {
    $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'))
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in @('-s',$Serial,'exec-out','run-as',$package,'sha256sum','files/requester-config.json')) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'PIN_HASH_START' }
        $output = $process.StandardOutput.ReadToEndAsync()
        $errorOutput = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { $process.Kill($true); throw 'PIN_HASH_TIMEOUT' }
        $text = $output.GetAwaiter().GetResult()
        $null = $errorOutput.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $text.Length -gt 1024 -or
            $text -cnotmatch '^([a-f0-9]{64})\s+files/requester-config\.json\s*$') { throw 'PIN_HASH_FAILED' }
        $Matches[1]
    } finally { $process.Dispose() }
}

try {
    $PairRoot = [IO.Path]::GetFullPath($PairRoot)
    $privateBase = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'android-device-lab')) + [IO.Path]::DirectorySeparatorChar
    if (-not $PairRoot.StartsWith($privateBase,[StringComparison]::OrdinalIgnoreCase)) { throw 'PIN_PRIVATE_ROOT' }
    $record = Get-Content -LiteralPath (Join-Path $PairRoot 'current-pair.json') -Raw | ConvertFrom-Json
    if ($record.schema_version -ne 1 -or $record.pair_id -cnotmatch '^[a-f0-9]{32}$' -or
        $record.requester_serial -cne $Serial) { throw 'PIN_PAIR_IDENTITY' }
    $pairDirectory = [IO.Path]::GetFullPath([string]$record.pair_directory)
    if ($pairDirectory -cne [IO.Path]::GetFullPath((Join-Path $PairRoot $record.pair_id))) { throw 'PIN_PAIR_DIRECTORY' }
    $stateDirectory = Join-Path $pairDirectory 'state'
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) { throw 'PIN_STATE_DIRECTORY' }
    $configPath = Join-Path $pairDirectory 'requester-config.json'
    $raw = [IO.File]::ReadAllBytes($configPath)
    if ($raw.Length -lt 1 -or $raw.Length -gt 32768) { throw 'PIN_CONFIG_SIZE' }
    $original = [Text.UTF8Encoding]::new($false,$true).GetString($raw)
    $originalHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
    $config = $original | ConvertFrom-Json
    if ($config.schema_version -ne 1 -or $config.pair_id -cne $record.pair_id -or
        $config.server_spki_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $config.server_spki_sha256 -ceq ('0'*64)) {
        throw 'PIN_CONFIG_IDENTITY'
    }
    $negativeName = $Name + '_negative'
    $negativePath = Join-Path $PSScriptRoot ('..\reports\' + $negativeName + '.json')
    $priorNegativeId = ''
    if (Test-Path -LiteralPath $negativePath -PathType Leaf) {
        $priorNegative = Get-Content -LiteralPath $negativePath -Raw | ConvertFrom-Json -Depth 20
        if ($null -ne $priorNegative.PSObject.Properties['request_id']) { $priorNegativeId = [string]$priorNegative.request_id }
    }
    $summary.receipts_before = @(Get-ChildItem -LiteralPath $stateDirectory -File -Filter '*.json').Count
    $config.server_spki_sha256 = '0' * 64
    $restoreRequired = $true
    Set-PrivateConfig ([Text.UTF8Encoding]::new($false).GetBytes(($config | ConvertTo-Json -Depth 10 -Compress)))

    $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in @('-NoProfile','-File',(Join-Path $PSScriptRoot 'test-relay-requester-device.ps1'),
        '-Serial',$Serial,'-Operation','echo_sha256','-Name',$negativeName,'-TimeoutSeconds','40')) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'PIN_TEST_START' }
        $output = $process.StandardOutput.ReadToEndAsync()
        $errorOutput = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) { $process.Kill($true); throw 'PIN_TEST_TIMEOUT' }
        $null = $output.GetAwaiter().GetResult()
        $null = $errorOutput.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    } finally { $process.Dispose() }
    if (-not (Test-Path -LiteralPath $negativePath -PathType Leaf)) { throw 'PIN_NEGATIVE_REPORT_MISSING' }
    $negative = Get-Content -LiteralPath $negativePath -Raw | ConvertFrom-Json -Depth 20
    $summary.receipts_after = @(Get-ChildItem -LiteralPath $stateDirectory -File -Filter '*.json').Count
    if ($exitCode -ne 1 -or $negative.request_id -cnotmatch '^[a-f0-9]{32}$' -or $negative.request_id -ceq $priorNegativeId -or
        $negative.operation -cne 'echo_sha256' -or $negative.origin -cne 'cooperative_remote_worker' -or
        $negative.verification_state -cne 'failed' -or $negative.error_code -cne 'TLS_REJECTED' -or
        $negative.requester_integrity_verified -isnot [bool] -or $negative.requester_integrity_verified -or
        $summary.receipts_before -ne $summary.receipts_after) { throw 'PIN_NEGATIVE_UNEXPECTED' }
    $summary.code = 'TLS_REJECTED'
    $summary.passed = $true
} catch {
    $summary.passed = $false
    $summary.code = if ($_.Exception.Message -cmatch '^PIN_[A-Z0-9_]+$') { $_.Exception.Message } else { 'PIN_TEST_FAILED' }
} finally {
    if ($restoreRequired) {
        try {
            Set-PrivateConfig $raw
            $summary.restored_hash_match = (Get-DeviceConfigHash) -ceq $originalHash
        } catch { $summary.restored_hash_match = $false }
        if (-not $summary.restored_hash_match) { $summary.passed = $false; $summary.code = 'PIN_RESTORATION_UNCONFIRMED' }
    }
    $original = $null; $config = $null; $raw = $null
    $reports = Join-Path $PSScriptRoot '..\reports'
    $null = New-Item -ItemType Directory -Path $reports -Force
    $destination = [IO.Path]::GetFullPath((Join-Path $reports ($Name+'.json')))
    [IO.File]::WriteAllText($destination,($summary | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
[pscustomobject]@{passed=$summary.passed;code=$summary.code;receipts_before=$summary.receipts_before;
    receipts_after=$summary.receipts_after;restored_hash_match=$summary.restored_hash_match;report_path=$destination}
if (-not $summary.passed -or -not $summary.restored_hash_match) { exit 1 }
exit 0

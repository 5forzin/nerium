#requires -Version 7.0
param(
    [Parameter(Mandatory = $true)][string]$Serial,
    [Parameter(Mandatory = $true)][ValidateSet('echo_sha256', 'play_integrity')][string]$Operation,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_-]{1,100}$')][string]$Name,
    [ValidateRange(30,150)][int]$TimeoutSeconds = 130
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'dev.androidlab.relayrequester'
$adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$uiPath = '/data/local/tmp/requester-v37-ui.xml'

function Invoke-RequesterAdb {
    param([string[]]$Arguments, [int]$TimeoutMs = 15000, [int]$MaxChars = 262144, [switch]$AllowFailure)
    $info = [Diagnostics.ProcessStartInfo]::new($adb)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in (@('-s', $Serial) + $Arguments)) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Requester test: ADB_START_FAILED' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            $process.Kill($true)
            throw 'Requester test: ADB_TIMEOUT'
        }
        $text = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($text.Length -gt $MaxChars) { throw 'Requester test: ADB_OUTPUT_SIZE' }
        if ($process.ExitCode -ne 0) {
            if ($AllowFailure) { return $null }
            throw 'Requester test: ADB_FAILED'
        }
        $text
    } catch {
        if ($_.Exception.Message -cmatch '^Requester test: [A-Z0-9_]+$') { throw $_.Exception.Message }
        throw 'Requester test: ADB_TRANSPORT_FAILED'
    } finally { $process.Dispose() }
}

function Read-RequesterResult {
    param([int]$TimeoutMs = 10000)
    $text = Invoke-RequesterAdb -Arguments @('exec-out', 'run-as', $package, 'cat', 'files/requester-result.json') `
        -TimeoutMs $TimeoutMs -MaxChars 16384 -AllowFailure
    if (-not $text) { return $null }
    try { return $text | ConvertFrom-Json -Depth 20 }
    catch { return $null }
}

try {
    if ($Serial -cnotmatch '^[A-Za-z0-9_.:-]{1,128}$') { throw 'Requester test: SERIAL_FORMAT' }
    if (-not (Test-Path -LiteralPath $adb -PathType Leaf)) { throw 'Requester test: ADB_MISSING' }
    $before = Read-RequesterResult
    $priorId = if ($null -ne $before -and $null -ne $before.PSObject.Properties['request_id']) {
        [string]$before.request_id
    } else { '' }

    $dump = Invoke-RequesterAdb -Arguments @('shell', 'uiautomator', 'dump', $uiPath)
    if ($dump -notmatch ('(?i)dumped to:\s*' + [Regex]::Escape($uiPath))) {
        throw 'Requester test: UI_DUMP_NOT_CONFIRMED'
    }
    $xmlText = Invoke-RequesterAdb -Arguments @('exec-out', 'cat', $uiPath)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($xmlText), $settings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
    } finally { $reader.Dispose() }
    $label = if ($Operation -eq 'echo_sha256') { 'RUN ECHO' } else { 'RUN INTEGRITY' }
    $buttons = @($document.SelectNodes('//node') | Where-Object {
        $_.GetAttribute('package') -ceq $package -and
        $_.GetAttribute('text') -ieq $label -and
        $_.GetAttribute('enabled') -ceq 'true' -and
        $_.GetAttribute('clickable') -ceq 'true'
    })
    if ($buttons.Count -ne 1) { throw 'Requester test: UNIQUE_ENABLED_BUTTON_NOT_FOUND' }
    $bounds = $buttons[0].GetAttribute('bounds')
    if ($bounds -cnotmatch '^\[(\d{1,5}),(\d{1,5})\]\[(\d{1,5}),(\d{1,5})\]$') {
        throw 'Requester test: BUTTON_BOUNDS_FORMAT'
    }
    $left = [int]$Matches[1]; $top = [int]$Matches[2]
    $right = [int]$Matches[3]; $bottom = [int]$Matches[4]
    if ($right -le $left -or $bottom -le $top) { throw 'Requester test: BUTTON_BOUNDS_EMPTY' }
    $x = [int][Math]::Floor(($left + $right) / 2)
    $y = [int][Math]::Floor(($top + $bottom) / 2)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $null = Invoke-RequesterAdb -Arguments @('shell', 'input', 'tap', [string]$x, [string]$y) `
        -TimeoutMs ([Math]::Min(15000, $TimeoutSeconds * 1000))
    $result = $null
    while ($clock.ElapsedMilliseconds -lt $TimeoutSeconds * 1000L) {
        $remaining = $TimeoutSeconds * 1000L - $clock.ElapsedMilliseconds
        $candidate = Read-RequesterResult -TimeoutMs ([int][Math]::Max(1, [Math]::Min(10000, $remaining)))
        if ($null -ne $candidate -and $null -ne $candidate.PSObject.Properties['request_id']) {
            $id = [string]$candidate.request_id
            if ($id -cmatch '^[a-f0-9]{32}$' -and $id -cne $priorId) { $result = $candidate; break }
        }
        $remaining = $TimeoutSeconds * 1000L - $clock.ElapsedMilliseconds
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(500, $remaining)) }
    }
    $clock.Stop()
    if ($null -eq $result) { throw 'Requester test: NEW_RESULT_TIMEOUT' }
    $reports = Join-Path $PSScriptRoot '..\reports'
    $null = New-Item -ItemType Directory -Path $reports -Force
    $destination = [IO.Path]::GetFullPath((Join-Path $reports ($Name + '.json')))
    [IO.File]::WriteAllText($destination, (ConvertTo-Json -InputObject $result -Depth 20), [Text.UTF8Encoding]::new($false))
    $verified = $null -ne $result.PSObject.Properties['verification_state'] -and
        $result.verification_state -ceq 'verified_remote_result' -and
        $null -ne $result.PSObject.Properties['operation'] -and $result.operation -ceq $Operation -and
        $null -ne $result.PSObject.Properties['origin'] -and $result.origin -ceq 'cooperative_remote_worker' -and
        $null -ne $result.PSObject.Properties['requester_integrity_verified'] -and
        $result.requester_integrity_verified -is [bool] -and -not $result.requester_integrity_verified
    [pscustomobject]@{
        status = if ($verified) { 'passed' } else { 'failed' }
        verification_state = if ($null -ne $result.PSObject.Properties['verification_state']) { $result.verification_state } else { 'missing' }
        report_path = $destination
        requester_integrity_verified = $false
    }
    if (-not $verified) { exit 1 }
} catch {
    if ($_.Exception.Message -cmatch '^Requester test: [A-Z0-9_]+$') { Write-Error $_.Exception.Message }
    else { Write-Error 'Requester test: FAILED' }
    exit 1
}

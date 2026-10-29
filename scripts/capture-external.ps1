param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Detector,
    [string]$Serial = 'emulator-5554',
    [int]$CurrentProcessId = 0,
    [string]$ExportedReport,
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CatalogPath = (Join-Path $PSScriptRoot 'detectors.json')
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$catalog = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json
$entry = @($catalog | Where-Object { $_.id -eq $Detector })
if ($entry.Count -ne 1) { throw 'Select one detector from detectors.json.' }
$entry = $entry[0]
if (($CurrentProcessId -gt 0 -or $ExportedReport) -and ($entry.id -ne 'duck' -or $CurrentProcessId -le 0 -or -not $ExportedReport)) {
    throw 'An existing process and exported report may only be paired for Duck Detector.'
}
if ($entry.capture -eq 'reveny-emulator') {
    & "$PSScriptRoot\capture-detector.ps1" -Name $Name -Serial $Serial -SdkRoot $SdkRoot
    return
}
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$reports = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\reports'))
$prefix = Join-Path $reports $Name
New-Item -ItemType Directory -Path $reports -Force | Out-Null
$paths = @(& $adb -s $Serial shell pm path $entry.package)
if ($LASTEXITCODE -ne 0) { throw 'Could not query detector APK.' }
$paths = @($paths | Where-Object { $_.StartsWith('package:') })
if ($paths.Count -ne 1) { throw 'Expected one installed APK.' }
$apkPath = $paths[0].Substring(8).Trim()
$hashOutput = (& $adb -s $Serial shell sha256sum $apkPath) -join ''
if ($LASTEXITCODE -ne 0 -or ($hashOutput -split '\s+')[0] -ne $entry.sha256) { throw 'Installed APK checksum mismatch.' }
$packageInfo = @(& $adb -s $Serial shell dumpsys package $entry.package)
$abiLine = @($packageInfo | Where-Object { $_ -match '^\s*primaryCpuAbi=' })
if ($abiLine.Count -ne 1) { throw 'Could not identify detector ABI.' }
$abi = ($abiLine[0] -split '=', 2)[1].Trim()
if ($abi -ne $entry.abi) { throw "Installed ABI mismatch: $abi" }
$since = ((& $adb -s $Serial shell date '+%m-%d_%H:%M:%S.000') -join '').Trim().Replace('_', ' ')
if ($CurrentProcessId -gt 0) {
    $launch = 'Capturing the explicitly identified scan after its built-in report export.'
} else {
    & $adb -s $Serial shell am force-stop $entry.package | Out-Null
    $launch = (& $adb -s $Serial shell am start -W -n "$($entry.package)/$($entry.activity)") -join "`n"
    Start-Sleep -Seconds $(if ($entry.capture -eq 'compose') { 10 } else { 3 })
}
$detectorPid = ((& $adb -s $Serial shell pidof $entry.package) -join '').Trim()
if ($CurrentProcessId -gt 0 -and $detectorPid -ne "$CurrentProcessId") { throw 'Duck process changed before report capture.' }
$activities = (& $adb -s $Serial shell dumpsys activity activities) -join "`n"
$foreground = @($activities -split '\r?\n' | Where-Object { $_ -match 'topResumedActivity|mResumedActivity' }) -join "`n"
$running = $detectorPid -match '^\d+$'
$visible = $running -and $foreground.Contains($entry.package)
$status = if (-not $running) { 'unavailable' } elseif (-not $visible) { 'not_visible' } else { 'needs_review' }
$reason = if (-not $running) { 'Process exited before a result was collected.' } elseif (-not $visible) { 'Detector is not the foreground activity.' } else { 'Result needs visual review.' }
$detected = $null
$resultText = $null
$texts = @()
$duckEvidence = $null
$remoteXml = '/sdcard/device-lab-external.xml'
function Read-FreshUi {
    & $adb -s $Serial shell rm -f $remoteXml
    & $adb -s $Serial shell uiautomator dump $remoteXml | Out-Null
    if ($LASTEXITCODE -ne 0) { return $null }
    & $adb -s $Serial pull $remoteXml "$prefix.xml" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { return $null }
    $document = [xml](Get-Content -LiteralPath "$prefix.xml" -Raw)
    if ($null -eq $document.SelectSingleNode("//*[@package='$($entry.package)']")) { return $null }
    return $document
}
if ($visible) {
    $ui = Read-FreshUi
    if ($null -ne $ui -and $entry.capture -eq 'spotter') {
        $button = $ui.SelectSingleNode("//*[@resource-id='$($entry.package):id/button']")
        if ($null -ne $button -and $button.bounds -match '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$') {
            $x = [int](([int]$Matches[1] + [int]$Matches[3]) / 2)
            $y = [int](([int]$Matches[2] + [int]$Matches[4]) / 2)
            & $adb -s $Serial shell input tap $x $y
            Start-Sleep -Seconds 2
            $ui = Read-FreshUi
        }
        if ($null -ne $ui) {
            $resultNode = $ui.SelectSingleNode("//*[@resource-id='$($entry.package):id/info']")
            if ($null -ne $resultNode) {
                $resultText = [string]$resultNode.text
                if ($resultText -match 'Is this an Emulator\? (YES|NO)') {
                    $detected = $Matches[1] -eq 'YES'
                    $status = 'complete'
                    $reason = 'Fresh result read from the unchanged detector APK.'
                }
            }
        }
    }
    if ($null -ne $ui) { $texts = @($ui.SelectNodes('//*[@text!=""]') | ForEach-Object { [string]$_.text }) }
    if ($null -ne $ui -and $entry.capture -eq 'framgia') {
        $resultNode = $ui.SelectSingleNode("//*[@resource-id='$($entry.package):id/text']")
        if ($null -ne $resultNode) {
            $resultText = [string]$resultNode.text
            if ($resultText -match '^This device is (not )?emulator') {
                $detected = -not $Matches[1]
                $status = 'complete'
                $reason = 'Fresh result read from the unchanged detector APK.'
            }
        }
    }
    if ($null -ne $ui -and $entry.capture -eq 'duck' -and $ExportedReport) {
        if ($ExportedReport -notmatch '^/sdcard/Download/[a-zA-Z0-9_-]+\.txt$') { throw 'Use a laboratory report in Downloads.' }
        $modified = ((& $adb -s $Serial shell stat -c %Y $ExportedReport) -join '').Trim()
        $deviceNow = ((& $adb -s $Serial shell date +%s) -join '').Trim()
        if ($modified -notmatch '^\d+$' -or $deviceNow -notmatch '^\d+$' -or [Math]::Abs([long]$deviceNow - [long]$modified) -gt 300) {
            throw 'Duck export is missing or older than five minutes.'
        }
        $exportPath = "$prefix-export.txt"
        & $adb -s $Serial pull $ExportedReport $exportPath 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not retrieve the built-in Duck report.' }
        $export = [IO.File]::ReadAllText($exportPath)
        if (-not $entry.export_version -or -not $entry.build_commit -or -not $entry.ready_modules) {
            throw 'Duck catalog lacks pinned export identity and module count.'
        }
        if (-not $export.Contains("App Version    : $($entry.export_version)") -or
            -not $export.Contains("Build Commit   : $($entry.build_commit)") -or -not $export.Contains('END OF REPORT')) {
            throw 'Duck export identity or completeness differs from the pinned build.'
        }
        $statistics = [ordered]@{}
        foreach ($label in @('Danger', 'Warning', 'Ready', 'Pending')) {
            $match = [regex]::Match($export, "(?m)^\s+\[[^\r\n]+\]\s+$label\s*:\s*(\d+)\s*$")
            if (-not $match.Success) { throw "Duck export lacks $label statistics." }
            $statistics[$label] = [int]$match.Groups[1].Value
            if ($texts -notcontains $label -or $texts -notcontains "$($statistics[$label])") { throw "Duck UI does not corroborate $label statistics." }
        }
        if ($statistics.Pending -ne 0 -or $statistics.Ready -ne $entry.ready_modules) { throw 'Duck scan is incomplete.' }
        $verdicts = @([regex]::Matches($export, '(?m)^  \[[^\]\r\n]+ (DANGER|WARNING|INFO|CLEAR)\] ([^\r\n]+)\r?\n  Verdict\s*:\s*([^\r\n]+)') | ForEach-Object {
            [ordered]@{ severity = $_.Groups[1].Value; detector = $_.Groups[2].Value; verdict = $_.Groups[3].Value }
        })
        if ($verdicts.Count -ne $statistics.Ready) { throw 'Duck module verdict count differs from its statistics.' }
        $detected = $statistics.Danger -gt 0 -or $statistics.Warning -gt 0
        $status = 'complete'
        $reason = 'Built-in report from the pinned APK corroborated by its current process and dashboard.'
        $resultText = ([regex]::Match($export, '(?m)^  Overall Status\s*:\s*(.+)$')).Groups[1].Value.Trim()
        $duckEvidence = [ordered]@{
            scan_statistics = $statistics
            module_verdicts = $verdicts
            export_report = [IO.Path]::GetFileName($exportPath)
            export_sha256 = (Get-FileHash -LiteralPath $exportPath -Algorithm SHA256).Hash.ToLowerInvariant()
            exported_report_mtime = [long]$modified
        }
    }
}
$remotePng = '/sdcard/device-lab-external.png'
& $adb -s $Serial shell rm -f $remotePng
& $adb -s $Serial shell screencap -p $remotePng
if ($LASTEXITCODE -ne 0) { throw 'Could not capture fresh screenshot.' }
& $adb -s $Serial pull $remotePng "$prefix.png" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not transfer screenshot.' }
$finalPid = ((& $adb -s $Serial shell pidof $entry.package) -join '').Trim()
$finalActivities = (& $adb -s $Serial shell dumpsys activity activities) -join "`n"
$finalForeground = @($finalActivities -split '\r?\n' | Where-Object { $_ -match 'topResumedActivity|mResumedActivity' }) -join "`n"
if ($finalPid -ne $detectorPid -or $finalPid -notmatch '^\d+$') {
    $status = 'unavailable'
    $detected = $null
    $reason = 'Detector exited or restarted during result collection.'
} elseif (-not $finalForeground.Contains($entry.package)) {
    $status = 'not_visible'
    $detected = $null
    $reason = 'Detector lost the foreground before evidence collection finished.'
}
$log = (& $adb -s $Serial logcat -d -v threadtime -T $since) -join "`n"
if ($running -and $log -match "Fatal signal[^\r\n]*pid $detectorPid\b") {
    $status = 'unavailable'
    $detected = $null
    $reason = 'The current detector process received a fatal native signal.'
}
if ($status -eq 'needs_review' -and @($texts | Where-Object { $_ -match '^(?:& )?Disclaimer$|^User Agreement$|^Startup policy review$' }).Count -gt 0) {
    $status = 'needs_interaction'
    $reason = 'Startup notice is visible; no detector verdict has been collected.'
}
if ($status -eq 'complete' -and $entry.capture -eq 'framgia') {
    $expected = "Running on emulator --> $($detected.ToString().ToLowerInvariant())"
    $processLines = @($log -split '\r?\n' | Where-Object { $_ -match "\s$detectorPid\s+\d+\s" }) -join "`n"
    if (-not $processLines.Contains($expected)) { throw 'Framgia UI was not corroborated by its current process log.' }
}
$log | Set-Content -LiteralPath "$prefix.log" -Encoding utf8
$report = [ordered]@{
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    detector = $entry.id
    version = $entry.version
    package = $entry.package
    release = $entry.release
    apk_sha256 = $entry.sha256
    installed_abi = $abi
    status = $status
    detected = $detected
    reason = $reason
    process_id = if ($running) { [int]$detectorPid } else { $null }
    foreground = $foreground.Trim()
    final_foreground = $finalForeground.Trim()
    final_process_id = $finalPid
    launch = $launch
    ui_result = $resultText
    visible_text = $texts
    screenshot = "$Name.png"
    log = "$Name.log"
}
if ($null -ne $duckEvidence) { $report.duck = $duckEvidence }
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$prefix.json" -Encoding utf8
Write-Output "$Detector`: $status; detected=$detected; checksum and ABI verified."
Write-Output "$prefix.json"

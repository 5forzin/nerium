param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5554',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name without a file extension.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$package = 'com.reveny.emulator.detection.sample'
$activity = "$package/com.reveny.emulatordetector.ui.activity.MainActivity"
$expectedHash = '9f064f3968e9a224612810ec2b6078872f479930ce4dd0fc1f7132b08c6b3f5b'
$reports = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\reports'))
New-Item -ItemType Directory -Path $reports -Force | Out-Null
$apkOutput = @(& $adb -s $Serial shell pm path $package)
if ($LASTEXITCODE -ne 0) { throw 'Could not query the installed detector APK.' }
$apkPaths = @($apkOutput | Where-Object { $_.StartsWith('package:') })
if ($apkPaths.Count -ne 1) { throw 'Expected one installed detector APK.' }
$apkPath = $apkPaths[0].Substring(8).Trim()
if (-not $apkPath.StartsWith('/data/app/')) { throw 'The pinned detector is not installed.' }
$hashLine = & $adb -s $Serial shell sha256sum $apkPath
if ($LASTEXITCODE -ne 0 -or ($hashLine -split '\s+')[0] -ne $expectedHash) { throw 'Installed detector APK does not match the pinned v1.5.0 release.' }
& $adb -s $Serial shell am force-stop $package | Out-Null
& $adb -s $Serial shell am start -W -n $activity | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not start the detector.' }

$result = $null
$remoteXml = '/sdcard/device-lab-detector.xml'
$localXml = Join-Path $reports "$Name.xml"
for ($attempt = 0; $attempt -lt 5; $attempt++) {
    Start-Sleep -Seconds 1
    & $adb -s $Serial shell rm -f $remoteXml
    & $adb -s $Serial shell uiautomator dump $remoteXml | Out-Null
    & $adb -s $Serial pull $remoteXml $localXml 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { continue }
    $ui = [xml](Get-Content -LiteralPath $localXml -Raw)
    $node = $ui.SelectSingleNode('//*[substring(@resource-id, string-length(@resource-id) - 11) = "/result_text"]')
    if ($null -ne $node -and $node.text) {
        $result = [string]$node.text
        break
    }
}
if ($null -eq $result) { throw 'No fresh detector result was visible. Inspect the saved UI dump.' }
$nativeProcessId = ((& $adb -s $Serial shell pidof $package) -join '').Trim()
if ($nativeProcessId -notmatch '^\d+$') { throw 'Detector process is not running.' }
$nativeLog = (& $adb -s $Serial logcat -d --pid=$nativeProcessId -s EmulatorDetection:I) -join "`n"
$nothingDetected = $result.Trim() -eq 'Nothing detected!'
$normalized = $result.Replace('\n', "`n")
$findings = @($normalized -split '\r?\n' | Where-Object { $_.StartsWith('- Detected ') })
if ($nothingDetected) {
    if ($nativeLog -notmatch 'isEmulator: false') { throw 'Clear UI result was not corroborated by the current process log.' }
} elseif ($findings.Count -gt 0) {
    if ($nativeLog -notmatch 'isEmulator: true') { throw 'Detected UI result was not corroborated by the current process log.' }
} else {
    throw "Unrecognized detector result: $result"
}
$nativeLog | Set-Content -LiteralPath (Join-Path $reports "$Name.log") -Encoding utf8
$report = [ordered]@{
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    package = $package
    apk_sha256 = $expectedHash
    process_id = [int]$nativeProcessId
    detected = -not $nothingDetected
    finding_count = $findings.Count
    findings = $findings
    ui_result = $result
    native_log = $nativeLog
}
$destination = Join-Path $reports "$Name.json"
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output $destination
Write-Output "Detected: $($report.detected); findings: $($report.finding_count); APK checksum matched."
if ($findings.Count -gt 0) { $findings | Write-Output }

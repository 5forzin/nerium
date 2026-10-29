param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Serial = 'emulator-5554',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CatalogPath = (Join-Path $PSScriptRoot 'detectors.json')
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$remoteUi = '/sdcard/device-lab-duck-export.xml'
$localUi = Join-Path $PSScriptRoot "..\reports\$Name-export-ui.xml"
$remoteReport = "/sdcard/Download/$Name.txt"

function Read-FreshUi {
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        & $adb -s $Serial shell rm -f $remoteUi
        & $adb -s $Serial shell uiautomator dump $remoteUi 2>$null | Out-Null
        & $adb -s $Serial pull $remoteUi $localUi 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Get-Item -LiteralPath $localUi).Length -gt 0) {
            try {
                $document = [xml](Get-Content -LiteralPath $localUi -Raw)
                if ($document.DocumentElement.Name -eq 'hierarchy' -and $document.SelectNodes('//node').Count -gt 0) { return $document }
            } catch { }
        }
        Start-Sleep -Seconds 1
    }
    throw 'Could not read fresh Android UI.'
}

function Tap-Node($Node) {
    if ($null -eq $Node -or $Node.bounds -notmatch '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$') { throw 'UI control is unavailable.' }
    $x = [int](([int]$Matches[1] + [int]$Matches[3]) / 2)
    $y = [int](([int]$Matches[2] + [int]$Matches[4]) / 2)
    & $adb -s $Serial shell input tap $x $y
    if ($LASTEXITCODE -ne 0) { throw 'Could not activate UI control.' }
}

$deadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
$exportButton = $null
do {
    $ui = Read-FreshUi
    if ($null -ne $ui.SelectSingleNode("//*[@text='Nightly update available']")) {
        Tap-Node ($ui.SelectSingleNode("//*[@text='Later']"))
        continue
    }
    if ($null -eq $ui.SelectSingleNode("//*[@package='com.eltavine.duckdetector']")) { throw 'Duck Detector is not visible.' }
    $exportButton = $ui.SelectSingleNode("//*[@text='Tap to export full report']")
    if ($null -ne $exportButton) { break }
    if ($null -ne $ui.SelectSingleNode("//*[@text='Running local checks']")) {
        Start-Sleep -Seconds 5
    } else {
        & $adb -s $Serial shell input swipe 540 600 540 2010 250
    }
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if ($null -eq $exportButton) { throw 'Duck did not expose a completed scan report.' }
$detectorPid = ((& $adb -s $Serial shell pidof com.eltavine.duckdetector) -join '').Trim()
if ($detectorPid -notmatch '^\d+$') { throw 'Expected one completed Duck application process.' }
& $adb -s $Serial shell rm -f $remoteReport
if ($LASTEXITCODE -ne 0) { throw 'Could not remove a previous export.' }
Tap-Node $exportButton
$ui = Read-FreshUi
$title = $ui.SelectSingleNode("//*[@package='com.google.android.documentsui' and @resource-id='android:id/title' and @class='android.widget.EditText']")
Tap-Node $title
& $adb -s $Serial shell input keycombination 113 29
& $adb -s $Serial shell input text "$Name.txt"
& $adb -s $Serial shell input keyevent 4
$ui = Read-FreshUi
if ($null -eq $ui.SelectSingleNode("//*[@resource-id='android:id/title' and @text='$Name.txt']")) { throw 'Export file name differs.' }
Tap-Node ($ui.SelectSingleNode("//*[@resource-id='android:id/button1' and @text='SAVE']"))
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    & $adb -s $Serial shell test -s $remoteReport
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 1
}
if ($LASTEXITCODE -ne 0) { throw 'Duck did not write its report.' }
& "$PSScriptRoot\capture-external.ps1" -Name $Name -Detector duck -Serial $Serial -SdkRoot $SdkRoot -CatalogPath $CatalogPath -CurrentProcessId ([int]$detectorPid) -ExportedReport $remoteReport

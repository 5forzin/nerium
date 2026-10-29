param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$ServiceAccount,
    [string]$Serial = 'emulator-5556',
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$CloudSdkRoot = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk"
)

$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple report name.' }
if ($ServiceAccount -notmatch '^[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com$') {
    throw 'Expected a service account address.'
}
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$gcloud = Join-Path $CloudSdkRoot 'bin\gcloud.cmd'
$package = 'dev.androidlab.integrityprobe'
$requestReport = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "..\reports\$Name.json") | ConvertFrom-Json
if ($requestReport.status -ne 'token_received') { throw 'The request did not produce a token.' }
if ($requestReport.package -ne $package) { throw 'Unexpected package in request report.' }
$privatePath = "files/token-$Name.txt"
if ($requestReport.token_private_path -ne $privatePath) { throw 'Unexpected app-private token path.' }

$token = ((& $adb -s $Serial exec-out run-as $package cat $privatePath 2>$null) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $token.Length -ne $requestReport.token_length) {
    throw 'The app-private token is missing or has the wrong length.'
}
$sha = [Security.Cryptography.SHA256]::Create()
try { $tokenHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($tokenHash -ne $requestReport.token_sha256) { throw 'The token hash does not match the request report.' }

$accessToken = ((& $gcloud auth print-access-token "--impersonate-service-account=$ServiceAccount" '--scopes=https://www.googleapis.com/auth/playintegrity' 2>$null) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or -not $accessToken) { throw 'Could not impersonate the service account.' }
$uri = "https://playintegrity.googleapis.com/v1/${package}:decodeIntegrityToken"
$body = @{ integrity_token = $token } | ConvertTo-Json -Compress
try {
    $decoded = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Bearer $accessToken" } -ContentType 'application/json' -Body $body
} catch {
    $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'unavailable' }
    throw "Token decode failed with HTTP status $statusCode."
}
$details = $decoded.tokenPayloadExternal.requestDetails
function ConvertFrom-Base64Url([string]$value) {
    $base64 = $value.Replace('-', '+').Replace('_', '/')
    return [Convert]::FromBase64String($base64.PadRight($base64.Length + ((4 - $base64.Length % 4) % 4), '='))
}
$expectedNonce = [BitConverter]::ToString((ConvertFrom-Base64Url $requestReport.nonce_base64url))
$actualNonce = [BitConverter]::ToString((ConvertFrom-Base64Url $details.nonce))
if ($details.requestPackageName -ne $package -or $actualNonce -ne $expectedNonce) {
    throw 'The decoded verdict does not match the request package and host nonce.'
}
$payload = $decoded.tokenPayloadExternal
$result = [ordered]@{
    schema_version = 1
    decoded_at = [DateTimeOffset]::UtcNow.ToString('o')
    source_report = "$Name.json"
    token_sha256 = $tokenHash
    request_package_name = $details.requestPackageName
    nonce_matches = $true
    request_timestamp_ms = $details.timestampMillis
    app_recognition_verdict = $payload.appIntegrity.appRecognitionVerdict
    device_recognition_verdict = @($payload.deviceIntegrity.deviceRecognitionVerdict | Where-Object { $null -ne $_ })
    app_licensing_verdict = $payload.accountDetails.appLicensingVerdict
}
$destination = Join-Path $PSScriptRoot "..\reports\$Name-verdict.json"
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output $destination
Write-Output "Device verdict: $($result.device_recognition_verdict -join ',')"

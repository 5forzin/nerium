#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$UnexpectedArguments=@())
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false,$true)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

function Require([bool]$Condition,[string]$Code) { if(!$Condition){throw $Code} }
function Check-Fields($Element,[string[]]$Fields) {
    Require ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) 'INVALID_OBJECT'
    $names = @($Element.EnumerateObject() | ForEach-Object Name)
    Require ($names.Count -eq $Fields.Count -and @($names | Select-Object -Unique).Count -eq $Fields.Count) 'INVALID_FIELDS'
    foreach($name in $names){ Require ($Fields -ccontains $name) 'INVALID_FIELDS' }
}
function String-Field($Element,[string]$Name) {
    $value=$Element.GetProperty($Name)
    Require ($value.ValueKind -eq [Text.Json.JsonValueKind]::String) 'INVALID_FIELD_TYPE'
    $value.GetString()
}
$document=$null
$stage='input'
try {
    Require $IsWindows 'WINDOWS_REQUIRED'
    Require ($UnexpectedArguments.Count -eq 0) 'STDIN_ONLY'
    $inputText=[Text.StringBuilder]::new()
    while(($next=[Console]::In.Read()) -ne -1) { Require ($inputText.Length -lt 65536) 'INPUT_TOO_LARGE'; [void]$inputText.Append([char]$next) }
    $text=$inputText.ToString()
    Require ([Text.Encoding]::UTF8.GetByteCount($text) -le 65536) 'INPUT_TOO_LARGE'
    $stage='parse'
    $options=[Text.Json.JsonDocumentOptions]::new();$options.MaxDepth=5
    $document=[Text.Json.JsonDocument]::Parse($text,$options)
    $request=$document.RootElement
    $stage='schema'
    $operation=String-Field $request 'operation'
    $fields=@('schema_version','operation','nonce_base64url','payload_utf8')
    if($operation -ceq 'verify_response'){ $fields+='response' } else { Require ($operation -ceq 'create_response') 'INVALID_OPERATION' }
    Check-Fields $request $fields
    Require ($request.GetProperty('schema_version').GetRawText() -ceq '1') 'INVALID_SCHEMA'
    $nonce=String-Field $request 'nonce_base64url';$payload=String-Field $request 'payload_utf8'
    $sourcePath=Join-Path $PSScriptRoot '..\hostkey\WindowsVbsKey.cs'
    Require (-not ('AndroidLab.HostKey.V40.WindowsVbsKey' -as [type])) 'FRESH_PROCESS_REQUIRED'
    $stage='compile'
    Add-Type -Path $sourcePath
    $stage=$operation
    if($operation -ceq 'create_response') { $output=[AndroidLab.HostKey.V40.WindowsVbsKey]::CreateResponse($nonce,$payload) }
    else {
        $response=$request.GetProperty('response')
        $responseFields=@('schema_version','nonce_base64url','payload_sha256','subject_public_blob_base64url','subject_spki_base64url','authority_public_blob_base64url','root_claim_base64url','identity_claim_base64url','signature_base64url','signature_algorithm','salt_length')
        Check-Fields $response $responseFields
        Require ($response.GetProperty('schema_version').GetRawText() -ceq '1' -and $response.GetProperty('salt_length').GetRawText() -ceq '32') 'INVALID_RESPONSE_SCHEMA'
        Require ((String-Field $response 'signature_algorithm') -ceq 'RSA-PSS-SHA256') 'INVALID_SIGNATURE_ALGORITHM'
        $values=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        foreach($name in $responseFields) { if($name -cnotin @('schema_version','salt_length')) { $values.Add($name,(String-Field $response $name)) } }
        $output=[AndroidLab.HostKey.V40.WindowsVbsKey]::VerifyResponse($nonce,$payload,$values)
    }
} catch {
    $code=if($_.Exception.Message -cmatch '^[A-Z0-9_]{1,80}$'){$_.Exception.Message}else{'INVALID_INPUT_OR_LOCAL_FAILURE'}
    $output=@{schema_version=1;status='failed';origin='windows_vbs_host_key';android_tee_verified=$false;external_root_authenticated=$false;error=@{code=$code;stage=$stage;exception_type=$_.Exception.GetType().Name;script_line=$_.InvocationInfo.ScriptLineNumber}}
} finally { if($document){$document.Dispose()} }
$json=ConvertTo-Json -InputObject $output -Depth 15 -Compress
if([Text.Encoding]::UTF8.GetByteCount($json) -gt 65536){$output=@{status='failed'};$json='{"schema_version":1,"status":"failed","origin":"windows_vbs_host_key","error":{"code":"OUTPUT_TOO_LARGE"},"external_root_authenticated":false,"android_tee_verified":false}'}
[Console]::Out.WriteLine($json)
if($output.status -cne 'completed'){exit 1}
if($operation -ceq 'verify_response' -and !$output.valid){exit 2}

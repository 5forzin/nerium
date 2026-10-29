#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('once','persistent')][string]$Mode,
    [string]$WorkerSerial='emulator-5582',
    [string]$RequesterSerial='emulator-5584',
    [string]$ConfigPath="$env:LOCALAPPDATA\android-device-lab\research-v36\cloud-config.json",
    [string]$PrivateRoot="$env:LOCALAPPDATA\android-device-lab\research-v38",
    [ValidateRange(1,3)][int]$SamplesPerOperation=2
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$sessionPath=Join-Path $PrivateRoot ('worker-'+$Mode+'.json')
$pairRoot=Join-Path $PrivateRoot ('requester-'+$Mode)
$reportPath=Join-Path $PSScriptRoot ('..\reports\relay-v38-latency-'+$Mode+'.json')
$rows=[Collections.Generic.List[object]]::new()
$startup=$null
$started=$false
$cleanup=$false
try {
    $pairWatch=[Diagnostics.Stopwatch]::StartNew()
    $null=& (Join-Path $PSScriptRoot 'relay-lab.ps1') -Action Pair -ConfigPath $ConfigPath -SessionPath $sessionPath -Serial $WorkerSerial
    if(!$?){throw 'BENCHMARK_WORKER_PAIR_FAILED'}
    $null=& (Join-Path $PSScriptRoot 'relay-requester.ps1') -Action Start -ConfigPath $ConfigPath -WorkerSessionPath $sessionPath -PairRoot $pairRoot -RequesterSerial $RequesterSerial -ExecutionMode $Mode
    if(!$?){throw 'BENCHMARK_REQUESTER_PAIR_FAILED'}
    $started=$true
    $current=Get-Content -LiteralPath (Join-Path $pairRoot 'current-pair.json') -Raw|ConvertFrom-Json -AsHashtable
    $transport=Get-Content -LiteralPath (Join-Path $current.pair_directory 'transport.json') -Raw|ConvertFrom-Json -AsHashtable
    $startup=[ordered]@{pair_total_ms=$pairWatch.ElapsedMilliseconds;execution_mode=$transport.execution_mode;
        service_pid=if($transport.ContainsKey('service_pid')){$transport.service_pid}else{$null};
        service_startup_ms=if($transport.ContainsKey('startup_ms')){$transport.startup_ms}else{$null}}
    foreach($operation in @('echo_sha256','play_integrity')) {
        for($index=1;$index -le $SamplesPerOperation;$index++) {
            $name='relay-v38-'+$Mode+'-'+$operation+'-'+$index
            $null=& (Join-Path $PSScriptRoot 'test-relay-requester-device.ps1') -Serial $RequesterSerial -Operation $operation -Name $name
            if(!$?){throw 'BENCHMARK_REQUEST_FAILED'}
            $client=Get-Content -LiteralPath (Join-Path $PSScriptRoot ('..\reports\'+$name+'.json')) -Raw|ConvertFrom-Json -AsHashtable
            if($client.verification_state -cne 'verified_remote_result'){throw 'BENCHMARK_UNVERIFIED_RESULT'}
            $id=$client.request_id
            $hostReport=Get-Content -LiteralPath (Join-Path $PSScriptRoot ('..\reports\requester_'+$id+'.json')) -Raw|ConvertFrom-Json -AsHashtable
            $state=Get-Content -LiteralPath (Join-Path $current.pair_directory ('state\'+$id+'.json')) -Raw|ConvertFrom-Json -AsHashtable
            $rows.Add([ordered]@{operation=$operation;sample=$index;request_id=$id;
                client_elapsed_ms=$client.client_elapsed_ms;broker_observed_elapsed_ms=$client.broker_observed_elapsed_ms;
                execution_elapsed_ms=$client.execution_elapsed_ms;host_timings=$hostReport.host_timings;
                cleanup_state=$hostReport.cleanup_state;service_metrics=if($state.receipt.ContainsKey('service_metrics')){$state.receipt.service_metrics}else{@{}};
                requester_integrity_verified=$false;verification_state=$client.verification_state})
        }
    }
} finally {
    try {
        if($started){
            $null=& (Join-Path $PSScriptRoot 'relay-requester.ps1') -Action Stop -PairRoot $pairRoot
            $cleanup=$?
        }elseif(Test-Path -LiteralPath $sessionPath){
            $null=& (Join-Path $PSScriptRoot 'relay-lab.ps1') -Action Revoke -ConfigPath $ConfigPath -SessionPath $sessionPath
            $cleanup=$?
        }
    }catch{$cleanup=$false}
    [ordered]@{recorded_at=[DateTimeOffset]::UtcNow.ToString('o');mode=$Mode;startup=$startup;
        samples=@($rows.ToArray());worker_session_revoked=$cleanup;physical_worker=$false;zero_detections_achieved=$false}|
        ConvertTo-Json -Depth 15|Set-Content -LiteralPath $reportPath
}
if(!$cleanup -or $rows.Count -ne $SamplesPerOperation*2){throw 'BENCHMARK_INCOMPLETE'}
[pscustomobject]@{mode=$Mode;samples=$rows.Count;worker_session_revoked=$cleanup;report_path=[IO.Path]::GetFullPath($reportPath)}

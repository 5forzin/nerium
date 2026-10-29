#requires -Version 7.2
param(
    [Parameter(Mandatory = $true)][string]$PairRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_-]{1,100}$')][string]$Name
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$summary=[ordered]@{schema_version=1;test='idle_persistent_service_exit';passed=$false;code='NOT_RUN';
    idle_only=$true;inflight_cancellation_tested=$false;service_exited=$false;completed_get_unchanged=$false;
    new_post_status=$null;state_count_before=$null;state_count_after=$null;parent_alive=$false;child_respawned=$null}

function Require([bool]$Condition,[string]$Code){if(-not $Condition){throw $Code}}
function Read-LocalJson([string]$Path){
    $file=Get-Item -LiteralPath $Path
    Require ($file.Length -gt 0 -and $file.Length -le 262144 -and -not ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'LIFECYCLE_PRIVATE_FILE'
    [IO.File]::ReadAllText($file.FullName,[Text.UTF8Encoding]::new($false,$true))|ConvertFrom-Json -Depth 30
}
function Service-CommandMatches($Process,[string]$Script,[string]$Generation){
    $command=[string]$Process.CommandLine
    $scriptPattern='(?:^|[\s"])'+[Regex]::Escape($Script)+'(?=[\s"]|$)'
    if(-not $Generation){return $command -imatch $scriptPattern}
    $generationPattern='(?:^|[\s"])'+[Regex]::Escape($Generation)+'(?=[\s"]|$)'
    $command -imatch $scriptPattern -and $command -cmatch $generationPattern
}

try{
    $PairRoot=[IO.Path]::GetFullPath($PairRoot)
    $privateBase=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'android-device-lab'))+[IO.Path]::DirectorySeparatorChar
    Require ($PairRoot.StartsWith($privateBase,[StringComparison]::OrdinalIgnoreCase)) 'LIFECYCLE_PRIVATE_ROOT'
    $record=Read-LocalJson (Join-Path $PairRoot 'current-pair.json')
    Require ($record.schema_version -eq 1 -and $record.pair_id -cmatch '^[a-f0-9]{32}$' -and $record.execution_mode -ceq 'persistent') 'LIFECYCLE_PAIR'
    $directory=[IO.Path]::GetFullPath([string]$record.pair_directory)
    Require ($directory -ceq [IO.Path]::GetFullPath((Join-Path $PairRoot $record.pair_id))) 'LIFECYCLE_PAIR_DIRECTORY'
    $transport=Read-LocalJson (Join-Path $directory 'transport.json')
    $config=Read-LocalJson (Join-Path $directory 'broker-config.json')
    Require ($transport.execution_mode -ceq 'persistent' -and $config.execution_mode -ceq 'persistent' -and
        $transport.pair_id -ceq $record.pair_id -and $config.pair_id -ceq $record.pair_id -and
        $transport.pid -eq $record.pid -and $transport.generation -cmatch '^[a-f0-9]{32}$' -and
        $transport.service_state -ceq 'ready' -and $transport.service_pid -gt 0 -and
        $config.expires_at_ms -gt [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+10000) 'LIFECYCLE_TRANSPORT'
    $parent=Get-Process -Id $record.pid -ErrorAction Stop
    $parentStarted=[DateTimeOffset]::new($parent.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()
    Require ($parent.Path -ceq $record.node_path -and [Math]::Abs($parentStarted-[long]$record.process_started_at_ms) -le 1000) 'LIFECYCLE_PARENT_OWNER'
    $stateDirectory=[IO.Path]::GetFullPath([string]$config.state_directory)
    Require ($stateDirectory -ceq [IO.Path]::GetFullPath((Join-Path $directory 'state'))) 'LIFECYCLE_STATE_DIRECTORY'
    $files=@(Get-ChildItem -LiteralPath $stateDirectory -File -Filter '*.json')
    Require ($files.Count -gt 0 -and $files.Count -le 1024) 'LIFECYCLE_STATE_COUNT'
    $summary.state_count_before=$files.Count
    $stateNamesBefore=@($files.Name|Sort-Object)
    $known=$null
    foreach($file in $files){
        $state=Read-LocalJson $file.FullName
        Require ($state.receipt.state -cnotin @('accepted','running')) 'LIFECYCLE_NOT_IDLE'
        if($null -eq $known -and $state.receipt.state -ceq 'completed'){$known=$state.receipt}
    }
    Require ($null -ne $known -and $known.request_id -cmatch '^[a-f0-9]{32}$') 'LIFECYCLE_COMPLETED_REQUIRED'
    $service=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$transport.service_pid)
    Require ($null -ne $service -and $service.ParentProcessId -eq $record.pid -and
        $service.ExecutablePath -ceq $config.pwsh_path -and
        (Service-CommandMatches $service $config.service_script_path $transport.generation)) 'LIFECYCLE_SERVICE_OWNER'
    $child=Get-Process -Id $transport.service_pid -ErrorAction Stop
    try{
        Require ([Math]::Abs(($child.StartTime.ToUniversalTime()-$service.CreationDate.ToUniversalTime()).TotalMilliseconds) -le 1000) 'LIFECYCLE_SERVICE_START'
        $rechecked=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$transport.service_pid)
        Require ($null -ne $rechecked -and $rechecked.ParentProcessId -eq $record.pid -and
            (Service-CommandMatches $rechecked $config.service_script_path $transport.generation)) 'LIFECYCLE_SERVICE_RECHECK'
        $child.Kill($false)
        Require ($child.WaitForExit(5000)) 'LIFECYCLE_EXIT_TIMEOUT'
        $summary.service_exited=$true
    }finally{$child.Dispose()}

    $nodeCode=@'
const https=require('node:https');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
(async()=>{
 try{
  const deadline=Date.now()+5000;
  function call(method,path,body){return new Promise((resolve,reject)=>{
   const encoded=body===undefined?null:Buffer.from(JSON.stringify(body));
   const headers={Authorization:`Bearer ${c.bearer}`};
   if(encoded){headers['Content-Type']='application/json';headers['Content-Length']=encoded.length}
   const request=https.request({hostname:'127.0.0.1',port:c.port,method,path,ca:c.certificate,
    rejectUnauthorized:true,headers,timeout:Math.max(1,Math.min(1500,deadline-Date.now()))},response=>{
    const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>262144)response.destroy();else chunks.push(chunk)});
    response.on('error',reject);response.on('end',()=>{try{resolve({status:response.statusCode,body:JSON.parse(Buffer.concat(chunks).toString('utf8'))})}catch{reject(new Error('INVALID_JSON'))}});
   });request.on('timeout',()=>request.destroy(new Error('TIMEOUT')));request.on('error',reject);
   if(encoded)request.write(encoded);request.end();
  })}
  let existing;
  while(Date.now()<deadline){try{existing=await call('GET','/v1/requests/'+c.receipt.request_id);break}catch{await new Promise(r=>setTimeout(r,100))}}
  assert.equal(existing?.status,200);assert.deepEqual(existing.body,c.receipt);
  const id=crypto.randomBytes(16).toString('hex');
  const post=await call('POST','/v1/requests',{schema_version:1,request_id:id,operation:'echo_sha256',
   challenge_base64url:crypto.randomBytes(32).toString('base64url'),timeout_ms:30000});
  assert.equal(post.status,503);
  process.stdout.write(JSON.stringify({completed_get_unchanged:true,new_post_status:post.status}));
 }catch{process.stdout.write(JSON.stringify({error:'LIFECYCLE_HTTPS_FAILED'}));process.exitCode=1}
})();
'@
    $payload=@{port=$transport.port;bearer=$config.bearer_token;certificate=[IO.File]::ReadAllText($config.certificate_path);receipt=$known}|ConvertTo-Json -Depth 30 -Compress
    $info=[Diagnostics.ProcessStartInfo]::new([string]$record.node_path)
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardInputEncoding=[Text.UTF8Encoding]::new($false)
    $info.ArgumentList.Add('-')
    $probe=[Diagnostics.Process]::new();$probe.StartInfo=$info
    try{
        Require ($probe.Start()) 'LIFECYCLE_PROBE_START'
        $stdout=$probe.StandardOutput.ReadToEndAsync();$stderr=$probe.StandardError.ReadToEndAsync()
        $probe.StandardInput.Write('const c = '+$payload+';'+[Environment]::NewLine+$nodeCode);$probe.StandardInput.Close()
        if(-not $probe.WaitForExit(7000)){$probe.Kill($true);throw 'LIFECYCLE_PROBE_TIMEOUT'}
        $output=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        Require ($probe.ExitCode -eq 0 -and $output.Length -le 4096) 'LIFECYCLE_PROBE_FAILED'
        $result=$output|ConvertFrom-Json
        Require ($result.completed_get_unchanged -eq $true -and $result.new_post_status -eq 503) 'LIFECYCLE_HTTPS_RESULT'
        $summary.completed_get_unchanged=$true;$summary.new_post_status=503
    }finally{$payload=$null;$config.bearer_token=$null;$probe.Dispose()}
    Start-Sleep -Milliseconds 500
    $afterFiles=@(Get-ChildItem -LiteralPath $stateDirectory -File -Filter '*.json')
    $summary.state_count_after=$afterFiles.Count
    $parent.Refresh();$summary.parent_alive=-not $parent.HasExited
    $children=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId = '+[int]$record.pid)|Where-Object{
        Service-CommandMatches $_ $config.service_script_path ''
    })
    $summary.child_respawned=$children.Count -ne 0
    Require ($summary.parent_alive -and -not $summary.child_respawned -and
        $summary.state_count_after -eq $summary.state_count_before -and
        @(Compare-Object $stateNamesBefore @($afterFiles.Name|Sort-Object)).Count -eq 0) 'LIFECYCLE_POSTCONDITIONS'
    $summary.code='IDLE_SERVICE_FAILURE_CONTAINED';$summary.passed=$true
}catch{
    $summary.code=if($_.Exception.Message -cmatch '^LIFECYCLE_[A-Z0-9_]+$'){$_.Exception.Message}else{'LIFECYCLE_FAILED'}
    $summary.passed=$false
}finally{
    $config=$null;$payload=$null
    $reports=Join-Path $PSScriptRoot '..\reports';$null=New-Item -ItemType Directory -Path $reports -Force
    $destination=[IO.Path]::GetFullPath((Join-Path $reports ($Name+'.json')))
    [IO.File]::WriteAllText($destination,($summary|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
[pscustomobject]@{passed=$summary.passed;code=$summary.code;report_path=$destination}
if(-not $summary.passed){exit 1}

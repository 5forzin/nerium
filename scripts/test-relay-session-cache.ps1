#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$path=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\relay\RelaySession.psm1'))
$module=New-Module -Name ('RelaySessionCacheTest_'+[Guid]::NewGuid().ToString('N')) -ScriptBlock ([scriptblock]::Create([IO.File]::ReadAllText($path)))
try {
    & $module {
        $originals=@{}
        foreach($name in @('Get-SessionMonotonic','Fetch-SessionSourceToken','Exchange-SessionSignerToken')){
            $originals[$name]=(Get-Command $name -CommandType Function).ScriptBlock
        }
        try{
            $script:testNow=1000L;$script:fetches=0;$script:exchanges=0;$script:sends=0
            function Get-SessionMonotonic {$script:testNow}
            function Fetch-SessionSourceToken {param($Context) $script:fetches++;@{token=('source-fixture-'+$script:fetches);deadline=$script:testNow+10000}}
            function Exchange-SessionSignerToken {param($Context,$SourceToken,$Scope) $script:exchanges++;@{token=('signer-fixture-'+$script:exchanges);deadline=$script:testNow+10000}}
            foreach($name in $originals.Keys){if((Get-Command $name).ScriptBlock -eq $originals[$name]){throw 'Cache isolation failed'}}
            $signer='decoder@fixture-project.iam.gserviceaccount.com'
            $scope='https://www.googleapis.com/auth/playintegrity'
            Initialize-RelaySessionTransport -Account 'fixture@example.com' -ConfigurationName default -ProjectId fixture-project `
                -SignerServiceAccount $signer -ExpiresAtMs ((Get-SessionEpoch)+900000)
            $first=Get-RelaySessionToken
            if((Get-RelaySessionToken) -cne $first -or $script:fetches -ne 1){throw 'Source cache hit failed'}
            $delegated=Get-RelaySessionToken -ServiceAccount $signer -Scope $scope
            if((Get-RelaySessionToken -ServiceAccount $signer -Scope $scope) -cne $delegated -or $script:exchanges -ne 1){throw 'Signer cache hit failed'}
            foreach($target in @(@{ServiceAccount=$signer;Scope='https://www.googleapis.com/auth/cloud-platform'},
                @{ServiceAccount='other@fixture-project.iam.gserviceaccount.com';Scope=$scope},@{Scope=$scope})){
                $rejected=$false;try{$null=Get-RelaySessionToken @target}catch{$rejected=$true}
                if(-not $rejected){throw 'Scope or target isolation failed'}
            }
            $script:testNow+=10001
            if((Get-RelaySessionToken) -ceq $first -or $script:fetches -ne 2){throw 'Monotonic expiry failed'}
            Invalidate-RelaySessionToken -ServiceAccount $signer -Scope $scope
            $null=Get-RelaySessionToken -ServiceAccount $signer -Scope $scope
            if($script:exchanges -ne 2){throw 'Explicit invalidation failed'}
            $realClient=$script:Context.client
            $fakeClient=[pscustomobject]@{}
            $fakeClient|Add-Member -MemberType ScriptMethod -Name SendAsync -Value {
                param($request,$completion,$cancel)
                $script:sends++
                [Threading.Tasks.Task]::FromResult([Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Unauthorized))
            }
            $script:Context.client=$fakeClient
            try{
                foreach($role in @('source','signer')){
                    $before=$script:sends;$rejected=$false
                    try{
                        if($role -ceq 'source'){$null=Invoke-SessionJson -Uri 'https://offline.invalid' -Json '{}' -AccessToken 'fixture'}
                        else{$null=Invoke-SessionJson -Uri 'https://offline.invalid' -Json '{}' -AccessToken 'fixture' -InvalidationAccount $signer -InvalidationScope $scope}
                    }catch{$rejected=$_.Exception.Message -ceq 'Relay session: HTTP_401'}
                    if(-not $rejected -or $script:sends -ne $before+1){throw '401 must invalidate without retry'}
                    $key=if($role -ceq 'source'){Get-TokenKey}else{Get-TokenKey $signer $scope}
                    if($script:Context.cache.ContainsKey($key)){throw '401 left rejected token cached'}
                }
            }finally{$script:Context.client=$realClient}
            $null=Get-RelaySessionToken
            if($script:fetches -ne 3){throw '401 did not force next-call fetch'}
            $metrics=Get-RelaySessionMetrics
            if($metrics.cache_hits -lt 2 -or $metrics.invalidations -ne 3){throw 'Cache metrics failed'}
            Close-RelaySessionTransport
            $rejected=$false;try{$null=Get-RelaySessionToken}catch{$rejected=$true}
            if(-not $rejected){throw 'Closed context still usable'}
            Initialize-RelaySessionTransport -Account 'second@example.com' -ConfigurationName isolated -ProjectId second-project `
                -SignerServiceAccount 'decoder@second-project.iam.gserviceaccount.com' -ExpiresAtMs ((Get-SessionEpoch)+900000)
            $null=Get-RelaySessionToken
            if($script:fetches -ne 4 -or (Get-RelaySessionMetrics).cache_entries -ne 1){throw 'Context token isolation failed'}
            [pscustomobject]@{passed=$true;checks=@('source_hit','signer_hit','monotonic_expiry','scope_isolation',
                'explicit_invalidation','source_401_no_retry','signer_401_no_retry','close','context_isolation')}
        }finally{
            Close-RelaySessionTransport
            foreach($name in $originals.Keys){Set-Item -Path ('Function:'+$name) -Value $originals[$name]}
        }
    }
}finally{Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue}

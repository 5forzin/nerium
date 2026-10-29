#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$BackendPath = (Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v44\build-windows-llvm18\keymint_pipe_backend.exe')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-Exact([IO.Stream]$Stream, [int]$Length) {
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($count -le 0) { throw 'The backend closed before completing its response.' }
        $offset += $count
    }
    return $bytes
}

function Invoke-PipeCase([bool]$SendRequest) {
    $name = 'adl-keymint-readiness-' + [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(8)).ToLowerInvariant()
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($name, [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
    $process = $null
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = [IO.Path]::GetFullPath($BackendPath)
        [void]$start.ArgumentList.Add($name)
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $runtime = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v41\llvm-mingw-20240619-ucrt-x86_64\bin'
        $start.Environment['PATH'] = $runtime + ';' + $env:PATH
        $process = [Diagnostics.Process]::Start($start)
        if (-not $process) { throw 'The backend process did not start.' }
        if (-not $pipe.WaitForConnectionAsync().Wait(10000)) { throw 'The backend did not connect to the test pipe.' }
        if ($SendRequest) {
            [byte[]]$request = @(19, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0)
            $pipe.Write($request, 0, $request.Length)
            $pipe.Flush()
            $header = Read-Exact $pipe 8
            $responseCommand = [BitConverter]::ToUInt32($header, 0)
            if ($responseCommand -ne [uint32]2147483667) { throw "The response command differs: $responseCommand." }
            $size = [BitConverter]::ToUInt32($header, 4)
            if ($size -lt 4 -or $size -gt 1048576) { throw 'The response size is invalid.' }
            [void](Read-Exact $pipe ([int]$size))
        }
        $pipe.Dispose()
        if (-not $process.WaitForExit(10000)) { throw 'The backend did not close after the pipe ended.' }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if ($process.ExitCode -ne 0) { throw "The backend failed: $stderr" }
        $serving = @($stdout -split '\r?\n' | Where-Object {
            $_ -ceq '{"state":"serving","completed_frames":1,"security_level":"SOFTWARE"}'
        })
        if ($SendRequest -and $serving.Count -ne 1) { throw 'A completed response did not produce exactly one readiness marker.' }
        if (-not $SendRequest -and $serving.Count -ne 0) { throw 'Readiness was reported before a response completed.' }
        return [pscustomobject]@{request_sent=$SendRequest;serving_markers=$serving.Count;exit_code=$process.ExitCode}
    } finally {
        $pipe.Dispose()
        if ($process) {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(5000)
            }
            $process.Dispose()
        }
    }
}

$results = @(Invoke-PipeCase $false; Invoke-PipeCase $true)
$results | ConvertTo-Json -Depth 3

param(
    [Parameter(Mandatory = $true)][string[]]$Command,
    [ValidateSet(5556)][int]$Port = 5556
)

$ErrorActionPreference = 'Stop'
$client = [Net.Sockets.TcpClient]::new('127.0.0.1',$Port)
try {
    $stream = $client.GetStream()
    $stream.ReadTimeout = 3000
    $reader = [IO.StreamReader]::new($stream)
    $writer = [IO.StreamWriter]::new($stream)
    $writer.NewLine = "`n"
    $writer.AutoFlush = $true
    function Read-Reply {
        $reply = @()
        while ($true) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            $reply += $line
            if ($line -eq 'OK' -or $line.StartsWith('KO:')) { break }
        }
        return $reply
    }
    Read-Reply | Out-Null
    $token = (Get-Content -LiteralPath "$env:USERPROFILE\.emulator_console_auth_token" -Raw).Trim()
    $writer.WriteLine("auth $token")
    $authenticated = @(Read-Reply)
    if ($authenticated[-1] -ne 'OK') { throw 'Emulator console authentication failed.' }
    $writer.WriteLine('avd name')
    $identity = @(Read-Reply)
    if ($identity[0].Trim() -ne 'device-lab-numa') { throw 'The console does not belong to the lab NUMA AVD.' }
    foreach ($item in $Command) {
        $writer.WriteLine($item)
        Read-Reply
    }
} finally {
    $client.Dispose()
}

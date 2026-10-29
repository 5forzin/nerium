param(
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
if (-not ('DeviceLab.WindowsTpm' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace DeviceLab {
    [StructLayout(LayoutKind.Sequential)]
    public struct TpmInfo {
        public UInt32 StructVersion, TpmVersion, InterfaceType, ImplementationRevision;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct TbsContextParams {
        public UInt32 Version, Flags;
    }
    public static class WindowsTpm {
        [DllImport("tbs.dll", ExactSpelling=true)]
        public static extern UInt32 Tbsi_GetDeviceInfo(UInt32 size, ref TpmInfo info);
        [DllImport("tbs.dll", ExactSpelling=true)]
        public static extern UInt32 Tbsi_Context_Create(ref TbsContextParams parameters, out UIntPtr context);
        [DllImport("tbs.dll", ExactSpelling=true)]
        public static extern UInt32 Tbsip_Submit_Command(UIntPtr context, UInt32 locality, UInt32 priority,
            byte[] command, UInt32 commandSize, [Out] byte[] response, ref UInt32 responseSize);
        [DllImport("tbs.dll", ExactSpelling=true)]
        public static extern UInt32 Tbsip_Context_Close(UIntPtr context);
        public static UInt32 ReadU32(byte[] data, int offset) {
            return ((UInt32)data[offset] << 24) | ((UInt32)data[offset+1] << 16) |
                   ((UInt32)data[offset+2] << 8) | data[offset+3];
        }
        public static UInt16 ReadU16(byte[] data, int offset) {
            return (UInt16)((data[offset] << 8) | data[offset+1]);
        }
    }
}
'@
}

$report = [ordered]@{
    schema_version = 1
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'Local Windows TBS device query and optional GetRandom; no keys, certificates, enrollment or persistent TPM changes'
    device_query = $null
    get_random = $null
    commands_submitted = @()
    android_keymint_verified = $false
    google_attestation_verified = $false
    zero_detections_achieved = $false
}

try {
    $info = [DeviceLab.TpmInfo]::new()
    $info.StructVersion = 2
    $code = [DeviceLab.WindowsTpm]::Tbsi_GetDeviceInfo(16, [ref]$info)
    $report.device_query = [ordered]@{
        tbs_return_code = ('0x{0:x8}' -f $code)
        succeeded = $code -eq 0
        struct_version = $(if ($code -eq 0) { $info.StructVersion } else { $null })
        tpm_version = $(if ($code -eq 0) { $info.TpmVersion } else { $null })
        interface_type = $(if ($code -eq 0) { $info.InterfaceType } else { $null })
        implementation_revision = $(if ($code -eq 0) { $info.ImplementationRevision } else { $null })
    }
    if ($code -eq 0 -and $info.TpmVersion -eq 2) {
        $parameters = [DeviceLab.TbsContextParams]::new()
        $parameters.Version = 2
        $parameters.Flags = 4
        $context = [UIntPtr]::Zero
        $opened = [DeviceLab.WindowsTpm]::Tbsi_Context_Create([ref]$parameters, [ref]$context)
        $report.get_random = [ordered]@{ context_return_code = ('0x{0:x8}' -f $opened); succeeded = $false }
        if ($opened -eq 0) {
            try {
                [byte[]]$command = 0x80,0x01,0,0,0,0x0c,0,0,0x01,0x7b,0,0x10
                [byte[]]$response = [byte[]]::new(128)
                [uint32]$responseSize = $response.Length
                $report.commands_submitted = @('TPM2_GetRandom')
                $submitted = [DeviceLab.WindowsTpm]::Tbsip_Submit_Command($context, 0, 200, $command, $command.Length, $response, [ref]$responseSize)
                $report.get_random.submit_return_code = ('0x{0:x8}' -f $submitted)
                $report.get_random.response_bytes = $responseSize
                if ($submitted -eq 0 -and $responseSize -ge 10 -and $responseSize -le $response.Length) {
                    $tag = [DeviceLab.WindowsTpm]::ReadU16($response, 0)
                    $size = [DeviceLab.WindowsTpm]::ReadU32($response, 2)
                    $tpmCode = [DeviceLab.WindowsTpm]::ReadU32($response, 6)
                    $report.get_random.tpm_return_code = ('0x{0:x8}' -f $tpmCode)
                    $report.get_random.header_valid = $tag -eq 0x8001 -and $size -eq $responseSize
                    if ($report.get_random.header_valid -and $tpmCode -eq 0 -and $size -ge 12) {
                        $count = [DeviceLab.WindowsTpm]::ReadU16($response, 10)
                        $report.get_random.requested_bytes = 16
                        $report.get_random.returned_bytes = $count
                        if ($count -gt 0 -and $count -le 16 -and $size -eq 12 + $count) {
                            [byte[]]$sample = $response[12..(11 + $count)]
                            $report.get_random.sample_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sample)).ToLowerInvariant()
                            $report.get_random.succeeded = $true
                        }
                    }
                }
            } finally {
                $report.get_random.close_return_code = ('0x{0:x8}' -f [DeviceLab.WindowsTpm]::Tbsip_Context_Close($context))
            }
        }
    }
} catch {
    $report.error_type = $_.Exception.GetType().FullName
    $report.error_message = $_.Exception.Message
}

$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
$report | ConvertTo-Json -Depth 8

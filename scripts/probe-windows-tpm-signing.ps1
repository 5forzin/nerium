param([Parameter(Mandatory = $true)][string]$OutputPath)

$ErrorActionPreference = 'Stop'
if (-not ('DeviceLab.TpmTransientSigning' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DeviceLab {
    public static class TpmTransientSigning {
        [StructLayout(LayoutKind.Sequential)]
        public struct ContextParams { public uint Version, Flags; }
        [DllImport("tbs.dll", ExactSpelling=true)]
        static extern uint Tbsi_Context_Create(ref ContextParams parameters, out UIntPtr context);
        [DllImport("tbs.dll", ExactSpelling=true)]
        static extern uint Tbsip_Submit_Command(UIntPtr context, uint locality, uint priority,
            byte[] command, uint commandSize, [Out] byte[] response, ref uint responseSize);
        [DllImport("tbs.dll", ExactSpelling=true)]
        static extern uint Tbsip_Context_Close(UIntPtr context);

        static byte[] U16(ushort v) { return new byte[] { (byte)(v >> 8), (byte)v }; }
        static byte[] U32(uint v) {
            return new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };
        }
        static byte[] Join(params byte[][] parts) {
            using (var stream = new MemoryStream()) {
                foreach (var part in parts) stream.Write(part, 0, part.Length);
                return stream.ToArray();
            }
        }
        static byte[] Sized(byte[] value) {
            if (value.Length > ushort.MaxValue) throw new InvalidDataException("Oversized TPM2B");
            return Join(U16((ushort)value.Length), value);
        }
        static uint Read32(byte[] data, ref int offset, int end) {
            if (offset < 0 || offset + 4 > end) throw new InvalidDataException("Truncated uint32");
            uint value = ((uint)data[offset] << 24) | ((uint)data[offset+1] << 16) |
                ((uint)data[offset+2] << 8) | data[offset+3];
            offset += 4;
            return value;
        }
        static ushort Read16(byte[] data, ref int offset, int end) {
            if (offset < 0 || offset + 2 > end) throw new InvalidDataException("Truncated uint16");
            ushort value = (ushort)((data[offset] << 8) | data[offset+1]);
            offset += 2;
            return value;
        }
        static byte[] ReadSized(byte[] data, ref int offset, int end) {
            int count = Read16(data, ref offset, end);
            if (offset + count > end) throw new InvalidDataException("Truncated TPM2B");
            var value = new byte[count];
            Buffer.BlockCopy(data, offset, value, 0, count);
            offset += count;
            return value;
        }
        static byte[] Pad32(byte[] value) {
            if (value.Length == 0 || value.Length > 32) throw new InvalidDataException("Invalid P256 integer");
            var padded = new byte[32];
            Buffer.BlockCopy(value, 0, padded, 32-value.Length, value.Length);
            return padded;
        }
        static string Hex(byte[] value) { return BitConverter.ToString(value).Replace("-", "").ToLowerInvariant(); }
        static byte[] Submit(UIntPtr context, ushort tag, uint code, byte[] body,
            string name, List<Dictionary<string, object>> transcript) {
            var command = Join(U16(tag), U32((uint)(10 + body.Length)), U32(code), body);
            var response = new byte[4096];
            uint responseSize = (uint)response.Length;
            uint tbsCode = Tbsip_Submit_Command(context, 0, 200, command, (uint)command.Length,
                response, ref responseSize);
            var entry = new Dictionary<string, object>();
            transcript.Add(entry);
            entry["command"] = name;
            entry["tbs_return_code"] = "0x" + tbsCode.ToString("x8");
            if (tbsCode != 0) throw new InvalidOperationException(name + " TBS failure " + entry["tbs_return_code"]);
            int offset = 0;
            ushort responseTag = Read16(response, ref offset, (int)responseSize);
            uint declaredSize = Read32(response, ref offset, (int)responseSize);
            uint tpmCode = Read32(response, ref offset, (int)responseSize);
            entry["tpm_return_code"] = "0x" + tpmCode.ToString("x8");
            entry["response_bytes"] = responseSize;
            if (declaredSize != responseSize) throw new InvalidDataException("TPM response length mismatch");
            if (tpmCode != 0) throw new InvalidOperationException(name + " TPM failure " + entry["tpm_return_code"]);
            if (responseTag != tag) throw new InvalidDataException("TPM response tag mismatch");
            Array.Resize(ref response, (int)responseSize);
            return response;
        }
        public static Dictionary<string, object> Run() {
            var report = new Dictionary<string, object>();
            var transcript = new List<Dictionary<string, object>>();
            report["schema_version"] = 1;
            report["captured_at"] = DateTime.UtcNow.ToString("o");
            report["scope"] = "TBS transient NULL-hierarchy ECC key, TPM2_Sign, host verification and FlushContext";
            report["persistent_operations_requested"] = false;
            report["android_keymint_verified"] = false;
            report["google_attestation_verified"] = false;
            report["zero_detections_achieved"] = false;
            report["commands"] = transcript;
            report["signature_verified"] = false;
            report["altered_digest_rejected"] = false;
            report["verification_backend"] = "Windows CNG ECDSA VerifyHash";
            report["key_flushed"] = false;
            UIntPtr context = UIntPtr.Zero;
            uint handle = 0;
            try {
                var parameters = new ContextParams { Version = 2, Flags = 4 };
                uint result = Tbsi_Context_Create(ref parameters, out context);
                report["context_return_code"] = "0x" + result.ToString("x8");
                if (result != 0) throw new InvalidOperationException("TBS context creation failed");
                // Empty password authorization applies only to this new NULL-hierarchy object.
                byte[] auth = Join(U32(9), U32(0x40000009), U16(0), new byte[] { 0 }, U16(0));
                byte[] publicTemplate = Join(U16(0x23), U16(0x0b), U32(0x00040472), U16(0),
                    U16(0x10), U16(0x18), U16(0x0b), U16(3), U16(0x10), U16(0), U16(0));
                byte[] createBody = Join(U32(0x40000007), auth, Sized(Join(U16(0), U16(0))),
                    Sized(publicTemplate), U16(0), U32(0));
                byte[] created = Submit(context, 0x8002, 0x131, createBody, "TPM2_CreatePrimary", transcript);
                int offset = 10;
                handle = Read32(created, ref offset, created.Length);
                if ((handle >> 24) != 0x80) throw new InvalidDataException("Expected transient object handle");
                int parameterSize = checked((int)Read32(created, ref offset, created.Length));
                int parameterEnd = checked(offset + parameterSize);
                if (parameterEnd > created.Length) throw new InvalidDataException("Invalid creation parameter area");
                byte[] publicArea = ReadSized(created, ref offset, parameterEnd);
                int pubOffset = 0;
                if (Read16(publicArea, ref pubOffset, publicArea.Length) != 0x23 ||
                    Read16(publicArea, ref pubOffset, publicArea.Length) != 0x0b ||
                    Read32(publicArea, ref pubOffset, publicArea.Length) != 0x00040472 ||
                    ReadSized(publicArea, ref pubOffset, publicArea.Length).Length != 0 ||
                    Read16(publicArea, ref pubOffset, publicArea.Length) != 0x10 ||
                    Read16(publicArea, ref pubOffset, publicArea.Length) != 0x18 ||
                    Read16(publicArea, ref pubOffset, publicArea.Length) != 0x0b ||
                    Read16(publicArea, ref pubOffset, publicArea.Length) != 3 ||
                    Read16(publicArea, ref pubOffset, publicArea.Length) != 0x10)
                    throw new InvalidDataException("Returned public template differs");
                byte[] x = Pad32(ReadSized(publicArea, ref pubOffset, publicArea.Length));
                byte[] y = Pad32(ReadSized(publicArea, ref pubOffset, publicArea.Length));
                if (pubOffset != publicArea.Length) throw new InvalidDataException("Unexpected public fields");
                report["public_key"] = new Dictionary<string, object> {
                    { "curve", "NIST_P256" }, { "x", Hex(x) }, { "y", Hex(y) },
                    { "attributes", "0x00040472" }, { "hierarchy", "TPM_RH_NULL" }
                };
                byte[] challenge = new byte[32];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(challenge);
                byte[] digest;
                using (var sha = SHA256.Create()) digest = sha.ComputeHash(challenge);
                report["challenge_sha256"] = Hex(digest);
                byte[] signBody = Join(U32(handle), auth, Sized(digest), U16(0x18), U16(0x0b),
                    U16(0x8024), U32(0x40000007), U16(0));
                byte[] signed = Submit(context, 0x8002, 0x15d, signBody, "TPM2_Sign", transcript);
                offset = 10;
                parameterSize = checked((int)Read32(signed, ref offset, signed.Length));
                parameterEnd = checked(offset + parameterSize);
                if (parameterEnd > signed.Length ||
                    Read16(signed, ref offset, parameterEnd) != 0x18 ||
                    Read16(signed, ref offset, parameterEnd) != 0x0b)
                    throw new InvalidDataException("Invalid signature parameters");
                byte[] signature = Join(Pad32(ReadSized(signed, ref offset, parameterEnd)),
                    Pad32(ReadSized(signed, ref offset, parameterEnd)));
                if (offset != parameterEnd) throw new InvalidDataException("Unexpected signature fields");
                report["signature_p1363_hex"] = Hex(signature);
                using (var verifier = new ECDsaCng()) {
                    verifier.ImportParameters(new ECParameters {
                        Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y }
                    });
                    report["signature_verified"] = verifier.VerifyHash(digest, signature);
                    digest[0] ^= 1;
                    report["altered_digest_rejected"] = !verifier.VerifyHash(digest, signature);
                }
            } catch (Exception error) {
                report["error"] = error.GetType().Name + ": " + error.Message;
            } finally {
                if (handle != 0 && context != UIntPtr.Zero) {
                    try {
                        Submit(context, 0x8001, 0x165, U32(handle), "TPM2_FlushContext", transcript);
                        report["key_flushed"] = true;
                    } catch (Exception error) { report["flush_error"] = error.Message; }
                }
                if (context != UIntPtr.Zero)
                    report["close_return_code"] = "0x" + Tbsip_Context_Close(context).ToString("x8");
            }
            report["succeeded"] = (bool)report["signature_verified"] &&
                (bool)report["altered_digest_rejected"] && (bool)report["key_flushed"] &&
                report.ContainsKey("close_return_code") && (string)report["close_return_code"] == "0x00000000";
            return report;
        }
    }
}
'@
}

$result = [DeviceLab.TpmTransientSigning]::Run()
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 8
if (-not $result.succeeded) { exit 1 }

#Requires -Version 7.2
[CmdletBinding()]
param([string]$ReportPath = (Join-Path $PSScriptRoot '..\reports\boottee-v39-vbs-claim.json'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Constants and layouts: microsoft/win32metadata, revision below, um/ncrypt.h.
# This experiment never uses named keys, provider fallback, enrollment or private-key export.
$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AndroidLab.VbsClaimV39 {
public static class Probe {
    const int Limit = 1048576;
    const uint RequireVbs = 0x00020000, AllowAttestation = 0x10;
    const uint RootClaim = 5, IdentityClaim = 6;
    [StructLayout(LayoutKind.Sequential)] struct Buffer { public uint cbBuffer, BufferType; public IntPtr pvBuffer; }
    [StructLayout(LayoutKind.Sequential)] struct Desc { public uint ulVersion, cBuffers; public IntPtr pBuffers; }
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr provider, string name, uint flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptCreatePersistedKey(IntPtr provider, out IntPtr key, string algorithm, string name, uint legacy, uint flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptSetProperty(IntPtr key, string name, byte[] value, int length, uint flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptGetProperty(IntPtr key, string name, byte[] value, int length, out int result, uint flags);
    [DllImport("ncrypt.dll")] static extern int NCryptFinalizeKey(IntPtr key, uint flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptExportKey(IntPtr key, IntPtr exportKey, string type, IntPtr parameters, byte[] output, int length, out int result, uint flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptImportKey(IntPtr provider, IntPtr importKey, string type, IntPtr parameters, out IntPtr key, byte[] input, int length, uint flags);
    [DllImport("ncrypt.dll")] static extern int NCryptCreateClaim(IntPtr subject, IntPtr authority, uint type, IntPtr parameters, byte[] output, int length, out int result, uint flags);
    [DllImport("ncrypt.dll")] static extern int NCryptVerifyClaim(IntPtr subject, IntPtr authority, uint type, IntPtr parameters, byte[] claim, int length, out Desc output, uint flags);
    [DllImport("ncrypt.dll")] static extern int NCryptFreeObject(IntPtr handle);
    [DllImport("ncrypt.dll")] static extern int NCryptFreeBuffer(IntPtr buffer);
    sealed class Stop : Exception { }
    sealed class Parameters : IDisposable {
        readonly List<IntPtr> allocated = new List<IntPtr>();
        public IntPtr Pointer;
        public Parameters(uint[] types, byte[][] values) {
            try {
                int size = Marshal.SizeOf<Buffer>();
                IntPtr buffers = Allocate(checked(types.Length * size));
                for (int i=0; i<types.Length; i++) {
                    IntPtr data = Allocate(values[i].Length); Marshal.Copy(values[i],0,data,values[i].Length);
                    Marshal.StructureToPtr(new Buffer { cbBuffer=(uint)values[i].Length, BufferType=types[i], pvBuffer=data },IntPtr.Add(buffers,i*size),false);
                }
                Pointer=Allocate(Marshal.SizeOf<Desc>());
                Marshal.StructureToPtr(new Desc { ulVersion=0,cBuffers=(uint)types.Length,pBuffers=buffers },Pointer,false);
            } catch { Dispose(); throw; }
        }
        IntPtr Allocate(int size) { if(size<1 || size>Limit) throw new InvalidOperationException(); IntPtr p=Marshal.AllocHGlobal(size); allocated.Add(p); return p; }
        public void Dispose() { for(int i=allocated.Count-1;i>=0;i--) Marshal.FreeHGlobal(allocated[i]); allocated.Clear(); Pointer=IntPtr.Zero; }
    }
    static string Hex(int status) { return "0x"+unchecked((uint)status).ToString("X8"); }
    static string Hash(byte[] bytes) { using(var sha=SHA256.Create()) return Convert.ToHexString(sha.ComputeHash(bytes)).ToLowerInvariant(); }
    static void Check(int status,string stage,List<object> operations,Dictionary<string,object> report) {
        operations.Add(new Dictionary<string,object>{{"stage",stage},{"status",Hex(status)},{"succeeded",status==0}});
        if(status!=0) { report["unsupported_stage"]=stage; report["status"]=Hex(status); throw new Stop(); }
    }
    static IntPtr Key(IntPtr provider,bool attestation,string label,List<IntPtr> keys,List<object> operations,Dictionary<string,object> report) {
        IntPtr key;
        int status=NCryptCreatePersistedKey(provider,out key,"RSA",null,0,RequireVbs);
        if(key!=IntPtr.Zero) keys.Add(key);
        Check(status,label+"_create_require_vbs",operations,report);
        Check(NCryptSetProperty(key,"Length",BitConverter.GetBytes(2048),4,0),label+"_length",operations,report);
        if(attestation) Check(NCryptSetProperty(key,"Key Usage",BitConverter.GetBytes(AllowAttestation),4,0),label+"_attestation_usage",operations,report);
        Check(NCryptFinalizeKey(key,0),label+"_finalize",operations,report);
        return key;
    }
    static byte[] Public(IntPtr key,string label,List<object> operations,Dictionary<string,object> report) {
        int length; Check(NCryptExportKey(key,IntPtr.Zero,"RSAPUBLICBLOB",IntPtr.Zero,null,0,out length,0),label+"_public_size",operations,report);
        if(length<1 || length>Limit) throw new InvalidOperationException();
        byte[] bytes=new byte[length]; Check(NCryptExportKey(key,IntPtr.Zero,"RSAPUBLICBLOB",IntPtr.Zero,bytes,bytes.Length,out length,0),label+"_public_export",operations,report);
        if(length<1 || length>bytes.Length) throw new InvalidOperationException(); Array.Resize(ref bytes,length);
        report[label+"_public"]=new Dictionary<string,object>{{"length",length},{"sha256",Hash(bytes)}}; return bytes;
    }
    static IntPtr Import(IntPtr provider,byte[] bytes,string label,List<IntPtr> keys,List<object> operations,Dictionary<string,object> report) {
        IntPtr key; int status=NCryptImportKey(provider,IntPtr.Zero,"RSAPUBLICBLOB",IntPtr.Zero,out key,bytes,bytes.Length,0);
        if(key!=IntPtr.Zero) keys.Add(key); Check(status,label+"_public_import",operations,report); return key;
    }
    static Dictionary<string,object> Property(IntPtr key,string name) {
        byte[] bytes=new byte[4]; int length; int status=NCryptGetProperty(key,name,bytes,4,out length,0);
        return new Dictionary<string,object>{{"status",Hex(status)},{"supported",status==0 && length==4},{"value",status==0 && length==4 ? (object)BitConverter.ToUInt32(bytes,0) : null}};
    }
    static byte[] Claim(IntPtr subject,IntPtr authority,uint type,Parameters parameters,string label,List<object> operations,Dictionary<string,object> report) {
        int length; Check(NCryptCreateClaim(subject,authority,type,parameters.Pointer,null,0,out length,0),label+"_claim_size",operations,report);
        if(length<1 || length>Limit) throw new InvalidOperationException(); byte[] bytes=new byte[length];
        Check(NCryptCreateClaim(subject,authority,type,parameters.Pointer,bytes,bytes.Length,out length,0),label+"_claim_create",operations,report);
        if(length<1 || length>bytes.Length) throw new InvalidOperationException(); Array.Resize(ref bytes,length); return bytes;
    }
    static int Verify(IntPtr subject,IntPtr authority,uint type,byte[] claim) {
        Desc output=new Desc();
        try { return NCryptVerifyClaim(subject,authority,type,IntPtr.Zero,claim,claim.Length,out output,0); }
        finally {
            if(output.pBuffers!=IntPtr.Zero) {
                // CNG owns this output allocation. No returned identity details are published.
                if(output.cBuffers<=32) for(int i=0;i<output.cBuffers;i++) {
                    Buffer item=Marshal.PtrToStructure<Buffer>(IntPtr.Add(output.pBuffers,i*Marshal.SizeOf<Buffer>()));
                    if(item.pvBuffer!=IntPtr.Zero) NCryptFreeBuffer(item.pvBuffer);
                }
                NCryptFreeBuffer(output.pBuffers);
            }
        }
    }
    static int NonceOffset(byte[] claim,uint type,int nonceLength) {
        // Only parse layouts explicitly defined in the pinned SDK. Unknown formats remain unsupported.
        int offset=0;
        if(claim.Length>=12 && BitConverter.ToUInt32(claim,0)==0x53414B56) {
            uint version=BitConverter.ToUInt32(claim,4);
            if((version!=1 && version!=2) || BitConverter.ToUInt32(claim,8)!=type) return -1;
            offset=12;
        }
        int size=type==RootClaim ? 24 : 32;
        uint magic=type==RootClaim ? 0x48435256u : 0x48434956u;
        if(claim.Length<offset+size || BitConverter.ToUInt32(claim,offset)!=magic || BitConverter.ToUInt32(claim,offset+4)!=0) return -1;
        uint attributes=BitConverter.ToUInt32(claim,offset+8), length=BitConverter.ToUInt32(claim,offset+12);
        long start=(long)offset+size+attributes;
        if(start>claim.Length || length!=nonceLength || start+length>claim.Length) return -1;
        return (int)start;
    }
    static object NonceMatches(byte[] claim,uint type,byte[] nonce) {
        int start=NonceOffset(claim,type,nonce.Length);
        if(start<0) return null;
        for(int i=0;i<nonce.Length;i++) if(claim[start+i]!=nonce[i]) return false;
        return true;
    }
    static bool TestClaim(IntPtr subject,IntPtr authority,IntPtr wrong,uint type,byte[] bytes,byte[] nonce,string label,Dictionary<string,object> report) {
        int valid=Verify(subject,authority,type,bytes);
        byte[] altered=(byte[])bytes.Clone(); altered[altered.Length-1]^=1;
        int tampered=Verify(subject,authority,type,altered), wrongKey=Verify(wrong,authority,type,bytes);
        int? wrongAuthority=type==IdentityClaim ? Verify(subject,wrong,type,bytes) : (int?)null;
        byte[] wrongNonce=(byte[])nonce.Clone(); wrongNonce[0]^=1;
        object nonceValid=NonceMatches(bytes,type,nonce), nonceRejected=NonceMatches(bytes,type,wrongNonce);
        int nonceOffset=NonceOffset(bytes,type,nonce.Length);
        int? nonceTampered=null;
        if(nonceOffset>=0) {
            byte[] changedNonce=(byte[])bytes.Clone(); changedNonce[nonceOffset]^=1;
            nonceTampered=Verify(subject,authority,type,changedNonce);
        }
        bool nonceBindingVerified=valid==0 && nonceValid is bool && (bool)nonceValid && nonceTampered.HasValue && nonceTampered.Value!=0;
        report[label]=new Dictionary<string,object>{{"length",bytes.Length},{"sha256",Hash(bytes)},{"verify_status",Hex(valid)},
            {"tampered_status",Hex(tampered)},{"wrong_subject_public_key_status",Hex(wrongKey)},
            {"wrong_authority_public_key_status",wrongAuthority.HasValue ? Hex(wrongAuthority.Value) : null},
            {"nonce_layout_supported",nonceValid!=null},{"nonce_matches",nonceValid},{"wrong_nonce_rejected",nonceRejected==null ? null : (object)!(bool)nonceRejected},
            {"nonce_blob_tampered_status",nonceTampered.HasValue ? Hex(nonceTampered.Value) : null},
            {"nonce_blob_tampered_rejected",nonceTampered.HasValue ? (object)(nonceTampered.Value!=0) : null},
            {"nonce_binding_verified",nonceBindingVerified},
            {"nonce_check","Explicit expected-challenge comparison after native signature verification; not an undocumented VerifyClaim parameter."}};
        return valid==0 && tampered!=0 && wrongKey!=0 && (!wrongAuthority.HasValue || wrongAuthority.Value!=0) && nonceBindingVerified && nonceRejected is bool && !(bool)nonceRejected;
    }
    public static Dictionary<string,object> Run() {
        var report=new Dictionary<string,object>{{"outcome","unsupported"},{"unsupported_stage",null},{"status",null},
            {"keys_ephemeral",true},{"provider_fallback",false},{"private_key_exported",false},{"raw_claims_retained",false},
            {"external_attestation_root_authenticated",false},
            {"android_tee_verified",false},{"google_attestation_verified",false},{"zero_detections_achieved",false}};
        var operations=new List<object>(); var cleanup=new List<object>(); var keys=new List<IntPtr>(); IntPtr provider=IntPtr.Zero;
        report["operations"]=operations; report["cleanup"]=cleanup;
        try {
            Check(NCryptOpenStorageProvider(out provider,"Microsoft Software Key Storage Provider",0),"provider_open",operations,report);
            IntPtr subject=Key(provider,false,"subject",keys,operations,report);
            report["subject_virtual_isolation"]=Property(subject,"Virtual Iso"); report["subject_implementation_type"]=Property(subject,"Impl Type");
            byte[] subjectBytes=Public(subject,"subject",operations,report);
            IntPtr authority=Key(provider,true,"authority",keys,operations,report);
            report["authority_virtual_isolation"]=Property(authority,"Virtual Iso");
            byte[] authorityBytes=Public(authority,"authority",operations,report);
            IntPtr wrong=Key(provider,false,"wrong_subject",keys,operations,report);
            byte[] wrongBytes=Public(wrong,"wrong_subject",operations,report);
            IntPtr subjectPublic=Import(provider,subjectBytes,"subject",keys,operations,report);
            IntPtr authorityPublic=Import(provider,authorityBytes,"authority",keys,operations,report);
            IntPtr wrongPublic=Import(provider,wrongBytes,"wrong_subject",keys,operations,report);
            byte[] nonce=new byte[32]; RandomNumberGenerator.Fill(nonce); report["nonce_sha256"]=Hash(nonce);
            bool rootPassed,identityPassed;
            using(var parameters=new Parameters(new uint[]{49},new byte[][]{nonce})) {
                byte[] root=Claim(authority,IntPtr.Zero,RootClaim,parameters,"root",operations,report);
                rootPassed=TestClaim(authorityPublic,IntPtr.Zero,wrongPublic,RootClaim,root,nonce,"root",report);
            }
            using(var parameters=new Parameters(new uint[]{90,91,92,93,49},new byte[][]{Encoding.Unicode.GetBytes("SHA256\0"),BitConverter.GetBytes(8u),Encoding.Unicode.GetBytes("SHA256\0"),BitConverter.GetBytes(32u),nonce})) {
                byte[] identity=Claim(subject,authority,IdentityClaim,parameters,"identity",operations,report);
                identityPassed=TestClaim(subjectPublic,authorityPublic,wrongPublic,IdentityClaim,identity,nonce,"identity",report);
            }
            report["outcome"]=rootPassed && identityPassed ? "verified_windows_claim_controls" : "failed_verification_control";
        } catch(Stop) { }
        catch(Exception error) { report["outcome"]="local_or_api_failure"; report["exception_type"]=error.GetType().Name; }
        finally {
            bool cleanupSucceeded=true;
            for(int i=keys.Count-1;i>=0;i--) {
                int status=NCryptFreeObject(keys[i]); cleanupSucceeded &= status==0;
                cleanup.Add(new Dictionary<string,object>{{"kind","own_key_handle"},{"status",Hex(status)}});
            }
            if(provider!=IntPtr.Zero) {
                int status=NCryptFreeObject(provider); cleanupSucceeded &= status==0;
                cleanup.Add(new Dictionary<string,object>{{"kind","provider_handle"},{"status",Hex(status)}});
            }
            report["cleanup_succeeded"]=cleanupSucceeded;
            if(!cleanupSucceeded && (string)report["outcome"]=="verified_windows_claim_controls") report["outcome"]="failed_cleanup";
        }
        return report;
    }
}
}
'@

$report = [ordered]@{
    schema_version = 1
    recorded_at = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'Windows VBS key protection and native claim controls; not Android KeyMint, Duck clearance, or Google certification.'
    sdk_header_revision = '2f767671802301cf043c717d66bf004ed7863487'
    test_source_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    sources = @(
        'https://github.com/microsoft/win32metadata/blob/2f767671802301cf043c717d66bf004ed7863487/generation/WinSDK/RecompiledIdlHeaders/um/ncrypt.h',
        'https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey',
        'https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreateclaim',
        'https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptverifyclaim'
    )
    configuration_changes = $false
    native_result = $null
}
try {
    if (!$IsWindows) { throw 'WINDOWS_REQUIRED' }
    if (-not ('AndroidLab.VbsClaimV39.Probe' -as [type])) { Add-Type -TypeDefinition $source -Language CSharp }
    $report.native_result = [AndroidLab.VbsClaimV39.Probe]::Run()
} catch {
    $report.native_result = @{outcome='local_or_build_failure';exception_type=$_.Exception.GetType().Name;android_tee_verified=$false;google_attestation_verified=$false;zero_detections_achieved=$false}
}
$resolvedReport = [IO.Path]::GetFullPath($ReportPath)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($resolvedReport)) | Out-Null
[IO.File]::WriteAllText($resolvedReport,($report | ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
[pscustomobject]@{report_path=$resolvedReport;outcome=$report.native_result.outcome}
if ($report.native_result.outcome -ne 'verified_windows_claim_controls') { exit 1 }

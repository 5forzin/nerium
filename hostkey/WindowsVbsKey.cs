using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AndroidLab.HostKey.V40 {
public static class WindowsVbsKey {
    // ABI/constants: microsoft/win32metadata 2f767671802301cf043c717d66bf004ed7863487, um/ncrypt.h.
    // A valid claim here does not authenticate an external attestation root or Android TEE.
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
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Pss { [MarshalAs(UnmanagedType.LPWStr)] public string algorithm; public int saltLength; }
    [DllImport("ncrypt.dll")] static extern int NCryptSignHash(IntPtr key,ref Pss padding,byte[] hash,int hashLength,byte[] signature,int signatureLength,out int result,uint flags);
    [DllImport("ncrypt.dll")] static extern int NCryptVerifySignature(IntPtr key,ref Pss padding,byte[] hash,int hashLength,byte[] signature,int signatureLength,uint flags);
    static string B64(byte[] bytes) { return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_'); }
    static byte[] Decode(string value,int maximum) {
        if(String.IsNullOrEmpty(value) || value.Length>maximum*2 || !System.Text.RegularExpressions.Regex.IsMatch(value,"^[A-Za-z0-9_-]+$")) throw new ArgumentException("INVALID_BASE64URL");
        byte[] bytes=Convert.FromBase64String(value.Replace('-','+').Replace('_','/')+new String('=',(4-value.Length%4)%4));
        if(bytes.Length>maximum || B64(bytes)!=value) throw new ArgumentException("INVALID_BASE64URL"); return bytes;
    }
    static byte[] Payload(string value) {
        if(value==null) throw new ArgumentException("INVALID_PAYLOAD");
        byte[] bytes=new UTF8Encoding(false,true).GetBytes(value);
        if(bytes.Length<1 || bytes.Length>4096) throw new ArgumentException("INVALID_PAYLOAD"); return bytes;
    }
    static byte[] Nonce(string value) { byte[] bytes=Decode(value,32); if(bytes.Length!=32) throw new ArgumentException("INVALID_NONCE"); return bytes; }
    static byte[] Digest(byte[] value) { using(var sha=SHA256.Create()) return sha.ComputeHash(value); }
    static byte[] Spki(byte[] blob) {
        if(blob.Length<24 || BitConverter.ToUInt32(blob,0)!=0x31415352 || BitConverter.ToUInt32(blob,4)!=2048 || BitConverter.ToUInt32(blob,16)!=0 || BitConverter.ToUInt32(blob,20)!=0) throw new ArgumentException("INVALID_RSA_PUBLIC_BLOB");
        uint exponent=BitConverter.ToUInt32(blob,8), modulus=BitConverter.ToUInt32(blob,12);
        if(exponent<1 || exponent>8 || modulus!=256 || 24L+exponent+modulus!=blob.Length) throw new ArgumentException("INVALID_RSA_PUBLIC_BLOB");
        byte[] e=new byte[exponent],n=new byte[modulus]; Array.Copy(blob,24,e,0,e.Length); Array.Copy(blob,24+e.Length,n,0,n.Length);
        using(var rsa=RSA.Create()) { rsa.ImportParameters(new RSAParameters{Exponent=e,Modulus=n}); return rsa.ExportSubjectPublicKeyInfo(); }
    }
    static bool CloseAll(List<IntPtr> keys,IntPtr provider,List<object> cleanup) {
        bool succeeded=true;
        for(int i=keys.Count-1;i>=0;i--) { int status=NCryptFreeObject(keys[i]); succeeded &= status==0; cleanup.Add(Hex(status)); }
        if(provider!=IntPtr.Zero) { int status=NCryptFreeObject(provider); succeeded &= status==0; cleanup.Add(Hex(status)); }
        return succeeded;
    }
    static Dictionary<string,object> Envelope() { return new Dictionary<string,object>{{"schema_version",1},{"status","failed"},{"origin","windows_vbs_host_key"},{"android_tee_verified",false},{"external_root_authenticated",false}}; }
    static Dictionary<string,object> Error(Exception error,Dictionary<string,object> internals) {
        string code=error is Stop ? "NATIVE_OPERATION_FAILED" : error is ArgumentException ? "INVALID_INPUT" : "LOCAL_OPERATION_FAILED";
        var result=new Dictionary<string,object>{{"code",code}};
        if(internals.ContainsKey("unsupported_stage")) result["stage"]=internals["unsupported_stage"];
        if(internals.ContainsKey("status")) result["native_status"]=internals["status"];
        return result;
    }
    public static Dictionary<string,object> CreateResponse(string nonceBase64Url,string payloadUtf8) {
        var result=Envelope(); var internals=new Dictionary<string,object>(); var operations=new List<object>(); var cleanup=new List<object>(); var keys=new List<IntPtr>(); IntPtr provider=IntPtr.Zero;
        try {
            byte[] nonce=Nonce(nonceBase64Url), payload=Payload(payloadUtf8);
            Check(NCryptOpenStorageProvider(out provider,"Microsoft Software Key Storage Provider",0),"provider_open",operations,internals);
            IntPtr subject=Key(provider,false,"subject",keys,operations,internals);
            IntPtr authority=Key(provider,true,"authority",keys,operations,internals);
            var subjectIsolation=Property(subject,"Virtual Iso"); var authorityIsolation=Property(authority,"Virtual Iso");
            if(!(bool)subjectIsolation["supported"] || !(bool)authorityIsolation["supported"] || (uint)subjectIsolation["value"]!=1 || (uint)authorityIsolation["value"]!=1) throw new ArgumentException("VBS_ISOLATION_NOT_CONFIRMED");
            byte[] subjectPublic=Public(subject,"subject",operations,internals), authorityPublic=Public(authority,"authority",operations,internals);
            byte[] root,identity;
            using(var parameters=new Parameters(new uint[]{49},new byte[][]{nonce})) root=Claim(authority,IntPtr.Zero,RootClaim,parameters,"root",operations,internals);
            using(var parameters=new Parameters(new uint[]{90,91,92,93,49},new byte[][]{Encoding.Unicode.GetBytes("SHA256\0"),BitConverter.GetBytes(8u),Encoding.Unicode.GetBytes("SHA256\0"),BitConverter.GetBytes(32u),nonce})) identity=Claim(subject,authority,IdentityClaim,parameters,"identity",operations,internals);
            byte[] hash=Digest(payload); var padding=new Pss{algorithm="SHA256",saltLength=32}; int length;
            Check(NCryptSignHash(subject,ref padding,hash,hash.Length,null,0,out length,8),"payload_signature_size",operations,internals);
            if(length<1 || length>Limit) throw new InvalidOperationException(); byte[] signature=new byte[length];
            Check(NCryptSignHash(subject,ref padding,hash,hash.Length,signature,signature.Length,out length,8),"payload_sign",operations,internals);
            if(length!=256) throw new InvalidOperationException(); Array.Resize(ref signature,length);
            result["response"]=new Dictionary<string,object>{{"schema_version",1},{"nonce_base64url",nonceBase64Url},{"payload_sha256",Hash(payload)},
                {"subject_public_blob_base64url",B64(subjectPublic)},{"subject_spki_base64url",B64(Spki(subjectPublic))},{"authority_public_blob_base64url",B64(authorityPublic)},
                {"root_claim_base64url",B64(root)},{"identity_claim_base64url",B64(identity)},{"signature_base64url",B64(signature)},{"signature_algorithm","RSA-PSS-SHA256"},{"salt_length",32}};
            result["status"]="completed";
        } catch(Exception error) { result["error"]=Error(error,internals); }
        finally {
            bool clean=CloseAll(keys,provider,cleanup); result["cleanup_succeeded"]=clean; result["cleanup_statuses"]=cleanup;
            if(!clean) { result["status"]="failed"; result.Remove("response"); result["error"]=new Dictionary<string,object>{{"code","HANDLE_CLEANUP_FAILED"}}; }
        }
        return result;
    }
    public static Dictionary<string,object> VerifyResponse(string nonceBase64Url,string payloadUtf8,Dictionary<string,string> response) {
        var result=Envelope(); var internals=new Dictionary<string,object>(); var operations=new List<object>(); var cleanup=new List<object>(); var keys=new List<IntPtr>(); IntPtr provider=IntPtr.Zero;
        try {
            byte[] nonce=Nonce(nonceBase64Url),payload=Payload(payloadUtf8);
            if(response["signature_algorithm"]!="RSA-PSS-SHA256") throw new ArgumentException("INVALID_SIGNATURE_ALGORITHM");
            byte[] subjectBlob=Decode(response["subject_public_blob_base64url"],1024), authorityBlob=Decode(response["authority_public_blob_base64url"],1024);
            byte[] spki=Decode(response["subject_spki_base64url"],1024),root=Decode(response["root_claim_base64url"],16384),identity=Decode(response["identity_claim_base64url"],16384),signature=Decode(response["signature_base64url"],256);
            byte[] expectedSpki=Spki(subjectBlob); Spki(authorityBlob);
            bool spkiMatches=CryptographicOperations.FixedTimeEquals(spki,expectedSpki);
            Check(NCryptOpenStorageProvider(out provider,"Microsoft Software Key Storage Provider",0),"provider_open",operations,internals);
            IntPtr subject=Import(provider,subjectBlob,"subject",keys,operations,internals), authority=Import(provider,authorityBlob,"authority",keys,operations,internals);
            int rootStatus=Verify(authority,IntPtr.Zero,RootClaim,root),identityStatus=Verify(subject,authority,IdentityClaim,identity);
            object rootNonce=NonceMatches(root,RootClaim,nonce),identityNonce=NonceMatches(identity,IdentityClaim,nonce);
            bool nonceMatches=response["nonce_base64url"]==nonceBase64Url && rootNonce is bool && (bool)rootNonce && identityNonce is bool && (bool)identityNonce;
            bool payloadMatches=response["payload_sha256"]==Hash(payload);
            byte[] hash=Digest(payload); var padding=new Pss{algorithm="SHA256",saltLength=32};
            int signatureStatus=NCryptVerifySignature(subject,ref padding,hash,hash.Length,signature,signature.Length,8);
            bool valid=rootStatus==0 && identityStatus==0 && nonceMatches && payloadMatches && spkiMatches && signatureStatus==0;
            result["status"]="completed"; result["valid"]=valid; result["native_root_valid"]=rootStatus==0; result["native_identity_valid"]=identityStatus==0;
            result["nonce_valid"]=nonceMatches; result["payload_valid"]=payloadMatches; result["spki_matches_public_blob"]=spkiMatches; result["signature_valid"]=signatureStatus==0;
            result["root_status"]=Hex(rootStatus); result["identity_status"]=Hex(identityStatus); result["signature_status"]=Hex(signatureStatus);
        } catch(Exception error) { result["valid"]=false; result["error"]=Error(error,internals); }
        finally {
            bool clean=CloseAll(keys,provider,cleanup); result["cleanup_succeeded"]=clean; result["cleanup_statuses"]=cleanup;
            if(!clean) { result["status"]="failed"; result["valid"]=false; result["error"]=new Dictionary<string,object>{{"code","HANDLE_CLEANUP_FAILED"}}; }
        }
        return result;
    }
}
}

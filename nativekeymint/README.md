# Native Windows Keymaster laboratory

`native_keymaster_baseline` runs AOSP `AndroidKeymaster` at revision
`8729d4dd86c0bfec54c34610aa1c35f3d109b8a6` with `PureSoftKeymasterContext`,
Keymaster 4.1 and `SOFTWARE` security level. Every request and response passes
through the official binary `Serialize` and `Deserialize` implementations.
This is an in-process protocol-payload test, without AIDL, a guest, or named pipes.

```powershell
.\scripts\build-native-keymint.ps1
.\scripts\build-native-keymint.ps1 -SkipPrepare -Target cng_protocol_tests
```

Sources, portable compilers, build output, source hashes and result receipts stay
under `%LOCALAPPDATA%\android-device-lab\research-v41`. The build uses the existing
Android SDK CMake/Ninja and downloads the official LLVM-MinGW 20240619 portable
toolchain without installing it. LLVM 18 retains the generic `char_traits` used by
Android 14 cppbor; LLVM 23 no longer supports that dependency unchanged.

Pinned dependencies:

| Dependency | Revision |
| --- | --- |
| AOSP system/keymaster | `8729d4dd86c0bfec54c34610aa1c35f3d109b8a6` |
| AOSP system/libcppbor | `345280db59917d2b7085a4bd5cadab3f6935bc93` |
| AOSP hardware/libhardware | `32748ddb39cf99296ff35d374b15f04b4522e85c` |
| AOSP external/boringssl build metadata | `d513cbc24acec3bfefe3fccb0d963bfcea876a03` |
| BoringSSL production sources | `32b51305debe43e38e7bf2c2b13c4ebf3b474e80` |

The portable build has two explicit compatibility adaptations. CMake generates a
copy of the PureSoft header/source with a const-correct `GetSupportedAlgorithms`
return type, matching its base class; cached upstream files remain unchanged.
The local logging header implements only fatal assertions and sanitized error
logging required by cppbor and the linked RKP code. Cryptographic and message
implementations come from the pinned sources.

`soft_attestation_cert.cpp` and its fixture keys are not downloaded or linked.
`attestation_disabled.cpp` rejects requests for those fixtures. The software
baseline requires an empty certificate chain. No Google attestation, TEE security
level, boot verification, Android integration, or detector outcome is established
by these tests.

The baseline tests RSA-PSS 2048/SHA-256 generation and signing across two updates,
public-key export and signature verification, altered-message rejection, finished
operation handle rejection, and abort. Private keys and serialized blobs remain
in memory and are not printed or persisted.

CNG extension points are `KeymasterContext::GetKeyFactory`,
`KeyFactory::GenerateKey/LoadKey`, and `OperationFactory`/`Operation`.
`cng_key_store.*`, `cng_keymint_context.*`, and `cng_protocol_tests.cpp` form a
separate target and do not change the software baseline.

## CNG adapter

The CNG target uses the real `AndroidKeymaster`, `KeyFactory` and `Operation`
interfaces. It supports RSA-2048/SIGN/PSS/SHA-256 without user authentication.
Generation requires VBS and confirms isolation and private-export policy. The
external blob contains only a version and a random 256-bit reference, 36 bytes
total. Authorizations, exact application ID/data bindings and the public key stay
in a process-local map. The fixed public HMAC used by AOSP's software integrity
blob is not used to authenticate these references.

Only SPKI public export is supported. KeyMint 3 generation can also return a
self-signed X.509 certificate whose RSA-PSS signature is produced by CNG. This
certificate carries no Android attestation extension or external trust chain.
Import, remote provisioning, UniqueId and wrapped keys remain unsupported in
the CNG adapter. Current-epoch upgrade
preserves the blob; a changed OS/patch epoch requires upgrade and is not silently
rewritten. Keys and references expire with the process. Persistence, recovery,
cross-boot migration and full KeyMint 3 coverage are not implemented.

The current protocol run passes 79 controls, retaining the original 46 controls.
It exercises signature verification with public BoringSSL operations,
streaming Update plus Finish input, key/application binding, operation lifetime,
deletion, cross-context references, unsupported authorizations, patch epochs and
truncated input. Six independent CNG-store controls cover BCrypt verification and
Sign/Delete concurrency. That concurrency test accepts either valid ordering; it
does not force or exhaust all interleavings.

Receipts are `reports/boottee-v41-native-baseline.json`,
`reports/boottee-v41-cng-protocol.json` and
`reports/boottee-v41-cng-store-controls.json`. The protocol receipt records explicit
`equal` or `nonzero` comparisons, source/compiler/executable hashes and the actual
exit status. The build wrapper replaces stale receipts before starting and records
failed phases; `-SkipRun` produces `compiled_only`, never a passing runtime claim.

## KeyMint guest integration

`CreateHybridKeymintContext()` routes the supported RSA signing profile to CNG.
Other algorithms retain the pinned PureSoft factories for existing software key
blobs. Errors from a selected CNG operation never trigger a software retry.
The Android RSA-PSS Begin request accepts `ALGORITHM=RSA` and rejects incompatible
algorithms, duplicates and malformed types. Optional `CREATION_DATETIME` is retained as software metadata; duplicate,
incorrectly typed and negative AIDL values are rejected. The hybrid suite passes
60 controls and the KeyMint 3 certificate suite passes 57 controls.

`keymint_pipe_backend` connects to a QEMU-owned Windows named pipe and dispatches
official message-version-4 requests to the actual AndroidKeymaster. Header and
payload sizes are bounded; idle connections remain open, while incomplete I/O is
bounded. Empty Cuttlefish command buffers retain their canonical four-byte length
field. `--wire-self-test` checks two canonical messages and 16 malformed cases.
Logs contain command numbers, byte counts and storage-path events, without key
blobs or request contents. The backend does not reconnect or retry requests.
After the first complete response is written to the guest transport, the backend emits a
`serving` record. The isolated launcher waits for that record and live process
handles before publishing its ownership receipt. Startup failures retain a
separate failure receipt and attempt to stop only the newly launched processes.
`scripts/test-keymint-backend-readiness.ps1` checks that connecting alone does
not report readiness and that one canonical request does.

The isolated v42 guest service is documented in [guestkeymint](../guestkeymint/README.md).
Its runtime comparisons are recorded separately from native build receipts.
All interfaces continue to advertise `SOFTWARE` with empty hardware
authorizations. Bootloader/TEE clearance, trusted boot and Google-recognized
identity are not established by Windows protected signing.

## Optional laboratory attestation

`CreateHybridKeymintContext(true)` enables an ephemeral P-256 laboratory CA.
The default remains disabled. The CA signs the generated key's public SPKI with
the official AOSP attestation encoder, binds the supplied challenge and
application identity, and returns a two-certificate chain. Its private EVP key
is never serialized. CNG leaf private keys remain inside their existing provider.
Device IDs, UniqueId, external attestation keys and remote provisioning remain
unsupported. Ordinary generation without a challenge retains its self-signed
certificate behavior.

Certificates identify `AndroidLab Software Attestation Root` and declare
`SOFTWARE` for both security levels. The generated AOSP port omits the optional
RootOfTrust only for the software context's explicit unavailable result. It does
not replace unknown boot state with verified, locked, or invented boot hashes.
Hardware-context errors still fail. The laboratory suite passes 91 controls,
including public-root output, challenge/application binding, signature rejection,
software authorization placement and the hardware-context guards.

The backend requires `--lab-software-attestation` to enable this mode. Startup
publishes the public root certificate's SHA-256 directly on the host; Android
evidence must match that fingerprint. No private key is included in logs or
reports. The public root output parameter clears its destination when disabled.

The dedicated C-drive clone retains a read-only backing dependency on the older
isolated E-drive clone. Keep that backing file. Runtime preparation records
logical disk equality, and launch checks the selected runtime against the AVD
registration. Quick Boot file-backed RAM is disabled only for this emulator
instance. The unused caches are retained, including the new cache compressed
losslessly with identical content hashes.

```powershell
$buildRoot = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v44\build-windows-llvm18'
.\scripts\build-native-keymint.ps1 -BuildRoot $buildRoot -SkipPrepare -SkipRun -Target keymint_pipe_backend
.\scripts\test-keymint-backend-readiness.ps1
$keymintRuntime = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v42\runtime-c'
.\scripts\start-keymint-isolated.ps1 -Name lab-next -RuntimeRoot $keymintRuntime -LabSoftwareAttestation
```

Use a fresh launch name. The owned emulator is port 5586; the other emulator on
5554 is excluded from the control scripts. Private CNG references and the
laboratory issuer expire with the backend process. This remains an isolated
prototype, without persistent protected keys or manufacturer trust.
The launcher uses the readiness-enabled backend built under
`%LOCALAPPDATA%\android-device-lab\research-v44\build-windows-llvm18`.
Build it while that executable is not running; Windows locks a running executable
against relinking.

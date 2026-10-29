# Windows protected-key bridge

This experiment signs an Android-generated challenge with an ephemeral Windows VBS-protected key. It does not replace Android KeyMint, authenticate the host's boot state, or supply Google attestation.

`WindowsVbsKey.cs` requires VBS through CNG, checks `Virtual Iso=1`, and uses RSA-2048/PSS/SHA-256 with a 32-byte salt. Private keys remain in the provider and are released before the response leaves the process. Only public blobs, SPKI, claims and a signature cross the process boundary. No named key, enrollment, provider fallback or host configuration change is used.

## Protocol

`scripts/vbs-key-operation.ps1` accepts one UTF-8 JSON request on stdin, limited to 64 KiB. Each invocation requires a fresh process. `schema_version` is 1.

| Operation | Required fields beyond schema/operation | Output |
| --- | --- | --- |
| `create_response` | `nonce_base64url`, `payload_utf8` | Public response, claim blobs, payload signature and cleanup status |
| `verify_response` | `nonce_base64url`, `payload_utf8`, `response` | Native ROOT/IDENTITY, nonce, payload, public-key binding and signature verdicts |

The nonce is exactly 32 bytes in canonical unpadded base64url. Payloads contain 1–4096 UTF-8 bytes. The signature covers those exact bytes. The response declares `RSA-PSS-SHA256` and salt length 32. Unknown or duplicate fields, trailing JSON, wrong types and noncanonical encodings are rejected. Exit codes are 0 for success, 2 for a completed negative verification, and 1 for input, API or cleanup failure. Stdout is protocol data; it can contain the public attestation evidence and must not be copied into general logs.

## Android control

The `hostkeyprobe` APK creates its own request ID, nonce and 120-second challenge. Its signed payload binds the protocol, request ID, nonce, package and expiration. It verifies the host signature and the CNG public blob/SPKI binding. Consumption is saved before a success report, and replay remains rejected after an application-process restart.

The harness uses the owned APK's private files over the dedicated ADB target. It does not expose a network service or intercept another application. A separate Windows process verifies the native claims, and Node independently verifies the same signature. Android does not implement a Windows claim or trust-chain verifier: its result is explicitly `verified_untrusted_host_signature`, with `android_verified_windows_claims=false` and external/Android/Google trust all false.

Build with the project's configured JDK/Gradle environment:

```powershell
.\gradlew.bat :hostkeyprobe:assembleDebug :hostkeyprobe:lintDebug
```

With the existing isolated `device-lab-requester-v37` AVD booted on port 5584:

```powershell
node scripts/test-hostkey-android.mjs emulator-5584
```

The harness verifies both serial and AVD identity before installation. It clears only this new diagnostic package's private test data after a run, retaining sanitized host reports. It does not boot or stop an AVD itself.

## Measured scope

`reports/boottee-v40-native-controls.json` records nine passing native controls. `reports/boottee-v40-android-controls.json` records 16 passing integration controls, including the independent verifier, a valid Android signature, tampered fields/signatures, strict JSON, same-request replay, replay after process restart, prior-request replay and expiration. The earlier 15-control report is retained separately. Build/lint passed with zero errors and eleven warnings.

These are bridge and verifier tests, not new emulator detector scores. The 54/79/99/Reveny baselines were not rerun. No Bootloader/TEE clearance is claimed.

## KeyMint integration gate

A real Android backend must retain opaque private-key references and authenticate their authorization sets. It also needs correct operation-handle lifetime, streamed input/digests, upgrade, deletion, import and certificate-generation semantics. Wrapping an OpenSSL private blob with TPM/CNG is different from executing the private operation in the protected provider. A host-protected key alone does not justify changing Android's advertised security level or boot claims.

The relevant AOSP contracts are [KeyFactory](https://android.googlesource.com/platform/system/keymaster/+/8729d4dd86c0bfec54c34610aa1c35f3d109b8a6/include/keymaster/key_factory.h), [Operation](https://android.googlesource.com/platform/system/keymaster/+/8729d4dd86c0bfec54c34610aa1c35f3d109b8a6/include/keymaster/operation.h) and [authorization enforcement](https://source.android.com/docs/security/features/keystore/features). Windows CNG behavior follows [CreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey), [SignHash](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash) and [VerifyClaim](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptverifyclaim). Hardware-certified Android provisioning and a verified guest boot chain remain separate unresolved requirements.

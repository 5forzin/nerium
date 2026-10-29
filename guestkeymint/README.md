# Guest KeyMint service

`scripts/build-guest-keymint.ps1` builds an Android x86_64 API 34 executable using NDK 27 and SDK 35's AIDL compiler. It consumes the existing pinned production Keymaster source cache and the audited platform `libbinder_ndk.so` extracted into `research-v42/hal-research`. It does not install or start the service.

The executable registers these real NDK Binder interfaces at `/default`:

- KeyMint V3, including per-operation Binder objects.
- SharedSecret V1 and SecureClock V1, forwarded to the host backend.
- RemotelyProvisionedComponent V3, with every method returning `EX_UNSUPPORTED_OPERATION`.

Run the executable with the actual virtio serial character device path. The isolated v42 clone uses `androidlab-keymint-service /dev/vport22p1`. Deployment replaces the existing vendor binary and its command-line argument, preserving the executable label, service identity, VINTF declarations and SELinux policy. The observed service runs as `nobody` in `hal_keymint_default` and registers all four interfaces. The build alone establishes none of those runtime conditions.

The transport uses Cuttlefish's little-endian eight-byte KeymasterChannel header: command in bits 0–30, response in bit 31, then a 32-bit payload length. Payloads are AOSP AndroidKeymaster message version 4. Requests are serialized through one connection, capped at 1 MiB, with a 30-second deadline per transfer. Command mismatches, malformed responses, timeout and EOF close the connection; requests are never retried automatically.

The service reports `SOFTWARE`, author `Android Device Lab`, and name `AndroidLab Windows CNG`. It does not provision attestation IDs, synthesize verified boot state, or claim Google or TEE implementation. Root-of-trust APIs, storage-key conversion and attestation-ID destruction return `KM_ERROR_UNIMPLEMENTED`. Other backend errors propagate as KeyMint service-specific errors.

The preparation step adapts pinned Cuttlefish forwarding sources and AOSP converters in the external cache. It removes the upstream initialization that fabricated emulator attestation IDs and supplied device properties. Host configuration remains explicit. Build receipts contain source hashes, AIDL interface hashes, the ELF hash, and `runtime_tested: false`; no emulator boot or image changes are performed by this build.

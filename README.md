# nerium

**An open-source Android emulator that doesn't want to be caught being an emulator.**

There are paid products that cloak Android emulators from detection — [hidemyemulator.com](https://hidemyemulator.com/en/) is the famous one. They work, they're closed-source, and they charge by the month. We got stubborn about that: how far can a couple of people get, building every layer ourselves, in the open, with receipts for every claim? This repository is the answer so far. Not "0 detections" yet — but every step is measured, and every dead end is written down.

*Nerium* is the oleander genus: pretty, hard to kill, and deeply unpleasant to anything that swallows it. Seemed fitting.

## The scoreboard, honestly

| Detector | Baseline | Current |
| --- | --- | --- |
| Device Probe (54 frozen checks) | 28 detections | **0** |
| Raw Proc Probe (79 frozen checks) | 41 detections | **0** |
| Proc Interface Probe (99 frozen checks) | 14 detections | **0** |
| [Reveny](https://github.com/reveny/Android-Emulator-Detection) v1.5.0 | 4 findings | **0** |
| [Duck Detector](https://github.com/eltavine/Duck-Detector-Refactoring) `nightly-2026-10-24` | 6 danger modules | **1 danger, 2 warnings, 20 ready, 0 pending** |

All 232 frozen checks pass with zero "unavailable" weaseling. Duck's remaining danger is **TEE**, plus **Bootloader** and **ADB** warnings — more on that wall below. Play Integrity still returns an empty device-recognition verdict, while our locked physical control device (a Galaxy S25 Ultra rented through Firebase) returns `MEETS_DEVICE_INTEGRITY`. We show you that gap instead of hiding it.

Every number above has a paired before/after capture with matching APK hashes and installed ABIs sitting in [`reports/`](reports) — or it didn't happen. The full saga, version by version, is in [EXPERIMENT.md](EXPERIMENT.md). It is 170 KB of lab notebook and worth it if you're into this kind of thing.

## What this is, and the ground rules

A research lab that runs on **our own AVDs and rented lab hardware**. It is not a fraud kit: no leaked keyboxes (ours are synthetic and say so in the certificate), no Play Integrity bypass service, nothing aimed at anyone's production app. If your use case starts with "so there's this signup bonus...", this is not the repo for it.

## How an emulator gets caught, and how this one stopped being

Detectors look for tells everywhere. The lab answers layer by layer:

- **Identity (`module`)** — a scoped Zygisk runtime that rewrites what Java and native code see: `Build` fields, system properties, sensor names. A Pixel 8 fingerprint (from Google's own published research artifact) instead of `google/sdk_gphone64_x86_64`.
- **Namespaces (`module/src/main/cpp`)** — before an app specializes, it gets a private mount namespace: a reference `/proc/cpuinfo`, its own property areas (remapped at their original addresses, serial area included). Magisk mounts? Actually unmounted, not just hidden from `mountinfo`.
- **The syscall broker** — a seccomp user-notification filter that answers `uname`, `open`/`openat`/`openat2`, `stat` family and friends from snapshots injected as real read-only file descriptors (`SECCOMP_IOCTL_NOTIF_ADDFD`). The kernel fields you're allowed to keep, you keep; the ones that leak, you serve from the reference.
- **The kernel itself** — one AVD runs a kernel built from the matching Android common revision with `CONFIG_NUMA` on, because the stock emulator kernel doesn't have `numa_maps` and detectors noticed. We'd rather restore the real interface than fake it.
- **The environment** — an adbd that's actually authenticated, MTP actually applied, the legacy mDNS advertiser actually stopped during measurement windows, SELinux left Enforcing (policy hash verified), the Magisk-free bootstrap that boots root without leaving `tmpfs magisk` mounts where cross-process scanners can read them.
- **KeyMint (`nativekeymint`)** — a real guest KeyMint V3 service that forwards to a Windows backend doing RSA private operations inside VBS-protected CNG keys. It signs real attestations. It also tells the truth: both security levels say `SOFTWARE`. That honesty is the point.
- **Physical controls (`relay/`)** — a Firebase RTDB relay that pairs a rented physical phone with the emulator, so every "is this what a real device does?" question gets answered with hardware instead of vibes.

The one wall left standing is **hardware-backed trust**. An emulator has no Titan M and no Google-signed verified-boot chain, so TEE/Bootloader attestation can't be *real* — and every fake we refuse to build is documented in [EXPERIMENT.md](EXPERIMENT.md) alongside the ones that worked.

## The discipline

The part we're weirdly proud of: nothing gets counted as clear unless it survived the process.

- Detector APKs are **frozen** (hash-pinned) and installed in a matching ABI before/after. A result with a different APK hash is a different experiment.
- "Unavailable" is never "clear". If a check couldn't run, it's recorded as unavailable.
- A UI verdict must agree with the process logs, or the run is discarded.
- Every cleanup and revert is verified (reservations returned, sessions revoked, other emulators untouched — all in reports).

## Repo map

| Path | What it is |
| --- | --- |
| `probe/`, `rawprobe/`, `procprobe/` | The frozen 54/79/99-check diagnostic APKs |
| `attestationprobe/` | Keystore attestation probe with host-side verifier |
| `integrityprobe/` | Play Integrity probe (nonce-bound, tokens stay on-device) |
| `boundaryprobe/`, `adbcontrol/`, `hostkeyprobe/` | Root-boundary, ADB-state and Windows VBS key probes |
| `module/` | The Zygisk runtime + namespace component (the actual cloaking) |
| `guestkeymint/`, `nativekeymint/`, `keymintcontrol/`, `cngattestationcontrol/` | The guest KeyMint service and Windows CNG backend |
| `relay/`, `relayworker/`, `relayrequester/` | The Firebase relay for physical-device controls |
| `hardwareprobe/` | Hardware snapshot probe (see below) |
| `scripts/` | ~120 build/capture/verify scripts. PowerShell on the host, POSIX in the guest |
| `reports/` | The evidence: JSON, logs, exports. Screenshots and frozen APKs stay local |

## Build

Requirements: JDK 17–23, Android SDK platform 35, Build Tools 35.0.0, NDK 27.0.12077973, CMake 3.22.1 (Gradle 8.13 pinned by the wrapper). Set `JAVA_HOME` and `ANDROID_HOME`, or drop the SDK path into an untracked `local.properties`.

```powershell
.\scripts\build.ps1
```

APKs land in each module's `build/outputs/apk/debug/`. Yes, the Gradle project is named `nerium` while the packages stay `dev.androidlab.*` — the frozen APK hashes depend on those names, and we don't break our own evidence.

## Run the paired experiment

Short version (the dedicated Android 14 Google APIs AVD, on its default port):

```powershell
.\scripts\start-emulator.ps1                     # device-lab-api34 on port 5554
.\scripts\install-probe.ps1 -Abi arm64-v8a
.\scripts\install-namespace-module.ps1 -Serial emulator-5554   # then reboot

# baseline, then enabled — same APK, same ABI, before/after
.\scripts\set-module.ps1 -State disable
.\scripts\capture.ps1 -Name before-probe
.\scripts\set-module.ps1 -State enable
.\scripts\capture.ps1 -Name after-probe
python .\scripts\compare_reports.py .\reports\before-probe.json .\reports\after-probe.json
```

If port 5554 is taken, boot the lab on `-Port 5556` and pass `-Serial emulator-5556` to the scope, installer and capture scripts.

From there the README hands you off to the scripts: `capture-detector.ps1` (Reveny, hash-verified), `capture-external.ps1` (the pinned detector catalog in `scripts/detectors.json`), `export-duck.ps1` (Duck's own export, matched to the live UI), `capture-attestation.ps1` (Keystore chains + host-side `verify-attestation.py`), `capture-play-integrity.ps1`. Each one fails loudly instead of guessing. The extended recipes — NUMA AVD, offline ADB windows, platform supervisor, per-version steps — are in [EXPERIMENT.md](EXPERIMENT.md).

## Physical hardware reference (current work)

The remaining tells are hardware-shaped: our CPU snapshot is the native bridge's *generic* ARM view, sensor labels are cosmetic, GLES strings are neutral. The next milestone is a reference profile captured from **real hardware** — and Firebase Test Lab rents real Pixels by the minute, which is cheaper than buying a Pixel and infinitely cheaper than guessing.

The flow:

1. Stream a physical device (Android Studio's Device Manager streaming, or `gcloud alpha firebase test android streaming create --model <id> --version 35`), which gives you an adb endpoint like `localhost:56785`.
2. `.\scripts\capture-hardware.ps1 -Serial localhost:56785 -Name physical-pixel9` — installs `hardwareprobe`, collects the app-visible hardware view (props, sensors, cameras, codecs, EGL strings, Widevine level, system features…) plus the shell-side view (`/proc/cpuinfo`, cpufreq topology, `/proc/bus/input/devices`, `dumpsys sensorservice`…), verifies device identity before and after, and writes one merged JSON.
3. Repeat on the emulator with the profile enabled, then `python .\scripts\compare-hardware-profile.py reports/physical-pixel9.json reports/emulator-enabled.json` — a field-by-field diff that is, effectively, the to-do list for the next version.

## Honest boundaries

The full list lives at the end of [EXPERIMENT.md](EXPERIMENT.md); the short version:

- No hardware-backed attestation, no Play Integrity device integrity, no StrongBox. The KeyMint work is real and explicitly software.
- The CPU reference is a snapshot, not telemetry; the x86_64 kernel and host CPU are still x86_64 and an honest probe still says so.
- Everything was measured on pinned Android 14 images with the pinned detector catalog. Other apps, other versions, other kernels: unmeasured.
- Framework backends, seccomp broker and ARM helper depend on validated layouts of *those* images (API 34 ART/libc/EGL pins).
- We do not claim the emulator is indistinguishable from physical hardware. We claim exactly what's in the reports.

## References

- [EXPERIMENT.md](EXPERIMENT.md) — the complete lab notebook, v0.1 through v0.44
- [Zygisk API](https://github.com/topjohnwu/Magisk/blob/master/docs/guides.md#zygisk) and [seccomp user notification](https://docs.kernel.org/userspace-api/seccomp_filter.html#userspace-notification)
- [Android key attestation](https://source.android.com/docs/security/features/keystore/attestation) and [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)
- [hidemyemulator.com](https://hidemyemulator.com/en/) — the paid thing this project answers

## License

[MIT](LICENSE) — do what you want, don't blame us, and keep the honesty in the reports if you fork it.

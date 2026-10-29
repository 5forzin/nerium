# Android Device Lab

A small Android observation and interception lab. It contains three frozen diagnostic APKs (`probe`, `rawprobe` and `procprobe`), an independent Java-only attestation APK (`attestationprobe`), a native runtime APK (`module`), and a scoped Zygisk namespace component. The optional `adbcontrol` APK schedules an ADB-off measurement and a recovery alarm on an isolated test AVD; its host-granted permission is removed when the helper is uninstalled. The original probe contains x86_64 and ARM64 native libraries. The other frozen diagnostics contain only x86_64 code and issue inline syscall instructions. The runtime targets the lab's pinned x86_64 Android 14 image.

See [the initial experiment](EXPERIMENT.md) for measured runtime results and the exact tested environment.

The `relayworker` APK and `relay/RelayHost.psm1` implement a cooperative Firebase relay for challenge echoes and the worker APK's own Play Integrity requests. The host pairs a foreground worker through private ADB provisioning, verifies request bindings, and reports the worker's verdict separately from the requester. See [the relay protocol](relay/PROTOCOL.md) for Worker behavior and v36 evidence, and [requester integration](relay/REQUESTER.md) for the pinned local broker, persistent-service bootstrap, v0.37/v0.38 measurements, and remaining limitations. The small v0.38 comparison observed lower request latency with unchanged APKs; it does not establish zero detections or transfer the worker's identity to the emulator.

Version 0.5 changes selected Java `Build` fields, Java/native properties and sensor labels to a reference profile. Its Pixel 8 fingerprint comes from [Google's published research artifact](https://github.com/google/droidcct-paper-artifact/blob/main/bug_samples/BUG_01_key_size_not_available.csv); the build ID is listed in the [AOSP build reference](https://source.android.com/docs/setup/reference/build-numbers). Sensor events and the real Android version are preserved. This is an observation profile, not a complete Pixel 8 hardware reproduction.

Versions through 0.9 used an Xposed/Vector backend for some packages, including Java identity and sensor-label getters, native properties, CPU file reads and subprocess helpers. Version 0.10 removes the Xposed dependency and registration from the APK. Earlier backend measurements remain in the experiment log.

Translated ARM apps use a bridged native-library namespace. The runtime prepares a host class loader before specialization, then loads the ARM helper through its own bridged loader after specialization. The host runtime registers the sensor JNI adapter through public Zygisk API v4. Its original method pointer is validated against the pinned ART layout. Inspect `DeviceLabRuntime` and `DeviceLabNamespace` logcat tags for initialization results.

Version 0.5 also loads a small ARM64 library through the bridged loader. It validates the pinned Android 14 libc getter's instruction layout and page-size entry, copies its auxiliary vector, supplies an ARM64 `AT_PLATFORM` entry and publishes the immutable copy. Existing entries remain intact. Unsupported layouts are reported without changing their pointers. This updates the guest libc table, rather than replacing the diagnostic's getter.

Version 0.6 supplies process-local snapshots for `maps`, `smaps`, `mountinfo` and `mounts` through the syscall broker. It handles x86 `open` and `openat`, including inline instructions, numeric PID/TID paths, task directories, thread-self, dirfd-relative paths, root aliases and normalized components. The views omit native-bridge libraries, this module's APK mappings, and private profile mounts. A filtered `smaps` mapping loses its entire record, including its associated counters. Retained records are unchanged. Earlier releases also provided a libc snapshot fallback.

The Zygisk component creates a private mount namespace before specialization. A root companion binds a reference ARM CPU snapshot captured from the stock image's native-bridge view and copies only the property areas needed by the profile, including their serial area. It runs Magisk's `resetprop -n` against these private copies, then remaps inherited read-only property pages at their original addresses after specialization. This covers the translated ARM libc as well as newly executed subprocesses. The reference profile leaves global identity properties and the global CPU mount unchanged and does not relax SELinux. ADB authentication and policy tightening are separate global security changes on this dedicated AVD. Scope is restricted to the laboratory package list written by `set-module.ps1`, including their colon-suffixed subprocess names.

An additional seccomp user-notification filter handles x86_64 `uname` and selected proc operations in scoped processes and descendants. A root companion worker supplies the uname machine field while preserving the other kernel fields. Proc snapshots use read-only, unlinked files labeled `system_file`, atomically injected through `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. The broker also handles `fstat`, `fstatfs`, selected `newfstatat` calls and descriptor links through `readlink`/`readlinkat`. It retains each snapshot's original proc path so inode, device and descriptor aliases match that source. The worker validates notification IDs, pins target memory before writing, checks writable mappings and preserves invalid/read-only pointer failures. It exits on listener HUP when the last filtered task exits. Installation uses the zygote's existing privileges, leaves `NoNewPrivs` unchanged and keeps SELinux enforcing. Removing `proc-enabled` disables only the new proc broker for newly started processes; `uname-enabled` controls the entire syscall listener.

Raw Proc Probe has 79 checks: 41 proc content paths and 38 I/O/metadata controls. Its ELF contains an actual x86 `syscall` instruction, independently verified with `llvm-objdump`. Both APK hashes and installed ABIs must match in comparisons. The original 54-check APK remains unchanged.

Version 0.7 adds legacy `stat`, path-based `statfs`, `statx`, selected file-backed `mmap` requests, `fdinfo` and `map_files` coverage. It supports measured read-only opens using `O_NOFOLLOW`, `O_NOCTTY` and `O_NOATIME`, preserving final-symlink failures. Extended metadata uses the source inode/device and the notifying process's proc mount ID. Fdinfo snapshots retain real descriptor positions and flags while normalizing source inode and mount identity. Selected proc snapshots preserve the original mmap error instead of behaving as mappable data files.

Map-files directory reads duplicate the original descriptor using `pidfd_getfd` after checking the shared descriptor table with `kcmp(KCMP_FILES)`. The broker omits selected mapping entries while retaining the real directory stream, cookies and rewind behavior. Invalid output buffers restore the original stream position. Selected hidden map-file links return ENOENT. The original mappings still exist and remain visible outside the scoped processes.

Proc Interface Probe is a separate APK with 95 baseline checks. Its first frozen 60-check revision found 41 additional detections against version 0.6; the expanded revision adds 35 error/metadata controls. With version 0.7, Android's inherited seccomp policy blocks `openat2`, and the stock kernel does not provide `numa_maps`. Capability calls run in children so SIGSYS does not terminate the main diagnostic. Unavailable results are retained explicitly and are never counted as clear.

Version 0.8 permits x86_64 `openat2` in the scoped child's Android seccomp policy. It prepends five instructions and retains the original policy verbatim for every other syscall and architecture. The temporary `libandroid_runtime` PLT hook is restored after specialization. The existing proc broker handles the measured read-only, zero-resolve-flags form; unsupported arguments continue to the kernel for validation. The unchanged diagnostic APK then executes four additional openat2 reads: all 99 checks returned no detections on the stock kernel, with only `numa_maps` unavailable. The original 79-check and 54-check APKs and the pinned Reveny APK remained clear after reboot.

The separate `device-lab-numa` AVD uses a kernel built from the matching Android common revision with CONFIG_NUMA enabled. Its ramdisk and logical vendor/system_dlkm partitions contain modules rebuilt against that kernel. This restores the real numa_maps interface and get_mempolicy syscall. Adding numa_maps to the existing scoped proc views clears its newly observable mapping finding. The frozen APK returned 0 detections and 0 unavailable results across 99 checks; the 79-check, 54-check and Reveny regressions also remained clear. The stock AVD and SDK images are preserved.

Independent expansion with the pinned Duck Detector nightly found remaining virtualization and instrumentation evidence. Applying the unchanged version 0.8 profile reduced Duck's direct virtualization signals from 14 to 8, while revealing nine high-risk memory signals and a high-risk LSPosed signal. The original 99/79/54 diagnostics and Reveny remained clear. Both previously unavailable ARM detectors still exited without a usable verdict. These findings are recorded separately from the original regression results in `reports/strict-v09-summary.json` and [the experiment log](EXPERIMENT.md).

Version 0.9 adds an optional native-only runtime for selected x86_64 packages on the pinned API 34 image. The namespace component loads a normal APK-backed library after specialization and then unloads itself. That library updates Build fields through JNI, validates and copies the host libc auxiliary vector, and changes the shared EGL string-dispatch data slot. It does not patch libc or GLES instructions or allocate executable trampolines. Packages using this backend are excluded from the Vector module scope while retaining the namespace and syscall broker. The existing framework backend remains available for translated ARM packages and comparison runs.

The private property profile now covers ro.boot.hardware and clears the AVD-name value before startup preload. Scoped proc views also omit the ranchu graphics-mapper records and use neutral readlink labels for the goldfish graphics-channel and sync descriptors. The real library mappings, character descriptors and their I/O remain unchanged outside these views. The framework backend initializes once per process, preventing a second WebView load-package callback from trying to create another package's cache directory.

The complete version 0.9 Duck export reports virtualization 8→0, high-risk memory signals 9→0 and high-risk LSPosed signals 1→0 against the accepted version 0.8 capture. Memory has zero review findings as well. Virtualization remains INFO because ARM-only probes are unsupported in the unchanged x86_64 installation, and LSPosed retains root-policy/module-metadata warnings and an unavailable native heap slice. Duck overall remains DANGER with six danger modules. The 99/79/54 diagnostics and Reveny remained clear before, between and after the changes. See `reports/strict-v10-summary.json` for verified hashes, scope, original exports and comparisons.

Version 0.10 migrates all ten laboratory packages to the native backend and disables Vector. Actual private unmounting, authenticated ADB, policy tightening and removal of broker-generated package-directory opens reduce the default Duck result to three danger modules. The optional isolated `READPROC` restriction reduces this to two danger modules with narrower cross-process mount visibility. The verified configuration also removes the unused Magisk manager after boot: memory is clear, LSPosed has zero review signals, and virtualization has zero findings in supported checks. Bootloader and TEE still lack hardware-backed trust; five unrelated warning modules remain. The unchanged 99/79/54 diagnostics and Reveny remained clear after cold restart. Evidence and availability details are in `reports/strict-v11-summary.json`.

The probe has 54 checks spanning Java/native identity, libc reads, the `syscall()` wrapper, inline syscall instructions, clean-environment subprocesses, auxiliary-vector access, filesystem metadata, maps, mountinfo and GLES strings. Seven I/O controls cover five ordinary-file read paths, CPU descriptor semantics and ordinary-file metadata. The native architecture function is unchanged and reports the compiled library's actual ABI. ARM64 mode executes that ARM64 library through the image's existing native bridge. Each report distinguishes detected, clear and unavailable results. None establishes that a device is physical.

## Build

Requirements: JDK 17–23, Android SDK platform 35, Build Tools 35.0.0, NDK 27.0.12077973 and CMake 3.22.1. Gradle 8.13 is pinned by the wrapper. Set `JAVA_HOME` to a compatible JDK and set `ANDROID_HOME` or provide the SDK path through untracked `local.properties`.

```powershell
.\scripts\build.ps1
```

The Windows helper defaults to `C:\Program Files\Java\jdk-21` and `%LOCALAPPDATA%\Android\Sdk`. Override these paths with `-JavaHome` and `-SdkRoot`. It changes environment variables only for the build process and restores their previous values afterward.

APKs are written to each module's `build/outputs/apk/debug/` directory. Version 0.10 has no Xposed API dependency or module registration.

## Run the experiment

1. Start the dedicated Android 14 Google APIs AVD with `./scripts/start-emulator.ps1`. Add `-Visible` for a window. The configured AVD is `device-lab-api34`; wait for boot and application storage to become available.
2. Run `./scripts/install-probe.ps1 -Abi arm64-v8a`. Both baseline and enabled runs must use the same APK and installation ABI. Use `-Abi x86_64` for the native x86 control.
3. Install the runtime APK on the configured Magisk AVD, then run `./scripts/install-namespace-module.ps1` and reboot. The installer requires the emulator property. Vector is disabled in the version 0.10 configuration.
4. Use `set-module.ps1 -State disable` for the baseline, then enable it and restart both apps before collecting the paired measurements below.
`./scripts/set-module.ps1 -State enable` selects only Device Probe. Native-only mode is the default and does not call the Vector CLI. Add `-IncludeIndependentDetector` for the installed Reveny v1.5.0 demo and `-IncludeRawProbe` for Raw Proc Probe. Use `-State disable` for the disabled control.

If another AVD occupies port 5554, leave it running and use `start-emulator.ps1 -Port 5556`. Pass `-Serial emulator-5556` to the scope, namespace installer and capture scripts. The version 0.6 experiment used this separate port while `apollonia-test` continued on 5554. To collect raw diagnostics after installing `rawprobe-debug.apk` with ABI x86_64:

```powershell
.\scripts\set-module.ps1 -Serial emulator-5556 -IncludeIndependentDetector -IncludeRawProbe
.\scripts\capture.ps1 -Serial emulator-5556 -Package dev.androidlab.rawprobe -Name after-raw
```

Install `procprobe-debug.apk` with ABI x86_64, add `-IncludeProcProbe` when setting scope, then collect with `capture.ps1 -Serial emulator-5556 -Package dev.androidlab.procprobe -TimeoutSeconds 45 -Name after-proc`. Keep the original 54-check and 79-check APKs unchanged for regression measurements.

The prepared NUMA AVD stores its independent disks and custom system directory under `%LOCALAPPDATA%\android-device-lab\numa-kernel`. Once stopped, open it with a normal emulator window:

```powershell
.\scripts\start-emulator.ps1 -Name device-lab-numa -Port 5556 -Visible
```

Mouse, keyboard, APK installation and persistent app storage work through the usual emulator interface. Scope still applies only to the configured laboratory packages. After a namespace module upgrade, reboot first and then reapply scope with `set-module.ps1`; Magisk replaces that module directory during the upgrade. Ordinary restarts preserve the configured scope.

For paired probe and independent-detector measurements:

```powershell
.\scripts\set-module.ps1 -State disable
.\scripts\capture.ps1 -Name before-probe
.\scripts\capture-boundaries.ps1 -Name before-boundaries
.\scripts\capture-detector.ps1 -Name before-detector
.\scripts\set-module.ps1 -State enable -IncludeIndependentDetector
.\scripts\capture.ps1 -Name after-probe
.\scripts\capture-boundaries.ps1 -Name after-boundaries
.\scripts\capture-detector.ps1 -Name after-detector
python .\scripts\compare_reports.py .\reports\before-probe.json .\reports\after-probe.json
python .\scripts\compare_reports.py .\reports\before-detector.json .\reports\after-detector.json
```

`capture-detector.ps1` requires the unchanged [reveny v1.5.0 release APK](https://github.com/reveny/Android-Emulator-Detection/releases/tag/v1.5.0). It verifies the installed APK's SHA-256 and requires agreement between a fresh UI result and the current detector process log. It fails instead of treating a missing result or a crash as success. Disable and re-enable the module, restarting the apps each time, to check reversal and repeatability.

The probe collects on launch and writes `files/report.json` to private application storage. Debug builds allow extraction using `adb run-as`. The UI can also share JSON. The capture helper requires successful deletion of the previous report and records the installed APK hash and Package Manager ABI. The comparison helper rejects changes to either. Boundary captures inspect the running probe before launching the independent detector, to avoid losing the background process to memory pressure.

For the extended suite, use `set-module.ps1 -State enable -IncludeExtendedDetectors` and select a pinned detector ID from `scripts/detectors.json`:

```powershell
.\scripts\capture-external.ps1 -Name after-spotter -Detector spotter
.\scripts\capture-external.ps1 -Name after-native-root -Detector native-root
```

The collector verifies installed APK checksums and ABIs, saves fresh screenshots/UI/logs, and checks process and foreground identity again after collection. A missing result, startup notice or crash is not a clear verdict. Native canvas results require visual review. Framgia's tested configuration grants only `READ_PHONE_STATE` on the empty laboratory AVD; both baseline and enabled runs use that same permission.

The catalog also pins Duck Detector `nightly-2026-10-24-b5305070` in x86_64 mode. Install its original APK before including every catalog entry in scope. For an unscoped control that keeps the regression packages enabled, add `-ExcludeDetector duck,native-root,native-test` to `set-module.ps1 -IncludeExtendedDetectors -IncludeRawProbe -IncludeProcProbe`. Remove that exclusion for the paired enabled run.

After launching Duck and completing its startup choices, `export-duck.ps1 -Serial emulator-5556 -Name <measurement>` waits for the completed dashboard and uses the app's own export action to save its text report through Android DocumentsUI. It dismisses update offers without installing another build. The collector verifies the pinned APK, current process, dashboard counts, export age and build identity. It requires all 20 module reports and zero pending modules; unsupported subchecks inside completed modules remain visible in the original export. The before/after runs used the same startup choices and original APK.

To configure all installed laboratory packages on the current native runtime:

```powershell
.\scripts\set-module.ps1 -Serial emulator-5556 -IncludeExtendedDetectors -IncludeRawProbe -IncludeProcProbe -NativeOnly
```

The helper validates installed x86_64, translated ARM64 and Java-only packages. Reapply scope after replacing the runtime APK or upgrading the namespace ZIP; the configuration records the installed APK's current path. The namespace installer flushes staged writes before a cold restart. Version 0.9 framework comparisons require the preserved older APK and configuration.

The version 0.10 runtime stages an exact APK copy under `/data/misc/device-lab` with root ownership and a `system_file` label. CPU/property snapshots use the same backing directory. This allows the public Zygisk private-unmount option to remove Magisk and Vector mounts without removing the profile itself. It does not unload the retained runtime or change the underlying x86 hardware.

`-RestrictIsolatedProc` is a separate, default-off sandbox experiment. It removes only supplemental GID 3009 (`READPROC`) from scoped isolated services with app IDs 99000–99999. Other groups, main application identities and app-zygote carriers are preserved. This changes actual kernel visibility of other processes; a lower mount finding count under this option must be reported with its reduced cross-process observation scope. Disabling the profile removes its marker too.

`enable-adb-auth.ps1 -Serial emulator-5556` authorizes only the host's existing ADB public key before enabling authentication and restarting adbd. `harden-lab.sh` revokes the two measured dirty-policy grants after Vector is disabled. The namespace module's `service.sh` repeats these changes after boot only when their root-owned opt-in markers exist. Keep the public-key authorization backup in the local cache when reproducing this setup.

The optional root-owned `/data/misc/device-lab/remove-manager-enabled` marker also removes the Magisk manager APK after Magisk's boot-complete installation, preserving its application data. The root daemon, CLI and laboratory runtime remain installed. The original manager APK is backed up in `%LOCALAPPDATA%\android-device-lab\research-v11\magisk-manager27.apk`; remove the marker before reinstalling that backup when the manager UI is needed. This avoids the detector's package inspection creating a transient maps-only manager-APK warning inside its own process.

## Independent attestation measurements

Install `attestationprobe/build/outputs/apk/debug/attestationprobe-debug.apk` without adding its package to the runtime scope. It generates an Android Keystore EC key with a fresh 32-byte challenge, collects the public certificate chain, checks key possession, records `KeyInfo` and signed `RootOfTrust`, and separately attempts StrongBox. Measurement keys are deleted after collection; private keys are never exported.

```powershell
.\scripts\capture-attestation.ps1 -Serial emulator-5556 -Name attestation
python .\scripts\verify-attestation.py reports/attestation.json --output reports/attestation-verified.json
python .\scripts\check-attestation-verifier.py reports/attestation.json
```

The host verifier uses Python `cryptography` to independently check certificate signatures, validity, nonce binding, key possession and the DER authorization lists. These checks establish consistency, not manufacturer trust. The measured emulator supplies software security level 0, an unlocked/unverified software `RootOfTrust`, no StrongBox and a test CA. It does not establish hardware-backed storage or a manufacturer trust anchor.

The version 0.10 follow-up found a genuine image metadata inconsistency: both KeyMint AIDL interfaces report version 3, but their VINTF declarations were version 2. `update-keymint-manifest.py` updates only those two version digits in independent image copies after checking the measured versions, identical vendor extents and filesystem integrity. Duck then reports a matching VINTF version; its TEE score changed from 26 to 16 while the software attestation claims stayed unchanged. The original images and AVD configuration are preserved under the local research cache.

`invoke-emulator-console.ps1` authenticates to port 5556 and verifies the dedicated AVD name before accepting console commands. It supports recovery and screenshots when ADB is unavailable without restarting the other emulator or the shared ADB server.

`configure-network-adb.ps1` disables USB debugging and applies the actual MTP configuration while retaining the emulator's existing authenticated network transport. Its independent root worker restores the previous state unless the host reconnects, verifies the state and acknowledges it. Namespace package 0.10.1 can repeat that mode at boot when the root-owned `/data/misc/device-lab/network-adb-only-enabled` marker exists. The runtime APK and native ELF version remain 0.10.0. An active network daemon still produces a legitimate ADB Runtime warning.

`measure-adb-offline.ps1 -Name <measurement>` temporarily stops that daemon and this guest's legacy mDNS advertiser. It requires 36 samples with debugging disabled, both services stopped, ADB authentication enabled, MTP present/applied and root property 0, then restores the previous operating mode. Wi-Fi and the Java NsdService discovery backend remain enabled. The original pinned Duck APK runs inside that window. The collector checks that its process survives until the built-in report export. A scan from this offline window must not be presented as the normal active-ADB result.

The inode review was tested with actual filesystem placement. `prepare-lab-tmp.sh` briefly sets ext4's allocation goal to create `/data/local/device-lab-tmp-v12` with inode 1000, then restores the allocator to 0. `exchange-lab-tmp.cpp` uses ordinary directory and child renames to exchange that empty directory with `/data/local/tmp`, preserving file contents, child inodes, ownership, modes and the two observed SELinux xattrs. The original directory remains empty and root-only at the staging path. The helper is restricted to the measured inode identities and directories; it is not a general filesystem migration tool. Its `--restore` operation was tested before final application. This removes a weak numeric heuristic, not evidence of root or virtualization.

## Version 0.11 platform notification experiment

The custom kernel adds a privileged notification domain for the laboratory broker, leaving the normal application listener slot available. Application filters run first, including ERRNO and TRAP; a continued syscall then reaches the platform broker. Installation requires initial-user-namespace `CAP_SYS_ADMIN`, no `no_new_privs`, and an ALLOW/USER_NOTIF-only program. Platform descriptor ioctls also require that capability. Ordinary duplicate listeners still return EBUSY, and every filter remains counted.

`prepare-supervisor-kernel.py` accepts only the pinned original seccomp source. `build-supervisor-kernel.sh` builds in a separate Docker volume and checks all 14,633 exported symbol CRCs against the baseline. The independent `platform-seccomp-check.cpp` exercises twelve capacity, privilege, metadata, action-ordering, inheritance, TSYNC and FD-injection cases. This is a kernel extension, not stock Android behavior or hardware attestation.

Boot `device-lab-numa` on port 5556 with the built `research-v13/kernel-platform` image using `start-emulator.ps1 -KernelImage`. Install native APK and namespace package 0.11.0, reboot, and reapply package scope. Enable the domain with:

```powershell
$env:ANDROID_AVD_HOME = Join-Path $env:USERPROFILE '.android\avd'
.\scripts\start-emulator.ps1 -Name device-lab-numa -Port 5556 -KernelImage "$env:LOCALAPPDATA\android-device-lab\research-v13\kernel-platform"
# After installing 0.11.0, rebooting and reapplying scope:
.\scripts\set-platform-supervisor.ps1 -Serial emulator-5556
```

Activation requires all twelve independent checks. Its root-owned marker is bound to the current boot ID. The service rechecks kernel support after reboot; an unsupported kernel retains the legacy backend. Restart measured apps after enabling or disabling the domain. `-State disable` removes the request and active markers.

The paired Duck scans `strict-v13-duck-kernel-legacy` and `strict-v13-duck-platform` use the same new kernel, runtime and original detector APK. The legacy mode retains EBUSY. With the platform domain enabled, Duck creates its listener and receives notifications for all 10,000 tested getpriority queries. Its warning count changes from three to two. Dangerous Apps becomes INFO because its Android 15/16 permission probe remains unsupported on Android 14; this is not a full-coverage clear verdict.

`audit-attestation-trust.py` invokes the independent host signature/nonce/possession verifier and compares the public root with an externally supplied PEM snapshot. The official Google snapshot is available at `https://android.googleapis.com/attestation/root`. The audit records signed hardware/boot prerequisites and RKP extension placement, but does not perform full PKIX path validation or revocation checks. A matched root alone never establishes manufacturer trust. The measured software test chain matches neither official root certificate nor public key. Its signed hardware and boot claims remain unchanged.

## Version 0.12 stock-policy bootstrap experiment

The independent `research-v14/avd/device-lab-numa.avd` clone uses the restored stock init and a root-owned userdebug bootstrap instead of Magisk's boot injection. The original six AVD disk files remain unchanged against the clone manifest. `audit-restored-ramdisk.py` checks the restored init and the eight retained kernel modules. The loaded SELinux policy retains its original SHA-256, `725322b8bb21c399e222db65bd9e0ee307a3b603d19d9a3d5f47a93cc8f369c0`; raw kernel context checks accept the stock zygote control and reject both Magisk types with EINVAL while enforcement remains enabled.

`prepare-platform-bootstrap.py` transforms a clean ReZygisk checkout pinned to `b5aa415c2ce1161ab807578ce0414129fbfc6313`. Its Platform backend requires UID/EUID 0, the stock userdebug `su` context and an explicit root-owned marker. It loads only `device_lab_cpu`, requires a root peer for companion requests, and grants no application UID root access. `scripts/platform-bootstrap/CMakeLists.txt` builds the host x86_64 components with NDK 27. Application debug logging is disabled at compilation; errors remain available. The reproduction audit matches all thirteen transformed source files after normalizing Windows line endings.

`prepare-platform-images.py` adds the vendor init service to independent copies of both vendor extents, checks filesystem integrity, and verifies that all existing vendor SELinux policy files remain identical. The early service launches the monitor before zygote; a separate late service restores authenticated network ADB with USB debugging disabled and actual MTP configuration. The monitor occupies its own cgroup and survives service exit and adbd restarts. Boot markers contain the current kernel boot ID.

```powershell
.\scripts\capture-platform-boot.ps1 -Name platform-boot
```

The collector requires fresh early/late/domain markers, an active init tracer in the private cgroup, identical installed binaries, the unchanged policy, five SELinux controls, all twelve platform syscall contracts and the restored network operating mode. The first automatic cold boot passed these checks, all 232 frozen diagnostic checks and the pinned Reveny detector. Its first Reveny collection was obscured by a System UI ANR and is explicitly retained as unavailable; the fresh retry produced the corroborated clear result.

The prototype retains private legacy files and a standalone Magisk 27 `resetprop` executable. Version 0.12.0 invokes that root-only executable for private property copies and falls back to the legacy CLI on the earlier baseline. Removing Magisk's boot injection and SELinux types does not remove all Magisk-derived code or supply hardware trust. The unscoped attestation APK still measures software security level 0, unlocked/unverified boot, zero boot key/hash, no StrongBox and a test CA outside both official Google roots. The host verifier passes its nonce/signature/possession controls without establishing manufacturer trust.

The first version 0.12 offline window proved adbd was stopped, but Duck still resolved a local legacy mDNS announcement and retained its ADB warning; its TCP connection was refused. [Android 14 adbd registers mDNS cleanup with `atexit` and notes a hard-kill limitation](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/daemon/mdns.cpp). The revised worker also stops and restores this guest's legacy `mdnsd` publisher. This changes the actual publication lifecycle and does not filter discovery responses or alter the detector.

Version 0.12.1 moves module configuration and syscall snapshots out of `/data/adb`. `migrate-platform-storage.sh` copies active configuration to the private platform module directory and atomically renames the complete legacy directory to `/data/misc/device-lab/legacy-v012/adb`, preserving its inode, contents and root-only protection. The stock `init.usb.rc` recreates an empty `/data/adb` at boot; the early service retires that unused directory with `rmdir`, which refuses unexpected contents. No audit records or SELinux permissions are changed. The first mDNS-corrected scan had exposed the detector's own denied access to that legacy path; it remains recorded as a real warning. A standalone BusyBox copied from the legacy installation supports root boundary measurements.

The final automatic-boot validation keeps all 232 frozen checks and Reveny clear. Duck's normal scan retains two Danger modules and the active-ADB warning. Its final controlled offline scan reports two Danger, zero Warning, twenty Ready and zero Pending; Bootloader and TEE remain unresolved. SELinux, ADB and Memory are CLEAR in that window. LSPosed and Virtualization remain INFO with the documented coverage gaps. All 36 inactive-ADB samples also verify that the legacy advertiser is stopped; network operation is restored afterward. See `reports/strict-v14-summary.json` for comparisons, hashes, failed attempts and the independent trust audit.

Cold-boot regression workloads also produced System UI service ANRs and a Google Play services broadcast ANR. Obscured detector collections are retained as unavailable; their fresh retries pass. The primary System UI trace shows its main thread runnable during view-model initialization, but the cause is not established. These detection results do not establish full interactive stability.

## Version 0.12.2 CPU enumeration and trust audit

The namespace CPU snapshot previously contained only processor 1 while the guest had processors 0–1 online. Version 0.12.2 generates one reference record per online guest CPU. The external root observer in `capture-cpu-topology.ps1` compares namespace CPU enumeration, unscoped kernel enumeration, sysfs online/present lists and process affinity. Its four controls change from one finding to zero; both two-core and four-core runs pass. This observer is separate from the frozen in-app diagnostics. Per-core ARM fields remain the native bridge reference, and enumeration assumes the pinned guest's contiguous CPU IDs without hotplug.

`start-emulator.ps1` accepts `-Cores`, with the existing default of two. The dedicated prototype was cold-started with four cores, then two, then four using the same 0.12.2 runtime. Each run passed the unchanged 99/79/54 diagnostics and Reveny without an ANR recorded during that workload. The four-core final run also passed all five SELinux controls and twelve platform syscall contracts. Boot time and warmed caches differ across these runs, so this does not establish a CPU-count cause for the earlier ANRs or prove sustained interactive stability. The running prototype uses four cores:

```powershell
# Run only when the dedicated emulator is stopped.
.\scripts\start-emulator.ps1 -Name device-lab-numa -Port 5556 -Cores 4
```

The independent Java attestation and host signature/nonce/possession verifier still report software security level 0, unlocked/unverified boot and zero boot key/hash. `audit-duck-attestation.py` correlates Duck's exported root public-key fingerprint with the independent certificate. Duck hashes SubjectPublicKeyInfo; the host's certificate hash covers the complete certificate, explaining the different printed fingerprints. In the pinned Duck source, Factory is a fallback classification rather than manufacturer authentication. Its six Bootloader danger entries reuse four signed boot fields. The audited certificate and public key match neither official Google anchor. The reviewed TEESimulator, Cuttlefish TPM backend and AVF attestation paths do not supply the missing provisioned manufacturer identity merely by installing their code. Bootloader and TEE remain unresolved.

Attestation Probe 0.2.0 accepts a 32-byte external challenge. `capture-attestation.ps1` generates it on the host and saves a separate `NAME-challenge.json` before launching the APK. Pass that file to the host verifier or trust audit with `--expected-challenge`. This checks the signed extension against the host request, independently of the challenge echoed in the device report. The checker also rejects a previously valid report against a different host challenge. The original attestation APK is preserved separately, and all three frozen diagnostic APKs remain unchanged.

The final four-core Duck offline export reports two Danger, zero Warning, twenty Ready and zero Pending. All 36 state samples show adbd and its legacy mDNS advertiser stopped, authenticated ADB configured and actual MTP functions; the measured detector process survives export, and normal network operation is restored afterward. Six verifier controls pass, including replay rejection, and a separately collected valid capture A is rejected against capture B's real host request. The attestation APK remains outside the ten-package runtime scope and retains its real x86 CPU view. Comparisons, hashes and remaining coverage limits are recorded in `reports/strict-v15-summary.json`.

## Version 0.42 KeyMint backend integration

The isolated Android KeyMint V3 service forwards actual Keystore operations to
the Windows AndroidKeymaster backend through virtio serial and a named pipe.
The supported RSA-2048/PSS/SHA-256 signing profile uses non-exportable Windows
CNG keys; EC, AES, HMAC and other supported software profiles retain their AOSP
factories. Interfaces continue to advertise `SOFTWARE`. The vendor service
label and loaded Enforcing SELinux policy are preserved.

An explicit laboratory-attestation option provides a fresh software issuer,
challenge and application binding, and a public chain. The host verifier pins
the root fingerprint published directly by the backend. Unknown boot state is
omitted rather than asserted. This does not establish Android hardware trust
or a Google-recognized identity. See [nativekeymint](nativekeymint/README.md) for
the runtime, lifetime constraints and control commands.

The [v42 measured comparison](reports/keymint-v42-verified-comparison.json) retains
0/54, 0/79, 0/99 and Reveny 0 with the same APKs and no unavailable checks.
Duck reports TEE danger plus Bootloader and ADB warnings. Its lower boot severity
does not establish verified boot: the new software issuer omits unknown boot
claims. The global zero-detection objective remains unresolved.

## Current boundaries

- No Play Integrity integration or hardware-backed attestation implementation. The independent probe measures the existing software Keystore implementation.
- No sensor-event simulation. The proc views omit selected translation/runtime records; the actual mappings remain present. Only sensor labels change. Magisk mounts are actually removed from successfully prepared scoped namespaces.
- The namespace component replaces selected property areas and provides a private `/proc/cpuinfo` mount. The native runtime depends on successful namespace preparation.
- CPU and property snapshots are ordinary files. Selected CPU descriptor observations are normalized, but their underlying metadata, SELinux labels and mount entries still differ from kernel-backed files. Values in copied property contexts and CPU frequency fields are snapshots rather than live telemetry.
- The CPU reference reproduces the native bridge's generic ARM view, not Tensor G3 hardware. This does not turn the x86 guest kernel or host CPU into ARM hardware. The x86_64 probe still honestly reports x86_64.
- Namespace installation and inherited property remapping were exercised only on this specific Android 14 image. The component depends on Magisk 27's local `resetprop` and public Zygisk API v4.
- Only the pinned laboratory suite was exercised. Two ARM native detectors fail before producing a verdict. ABI property overrides can affect native library selection in other apps.
- The syscall broker covers the measured x86 proc and uname calls. Other proc interfaces, unsupported open flags, inherited descriptors, other syscall ABIs and metadata operations outside the tested adapters remain outside this result. Snapshots reflect open time, rather than following later mapping changes. Root boundary captures still see the original mappings, mounts and x86 kernel. The kernel auxiliary vector is unchanged.
- Directory filtering was measured with a shared descriptor table, ordinary buffers, null-buffer failures, small buffers and rewind. Concurrent mutation of directory offsets, partially writable output buffers, descriptor transfer and other metadata queries on guessed hidden map-file paths are not covered. Mmap adaptation covers the tested read-only private/shared form.
- The ARM helper depends on a validated private libc layout from this image. The uname broker requires seccomp user notification and root access to target process memory; it was exercised on this image's Linux 6.1 kernel only.
- GLES vendor/renderer labels and the driver-description suffix change; the GPU, advertised API version, extensions and rendering implementation do not.
- The native-only backend depends on validated API 34 ART, libc and EGL layouts. Sensor labels use a JNI adapter that preserves original enumeration and events. Neutral graphics-descriptor labels are a scoped observation profile, not new device nodes or physical hardware.
- Filesystem absence is subject to Android visibility and permissions.
- x86 and AOSP sensor checks are heuristics and may produce false positives.
- A framework can change observations independently of this module. Compare an unmodified baseline, a framework-only control and the enabled module.
- Build success, runtime hook success and third-party app compatibility are separate results and must be recorded separately.

## References

- [Xposed load-package API](https://api.xposed.info/reference/de/robv/android/xposed/IXposedHookLoadPackage.html)
- [LSPosed native hook API](https://github.com/LSPosed/LSPosed/wiki/Native-Hook)
- [Android Emulator](https://developer.android.com/studio/run/emulator)
- [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)
- [Android hardware-backed key attestation](https://source.android.com/docs/security/features/keystore/attestation)
- [Linux seccomp user notification and atomic descriptor injection](https://docs.kernel.org/userspace-api/seccomp_filter.html#userspace-notification)
- [Linux proc descriptor information](https://docs.kernel.org/filesystems/proc.html)
- [Linux 6.1 fdinfo implementation](https://github.com/torvalds/linux/blob/v6.1/fs/proc/fd.c)
- [Linux 6.1 ext4 inode allocation](https://github.com/torvalds/linux/blob/v6.1/fs/ext4/ialloc.c)

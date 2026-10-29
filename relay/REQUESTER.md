# Owned-APK requester relay

The requester APK sends explicit laboratory requests to a Windows loopback HTTPS broker. The broker creates a job for the paired Firebase Worker, verifies its response through `RelayHost.psm1`, and returns a bound receipt. Neither APK receives administrator credentials. A verified receipt describes the remote Worker; `requester_integrity_verified` remains false and is not the emulator's integrity verdict.

## Bootstrap and lifecycle

Requirements are PowerShell 7.2+, Node.js, Java/Android build tools, the existing authenticated host setup, and two already running caller-owned Android targets. The commands below use the isolated laboratory targets `emulator-5582` for the Worker and `emulator-5584` for the requester. They do not start emulators or target the pre-existing `emulator-5554`. Confirm those serials belong to the intended lab targets before running them.

Run from the repository root with the existing private Cloud configuration. The configuration must already authorize the host operations; these commands do not enable billing, modify IAM, or provision a physical reservation.

```powershell
.\gradlew.bat :relayworker:assembleDebug :relayrequester:assembleDebug
$cloud = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v36\cloud-config.json'
$worker = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v37\worker-session.json'
$pairRoot = Join-Path $env:LOCALAPPDATA 'android-device-lab\research-v37\requester'
.\scripts\relay-lab.ps1 -Action Pair -ConfigPath $cloud -SessionPath $worker -Serial emulator-5582
.\scripts\relay-requester.ps1 -Action Start -ConfigPath $cloud -WorkerSessionPath $worker -PairRoot $pairRoot -RequesterSerial emulator-5584
.\scripts\relay-requester.ps1 -Action Status -PairRoot $pairRoot
```

Start requires an active, unrevoked Worker session with at least 30 seconds remaining. It creates a fresh private pairing, short-lived TLS certificate/key and random bearer, starts Node on `127.0.0.1`, installs/provisions the requester, creates only its dedicated ADB reverse tunnel, and opens the app. Select Echo or Play Integrity inside the requester. There is no intent-triggered automatic execution. The private `current-pair.json` records process identity and owned transport details for Status/Stop.

Start defaults to `-ExecutionMode persistent`: Node owns one PowerShell service, imports the existing Host logic once, and waits for authenticated-context initialization before listening. Use `-ExecutionMode once` on the same Start command for the preserved per-request runner used in the comparison. There is no automatic fallback between modes. The private configuration pins the SDK account/configuration captured during bootstrap; administrator and scoped decoder tokens remain separate and are cached only in memory.

The persistent transport is private stdin/stdout JSONL, limited to 8 KiB input and 64 KiB output per line. It binds schema, service generation, PID, pair/session, RPC ID, request ID and canonical hash. Only one RPC is active; malformed/truncated output, EOF or deadline failure makes the service unavailable without resending a request or restarting it. New requests receive 503, while known receipts remain readable and identical POSTs remain idempotent. Startup failures expose sanitized codes. Readiness and receipts may include numeric service metrics; they never expose tokens or account details.

The requester trusts only the provisioned certificate and verifies its SHA-256 SPKI pin with normal hostname checking. Its `server_spki_sha256` configuration uses lowercase hex; the broker readiness file exposes the same public digest in standard base64. TLS uses an IP SAN for `127.0.0.1`. No global certificate store, SSL binding, trust-all verifier, SELinux policy, or system image is changed. Private material stays below LOCALAPPDATA and in the owned APK's internal files; do not copy these configurations, bearer values, or keys into repository reports.

Stop the pairing explicitly:

```powershell
.\scripts\relay-requester.ps1 -Action Stop -PairRoot $pairRoot
```

Stop revokes the explicitly bound Worker session, verifies the local broker process identity, kills its process tree with `Kill(true)` and waits for exit, force-stops the requester where reachable, and removes the owned reverse tunnel. It still attempts local termination if cloud revocation fails, and reports that failure instead of claiming successful revocation. Use a dedicated Worker session: Stop also prevents commits from any other client sharing that session. Returning a separately allocated physical reservation is an additional lifecycle action.

The broker observes taskkill status and the retained runner's close event. If termination cannot be confirmed, it records `TERMINATION_UNCONFIRMED`, rejects new work, and retains process ancestry for the bootstrap's explicit stop. It does not claim that an uncertain runner or an already-started Android API call was cancelled.

## API contract

All endpoints require the per-pair bearer in the Authorization header over the pinned TLS connection. There is no CORS or redirect support. The broker accepts at most one active job and 64 persisted receipts per pairing, with bounded request sizes, output, connections, and execution time.

`POST /v1/requests` accepts a flat JSON object of at most 4 KiB with exactly these fields:

| Field | Constraint |
| --- | --- |
| `schema_version` | Integer 1 |
| `request_id` | 32 lowercase hexadecimal characters |
| `operation` | `echo_sha256` or `play_integrity` |
| `challenge_base64url` | Canonical unpadded base64url of exactly 32 random bytes |
| `timeout_ms` | Integer from 30,000 through 120,000 |

The request SHA-256 is computed over UTF-8 fields joined by LF, without a final LF: `r1`, pairing ID, request ID, operation, challenge, and decimal timeout. The broker persists the mapping before invoking the runner and fixes `job_id` to the request ID. The caller cannot select a Worker UID, Firebase session, cloud project, package, or decoder.

A successful POST returns 202, including identical retries while running or after completion. Reusing an ID with a different canonical hash returns 409. Another request while busy also returns 409. Poll the authenticated request-ID resource under `/v1/requests/`; GET returns 200 for a known receipt. Missing/invalid authentication returns 401; unknown resources 404, wrong methods 405, invalid JSON/schema 400, oversized input 413, expired pairing 410, and receipt capacity 429.

Receipts contain `schema_version`, `request_id`, `request_sha256`, `operation`, `challenge_sha256`, `created_at_ms`, `deadline_at_ms`, `state`, `origin`, and `requester_integrity_verified`. States are `accepted`, `running`, `completed`, `failed`, and `expired`; origin is `cooperative_remote_worker`. Completion includes a nested `result` repeating request bindings and origin, with Worker package/version/certificate digest, job ID/attempt, operation-specific bindings/verdict, and optional timing metrics. Failures use a sanitized error code. Raw Integrity tokens are never returned to the requester or logged by Node.

For Integrity, all three `request_binding` values must be true: `package_matches`, `nonce_bytes_match`, and `timestamp_in_window`. The app preserves the Host's snake_case `worker_verdict`, including an empty `device_integrity` object. An empty verdict is not physical recognition, and successful decode/request binding does not mean that an integrity policy approved the requester.

The original receipt deadline is authoritative through `DeadlineAtMs`; startup and OAuth work do not extend it. Runner seconds use ceiling with the Host's minimum duration while the absolute deadline still clamps the job. Worker leases and server timestamps follow [PROTOCOL.md](PROTOCOL.md). Delivery is at least once. CAS and cached receipts prevent duplicate submission effects at this boundary, not exactly-once remote API execution. On broker restart, unfinished persisted requests fail as `BROKER_RESTARTED` and are not reissued. Host cleanup verifies job ownership/hash and ETag, then conditionally deletes inbox before execution; it does not delete a colliding or ambiguously owned job.

## Measured v0.37 evidence

The final requester APK SHA-256 is `4ad843aca3156d555ce9c3934153c34495bc567144159cffc7faab798f2dd307`; the unchanged clock-fixed Worker is `af02d68a3b09eb6bd3aa7292116f24e26533cf7055b785eb127a06886eea0d9f`. Installed hashes are recorded in `reports/relay-v37-emulator-apks.json`.

- `relay-v37-broker-tests.json`: 12/12 live HTTPS API checks passed, including authentication, schema/size rejection, 30-second Echo completion, idempotent retry/conflict, and cached completion.
- The actual Host ownership-cleanup function passed four checks with mocked transport. This validates local branch behavior, not a live ambiguous cloud-write failure. Two read-only Codex CLI audits completed, and their actionable findings were addressed.
- `relay-v37-requester-final-echo1.json`: verified client Echo in 6,348 ms, broker observation 1,920 ms. `relay-v37-requester-final-integrity1.json`: verified remote result in 10,954 ms client / 3,227 ms broker, all request bindings true, Worker `device_integrity` empty.
- `relay-v37-requester-pin-test.json`: expected `TLS_REJECTED`, unchanged receipt count 4 to 4, and exact restored configuration hash. The successful post-restoration Echo is `relay-v37-requester-after-pin-final-echo.json`, 8,244 ms client / 3,804 ms broker. Negative-result reports preserve the expected verification failure. Restoration attempts 1 and 2 failed because of Windows text-transfer/line-ending behavior and remain separate failed artifacts. The final restoration used base64 ASCII stdin, private Android decoding, and exact SHA-256 comparison; it did not weaken TLS.

These are requester-to-emulator-Worker measurements. A new physical reservation failed with `RESOURCE_EXHAUSTED` / insufficient device quota (`relay-v37-physical-unavailable.json`). The entire new requester-to-physical-Worker path is therefore unverified. The v36 physical Worker's `MEETS_DEVICE_INTEGRITY` observation remains historical evidence for that earlier Worker-only path, not a fresh v37 requester result.

Both v37 Worker sessions are confirmed revoked in `relay-v37-session-cleanup.json`, and the device CLI listed no reservations. Final ADB inventory confirms the owned port-5582/5584 instances stopped and the pre-existing port-5554 emulator still connected. The broker process is stopped and billing remains disabled on the original project. The unchanged Rules retain the v36 49-pass evidence; that suite and the older detector suites were not rerun in v37.

## Remaining limits

Client latency remains multi-second; continuous low-latency service and permanent free phone availability are not established. Full transparent handling of another APK, local sensor fidelity, SMS/cellular operations, and hardware-signing delegation remain incomplete. Requester result verification does not alter the emulator's identity or satisfy its own Play Integrity request. No zero-detection outcome or new detector-suite score is claimed. Bootloader/TEE is the next requested focus after this latency comparison.

## Measured v0.38 latency comparison

`reports/relay-v38-comparison.json` compares sequential emulator controls with two samples per operation per mode: eight verified results, all with confirmed job cleanup. Requester and Worker APKs retain the v0.37 hashes above; no APK source or runtime-hardening changes were part of this round.

| Operation | Once mean client time | Persistent mean client time | Observed reduction |
| --- | --- | --- | --- |
| Echo | 9,302 ms | 3,546 ms | 61.9% |
| Play Integrity | 16,051 ms | 7,245 ms | 54.9% |

These small sequential samples describe the observed runs, not a latency guarantee or isolated proof of one cause. Persistent initialization took 1,862 ms; total pairing took 13,530 ms versus 10,954 ms for once mode, so cold cost is recorded separately. Persistent PowerShell PID 27024 handled four jobs, with one source fetch, one introspection, one decoder exchange, 48 cache hits and two misses. Cache counters are cumulative; Host `http_requests` describes the last job. Timing categories overlap and must not be summed.

Nine pure cache checks, 19 pure IPC checks and the earlier four mocked-transport ownership checks passed. The persistent live HTTPS API helper passed 12/12 checks (`relay-v38-broker-tests.json`). The idle-service failure control passed `IDLE_SERVICE_FAILURE_CONTAINED`: an existing receipt remained unchanged, a new POST returned 503 without creating a record or respawning the service, and the parent remained alive (`relay-v38-service-lifecycle.json`). This is an idle-failure control, not an in-flight cancellation test.

All three v38 Worker sessions are confirmed revoked in `relay-v38-session-cleanup.json`; explicit Stop completed, and termination commands for the owned port-5582/5584 emulators completed. The validation manifest is `relay-v38-validation.json`. No physical rerun was available because of quota; v36/v37 evidence retains its original scope. Rules and the 54/79/99 detector suites/Reveny were not rerun in this round.

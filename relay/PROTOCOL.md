# Laboratory relay protocol v1

This relay coordinates explicit operations between APKs and a backend controlled by the laboratory. A result describes the worker APK and its execution on the worker device. It does not attest an emulator, change another application's environment, intercept third-party calls, or transfer the worker device's identity to another device. The `play_integrity` operation requests a token for the worker APK itself; the backend must verify that token for the expected package and request before accepting it.

## Trust and authorization

The host broker uses its own authorized OAuth/admin access to create sessions and immutable inbox jobs. Admin access bypasses Realtime Database Rules, including validation rules; the broker must enforce this document's schemas, hashes, deadlines, package expectations, and payload limits before writing. Admin credentials never enter either APK or a database record.

A worker signs into Firebase Authentication with a broker-issued custom token. Its UID is the designated worker UID. Required custom claims are `role: "worker"`, `session_id`, and numeric `session_expires_at_ms`. Firebase ID-token refresh does not extend the laboratory session deadline. The broker must not issue a token with a deadline beyond the session record.

Session IDs, job IDs, and broker-generated worker UIDs contain 1-128 ASCII letters, digits, underscores, or hyphens. The rules deny all access by default. A worker can read only its current session inbox and individual job executions. It cannot write sessions or inbox jobs, read another UID/session, delete an execution, or change a terminal execution.

Every worker execution read/write requires matching authenticated UID and session claim, `role == "worker"`, unexpired claim and backend session, `revoked == false`, and an unexpired inbox job. Authorization depends on the authenticated UID, not a client-provided `worker_uid`. The backend session is checked on every request; expiration in a JWT alone is insufficient.

## Authentication and HTTP implementation

The custom-token exchange response from `accounts:signInWithCustomToken` supplies `idToken`, `refreshToken`, `expiresIn`, and `isNewUser`; it does not supply `localId`. Both the worker and Rules test helper confirm the signed-in identity with `POST accounts:lookup?key=API_KEY`, passing the ID token in the JSON body and requiring exactly one `users` entry whose `localId` matches the configured worker UID. They discard unrelated account information. The worker does not retain or use the refresh token.

Google administration calls authenticated with the host OAuth `Authorization` header use `x-goog-user-project`. Firebase client Authentication calls using the API key and token body omit that quota header and do not attach the administrator's OAuth header. An observed control returned `USER_PROJECT_DENIED` with the quota header and the normal authentication error without it; the header must not be applied indiscriminately to client Authentication requests.

The Play Integrity decoder uses an impersonated service-account access token scoped to `https://www.googleapis.com/auth/playintegrity`, as implemented in `scripts/decode-play-integrity.ps1`. Its decode request carries that token in `Authorization` and omits `x-goog-user-project`. This is separate from the host administration client's quota-header convention.

The REST Rules test helper reads ETag values through `HttpResponseMessage.Headers.NonValidated`. Firebase can return the unquoted `null_etag` sentinel, which a typed ETag parser can discard. Preserve the server's raw ETag value for `If-Match`; use the literal unquoted `null_etag` sentinel for create-if-absent fixtures. A missing parsed ETag is not evidence that Firebase omitted the header.

## Database layout

- `relay/v1/sessions/{session_id}`: `worker_uid` (string), `expires_at_ms` (integer Unix milliseconds), `revoked` (boolean, initially false).
- `relay/v1/inboxes/{worker_uid}/{session_id}/{job_id}`: a broker-created job.
- `relay/v1/executions/{worker_uid}/{session_id}/{job_id}`: a worker-owned lease or terminal result.

The worker reads its session inbox, checks each job deadline locally, and claims work through the execution path. Inbox visibility does not mean a job is still executable: individual jobs can expire while the session remains active. The broker and worker must reject unsupported schema versions and operations.

## Job schema

All fields are required. The broker rejects extra fields.

| Field | Type and constraint |
| --- | --- |
| `schema_version` | Integer, exactly 1 |
| `job_id` | Valid job ID, equal to its path component |
| `session_id` | Valid session ID, equal to its path component |
| `worker_uid` | Valid worker UID, equal to its path component and session owner |
| `operation` | `echo_sha256` or `play_integrity` |
| `challenge_base64url` | Exactly 32 random bytes encoded as 43 unpadded base64url characters |
| `cloud_project_number` | Positive JSON integer from 1 through 9,007,199,254,740,991 |
| `created_at_ms` | Integer Unix milliseconds, not in the future when the worker claims it |
| `expires_at_ms` | Integer Unix milliseconds, greater than creation and no later than the session deadline |
| `request_sha256` | Lowercase hexadecimal SHA-256, exactly 64 characters |

Project numbers and timestamps are JSON integers, not strings or floating-point values. Both operations carry this field. The broker chooses its configured project number; the worker does not accept a project selected by an unauthenticated party.

`request_sha256` is SHA-256 over the UTF-8 encoding of the following concatenation, with literal LF characters and no trailing LF:

```text
"v1\n" + session_id + "\n" + worker_uid + "\n" + job_id + "\n" + operation + "\n" + challenge_base64url + "\n" + decimal(cloud_project_number) + "\n" + decimal(created_at_ms) + "\n" + decimal(expires_at_ms)
```

Project numbers and integer timestamps use plain base-10 digits, without exponent notation, grouping, fractions, or leading plus signs. The broker and worker independently recompute this digest. They decode the challenge, require exactly 32 bytes, and require canonical base64url re-encoding to equal the supplied string. Rules enforce the alphabet and length but cannot validate canonical pad bits or calculate SHA-256.

## Lease and state machine

Every execution has these required fields:

| Field | Constraint |
| --- | --- |
| `state` | `leased`, `completed`, or `failed` |
| `job_id`, `session_id`, `worker_uid`, `operation`, `request_sha256` | Exact match to the inbox job; immutable after creation |
| `lease_id` | Fresh random 16-byte identifier encoded as 32 lowercase hexadecimal characters |
| `lease_until_ms` | Integer future deadline, at most 120,000 ms from database server `now`, and no later than the job, session, or claim deadlines |
| `attempt` | Integer from 1 through 2,147,483,647 |
| `started_at_ms` | Integer Unix milliseconds for the current attempt, before the lease deadline and no earlier than job creation |

Claim the execution with a Realtime Database transaction or an HTTP ETag/`If-Match` compare-and-set against the entire execution record. The transaction must produce one of these transitions:

1. Absent -> `leased`: attempt 1 and a fresh lease ID.
2. Expired `leased` -> `leased`: previous attempt + 1, a different lease ID, and a new start timestamp no earlier than the previous start. Reclaim start time must be within 30 seconds of server `now`.
3. Active `leased` -> `leased`: same lease ID, attempt, and start timestamp; extend or retain the deadline within all limits. Renewal is optional.
4. Active `leased` -> `completed` or `failed`: same lease ID, deadline, attempt, start timestamp, and job identity. Commit before the lease and all authorization deadlines expire.

New claims also require a start timestamp within 30 seconds of server `now`. Renewals preserve the attempt's original start. The worker uses server timestamp sentinels for new starts and completions, and an HTTPS Date-based monotonic estimate for lease/deadline decisions; it does not substitute the device wall clock for these values. Rules allow completion timestamps up to 30 seconds ahead and 120 seconds behind server time, but never before the attempt started.

A leased record contains neither `result` nor `error`. A completed record contains `result` only. A failed record contains `error` only. Rules reject arbitrary fields at the execution, result, and error levels. Workers cannot delete or reopen terminal records. A failed operation is terminal for that job; a deliberate retry requires a new broker job ID.

Transactions can rerun their update callbacks. Do not invoke Android APIs, request an integrity token, send a network operation, or perform another side effect inside the transaction callback. Execute only after the lease has committed. A client that loses its lease must discard its completion attempt; it cannot publish under another lease ID.

## Clock compatibility design and regression cases

The clock fix is implemented and has been exercised in live Rules tests and new same-APK physical/emulator runs. It keeps the existing Rules unchanged: a start before job creation is invalid, all authorization deadlines still apply, and a lease remains bounded by 120 seconds of database server time.

The worker writes the Realtime Database server-value sentinel `{ ".sv": "timestamp" }` for a new attempt's `started_at_ms` and a successful result's `completed_at_ms`. Firebase resolves these values before Rules validation. After a successful lease PUT, the worker must parse the numeric start timestamp returned by Firebase and retain that resolved lease for CAS completion and renewal. It must not keep or resubmit the unresolved sentinel as an immutable lease start. Result duration remains measured with a monotonic clock, independently of wall-clock timestamps.

The lease duration is 90 seconds, estimated from the authenticated HTTPS response's Date header rather than the device wall clock, leaving margin below the Rules maximum of 120 seconds. HTTP Date has one-second granularity and network delay; it is an estimate, not a time oracle. Bound the deadline by the job, session, and claim expirations, refresh the estimate when needed, and fail explicitly when a trustworthy estimate is unavailable. This does not establish that clock differences caused all previous failures.

`scripts/test-relay-rules.ps1` now includes live REST cases for a naive start at `created_at_ms - 1500` being denied, an excessive future lease being denied, a server-value lease being accepted with a numeric start in the successful response, and a server-value completion being accepted with a numeric completion timestamp. It also preserves expired-job, expired-claim, revoked-session, and prior CAS/terminal controls. The current live report contains 49 passing records, including the clock cases and four cleanup-order regression records: delete an individual job inbox first, delete its execution second, deny a fresh worker lease for the same now-missing job, and confirm by admin read that the execution remains absent. These four cases test prevention of result recreation after inbox removal, not terminal immutability. Earlier 36-record pre-clock and 45-record pre-cleanup-order reports remain separate historical evidence. The negative case demonstrates rejection of a start before job creation; the positive cases demonstrate server resolution and acceptance without weakening Rules. This controlled reproduction does not prove that the specific earlier timeout had the same cause.

Both measured phases below retain their own same-APK hashes and report prefixes. The pre-clock-fix baseline uses the original physical and final-control prefixes; the clock-fixed phase uses the physical-clock and control-clock prefixes. Measurements are not transferred between APKs or report phases.

## Completed result

The common required fields in `result` are:

- `worker_package`: Android package name, at most 255 characters, composed of at least two dot-separated identifiers beginning with letters.
- `worker_version_code`: positive integer no greater than 9,007,199,254,740,991, the exact JSON integer range used by this protocol.
- `worker_apk_cert_sha256`: lowercase hexadecimal SHA-256 of the worker signing certificate's DER bytes.
- `execution_elapsed_ms`: nonnegative integer measured with a monotonic clock. Rules bound it by server time since the attempt start plus the 30-second skew allowance.
- `completed_at_ms`: integer Unix milliseconds following the timestamp constraints above.

For `echo_sha256`, the only additional field is `challenge_sha256`, the lowercase hexadecimal SHA-256 of the decoded 32-byte challenge.

For `play_integrity`, the only additional fields are `token`, `token_sha256`, `token_length`, and `nonce_base64url`. `nonce_base64url` equals the job's `challenge_base64url`; this operation uses the Play Integrity request variant that accepts a nonce. A future Standard Integrity request requires a separate protocol revision with explicit request-hash semantics rather than silently treating a nonce as a Standard request hash.

The token is a nonempty ASCII string of at most 32,768 characters, limited to letters, digits, underscore, plus, dot, equals, colon, slash, and hyphen. This accommodates base64/base64url and dot-separated opaque token encodings without arbitrary text. `token_length` equals its character count. `token_sha256` is lowercase hexadecimal SHA-256 of its UTF-8 bytes. This is an explicit token-size ceiling for this laboratory; oversize responses must become failed executions. Rules cap individual fields and deny unknown fields, keeping an accepted execution below 40 KiB of compact UTF-8 JSON when the broker and worker emit ordinary ASCII package/token data. The broker additionally rejects any execution exceeding 64 KiB of UTF-8 JSON; Rules do not implement an exact serialized-byte counter.

The broker verifies the digest and schema, decodes/verifies integrity responses through the configured service, and checks package, signing certificate, nonce, timestamp, and verdict against the worker APK's expectations. Worker-provided package/certificate/hash metadata alone is not trusted evidence. Preserve the result as a worker execution; never label it as an integrity result for the emulator or another package.

## Failed result

A failed execution has `error.code` and `error.message`. `code` contains 1-64 uppercase ASCII letters, digits, or underscores and starts with a letter. `message` is a nonempty string of at most 1,024 characters. Optional `error.error_code` is a signed 32-bit integer from the platform/API. No other error fields are accepted. Report actual platform failures without fabricating success or manufacturing a token. Do not include credentials or full tokens in error messages.

## Delivery, cancellation, and cleanup

Delivery is at least once. Inbox notifications, reconnects, transaction retries, and lease expiry can produce repeated attempts. CAS protects record ownership and terminal commits; it does not guarantee exactly-once external execution. A worker may complete an Android operation and lose connectivity before publishing, allowing a later attempt to repeat the operation. The broker deduplicates accepted results by session ID and job ID and must design any downstream side effect to be idempotent.

STOP means the broker sets the session's `revoked` flag to true, stops issuing jobs/tokens, and stops accepting results for that session. The worker closes the session on SSE `cancel`/`auth_revoked`, root-inbox authorization denial, sign-out, session expiration, or explicit local Stop. An expired individual job is rejected without being counted as completed. Revocation prevents subsequent database commits even if a previously issued Firebase ID token remains valid. It cannot undo an Android API call already started, retract a result already read, or guarantee immediate cancellation of an offline operation.

An execution-level HTTP 401/403 is classified separately from session authorization. The worker checks read access to the parent session inbox. If that check returns 200, it records `JOB_AUTHORIZATION_REJECTED` for the individual job rather than closing an otherwise authorized session. A parent-inbox 401/403 closes the session. Other parent-check failures are recorded as `AUTH_CHECK_UNAVAILABLE`; a failed check does not prove revocation. These checks do not override Rules or turn a rejected terminal write into success.

The worker remembers terminal job IDs in a bounded FIFO set of 4,096 entries and skips them on subsequent poll/SSE notifications. Eviction or process restart can cause another terminal-record read, so this cache is an optimization rather than an exactly-once guarantee. SSE frames whose `data` is JSON null are skipped rather than enqueued as jobs.

For safe local diagnostics, `worker-failure.json` contains only `code`, HTTP `status`, `method`, `scope`, and millisecond `timestamp`. It never includes a URL, API key, ID token, custom token, integrity token, raw response body, or request body. The file records the latest diagnostic and does not by itself establish a causal chain for an earlier failure.

The worker checks cancellation/deadlines before claiming, before executing, and before publishing. It does not extend backend sessions. Expired or revoked work is never counted as a successful result. The broker may read and archive records through admin access and remove expired sessions/jobs/executions according to its retention policy. Removing records through admin access is a broker action, not a worker permission.

A remote physical-device reservation is separate from a relay session. Do not reserve a phone until the APK and backend are ready. Confirm catalog eligibility, remaining quota, reservation expiry, network access, and any required permissions before the laboratory run. Physical hardware does not imply an active SIM, SMS service, or cellular subscription; verify those independently when a test actually needs them.

## Rules verification

`database.rules.json` is the deployable Rules document. The live REST verification in `reports/relay-v36-rules-tests.json` records 49 passing checks/fixture-cleanup records and no failures. The helper first compares canonical parsed local and deployed Rules JSON, then exercises authorization, inbox/session immutability, lease acquisition, stale-ETag rejection, valid renewal, rejected identity/hash/lease completions, job expiry, lease bounds, matching terminal completion, and terminal immutability. These are explicitly synthetic protocol/Rules fixtures, not APK executions or attestations. The helper cleans up only its own database paths and positively identified newly created Auth users; the final 49-record run confirmed their removal. Host cleanup removes inbox jobs before executions, preventing a restarted worker from recreating an execution after its job is gone.

This result does not cover every possible Rules state or replace future regression checks. Preserve negative tests for wrong role/session, revocation, malformed or arbitrary fields, expired deadlines, reclaim behavior, deletes, and lost-CAS writes when changing the implementation. A JSON parse alone does not validate Rules semantics. This document does not authorize a deployment or device reservation.

## Observed laboratory state

Both phases used `dev.androidlab.relayworker`, version code 1. Within each phase, the physical and emulator controls ran identical APK bytes. Their results remain worker-specific; `requester_integrity_verified` is false.

| Phase | Same-APK SHA-256 | Evidence |
| --- | --- | --- |
| Pre-clock-fix baseline | `fd74ca1a1f897da21dd35cedd20a963abb0d97105c38640a73f887bd3437217d` | Corrected `reports/relay-v36-comparison.json`, physical reports and `control-final` reports |
| Clock-fixed rerun | `af02d68a3b09eb6bd3aa7292116f24e26533cf7055b785eb127a06886eea0d9f` | `reports/relay-v36-clock-comparison.json`, `physical-clock` and `control-clock` reports |

The baseline physical run produced six verified echo completions at 1,291-3,171 ms broker-observed time, median 1,331 ms. Its decoded Integrity result took 3,496 ms broker-observed and 963 ms worker execution, with `MEETS_DEVICE_INTEGRITY`, `UNRECOGNIZED_VERSION` app recognition, and `UNEVALUATED` licensing. The baseline final-control echo took 3,292 ms, and its decoded Integrity result took 20,482 ms broker-observed and 1,246 ms worker execution, with no device-recognition labels and app/licensing `UNEVALUATED`. The corrected aggregate baseline references `relay-v36-control-final-integrity.json`, rather than the older `control-integrity4` result.

The clock-fixed physical control again used Samsung SM-S938U1, API 35, ARM64. Three echo jobs completed with verified challenge digests: minimum 752 ms, median 1,306 ms, maximum and nearest-rank p95 1,343 ms. Its decoded Integrity job took 4,033 ms broker-observed and 665 ms worker execution. Package, nonce bytes, timestamp window, and worker signing certificate were verified. The device verdict contained `MEETS_DEVICE_INTEGRITY`; app recognition remained `UNRECOGNIZED_VERSION`, licensing `UNEVALUATED`, and version code 1. No strong-integrity verdict or Play-recognized worker version is established.

The identical clock-fixed APK on the emulator completed five verified echo jobs: minimum 1,970 ms, median 3,299 ms, maximum and nearest-rank p95 4,516 ms. Two decoded Integrity jobs took 6,042/3,297 ms broker-observed and 3,364/921 ms worker execution. Both matched package, nonce bytes, and the configured timestamp window; neither contained a device-recognition label. Empty verdicts are preserved as empty and are not physical-device recognition.

Broker times measure the host's monotonic interval from inbox PUT through terminal observation, excluding CLI/OAuth startup and Google server decode. Worker durations use a separate monotonic clock. Small sample sizes and observed multi-second transport times do not establish continuous or guaranteed low-latency relay service.

`reports/relay-v36-validation.json` records a passing APK build, lint with zero errors and eight warnings, 49 passing Rules records, and source hashes. The clock tests demonstrate a real timestamp-compatibility failure mode and the server-timestamp remedy. Earlier failed or timed-out requests remain failures. A coarse -1,415 ms VM/host observation with 1,000 ms quantization uncertainty and the earlier authorization-stopped screenshot do not fully establish the cause of that particular incident.

`reports/relay-v36-session-cleanup.json` confirms all six relay sessions revoked. Both physical reservations were returned, and the CLI listed no remaining reservations. The owned emulator on port 5582 was stopped; the pre-existing emulator on port 5554 was left untouched. The final billing-enabled state was false. `reports/relay-v36-image-preservation.json` confirms that the preserved v32 system partition's rehashed range matches the expected digest.

## Remaining objective audit

The cooperative owned-APK/backend relay is implemented and measured. Requester integration and transparent handling of another application's calls are absent. Hardware-backed signing delegation and SMS/telephony operations are not implemented; loaded SIM state alone does not verify service. No new local sensor simulation or environment-hardening work was completed in v36. Existing Google Play emulator detector results remain nonzero; the 54/79/99 suites and Reveny were not rerun here. Permanent free availability of physical phones is not established. These results do not make an emulator indistinguishable from a physical device or achieve zero detections.

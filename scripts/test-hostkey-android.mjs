import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, verify, constants } from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const serial = process.argv[2] ?? 'emulator-5584';
if (serial !== 'emulator-5584') throw new Error('DEDICATED_REQUESTER_SERIAL_REQUIRED');
const adb = path.join(process.env.LOCALAPPDATA, 'Android', 'Sdk', 'platform-tools', 'adb.exe');
const pkg = 'dev.androidlab.hostkeyprobe';
const reportPath = path.join(root, 'reports', 'boottee-v40-android-controls.json');
const rows = [];
let currentChallenge = null;
let currentSubjectSpkiHash = null;
const sha = value => createHash('sha256').update(value).digest('hex');
const assert = (condition, code) => { if (!condition) throw new Error(code); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const clone = object => JSON.parse(JSON.stringify(object));

function execute(command, args, input, acceptedCodes = [0], timeout = 20000) {
  const child = spawnSync(command, args, { input, encoding: 'utf8', timeout, maxBuffer: 131072, windowsHide: true, shell: false });
  assert(!child.error && !child.signal && acceptedCodes.includes(child.status), 'CHILD_PROCESS_FAILED');
  assert(Buffer.byteLength(child.stdout ?? '') <= 65536, 'CHILD_OUTPUT_LIMIT');
  return { text: child.stdout ?? '', exit: child.status };
}
function device(args, input) { return execute(adb, ['-s', serial, ...args], input).text; }
function readPrivate(name) { return JSON.parse(device(['exec-out', 'run-as', pkg, 'cat', `files/${name}`])); }
function writePrivate(name, text) {
  assert(['response.json', 'challenge.json'].includes(name), 'PRIVATE_FILE_NAME');
  const payload = Buffer.from(text, 'utf8').toString('base64');
  // ASCII stdin prevents Windows text conversions; decoded bytes remain in this app's private directory.
  device(['shell', '-T', 'run-as', pkg, 'sh', '-c', `'base64 -d > files/${name}'`], payload);
}
function vbs(request, acceptedCodes = [0]) {
  const result = execute('pwsh', ['-NoLogo', '-NoProfile', '-File', path.join(root, 'scripts', 'vbs-key-operation.ps1')], JSON.stringify(request), acceptedCodes);
  return { value: JSON.parse(result.text), exit: result.exit };
}
async function tap(label) {
  const ui = '/data/local/tmp/hostkey-v40-ui.xml';
  device(['shell', 'uiautomator', 'dump', ui]);
  const xml = device(['exec-out', 'cat', ui]);
  const matches = [...xml.matchAll(/<node\b[^>]*>/g)].map(match => match[0]).filter(node =>
    node.includes(`package="${pkg}"`) && node.includes('clickable="true"') && node.includes('enabled="true"') &&
    (node.includes(`text="${label.toUpperCase()}"`) || node.includes(`text="${label}"`)));
  assert(matches.length === 1, 'UNIQUE_ENABLED_BUTTON_REQUIRED');
  const bounds = matches[0].match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
  assert(bounds && Number(bounds[3]) > Number(bounds[1]) && Number(bounds[4]) > Number(bounds[2]), 'BUTTON_BOUNDS');
  device(['shell', 'input', 'tap', String(Math.floor((Number(bounds[1]) + Number(bounds[3])) / 2)),
    String(Math.floor((Number(bounds[2]) + Number(bounds[4])) / 2))]);
  await sleep(120);
}
async function challenge() {
  const previous = (() => { try { return readPrivate('challenge.json').request_id; } catch { return null; } })();
  await tap('New challenge');
  const current = readPrivate('challenge.json');
  assert(current.schema_version === 1 && /^[a-f0-9]{32}$/.test(current.request_id) && current.request_id !== previous && current.consumed === false, 'FRESH_CHALLENGE_REQUIRED');
  const canonical = ['android-device-lab-hostkey-v1', current.request_id, current.nonce_base64url, pkg, String(current.expires_at_ms)].join('\n');
  assert(current.payload_utf8 === canonical && Buffer.from(current.nonce_base64url, 'base64url').length === 32, 'ANDROID_CHALLENGE_BINDING');
  currentChallenge = current;
  return current;
}
async function androidCase(name, responseText, expectedState, expectedError) {
  let previous = null;
  try { previous = readPrivate('result.json').attempt_id; } catch { }
  writePrivate('response.json', responseText);
  await tap('Verify response');
  const result = readPrivate('result.json');
  assert(/^[a-f0-9]{32}$/.test(result.attempt_id) && result.attempt_id !== previous && result.request_id === currentChallenge.request_id
    && result.verification_state === expectedState, `${name.toUpperCase()}_OUTCOME`);
  assert(result.external_root_authenticated === false && result.android_tee_verified === false && result.google_attestation_verified === false
    && result.android_verified_windows_claims === false && result.origin === 'untrusted_host_key_response', 'HONEST_TRUST_SCOPE_REQUIRED');
  if (expectedError) assert(result.error_code === expectedError, `${name.toUpperCase()}_ERROR`);
  if (expectedState === 'verified_untrusted_host_signature') {
    assert(['signature_verified', 'nonce_matches', 'public_blob_matches_spki', 'challenge_consumed'].every(field => result[field] === true), 'ANDROID_POSITIVE_FLAGS');
    assert(result.payload_sha256 === sha(Buffer.from(currentChallenge.payload_utf8, 'utf8'))
      && result.subject_spki_sha256 === currentSubjectSpkiHash && readPrivate('challenge.json').consumed === true, 'ANDROID_POSITIVE_BINDING');
  }
  const item = { name, passed: true, expected_state: expectedState, result };
  rows.push(item);
  process.stdout.write(JSON.stringify({ name, passed: true, error_code: result.error_code ?? null }) + '\n');
  return result;
}
function changedBase64(value) { const bytes = Buffer.from(value, 'base64url'); bytes[bytes.length - 1] ^= 1; return bytes.toString('base64url'); }
function publicBinding(response) {
  const blob = Buffer.from(response.subject_public_blob_base64url, 'base64url');
  assert(blob.length >= 24 && blob.readUInt32LE(0) === 0x31415352 && blob.readUInt32LE(4) === 2048, 'NATIVE_PUBLIC_BLOB');
  const exponent = blob.readUInt32LE(8), modulus = blob.readUInt32LE(12);
  assert(exponent >= 1 && exponent <= 8 && modulus === 256 && blob.readUInt32LE(16) === 0 && blob.readUInt32LE(20) === 0 && blob.length === 24 + exponent + modulus, 'NATIVE_PUBLIC_BLOB_SIZE');
  const key = createPublicKey({ key: Buffer.from(response.subject_spki_base64url, 'base64url'), format: 'der', type: 'spki' });
  const jwk = key.export({ format: 'jwk' });
  assert(Buffer.from(jwk.e, 'base64url').equals(blob.subarray(24, 24 + exponent))
    && Buffer.from(jwk.n, 'base64url').equals(blob.subarray(24 + exponent)), 'NATIVE_SPKI_BINDING');
  return key;
}

let failure = null;
let nativeClaimsVerified = false;
let privateArtifactsCleared = false;
let ownedPackageInstalled = false;
try {
  const avd = device(['emu', 'avd', 'name']).split(/\r?\n/)[0].trim();
  assert(avd === 'device-lab-requester-v37', 'DEDICATED_REQUESTER_AVD_REQUIRED');
  assert(device(['shell', 'getprop', 'sys.boot_completed']).trim() === '1', 'ANDROID_BOOT_REQUIRED');
  device(['install', '-r', path.join(root, 'hostkeyprobe', 'build', 'outputs', 'apk', 'debug', 'hostkeyprobe-debug.apk')]);
  ownedPackageInstalled = true;
  device(['shell', 'am', 'force-stop', pkg]);
  device(['shell', 'am', 'start', '-n', `${pkg}/.MainActivity`]);
  await sleep(500);
  const first = await challenge();
  const creation = vbs({ schema_version: 1, operation: 'create_response', nonce_base64url: first.nonce_base64url, payload_utf8: first.payload_utf8 }).value;
  assert(creation.status === 'completed' && creation.cleanup_succeeded === true && creation.external_root_authenticated === false && creation.android_tee_verified === false, 'WINDOWS_CREATION_REQUIRED');
  const response = creation.response;
  const second = vbs({ schema_version: 1, operation: 'verify_response', nonce_base64url: first.nonce_base64url, payload_utf8: first.payload_utf8, response }).value;
  assert(second.valid === true && second.native_root_valid === true && second.native_identity_valid === true && second.nonce_valid === true
    && second.payload_valid === true && second.spki_matches_public_blob === true && second.signature_valid === true && second.cleanup_succeeded === true, 'INDEPENDENT_NATIVE_VERIFIER_REQUIRED');
  nativeClaimsVerified = true;
  const key = publicBinding(response);
  currentSubjectSpkiHash = sha(Buffer.from(response.subject_spki_base64url, 'base64url'));
  assert(verify('sha256', Buffer.from(first.payload_utf8, 'utf8'), { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(response.signature_base64url, 'base64url')), 'INDEPENDENT_NODE_SIGNATURE_REQUIRED');
  rows.push({ name: 'separate_process_native_and_node_verification', passed: true, native: second,
    request_id: first.request_id, subject_spki_sha256: sha(Buffer.from(response.subject_spki_base64url, 'base64url')) });
  const text = JSON.stringify(response);
  let modified = clone(response);
  modified.signature_base64url = changedBase64(modified.signature_base64url);
  await androidCase('signature_tampered', JSON.stringify(modified), 'rejected', 'SIGNATURE_INVALID');
  modified = clone(response); modified.subject_public_blob_base64url = changedBase64(modified.subject_public_blob_base64url);
  await androidCase('public_blob_tampered', JSON.stringify(modified), 'rejected', 'PUBLIC_KEY_BINDING');
  modified = clone(response); modified.nonce_base64url = changedBase64(modified.nonce_base64url);
  await androidCase('nonce_tampered', JSON.stringify(modified), 'rejected', 'NONCE_MISMATCH');
  modified = clone(response); modified.payload_sha256 = '0'.repeat(64);
  await androidCase('payload_hash_tampered', JSON.stringify(modified), 'rejected', 'PAYLOAD_MISMATCH');
  await androidCase('duplicate_field', text.replace('{', '{"salt_length":32,'), 'rejected', 'DUPLICATE_FIELD');
  await androidCase('fractional_schema', text.replace('"schema_version":1', '"schema_version":1.5'), 'rejected', 'JSON_INTEGER_FORMAT');
  await androidCase('string_schema', text.replace('"schema_version":1', '"schema_version":"1"'), 'rejected', 'RESPONSE_FIELD_TYPE');
  await androidCase('wrapped_schema', text.replace('"schema_version":1', '"schema_version":4294967297'), 'rejected', 'RESPONSE_SCHEMA');
  await androidCase('wrapped_salt', text.replace('"salt_length":32', '"salt_length":4294967328'), 'rejected', 'SIGNATURE_ALGORITHM');
  // Android's streaming reader rejects a second document while peeking for EOF.
  await androidCase('trailing_document', text + '{}', 'rejected', 'LOCAL_VERIFICATION_FAILED');
  await androidCase('valid_host_signature', text, 'verified_untrusted_host_signature');
  await androidCase('same_challenge_replay', text, 'rejected', 'CHALLENGE_CONSUMED');
  device(['shell', 'am', 'force-stop', pkg]);
  device(['shell', 'am', 'start', '-n', `${pkg}/.MainActivity`]);
  await sleep(500);
  await androidCase('replay_after_process_restart', text, 'rejected', 'CHALLENGE_CONSUMED');
  const fresh = await challenge();
  assert(fresh.request_id !== first.request_id && fresh.nonce_base64url !== first.nonce_base64url, 'DISTINCT_CHALLENGES_REQUIRED');
  await androidCase('prior_challenge_replay', text, 'rejected', 'NONCE_MISMATCH');
  const expired = { ...fresh, elapsed_created_ms: fresh.elapsed_created_ms - 120001, created_at_ms: fresh.created_at_ms - 120001 };
  writePrivate('challenge.json', JSON.stringify(expired));
  await androidCase('expired_challenge', text, 'rejected', 'CHALLENGE_EXPIRED');
} catch (error) {
  failure = /^[A-Z0-9_]{1,100}$/.test(error.message ?? '') ? error.message : 'HOSTKEY_ANDROID_TEST_FAILED';
  process.stderr.write(failure + '\n');
} finally {
  if (ownedPackageInstalled) {
    try { device(['shell', 'am', 'force-stop', pkg]); } catch { }
    try { privateArtifactsCleared = device(['shell', 'pm', 'clear', pkg]).trim() === 'Success'; } catch { }
    if (!privateArtifactsCleared && !failure) failure = 'PRIVATE_ARTIFACT_CLEANUP_FAILED';
  }
  const sourceFiles = ['hostkeyprobe/src/main/java/dev/androidlab/hostkeyprobe/MainActivity.java', 'hostkey/WindowsVbsKey.cs', 'scripts/vbs-key-operation.ps1', 'scripts/test-hostkey-android.mjs'];
  const fileHash = file => { try { return sha(fs.readFileSync(path.join(root, file))); } catch { return null; } };
  const report = { schema_version: 1, recorded_at: new Date().toISOString(), status: failure ? 'failed' : 'passed', error_code: failure,
    transport: 'private_owned_apk_files_over_dedicated_adb', serial, android_package: pkg, owned_package_installed: ownedPackageInstalled,
    private_artifacts_cleared: privateArtifactsCleared, private_artifact_cleanup_required: ownedPackageInstalled,
    source_artifacts: sourceFiles.map(file => ({ path: file, sha256: fileHash(file) })),
    apk_sha256: fileHash('hostkeyprobe/build/outputs/apk/debug/hostkeyprobe-debug.apk'),
    checks: rows, native_claims_verified_on_windows: nativeClaimsVerified, android_verified_windows_claims: false,
    external_root_authenticated: false, android_tee_verified: false, google_attestation_verified: false,
    hardware_level_advertised_to_android: false, keymint_integrated: false, fresh_detector_run: false, zero_detections_achieved: false };
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify({ status: report.status, passed_checks: rows.length, report_path: reportPath }) + '\n');
}
if (failure) process.exitCode = 1;

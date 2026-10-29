import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { RelayServiceClient } from './RelayServiceClient.mjs';

const HEX32 = /^[a-f0-9]{32}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const MAX_RECEIPTS = 64;
const MAX_OUTPUT = 65536;
const sha = value => createHash('sha256').update(value).digest('hex');
const integer = value => Number.isSafeInteger(value) && value >= 0;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const assert = (condition, code) => { if (!condition) throw new Error(code); };
const safeCode = error => /^[A-Z0-9_]{1,80}$/.test(error?.message ?? '') ? error.message : 'BROKER_INTERNAL_ERROR';
const inside = (parent, child) => { const relative = path.relative(parent, child); return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative); };
function readJson(file, limit = 65536) {
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.size <= limit, 'PRIVATE_FILE_INVALID');
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}
function privatePath(value) {
  assert(typeof value === 'string' && path.isAbsolute(value), 'PRIVATE_PATH_REQUIRED');
  const absolute = path.resolve(value);
  assert(inside(privateRoot, absolute), 'PRIVATE_PATH_OUTSIDE_LOCALAPPDATA');
  return absolute;
}
function atomicJson(file, value, exclusive = false) {
  const text = JSON.stringify(value);
  assert(Buffer.byteLength(text) <= MAX_OUTPUT, 'STATE_TOO_LARGE');
  const temporary = exclusive ? file : `${file}.${randomBytes(8).toString('hex')}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, text, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    if (!exclusive) fs.renameSync(temporary, file);
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (!exclusive) { try { fs.unlinkSync(temporary); } catch {} }
    throw error;
  }
}
function requestHash(request) {
  return sha(['r1', config.pair_id, request.request_id, request.operation, request.challenge_base64url, String(request.timeout_ms)].join('\n'));
}
function parseRequest(text) {
  let value;
  try { value = JSON.parse(text); } catch { throw new Error('INVALID_JSON'); }
  assert(object(value), 'INVALID_REQUEST');
  const keys = ['schema_version', 'request_id', 'operation', 'challenge_base64url', 'timeout_ms'];
  assert(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), 'REQUEST_FIELDS');
  assert(value.schema_version === 1 && typeof value.request_id === 'string' && HEX32.test(value.request_id), 'REQUEST_ID');
  assert(['echo_sha256', 'play_integrity'].includes(value.operation), 'OPERATION');
  assert(typeof value.challenge_base64url === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value.challenge_base64url), 'CHALLENGE');
  const decoded = Buffer.from(value.challenge_base64url, 'base64url');
  assert(decoded.length === 32 && decoded.toString('base64url') === value.challenge_base64url, 'CHALLENGE_CANONICAL');
  assert(integer(value.timeout_ms) && value.timeout_ms >= 30000 && value.timeout_ms <= 120000, 'TIMEOUT');
  const rawKeys = [...text.matchAll(/"((?:[^"\\]|\\.)*)"\s*:/g)].map(match => JSON.parse(`"${match[1]}"`));
  assert(rawKeys.length === keys.length && new Set(rawKeys).size === keys.length, 'DUPLICATE_FIELDS');
  return value;
}
function stateFile(id) { assert(HEX32.test(id), 'STATE_ID'); return path.join(config.state_directory, `${id}.json`); }
function save(record, exclusive = false) { atomicJson(stateFile(record.receipt.request_id), record, exclusive); }
function failRecord(record, state, code) {
  record.receipt.state = state;
  record.receipt.error = { code };
  save(record);
}
function receipt(record) { return record.receipt; }
function sanitizeVerdict(value) {
  assert(object(value), 'VERDICT_INVALID');
  const result = {};
  const fields = {
    app_integrity: ['appRecognitionVerdict', 'packageName', 'certificateSha256Digest', 'versionCode'],
    device_integrity: ['deviceRecognitionVerdict'],
    account_details: ['appLicensingVerdict'],
  };
  for (const [section, names] of Object.entries(fields)) {
    assert(object(value[section]), 'VERDICT_SECTION');
    result[section] = {};
    for (const name of names) {
      if (!Object.hasOwn(value[section], name)) continue;
      const item = value[section][name];
      if (Array.isArray(item)) {
        assert(item.length <= 16 && item.every(entry => typeof entry === 'string' && entry.length <= 256), 'VERDICT_ARRAY');
      } else assert(typeof item === 'string' && item.length <= 256, 'VERDICT_VALUE');
      result[section][name] = item;
    }
  }
  return result;
}
function validateReport(report, record) {
  const request = record.request;
  assert(object(report) && report.schema_version === 1, 'RUNNER_SCHEMA');
  assert(report.job_id === request.request_id && report.session_id === config.session_id && report.worker_uid === session.worker_uid, 'RUNNER_JOB_IDENTITY');
  assert(report.operation === request.operation && report.origin === 'cooperative_remote_worker' && report.requester_integrity_verified === false, 'RUNNER_ORIGIN');
  assert(report.worker_package === session.worker_package && report.worker_package === cloud.worker_package, 'RUNNER_PACKAGE');
  assert(report.challenge_sha256 === record.receipt.challenge_sha256, 'RUNNER_CHALLENGE');
  assert(typeof report.request_sha256 === 'string' && HEX64.test(report.request_sha256), 'RUNNER_JOB_HASH');
  assert(integer(report.created_at_ms) && integer(report.expires_at_ms) && report.expires_at_ms > report.created_at_ms && report.expires_at_ms <= record.receipt.deadline_at_ms, 'RUNNER_JOB_TIME');
  const jobHash = sha(['v1', config.session_id, session.worker_uid, request.request_id, request.operation, request.challenge_base64url,
    String(cloud.project_number), String(report.created_at_ms), String(report.expires_at_ms)].join('\n'));
  assert(jobHash === report.request_sha256, 'RUNNER_JOB_HASH');
  if (report.status !== 'completed') {
    assert(['failed', 'worker_failed', 'timeout', 'expired', 'pending'].includes(report.status), 'RUNNER_STATUS');
    const code = report.error?.code;
    return { state: report.status === 'timeout' || report.status === 'expired' ? 'expired' : 'failed', error: { code: typeof code === 'string' && /^[A-Z0-9_]{1,80}$/.test(code) ? code : 'WORKER_NOT_COMPLETED' } };
  }
  assert(report.worker_execution_state === 'completed', 'RUNNER_EXECUTION_STATE');
  assert(integer(report.worker_version_code) && report.worker_version_code > 0 && HEX64.test(report.worker_apk_cert_sha256), 'RUNNER_WORKER_IDENTITY');
  assert(integer(report.execution_elapsed_ms) && report.execution_elapsed_ms <= 150000 && integer(report.broker_observed_elapsed_ms), 'RUNNER_ELAPSED');
  assert(integer(report.attempt) && report.attempt >= 1 && report.attempt <= 2147483647, 'RUNNER_ATTEMPT');
  const result = {
    schema_version: 1, request_id: record.receipt.request_id, request_sha256: record.receipt.request_sha256,
    operation: request.operation, challenge_sha256: record.receipt.challenge_sha256,
    origin: 'cooperative_remote_worker', requester_integrity_verified: false,
    worker_package: report.worker_package,
    worker_version_code: report.worker_version_code,
    worker_apk_cert_sha256: report.worker_apk_cert_sha256,
    execution_elapsed_ms: report.execution_elapsed_ms,
    broker_observed_elapsed_ms: report.broker_observed_elapsed_ms,
    job_id: report.job_id,
    attempt: report.attempt,
    request_binding: { challenge_sha256_matches: true },
  };
  if (request.operation === 'play_integrity') {
    assert(object(report.request_binding) && ['package_matches', 'nonce_bytes_match', 'timestamp_in_window'].every(key => report.request_binding[key] === true), 'RUNNER_INTEGRITY_BINDING');
    result.request_binding = { ...result.request_binding, package_matches: true, nonce_bytes_match: true, timestamp_in_window: true };
    result.worker_verdict = sanitizeVerdict(report.worker_verdict);
    const app = result.worker_verdict.app_integrity;
    if (app.certificateSha256Digest !== undefined) {
      assert(app.certificateSha256Digest.length === 1 && Buffer.from(app.certificateSha256Digest[0], 'base64url').toString('hex') === report.worker_apk_cert_sha256, 'RUNNER_CERTIFICATE_BINDING');
    }
    if (app.packageName !== undefined) assert(app.packageName === session.worker_package, 'RUNNER_VERDICT_PACKAGE');
    if (app.versionCode !== undefined) assert(app.versionCode === String(report.worker_version_code), 'RUNNER_VERDICT_VERSION');
  }
  return { state: 'completed', result };
}
function runnerAlive(entry) {
  return !entry.closed && entry.child.exitCode === null && entry.child.signalCode === null && !!entry.child.pid;
}
function waitForClose(entry, milliseconds) {
  if (entry.closed) return Promise.resolve(true);
  return new Promise(resolve => {
    const done = () => { clearTimeout(timer); entry.child.off('close', done); resolve(true); };
    const timer = setTimeout(() => { entry.child.off('close', done); resolve(entry.closed); }, milliseconds);
    entry.child.once('close', done);
  });
}
function terminateTreeAttempt(entry) {
  if (!runnerAlive(entry)) return Promise.resolve(null);
  if (process.platform !== 'win32') {
    try { return Promise.resolve(entry.child.kill(entry.killAttempts > 1 ? 'SIGKILL' : 'SIGTERM') ? 0 : -1); }
    catch { return Promise.resolve(-1); }
  }
  return new Promise(resolve => {
    let settled = false;
    const finish = code => { if (settled) return; settled = true; clearTimeout(timer); resolve(code); };
    let killer;
    try {
      // Retain the original child handle and never target this PID after exit/close.
      if (!runnerAlive(entry)) { resolve(null); return; }
      killer = spawn(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe'),
        ['/PID', String(entry.child.pid), '/T', '/F'], { shell: false, windowsHide: true, stdio: 'ignore' });
    } catch { resolve(-1); return; }
    const timer = setTimeout(() => { try { killer.kill(); } catch {} finish(-1); }, 1500);
    killer.once('error', () => finish(-1));
    killer.once('close', code => finish(Number.isInteger(code) ? code : -1));
  });
}
function stopOwnedChild(entry) {
  if (!entry?.child) return Promise.resolve(true);
  if (entry.stopPromise) return entry.stopPromise;
  if (entry.closed) return Promise.resolve(true);
  entry.stopping = true;
  terminationPending = true;
  terminatingEntry = entry;
  entry.stopPromise = (async () => {
    let treeConfirmed = false;
    for (let attempt = 1; attempt <= 3 && !entry.closed; attempt++) {
      if (!runnerAlive(entry)) { await waitForClose(entry, 1000); break; }
      entry.killAttempts = attempt;
      const code = await terminateTreeAttempt(entry);
      entry.terminationToolCode = code;
      if (code === 0) treeConfirmed = true;
      await waitForClose(entry, 1500);
      // A retry is allowed only while the same retained child still reports alive.
      if (!runnerAlive(entry)) break;
    }
    const confirmed = entry.closed && (treeConfirmed || entry.terminationToolCode === null);
    terminationPending = false;
    terminationState = confirmed ? 'confirmed' : 'unconfirmed';
    terminationExitCode = entry.closeCode ?? null;
    terminationToolExitCode = entry.terminationToolCode ?? null;
    if (!confirmed) {
      terminationBlocked = true;
      try { if (entry.record && entry.record.receipt.state !== 'completed') failRecord(entry.record, entry.record.receipt.state === 'expired' ? 'expired' : 'failed', 'TERMINATION_UNCONFIRMED'); } catch {}
    }
    try { if (!confirmed) readiness('termination_unconfirmed'); else if (!closing) readiness('listening'); } catch {}
    if (terminatingEntry === entry) terminatingEntry = null;
    return confirmed;
  })();
  return entry.stopPromise;
}
function runnerTimeoutSeconds(remainingMs) {
  return remainingMs > 0 ? Math.max(30, Math.min(120, Math.ceil(remainingMs / 1000))) : null;
}
function execute(record) {
  if (config.execution_mode === 'persistent') { void executePersistent(record); return; }
  if (closing || Date.now() >= record.receipt.deadline_at_ms) { failRecord(record, 'expired', 'REQUEST_EXPIRED'); active = null; return; }
  record.receipt.state = 'running'; save(record);
  const remainingMs = record.receipt.deadline_at_ms - Date.now();
  const seconds = runnerTimeoutSeconds(remainingMs);
  if (remainingMs <= 0) { failRecord(record, 'expired', 'INSUFFICIENT_DEADLINE'); active = null; return; }
  const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', config.job_script_path,
    '-ConfigPath', config.cloud_config_path, '-SessionPath', config.worker_session_path,
    '-ReportsDirectory', config.reports_directory, '-Name', `requester_${record.request.request_id}`,
    '-Operation', record.request.operation, '-ChallengeBase64Url', record.request.challenge_base64url,
    '-JobId', record.request.request_id, '-TimeoutSeconds', String(Math.min(120, seconds)), '-DeadlineAtMs', String(record.receipt.deadline_at_ms)];
  let child;
  try { child = spawn(config.pwsh_path, args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch { failRecord(record, 'failed', 'RUNNER_START_FAILED'); active = null; return; }
  const entry = { child, record, stopping: false, closed: false, closeCode: null, killAttempts: 0, terminationToolCode: null };
  active = entry;
  let output = Buffer.alloc(0); let stderrBytes = 0; let overflow = false;
  const timer = setTimeout(() => {
    try { if (record.receipt.state === 'running') failRecord(record, 'expired', 'REQUEST_EXPIRED'); }
    finally { stopOwnedChild(entry); }
  }, Math.max(1, record.receipt.deadline_at_ms - Date.now()));
  child.stdout.on('data', chunk => {
    if (overflow) return;
    if (output.length + chunk.length > MAX_OUTPUT) { overflow = true; stopOwnedChild(entry); return; }
    output = Buffer.concat([output, chunk]);
  });
  child.stderr.on('data', chunk => { stderrBytes += chunk.length; if (stderrBytes > MAX_OUTPUT) { overflow = true; stopOwnedChild(entry); } });
  child.on('error', () => { if (record.receipt.state === 'running') { try { failRecord(record, 'failed', 'RUNNER_START_FAILED'); } catch { shutdown('STATE_WRITE_FAILED'); } } });
  child.on('close', code => {
    entry.closed = true; entry.closeCode = code;
    clearTimeout(timer);
    if (active === entry) active = null;
    if (record.receipt.state !== 'running') return;
    try {
      if (entry.stopping) { failRecord(record, 'failed', 'RUNNER_STOPPED'); return; }
      if (Date.now() >= record.receipt.deadline_at_ms) { failRecord(record, 'expired', 'REQUEST_EXPIRED'); return; }
      assert(!overflow, 'RUNNER_OUTPUT_LIMIT');
      const report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(output).trim());
      if (code !== 0 && !report.job_id) throw new Error(typeof report.error?.code === 'string' && /^[A-Z0-9_]{1,80}$/.test(report.error.code) ? report.error.code : 'RUNNER_FAILED');
      const terminal = validateReport(report, record);
      record.receipt.state = terminal.state;
      if (terminal.result) record.receipt.result = terminal.result;
      if (terminal.error) record.receipt.error = terminal.error;
      save(record);
    } catch (error) { try { failRecord(record, 'failed', safeCode(error)); } catch { shutdown('STATE_WRITE_FAILED'); } }
    finally { output = Buffer.alloc(0); }
  });
}
async function executePersistent(record) {
  const entry = { record, child: service.child, closed: service.closed, closeCode: service.closeCode, stopping: false, killAttempts: 0, terminationToolCode: null };
  active = entry;
  serviceEntry.record = record;
  try {
    assert(!closing && service.ready && !service.dead, 'SERVICE_UNAVAILABLE');
    assert(Date.now() < record.receipt.deadline_at_ms, 'REQUEST_EXPIRED');
    record.receipt.state = 'running'; save(record);
    const response = await service.execute({ request_id: record.request.request_id, request_sha256: record.receipt.request_sha256,
      operation: record.request.operation, challenge_base64url: record.request.challenge_base64url, timeout_ms: record.request.timeout_ms,
      deadline_at_ms: record.receipt.deadline_at_ms });
    if (closing || record.receipt.state !== 'running') return;
    assert(Date.now() < record.receipt.deadline_at_ms, 'REQUEST_EXPIRED');
    record.receipt.service_metrics = response.service_metrics;
    if (response.error) throw new Error(response.error.code);
    const terminal = validateReport(response.report, record);
    record.receipt.state = terminal.state;
    if (terminal.result) record.receipt.result = { ...terminal.result, service_metrics: response.service_metrics };
    if (terminal.error) record.receipt.error = terminal.error;
    save(record);
  } catch (error) {
    if (['accepted', 'running'].includes(record.receipt.state)) failRecord(record, Date.now() >= record.receipt.deadline_at_ms ? 'expired' : 'failed', safeCode(error));
    if (service.dead) await stopOwnedChild(serviceEntry);
  } finally { if (active === entry) active = null; if (!service.dead) serviceEntry.record = null; }
}
function respond(response, code, body, allow) {
  const payload = JSON.stringify(body);
  response.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...(allow ? { Allow: allow } : {}) });
  response.end(payload);
}
function authenticate(request) {
  const headers = request.rawHeaders.filter((_, index) => index % 2 === 0).filter(name => name.toLowerCase() === 'authorization');
  if (headers.length !== 1) return false;
  const value = request.headers.authorization;
  if (typeof value !== 'string' || !/^Bearer [A-Za-z0-9_-]{43}$/.test(value)) return false;
  const supplied = Buffer.from(value.slice(7), 'ascii');
  return supplied.length === bearer.length && timingSafeEqual(supplied, bearer);
}
async function handle(request, response) {
  try {
    if (!authenticate(request)) { request.resume(); respond(response, 401, { error: { code: 'UNAUTHORIZED' } }); return; }
    if (Date.now() >= config.expires_at_ms || closing) { request.resume(); respond(response, 410, { error: { code: 'PAIR_EXPIRED' } }); return; }
    const isPostPath = request.url === '/v1/requests';
    const getMatch = /^\/v1\/requests\/([a-f0-9]{32})$/.exec(request.url ?? '');
    if (!isPostPath && !getMatch) { request.resume(); respond(response, 404, { error: { code: 'NOT_FOUND' } }); return; }
    if ((isPostPath && request.method !== 'POST') || (getMatch && request.method !== 'GET')) {
      request.resume(); respond(response, 405, { error: { code: 'METHOD_NOT_ALLOWED' } }, isPostPath ? 'POST' : 'GET'); return;
    }
    if (getMatch) {
      request.resume(); const record = records.get(getMatch[1]);
      if (!record) respond(response, 404, { error: { code: 'NOT_FOUND' } });
      else respond(response, 200, receipt(record));
      return;
    }
    assert(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? ''), 'CONTENT_TYPE');
    if (request.headers['content-length'] !== undefined) assert(/^\d+$/.test(request.headers['content-length']) && Number(request.headers['content-length']) <= 4096, 'REQUEST_TOO_LARGE');
    const chunks = []; let length = 0;
    for await (const chunk of request) { length += chunk.length; assert(length <= 4096, 'REQUEST_TOO_LARGE'); chunks.push(chunk); }
    const body = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    const parsed = parseRequest(body); const hash = requestHash(parsed);
    const existing = records.get(parsed.request_id);
    if (existing) {
      if (existing.receipt.request_sha256 !== hash) respond(response, 409, { error: { code: 'IDEMPOTENCY_CONFLICT' } });
      else respond(response, 202, receipt(existing));
      return;
    }
    if (terminationBlocked || terminationPending) { respond(response, 503, { error: { code: terminationBlocked ? 'TERMINATION_UNCONFIRMED' : 'TERMINATION_PENDING' } }); return; }
    if (config.execution_mode === 'persistent' && (!service?.ready || service.dead)) { respond(response, 503, { error: { code: 'SERVICE_UNAVAILABLE' } }); return; }
    if (active) { respond(response, 409, { error: { code: 'PAIR_BUSY' } }); return; }
    if (records.size >= MAX_RECEIPTS) { respond(response, 429, { error: { code: 'RECEIPT_LIMIT' } }); return; }
    const now = Date.now(); const deadline = Math.min(now + parsed.timeout_ms, config.expires_at_ms);
    if (deadline - now < 30000) { respond(response, 410, { error: { code: 'PAIR_NEAR_EXPIRY' } }); return; }
    const record = { pair_id: config.pair_id, session_id: config.session_id, request: parsed, receipt: {
      schema_version: 1, request_id: parsed.request_id, request_sha256: hash, operation: parsed.operation,
      challenge_sha256: sha(Buffer.from(parsed.challenge_base64url, 'base64url')), created_at_ms: now, deadline_at_ms: deadline,
      state: 'accepted', origin: 'cooperative_remote_worker', requester_integrity_verified: false } };
    save(record, true); records.set(parsed.request_id, record); active = { reserved: true, record };
    respond(response, 202, receipt(record));
    setImmediate(() => { try { execute(record); } catch { try { failRecord(record, 'failed', 'RUNNER_START_FAILED'); } finally { active = null; } } });
  } catch (error) {
    if (!response.headersSent && !response.destroyed) respond(response, safeCode(error) === 'REQUEST_TOO_LARGE' ? 413 : 400, { error: { code: safeCode(error) } });
    else response.destroy();
  }
}
function releaseLock() {
  if (!stateLockFile || !lockNonce) return;
  try { const owner = readJson(stateLockFile, 1024); if (owner.pid === process.pid && owner.nonce === lockNonce) fs.unlinkSync(stateLockFile); } catch {}
}
function readiness(state) {
  const transport = { schema_version: 1, pair_id: config.pair_id,
    pid: process.pid, host: '127.0.0.1', port: server.address()?.port ?? config.port,
    expires_at_ms: config.expires_at_ms, spki_sha256: pin, state, execution_mode: config.execution_mode,
    ...(service ? { service_pid: service.child.pid, service_state: service.dead ? 'unavailable' : service.ready ? 'ready' : 'starting', generation: service.generation, startup_ms: service.startupMs ?? 0, startup_metrics: service.startupMetrics ?? {}, service_metrics: service.metrics ?? {} } : {}),
    termination_state: terminationState, runner_exit_code: terminationExitCode, termination_tool_exit_code: terminationToolExitCode };
  if (config.readiness_file) atomicJson(config.readiness_file, transport);
  process.stdout.write(`${JSON.stringify(transport)}\n`);
}
async function shutdown(code = 'BROKER_STOPPED') {
  if (closing) return; closing = true;
  const owned = active ?? terminatingEntry;
  if (owned?.record && ['accepted', 'running'].includes(owned.record.receipt.state)) {
    try { failRecord(owned.record, Date.now() >= config.expires_at_ms ? 'expired' : 'failed', code); } catch {}
  }
  server.close();
  for (const socket of sockets) socket.destroy();
  clearTimeout(expiryTimer);
  const confirmed = serviceEntry ? await stopOwnedChild(serviceEntry) : owned?.child ? await stopOwnedChild(owned) : !terminationBlocked;
  if (!confirmed || terminationBlocked) {
    try { readiness('termination_unconfirmed'); } catch {}
    // Keep the process ancestry and lock available for the bootstrap's Kill(true).
    if (!terminationHold) terminationHold = setInterval(() => {}, 30000);
    process.exitCode = 1;
    return;
  }
  try { readiness('closed'); } catch {}
  releaseLock();
  setTimeout(() => process.exit(0), 100).unref();
}

process.umask(0o077);
let privateRoot; let config; let cloud; let session; let bearer; let pin; let server; let expiryTimer; let stateLockFile; let lockNonce;
let active = null; let closing = false; let terminationPending = false; let terminationBlocked = false;
let terminatingEntry = null;
let service; let serviceEntry;
let terminationState = 'not_requested'; let terminationExitCode = null; let terminationToolExitCode = null; let terminationHold = null;
const records = new Map(); const sockets = new Set();
try {
  assert(process.argv.length === 4 && process.argv[2] === '--config', 'CONFIG_ARGUMENTS');
  assert(process.env.LOCALAPPDATA, 'LOCALAPPDATA_REQUIRED'); privateRoot = path.resolve(process.env.LOCALAPPDATA);
  const configPath = privatePath(process.argv[3]); config = readJson(configPath);
  const mandatory = ['schema_version','pair_id','bearer_token','session_id','expires_at_ms','port','certificate_path','key_path','state_directory','cloud_config_path','worker_session_path','pwsh_path','job_script_path','reports_directory'];
  assert(object(config) && mandatory.every(key => Object.hasOwn(config, key)) && Object.keys(config).every(key => mandatory.includes(key) || ['readiness_file','execution_mode','service_script_path','auth_account','auth_configuration'].includes(key)), 'CONFIG_FIELDS');
  config.execution_mode ??= 'once';
  assert(['once','persistent'].includes(config.execution_mode), 'CONFIG_EXECUTION_MODE');
  if (config.execution_mode === 'persistent') {
    assert(typeof config.service_script_path === 'string' && path.isAbsolute(config.service_script_path) && fs.statSync(config.service_script_path).isFile(), 'SERVICE_SCRIPT');
    assert(typeof config.auth_account === 'string' && /^[A-Za-z0-9_.@+-]{3,254}$/.test(config.auth_account), 'AUTH_ACCOUNT');
    assert(typeof config.auth_configuration === 'string' && /^[a-z][a-z0-9_-]{0,62}$/.test(config.auth_configuration), 'AUTH_CONFIGURATION');
  }
  assert(config.schema_version === 1 && HEX32.test(config.pair_id) && HEX32.test(config.session_id), 'CONFIG_ID');
  assert(typeof config.bearer_token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(config.bearer_token), 'CONFIG_BEARER');
  assert(Buffer.from(config.bearer_token, 'base64url').length === 32 && Buffer.from(config.bearer_token, 'base64url').toString('base64url') === config.bearer_token, 'CONFIG_BEARER');
  assert(integer(config.expires_at_ms) && config.expires_at_ms > Date.now() && config.expires_at_ms <= Date.now() + 86400000, 'CONFIG_EXPIRY');
  assert(integer(config.port) && config.port >= 0 && config.port <= 65535, 'CONFIG_PORT');
  for (const key of ['certificate_path','key_path','state_directory','cloud_config_path','worker_session_path']) config[key] = privatePath(config[key]);
  for (const key of ['pwsh_path','job_script_path','reports_directory']) assert(typeof config[key] === 'string' && path.isAbsolute(config[key]), 'CONFIG_ABSOLUTE_PATH');
  assert(fs.statSync(config.pwsh_path).isFile() && fs.statSync(config.job_script_path).isFile(), 'RUNNER_FILES');
  assert(!fs.lstatSync(config.certificate_path).isSymbolicLink() && !fs.lstatSync(config.key_path).isSymbolicLink(), 'TLS_FILE_LINK');
  if (config.readiness_file) config.readiness_file = privatePath(config.readiness_file);
  fs.mkdirSync(config.state_directory, { recursive: true, mode: 0o700 });
  assert(fs.lstatSync(config.state_directory).isDirectory() && !fs.lstatSync(config.state_directory).isSymbolicLink(), 'STATE_DIRECTORY');
  assert(inside(privateRoot, fs.realpathSync(config.state_directory)), 'STATE_DIRECTORY_OUTSIDE_PRIVATE_ROOT');
  for (const key of ['certificate_path', 'key_path', 'cloud_config_path', 'worker_session_path']) assert(inside(privateRoot, fs.realpathSync(config[key])), 'PRIVATE_FILE_OUTSIDE_LOCALAPPDATA');
  stateLockFile = path.join(config.state_directory, 'broker.lock');
  if (fs.existsSync(stateLockFile)) {
    const previous = readJson(stateLockFile, 1024);
    assert(integer(previous.pid) && previous.pid > 0 && previous.pair_id === config.pair_id, 'STATE_LOCK_INVALID');
    let alive = true;
    try { process.kill(previous.pid, 0); } catch (error) { alive = error.code !== 'ESRCH'; }
    assert(!alive, 'STATE_DIRECTORY_BUSY'); fs.unlinkSync(stateLockFile);
  }
  lockNonce = randomBytes(16).toString('hex');
  atomicJson(stateLockFile, { pid: process.pid, pair_id: config.pair_id, nonce: lockNonce }, true);
  cloud = readJson(config.cloud_config_path); session = readJson(config.worker_session_path);
  assert(session.session_id === config.session_id && session.revoked === false && integer(session.expires_at_ms) && config.expires_at_ms <= session.expires_at_ms, 'SESSION_CONFIG');
  assert(typeof session.worker_uid === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(session.worker_uid) && session.worker_package === cloud.worker_package, 'SESSION_IDENTITY');
  assert(integer(cloud.project_number) && cloud.project_number > 0 && typeof cloud.worker_package === 'string', 'CLOUD_IDENTITY');
  const cert = fs.readFileSync(config.certificate_path); const key = fs.readFileSync(config.key_path);
  const certificate = new X509Certificate(cert);
  assert(certificate.checkIP('127.0.0.1') === '127.0.0.1', 'CERTIFICATE_SAN');
  assert(Date.parse(certificate.validFrom) <= Date.now() && Date.parse(certificate.validTo) >= config.expires_at_ms, 'CERTIFICATE_VALIDITY');
  pin = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  bearer = Buffer.from(config.bearer_token, 'ascii'); delete config.bearer_token;
  for (const name of fs.readdirSync(config.state_directory)) {
    if (!/^[a-f0-9]{32}\.json$/.test(name)) continue;
    assert(records.size < MAX_RECEIPTS, 'STATE_RECEIPT_LIMIT');
    const record = readJson(path.join(config.state_directory, name));
    assert(record.pair_id === config.pair_id && record.session_id === config.session_id && object(record.receipt), 'STATE_PAIR_MISMATCH');
    assert(record.receipt.request_id === name.slice(0, -5) && requestHash(parseRequest(JSON.stringify(record.request))) === record.receipt.request_sha256, 'STATE_REQUEST_INVALID');
    assert(integer(record.receipt.created_at_ms) && integer(record.receipt.deadline_at_ms) && record.receipt.deadline_at_ms <= config.expires_at_ms && record.receipt.deadline_at_ms > record.receipt.created_at_ms, 'STATE_DEADLINE');
    assert(['accepted','running','completed','failed','expired'].includes(record.receipt.state), 'STATE_VALUE');
    if (['accepted','running'].includes(record.receipt.state)) failRecord(record, 'failed', 'BROKER_RESTARTED');
    records.set(record.receipt.request_id, record);
  }
  server = https.createServer({ key, cert, minVersion: 'TLSv1.2', maxHeaderSize: 8192, handshakeTimeout: 5000 }, (request, response) => { void handle(request, response); });
  server.headersTimeout = 5000; server.requestTimeout = 10000; server.keepAliveTimeout = 2000; server.maxRequestsPerSocket = 32;
  server.on('connection', socket => { if (sockets.size >= 16) { socket.destroy(); return; } sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('tlsClientError', () => {});
  server.on('error', () => shutdown('TRANSPORT_FAILED'));
  if (config.execution_mode === 'persistent') {
    service = new RelayServiceClient({ executable: config.pwsh_path, script: config.service_script_path, configPath,
      generation: randomBytes(16).toString('hex'), pairId: config.pair_id, sessionId: config.session_id,
      onFailure: () => { if (serviceEntry) void stopOwnedChild(serviceEntry); } });
    serviceEntry = { child: service.child, record: null, stopping: false, closed: false, closeCode: null, killAttempts: 0, terminationToolCode: null };
    service.child.on('close', code => { serviceEntry.closed = true; serviceEntry.closeCode = code; });
    await service.readyPromise;
  }
  server.listen({ host: '127.0.0.1', port: config.port, exclusive: true }, () => {
    try { readiness('listening'); } catch { shutdown('READINESS_WRITE_FAILED'); }
  });
  expiryTimer = setTimeout(() => {
    if (active?.record && ['accepted', 'running'].includes(active.record.receipt.state)) {
      try { failRecord(active.record, 'expired', 'PAIR_EXPIRED'); } catch {}
      if (serviceEntry) stopOwnedChild(serviceEntry);
      else if (active?.child) stopOwnedChild(active);
    }
    try { readiness('expired'); } catch {}
    setTimeout(() => shutdown('PAIR_EXPIRED'), 2000);
  }, Math.max(1, config.expires_at_ms - Date.now()));
  process.once('SIGINT', () => shutdown()); process.once('SIGTERM', () => shutdown());
} catch (error) {
  const confirmed = serviceEntry ? await stopOwnedChild(serviceEntry) : true;
  if (confirmed) releaseLock();
  else if (!terminationHold) terminationHold = setInterval(() => {}, 30000);
  process.stderr.write(`${safeCode(error)}\n`); process.exitCode = 1;
}

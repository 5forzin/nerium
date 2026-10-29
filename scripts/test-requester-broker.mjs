import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { setTimeout as pause } from 'node:timers/promises';

const hash = value => createHash('sha256').update(value).digest('hex');
const inside = (parent, candidate) => { const relative = path.relative(parent, candidate); return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); };
const tests = [];
const overallDeadline = Date.now() + 120000;
let agent;
let target;
let bearer;
let reportPath;
let failed = false;
function check(condition, code) { if (!condition) throw new Error(code); }
function jsonFile(file) {
  const metadata = fs.lstatSync(file);
  check(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 65536, 'CONFIG_FILE_INVALID');
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}
function record(name, response, expected, requestHash = hash(''), extra = true) {
  const passed = response.code === expected && extra;
  tests.push({ name, status_code: response.code, passed, request_sha256: requestHash });
  check(passed, 'ASSERTION_FAILED');
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function containsToken(value) {
  if (value === null || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, item]) => /^(token|idtoken|refreshtoken|bearer_token)$/i.test(key) || containsToken(item));
}
function call(method, route, body, auth = 'valid') {
  check(Date.now() < overallDeadline, 'TEST_DEADLINE');
  return new Promise((resolve, reject) => {
    const headers = { 'Content-Type': 'application/json; charset=utf-8', Connection: 'close' };
    if (auth === 'valid') headers.Authorization = `Bearer ${bearer}`;
    if (auth === 'invalid') headers.Authorization = `Bearer ${bearer[0] === 'A' ? 'B' : 'A'}${bearer.slice(1)}`;
    if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);
    const request = https.request({ hostname: '127.0.0.1', port: target.port, path: route, method, headers, agent,
      rejectUnauthorized: true, timeout: Math.min(10000, overallDeadline - Date.now()) }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 65536) response.destroy(new Error('RESPONSE_TOO_LARGE'));
        else chunks.push(chunk);
      });
      response.once('error', () => reject(new Error('HTTP_RESPONSE_FAILED')));
      response.once('end', () => {
        try { resolve({ code: response.statusCode, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { reject(new Error('INVALID_RESPONSE_JSON')); }
      });
    });
    request.once('timeout', () => request.destroy(new Error('HTTP_TIMEOUT')));
    request.once('error', error => reject(new Error(/^[A-Z0-9_]+$/.test(error.code ?? '') ? error.code : 'HTTP_REQUEST_FAILED')));
    request.end(body);
  });
}
try {
  check(process.argv.length === 6, 'ARGUMENTS');
  const options = {};
  for (let index = 2; index < process.argv.length; index += 2) {
    check(['--config', '--report'].includes(process.argv[index]) && options[process.argv[index]] === undefined, 'ARGUMENTS');
    options[process.argv[index]] = process.argv[index + 1];
  }
  check(options['--config'] && options['--report'] && process.env.LOCALAPPDATA, 'ARGUMENTS');
  const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const reportCandidate = path.resolve(options['--report']);
  check(path.isAbsolute(options['--report']) && inside(path.join(workspace, 'reports'), reportCandidate) && /^[A-Za-z0-9_.-]+\.json$/.test(path.basename(reportCandidate)), 'REPORT_PATH');
  reportPath = reportCandidate;
  const configPath = path.resolve(options['--config']);
  check(path.isAbsolute(options['--config']) && inside(path.resolve(process.env.LOCALAPPDATA), fs.realpathSync(configPath)), 'PRIVATE_CONFIG_PATH');
  const config = jsonFile(configPath);
  check(config.schema_version === 1 && /^[a-f0-9]{32}$/.test(config.pair_id) && typeof config.bearer_token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(config.bearer_token), 'CONFIG_SCHEMA');
  check(Number.isSafeInteger(config.expires_at_ms) && config.expires_at_ms > Date.now() + 35000, 'PAIR_NEAR_EXPIRY');
  target = { port: config.port };
  if (config.readiness_file) {
    const readiness = jsonFile(config.readiness_file);
    check(readiness.pair_id === config.pair_id && readiness.host === '127.0.0.1' && readiness.state === 'listening', 'READINESS_MISMATCH');
    target.port = readiness.port;
  }
  check(Number.isInteger(target.port) && target.port > 0 && target.port <= 65535, 'PORT_INVALID');
  check(path.isAbsolute(config.certificate_path), 'CERTIFICATE_PATH');
  const certificate = fs.readFileSync(config.certificate_path);
  agent = new https.Agent({ ca: certificate, rejectUnauthorized: true, keepAlive: false, maxSockets: 2 });
  bearer = config.bearer_token;
  delete config.bearer_token;
  record('missing_bearer_denied', await call('GET', '/v1/requests', undefined, 'none'), 401);
  record('invalid_bearer_denied', await call('GET', '/v1/requests', undefined, 'invalid'), 401);
  record('wrong_path_not_found', await call('GET', '/v1/nonexistent'), 404);
  record('wrong_method_rejected', await call('GET', '/v1/requests'), 405);
  record('malformed_json_rejected', await call('POST', '/v1/requests', '{'), 400, hash('{'));
  const request = { schema_version: 1, request_id: randomBytes(16).toString('hex'), operation: 'echo_sha256',
    challenge_base64url: randomBytes(32).toString('base64url'), timeout_ms: 30000 };
  const extra = JSON.stringify({ ...request, unexpected: true });
  record('extra_json_field_rejected', await call('POST', '/v1/requests', extra), 400, hash(extra));
  const oversized = ' '.repeat(4097);
  record('oversized_request_rejected', await call('POST', '/v1/requests', oversized), 413, hash(oversized));
  const body = JSON.stringify(request);
  const expectedHash = hash(['r1', config.pair_id, request.request_id, request.operation, request.challenge_base64url, String(request.timeout_ms)].join('\n'));
  const challengeHash = hash(Buffer.from(request.challenge_base64url, 'base64url'));
  const bound = value => value?.schema_version === 1 && value.request_id === request.request_id && value.request_sha256 === expectedHash
    && value.operation === 'echo_sha256' && value.challenge_sha256 === challengeHash
    && value.origin === 'cooperative_remote_worker' && value.requester_integrity_verified === false && !containsToken(value);
  const posted = await call('POST', '/v1/requests', body);
  record('thirty_second_echo_accepted', posted, 202, expectedHash,
    bound(posted.value) && ['accepted', 'running', 'completed'].includes(posted.value.state)
    && Number.isSafeInteger(posted.value.created_at_ms) && Number.isSafeInteger(posted.value.deadline_at_ms)
    && posted.value.deadline_at_ms - posted.value.created_at_ms <= 30000);
  const duplicate = await call('POST', '/v1/requests', body);
  record('identical_inflight_post_is_idempotent', duplicate, 202, expectedHash,
    bound(duplicate.value) && duplicate.value.deadline_at_ms === posted.value.deadline_at_ms);
  const changed = Buffer.from(request.challenge_base64url, 'base64url'); changed[0] ^= 1;
  const conflictBody = JSON.stringify({ ...request, challenge_base64url: changed.toString('base64url') });
  record('changed_request_conflicts', await call('POST', '/v1/requests', conflictBody), 409, hash(conflictBody));
  let terminal;
  const pollDeadline = Math.min(overallDeadline, posted.value.deadline_at_ms + 10000);
  while (Date.now() < pollDeadline) {
    const polled = await call('GET', `/v1/requests/${request.request_id}`);
    check(polled.code === 200 && bound(polled.value), 'POLL_RESPONSE_MISMATCH');
    if (['completed', 'failed', 'expired'].includes(polled.value.state)) { terminal = polled; break; }
    await pause(750);
  }
  check(terminal, 'TERMINAL_TIMEOUT');
  const result = terminal.value.result;
  record('thirty_second_echo_completed_and_bound', terminal, 200, expectedHash,
    terminal.value.state === 'completed' && bound(result) && result.job_id === request.request_id
    && result.worker_package === 'dev.androidlab.relayworker' && Number.isSafeInteger(result.worker_version_code) && result.worker_version_code > 0
    && typeof result.worker_apk_cert_sha256 === 'string' && /^[a-f0-9]{64}$/.test(result.worker_apk_cert_sha256));
  const cached = await call('POST', '/v1/requests', body);
  record('completed_post_returns_cached_receipt', cached, 202, expectedHash,
    bound(cached.value) && cached.value.state === 'completed' && cached.value.deadline_at_ms === posted.value.deadline_at_ms
    && hash(JSON.stringify(canonical(cached.value.result))) === hash(JSON.stringify(canonical(result))));
} catch (error) {
  failed = true;
  if (tests.length === 0 || tests.at(-1).passed) tests.push({ name: /^[A-Z0-9_]{1,80}$/.test(error.message ?? '') ? error.message : 'LOCAL_TEST_FAILURE', status_code: 0, passed: false, request_sha256: hash('') });
} finally {
  bearer = undefined;
  agent?.destroy();
  if (reportPath) {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    const temporary = `${reportPath}.${randomBytes(8).toString('hex')}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(tests, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, reportPath);
  }
}
process.stdout.write(failed ? 'Requester broker verification failed; inspect the sanitized report.\n' : 'Requester broker verification passed.\n');
process.exitCode = failed ? 1 : 0;

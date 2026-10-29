import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { TextDecoder } from 'node:util';

const fail = code => new Error(code);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export function serviceMetrics(value = {}) {
  if (!object(value) || Object.keys(value).length > 32) throw fail('SERVICE_METRICS');
  const result = {};
  for (const [key, number] of Object.entries(value)) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || !Number.isSafeInteger(number) || number < 0) throw fail('SERVICE_METRICS');
    result[key] = number;
  }
  return result;
}

export class RelayServiceClient {
  constructor({ executable, script, configPath, generation, pairId, sessionId, spawnChild = spawn, startupMs = 30000, onFailure = () => {} }) {
    this.generation = generation; this.pairId = pairId; this.sessionId = sessionId;
    this.onFailure = onFailure; this.startedAt = Date.now(); this.ready = false; this.dead = false; this.closed = false;
    this.decoder = new TextDecoder('utf-8', { fatal: true }); this.buffer = Buffer.alloc(0); this.stderrBytes = 0;
    this.readyPromise = new Promise((resolve, reject) => { this.readyResolve = resolve; this.readyReject = reject; });
    this.child = spawnChild(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', script, '-ConfigPath', configPath, '-Generation', generation],
      { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.startupTimer = setTimeout(() => this.die('SERVICE_READY_TIMEOUT'), startupMs);
    this.child.stdout.on('data', chunk => this.consume(chunk));
    this.child.stderr.on('data', chunk => { this.stderrBytes += chunk.length; if (this.stderrBytes > 65536) this.die('SERVICE_STDERR_LIMIT'); });
    this.child.stdin.on('error', () => this.die('SERVICE_PIPE_FAILED'));
    this.child.on('error', () => this.die('SERVICE_START_FAILED'));
    this.child.on('close', code => { this.closed = true; this.closeCode = code; this.die(this.buffer.length ? 'SERVICE_TRUNCATED' : 'SERVICE_CLOSED'); });
  }
  die(code) {
    if (this.dead) return;
    this.dead = true; this.ready = false; clearTimeout(this.startupTimer);
    this.readyReject(fail(code));
    if (this.pending) { clearTimeout(this.pending.timer); this.pending.reject(fail(code)); this.pending = null; }
    this.onFailure(code);
  }
  consume(chunk) {
    if (this.dead) return;
    this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
    while (!this.dead) {
      const end = this.buffer.indexOf(10);
      if (end < 0) { if (this.buffer.length > 65536) this.die('SERVICE_LINE_LIMIT'); return; }
      if (end > 65536) { this.die('SERVICE_LINE_LIMIT'); return; }
      const line = this.buffer.subarray(0, end); this.buffer = this.buffer.subarray(end + 1);
      try { this.message(JSON.parse(this.decoder.decode(line))); }
      catch (error) { this.die(/^[A-Z0-9_]+$/.test(error.message) ? error.message : 'SERVICE_INVALID_JSON'); }
    }
  }
  message(value) {
    if (!object(value) || value.schema_version !== 1 || value.generation !== this.generation || value.pair_id !== this.pairId || value.session_id !== this.sessionId || value.pid !== this.child.pid) throw fail('SERVICE_BINDING');
    const metrics = serviceMetrics(value.service_metrics);
    if (value.type === 'error') {
      if (!object(value.error) || Object.keys(value.error).length !== 1 || !/^[A-Z0-9_]{1,80}$/.test(value.error.code) || Object.hasOwn(value, 'report')) throw fail('SERVICE_ERROR_CODE');
      throw fail(value.error.code);
    }
    if (!this.ready) {
      if (value.type !== 'ready' || this.pending) throw fail('SERVICE_READY_REQUIRED');
      this.startupMetrics = serviceMetrics(value.startup_metrics);
      this.ready = true; this.metrics = metrics; this.startupMs = Date.now() - this.startedAt;
      clearTimeout(this.startupTimer); this.readyResolve(this); return;
    }
    const pending = this.pending;
    if (!pending || value.type !== 'result' || value.rpc_id !== pending.rpc.rpc_id || value.request_id !== pending.rpc.request_id || value.request_sha256 !== pending.rpc.request_sha256) throw fail('SERVICE_REQUEST_BINDING');
    if (Object.hasOwn(value, 'report') === Object.hasOwn(value, 'error') || (value.report !== undefined && !object(value.report)) || (value.error !== undefined && !object(value.error))) throw fail('SERVICE_RESULT_FIELDS');
    if (value.error && (Object.keys(value.error).length !== 1 || !/^[A-Z0-9_]{1,80}$/.test(value.error.code))) throw fail('SERVICE_ERROR_CODE');
    clearTimeout(pending.timer); this.pending = null; this.metrics = metrics;
    pending.resolve({ report: value.report, error: value.error, service_metrics: metrics });
  }
  execute(request) {
    if (this.dead || !this.ready) return Promise.reject(fail('SERVICE_UNAVAILABLE'));
    if (this.pending) return Promise.reject(fail('SERVICE_BUSY'));
    const rpc = { schema_version: 1, type: 'execute', generation: this.generation, rpc_id: randomBytes(16).toString('hex'), pair_id: this.pairId, session_id: this.sessionId, ...request };
    if (rpc.deadline_at_ms <= Date.now()) return Promise.reject(fail('REQUEST_EXPIRED'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.die('SERVICE_DEADLINE'), Math.max(1, rpc.deadline_at_ms - Date.now()));
      this.pending = { rpc, resolve, reject, timer };
      // A failed or ambiguous write is never retried; the fixed job ID remains consumed.
      try { this.child.stdin.write(`${JSON.stringify(rpc)}\n`, error => { if (error) this.die('SERVICE_PIPE_FAILED'); }); }
      catch { this.die('SERVICE_PIPE_FAILED'); }
    });
  }
}

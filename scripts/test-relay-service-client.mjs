import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { RelayServiceClient } from '../relay/RelayServiceClient.mjs';

function fixture() {
  const child = new EventEmitter(); const writes = [];
  child.pid = 42; child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.stdin = new Writable({ write(chunk, _encoding, callback) { writes.push(JSON.parse(chunk)); callback(); } });
  let spawns = 0;
  const client = new RelayServiceClient({ executable: 'mock', script: 'mock', configPath: 'mock', generation: 'a'.repeat(32), pairId: 'b'.repeat(32), sessionId: 'c'.repeat(32),
    spawnChild: () => { spawns++; return child; } });
  const envelope = { schema_version: 1, generation: 'a'.repeat(32), pair_id: 'b'.repeat(32), session_id: 'c'.repeat(32), pid: 42 };
  const emit = value => child.stdout.write(`${JSON.stringify({ ...envelope, ...value })}\n`);
  const request = { request_id: 'd'.repeat(32), request_sha256: 'e'.repeat(64), operation: 'echo_sha256', challenge_base64url: 'A'.repeat(43), timeout_ms: 30000, deadline_at_ms: Date.now() + 30000 };
  return { child, client, writes, emit, request, spawns: () => spawns };
}
let count = 0;
async function check(name, test) { await test(); count++; console.log(`PASS ${name}`); }
await check('matching response and single spawn', async () => {
  const f = fixture(); f.emit({ type: 'ready', service_metrics: { oauth_calls: 1 } }); await f.client.readyPromise;
  const pending = f.client.execute(f.request); const rpc = f.writes[0];
  f.emit({ type: 'result', rpc_id: rpc.rpc_id, request_id: rpc.request_id, request_sha256: rpc.request_sha256, report: { schema_version: 1 }, service_metrics: { cache_hits: 1 } });
  assert.equal((await pending).service_metrics.cache_hits, 1); assert.equal(f.spawns(), 1); f.child.emit('close', 0);
});
for (const field of ['generation', 'pair_id', 'session_id', 'pid', 'request_id', 'request_sha256', 'rpc_id']) await check(`reject mismatched ${field}`, async () => {
  const f = fixture(); f.emit({ type: 'ready' }); await f.client.readyPromise;
  const pending = f.client.execute(f.request); const rpc = f.writes[0];
  f.emit({ type: 'result', rpc_id: rpc.rpc_id, request_id: rpc.request_id, request_sha256: rpc.request_sha256, report: {}, [field]: 'wrong' });
  await assert.rejects(pending); await assert.rejects(f.client.execute(f.request)); assert.equal(f.writes.length, 1); assert.equal(f.spawns(), 1);
});
await check('EOF after dispatch never retries', async () => {
  const f = fixture(); f.emit({ type: 'ready' }); await f.client.readyPromise;
  const pending = f.client.execute(f.request); f.child.emit('close', 1);
  await assert.rejects(pending, /SERVICE_CLOSED/); assert.equal(f.writes.length, 1); assert.equal(f.spawns(), 1);
});
await check('truncated output fails', async () => {
  const f = fixture(); f.emit({ type: 'ready' }); await f.client.readyPromise;
  const pending = f.client.execute(f.request); f.child.stdout.write('{'); f.child.emit('close', 1);
  await assert.rejects(pending, /SERVICE_TRUNCATED/);
});
await check('line bound enforced', async () => {
  const f = fixture(); f.emit({ type: 'ready' }); await f.client.readyPromise;
  const pending = f.client.execute(f.request); f.child.stdout.write(Buffer.alloc(65537, 65));
  await assert.rejects(pending, /SERVICE_LINE_LIMIT/);
});
await check('invalid UTF8 rejected', async () => {
  const f = fixture(); const pending = f.client.readyPromise;
  f.child.stdout.write(Buffer.from([0xff, 10])); await assert.rejects(pending, /SERVICE_INVALID_JSON/);
});
await check('deadline does not resend', async () => {
  const f = fixture(); f.emit({ type: 'ready' }); await f.client.readyPromise;
  await assert.rejects(f.client.execute({ ...f.request, deadline_at_ms: Date.now() + 5 }), /SERVICE_DEADLINE/);
  assert.equal(f.writes.length, 1); assert.equal(f.spawns(), 1);
});
await check('only one active RPC', async () => {
  const f = fixture(); f.emit({ type: 'ready' }); await f.client.readyPromise;
  const pending = f.client.execute(f.request);
  await assert.rejects(f.client.execute(f.request), /SERVICE_BUSY/);
  f.child.emit('close', 1); await assert.rejects(pending); assert.equal(f.writes.length, 1);
});
await check('non numeric metrics rejected', async () => {
  const f = fixture(); f.emit({ type: 'ready', service_metrics: { token: 'secret' } });
  await assert.rejects(f.client.readyPromise, /SERVICE_METRICS/);
});
await check('malformed JSON rejected', async () => {
  const f = fixture(); const pending = f.client.readyPromise;
  f.child.stdout.write('{\n'); await assert.rejects(pending, /SERVICE_INVALID_JSON/);
});
await check('startup timeout is bounded', async () => {
  const child = new EventEmitter(); child.pid = 43; child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
  const client = new RelayServiceClient({ executable: 'mock', script: 'mock', configPath: 'mock', generation: 'a'.repeat(32), pairId: 'b'.repeat(32), sessionId: 'c'.repeat(32), spawnChild: () => child, startupMs: 5 });
  await assert.rejects(client.readyPromise, /SERVICE_READY_TIMEOUT/);
});
await check('bound startup error preserves sanitized code', async () => {
  const f = fixture(); f.emit({ type: 'error', error: { code: 'OAUTH_FAILED' } });
  await assert.rejects(f.client.readyPromise, /OAUTH_FAILED/);
});
await check('startup error cannot bypass binding', async () => {
  const f = fixture(); f.emit({ type: 'error', generation: 'wrong', error: { code: 'OAUTH_FAILED' } });
  await assert.rejects(f.client.readyPromise, /SERVICE_BINDING/);
});
console.log(`${count} protocol checks passed`);

// End-to-end server contract test. Simulates the browser client: derives an auth
// hash, uploads an encrypted library doc, uploads a chunked encrypted blob, then
// streams it back and decrypts. Run: npm test
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import assert from 'node:assert/strict';

const PORT = 8907;
const BASE = `http://127.0.0.1:${PORT}`;
const DATA_DIR = path.join(process.cwd(), 'data-test');

fs.rmSync(DATA_DIR, { recursive: true, force: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, PORT: String(PORT), DATA_DIR },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitReady() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/api/auth/me`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await sleep(100);
  }
  throw new Error(`Server did not start.\n${serverLog}`);
}

let cookie = '';
async function api(method, url, body, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (cookie) headers.Cookie = cookie;
  let payload;
  if (body !== undefined && !(body instanceof Buffer) && !(body instanceof Uint8Array)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  } else if (body !== undefined) {
    payload = body;
  }
  const res = await fetch(`${BASE}${url}`, { method, headers, body: payload, redirect: 'manual' });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  return res;
}

// ---------------------------------------------------------------- tests

const email = `test-${Date.now()}@example.com`;
const password = 'correct horse battery staple 9!';
const salt = crypto.randomBytes(16);

// Same shape the browser uses with PBKDF2: server only ever sees a one-way hash.
const authHash = crypto.scryptSync(password, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }).toString('base64');

await waitReady();
console.log('· server up');

// signup
const kdfSalt = crypto.randomBytes(16).toString('base64');
{
  const r = await api('POST', '/api/auth/signup', { email, authHash, kdfSalt });
  assert.equal(r.status, 201, `signup failed: ${r.status}`);
  const j = await r.json();
  assert.ok(j.ok && j.userId);
}

// salt endpoint returns the stored salt
{
  const r = await fetch(`${BASE}/api/auth/salt?email=${encodeURIComponent(email)}`);
  const j = await r.json();
  assert.equal(r.status, 200);
  assert.equal(j.salt, kdfSalt);
}
console.log('· salt endpoint ok');
console.log('· signup ok');

// duplicate signup rejected
{
  const r = await api('POST', '/api/auth/signup', { email, authHash: authHash.slice(0, 44) + 'A'.repeat(44) });
  assert.equal(r.status, 409);
}
console.log('· duplicate signup rejected');

// me
{
  const r = await api('GET', '/api/auth/me');
  const j = await r.json();
  assert.equal(j.user.email, email);
}
console.log('· session me ok');

// library doc: empty then round-trip
{
  let r = await api('GET', '/api/library');
  let j = await r.json();
  assert.equal(j.ct, '');

  const iv = crypto.randomBytes(12).toString('base64');
  const docCipher = crypto.randomBytes(64).toString('base64');
  r = await api('PUT', '/api/library', { salt: salt.toString('base64'), iv, ct: docCipher });
  assert.equal(r.status, 200);

  r = await api('GET', '/api/library');
  j = await r.json();
  assert.equal(j.salt, salt.toString('base64'));
  assert.equal(j.iv, iv);
  assert.equal(j.ct, docCipher);
}
console.log('· library doc round-trip ok');

// blob: init -> chunks -> finalize -> stream -> decrypt
{
  const blobId = crypto.randomBytes(12).toString('base64url');
  const plaintext = crypto.randomBytes(3 * 1024 * 1024 + 777); // spans several chunks
  const iv = crypto.randomBytes(12);
  const blobKey = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv('aes-256-gcm', blobKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const blobSalt = crypto.randomBytes(16).toString('base64');
  let r = await api('POST', `/api/blob/${blobId}/init`, { blobId, salt: blobSalt, iv: iv.toString('base64') });
  assert.equal(r.status, 200);

  const CHUNK = 4 * 1024 * 1024;
  const nChunks = Math.ceil(ct.length / CHUNK);
  for (let i = 0; i < nChunks; i++) {
    const part = ct.subarray(i * CHUNK, Math.min((i + 1) * CHUNK, ct.length));
    r = await api('PUT', `/api/blob/${blobId}/chunk/${i}`, part);
    assert.equal(r.status, 200, `chunk ${i} failed`);
  }

  r = await api('POST', `/api/blob/${blobId}/finalize`, { size: plaintext.length });
  assert.equal(r.status, 200);

  r = await api('GET', `/blob/${blobId}`);
  assert.equal(r.status, 200);
  const gotIv = Buffer.from(r.headers.get('x-blob-iv'), 'base64');
  const gotSalt = r.headers.get('x-blob-salt');
  const buf = Buffer.from(await r.arrayBuffer());
  assert.equal(buf.length, ct.length);
  assert.ok(buf.equals(ct));

  // Decrypt (ciphertext || tag, matching how the client decrypts whole-file blobs).
  const tag = buf.subarray(buf.length - 16);
  const data = buf.subarray(0, buf.length - 16);
  const dec = crypto.createDecipheriv('aes-256-gcm', blobKey, gotIv);
  dec.setAuthTag(tag);
  const out = Buffer.concat([dec.update(data), dec.final()]);
  assert.ok(out.equals(plaintext));
  assert.equal(gotSalt, blobSalt);
}
console.log('· blob chunked upload + stream + decrypt ok');

// status and delete
{
  const blobId = crypto.randomBytes(12).toString('base64url');
  await api('POST', `/api/blob/${blobId}/init`, { blobId, salt: 's'.repeat(22), iv: 'i'.repeat(16) });
  let r = await api('GET', `/api/blob/${blobId}/status`);
  let j = await r.json();
  assert.deepEqual(j, { exists: true, complete: false, chunks: 0 });

  r = await api('DELETE', `/api/blob/${blobId}`);
  assert.equal(r.status, 200);
  r = await api('GET', `/api/blob/${blobId}/status`);
  j = await r.json();
  assert.equal(j.exists, false);
}
console.log('· blob status + delete ok');

// isolation: another account cannot see or delete the first user's blob
{
  const blobId = crypto.randomBytes(12).toString('base64url');
  await api('POST', `/api/blob/${blobId}/init`, { blobId, salt: 's'.repeat(22), iv: 'i'.repeat(16) });
  await api('PUT', `/api/blob/${blobId}/chunk/0`, Buffer.from('secret'));
  await api('POST', `/api/blob/${blobId}/finalize`, { size: 6 });

  const saved = cookie;
  cookie = '';
  const r2 = await api('POST', '/api/auth/signup', {
    email: `other-${Date.now()}@example.com`,
    authHash: crypto.scryptSync('other password', crypto.randomBytes(16), 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }).toString('base64'),
    kdfSalt: crypto.randomBytes(16).toString('base64'),
  });
  assert.equal(r2.status, 201);
  let r = await api('GET', `/blob/${blobId}`);
  assert.equal(r.status, 404);
  r = await api('DELETE', `/api/blob/${blobId}`);
  assert.equal(r.status, 200); // delete is idempotent but must not touch user A's row
  r = await api('GET', `/api/blob/${blobId}/status`);
  assert.equal(r.status, 200);
  cookie = saved;

  r = await api('GET', `/api/blob/${blobId}/status`);
  const j = await r.json();
  assert.equal(j.complete, true); // user A's blob untouched
}
console.log('· per-user isolation ok');

// logout
{
  const r = await api('POST', '/api/auth/logout', {});
  assert.equal(r.status, 200);
  const r2 = await api('GET', '/api/library');
  assert.equal(r2.status, 401);
}
console.log('· logout ok');

// login + bad password
{
  const r = await api('POST', '/api/auth/login', { email, authHash });
  assert.equal(r.status, 200);
  const bad = await api('POST', '/api/auth/login', {
    email, authHash: crypto.scryptSync('wrong', crypto.randomBytes(16), 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }).toString('base64'),
  });
  assert.equal(bad.status, 401);
}
console.log('· login ok, bad password rejected');

console.log('\nAll server contract tests passed.');
server.kill('SIGTERM');
process.exit(0);

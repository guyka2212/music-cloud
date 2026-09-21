// Manual smoke run: node test/smoke.js — exercises the API like the browser does.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';

const PORT = 8915;
const BASE = `http://127.0.0.1:${PORT}`;
fs.rmSync('data-smoke', { recursive: true, force: true });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, PORT: String(PORT), DATA_DIR: 'data-smoke' },
  stdio: ['ignore', 'inherit', 'inherit'],
});
await new Promise((r) => setTimeout(r, 700));

let cookie = '';
async function api(method, url, body) {
  const headers = {};
  if (cookie) headers.Cookie = cookie;
  if (body && !(body instanceof Uint8Array)) headers['Content-Type'] = 'application/json';
  const res = await fetch(BASE + url, { method, headers, body: body instanceof Uint8Array ? body : body ? JSON.stringify(body) : undefined });
  const sc = res.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  return res;
}

const email = `smoke-${Date.now()}@example.com`;
const authHash = crypto.scryptSync('pw', crypto.randomBytes(16), 32, { N: 1024 }).toString('base64');
const kdfSalt = crypto.randomBytes(16).toString('base64');
const signupRes = await api('POST', '/api/auth/signup', { email, authHash, kdfSalt });
console.log('signup:', signupRes.status);
if (signupRes.status !== 201) { console.error('signup failed, aborting'); server.kill(); process.exit(1); }

console.log('library empty:', await (await api('GET', '/api/library')).text());
const iv = crypto.randomBytes(12).toString('base64');
console.log('library put:', (await api('PUT', '/api/library', { salt: 's'.repeat(22), iv, ct: 'AAAABBBB' })).status);
console.log('library get:', await (await api('GET', '/api/library')).text());

const blobId = crypto.randomBytes(12).toString('base64url');
const payload = crypto.randomBytes(5 * 1024 * 1024);
const b64e = (b) => b.toString('base64');
console.log('blob init:', (await api('POST', `/api/blob/${blobId}/init`, { blobId, salt: 's'.repeat(22), iv: b64e(crypto.randomBytes(12)) })).status);
for (let i = 0; i < 2; i++) {
  console.log(`chunk ${i}:`, (await api('PUT', `/api/blob/${blobId}/chunk/${i}`, payload.subarray(i * 4 * 1024 * 1024, (i + 1) * 4 * 1024 * 1024))).status);
}
console.log('finalize:', (await api('POST', `/api/blob/${blobId}/finalize`, { size: payload.length })).status);
const dl = await api('GET', `/blob/${blobId}`);
const buf = Buffer.from(await dl.arrayBuffer());
console.log('download:', dl.status, dl.headers.get('x-blob-iv') ? 'has-iv' : 'NO-IV', buf.length === payload.length ? 'size-ok' : 'SIZE-MISMATCH');

console.log('status:', await (await api('GET', `/api/blob/${blobId}/status`)).text());
console.log('index.html:', (await api('GET', '/')).status);
console.log('app.js:', (await api('GET', '/js/app.js')).status);
console.log('css:', (await api('GET', '/css/app.css')).status);
console.log('spa fallback:', (await api('GET', '/library')).status);
console.log('logout:', (await api('POST', '/api/auth/logout', {})).status);

server.kill('SIGTERM');
process.exit(0);

// End-to-end test of the shared-library GitHub driver against a mock
// Contents API. Verifies: library save/load, blob upload/download/delete,
// multi-part reassembly, duplicate-id rejection, and that all writes land
// under data/. Run: node test/gh.test.js

// ---- mock GitHub Contents API -------------------------------------------
const lstore = new Map();
globalThis.localStorage = {
  getItem: (k) => (lstore.has(k) ? lstore.get(k) : null),
  setItem: (k, v) => lstore.set(k, String(v)),
  removeItem: (k) => lstore.delete(k),
};
const files = new Map(); // path -> { content: b64 }
let commitLog = [];

function b64e(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64d(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function bodyBytes(body) {
  if (!body) return new Uint8Array();
  if (typeof body === 'string') return new TextEncoder().encode(body);
  return body instanceof Uint8Array ? body : new Uint8Array(body);
}

function jsonResponse(obj, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => obj,
    headers: { get: () => 'application/json' },
  };
}

globalThis.fetch = async (url, opts = {}) => {
  const u = new URL(url);
  const path = decodeURIComponent(u.pathname.replace(/^\/repos\/[^/]+\/[^/]+\/contents/, ''));
  const method = (opts.method || 'GET').toUpperCase();

  if (method === 'GET') {
    if (!files.has(path)) return jsonResponse({ message: 'Not Found' }, 404);
    const accept = opts.headers?.Accept || '';
    if (accept.includes('raw')) {
      const bytes = b64d(files.get(path).content);
      return { ok: true, status: 200, arrayBuffer: async () => bytes.slice().buffer, headers: { get: () => 'application/vnd.github.raw' } };
    }
    return jsonResponse({ sha: `sha-${path}`, type: 'file' });
  }

  if (method === 'PUT') {
    const body = JSON.parse(new TextDecoder().decode(bodyBytes(opts.body)));
    commitLog.push(path.replace(/^\//, ''));
    files.set(path, { content: body.content });
    return jsonResponse({ commit: { sha: 'c' + files.size } }, 201);
  }

  if (method === 'DELETE') {
    if (!files.has(path)) return jsonResponse({ message: 'Not Found' }, 404);
    files.delete(path);
    return jsonResponse({ commit: { sha: 'd' } }, 200);
  }

  return jsonResponse({ message: 'unsupported' }, 405);
};

globalThis.Headers = class Headers {
  constructor(init) { this.map = new Map(Object.entries(init || {})); }
  get(k) { return this.map.get(k) ?? null; }
};

// ---- import driver --------------------------------------------------------
const { makeGhApi } = await import('../js/gh.js');

function assert(cond, msg) {
  if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
  console.log(`ok - ${msg}`);
}

const api = makeGhApi();

// ---- library --------------------------------------------------------------
assert((await api.getLibrary()) === null, 'empty repo reports no library');

const doc = { version: 1, root: 'root', folders: { root: { id: 'root', name: 'Shared Music' } }, items: {} };
await api.saveLibrary(doc, 'mc: test init');
const back = await api.getLibrary();
assert(back && back.folders.root.name === 'Shared Music', 'library doc round-trips');
assert(files.has('/data/library.json'), 'library lives at data/library.json');

// ---- single-part blob -----------------------------------------------------
const bytes = new Uint8Array(1024).map((_, i) => i % 256);
await api.blobInit('blob-1');
await api.putChunk('blob-1', 0, bytes);
await api.blobFinalize('blob-1', bytes.length);
const got = await api.fetchBlob('blob-1');
const gotBytes = new Uint8Array(await got.arrayBuffer());
assert(gotBytes.length === bytes.length && gotBytes[5] === 5, 'blob bytes round-trip');
assert(files.has('/data/files/blob-1.json'), 'manifest at data/files/<id>.json');
assert(files.has('/data/files/blob-1/p0.enc'), 'part at data/files/<id>/p0.enc');

// ---- duplicate id rejected ------------------------------------------------
let threw = false;
try { await api.blobInit('blob-1'); } catch (e) { threw = e.status === 409; }
assert(threw, 'duplicate blob id rejected with 409');

// ---- multi-part blob ------------------------------------------------------
const part = new Uint8Array(512).map((_, i) => (i * 7) % 256);
await api.blobInit('blob-big');
for (let i = 0; i < 3; i++) await api.putChunk('blob-big', i, part);
await api.blobFinalize('blob-big', 512 * 3);
const big = await api.fetchBlob('blob-big');
const bigBytes = new Uint8Array(await big.arrayBuffer());
assert(bigBytes.length === 512 * 3, 'multi-part blob reassembles to full size');
assert(bigBytes[0] === 0 && bigBytes[512] === 0 && bigBytes[1024] === 0, 'multi-part ordering correct');

// ---- delete ---------------------------------------------------------------
await api.blobDelete('blob-1');
assert((await api.blobStatus('blob-1')).exists === false, 'blob delete removes manifest + parts');
await api.blobDelete('blob-big');
assert((await api.blobStatus('blob-big')).exists === false, 'multi-part delete works');

// ---- all writes under data/ ----------------------------------------------
assert(commitLog.length > 0 && commitLog.every((p) => p.startsWith('data/')), 'every commit is under data/');

console.log('\nAll GitHub driver tests passed.');
process.exit(0);

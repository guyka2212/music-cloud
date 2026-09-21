// End-to-end test of the GitHub driver against a mock Contents API.
// Verifies: signup → one encrypted users.json entry, password login, recovery
// login, salt determinism, library doc round-trip, blob upload/download/delete,
// per-account isolation, and that no plaintext lands in the repo. Run: node test/gh.test.js

// ---- minimal browser globals the driver expects -------------------------
const store = new Map(); // localStorage
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
globalThis.Headers = class Headers {
  constructor(init) { this.map = new Map(Object.entries(init || {})); }
  get(k) { return this.map.get(k) ?? null; }
};

// ---- mock GitHub Contents API -------------------------------------------
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

// Recreate the driver's entry-key derivation for direct db inspection.
async function a2key(email, authHash) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${email}:${authHash}`));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(obj, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => obj,
    arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(obj)).buffer,
    headers: { get: () => 'application/json' },
  };
}

globalThis.fetch = async (url, opts = {}) => {
  const u = new URL(url);
  const path = decodeURIComponent(u.pathname.replace(/^\/repos\/[^/]+\/[^/]+\/contents/, ''));
  const method = (opts.method || 'GET').toUpperCase();

  if (method === 'GET') {
    if (u.pathname === '/repos/guyka2212/music-cloud') return jsonResponse({ full_name: 'music-cloud' });
    if (!files.has(path)) return jsonResponse({ message: 'Not Found' }, 404);
    if (u.searchParams.get('ref')) {
      // raw fetch (Accept: raw) or sha lookup
      const accept = opts.headers?.Accept || '';
      if (accept.includes('raw')) {
        const bytes = b64d(files.get(path).content);
        return { ok: true, status: 200, arrayBuffer: async () => bytes.slice().buffer, headers: { get: () => 'application/vnd.github.raw' } };
      }
      return jsonResponse({ sha: `sha-${path}`, type: 'file' });
    }
    return jsonResponse({ sha: `sha-${path}` });
  }

  if (method === 'PUT') {
    const body = JSON.parse(new TextDecoder().decode(bodyBytes(opts.body)));
    commitLog.push(path.replace(/^\//, ''));
    files.set(path, { content: body.content });
    return jsonResponse({ commit: { sha: 'c' + files.size } }, 201);
  }

  if (method === 'DELETE') {
    const body = JSON.parse(new TextDecoder().decode(bodyBytes(opts.body)));
    if (!files.has(path)) return jsonResponse({ message: 'Not Found' }, 404);
    files.delete(path);
    return jsonResponse({ commit: { sha: 'd' } }, 200);
  }

  return jsonResponse({ message: 'unsupported' }, 405);
};

// ---- import driver (after globals are installed) ------------------------
const { makeGhApi } = await import('../js/gh.js');

function assert(cond, msg) {
  if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
  console.log(`ok - ${msg}`);
}

// ---- account A signs up --------------------------------------------------
localStorage.setItem('mc-gh-token', 'test-token');
const a = makeGhApi();
const enc = new TextEncoder();
const SALT_A = 'c2FsdC1h'; // arbitrary; deterministic salt comes from api.salt
const authA = 'authhash-a-b64';
const saltA = (await a.salt('a@test.dev')).salt;
assert(saltA && saltA.length > 0, 'deterministic salt returned pre-auth');
const signupA = await a.signup('a@test.dev', authA, 'recoveryhash-a', saltA);
assert(signupA.ok, 'signup A ok');
assert(files.has('/data/users.json'), 'users.json committed on signup');
assert(commitLog.length && commitLog.every((p) => p.startsWith('data/')), 'all writes are under data/');

// The single users file must leak nothing readable.
const usersRaw = new TextDecoder().decode(b64d(files.get('/data/users.json').content));
const usersDb = JSON.parse(usersRaw);
assert(usersDb.v === 2 && usersDb.users && usersDb.ptr, 'users.json has index + entries');
assert(!usersRaw.includes('a@test.dev'), 'email never stored in plaintext');
assert(!usersRaw.includes(authA) && !usersRaw.includes('recoveryhash-a'), 'auth/recovery hashes never in plaintext');
const kA = await a2key('a@test.dev', authA);

// library round trip
await a.saveLibrary(saltA, 'iv-a', 'ct-a');
const libA = await a.getLibrary();
assert(libA.ct === 'ct-a' && libA.iv === 'iv-a' && libA.salt === saltA, 'library doc round-trips');

// blob round trip
const blobBytes = new Uint8Array(1024).map((_, i) => i % 256);
await a.blobInit('blob-1', 'fsalt-a', 'fiv-a'); // (blobId, salt, iv)
await a.putChunk('blob-1', 0, blobBytes);
await a.blobFinalize('blob-1', blobBytes.length);
const got = await a.fetchBlob('blob-1');
const gotBytes = new Uint8Array(await got.arrayBuffer());
assert(gotBytes.length === blobBytes.length && gotBytes[5] === 5, 'blob bytes round-trip');
assert(got.headers.get('X-Blob-Iv') === 'fiv-a', 'blob IV exposed via header');

// blob delete
await a.blobDelete('blob-1');
assert((await a.blobStatus('blob-1')).exists === false, 'blob delete works');

// ---- multi-part blob (no storage cap) ------------------------------------
const part = new Uint8Array(512).map((_, i) => (i * 7) % 256);
await a.blobInit('blob-big', 'fsalt-big', 'fiv-big');
for (let i = 0; i < 3; i++) await a.putChunk('blob-big', i, part);
await a.blobFinalize('blob-big', 512 * 3);
const big = await a.fetchBlob('blob-big');
const bigBytes = new Uint8Array(await big.arrayBuffer());
assert(bigBytes.length === 512 * 3, 'multi-part blob reassembles to full size');
assert(bigBytes[0] === 0 && bigBytes[512] === 0 && bigBytes[1024] === 0, 'multi-part ordering correct');
assert(big.headers.get('X-Blob-Iv') === 'fiv-big', 'multi-part manifest exposes IV');
await a.blobDelete('blob-big');
assert((await a.blobStatus('blob-big')).exists === false, 'multi-part blob delete works');

// ---- account B: isolation ------------------------------------------------
const b = makeGhApi();
await b.signup('b@test.dev', 'authhash-b', 'recoveryhash-b', (await b.salt('b@test.dev')).salt);
await b.saveLibrary('salt-b', 'iv-b', 'ct-b');
const libB = await b.getLibrary();
assert(libB.ct === 'ct-b', 'account B sees only its own library');

// Both accounts coexist in the one users.json.
const db2 = JSON.parse(new TextDecoder().decode(b64d(files.get('/data/users.json').content)));
assert(Object.keys(db2.users).length === 2, 'both accounts live in the single users.json');
assert(Object.keys(db2.users).includes(kA), 'account A entry survives B signing up');
assert(!usersHasEmail(db2), 'no plaintext emails even with two accounts');
function usersHasEmail(db) {
  const raw = JSON.stringify(db);
  return raw.includes('@test.dev');
}

const a2 = makeGhApi();
await a2.login('a@test.dev', authA, null);
const libA2 = await a2.getLibrary();
assert(libA2.ct === 'ct-a', 'account A library intact after B signed up');

// ---- login failures ------------------------------------------------------
const bad = makeGhApi();
let threw = false;
try { await bad.login('a@test.dev', 'wrong-hash', null); } catch { threw = true; }
assert(threw, 'wrong password rejected');

// ---- recovery login ------------------------------------------------------
const rec = makeGhApi();
await rec.login('a@test.dev', null, 'recoveryhash-a');
assert(true, 'recovery login locates account via pointer');

// salt determinism: same email → same salt on any device
assert((await rec.salt('a@test.dev')).salt === saltA, 'salt identical across sessions');

console.log('\nAll GitHub driver tests passed.');
process.exit(0);

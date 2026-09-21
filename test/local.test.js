// End-to-end test for the local (IndexedDB) driver used on static hosting.
// Runs the real js/api.js in Node with a minimal in-memory indexedDB fake.
import assert from 'node:assert/strict';

// ---- minimal indexedDB fake -------------------------------------------------

class FakeRequest {
  constructor(result) {
    this._result = result;
    this._listeners = { success: [], error: [] };
    this._fired = false;
  }
  _fire(kind) {
    if (this._fired) return;
    this._fired = true;
    const ev = { target: this };
    for (const fn of this._listeners[kind]) fn(ev);
  }
  // IDB events fire async after the handler is attached.
  addEventListener(kind, fn) {
    this._listeners[kind].push(fn);
    setTimeout(() => this._fire(kind), 0);
  }
  set onsuccess(fn) { this.addEventListener('success', fn); }
  set onerror(fn) { this.addEventListener('error', fn); }
  get result() { return this._result; }
  get error() { return null; }
}

function fakeStore(name, data, keys) {
  const keyFor = (obj) => (keys.length === 1 ? obj[keys[0]] : keys.map((k) => obj[k]));
  const api = {
    get(key) {
      const hit = data.get(JSON.stringify(key));
      return new FakeRequest(hit ? structuredClone(hit) : undefined);
    },
    put(obj) {
      data.set(JSON.stringify(keyFor(obj)), structuredClone(obj));
      return new FakeRequest(obj);
    },
    delete(key) {
      data.delete(JSON.stringify(key));
      return new FakeRequest(undefined);
    },
    openCursor() {
      const values = [...data.values()];
      let pos = 0;
      const makeCursorReq = () => new FakeRequest(pos < values.length ? {
        value: structuredClone(values[pos]),
        continue() { pos += 1; return makeCursorReq(); },
      } : null);
      return makeCursorReq();
    },
  };
  return api;
}

const stores = {
  users: { data: new Map(), keys: ['email'] },
  library: { data: new Map(), keys: ['email'] },
  blobs: { data: new Map(), keys: ['email', 'id'] },
  chunks: { data: new Map(), keys: ['email', 'id', 'idx'] },
  meta: { data: new Map(), keys: ['key'] },
};

globalThis.indexedDB = {
  open() {
    const db = {
      objectStoreNames: { contains: () => true },
      transaction(name, _mode) {
        const s = stores[name];
        return { objectStore: () => fakeStore(name, s.data, s.keys) };
      },
    };
    // FakeRequest fires onsuccess automatically when the handler is attached.
    return new FakeRequest(db);
  },
};

globalThis.Headers = class Headers {
  constructor(init) { this.map = new Map(Object.entries(init)); }
  get(k) { return this.map.get(k.toLowerCase()) ?? this.map.get(k) ?? null; }
};
globalThis.localStorage = {
  _m: new Map(),
  getItem(k) { return this._m.get(k) ?? null; },
  setItem(k, v) { this._m.set(k, String(v)); },
  removeItem(k) { this._m.delete(k); },
};

globalThis.fetch = async () => { throw new Error('no network in local test'); };

// ---- run the driver ---------------------------------------------------------

const { selectBackend, api } = await import('../js/api.js');

// Force local selection without touching the real probe path.
localStorage.setItem('mc-backend', 'local');
const backend = await selectBackend();
assert.equal(backend.kind, 'local');
console.log('· local driver selected');

const email = 'local-test@example.com';
const authHash = 'A'.repeat(44);
const kdfSalt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64');

{
  const r = await api.signup(email, authHash, 'recovery-hash-abc', kdfSalt);
  assert.ok(r.ok);
  await assert.rejects(() => api.signup(email, authHash, null, kdfSalt), /already exists/);
}
console.log('· signup + duplicate rejected');

{
  const me = await api.me();
  assert.equal(me.user.email, email);
  const r = await api.login(email, authHash, null);
  assert.ok(r.ok);
  await assert.rejects(() => api.login(email, 'B'.repeat(44), null), /Incorrect/);
  await assert.rejects(() => api.login('nobody@example.com', authHash, null), /Incorrect/);
}
console.log('· login + wrong password rejected');

{
  assert.deepEqual(await api.getLibrary(), { salt: '', iv: '', ct: '' });
  await api.saveLibrary(kdfSalt, 'iv==', 'ct==');
  const doc = await api.getLibrary();
  assert.equal(doc.salt, kdfSalt);
  assert.equal(doc.iv, 'iv==');
}
console.log('· library doc round-trip');

{
  const blobId = 'b_localtest12345';
  const iv = Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64');
  await api.blobInit(blobId, kdfSalt, iv);
  const bigRandom = (n) => {
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += 65536) crypto.getRandomValues(out.subarray(o, Math.min(o + 65536, n)));
    return out;
  };
  const part1 = bigRandom(300_000);
  const part2 = bigRandom(200_001);
  await api.putChunk(blobId, 0, part1);
  await api.putChunk(blobId, 1, part2);
  await api.blobFinalize(blobId, part1.length + part2.length);
  const res = await api.fetchBlob(blobId);
  const buf = new Uint8Array(await res.arrayBuffer());
  assert.equal(buf.length, part1.length + part2.length);
  assert.deepEqual(Array.from(buf.subarray(0, 10)), Array.from(part1.subarray(0, 10)));
  assert.deepEqual(Array.from(buf.subarray(300_000, 300_010)), Array.from(part2.subarray(0, 10)));
  assert.equal(res.headers.get('X-Blob-Iv'), iv);
  const status = await api.blobStatus(blobId);
  assert.equal(status.complete, true);
  await api.blobDelete(blobId);
  await assert.rejects(() => api.fetchBlob(blobId), /not found/i);
}
console.log('· blob init/chunk/finalize/fetch/delete');

{
  // Second account must not see the first account's data.
  await api.signup('other@example.com', 'C'.repeat(44), null, kdfSalt);
  await api.saveLibrary('othersalt', 'oiv', 'oct');
  localStorage.setItem('mc-local-session', email);
  const doc = await api.getLibrary();
  assert.equal(doc.salt, kdfSalt); // unchanged by other user's save
  await api.logout();
  await assert.rejects(() => api.getLibrary(), /Authentication required/);
}
console.log('· per-account isolation + logout');

console.log('\nAll local driver tests passed.');
process.exit(0);

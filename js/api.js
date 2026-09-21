// Data layer. Two interchangeable backends behind one interface:
//
//   server — the zero-dependency Node server in /server (self-hosting).
//   local  — everything in the browser: users, library docs, and encrypted
//            blobs live in IndexedDB. Used on static hosting (GitHub Pages)
//            where no backend can run.
//
// Selection: localStorage 'mc-backend' = 'server' | 'local' | 'auto' (default).
// In auto mode we probe the server once at boot.

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/* ================================================================ server driver */

async function serverRequest(method, url, body, opts = {}) {
  const headers = {};
  let payload;
  if (body !== undefined && body !== null) {
    if (body instanceof Uint8Array || body instanceof ArrayBuffer || body instanceof Blob) {
      payload = body;
    } else {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
  }
  const res = await fetch(url, { method, headers, body: payload, signal: opts.signal, credentials: 'same-origin' });
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch { /* non-JSON error body */ }
    throw new ApiError(res.status, msg);
  }
  return res;
}

function makeServerApi() {
  return {
    kind: 'server',
    async probe() {
      try {
        const r = await fetch('/api/auth/me', { credentials: 'same-origin' });
        // A real server answers JSON. A static host's SPA fallback answers
        // 200 with HTML — that must NOT count as a server.
        return (r.headers.get('content-type') || '').includes('application/json');
      } catch { return false; }
    },
    signup: (email, authHash, recoveryHash, kdfSalt) =>
      serverRequest('POST', '/api/auth/signup', { email, authHash, recoveryHash, kdfSalt }),
    login: (email, authHash, recoveryHash) =>
      serverRequest('POST', '/api/auth/login', { email, authHash: authHash || '', recoveryHash }),
    logout: () => serverRequest('POST', '/api/auth/logout', {}),
    me: () => serverRequest('GET', '/api/auth/me').then((r) => r.json()),
    salt: (email) => serverRequest('GET', `/api/auth/salt?email=${encodeURIComponent(email)}`).then((r) => r.json()),
    getLibrary: () => serverRequest('GET', '/api/library').then((r) => r.json()),
    saveLibrary: (salt, iv, ct) => serverRequest('PUT', '/api/library', { salt, iv, ct }),
    blobInit: (blobId, salt, iv) => serverRequest('POST', `/api/blob/${blobId}/init`, { blobId, salt, iv }),
    putChunk: (blobId, idx, bytes, signal) => serverRequest('PUT', `/api/blob/${blobId}/chunk/${idx}`, bytes, { signal }),
    blobFinalize: (blobId, size) => serverRequest('POST', `/api/blob/${blobId}/finalize`, { size }),
    blobStatus: (blobId) => serverRequest('GET', `/api/blob/${blobId}/status`).then((r) => r.json()),
    blobDelete: (blobId) => serverRequest('DELETE', `/api/blob/${blobId}`),
    fetchBlob: (blobId) => serverRequest('GET', `/blob/${blobId}`),
  };
}

/* ================================================================ local driver (IndexedDB) */

const DB_NAME = 'music-cloud';
const DB_VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('users')) {
        db.createObjectStore('users', { keyPath: 'email' });
      }
      if (!db.objectStoreNames.contains('library')) {
        db.createObjectStore('library', { keyPath: 'email' });
      }
      if (!db.objectStoreNames.contains('blobs')) {
        const s = db.createObjectStore('blobs', { keyPath: ['email', 'id'] });
        s.createIndex('byEmail', 'email');
      }
      if (!db.objectStoreNames.contains('chunks')) {
        db.createObjectStore('chunks', { keyPath: ['email', 'id', 'idx'] });
      }
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta', { keyPath: 'key' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

let dbPromise = null;
function idb() {
  if (!dbPromise) dbPromise = openDb();
  return dbPromise;
}

function tx(store, mode, fn) {
  return idb().then((db) => new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const out = fn(t.objectStore(store));
    if (out && typeof out.then === 'function') {
      // Async callback managing its own requests.
      out.then(resolve, reject);
    } else if (out && typeof out.addEventListener === 'function') {
      out.addEventListener('success', () => resolve(out.result));
      out.addEventListener('error', () => reject(out.error));
    } else {
      resolve(out); // sync callback
    }
  }));
}

function b64FromBytes(bytes) {
  let s = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

function bytesFromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
void bytesFromB64;

// Static hosting (GitHub Pages etc.) can never serve the API — skip probing
// entirely there so a 200-HTML fallback can't fool the server driver.
function isStaticHost() {
  try {
    const h = globalThis.location.hostname;
    return h === 'github.io' || h.endsWith('.github.io');
  } catch {
    return false;
  }
}

const SESSION_KEY = 'mc-local-session';

function makeLocalApi() {
  const currentEmail = () => localStorage.getItem(SESSION_KEY);

  const requireAuth = () => {
    const email = currentEmail();
    if (!email) throw new ApiError(401, 'Authentication required');
    return email;
  };

  return {
    kind: 'local',
    async probe() { return true; },

    async signup(emailIn, authHash, recoveryHash, kdfSalt) {
      const email = String(emailIn || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(400, 'Enter a valid email address.');
      await tx('users', 'readwrite', (s) => s.get(email)).then(async (existing) => {
        if (existing) throw new ApiError(409, 'An account with this email already exists.');
      });
      const user = {
        email, authHash, recoveryHash: recoveryHash || null, kdfSalt: kdfSalt || '',
        createdAt: Date.now(),
      };
      await tx('users', 'readwrite', (s) => s.put(user));
      localStorage.setItem(SESSION_KEY, email);
      return { ok: true, userId: email };
    },

    async login(emailIn, authHash, recoveryHash) {
      const email = String(emailIn || '').trim().toLowerCase();
      const user = await tx('users', 'readonly', (s) => s.get(email));
      if (!user) throw new ApiError(401, 'Incorrect email or password.');
      const ok = (authHash && authHash === user.authHash)
        || (recoveryHash && user.recoveryHash && recoveryHash === user.recoveryHash);
      if (!ok) throw new ApiError(401, 'Incorrect email or password.');
      localStorage.setItem(SESSION_KEY, email);
      return { ok: true };
    },

    async logout() {
      localStorage.removeItem(SESSION_KEY);
      return { ok: true };
    },

    async me() {
      const email = currentEmail();
      if (!email) return { user: null };
      const user = await tx('users', 'readonly', (s) => s.get(email));
      return { user: user ? { id: email, email, createdAt: user.createdAt } : null };
    },

    async salt(emailIn) {
      const email = String(emailIn || '').trim().toLowerCase();
      const user = await tx('users', 'readonly', (s) => s.get(email));
      if (!user) throw new ApiError(404, 'No account with that email.');
      return { salt: user.kdfSalt };
    },

    async getLibrary() {
      const email = requireAuth();
      const row = await tx('library', 'readonly', (s) => s.get(email));
      return row ? { salt: row.salt, iv: row.iv, ct: row.ct } : { salt: '', iv: '', ct: '' };
    },

    async saveLibrary(salt, iv, ct) {
      const email = requireAuth();
      await tx('library', 'readwrite', (s) => s.put({ email, salt, iv, ct, updatedAt: Date.now() }));
      return { ok: true };
    },

    async blobInit(blobId, salt, iv) {
      const email = requireAuth();
      await tx('blobs', 'readwrite', async (s) => {
        const existing = await wrap(s.get([email, blobId]));
        if (existing && existing.complete) throw new ApiError(409, 'Blob id already used.');
        s.put({
          email, id: blobId, salt, iv, ct: null, complete: 0, createdAt: Date.now(),
        });
      });
      return { ok: true };
    },

    async putChunk(blobId, idx, bytes) {
      const email = requireAuth();
      await tx('chunks', 'readwrite', (s) =>
        s.put({ email, id: blobId, idx, data: bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes) }));
      return { ok: true };
    },

    async blobFinalize(blobId, size) {
      const email = requireAuth();
      const chunks = await tx('chunks', 'readonly', (s) =>
        collectCursor(s.openCursor(), (v) => v.email === email && v.id === blobId));
      chunks.sort((a, b) => a.idx - b.idx);
      if (!chunks.length) throw new ApiError(400, 'No chunks uploaded.');
      const parts = chunks.map((c) => c.data);
      const total = parts.reduce((n, p) => n + p.length, 0);
      const merged = new Uint8Array(total);
      let o = 0;
      for (const p of parts) { merged.set(p, o); o += p.length; }
      const existing = await tx('blobs', 'readonly', (s) => s.get([email, blobId]));
      await tx('blobs', 'readwrite', (s) =>
        s.put({ email, id: blobId, salt: existing ? existing.salt : '', iv: existing ? existing.iv : '', ct: merged, complete: 1, size, createdAt: Date.now() }));
      await tx('chunks', 'readwrite', (s) => {
        chunks.forEach((c) => s.delete([email, blobId, c.idx]));
      });
      return { ok: true };
    },

    async blobStatus(blobId) {
      const email = requireAuth();
      const row = await tx('blobs', 'readonly', (s) => s.get([email, blobId]));
      return { exists: Boolean(row), complete: Boolean(row && row.complete), chunks: 0 };
    },

    async blobDelete(blobId) {
      const email = requireAuth();
      await tx('blobs', 'readwrite', (s) => s.delete([email, blobId]));
      // Sweep any orphaned chunks for this blob (no per-blob index; fine at this scale).
      const stale = await tx('chunks', 'readonly', (s) =>
        collectCursor(s.openCursor(), (v) => v.email === email && v.id === blobId));
      await tx('chunks', 'readwrite', (s) => {
        stale.forEach((c) => s.delete([email, blobId, c.idx]));
      });
      return { ok: true };
    },

    async fetchBlob(blobId) {
      const email = requireAuth();
      const row = await tx('blobs', 'readonly', (s) => s.get([email, blobId]));
      if (!row || !row.complete) throw new ApiError(404, 'Blob not found');
      // The IV may have been stored as raw bytes or as base64 depending on the
      // writer; normalize to base64 like the server driver exposes it.
      const iv = typeof row.iv === 'string'
        ? row.iv
        : b64FromBytes(row.iv);
      return {
        ok: true,
        headers: new Headers({ 'X-Blob-Iv': iv, 'X-Blob-Salt': row.salt || '' }),
        arrayBuffer: async () => row.ct.buffer.slice(row.ct.byteOffset, row.ct.byteOffset + row.ct.byteLength),
      };
    },
  };
}

// Wrap a single IDBRequest into a promise.
function wrap(request) {
  return new Promise((resolve, reject) => {
    request.addEventListener('success', () => resolve(request.result));
    request.addEventListener('error', () => reject(request.error));
  });
}

// Walk an IDB cursor request to exhaustion, collecting values that pass the
// filter. Resolves with an array; safe with both real IDB and the test fake.
function collectCursor(request, filter) {
  return new Promise((resolve, reject) => {
    const out = [];
    const step = (req) => {
      req.addEventListener('success', () => {
        const cursor = req.result;
        if (!cursor) { resolve(out); return; }
        if (!filter || filter(cursor.value)) out.push(cursor.value);
        step(cursor.continue());
      });
      req.addEventListener('error', () => reject(req.error));
    };
    step(request);
  });
}

/* ================================================================ driver selection */

let active = null;
let probing = null;

export function backendKind() {
  return active ? active.kind : (localStorage.getItem('mc-backend') || 'auto');
}

export async function selectBackend() {
  if (active) return active;
  if (!probing) {
    probing = (async () => {
      const pref = localStorage.getItem('mc-backend') || 'auto';
      if (pref === 'local') return makeLocalApi();
      if (pref === 'server' && !isStaticHost()) return makeServerApi();
      if (pref === 'server') {
        // Requested server mode on a static host: server cannot exist.
        return makeLocalApi();
      }
      if (isStaticHost()) return makeLocalApi();
      const server = makeServerApi();
      const serverUp = await server.probe();
      return serverUp ? server : makeLocalApi();
    })();
  }
  active = await probing;
  return active;
}

// Re-export a proxy so `api.signup(...)` resolves against the selected driver.
export const api = new Proxy({}, {
  get(_t, prop) {
    if (!active) {
      throw new Error('Backend not selected yet — call selectBackend() first.');
    }
    const v = active[prop];
    return typeof v === 'function' ? v.bind(active) : v;
  },
});

export { ApiError };

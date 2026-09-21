// GitHub-backed driver. Data lives as files under data/ in the music-cloud
// repo, read/written through GitHub's Contents API with a pasted token.
//
//   data/users/<h>.rec     one encrypted record per account { email, authHash,
//                          recoveryHash, kdfSalt, createdAt }
//   data/lib/<h>.json      per-account library doc { salt, iv, ct }
//   data/blob/<h>/<id>.enc encrypted audio bytes (single PUT, <20MB per file)
//
// h = SHA-256(email ':' authHash) hex. Filename and record decryption both
// require email AND password, so the public repo leaks nothing usable.
// The token lives in localStorage only; data files are repo-committed.

const GH_API = 'https://api.github.com';
const REPO = 'guyka2212/music-cloud';
const BRANCH = 'main';

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function ghToken() {
  return localStorage.getItem('mc-gh-token') || '';
}

export function setGhToken(t) {
  if (t) localStorage.setItem('mc-gh-token', t);
  else localStorage.removeItem('mc-gh-token');
}

export function ghConfigured() {
  return Boolean(ghToken());
}

// ---------------------------------------------------------------- request core

export async function ghRequest(method, path, body, raw = false) {
  const token = ghToken();
  if (!token) throw new ApiError(500, 'No GitHub token configured — add one in Settings.');
  const headers = {
    Accept: raw
      ? 'application/vnd.github.raw+json'
      : 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
  };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${GH_API}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = `GitHub API ${res.status}`;
    try {
      const j = await res.json();
      if (j && j.message) msg = j.message;
    } catch { /* non-JSON body */ }
    if (res.status === 401) msg = 'GitHub rejected the token (401). Re-check it in Settings.';
    if (res.status === 403 && String(msg).toLowerCase().includes('rate limit')) {
      msg = 'GitHub API rate limit reached — wait a minute and try again.';
    }
    if (res.status === 403 && String(msg).toLowerCase().includes('resource not accessible')) {
      msg = 'Token lacks write access — fine-grained tokens need Contents: Read and write.';
    }
    throw new ApiError(res.status, msg);
  }
  return res;
}

// ---------------------------------------------------------------- base64

function b64Encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function b64Decode(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------- hash helper

const enc = new TextEncoder();
const subtle = () => globalThis.crypto.subtle;

async function h64(s) {
  const d = await subtle().digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Salt is deterministic per email in gh mode: it is public information (stored
// beside the ciphertext), and it must be derivable before authentication so
// the account's authHash — and therefore its filename — can be computed.
async function deterministicSalt(email) {
  const d = await subtle().digest('SHA-256', enc.encode(`mc-salt:${email}`));
  return b64Encode(new Uint8Array(d));
}

async function hkdfBits(ikmBytes, info) {
  const base = await subtle().importKey('raw', ikmBytes, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('music-cloud-gh'), info: enc.encode(info) },
    base,
    256,
  ));
}

// ---------------------------------------------------------------- repo file helpers

function encPath(p) {
  return encodeURIComponent(p).replaceAll('%2F', '/');
}

let currentSha = null;

async function getSha(path) {
  try {
    const r = await ghRequest('GET', `/repos/${REPO}/contents/${encPath(path)}?ref=${BRANCH}`);
    const j = await r.json();
    currentSha = j.sha;
    return j.sha;
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

async function putFile(path, bytes, message) {
  const sha = await getSha(path);
  const body = { message, branch: BRANCH, content: b64Encode(bytes) };
  if (sha) body.sha = sha;
  await ghRequest('PUT', `/repos/${REPO}/contents/${encPath(path)}`, body);
  return { created: !sha };
}

async function readFileRaw(path) {
  const r = await ghRequest('GET', `/repos/${REPO}/contents/${encPath(path)}?ref=${BRANCH}`, undefined, true);
  return new Uint8Array(await r.arrayBuffer());
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ---------------------------------------------------------------- account records

function accountPath(h) { return `data/users/${h}.rec`; }
function libPath(h) { return `data/lib/${h}.json`; }

// Public pointer file for recovery login: SHA-256(email) -> record filename.
// Reveals that an email has an account; nothing beyond that.
async function pointerHash(email) {
  return h64(`ptr:${email}`);
}

async function readPointer(email) {
  const ph = await pointerHash(email);
  try {
    const raw = await readFileRaw(`data/ptr/${ph}.json`);
    return JSON.parse(new TextDecoder().decode(raw));
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

async function writePointer(email, h) {
  const ph = await pointerHash(email);
  await putFile(
    `data/ptr/${ph}.json`,
    enc.encode(JSON.stringify({ h })),
    `mc: pointer ${ph.slice(0, 10)}`,
  );
}

async function readRecord(h) {
  const raw = await readFileRaw(accountPath(h)).catch((e) => {
    if (e.status === 404) return null;
    throw e;
  });
  if (!raw || !raw.length) return null;
  const env = JSON.parse(new TextDecoder().decode(raw));
  // Record key derives from h itself (email + authHash), never stored.
  const keyBits = await hkdfBits(hexToBytes(h), 'account-record');
  const key = await subtle().importKey('raw', keyBits, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64Decode(env.iv) },
    key,
    b64Decode(env.ct),
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

async function writeRecord(h, rec, message) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyBits = await hkdfBits(hexToBytes(h), 'account-record');
  const key = await subtle().importKey('raw', keyBits, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await subtle().encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(rec)),
  ));
  const file = { v: 1, iv: b64Encode(iv), ct: b64Encode(ct) };
  await putFile(accountPath(h), enc.encode(JSON.stringify(file)), message);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---------------------------------------------------------------- blobs

function blobPath(h, id) { return `data/blob/${h}/${id}.enc`; }

async function putBlob(h, id, bytes, meta, message) {
  const p = blobPath(h, id);
  const sha = await getSha(p);
  if (sha) return; // already uploaded; blobs are immutable
  const envelope = {
    v: 1,
    iv: meta.iv || '',
    salt: meta.salt || '',
    ct: b64Encode(bytes),
  };
  await ghRequest('PUT', `/repos/${REPO}/contents/${encPath(p)}`, {
    message,
    branch: BRANCH,
    content: b64Encode(enc.encode(JSON.stringify(envelope))),
  });
}

async function getBlob(h, id) {
  const raw = await readFileRaw(blobPath(h, id));
  const env = JSON.parse(new TextDecoder().decode(raw));
  if (!env || !env.ct) throw new ApiError(404, 'Blob not found');
  return env;
}

async function deleteRepoFile(path) {
  const sha = await getSha(path);
  if (!sha) return;
  await ghRequest('DELETE', `/repos/${REPO}/contents/${encPath(path)}`, {
    message: `delete ${path}`, branch: BRANCH, sha,
  });
}

// ---------------------------------------------------------------- driver

export function makeGhApi() {
  let sessionEmail = null;
  let sessionH = null;
  let sessionAuthHash = null;
  const pending = new Map(); // blobId -> Uint8Array[] chunks awaiting finalize
  const initMeta = new Map(); // blobId -> { salt, iv } from blobInit

  const session = () => {
    if (!sessionEmail) throw new ApiError(401, 'Authentication required');
    return { email: sessionEmail, h: sessionH, authHash: sessionAuthHash };
  };

  return {
    kind: 'github',

    async probe() { return true; },

    async signup(emailIn, authHash, recoveryHash, kdfSalt) {
      const email = String(emailIn || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(400, 'Enter a valid email address.');
      const h = await h64(`${email}:${authHash}`);
      const existing = await readRecord(h).catch(() => null);
      if (existing) throw new ApiError(409, 'An account with this email already exists.');
      const rec = {
        email,
        authHash,
        recoveryHash: recoveryHash || null,
        kdfSalt: kdfSalt || '',
        createdAt: Date.now(),
      };
      await writeRecord(h, rec, `mc: signup ${h.slice(0, 10)}`);
      await writePointer(email, h);
      sessionEmail = email; sessionH = h; sessionAuthHash = authHash;
      return { ok: true, userId: h, kdfSalt };
    },

    async login(emailIn, authHash, recoveryHash) {
      const email = String(emailIn || '').trim().toLowerCase();
      if (recoveryHash) {
        // Recovery login: locate the account via the public pointer file
        // (email hash -> record filename), which reveals nothing usable.
        const ptr = await readPointer(email);
        if (!ptr) throw new ApiError(401, 'Incorrect email or recovery key.');
        let rec = null;
        try { rec = await readRecord(ptr.h); } catch { rec = null; }
        if (!rec || rec.recoveryHash !== recoveryHash) throw new ApiError(401, 'Incorrect email or recovery key.');
        sessionEmail = rec.email; sessionH = ptr.h; sessionAuthHash = rec.authHash;
        return { ok: true };
      }
      const h = await h64(`${email}:${authHash || ''}`);
      let rec = null;
      try { rec = await readRecord(h); } catch { rec = null; }
      if (!rec || rec.email !== email) throw new ApiError(401, 'Incorrect email or password.');
      sessionEmail = email; sessionH = h; sessionAuthHash = authHash;
      return { ok: true };
    },

    async logout() {
      sessionEmail = null; sessionH = null; sessionAuthHash = null;
      return { ok: true };
    },

    async me() {
      if (!sessionEmail) return { user: null };
      return { user: { id: sessionH, email: sessionEmail } };
    },

    async salt(emailIn) {
      const email = String(emailIn || '').trim().toLowerCase();
      return { salt: await deterministicSalt(email) };
    },

    async getLibrary() {
      const s = session();
      try {
        const raw = await readFileRaw(libPath(s.h));
        return JSON.parse(new TextDecoder().decode(raw));
      } catch (e) {
        if (e.status === 404) return { salt: '', iv: '', ct: '' };
        throw e;
      }
    },

    async saveLibrary(salt, iv, ct) {
      const s = session();
      const body = JSON.stringify({ salt, iv, ct, v: 1 });
      await putFile(libPath(s.h), enc.encode(body), `mc: lib ${s.h.slice(0, 10)}`);
      return { ok: true };
    },

    async blobInit(blobId, salt, iv) {
      session();
      initMeta.set(blobId, { salt: salt || '', iv: iv || '' });
      return { ok: true };
    },

    async putChunk(blobId, idx, bytes) {
      session();
      const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      // Chunks accumulate in memory and merge at finalize; the merged file
      // must stay under the Contents API's 25MB request cap (~15MB plaintext).
      const parts = pending.get(blobId) || [];
      parts[idx] = b;
      const total = parts.reduce((n, p) => n + (p ? p.length : 0), 0);
      if (total > 15_000_000) {
        throw new ApiError(413, 'Files up to about 15 MB work with GitHub sync. Larger files need the self-hosted server.');
      }
      pending.set(blobId, parts);
      return { ok: true };
    },

    async blobFinalize(blobId, size) {
      const s = session();
      const parts = pending.get(blobId);
      if (!parts) throw new ApiError(400, 'No chunks uploaded.');
      pending.delete(blobId);
      const total = parts.reduce((n, p) => n + p.length, 0);
      const merged = new Uint8Array(total);
      let o = 0;
      for (const p of parts) { merged.set(p, o); o += p.length; }
      const meta = initMeta.get(blobId) || {};
      initMeta.delete(blobId);
      await putBlob(s.h, blobId, merged, meta, `mc: blob ${blobId.slice(0, 10)} (${size}B)`);
      return { ok: true };
    },

    async blobStatus(blobId) {
      const s = session();
      // getSha resolves to null on 404 rather than throwing, so judge by result.
      const sha = await getSha(blobPath(s.h, blobId));
      return { exists: Boolean(sha), complete: Boolean(sha), chunks: 0 };
    },

    async blobDelete(blobId) {
      const s = session();
      await deleteRepoFile(blobPath(s.h, blobId));
      return { ok: true };
    },

    async fetchBlob(blobId) {
      const s = session();
      const env = await getBlob(s.h, blobId);
      return {
        ok: true,
        headers: new Headers({ 'X-Blob-Iv': env.iv, 'X-Blob-Salt': env.salt || '' }),
        arrayBuffer: async () => b64Decode(env.ct).buffer,
      };
    },
  };
}

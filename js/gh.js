// GitHub-backed shared library driver. There are no user accounts: the whole
// library is ONE public JSON document plus file blobs under data/ in the
// music-cloud repo.
//
//   data/library.json        the entire library (folders, items, metadata)
//   data/files/<id>.json     manifest { v, size, parts }
//   data/files/<id>/pN.enc   file bytes in ~4MB parts
//
// Anyone can READ (raw Contents fetches, no token needed). WRITES go through
// the Contents API and require a token stored in this browser only.

const GH_API = 'https://api.github.com';
export const REPO = 'guyka2212/music-cloud';
export const BRANCH = 'main';

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

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------------------------------------------------------------- request core

export async function ghRequest(method, path, body, raw = false) {
  const headers = {
    Accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json',
  };
  const token = ghToken();
  if (token) headers.Authorization = `Bearer ${token}`;
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
      msg = 'Write denied — add a token with “Contents: Read and write” (key icon, bottom left).';
    }
    throw new ApiError(res.status, msg);
  }
  return res;
}

// ---------------------------------------------------------------- base64 + repo files

function b64Encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

const enc = new TextEncoder();

function encPath(p) {
  return encodeURIComponent(p).replaceAll('%2F', '/');
}

async function getSha(path) {
  try {
    const r = await ghRequest('GET', `/repos/${REPO}/contents/${encPath(path)}?ref=${BRANCH}`);
    const j = await r.json();
    return j.sha;
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

export async function readFileRaw(path) {
  const r = await ghRequest('GET', `/repos/${REPO}/contents/${encPath(path)}?ref=${BRANCH}`, undefined, true);
  return new Uint8Array(await r.arrayBuffer());
}

export async function putFile(path, bytes, message) {
  const sha = await getSha(path);
  const body = { message, branch: BRANCH, content: b64Encode(bytes) };
  if (sha) body.sha = sha;
  await ghRequest('PUT', `/repos/${REPO}/contents/${encPath(path)}`, body);
  return { created: !sha };
}

async function deleteRepoFile(path) {
  const sha = await getSha(path);
  if (!sha) return;
  await ghRequest('DELETE', `/repos/${REPO}/contents/${encPath(path)}`, {
    message: `delete ${path}`, branch: BRANCH, sha,
  });
}

// ---------------------------------------------------------------- driver

const LIBRARY_PATH = 'data/library.json';
const filesPath = (id) => `data/files/${id}.json`;
const partPath = (id, i) => `data/files/${id}/p${i}.enc`;

export function makeGhApi() {
  return {
    kind: 'github',

    async probe() { return true; },

    async getLibrary() {
      try {
        const raw = await readFileRaw(LIBRARY_PATH);
        return JSON.parse(new TextDecoder().decode(raw));
      } catch (e) {
        if (e.status === 404) return null;
        throw e;
      }
    },

    async saveLibrary(docObj, message) {
      await putFile(LIBRARY_PATH, enc.encode(JSON.stringify(docObj)), message || 'mc: update library');
      return { ok: true };
    },

    async blobInit(blobId) {
      const sha = await getSha(filesPath(blobId));
      if (sha) throw new ApiError(409, 'A file with this id already exists.');
      return { ok: true };
    },

    async putChunk(blobId, idx, bytes) {
      const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      await putFile(partPath(blobId, idx), b, `mc: part ${blobId.slice(0, 10)}#${idx}`);
      return { ok: true };
    },

    async blobFinalize(blobId, size) {
      // Verify every part landed before publishing the manifest.
      let parts = 0;
      while (await getSha(partPath(blobId, parts))) parts++;
      if (!parts) throw new ApiError(400, 'No chunks uploaded.');
      await putFile(filesPath(blobId), enc.encode(JSON.stringify({ v: 1, size: size || 0, parts })), `mc: add ${blobId.slice(0, 10)}`);
      return { ok: true };
    },

    async blobStatus(blobId) {
      const sha = await getSha(filesPath(blobId));
      return { exists: Boolean(sha), complete: Boolean(sha), chunks: 0 };
    },

    async blobDelete(blobId) {
      await deleteRepoFile(filesPath(blobId));
      for (let i = 0; i < 10_000; i++) {
        if (!(await getSha(partPath(blobId, i)))) break;
        await deleteRepoFile(partPath(blobId, i));
      }
      return { ok: true };
    },

    async fetchBlob(blobId) {
      const raw = await readFileRaw(filesPath(blobId));
      const m = JSON.parse(new TextDecoder().decode(raw));
      if (!m || !m.parts) throw new ApiError(404, 'File not found');
      const partBytes = await Promise.all(
        Array.from({ length: m.parts }, (_, i) => readFileRaw(partPath(blobId, i))),
      );
      const total = partBytes.reduce((n, p) => n + p.length, 0);
      const merged = new Uint8Array(total);
      let o = 0;
      for (const p of partBytes) { merged.set(p, o); o += p.length; }
      return {
        ok: true,
        headers: new Headers(),
        arrayBuffer: async () => merged.buffer,
      };
    },
  };
}

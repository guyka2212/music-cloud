// Thin fetch wrapper. Cookies carry the session; all payloads the server
// receives are ciphertext (or auth/recovery hashes).
class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function request(method, url, body, opts = {}) {
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

export const api = {
  signup: (email, authHash, recoveryHash, kdfSalt) =>
    request('POST', '/api/auth/signup', { email, authHash, recoveryHash, kdfSalt }),
  login: (email, authHash, recoveryHash) =>
    request('POST', '/api/auth/login', { email, authHash: authHash || '', recoveryHash }),
  salt: (email) => request('GET', `/api/auth/salt?email=${encodeURIComponent(email)}`).then((r) => r.json()),
  logout: () => request('POST', '/api/auth/logout', {}),
  me: () => request('GET', '/api/auth/me').then((r) => r.json()),
  getLibrary: () => request('GET', '/api/library').then((r) => r.json()),
  saveLibrary: (salt, iv, ct) => request('PUT', '/api/library', { salt, iv, ct }),
  blobInit: (blobId, salt, iv) => request('POST', `/api/blob/${blobId}/init`, { blobId, salt, iv }),
  putChunk: (blobId, idx, bytes, signal) => request('PUT', `/api/blob/${blobId}/chunk/${idx}`, bytes, { signal }),
  blobFinalize: (blobId, size) => request('POST', `/api/blob/${blobId}/finalize`, { size }),
  blobStatus: (blobId) => request('GET', `/api/blob/${blobId}/status`).then((r) => r.json()),
  blobDelete: (blobId) => request('DELETE', `/api/blob/${blobId}`),
  fetchBlob: (blobId) => request('GET', `/blob/${blobId}`),
};

export { ApiError };

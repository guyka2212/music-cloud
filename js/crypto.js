// Client-side cryptography. The server never sees key material or plaintext.
//
//   master bits = PBKDF2(password, per-user salt)  -> 32 raw bytes, never uploaded
//   doc key     = AES-256-GCM key imported from the bits (library JSON)
//   auth hash   = PBKDF2(password, "auth:" + salt) -> login-only, server compares
//   file keys   = random per-file AES-256-GCM keys, wrapped with HKDF(master bits)
//   chunk IVs   = file IV XOR chunk index (unique per chunk, no IV reuse)
//
// The recovery key IS the raw master material in a human-transcribable format.
// Shown once at signup; the server stores only SHA-256(recovery bytes).

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

export const b64 = {
  encode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  },
  decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

export const PBKDF2_ITERATIONS = 310_000;
export const CHUNK_SIZE = 4 * 1024 * 1024; // plaintext bytes per chunk (large files)

// ---------------------------------------------------------------- key derivation

async function pbkdf2Bytes(password, saltBytes, iterations, bits) {
  const base = await subtle().importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const out = await subtle().deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' }, base, bits);
  return new Uint8Array(out);
}

async function importAesKey(bits) {
  return subtle().importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function generateSalt() {
  return b64.encode(random(16));
}

// Everything needed at signup: master bits, the login auth hash (sent to the
// server), and the recovery key (the master bits in transcribable form).
export async function createAccountCredentials(password, saltB64) {
  const salt = b64.decode(saltB64);
  const masterBits = await pbkdf2Bytes(password, salt, PBKDF2_ITERATIONS, 256);
  const authBits = await pbkdf2Bytes(password, enc.encode(`auth:${saltB64}`), PBKDF2_ITERATIONS + 1, 256);
  return {
    masterBits,
    authHash: b64.encode(authBits),
    recoveryKey: formatRecoveryKey(masterBits),
  };
}

export async function loginCredentialsWithPassword(password, saltB64) {
  const salt = b64.decode(saltB64);
  const masterBits = await pbkdf2Bytes(password, salt, PBKDF2_ITERATIONS, 256);
  const authBits = await pbkdf2Bytes(password, enc.encode(`auth:${saltB64}`), PBKDF2_ITERATIONS + 1, 256);
  return { masterBits, authHash: b64.encode(authBits) };
}

// ---------------------------------------------------------------- recovery key

// 32 bytes -> base32 -> 52 chars in 11 dash-separated groups.
// 32-char alphabet, no I/L/O and no digit 1 (confusable).
const RKEY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ023456789';

export function formatRecoveryKey(bytes) {
  let bits = 0, value = 0;
  const out = [];
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out.push(RKEY_ALPHABET[(value >>> (bits - 5)) & 31]);
      bits -= 5;
    }
  }
  if (bits > 0) out.push(RKEY_ALPHABET[(value << (5 - bits)) & 31]);
  const s = out.join('');
  const groups = [];
  for (let i = 0; i < s.length; i += 5) groups.push(s.slice(i, i + 5));
  return groups.join('-');
}

export function parseRecoveryKey(text) {
  const clean = (text || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (clean.length !== 52) return null;
  let bits = 0, value = 0;
  const out = new Uint8Array(32);
  let oi = 0;
  for (const ch of clean) {
    const idx = RKEY_ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out[oi++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return oi === 32 ? out : null;
}

export async function sha256B64(bytes) {
  const d = await subtle().digest('SHA-256', bytes);
  return b64.encode(new Uint8Array(d));
}

// Recovery-mode login: SHA-256(recovery bytes) is what the server compares;
// the recovery bytes themselves become the master bits again.
export async function loginCredentialsWithRecovery(recoveryKeyText) {
  const raw = parseRecoveryKey(recoveryKeyText);
  if (!raw) return null;
  return { masterBits: raw, recoveryHash: await sha256B64(raw) };
}

// ---------------------------------------------------------------- library doc

export async function encryptJson(masterBits, obj) {
  const key = await importAesKey(masterBits);
  const iv = random(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64.encode(iv), ct: b64.encode(ct) };
}

export async function decryptJson(masterBits, ivB64, ctB64) {
  const key = await importAesKey(masterBits);
  const pt = await subtle().decrypt({ name: 'AES-GCM', iv: b64.decode(ivB64) }, key, b64.decode(ctB64));
  return JSON.parse(dec.decode(pt));
}

// ---------------------------------------------------------------- file keys

async function hkdfWrapKey(masterBits) {
  const base = await subtle().importKey('raw', masterBits, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('mc-file-wrap-v1') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// Returns the live file key plus the wrapped record stored in the library doc.
export async function makeFileKeyRecord(masterBits) {
  const fileKey = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const raw = new Uint8Array(await subtle().exportKey('raw', fileKey));
  const wrapKey = await hkdfWrapKey(masterBits);
  const wiv = random(12);
  const wrapped = await subtle().encrypt({ name: 'AES-GCM', iv: wiv }, wrapKey, raw);
  return {
    handle: fileKey,
    record: { k: b64.encode(new Uint8Array(wrapped)), wiv: b64.encode(wiv) },
  };
}

export async function unwrapFileKey(masterBits, record) {
  const wrapKey = await hkdfWrapKey(masterBits);
  const raw = await subtle().decrypt({ name: 'AES-GCM', iv: b64.decode(record.wiv) }, wrapKey, b64.decode(record.k));
  return subtle().importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// ---------------------------------------------------------------- payload crypto

// Single-shot encryption for small files; also used per-chunk for large ones.
export async function encryptWithIv(key, iv, data) {
  return new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, key, data));
}

export async function decryptWithIv(key, iv, ctWithTag) {
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv }, key, ctWithTag));
}

// Per-chunk IV: file IV XOR chunk index (first 4 bytes). Deterministic, unique
// per (file, chunk), so the download path re-derives it without extra storage.
export function deriveChunkIv(fileIv, index) {
  const iv = new Uint8Array(fileIv);
  const idx = new Uint8Array(4);
  new DataView(idx.buffer).setUint32(0, index);
  for (let i = 0; i < 4; i++) iv[i] ^= idx[i];
  return iv;
}

// ---------------------------------------------------------------- ids

export function newId(prefix) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`;
}

export const utf8 = { encode: enc.encode.bind(enc), decode: dec.decode.bind(dec) };

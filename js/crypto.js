// Shared utilities. This app stores files as plain bytes in the repo, so the
// former AES/PBKDF2 machinery is gone; only encoding and id helpers remain.

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

export const CHUNK_SIZE = 4 * 1024 * 1024; // bytes per part for large files

// ---------------------------------------------------------------- ids

export function newId(prefix) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`;
}

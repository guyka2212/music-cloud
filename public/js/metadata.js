// Reads audio metadata client-side: title, artist, album, duration, cover art.
// Everything is parsed from the plaintext File in the browser; only encrypted
// bytes ever leave the device.

import { b64 } from './crypto.js';

const UTF8 = (bytes) => new TextDecoder('utf-8').decode(bytes);
const UTF16LE = (bytes) => new TextDecoder('utf-16le').decode(bytes);

function isAudioish(file) {
  if (file.type && file.type.startsWith('audio/')) return true;
  // Extension-based fallback for formats whose MIME the OS didn't set.
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  return ['mp3', 'wav', 'flac', 'aac', 'm4a', 'm4b', 'ogg', 'oga', 'opus', 'aiff', 'aif', 'aifc', 'wma', 'caf', 'weba', 'mka'].includes(ext);
}

export function classifyFile(file) {
  const audio = isAudioish(file);
  return {
    kind: audio ? 'audio' : 'file',
    // 'unknown' means: probe at play time; show download instead of play if it fails.
    playability: audio ? 'unknown' : 'never',
  };
}

// ---------------------------------------------------------------- ID3v2 (MP3 etc.)

function syncsafe(b0, b1, b2, b3) {
  return ((b0 & 0x7f) << 21) | ((b1 & 0x7f) << 14) | ((b2 & 0x7f) << 7) | (b3 & 0x7f);
}

function readId3(view, u8) {
  if (!(u8[0] === 0x49 && u8[1] === 0x44 && u8[2] === 0x33)) return null; // 'ID3'
  const version = u8[3];
  const size = syncsafe(u8[6], u8[7], u8[8], u8[9]);
  const out = {};
  let pos = 10;
  const end = Math.min(10 + size, u8.byteLength);
  // Extended header?
  if (u8[5] & 0x40) {
    const ehSize = version === 4 ? syncsafe(u8[10], u8[11], u8[12], u8[13])
      : (view.getUint32(10) + 4);
    pos += ehSize;
  }
  while (pos + 10 <= end) {
    const id = UTF8(u8.subarray(pos, pos + 4));
    if (!/^[A-Z0-9]{4}$/.test(id)) break;
    let fsize;
    if (version === 4) fsize = syncsafe(u8[pos + 4], u8[pos + 5], u8[pos + 6], u8[pos + 7]);
    else fsize = view.getUint32(pos + 4);
    const flags = u8[pos + 8]; void flags;
    const data = u8.subarray(pos + 10, pos + 10 + fsize);
    if (fsize <= 0 || pos + 10 + fsize > end) break;

    const text = () => {
      if (data.length === 0) return '';
      const encByte = data[0];
      const body = data.subarray(1);
      let s = '';
      if (encByte === 0) s = UTF8(body.subarray(0, body.indexOf(0) === -1 ? body.length : body.indexOf(0)));
      else if (encByte === 1) s = UTF16LE(body.subarray(0, body.indexOf(0) === -1 ? body.length : body.indexOf(0)));
      else if (encByte === 2) s = UTF16LE(body.subarray(0, body.indexOf(0) === -1 ? body.length : body.indexOf(0)));
      else s = UTF8(body);
      return s.replace(/\u0000+$/g, '').trim();
    };

    if (id === 'TIT2') out.title = text();
    else if (id === 'TPE1') out.artist = text();
    else if (id === 'TALB') out.album = text();
    else if (id === 'TCON') out.genre = text();
    else if (id === 'TRCK') out.track = text();
    else if (id === 'TDRC' || id === 'TYER') out.year = text();
    else if (id === 'APIC') {
      // <enc> <mime cstr> <picType> <description cstr utf-16 or latin> <bin>
      let p = 1;
      while (p < data.length && data[p] !== 0) p++;
      const mime = UTF8(data.subarray(1, p)) || 'image/jpeg';
      p++; // null
      p += 1; // picture type byte
      // description terminated by 0x00 (latin1) or 0x0000 (utf16)
      const isUtf16Desc = data[0] === 1 || data[0] === 2;
      if (isUtf16Desc) {
        while (p + 1 < data.length && !(data[p] === 0 && data[p + 1] === 0)) p += 2;
        p += 2;
      } else {
        while (p < data.length && data[p] !== 0) p++;
        p += 1;
        while (p < data.length && data[p] === 0) p += 1;
      }
      const bin = data.subarray(p);
      if (bin.length > 100) {
        out.cover = { mime, data: b64.encode(bin) };
      }
    }
    if (id === 'APIC' && out.cover && out.cover.data.length > 400_000) break; // enough
    pos += 10 + fsize;
  }
  return Object.keys(out).length ? out : null;
}

// ---------------------------------------------------------------- FLAC

function readFlac(view, u8) {
  if (UTF8(u8.subarray(0, 4)) !== 'fLaC') return null;
  let pos = 4;
  const out = {};
  let last = false;
  while (!last && pos + 4 <= u8.byteLength) {
    const header = u8[pos];
    last = (header & 0x80) !== 0;
    const type = header & 0x7f;
    const len = (u8[pos + 1] << 16) | (u8[pos + 2] << 8) | u8[pos + 3];
    const body = u8.subarray(pos + 4, pos + 4 + len);
    if (type === 0 && len >= 18) { // STREAMINFO
      const bv = new DataView(body.buffer, body.byteOffset, body.byteLength);
      // sample rate 20 bits @ offset 10, total samples 36 bits @ offset 13
      const sr = (bv.getUint8(10) << 12) | (bv.getUint8(11) << 4) | (bv.getUint8(12) >> 4);
      const totalHi = bv.getUint8(13) & 0x0f;
      const total = totalHi * 2 ** 32 + bv.getUint32(14);
      if (sr > 0) out.duration = total / sr;
    } else if (type === 4) { // VORBIS_COMMENT
      const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
      let p = 0;
      const vlen = dv.getUint32(p, true); p += 4 + vlen;
      const count = dv.getUint32(p, true); p += 4;
      for (let i = 0; i < count && p + 4 <= body.length; i++) {
        const l = dv.getUint32(p, true); p += 4;
        const kv = UTF8(body.subarray(p, p + l)); p += l;
        const eq = kv.indexOf('=');
        if (eq > 0) {
          const key = kv.slice(0, eq).toUpperCase();
          const val = kv.slice(eq + 1);
          if (key === 'TITLE') out.title = val;
          else if (key === 'ARTIST') out.artist = out.artist || val;
          else if (key === 'ALBUM') out.album = val;
        }
    }
    } else if (type === 6) { // PICTURE
      const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
      let p = 4; // skip picture type
      const mlen = dv.getUint32(p); p += 4;
      const mime = UTF8(body.subarray(p, p + mlen)); p += mlen;
      const dlen = dv.getUint32(p); p += 4 + dlen; // description
      p += 16; // w, h, depth, colors
      const plen = dv.getUint32(p); p += 4;
      if (plen > 100) out.cover = { mime, data: b64.encode(body.subarray(p, p + plen)) };
    }
    pos += 4 + len;
    if (len > u8.byteLength) break;
  }
  return Object.keys(out).length ? out : null;
}

// ---------------------------------------------------------------- MP4 (M4A/MP4)

function readMp4(view, u8) {
  // Quick check: 'ftyp' at offset 4.
  if (u8.byteLength < 12) return null;
  const brandAt4 = UTF8(u8.subarray(4, 8));
  if (brandAt4 !== 'ftyp') return null;
  const out = {};
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

  const MOOV = 0x6D6F6F76, UDTA = 0x75647461, META = 0x6D657461, ILST = 0x696C7374;
  const DATA = 0x64617461, MDIA = 0x6D646961, MDHD = 0x6D646864;

  // Recursive atom scanner for ilst entries + mdhd duration.
  const scan = (start, end, d) => {
    let p = start;
    while (p + 8 <= end && d < 10) {
      const size = dv.getUint32(p);
      const type = dv.getUint32(p + 4);
      if (size < 8 || p + size > end) break;
      if (type === MOOV || type === UDTA || type === META) {
        scan(p + 8 + (type === META ? 4 : 0), p + size, d + 1);
      } else if (type === ILST) {
        scanIlst(p + 8, p + size);
      } else if (type === MDIA) {
        scan(p + 8, p + size, d + 1);
      } else if (type === MDHD) {
        // version(1) flags(3) [v1: 8+8 creation/mod] timescale(4) duration(4 or 8)
        const version = u8[p + 8];
        let q = p + 12;
        if (version === 1) q += 16;
        const ts = dv.getUint32(q); q += 4;
        const dur = version === 1 ? Number(dv.getBigUint64(q)) : dv.getUint32(q);
        if (ts > 0) out.duration = dur / ts;
      }
      p += size;
    }
  };
  const scanIlst = (start, end) => {
    let p = start;
    const NAMES = { '\u00A9nam': 'title', '\u00A9ART': 'artist', '\u00A9alb': 'album', aART: 'artist', covr: 'cover' };
    while (p + 8 <= end) {
      const size = dv.getUint32(p);
      const name = UTF8(u8.subarray(p + 4, p + 8));
      if (size < 8 || p + size > end) break;
      // children 'data' atoms
      let q = p + 8;
      while (q + 8 <= p + size) {
        const dsize = dv.getUint32(q);
        const dtype = dv.getUint32(q + 4);
        if (dsize < 8 || q + dsize > p + size) break;
        if (dtype === DATA) {
          const dataType = dv.getUint32(q + 8) & 0xffffff;
          const payload = u8.subarray(q + 16, q + dsize);
          const field = NAMES[name] || null;
          if (name === 'covr' && payload.length > 100) {
            const mime = dataType === 14 ? 'image/png' : 'image/jpeg';
            out.cover = { mime, data: b64.encode(payload) };
          } else if (field) {
            const val = UTF8(payload).replace(/\u0000+$/g, '').trim();
            if (val && !out[field]) out[field] = val;
          }
        }
        q += dsize;
      }
      p += size;
    }
  };
  scan(0, u8.byteLength, 0);
  return Object.keys(out).length ? out : null;
}

// ---------------------------------------------------------------- WAV

function readWavDuration(view) {
  if (view.byteLength < 44) return null;
  if (UTF8(view.buffer.slice(0, 4)) !== 'RIFF') return null;
  let p = 12;
  const u8 = new Uint8Array(view.buffer);
  while (p + 8 <= view.byteLength) {
    const id = UTF8(u8.subarray(p, p + 4));
    const size = view.getUint32(p + 4, true);
    if (id === 'fmt ' && p + 8 + 16 <= view.byteLength) {
      const sampleRate = view.getUint32(p + 12, true);
      const byteRate = view.getUint32(p + 16, true);
      const dataId = 'data';
      // find data chunk
      let q = p + 8 + size;
      while (q + 8 <= view.byteLength) {
        const id2 = UTF8(u8.subarray(q, q + 4));
        const s2 = view.getUint32(q + 4, true);
        if (id2 === dataId) {
          return byteRate > 0 ? (s2 / byteRate) : null;
        }
        q += 8 + s2 + (s2 % 2);
      }
      void sampleRate;
      return null;
    }
    p += 8 + size + (size % 2);
  }
  return null;
}

// ---------------------------------------------------------------- top-level reader

export async function readAudioMetadata(file) {
  const meta = {};
  try {
    const head = new Uint8Array(await file.slice(0, Math.min(file.size, 512 * 1024)).arrayBuffer());
    const view = new DataView(head.buffer);
    let parsed = null;

    if (head[0] === 0x49 && head[1] === 0x44 && head[2] === 0x33) parsed = readId3(view, head);
    else if (UTF8(head.subarray(0, 4)) === 'fLaC') parsed = readFlac(view, head);
    else if (head.byteLength > 12 && UTF8(head.subarray(4, 8)) === 'ftyp') parsed = readMp4(view, head);
    else if (UTF8(head.subarray(0, 4)) === 'RIFF') {
      const d = readWavDuration(view);
      if (d) meta.duration = d;
    }

    if (parsed) Object.assign(meta, parsed);

    // Fallback duration probe via a throwaway <audio> element for formats the
    // parsers above could not time (and general sanity check).
    if (meta.duration == null && file.size < 80 * 1024 * 1024) {
      meta.duration = await probeDuration(file).catch(() => null);
    }
    if (meta.duration != null) meta.duration = Math.round(meta.duration);
  } catch { /* metadata is best-effort */ }
  return meta;
}

function probeDuration(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const a = new Audio();
    const done = (v) => { URL.revokeObjectURL(url); a.removeAttribute('src'); resolve(v); };
    a.preload = 'metadata';
    a.onloadedmetadata = () => done(Number.isFinite(a.duration) ? a.duration : null);
    a.onerror = () => { done(null); reject(new Error('probe failed')); };
    a.src = url;
    setTimeout(() => done(null), 8000);
  });
}

// Can the browser play this blob? Probed once per item, cached in the doc.
export function probePlayability(url, mime) {
  return new Promise((resolve) => {
    const a = document.createElement('audio');
    const finish = (v) => { a.removeAttribute('src'); a.load?.(); resolve(v); };
    a.preload = 'metadata';
    a.onloadedmetadata = () => finish(true);
    a.onerror = () => finish(false);
    a.src = url;
    if (mime) a.type = mime;
    setTimeout(() => finish(false), 10000);
  });
}

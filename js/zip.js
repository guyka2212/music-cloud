// Minimal ZIP writer (STORE method — no compression). Files are already
// decrypted locally; we just need a valid archive the OS can open.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function dosDateTime(date) {
  const d = date || new Date();
  const time = ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((d.getSeconds() / 2) & 0x1f);
  const day = (((d.getFullYear() - 1980) & 0x7f) << 9) | (((d.getMonth() + 1) & 0xf) << 5) | (d.getDate() & 0x1f);
  return { time, day };
}

function u16(arr, v) { arr.push(v & 0xFF, (v >>> 8) & 0xFF); }
function u32(arr, v) { arr.push(v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF); }

function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

class ByteWriter {
  constructor() { this.chunks = []; this.length = 0; }
  push(bytes) { this.chunks.push(bytes); this.length += bytes.length; }
  concat() {
    const out = new Uint8Array(this.length);
    let o = 0;
    for (const c of this.chunks) { out.set(c, o); o += c.length; }
    return out;
  }
}

/**
 * entries: [{ path: 'Folder/song.mp3', data: Uint8Array, mtime?: Date }]
 * Returns a Uint8Array containing a valid .zip (STORE method).
 */
export function makeZip(entries) {
  const out = new ByteWriter();
  const central = new ByteWriter();

  for (const e of entries) {
    const nameBytes = utf8Bytes(e.path);
    const crc = crc32(e.data);
    const size = e.data.length;
    const { time, day } = dosDateTime(e.mtime);
    const offset = out.length;

    // Local file header
    const lfh = [];
    u32(lfh, 0x04034B50);
    u16(lfh, 20);          // version needed
    u16(lfh, 0x0800);      // flags: UTF-8 names
    u16(lfh, 0);           // method: store
    u16(lfh, time);
    u16(lfh, day);
    u32(lfh, crc);
    u32(lfh, size);        // compressed
    u32(lfh, size);        // uncompressed
    u16(lfh, nameBytes.length);
    u16(lfh, 0);           // extra len
    out.push(new Uint8Array(lfh));
    out.push(nameBytes);
    out.push(e.data);

    // Central directory entry
    const cde = [];
    u32(cde, 0x02014B50);
    u16(cde, 20);          // version made by
    u16(cde, 20);          // version needed
    u16(cde, 0x0800);
    u16(cde, 0);
    u16(cde, time);
    u16(cde, day);
    u32(cde, crc);
    u32(cde, size);
    u32(cde, size);
    u16(cde, nameBytes.length);
    u16(cde, 0);           // extra
    u16(cde, 0);           // comment
    u16(cde, 0);           // disk
    u16(cde, 0);           // internal attrs
    u32(cde, 0);           // external attrs
    u32(cde, offset);
    central.push(new Uint8Array(cde));
    central.push(nameBytes);
  }

  const cdOffset = out.length;
  const cd = central.concat();
  out.push(cd);

  // End of central directory
  const eocd = [];
  u32(eocd, 0x06054B50);
  u16(eocd, 0);
  u16(eocd, 0);
  u16(eocd, entries.length);
  u16(eocd, entries.length);
  u32(eocd, cd.length);
  u32(eocd, cdOffset);
  u16(eocd, 0);
  out.push(new Uint8Array(eocd));

  return out.concat();
}

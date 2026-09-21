import crypto from 'node:crypto';

export function sha256B64Url(input) {
  return crypto.createHash('sha256').update(input).digest('base64url');
}

export function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Still burn a comparison to keep timing flat.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

export function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

export function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

// Reads and parses a JSON body with a hard size cap (protects the event loop).
export function readJsonBody(req, limit = 30 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('Payload too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Invalid JSON body'), { statusCode: 400 }));
      }
    });
    req.on('error', reject);
  });
}

export function clientIp(req) {
  // Behind a trusted proxy this would read x-forwarded-for; locally socket address is correct.
  return req.socket.remoteAddress || 'unknown';
}

export function sendJson(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

export function jsonError(res, status, message) {
  sendJson(res, status, { error: message });
}

// Very small in-memory fixed-window limiter used for auth routes on top of
// the persistent per-email lockout in the db.
const buckets = new Map();
export function rateLimit(key, limit, windowMs) {
  const t = Date.now();
  let b = buckets.get(key);
  if (!b || t - b.start > windowMs) {
    b = { start: t, count: 0 };
    buckets.set(key, b);
  }
  b.count += 1;
  if (buckets.size > 10_000) {
    for (const [k, v] of buckets) if (t - v.start > windowMs) buckets.delete(k);
  }
  return b.count <= limit;
}

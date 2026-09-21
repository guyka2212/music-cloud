import {
  createUser, getUserByEmail, createSession, deleteSession, sweepSessions,
  getSession, getUser, db,
} from './db.js';
import {
  sha256B64Url, timingSafeEqualStr, randomToken, parseCookies,
  readJsonBody, clientIp, sendJson, jsonError, rateLimit,
} from './util.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SESSION_COOKIE = 'mc_session';
const SESSION_MAX_AGE = 30 * 24 * 3600;

function sessionCookie(token, maxAgeSec) {
  const secure = process.env.COOKIE_SECURE === '1' ? '; Secure' : '';
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure}`;
}

export function attachUser(req) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  req.sessionToken = null;
  req.user = null;
  if (!token) return;
  const session = getSession(sha256B64Url(token));
  if (!session) return;
  sweepSessions();
  req.sessionToken = token;
  req.user = { id: session.user_id };
}

export function requireUser(handler) {
  return async (ctx) => {
    if (!ctx.req.user) {
      jsonError(ctx.res, 401, 'Authentication required');
      return;
    }
    await handler(ctx);
  };
}

const clearCookie = () => `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;

// ---------------------------------------------------------------- routes

export async function handleSignup(ctx) {
  const { req, res } = ctx;
  const ip = clientIp(req);
  if (!rateLimit(`signup:${ip}`, 10, 60 * 60 * 1000)) {
    jsonError(res, 429, 'Too many attempts. Try again later.');
    return;
  }
  const body = await readJsonBody(req, 64 * 1024);
  const email = String(body.email || '').trim().toLowerCase();
  const authHash = String(body.authHash || '');
  const recoveryHash = body.recoveryHash ? String(body.recoveryHash) : null;
  if (!EMAIL_RE.test(email)) { jsonError(res, 400, 'Enter a valid email address.'); return; }
  if (!/^[A-Za-z0-9+/=]{43,128}$/.test(authHash)) {
    jsonError(res, 400, 'Invalid credentials payload.');
    return;
  }
  if (recoveryHash && !/^[A-Za-z0-9+/=]{43,128}$/.test(recoveryHash)) {
    jsonError(res, 400, 'Invalid recovery payload.');
    return;
  }
  if (getUserByEmail(email)) { jsonError(res, 409, 'An account with this email already exists.'); return; }

  const kdfSalt = String(body.kdfSalt || '');
  if (!/^[A-Za-z0-9+/=]{16,64}$/.test(kdfSalt)) {
    jsonError(res, 400, 'Invalid KDF salt.');
    return;
  }
  const user = createUser(email, authHash, recoveryHash, kdfSalt);
  const token = randomToken();
  createSession(user.id, sha256B64Url(token));
  sendJson(res, 201, { ok: true, userId: user.id }, { 'Set-Cookie': sessionCookie(token, SESSION_MAX_AGE) });
}

export async function handleLogin(ctx) {
  const { req, res } = ctx;
  const ip = clientIp(req);
  const body = await readJsonBody(req, 64 * 1024);
  const email = String(body.email || '').trim().toLowerCase();
  const authHash = String(body.authHash || '');
  const recoveryHash = body.recoveryHash ? String(body.recoveryHash) : null;

  if (!rateLimit(`login:${ip}`, 30, 15 * 60 * 1000)) {
    jsonError(res, 429, 'Too many attempts. Try again later.');
    return;
  }

  const lockKey = `lock:${email}`;
  const lock = getLock(lockKey);
  if (lock && lock.locked_until > Date.now()) {
    const mins = Math.ceil((lock.locked_until - Date.now()) / 60000);
    jsonError(res, 429, `Too many failed attempts. Locked for ${mins} more minute${mins === 1 ? '' : 's'}.`);
    return;
  }

  const user = getUserByEmail(email);
  const ok = user && (
    (/^[A-Za-z0-9+/=]{43,128}$/.test(authHash) && timingSafeEqualStr(user.auth_hash, authHash))
    || (recoveryHash && user.recovery_hash && /^[A-Za-z0-9+/=]{43,128}$/.test(recoveryHash)
      && timingSafeEqualStr(user.recovery_hash, recoveryHash))
  );
  if (!ok) {
    if (user) setLock(lockKey, lock ? lock.fail_count + 1 : 1);
    jsonError(res, 401, 'Incorrect email or password.');
    return;
  }
  setLock(lockKey, 0); // reset failure count

  const token = randomToken();
  createSession(user.id, sha256B64Url(token));
  sendJson(res, 200, { ok: true, userId: user.id }, { 'Set-Cookie': sessionCookie(token, SESSION_MAX_AGE) });
}

const getLock = (key) =>
  db.prepare('SELECT fail_count, locked_until FROM auth_rate WHERE key = ?').get(key) || null;

function setLock(key, failCount) {
  const t = Date.now();
  // Exponential backoff: 5 failures -> 5 min, each further failure doubles, cap 60 min.
  const lockedUntil = failCount === 0 ? 0
    : failCount >= 5 ? Math.min(t + Math.min(5 * 2 ** (failCount - 5), 60) * 60_000, t + 3600_000)
      : 0;
  db.prepare(`
    INSERT INTO auth_rate (key, fail_count, window_start, locked_until)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      fail_count = excluded.fail_count, locked_until = excluded.locked_until
  `).run(key, failCount, t, lockedUntil);
}

export async function handleLogout(ctx) {
  const { req, res } = ctx;
  if (req.sessionToken) deleteSession(sha256B64Url(req.sessionToken));
  sendJson(res, 200, { ok: true }, { 'Set-Cookie': clearCookie() });
}

// Pre-auth salt lookup so any device can derive the key. The salt is public
// by design — knowing it does not reveal the password or the master key.
export async function handleSalt(ctx) {
  const { req, res } = ctx;
  const email = String(ctx.url.searchParams.get('email') || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) { jsonError(res, 400, 'Enter a valid email address.'); return; }
  if (!rateLimit(`salt:${clientIp(req)}`, 60, 15 * 60 * 1000)) {
    jsonError(res, 429, 'Too many requests. Try again later.');
    return;
  }
  const user = getUserByEmail(email);
  if (!user) {
    jsonError(res, 404, 'No account with that email.');
    return;
  }
  sendJson(res, 200, { salt: user.kdf_salt });
}

export async function handleMe(ctx) {
  const { req, res } = ctx;
  if (!req.user) { sendJson(res, 200, { user: null }); return; }
  const user = getUser(req.user.id);
  sendJson(res, 200, { user: user ? { id: user.id, email: user.email, createdAt: user.created_at } : null });
}

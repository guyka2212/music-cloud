// Database layer. Users / sessions are plaintext by necessity (authentication).
// Everything the user stores — library JSON, file bytes, chunk payloads — lives
// in these tables only as opaque ciphertext + IV; the server never sees keys.
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';

const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
fs.mkdirSync(dataDir, { recursive: true });

export const db = new DatabaseSync(path.join(dataDir, 'music-cloud.db'));

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  auth_hash TEXT NOT NULL,
  recovery_hash TEXT,
  kdf_salt TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS library_docs (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  salt TEXT NOT NULL,
  doc_iv TEXT NOT NULL,
  doc_ct TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
  id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  salt TEXT NOT NULL,
  iv BLOB NOT NULL,
  ct BLOB,
  byte_len INTEGER NOT NULL DEFAULT 0,
  complete INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (id, user_id)
);

CREATE TABLE IF NOT EXISTS blob_chunks (
  user_id TEXT NOT NULL,
  blob_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  iv BLOB NOT NULL,
  ct BLOB NOT NULL,
  byte_len INTEGER NOT NULL,
  PRIMARY KEY (user_id, blob_id, idx)
);

CREATE TABLE IF NOT EXISTS auth_rate (
  key TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL,
  locked_until INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_chunks_blob ON blob_chunks(user_id, blob_id);
`);

const now = () => Date.now();
const rid = (prefix) => `${prefix}_${crypto.randomBytes(16).toString('base64url')}`;

// ---------------------------------------------------------------- users

export function createUser(email, authHash, recoveryHash = null, kdfSalt = '') {
  const id = rid('u');
  db.prepare('INSERT INTO users (id, email, auth_hash, recovery_hash, kdf_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, email, authHash, recoveryHash, kdfSalt, now());
  return getUser(id);
}

export function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email) || null;
}

export function getUser(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
}

// ---------------------------------------------------------------- sessions

export function createSession(userId, tokenHash) {
  const t = now();
  db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at) VALUES (?, ?, ?, ?)')
    .run(tokenHash, userId, t, t);
}

export function getSession(tokenHash) {
  const s = db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash);
  if (!s) return null;
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').run(now(), tokenHash);
  return s;
}

export function deleteSession(tokenHash) {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
}

// Sessions expire after 30 days of inactivity; sweep runs at most once an hour.
const SESSION_TTL_MS = 30 * 24 * 3600 * 1000;
let lastSweep = 0;
export function sweepSessions() {
  const t = now();
  if (t - lastSweep < 3600_000) return;
  lastSweep = t;
  db.prepare('DELETE FROM sessions WHERE last_seen_at < ?').run(t - SESSION_TTL_MS);
  db.prepare('DELETE FROM auth_rate WHERE window_start < ?').run(t - 24 * 3600 * 1000);
}

// ---------------------------------------------------------------- library doc (one encrypted JSON per user)

export function getLibraryDoc(userId) {
  return db.prepare('SELECT * FROM library_docs WHERE user_id = ?').get(userId) || null;
}

export function saveLibraryDoc(userId, salt, iv, ct) {
  db.prepare(`
    INSERT INTO library_docs (user_id, salt, doc_iv, doc_ct, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      salt = excluded.salt, doc_iv = excluded.doc_iv, doc_ct = excluded.doc_ct,
      updated_at = excluded.updated_at
  `).run(userId, salt, iv, ct, now());
}

// ---------------------------------------------------------------- blobs
// Lifecycle: init (row with salt/iv, complete=0) -> N chunks -> finalize
// (chunks merged into ct, complete=1). Incomplete blobs older than 24h are swept.

export function initBlob(userId, blobId, salt, iv) {
  db.prepare(`INSERT INTO blobs (id, user_id, salt, iv, ct, byte_len, complete, created_at)
              VALUES (?, ?, ?, ?, NULL, 0, 0, ?)`)
    .run(blobId, userId, salt, iv, now());
}

export function getBlobRow(userId, blobId) {
  return db.prepare('SELECT * FROM blobs WHERE user_id = ? AND id = ?').get(userId, blobId) || null;
}

export function addChunk(userId, blobId, idx, ct) {
  db.prepare(`INSERT INTO blob_chunks (user_id, blob_id, idx, iv, ct, byte_len)
              VALUES (?, ?, ?, x'', ?, ?)`)
    .run(userId, blobId, idx, ct, ct.length);
}

export function finalizeBlob(userId, blobId, byteLen) {
  const chunks = db.prepare('SELECT ct FROM blob_chunks WHERE user_id = ? AND blob_id = ? ORDER BY idx')
    .all(userId, blobId);
  const merged = Buffer.concat(chunks.map((c) => Buffer.from(c.ct)));
  db.prepare('UPDATE blobs SET ct = ?, byte_len = ?, complete = 1 WHERE user_id = ? AND id = ?')
    .run(merged, byteLen, userId, blobId);
  db.prepare('DELETE FROM blob_chunks WHERE user_id = ? AND blob_id = ?').run(userId, blobId);
}

export function getChunkCount(userId, blobId) {
  return db.prepare('SELECT COUNT(*) AS n FROM blob_chunks WHERE user_id = ? AND blob_id = ?')
    .get(userId, blobId).n;
}

export function getChunkList(userId, blobId) {
  return db.prepare('SELECT idx, ct FROM blob_chunks WHERE user_id = ? AND blob_id = ? ORDER BY idx')
    .all(userId, blobId);
}

export function getChunk(userId, blobId, idx) {
  return db.prepare('SELECT idx, ct FROM blob_chunks WHERE user_id = ? AND blob_id = ? AND idx = ?')
    .get(userId, blobId, idx) || null;
}

export function getBlobData(userId, blobId) {
  return db.prepare('SELECT ct FROM blobs WHERE user_id = ? AND id = ? AND complete = 1')
    .get(userId, blobId) || null;
}

export function deleteBlob(userId, blobId) {
  db.prepare('DELETE FROM blobs WHERE user_id = ? AND id = ?').run(userId, blobId);
  db.prepare('DELETE FROM blob_chunks WHERE user_id = ? AND blob_id = ?').run(userId, blobId);
}

let lastBlobSweep = 0;
export function sweepStaleBlobs() {
  const t = now();
  if (t - lastBlobSweep < 3600_000) return;
  lastBlobSweep = t;
  const stale = db.prepare('SELECT user_id, id FROM blobs WHERE complete = 0 AND created_at < ?')
    .all(t - 24 * 3600 * 1000);
  for (const b of stale) deleteBlob(b.user_id, b.id);
}

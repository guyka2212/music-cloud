// Create a music-cloud account directly in the repo — no browser needed.
//
//   GITHUB_TOKEN=ghp_xxx node scripts/create-user.mjs friend@example.com 'their password'
//
// The account is sealed exactly like a browser signup: an entry in the
// encrypted data/users.json (email + auth hash + salt), keyed so it can only
// be opened with the email AND password. Never run this with a password you
// also use elsewhere — it passes through your shell history.
import { setGhToken, deterministicSaltFor, usersEntryKey, sealUserEntry } from '../js/gh.js';

const [email, password] = process.argv.slice(2);
const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

if (!token || !email || !password) {
  console.error('Usage: GITHUB_TOKEN=ghp_xxx node scripts/create-user.mjs <email> <password>');
  console.error('Token needs Contents: Read and write on guyka2212/music-cloud.');
  process.exit(1);
}
if (password.length < 8) {
  console.error('Password must be at least 8 characters.');
  process.exit(1);
}

setGhToken(token);
const { createAccountCredentials } = await import('../js/crypto.js');

const emailN = String(email).trim().toLowerCase();
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailN)) {
  console.error('That does not look like a valid email address.');
  process.exit(1);
}

const salt = await deterministicSaltFor(emailN);
const { authHash, recoveryHash, recoveryKey } = await createAccountCredentials(password, salt);
const k = await usersEntryKey(emailN, authHash);

// Read-modify-write users.json through the same helpers the driver uses.
const { ghRequest, REPO, BRANCH } = await import('../js/gh.js');
const encPath = (p) => encodeURIComponent(p).replaceAll('%2F', '/');
const USERS = 'data/users.json';

async function readDb() {
  try {
    const r = await ghRequest('GET', `/repos/${REPO}/contents/${encPath(USERS)}?ref=${BRANCH}`, undefined, true);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(await r.arrayBuffer())));
  } catch (e) {
    if (e.status === 404) return { v: 2, users: {}, ptr: {} };
    throw e;
  }
}

const { readFileRaw, putFile, pointerHash } = await import('../js/gh.js');
const db = (await readDb()) || { v: 2, users: {}, ptr: {} };
db.users = db.users || {}; db.ptr = db.ptr || {};

if (db.ptr[await pointerHash(emailN)]) {
  console.error(`An account for ${emailN} already exists in users.json.`);
  process.exit(1);
}

db.users[k] = await sealUserEntry(k, {
  email: emailN,
  authHash,
  recoveryHash,
  kdfSalt: salt,
  createdAt: Date.now(),
});
db.ptr[await pointerHash(emailN)] = k;
await putFile(USERS, new TextEncoder().encode(JSON.stringify(db)), `mc: signup ${k.slice(0, 10)} (cli)`);

console.log(`\nAccount created: ${emailN}`);
console.log(`Recovery key (give this to the account owner):\n\n  ${recoveryKey}\n`);
console.log('They can now sign in at the site with this email + password.');

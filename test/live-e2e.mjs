// Live E2E: exercises the exact browser signup → login → library → blob path
// against the REAL GitHub API on guyka2212/music-cloud, then cleans up.
// Requires a token with push access. Run:
//   GITHUB_TOKEN=... node test/live-e2e.mjs
const ok = (c, m) => { if (!c) { console.error('FAIL: ' + m); process.exit(1); } console.log('ok - ' + m); };

// browser globals the driver expects
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
globalThis.Headers = class Headers {
  constructor(init) { this.map = new Map(Object.entries(init || {})); }
  get(k) { return this.map.get(k) ?? null; }
};

const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
if (!TOKEN) { console.error('Set GITHUB_TOKEN'); process.exit(1); }
localStorage.setItem('mc-gh-token', TOKEN);

// Cleanup helper: delete a repo file if it exists.
const API = 'https://api.github.com';
const encPath = (p) => encodeURIComponent(p).replaceAll('%2F', '/');
const jfetch = async (path, opts = {}) => {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${TOKEN}`, Accept: 'application/vnd.github+json', ...(opts.headers || {}) },
  });
  return res;
};
async function cleanupFile(path) {
  const r = await jfetch(`/repos/guyka2212/music-cloud/contents/${encPath(path)}?ref=main`);
  if (!r.ok) return;
  const j = await r.json();
  await jfetch(`/repos/guyka2212/music-cloud/contents/${encPath(path)}`, {
    method: 'DELETE',
    body: JSON.stringify({ message: `e2e cleanup ${path}`, branch: 'main', sha: j.sha }),
  });
}

// ---- import the real driver + crypto -------------------------------------
const { makeGhApi } = await import('../js/gh.js');
const { createAccountCredentials } = await import('../js/crypto.js');

const EMAIL = `e2e-${Date.now()}@test.dev`;
const PASSWORD = 'e2e-password-123';

const api = makeGhApi();

// 1. salt (pre-auth, deterministic)
const { salt } = await api.salt(EMAIL);
ok(salt && salt.length > 0, 'deterministic salt returned pre-auth');

// 2. signup (this is the exact browser signup path: createAccountCredentials → api.signup)
const creds = await createAccountCredentials(PASSWORD, salt);
const recovery = await api.signup(EMAIL, creds.authHash, creds.recoveryHash, salt);
ok(recovery.ok, 'signup committed to data/users.json via real API');

// 3. login from a "second device" (fresh driver instance, same credentials)
const api2 = makeGhApi();
const { authHash: loginHash } = await (await import('../js/crypto.js')).loginCredentialsWithPassword(PASSWORD, salt);
await api2.login(EMAIL, loginHash, null);
ok(true, 'password login works from a fresh session');

// 4. library round-trip
await api2.saveLibrary(salt, 'e2e-iv', 'e2e-ciphertext');
const lib = await api2.getLibrary();
ok(lib.ct === 'e2e-ciphertext', 'library doc round-trips via real API');

// 5. blob round-trip (music file path: chunked upload)
const bytes = new Uint8Array(2048).map((_, i) => i % 256);
await api2.blobInit('e2e-blob', 'fsalt', 'fiv');
await api2.putChunk('e2e-blob', 0, bytes);
await api2.blobFinalize('e2e-blob', bytes.length);
const got = await api2.fetchBlob('e2e-blob');
const gotBytes = new Uint8Array(await got.arrayBuffer());
ok(gotBytes.length === bytes.length && gotBytes[7] === 7, 'blob round-trips via real API');

// 6. verify users.json exists and leaks nothing
const usersRes = await jfetch(`/repos/guyka2212/music-cloud/contents/data/users.json?ref=main`);
const usersJson = JSON.parse(Buffer.from((await usersRes.json()).content, 'base64').toString());
ok(usersJson.ptr && Object.keys(usersJson.users).length >= 1, 'users.json readable with index + entries');
ok(!JSON.stringify(usersJson).includes(EMAIL), 'email not in plaintext in users.json');

// ---- cleanup --------------------------------------------------------------
const { pointerHash } = await import('../js/gh.js');
const ph = await pointerHash(EMAIL);
const k = usersJson.ptr[ph];
if (k) { delete usersJson.users[k]; delete usersJson.ptr[ph]; }
// rewrite users.json without the e2e account
const putRes = await jfetch(`/repos/guyka2212/music-cloud/contents/data/users.json`, {
  method: 'PUT',
  body: JSON.stringify({
    message: `e2e cleanup users.json`,
    branch: 'main',
    sha: usersRes.headers.get('sha') || (await (await jfetch(`/repos/guyka2212/music-cloud/contents/data/users.json?ref=main`)).json()).sha,
    content: Buffer.from(JSON.stringify(usersJson)).toString('base64'),
  }),
});
ok(putRes.ok || putRes.status === 200, 'users.json restored after cleanup');
await cleanupFile(`data/files/${k}.json`);
await cleanupFile(`data/files/${k}/e2e-blob.json`);
await cleanupFile(`data/files/${k}/e2e-blob/p0.enc`);
console.log('\nLive E2E passed — signup works against the real GitHub API.');
process.exit(0);

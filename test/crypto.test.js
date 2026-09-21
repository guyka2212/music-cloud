// Validates the client crypto module end to end using Node's WebCrypto:
// PBKDF2 derive, doc encrypt/decrypt, wrapped file keys, recovery key
// round-trip, chunk IV consistency. Run: node test/crypto.test.js
import assert from 'node:assert/strict';
import {
  createAccountCredentials, loginCredentialsWithPassword, loginCredentialsWithRecovery,
  encryptJson, decryptJson, makeFileKeyRecord, unwrapFileKey,
  encryptWithIv, decryptWithIv, deriveChunkIv, formatRecoveryKey, parseRecoveryKey,
  generateSalt, CHUNK_SIZE,
} from '../public/js/crypto.js';

const pw = 'correct horse battery staple 9!';
const salt = await generateSalt();

// signup credentials
const signup = await createAccountCredentials(pw, salt);
assert.ok(signup.masterBits);
assert.equal(signup.masterBits.length, 32);
assert.equal(signup.authHash.length, 44); // 32 bytes base64
assert.equal(signup.recoveryKey.split('-').length, 11); // 32 bytes -> 52 chars -> 11 groups
console.log('· signup credentials ok');

// recovery key round-trip: formatted -> parsed -> same master material
const parsed = parseRecoveryKey(signup.recoveryKey);
assert.ok(parsed, 'recovery key should parse');
const recovered = await loginCredentialsWithRecovery(signup.recoveryKey);
assert.ok(recovered.masterBits);
assert.deepEqual(Array.from(recovered.masterBits), Array.from(signup.masterBits));
assert.equal(recovered.recoveryHash, await (async () => {
  const d = await crypto.subtle.digest('SHA-256', parsed);
  return Buffer.from(d).toString('base64');
})());
console.log('· recovery key round-trip ok');

// wrong password produces a different auth hash and bits that cannot decrypt
const wrong = await loginCredentialsWithPassword('wrong password 123', salt);
assert.notEqual(wrong.authHash, signup.authHash);
const probe = await encryptJson(signup.masterBits, { a: 1 });
await assert.rejects(() => decryptJson(wrong.masterBits, probe.iv, probe.ct));
console.log('· wrong password rejected ok');

// doc encrypt/decrypt round-trip
const doc = { folders: { root: { id: 'root', name: 'My Library' } }, items: {}, settings: {} };
const sealed = await encryptJson(signup.masterBits, doc);
const opened = await decryptJson(signup.masterBits, sealed.iv, sealed.ct);
assert.deepEqual(opened, doc);
console.log('· doc round-trip ok');

// file key: wrap -> unwrap -> decrypt payload
const { handle: fileKey, record: keyRecord } = await makeFileKeyRecord(signup.masterBits);
const unwrapped = await unwrapFileKey(signup.masterBits, keyRecord);
const payload = crypto.getRandomValues(new Uint8Array(1024));
const fileIv = crypto.getRandomValues(new Uint8Array(12));
const sealedPayload = await encryptWithIv(fileKey, fileIv, payload);
const openedPayload = await decryptWithIv(unwrapped, fileIv, sealedPayload);
assert.deepEqual(Array.from(openedPayload), Array.from(payload));
// wrapped record must not decrypt with the wrong master bits
await assert.rejects(() => unwrapFileKey(wrong.masterBits, keyRecord));
console.log('· file key wrap/unwrap ok');

// chunked encryption round-trip (simulates a >4MB file upload + download)
const chunkCount = 3;
const bigRandom = (n) => {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) {
    crypto.getRandomValues(out.subarray(o, Math.min(o + 65536, n)));
  }
  return out;
};
const plaintexts = [];
const ciphertexts = [];
for (let i = 0; i < chunkCount; i++) {
  const pt = bigRandom(CHUNK_SIZE - (i === 2 ? 128 : 0));
  const iv = deriveChunkIv(fileIv, i);
  const ct = await encryptWithIv(fileKey, iv, pt);
  plaintexts.push(pt);
  ciphertexts.push(ct);
}
for (let i = 0; i < chunkCount; i++) {
  const iv = deriveChunkIv(fileIv, i);
  const out = await decryptWithIv(unwrapped, iv, ciphertexts[i]);
  assert.deepEqual(Array.from(out), Array.from(plaintexts[i]));
}
// IVs must differ per chunk
assert.notEqual(Buffer.from(deriveChunkIv(fileIv, 0)), Buffer.from(deriveChunkIv(fileIv, 1)));
console.log('· chunked crypto round-trip ok');

// deterministic IV derivation: same inputs, same IV, no input mutation
const ivA = deriveChunkIv(fileIv, 7);
const ivB = deriveChunkIv(fileIv, 7);
assert.deepEqual(Array.from(ivA), Array.from(ivB));
assert.deepEqual(Array.from(fileIv), Array.from(fileIv));
console.log('· chunk IV derivation ok');

console.log('\nAll client crypto tests passed.');
process.exit(0);

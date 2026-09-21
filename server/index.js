import http from 'node:http';
import { createRouter } from './router.js';
import {
  handleSignup, handleLogin, handleLogout, handleMe, handleSalt, attachUser, requireUser,
} from './auth.js';
import { readJsonBody, jsonError, sendJson } from './util.js';
import {
  getLibraryDoc, saveLibraryDoc, initBlob, getBlobRow, addChunk, finalizeBlob,
  deleteBlob, getChunkCount, getChunkList, sweepStaleBlobs,
} from './db.js';

const PORT = Number(process.env.PORT || 8080);

// ---------------------------------------------------------------- library doc

async function handleLibrary(ctx) {
  const { req, res } = ctx;
  if (req.method === 'GET') {
    const doc = getLibraryDoc(req.user.id);
    if (!doc) {
      sendJson(res, 200, { salt: '', iv: '', ct: '' });
      return;
    }
    sendJson(res, 200, { salt: doc.salt, iv: doc.doc_iv, ct: doc.doc_ct });
    return;
  }
  if (req.method === 'PUT') {
    const body = await readJsonBody(req, 40 * 1024 * 1024);
    const { salt, iv, ct } = body;
    const valid =
      typeof salt === 'string' && salt.length > 0 && salt.length <= 64 &&
      typeof iv === 'string' && iv.length > 0 && iv.length <= 128 &&
      typeof ct === 'string' && ct.length > 0 && ct.length <= 40 * 1024 * 1024;
    if (!valid) {
      jsonError(res, 400, 'Invalid library document.');
      return;
    }
    saveLibraryDoc(req.user.id, salt, iv, ct);
    sendJson(res, 200, { ok: true, updatedAt: Date.now() });
    return;
  }
  jsonError(res, 405, 'Method not allowed');
}

// ---------------------------------------------------------------- blob upload

async function handleBlobInit(ctx) {
  const { req, res, params } = ctx;
  const body = await readJsonBody(req, 4 * 1024);
  const { blobId, salt, iv } = body;
  const valid =
    typeof blobId === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(blobId) &&
    typeof salt === 'string' && salt.length > 0 && salt.length <= 64 &&
    typeof iv === 'string' && iv.length > 0 && iv.length <= 128;
  if (!valid) {
    jsonError(res, 400, 'Invalid blob init payload.');
    return;
  }
  const existing = getBlobRow(req.user.id, blobId);
  if (existing) {
    if (existing.complete) {
      jsonError(res, 409, 'Blob id already used.');
      return;
    }
    deleteBlob(req.user.id, blobId); // stale upload from a dropped connection
  }
  initBlob(req.user.id, blobId, salt, Buffer.from(iv, 'base64'));
  sendJson(res, 200, { ok: true });
}

function readRawBody(req, limit) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > limit) {
        reject(Object.assign(new Error('Payload too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      parts.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

async function handleBlobChunk(ctx) {
  const { req, res, params } = ctx;
  const idx = Number(params.idx);
  if (!Number.isInteger(idx) || idx < 0 || idx > 4096) {
    jsonError(res, 400, 'Invalid chunk index.');
    return;
  }
  const row = getBlobRow(req.user.id, params.id);
  if (!row || row.complete) {
    jsonError(res, 409, 'Blob not initialized or already finalized.');
    return;
  }
  let ct;
  try {
    ct = await readRawBody(req, 16 * 1024 * 1024 + 1024);
  } catch (err) {
    throw err;
  }
  if (ct.length === 0 || ct.length > 16 * 1024 * 1024) {
    jsonError(res, 400, 'Invalid chunk size.');
    return;
  }
  if (getChunkCount(req.user.id, params.id) >= 4096) {
    jsonError(res, 409, 'Too many chunks.');
    return;
  }
  addChunk(req.user.id, params.id, idx, ct);
  sendJson(res, 200, { ok: true, received: ct.length });
}

async function handleBlobFinalize(ctx) {
  const { req, res, params } = ctx;
  const body = await readJsonBody(req, 4 * 1024);
  const size = Number(body.size);
  const row = getBlobRow(req.user.id, params.id);
  if (!row) {
    jsonError(res, 404, 'Blob not found.');
    return;
  }
  if (row.complete) {
    sendJson(res, 200, { ok: true, already: true });
    return;
  }
  if (!Number.isSafeInteger(size) || size < 1 || size > 2 * 1024 * 1024 * 1024) {
    jsonError(res, 400, 'Invalid size.');
    return;
  }
  if (getChunkCount(req.user.id, params.id) === 0) {
    jsonError(res, 400, 'No chunks uploaded.');
    return;
  }
  finalizeBlob(req.user.id, params.id, size);
  sendJson(res, 200, { ok: true });
}

async function handleBlobStatus(ctx) {
  const { req, res, params } = ctx;
  const row = getBlobRow(req.user.id, params.id);
  sendJson(res, 200, {
    exists: Boolean(row),
    complete: Boolean(row && row.complete),
    chunks: getChunkCount(req.user.id, params.id),
  });
}

async function handleBlobDelete(ctx) {
  const { req, res, params } = ctx;
  deleteBlob(req.user.id, params.id);
  sendJson(res, 200, { ok: true });
}

// ---------------------------------------------------------------- blob download

// Streams the stored ciphertext back to the browser, which decrypts it.
function serveBlobStream(req, res, id) {
  const row = getBlobRow(req.user.id, id);
  if (!row || !row.complete) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Blob not found');
    return;
  }
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Cache-Control': 'private, no-store',
    'X-Blob-Salt': row.salt,
    'X-Blob-Iv': Buffer.from(row.iv).toString('base64'),
    'Access-Control-Expose-Headers': 'X-Blob-Salt, X-Blob-Iv',
  });
  if (row.ct && row.ct.length > 0) {
    res.end(Buffer.from(row.ct));
    return;
  }
  const chunks = getChunkList(req.user.id, id);
  let i = 0;
  const pump = () => {
    while (i < chunks.length) {
      const buf = Buffer.from(chunks[i].ct);
      i += 1;
      if (!res.write(buf)) {
        res.once('drain', pump);
        return;
      }
    }
    res.end();
  };
  pump();
}

// ---------------------------------------------------------------- routes

const routes = [
  { pattern: /^\/api\/auth\/signup$/, method: 'POST', handler: handleSignup },
  { pattern: /^\/api\/auth\/login$/, method: 'POST', handler: handleLogin },
  { pattern: /^\/api\/auth\/logout$/, method: 'POST', handler: handleLogout },
  { pattern: /^\/api\/auth\/me$/, method: 'GET', handler: handleMe },
  { pattern: /^\/api\/auth\/salt$/, method: 'GET', handler: handleSalt },
  { pattern: /^\/api\/library$/, handler: (c) => requireUser(handleLibrary)(c) },
  { pattern: /^\/api\/blob\/(?<id>[\w-]{8,64})\/init$/, method: 'POST', handler: (c) => requireUser(handleBlobInit)(c) },
  { pattern: /^\/api\/blob\/(?<id>[\w-]{8,64})\/chunk\/(?<idx>\d+)$/, method: 'PUT', handler: (c) => requireUser(handleBlobChunk)(c) },
  { pattern: /^\/api\/blob\/(?<id>[\w-]{8,64})\/finalize$/, method: 'POST', handler: (c) => requireUser(handleBlobFinalize)(c) },
  { pattern: /^\/api\/blob\/(?<id>[\w-]{8,64})\/status$/, method: 'GET', handler: (c) => requireUser(handleBlobStatus)(c) },
  { pattern: /^\/api\/blob\/(?<id>[\w-]{8,64})$/, method: 'DELETE', handler: (c) => requireUser(handleBlobDelete)(c) },
  { pattern: /^\/blob\/(?<id>[\w-]{8,64})$/, handler: (c) => requireUser(serveBlobStreamParam)(c) },
];

function serveBlobStreamParam(c) {
  serveBlobStream(c.req, c.res, c.params.id);
}

const handler = createRouter(routes);

const server = http.createServer(async (req, res) => {
  try {
    attachUser(req, res);
    await handler(req, res);
  } catch (err) {
    const status = err.statusCode || 500;
    if (status >= 500) console.error('[server]', err);
    if (!res.headersSent) {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: status >= 500 ? 'Internal error' : err.message }));
    } else {
      res.end();
    }
  } finally {
    sweepStaleBlobs();
  }
});

server.listen(PORT, () => {
  console.log(`music cloud — listening on http://localhost:${PORT}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close();
    process.exit(0);
  });
}

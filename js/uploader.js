// Upload pipeline. Everything here happens in the browser:
//   1. classify the file (audio vs other)
//   2. read audio metadata (title/artist/album/duration/cover)
//   3. generate a per-file key, wrap it with the master key
//   4. encrypt the file (chunked for large files, single-shot for small)
//   5. stream ciphertext chunks to the server, then finalize
// Cancellation is honored between steps and between chunks.

import { api } from './api.js';
import { store } from './store.js';
import {
  newId, makeFileKeyRecord, encryptWithIv, deriveChunkIv,
  CHUNK_SIZE, b64, decryptWithIv,
} from './crypto.js';
import { classifyFile, readAudioMetadata } from './metadata.js';

const SINGLE_SHOT_LIMIT = 4 * 1024 * 1024;

const uploadListeners = new Set();
export function onUploadProgress(fn) {
  uploadListeners.add(fn);
  return () => uploadListeners.delete(fn);
}
function emitUpload(job) {
  for (const fn of uploadListeners) fn({ ...job });
}

export function cancelUpload(itemId) {
  const job = activeJobs.get(itemId);
  if (job) job.controller.abort();
}
const activeJobs = new Map();

export async function uploadFiles(fileList, folderId) {
  const files = Array.from(fileList);
  const results = [];
  for (const file of files) {
    try {
      const item = await uploadOne(file, folderId);
      results.push({ ok: true, item });
    } catch (err) {
      results.push({ ok: false, name: file.name, error: err.message });
    }
  }
  return results;
}

async function uploadOne(file, folderId) {
  const itemId = newId('i');
  const blobId = newId('b').replace(/[^A-Za-z0-9_-]/g, '');
  const controller = new AbortController();
  const job = { controller, progress: 0, status: 'preparing' };
  activeJobs.set(itemId, job);

  const uiJob = {
    id: itemId, name: file.name, size: file.size, progress: 0, status: 'preparing',
  };
  emitUpload(uiJob);
  const setStage = (status, progress) => {
    job.status = status;
    uiJob.status = status;
    if (progress != null) { job.progress = progress; uiJob.progress = progress; }
    emitUpload(uiJob);
  };

  const throwIfAborted = () => {
    if (controller.signal.aborted) {
      const e = new Error('Upload canceled');
      e.aborted = true;
      throw e;
    }
  };

  try {
    // 1. classify + metadata (plaintext, local only)
    const { kind, playability } = classifyFile(file);
    let meta = null;
    if (kind === 'audio') {
      setStage('reading', 2);
      meta = await readAudioMetadata(file);
    }
    throwIfAborted();

    // 2. per-file key
    const { handle: fileKey, record: keyRecord } = await makeFileKeyRecord(store.masterBits);

    // 3. server-side blob slot
    setStage('encrypting', 4);
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  await api.blobInit(blobId, store.docSalt || 'mc', b64.encode(fileIv));
    throwIfAborted();

    // 4. encrypt + send
    let ciphertextTotal = 0;
    if (file.size <= SINGLE_SHOT_LIMIT) {
      const plaintext = new Uint8Array(await file.arrayBuffer());
      throwIfAborted();
      setStage('uploading', 30);
      const ct = await encryptWithIv(fileKey, fileIv, plaintext);
      await api.putChunk(blobId, 0, ct, { signal: controller.signal });
      ciphertextTotal = ct.byteLength;
      setStage('uploading', 96);
    } else {
      const chunkCount = Math.ceil(file.size / CHUNK_SIZE);
      for (let i = 0; i < chunkCount; i++) {
        throwIfAborted();
        const start = i * CHUNK_SIZE;
        const slice = new Uint8Array(await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer());
        const iv = deriveChunkIv(fileIv, i);
        const ct = await encryptWithIv(fileKey, iv, slice);
        await api.putChunk(blobId, i, ct, { signal: controller.signal });
        ciphertextTotal += ct.byteLength;
        setStage('uploading', Math.round(4 + (i + 1) / chunkCount * 92));
      }
    }

    // 5. finalize + register in the library doc
    setStage('finishing', 98);
    await api.blobFinalize(blobId, file.size);
    const item = await store.addItem({
      id: itemId,
      blobId,
      folderId,
      name: file.name,
      size: file.size,
      kind,
      mime: file.type || 'application/octet-stream',
      meta,
      playability,
      keyRecord,
    });
    setStage('done', 100);
    void ciphertextTotal;
    return item;
  } catch (err) {
    // Best-effort cleanup so failed uploads don't hold storage.
    api.blobDelete(blobId).catch(() => {});
    uiJob.status = err.aborted ? 'canceled' : 'error';
    uiJob.error = err.aborted ? null : err.message;
    emitUpload(uiJob);
    throw err;
  } finally {
    activeJobs.delete(itemId);
  }
}

// Decrypt-and-download helper shared by the player and the download action.
// Small blobs are one GCM payload. Large uploads were sent as independently
// encrypted chunks, each with IV = fileIV XOR chunkIndex, so we decrypt chunk
// by chunk and concatenate the plaintexts.
export async function fetchDecryptedBlob(item, onProgress) {
  const res = await api.fetchBlob(item.blobId);
  const ivHeader = res.headers.get('X-Blob-Iv');
  const fileIv = ivHeader ? b64.decode(ivHeader) : null;
  const buf = new Uint8Array(await res.arrayBuffer());
  if (onProgress) onProgress(55);
  const fileKey = await store.unwrapKey(item);

  let plaintext;
  if (fileIv && item.size > CHUNK_SIZE) {
    const parts = [];
    let offset = 0;
    let index = 0;
    while (offset < buf.byteLength) {
      // Each chunk ciphertext = GCM(ct || tag) for up to CHUNK_SIZE plaintext bytes.
      const overhead = 16; // GCM tag
      const maxCt = CHUNK_SIZE + overhead;
      const take = Math.min(maxCt, buf.byteLength - offset);
      const chunkCt = buf.subarray(offset, offset + take);
      const iv = deriveChunkIv(fileIv, index);
      parts.push(await decryptWithIv(fileKey, iv, chunkCt));
      offset += take;
      index += 1;
    }
    plaintext = concatBytes(parts);
  } else if (fileIv) {
    plaintext = await decryptWithIv(fileKey, fileIv, buf);
  } else {
    throw new Error('Missing decryption parameters');
  }
  if (onProgress) onProgress(100);
  return plaintext;
}

function concatBytes(parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.byteLength; }
  return out;
}

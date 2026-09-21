// Upload pipeline. Files are stored as-is (no encryption) and committed to
// the repo:   1. classify the file (audio vs other)
//   2. read audio metadata (title/artist/album/duration/cover)
//   3. upload in ~4MB parts, then finalize
// Cancellation is honored between steps and between parts.

import { api } from './api.js';
import { store } from './store.js';
import { newId, CHUNK_SIZE } from './crypto.js';
import { classifyFile, readAudioMetadata } from './metadata.js';

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
    // 1. classify + metadata
    const { kind, playability } = classifyFile(file);
    let meta = null;
    if (kind === 'audio') {
      setStage('reading', 2);
      meta = await readAudioMetadata(file);
    }
    throwIfAborted();

    // 2. blob slot
    setStage('uploading', 4);
    await api.blobInit(blobId);
    throwIfAborted();

    // 3. upload in parts
    let part = 0;
    if (file.size <= CHUNK_SIZE) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      throwIfAborted();
      await api.putChunk(blobId, 0, bytes);
      part = 1;
      setStage('uploading', 96);
    } else {
      const chunkCount = Math.ceil(file.size / CHUNK_SIZE);
      for (let i = 0; i < chunkCount; i++) {
        throwIfAborted();
        const start = i * CHUNK_SIZE;
        const slice = new Uint8Array(await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer());
        await api.putChunk(blobId, i, slice);
        part = i + 1;
        setStage('uploading', Math.round(4 + (i + 1) / chunkCount * 92));
      }
    }

    // 4. finalize + register in the library doc
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
    });
    setStage('done', 100);
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

// Plain fetch-and-assemble shared by the player and the download action.
// Large files were stored as consecutive parts; reassemble in order.
export async function fetchDecryptedBlob(item, onProgress) {
  const res = await api.fetchBlob(item.blobId);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (onProgress) onProgress(100);
  return buf;
}

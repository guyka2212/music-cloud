// Library store: owns the decrypted library document and all mutations.
// One encrypted JSON document per user; every save is read-modify-write with a
// retry on IV conflict (another tab may have saved meanwhile).

import { api } from './api.js';
import {
  encryptJson, decryptJson, newId,
} from './crypto.js';

const EMPTY_LIBRARY = () => ({
  version: 1,
  root: 'root',
  folders: {},
  items: {},
  settings: { view: 'list', sort: { key: 'name', dir: 'asc' }, theme: null },
});

export const store = {
  masterBits: null,
  doc: null,
  docSalt: '',
  listeners: new Set(),

  onChange(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  },

  emit() {
    for (const fn of this.listeners) fn();
  },

  // Called after auth; loads + decrypts (or initializes) the library document.
  async load(masterBits) {
    this.masterBits = masterBits;
    const res = await api.getLibrary();
    this.docSalt = res.salt || '';
    // Persist the doc salt for this device so password logins can re-derive the
    // master key without the recovery key (e.g. first login on a new device).
    if (this.docSalt) {
      try { localStorage.setItem('mc-salt', this.docSalt); } catch { /* private mode */ }
    }
    if (!res.ct) {
      this.doc = EMPTY_LIBRARY();
      const root = {
        id: 'root', name: 'My Library', parent: null, createdAt: Date.now(), trashed: false,
      };
      this.doc.folders.root = root;
      await this.save();
      return this.doc;
    }
    try {
      this.doc = await decryptJson(this.masterBits, res.iv, res.ct);
      this.lastIv = res.iv;
    } catch {
      const err = new Error('DECRYPT_FAILED');
      err.code = 'DECRYPT_FAILED';
      throw err;
    }
    if (!this.doc.folders || !this.doc.folders.root) {
      this.doc.folders.root = {
        id: 'root', name: 'My Library', parent: null, createdAt: Date.now(), trashed: false,
      };
    }
    return this.doc;
  },

  // Save flow: pull the latest server copy first (multi-tab safety), merge in
  // anything we don't have, then apply the mutation and push. On a 409/refresh
  // conflict we retry with a fresh pull.
  async save(mutator) {
    if (!this.masterBits) throw new Error('not signed in');
    for (let attempt = 0; attempt < 4; attempt++) {
      const res = await api.getLibrary();
      if (res.ct && res.iv !== this.lastIv) {
        // Server has a version we didn't write — merge it in before mutating.
        try {
          this.mergeServerDoc(await decryptJson(this.masterBits, res.iv, res.ct));
        } catch {
          /* undecryptable server copy (e.g. key rotated in another tab); ours wins */
        }
      }
      if (typeof mutator === 'function') mutator(this.doc);
      const { iv, ct } = await encryptJson(this.masterBits, this.doc);
      this.lastIv = iv;
      try {
        await api.saveLibrary(this.docSalt, iv, ct);
        this.emit();
        return;
      } catch (err) {
        if (err.status >= 500 || err.status === 429) {
          await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
    throw new Error('Could not save changes after several attempts.');
  },

  mergeServerDoc(serverDoc) {
    const local = this.doc;
    for (const [id, f] of Object.entries(serverDoc.folders || {})) {
      const mine = local.folders[id];
      if (!mine || (f.updatedAt || 0) > (mine.updatedAt || 0)) local.folders[id] = f;
    }
    for (const [id, it] of Object.entries(serverDoc.items || {})) {
      const mine = local.items[id];
      if (!mine || (it.updatedAt || 0) > (mine.updatedAt || 0)) local.items[id] = it;
    }
    // settings/view stay local (per-tab preference wins)
  },

  // ---------------------------------------------------------------- folders

  createFolder(name, parentId) {
    const id = newId('f');
    const folder = {
      id, name, parent: parentId, createdAt: Date.now(), updatedAt: Date.now(), trashed: false,
    };
    return this.save((doc) => { doc.folders[id] = folder; }).then(() => folder);
  },

  renameFolder(id, name) {
    return this.save((doc) => {
      if (doc.folders[id]) {
        doc.folders[id].name = name;
        doc.folders[id].updatedAt = Date.now();
      }
    });
  },

  moveFolder(id, newParent) {
    // Cycle check.
    let p = newParent;
    while (p) {
      if (p === id) return Promise.reject(new Error('Cannot move a folder into itself.'));
      p = this.doc.folders[p] ? this.doc.folders[p].parent : null;
    }
    return this.save((doc) => {
      if (doc.folders[id] && newParent !== id) {
        doc.folders[id].parent = newParent;
        doc.folders[id].updatedAt = Date.now();
      }
    });
  },

  trashFolder(id, trashedAt = Date.now()) {
    const ids = this.folderSubtree(id);
    return this.save((doc) => {
      for (const fid of ids) {
        if (doc.folders[fid]) { doc.folders[fid].trashed = true; doc.folders[fid].trashedAt = trashedAt; }
      }
      for (const it of Object.values(doc.items)) {
        if (ids.includes(it.folderId)) { it.trashed = true; it.trashedAt = trashedAt; }
      }
    });
  },

  restoreFolder(id) {
    const folder = this.doc.folders[id];
    if (!folder) return Promise.resolve();
    const ids = this.folderSubtree(id);
    const parent = this.doc.folders[folder.parent];
    const parentMissing = folder.parent && (!parent || parent.trashed);
    return this.save((doc) => {
      for (const fid of ids) {
        if (doc.folders[fid]) { doc.folders[fid].trashed = false; delete doc.folders[fid].trashedAt; }
      }
      for (const it of Object.values(doc.items)) {
        if (ids.includes(it.folderId)) { it.trashed = false; delete it.trashedAt; }
      }
      if (parentMissing || !folder.parent) doc.folders[id].parent = 'root';
    });
  },

  async deleteFolderForever(id) {
    const ids = this.folderSubtree(id);
    const blobIds = [];
    for (const it of Object.values(this.doc.items)) {
      if (ids.includes(it.folderId)) blobIds.push(it.blobId);
    }
    await Promise.allSettled(blobIds.map((b) => api.blobDelete(b)));
    await this.save((doc) => {
      for (const fid of ids) delete doc.folders[fid];
      for (const [iid, it] of Object.entries(doc.items)) {
        if (ids.includes(it.folderId)) delete doc.items[iid];
      }
    });
  },

  folderSubtree(id) {
    const out = [id];
    for (const f of Object.values(this.doc.folders)) {
      if (f.parent === id) out.push(...this.folderSubtree(f.id));
    }
    return out;
  },

  folderPath(id) {
    const path = [];
    let cur = id;
    while (cur) {
      const f = this.doc.folders[cur];
      if (!f) break;
      path.unshift(f);
      cur = f.parent;
    }
    return path;
  },

  // ---------------------------------------------------------------- items (files)

  async addItem(record) {
    // record.keyRecord is the per-file key already wrapped with the master key
    // by the uploader — the same key that encrypted the bytes on the server.
    const item = {
      id: record.id,
      blobId: record.blobId,
      folderId: record.folderId,
      name: record.name,
      size: record.size,
      kind: record.kind, // 'audio' | 'file'
      mime: record.mime,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      trashed: false,
      key: record.keyRecord,
      // audio metadata (parsed client-side at upload time):
      meta: record.meta || null,
      playability: record.playability || 'unknown',
    };
    await this.save((doc) => { doc.items[item.id] = item; });
    return item;
  },

  renameItem(id, name) {
    return this.save((doc) => {
      if (doc.items[id]) {
        doc.items[id].name = name;
        doc.items[id].updatedAt = Date.now();
      }
    });
  },

  moveItem(id, newFolderId) {
    return this.save((doc) => {
      if (doc.items[id]) {
        doc.items[id].folderId = newFolderId;
        doc.items[id].updatedAt = Date.now();
      }
    });
  },

  trashItem(id, trashedAt = Date.now()) {
    return this.save((doc) => {
      if (doc.items[id]) { doc.items[id].trashed = true; doc.items[id].trashedAt = trashedAt; }
    });
  },

  restoreItem(id) {
    return this.save((doc) => {
      const it = doc.items[id];
      if (!it) return;
      it.trashed = false;
      delete it.trashedAt;
      const f = doc.folders[it.folderId];
      if (it.folderId !== 'root' && (!f || f.trashed)) it.folderId = 'root';
    });
  },

  async deleteItemForever(id) {
    const item = this.doc.items[id];
    if (item) {
      await api.blobDelete(item.blobId).catch(() => {});
      await this.save((doc) => { delete doc.items[id]; });
    }
  },

  async emptyTrash() {
    const trashed = Object.values(this.doc.items).filter((i) => i.trashed);
    const trashedFolders = Object.values(this.doc.folders).filter((f) => f.trashed);
    await Promise.allSettled(trashed.map((i) => api.blobDelete(i.blobId)));
    await this.save((doc) => {
      for (const i of trashed) delete doc.items[i.id];
      for (const f of trashedFolders) {
        for (const fid of this.folderSubtree(f.id)) delete doc.folders[fid];
      }
      for (const it of Object.values(doc.items)) {
        if (it.trashed && trashedFolders.some((f) => this.folderSubtree(f.id).includes(it.folderId))) {
          delete doc.items[it.id];
        }
      }
    });
  },

  // ---------------------------------------------------------------- queries

  children(folderId, { includeTrashed = false } = {}) {
    const folders = Object.values(this.doc.folders)
      .filter((f) => f.parent === folderId && (includeTrashed || !f.trashed));
    const items = Object.values(this.doc.items)
      .filter((i) => i.folderId === folderId && (includeTrashed || !i.trashed));
    return { folders, items };
  },

  search(query) {
    const q = query.trim().toLowerCase();
    if (!q) return { folders: [], items: [] };
    const folders = Object.values(this.doc.folders).filter((f) =>
      !f.trashed && f.id !== 'root' && f.name.toLowerCase().includes(q));
    const items = Object.values(this.doc.items).filter((i) => {
      if (i.trashed) return false;
      const hay = [i.name, i.meta && i.meta.artist, i.meta && i.meta.album]
        .filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    });
    return { folders, items };
  },

  async unwrapKey(item) {
    const { unwrapFileKey } = await import('./crypto.js');
    return unwrapFileKey(this.masterBits, item.key);
  },

  storageUsed() {
    return Object.values(this.doc.items).reduce((sum, i) => sum + (Number(i.size) || 0), 0);
  },
};

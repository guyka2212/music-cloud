// Library store: owns the shared library document and all mutations.
// One public JSON document; every save is read-modify-write so concurrent
// visitors never lose each other's changes.

import { api } from './api.js';
import { newId } from './crypto.js';

const EMPTY_LIBRARY = () => ({
  version: 1,
  root: 'root',
  folders: {},
  items: {},
  settings: { view: 'list', sort: { key: 'name', dir: 'asc' }, theme: null },
});

export const store = {
  doc: null,
  lastSaved: null,
  listeners: new Set(),

  onChange(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  },

  emit() {
    for (const fn of this.listeners) fn();
  },

  async load() {
    const res = await api.getLibrary();
    if (!res || !res.folders || !res.folders.root) {
      this.doc = EMPTY_LIBRARY();
      this.doc.folders.root = {
        id: 'root', name: 'Shared Music', parent: null, createdAt: Date.now(), trashed: false,
      };
      await this.save(null, 'mc: init library');
      return this.doc;
    }
    this.doc = res;
    this.lastSaved = JSON.stringify(res);
    return this.doc;
  },

  async save(mutator, message) {
    // Pull the latest copy, apply the mutation, push. A 409 means someone else
    // committed between our read and write; retry with a fresh pull.
    for (let attempt = 0; attempt < 4; attempt++) {
      const res = await api.getLibrary();
      if (res && res.folders && res.folders.root) {
        if (this.lastSaved !== JSON.stringify(res)) {
          // Someone else changed the library since we loaded it — merge.
          this.mergeServerDoc(res);
        }
      }
      if (typeof mutator === 'function') mutator(this.doc);
      const serialized = JSON.stringify(this.doc);
      try {
        await api.saveLibrary(this.doc, message);
        this.lastSaved = serialized;
        this.emit();
        return;
      } catch (err) {
        if (err.status === 409 || err.status >= 500 || err.status === 429) {
          await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
    throw new Error('Could not save changes after several attempts.');
  },

  mergeServerDoc(serverDoc) {
    for (const [id, f] of Object.entries(serverDoc.folders || {})) {
      const mine = this.doc.folders[id];
      if (!mine || (f.updatedAt || 0) > (mine.updatedAt || 0)) this.doc.folders[id] = f;
    }
    for (const [id, it] of Object.entries(serverDoc.items || {})) {
      const mine = this.doc.items[id];
      if (!mine || (it.updatedAt || 0) > (mine.updatedAt || 0)) this.doc.items[id] = it;
    }
  },

  // ---------------------------------------------------------------- folders

  createFolder(name, parentId) {
    const id = newId('f');
    const folder = {
      id, name, parent: parentId, createdAt: Date.now(), updatedAt: Date.now(), trashed: false,
    };
    return this.save((doc) => { doc.folders[id] = folder; }, `mc: folder ${name}`).then(() => folder);
  },

  renameFolder(id, name) {
    return this.save((doc) => {
      if (doc.folders[id]) {
        doc.folders[id].name = name;
        doc.folders[id].updatedAt = Date.now();
      }
    }, `mc: rename folder`);
  },

  moveFolder(id, newParent) {
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
    }, 'mc: move folder');
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
    }, 'mc: trash folder');
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
    }, 'mc: restore folder');
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
    }, 'mc: delete folder');
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
      meta: record.meta || null,
      playability: record.playability || 'unknown',
    };
    await this.save((doc) => { doc.items[item.id] = item; }, `mc: add ${record.name}`);
    return item;
  },

  renameItem(id, name) {
    return this.save((doc) => {
      if (doc.items[id]) {
        doc.items[id].name = name;
        doc.items[id].updatedAt = Date.now();
      }
    }, 'mc: rename file');
  },

  moveItem(id, newFolderId) {
    return this.save((doc) => {
      if (doc.items[id]) {
        doc.items[id].folderId = newFolderId;
        doc.items[id].updatedAt = Date.now();
      }
    }, 'mc: move file');
  },

  trashItem(id, trashedAt = Date.now()) {
    return this.save((doc) => {
      if (doc.items[id]) { doc.items[id].trashed = true; doc.items[id].trashedAt = trashedAt; }
    }, 'mc: trash file');
  },

  restoreItem(id) {
    return this.save((doc) => {
      const it = doc.items[id];
      if (!it) return;
      it.trashed = false;
      delete it.trashedAt;
      const f = doc.folders[it.folderId];
      if (it.folderId !== 'root' && (!f || f.trashed)) it.folderId = 'root';
    }, 'mc: restore file');
  },

  async deleteItemForever(id) {
    const item = this.doc.items[id];
    if (item) {
      await api.blobDelete(item.blobId).catch(() => {});
      await this.save((doc) => { delete doc.items[id]; }, `mc: delete ${item.name}`);
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
    }, 'mc: empty trash');
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

  storageUsed() {
    return Object.values(this.doc.items).reduce((sum, i) => sum + (Number(i.size) || 0), 0);
  },
};

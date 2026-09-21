// App shell and views. Single page: auth -> unlock -> library.

import { api, selectBackend, backendKind } from './api.js';
import { store } from './store.js';
import {
  createAccountCredentials, loginCredentialsWithPassword, loginCredentialsWithRecovery,
  generateSalt, b64, utf8,
} from './crypto.js';
import { el, fmt, promptDialog, confirmDialog, openDialog, openMenu, toast } from './ui.js';
import { icon } from './icons.js';
import { uploadFiles, onUploadProgress, cancelUpload, fetchDecryptedBlob } from './uploader.js';
import { buildPlayerBar, playItem, guessMime } from './player.js';
import { makeZip } from './zip.js';

// Synchronous capability check: the browser tells us if it can decode this
// container/codec. Unsupported formats still show up — with a download action
// instead of play.
const playCache = new Map();
function isPlayableAudio(item) {
  if (item.kind !== 'audio' || item.playability === 'never') return false;
  if (!playCache.has(item.id)) {
    const a = document.createElement('audio');
    const verdict = a.canPlayType(guessMime(item)); // '' | 'maybe' | 'probably'
    playCache.set(item.id, verdict !== '');
  }
  return playCache.get(item.id);
}

const state = {
  view: 'library',        // library | recent | trash
  folderId: 'root',
  query: '',
  sortBy: localStorage.getItem('mc-sort') || 'name',
  sortDir: localStorage.getItem('mc-dir') || 'asc',
  viewMode: localStorage.getItem('mc-view') || 'list',
  uploads: new Map(),
};

/* ================================================================ auth gate */

function showAuth({ mode = 'login' } = {}) {
  document.title = 'music cloud';
  const root = document.getElementById('app');
  root.replaceChildren();
  const isSignup = mode === 'signup';

  const email = el('input', { class: 'input', type: 'email', autocomplete: 'email', placeholder: 'you@example.com', id: 'auth-email' });
  const password = el('input', { class: 'input', type: 'password', autocomplete: isSignup ? 'new-password' : 'current-password', placeholder: '••••••••••', id: 'auth-password' });
  const submit = el('button', { class: 'btn primary wide', type: 'submit', text: isSignup ? 'Create account' : 'Sign in' });
  const error = el('p', { class: 'form-error', role: 'alert' });

  const form = el('form', { class: 'auth-form' },
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'auth-email', text: 'Email' }), email),
    el('div', { class: 'field' },
      el('label', { class: 'field-label', for: 'auth-password', text: 'Password' }),
      password),
    submit,
    error,
  );

  const localMode = backendKind() === 'local';
  const ghMode = backendKind() === 'github';

  const card = el('div', { class: 'auth-card' },
    el('div', { class: 'brand' }, icon('music', 20), el('span', { text: 'music cloud' })),
    el('h1', { class: 'auth-title', text: isSignup ? 'Create your library' : 'Sign in' }),
    el('p', { class: 'auth-sub', text: isSignup
      ? 'Files are encrypted in this browser before anything leaves this device.'
      : 'Your library is decrypted in this browser only.' }),
    form,
    el('div', { class: 'auth-switch' },
      el('button', {
        class: 'linklike', type: 'button',
        text: isSignup ? 'Already have an account? Sign in' : 'Need an account? Create one',
        onclick: () => showAuth({ mode: isSignup ? 'login' : 'signup' }),
      }),
      ghMode
        ? el('button', { class: 'linklike', type: 'button', text: 'Stop using GitHub sync for this browser', onclick: disableGhMode })
        : el('button', { class: 'linklike', type: 'button', text: 'Use GitHub sync (same library on every device)', onclick: showGhSetup }),
    ),
    el('p', { class: 'hint', text: ghMode
      ? 'Mode: GitHub sync — signing up will commit your account to the music-cloud repo.'
      : 'Mode: local — your account will exist only in this browser.' }),
  );

  const aside = el('aside', { class: 'auth-aside' },
    el('h2', { class: 'aside-title', text: 'End-to-end encrypted' }),
    el('p', {}, ghMode
      ? 'GitHub sync: your encrypted library and account record are stored in the music-cloud repo (data/ folder). A GitHub token in this browser authorizes the commits; your password never leaves this device.'
      : localMode
        ? 'This is the static build: your account, library, and encrypted audio live in this browser (IndexedDB). Your password derives the key — it is never stored or uploaded.'
        : 'Your password never leaves this device. It derives the key that encrypts your library and files. The server stores ciphertext only.'),
    el('p', {}, 'No password, no access — there is no reset. A recovery key is shown once at signup; keep it somewhere safe.'),
    localMode ? el('p', { class: 'hint' }, 'Because data lives in this browser, clearing site data deletes the library. Use the same browser profile to return to it.') : null,
    ghMode ? el('p', { class: 'hint' }, 'Sign in with the same email and password on any device to reach the same library.') : null,
  );

  root.append(el('div', { class: 'auth-wrap' },
    el('main', { class: 'auth-main' },
      card,
      el('p', { class: 'auth-recovery-link' },
        el('button', { class: 'linklike', type: 'button', text: 'Sign in with recovery key', onclick: showRecoveryLogin })),
    ),
    aside,
  ));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    error.textContent = '';
    submit.disabled = true;
    const originalLabel = submit.textContent;
    submit.textContent = isSignup ? 'Creating account…' : 'Deriving key…';
    try {
      const pw = password.value;
      if (pw.length < 8) throw new Error('Password must be at least 8 characters.');
      if (isSignup) {
        // GitHub mode uses a deterministic per-email salt so every device
        // derives the same key without a pre-auth lookup.
        const salt = backendKind() === 'github'
          ? (await api.salt(email.value.trim())).salt
          : await generateSalt();
        const { masterBits, authHash, recoveryKey } = await createAccountCredentials(pw, salt);
        const recoveryHash = await sha256B64Url(utf8.encode(recoveryKey));
        await api.signup(email.value.trim(), authHash, recoveryHash, salt);
        localStorage.setItem('mc-salt', salt);
        await startApp(masterBits);
        showRecoveryKeyDialog(recoveryKey);
      } else {
        // Fetch this account's public KDF salt, then derive locally.
        const { salt } = await api.salt(email.value.trim());
        if (!salt) throw new Error('No key material found for that account.');
        localStorage.setItem('mc-salt', salt);
        const { masterBits, authHash } = await loginCredentialsWithPassword(pw, salt);
        await api.login(email.value.trim(), authHash, null);
        await startApp(masterBits);
      }
    } catch (err) {
      error.textContent = err.message || 'Something went wrong.';
    } finally {
      submit.disabled = false;
      submit.textContent = originalLabel;
    }
  });

  if (isSignup) email.focus();
  else password.focus();
}

async function sha256B64Url(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return b64.encode(new Uint8Array(d));
}

function showGhSetup() {
  const tokenInput = el('input', { class: 'input', type: 'password', placeholder: 'github_pat_… or ghp_…', id: 'gh-token' });
  const err = el('p', { class: 'form-error', role: 'alert' });
  openDialog({
    title: 'Use GitHub sync',
    width: 520,
    body: el('div', {},
      el('p', { class: 'dialog-message' },
        'GitHub sync stores your encrypted library in the music-cloud repo so the same account works on every device. You need a GitHub token with Contents: read and write for this repository.'),
      el('p', { class: 'hint' },
        'Create a fine-grained token at GitHub → Settings → Developer settings → Fine-grained tokens. Select only this repository, permission “Contents: Read and write”. The token is kept in this browser only.'),
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'gh-token', text: 'GitHub token' }), tokenInput),
      err,
    ),
    actions: [
      { label: 'Cancel', onClick: (close) => close() },
      {
        label: 'Save and reload', kind: 'primary',
        onClick: async (close) => {
          const t = tokenInput.value.trim();
          if (!t) { err.textContent = 'Paste a token first.'; return; }
          try {
            const r = await fetch('https://api.github.com/repos/guyka2212/music-cloud', {
              headers: { Authorization: `Bearer ${t}`, Accept: 'application/vnd.github+json' },
            });
            if (r.status === 401) throw new Error('GitHub rejected this token (401).');
            if (!r.ok) throw new Error(`Token check failed (${r.status}). Make sure it can access guyka2212/music-cloud.`);
            const repo = await r.json();
            if (!repo.permissions || repo.permissions.push !== true) {
              throw new Error('This token can read but not write. Re-create it with permission “Contents: Read and write”.');
            }
            localStorage.setItem('mc-gh-token', t);
            localStorage.setItem('mc-backend', 'github');
            close();
            location.reload();
          } catch (e2) {
            err.textContent = e2.message;
          }
        },
      },
    ],
  });
}

function disableGhMode() {
  localStorage.removeItem('mc-backend');
  localStorage.removeItem('mc-gh-token');
  location.reload();
}

function showRecoveryLogin() {
  const input = el('textarea', { class: 'input', rows: '2', placeholder: 'XXXXX-XXXXX-XXXXX-XXXXX-…', id: 'rk-input' });
  const email = el('input', { class: 'input', type: 'email', placeholder: 'Account email', id: 'rk-email' });
  const err = el('p', { class: 'form-error', role: 'alert' });
  openDialog({
    title: 'Sign in with recovery key',
    width: 480,
    body: el('div', {},
      el('p', { class: 'dialog-message', text: 'The recovery key re-derives your library key on this device. Your usual password keeps working afterwards.' }),
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'rk-email', text: 'Email' }), email),
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'rk-input', text: 'Recovery key' }), input),
      err,
    ),
    actions: [
      { label: 'Cancel', onClick: (close) => close() },
      {
        label: 'Continue', kind: 'primary',
        onClick: async (close) => {
          err.textContent = '';
          try {
            const creds = await loginCredentialsWithRecovery(input.value);
            if (!creds) throw new Error('That key does not look right. Check the groups and try again.');
            await api.login(email.value.trim(), '', creds.recoveryHash);
            // Remember the account's public KDF salt for future password logins
            // on this device, then open the library with the recovered key.
            try {
              const { salt } = await api.salt(email.value.trim());
              if (salt) localStorage.setItem('mc-salt', salt);
            } catch { /* keep whatever is cached */ }
            await startApp(creds.masterBits);
            close();
          } catch (e2) {
            err.textContent = e2.message;
          }
        },
      },
    ],
  });
}

function showRecoveryKeyDialog(recoveryKey) {
  const keyText = el('code', { class: 'recovery-key', text: recoveryKey });
  openDialog({
    title: 'Save your recovery key',
    width: 500,
    body: el('div', {},
      el('p', { class: 'dialog-message' },
        'This is the only time we show your recovery key. If you ever lose your password, this is the only way back into your library.'),
      el('div', { class: 'recovery-box' }, keyText),
      el('p', { class: 'hint' }, '11 groups of 5 characters. Only a hash of it is stored — the key itself never leaves your devices.'),
    ),
    actions: [
      {
        label: 'Download .txt',
        onClick: (close) => {
          const blob = new Blob([`music cloud recovery key\n\n${recoveryKey}\n\nKeep this file somewhere safe — anyone with it can open your library.\n`], { type: 'text/plain' });
          const a = el('a', { href: URL.createObjectURL(blob), download: 'music-cloud-recovery-key.txt' });
          document.body.append(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 30_000);
          close();
        },
      },
      { label: 'I saved it', kind: 'primary', onClick: (close) => close() },
    ],
  });
}

/* ================================================================ boot + start */

let currentEmail = null; // display only; the real session lives in the driver

async function startApp(masterBits) {
  // The derived key lives in memory only; a page refresh asks for the password
  // again. That is the standard tradeoff for end-to-end encrypted apps.
  // Re-verify the session server-side (or driver-side) before rendering —
  // a dashboard must never appear without a confirmed authenticated session.
  try {
    const me = await api.me();
    if (!me || !me.user) throw new Error('Session missing');
    currentEmail = me.user.email || currentEmail;
  } catch (err) {
    showAuth({ mode: 'login' });
    if (err && err.message && err.message !== 'Session missing') throw err;
    return;
  }
  await store.load(masterBits);
  buildShell();
  render();
}

async function boot() {
  setupThemeToggle();
  await selectBackend();
  // The session may still be valid, but the encryption key only exists after
  // this device derives it — so the password is always required here.
  showAuth({ mode: 'login' });
}

function signOut() {
  api.logout().finally(() => {
    location.reload();
  });
}

/* ================================================================ shell */

function buildShell() {
  const app = document.getElementById('app');
  app.replaceChildren();

  const sidebar = el('aside', { class: 'sidebar' });
  const main = el('div', { class: 'main' });
  const playerRoot = el('div', { id: 'player-root' });
  const dropOverlay = el('div', { class: 'drop-overlay', 'aria-hidden': 'true' },
    el('div', { class: 'drop-box' }, icon('upload', 26), el('p', { text: 'Drop files to encrypt and upload' })));
  const uploadsPanel = el('div', { id: 'uploads-panel', class: 'uploads-panel', 'aria-label': 'Upload progress' });

  app.append(
    el('div', { class: 'shell' },
      el('div', { class: 'shell-body' }, sidebar, main),
      uploadsPanel,
      playerRoot,
    ),
    dropOverlay,
  );

  buildSidebar(sidebar);
  buildPlayerBar(playerRoot);
  setupDragDrop(dropOverlay);
  setupMobileChrome(app);
}

function setupMobileChrome(app) {
  const menuBtn = el('button', { class: 'icon-btn menu-btn', 'aria-label': 'Open sidebar', 'aria-expanded': 'false' }, icon('menu', 20));
  const fab = el('button', { class: 'fab', 'aria-label': 'Add folder or upload files', 'aria-haspopup': 'menu' }, icon('plus', 24));
  const scrim = el('div', { class: 'scrim', 'aria-hidden': 'true' });
  app.append(menuBtn, fab, scrim);

  const sidebar = document.querySelector('.sidebar');
  const closeSidebar = () => { sidebar.classList.remove('open'); scrim.classList.remove('visible'); menuBtn.setAttribute('aria-expanded', 'false'); };
  menuBtn.onclick = () => {
    const open = !sidebar.classList.contains('open');
    sidebar.classList.toggle('open', open);
    scrim.classList.toggle('visible', open);
    menuBtn.setAttribute('aria-expanded', String(open));
  };
  scrim.onclick = closeSidebar;

  fab.onclick = () => openMenu({
    anchor: fab,
    align: 'end',
    onClose: () => fab.setAttribute('aria-expanded', 'false'),
    items: [
      { label: 'New folder', icon: 'folder-plus', onClick: () => createFolderFlow() },
      { label: 'Upload music', icon: 'music', onClick: () => uploadFlow('audio') },
      { label: 'Upload a file', icon: 'file', onClick: () => uploadFlow('any') },
    ],
  });

  // Place the menu button into the toolbar once it renders.
  const toolbarObserver = new MutationObserver(() => {
    const toolbar = document.querySelector('.toolbar');
    if (toolbar && !toolbar.contains(menuBtn)) {
      toolbar.prepend(menuBtn);
    }
  });
  toolbarObserver.observe(app, { childList: true, subtree: true });
}

function buildSidebar(sidebar) {
  const newBtn = el('button', { class: 'btn new-btn', type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false' },
    icon('plus', 18), el('span', { text: 'New' }));
  newBtn.onclick = () => {
    newBtn.setAttribute('aria-expanded', 'true');
    openMenu({
      anchor: newBtn,
      onClose: () => newBtn.setAttribute('aria-expanded', 'false'),
      items: [
        { label: 'New folder', icon: 'folder-plus', onClick: () => createFolderFlow() },
        { label: 'Upload music', icon: 'music', onClick: () => uploadFlow('audio') },
        { label: 'Upload a file', icon: 'file', onClick: () => uploadFlow('any') },
      ],
    });
  };

  const nav = el('nav', { class: 'side-nav', 'aria-label': 'Library sections' });
  const mk = (label, iconName, viewName) => {
    const b = el('button', { class: 'side-link', type: 'button' }, icon(iconName, 18), el('span', { text: label }));
    b.dataset.view = viewName;
    b.onclick = () => {
      state.view = viewName;
      state.folderId = 'root';
      state.query = '';
      if (searchInput) searchInput.value = '';
      render();
    };
    return b;
  };
  nav.append(mk('My Library', 'library', 'library'), mk('Recent', 'clock', 'recent'), mk('Trash', 'trash-2', 'trash'));

  const meterBar = el('div', { class: 'meter-bar' }, el('div', { class: 'meter-fill' }));
  const meterLabel = el('div', { class: 'meter-label' });
  const meter = el('div', { class: 'storage-meter' }, meterBar, meterLabel);

  sidebar.append(
    el('div', { class: 'side-top' },
      el('div', { class: 'side-brand' }, icon('music', 18), el('span', { text: 'music cloud' })),
      newBtn,
    ),
    nav,
    meter,
    el('div', { class: 'side-footer' },
      el('button', { class: 'icon-btn', 'aria-label': 'Toggle light or dark theme', onclick: toggleTheme }),
      el('button', { class: 'side-link small', type: 'button', onclick: signOut }, icon('log-out', 16), el('span', { text: 'Sign out' })),
      currentEmail ? el('div', { class: 'side-email', title: currentEmail, text: currentEmail }) : null,
    ),
  );

  window._mc = { newBtn, meterFill: meterBar.querySelector('.meter-fill'), meterLabel };
}

let searchInput = null;
function buildSearch() {
  if (!searchInput) {
    searchInput = el('input', {
      class: 'search', type: 'search', placeholder: 'Search your library',
      'aria-label': 'Search your library',
      oninput: () => { state.query = searchInput.value; render(); },
    });
  }
  return searchInput;
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('mc-theme', next);
}

function setupThemeToggle() {
  const saved = localStorage.getItem('mc-theme');
  document.documentElement.dataset.theme =
    saved || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}

function setupDragDrop(dropOverlay) {
  let depth = 0;
  window.addEventListener('dragenter', (e) => {
    if (e.dataTransfer?.types?.includes('Files')) {
      depth += 1;
      dropOverlay.classList.add('visible');
    }
  });
  window.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) dropOverlay.classList.remove('visible');
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', async (e) => {
    e.preventDefault();
    depth = 0;
    dropOverlay.classList.remove('visible');
    if (e.dataTransfer?.files?.length) {
      await uploadFiles(e.dataTransfer.files, state.view === 'library' ? state.folderId : 'root');
    }
  });
}

/* ================================================================ new + upload flows */

function uploadFlow(kind) {
  // Uploads from Recent/Trash/search views land in the library root.
  const target = state.view === 'library' && !state.query ? state.folderId : 'root';
  const input = el('input', {
    type: 'file',
    multiple: true,
    accept: kind === 'audio'
      ? 'audio/*,.mp3,.wav,.flac,.aac,.m4a,.ogg,.oga,.opus,.aiff,.aif,.wma,.m4b,.caf,.weba'
      : '',
  });
  input.style.display = 'none';
  document.body.append(input);
  input.addEventListener('change', async () => {
    if (input.files.length) await uploadFiles(input.files, target);
    input.remove();
  });
  input.click();
}

async function createFolderFlow() {
  const name = await promptDialog({
    title: 'New folder',
    label: 'Folder name',
    placeholder: 'e.g. Field recordings',
    confirm: 'Create',
  });
  if (!name) return;
  const parent = state.view === 'library' && !state.query ? state.folderId : 'root';
  await store.createFolder(name, parent);
  render();
  toast(`Folder "${name}" created`);
}

/* ================================================================ rendering */

function render() {
  if (!store.doc) return;
  const main = document.querySelector('.main');
  if (!main) return;
  main.replaceChildren();

  if (state.view === 'library') renderLibrary(main);
  else if (state.view === 'recent') renderRecent(main);
  else renderTrash(main);

  updateMeter();
  updateNav();
  document.title = 'music cloud';
}

function currentEntries() {
  let folders = [];
  let items = [];
  if (state.view === 'trash') {
    folders = Object.values(store.doc.folders).filter((f) => f.trashed);
    items = Object.values(store.doc.items).filter((i) => i.trashed);
  } else if (state.query) {
    ({ folders, items } = store.search(state.query));
  } else if (state.view === 'recent') {
    items = Object.values(store.doc.items)
      .filter((i) => !i.trashed)
      .sort((a, b) => (b.updatedAt || b.createdAt) - (a.updatedAt || a.createdAt))
      .slice(0, 20);
  } else {
    ({ folders, items } = store.children(state.folderId));
  }

  const dir = state.sortDir === 'desc' ? -1 : 1;
  const cmp = (getter) => (a, b) => {
    const av = getter(a);
    const bv = getter(b);
    if (typeof av === 'string' || typeof bv === 'string') {
      return String(av).localeCompare(String(bv), undefined, { numeric: true }) * dir;
    }
    return ((av || 0) - (bv || 0)) * dir;
  };
  folders.sort((a, b) => (state.sortBy === 'date'
    ? cmp((x) => x.createdAt)(a, b)
    : cmp((x) => x.name.toLowerCase())(a, b)));
  items.sort((a, b) => {
    if (state.sortBy === 'date') return cmp((x) => x.updatedAt || x.createdAt)(a, b);
    if (state.sortBy === 'size') return cmp((x) => x.size)(a, b);
    if (state.sortBy === 'artist') return cmp((x) => (x.meta?.artist || '').toLowerCase())(a, b);
    return cmp((x) => x.name.toLowerCase())(a, b);
  });
  return { folders, items };
}

function renderLibrary(main) {
  const crumbs = store.folderPath(state.folderId);
  const { folders, items } = currentEntries();

  const crumbBar = el('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' });
  crumbs.forEach((f, i) => {
    if (i > 0) crumbBar.append(icon('chevron-right', 14));
    if (i === crumbs.length - 1) {
      crumbBar.append(el('span', { class: 'crumb current', 'aria-current': 'page', text: f.name }));
    } else {
      crumbBar.append(el('button', {
        class: 'crumb linklike', text: f.name,
        onclick: () => { state.folderId = f.id; state.query = ''; if (searchInput) searchInput.value = ''; render(); },
      }));
    }
  });

  main.append(el('div', { class: 'toolbar' },
    crumbBar,
    el('div', { class: 'toolbar-right' },
      buildSearch(),
      buildSort(),
      buildViewToggle(),
    ),
  ));

  main.append(state.viewMode === 'grid' ? buildGrid(folders, items) : buildList(folders, items));
}

function renderRecent(main) {
  const { items } = currentEntries();
  main.append(el('div', { class: 'toolbar' },
    el('h2', { class: 'view-title', text: 'Recent' }),
    el('div', { class: 'toolbar-right' }, buildSearch()),
  ));
  main.append(buildList([], items));
}

function renderTrash(main) {
  const { folders, items } = currentEntries();
  const toolbar = el('div', { class: 'toolbar' },
    el('h2', { class: 'view-title', text: 'Trash' }),
    el('div', { class: 'toolbar-right' },
      Object.values(store.doc.items).some((i) => i.trashed) || Object.values(store.doc.folders).some((f) => f.trashed)
        ? el('button', {
          class: 'btn subtle', text: 'Empty trash',
          onclick: async () => {
            const ok = await confirmDialog({
              title: 'Empty trash?',
              message: 'Everything in the trash will be deleted for good. This cannot be undone.',
              confirmLabel: 'Empty trash',
            });
            if (!ok) return;
            await store.emptyTrash();
            render();
            toast('Trash emptied');
          },
        }) : null,
    ),
  );
  main.append(toolbar);
  main.append(buildList(folders, items));
}

function buildSort() {
  const labels = { name: 'Name', date: 'Date modified', size: 'Size', artist: 'Artist' };
  const btn = el('button', { class: 'btn subtle', type: 'button' },
    el('span', { text: labels[state.sortBy] || 'Name' }),
    icon(state.sortDir === 'asc' ? 'arrow-up' : 'arrow-down', 14));
  btn.setAttribute('aria-label', 'Sort files');
  btn.onclick = () => openMenu({
    anchor: btn,
    align: 'end',
    items: Object.entries(labels).map(([k, label]) => ({
      label: `${label}${state.sortBy === k ? (state.sortDir === 'asc' ? ' · asc' : ' · desc') : ''}`,
      icon: state.sortBy === k ? 'check' : null,
      onClick: () => {
        if (state.sortBy === k) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
        else { state.sortBy = k; state.sortDir = 'asc'; }
        localStorage.setItem('mc-sort', state.sortBy);
        localStorage.setItem('mc-dir', state.sortDir);
        render();
      },
    })),
  });
  return btn;
}

function buildViewToggle() {
  const wrap = el('div', { class: 'view-toggle', role: 'group', 'aria-label': 'View mode' });
  const listBtn = el('button', { class: 'icon-btn', 'aria-label': 'List view', 'aria-pressed': 'false' }, icon('list', 18));
  const gridBtn = el('button', { class: 'icon-btn', 'aria-label': 'Grid view', 'aria-pressed': 'false' }, icon('layout-grid', 18));
  const sync = () => {
    listBtn.classList.toggle('active', state.viewMode === 'list');
    gridBtn.classList.toggle('active', state.viewMode === 'grid');
    listBtn.setAttribute('aria-pressed', String(state.viewMode === 'list'));
    gridBtn.setAttribute('aria-pressed', String(state.viewMode === 'grid'));
  };
  listBtn.onclick = () => { state.viewMode = 'list'; localStorage.setItem('mc-view', 'list'); render(); };
  gridBtn.onclick = () => { state.viewMode = 'grid'; localStorage.setItem('mc-view', 'grid'); render(); };
  sync();
  wrap.append(listBtn, gridBtn);
  return wrap;
}

/* ================================================================ listings */

function buildList(folders, items) {
  const table = el('div', { class: 'listing', role: 'table', 'aria-label': 'Files and folders' });
  table.append(el('div', { class: 'lrow lhead', role: 'row' },
    el('div', { class: 'cell c-name', role: 'columnheader', text: 'Name' }),
    el('div', { class: 'cell c-artist', role: 'columnheader', text: 'Artist' }),
    el('div', { class: 'cell c-dur', role: 'columnheader', text: 'Duration' }),
    el('div', { class: 'cell c-size', role: 'columnheader', text: 'Size' }),
    el('div', { class: 'cell c-date', role: 'columnheader', text: 'Modified' }),
    el('div', { class: 'cell c-menu', role: 'columnheader', text: '' }),
  ));

  if (!folders.length && !items.length) {
    table.append(el('div', { class: 'empty-row' }, emptyState()));
    return table;
  }

  for (const f of folders) {
    const row = el('div', {
      class: 'lrow', role: 'row', tabindex: '0', dataset: { id: f.id, type: 'folder' },
    },
      el('div', { class: 'cell c-name' }, icon('folder', 18), el('span', { class: 'fname', text: f.name })),
      el('div', { class: 'cell c-artist', text: '—' }),
      el('div', { class: 'cell c-dur', text: '—' }),
      el('div', { class: 'cell c-size', text: '—' }),
      el('div', { class: 'cell c-date', text: fmt.date(f.updatedAt || f.createdAt) }),
      rowMenu(f, 'folder'),
    );
    row.draggable = true;
    row.addEventListener('dblclick', () => openFolder(f.id));
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter') openFolder(f.id); });
    attachDrag(row, f, 'folder');
    table.append(row);
  }

  for (const it of items) {
    const playable = state.view !== 'trash' && isPlayableAudio(it);
    const row = el('div', {
      class: 'lrow item', role: 'row', tabindex: '0', dataset: { id: it.id, type: 'item' },
    },
      el('div', { class: 'cell c-name' }, nameCell(it)),
      el('div', { class: 'cell c-artist', text: it.meta?.artist || '—' }),
      el('div', { class: 'cell c-dur num', text: fmt.duration(it.meta?.duration) }),
      el('div', { class: 'cell c-size num', text: fmt.bytes(it.size) }),
      el('div', { class: 'cell c-date', text: fmt.date(it.updatedAt || it.createdAt) }),
      rowMenu(it, 'item'),
    );
    row.draggable = true;
    row.dataset.playable = playable ? '1' : '0';
    if (playable) {
      row.addEventListener('dblclick', () => playItem(it, currentAudioQueue()));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') playItem(it, currentAudioQueue()); });
    } else {
      row.addEventListener('dblclick', () => downloadEntity(it));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') downloadEntity(it); });
    }
    attachDrag(row, it, 'item');
    table.append(row);
  }
  return table;
}

function nameCell(it) {
  const thumb = it.meta?.cover
    ? el('img', { class: 'thumb', src: `data:${it.meta.cover.mime};base64,${it.meta.cover.data}`, alt: '' })
    : el('span', { class: 'thumb icon-thumb' }, icon(it.kind === 'audio' ? 'music' : 'file', 14));
  return el('span', { class: 'name-wrap' }, thumb, el('span', { class: 'fname', text: it.name }));
}

function buildGrid(folders, items) {
  const grid = el('div', { class: 'grid' });
  if (!folders.length && !items.length) {
    grid.append(el('div', { class: 'empty-row' }, emptyState()));
    return grid;
  }
  for (const f of folders) {
    const card = el('div', { class: 'gcard', tabindex: '0', dataset: { id: f.id, type: 'folder' } },
      el('div', { class: 'gcard-icon' }, icon('folder', 36)),
      el('div', { class: 'gcard-name', text: f.name }),
      rowMenu(f, 'folder'),
    );
    card.draggable = true;
    card.addEventListener('dblclick', () => openFolder(f.id));
    card.addEventListener('keydown', (e) => { if (e.key === 'Enter') openFolder(f.id); });
    attachDrag(card, f, 'folder');
    grid.append(card);
  }
  for (const it of items) {
    const playable = isPlayableAudio(it);
    const art = it.meta?.cover
      ? el('img', { src: `data:${it.meta.cover.mime};base64,${it.meta.cover.data}`, alt: '' })
      : el('span', { class: 'gcard-art-fallback' }, icon(it.kind === 'audio' ? 'music' : 'file', 34));
    const card = el('div', { class: 'gcard', tabindex: '0', dataset: { id: it.id, type: 'item' } },
      el('div', { class: 'gcard-art' },
        art,
        playable ? el('button', { class: 'play-overlay', 'aria-label': `Play ${it.name}`, onclick: (e) => { e.stopPropagation(); playItem(it, currentAudioQueue()); } }, icon('play', 22)) : null),
      el('div', { class: 'gcard-name', text: it.name }),
      el('div', { class: 'gcard-sub', text: it.meta?.artist || fmt.bytes(it.size) }),
      rowMenu(it, 'item'),
    );
    card.draggable = true;
    if (playable) {
      card.addEventListener('dblclick', () => playItem(it, currentAudioQueue()));
      card.addEventListener('keydown', (e) => { if (e.key === 'Enter') playItem(it, currentAudioQueue()); });
    }
    attachDrag(card, it, 'item');
    grid.append(card);
  }
  return grid;
}

function emptyState() {
  const copy = {
    library: {
      title: 'Nothing here yet',
      body: 'Add your first tracks — they are encrypted in this browser before they leave it.',
      action: ['Upload music', () => uploadFlow('audio')],
    },
    folder: {
      title: 'This folder is empty',
      body: 'Drop files anywhere on the page, or use the buttons in the sidebar.',
      action: ['Upload music', () => uploadFlow('audio')],
    },
    search: {
      title: 'No matches',
      body: 'Try a different title, artist, or album.',
      action: ['Clear search', () => { state.query = ''; if (searchInput) searchInput.value = ''; render(); }],
    },
    trash: {
      title: 'Trash is empty',
      body: 'Deleted files and folders wait here until you remove them for good.',
      action: null,
    },
    recent: {
      title: 'Nothing recent yet',
      body: 'Tracks and files you add will appear here.',
      action: ['Upload music', () => uploadFlow('audio')],
    },
  };
  const key = state.query ? 'search'
    : state.view === 'trash' ? 'trash'
      : state.view === 'recent' ? 'recent'
        : state.folderId === 'root' ? 'library' : 'folder';
  const c = copy[key];
  const box = el('div', { class: 'empty' },
    el('div', { class: 'empty-icon' }, icon(key === 'trash' ? 'trash-2' : key === 'search' ? 'search' : 'music', 26)),
    el('h3', { text: c.title }),
    el('p', { text: c.body }),
  );
  if (c.action) box.append(el('button', { class: 'btn primary', type: 'button', text: c.action[0], onclick: c.action[1] }));
  return box;
}

function openFolder(id) {
  state.view = 'library';
  state.folderId = id;
  state.query = '';
  if (searchInput) searchInput.value = '';
  render();
}

function currentAudioQueue() {
  const { items } = currentEntries();
  return items.filter((i) => isPlayableAudio(i)).map((i) => i.id);
}

/* ================================================================ row actions */

function rowMenu(entity, type) {
  const btn = el('button', { class: 'icon-btn row-menu-btn', 'aria-label': `Actions for ${entity.name}`, 'aria-haspopup': 'menu' }, icon('ellipsis', 16));
  btn.onclick = (e) => {
    e.stopPropagation();
    openMenu({
      anchor: btn,
      align: 'end',
      items: menuItemsFor(entity, type),
    });
  };
  return el('div', { class: 'cell c-menu' }, btn);
}

function menuItemsFor(entity, type) {
  const isFolder = type === 'folder';
  if (state.view === 'trash') {
    return [
      {
        label: 'Restore', icon: 'rotate-ccw',
        onClick: async () => {
          if (isFolder) await store.restoreFolder(entity.id); else await store.restoreItem(entity.id);
          render();
        },
      },
      {
        label: 'Delete permanently', icon: 'trash-2', danger: true,
        onClick: async () => {
          const ok = await confirmDialog({
            title: 'Delete permanently?',
            message: isFolder
              ? `"${entity.name}" and everything inside it will be gone for good. This cannot be undone.`
              : `"${entity.name}" will be gone for good. This cannot be undone.`,
            confirmLabel: 'Delete forever',
          });
          if (!ok) return;
          if (isFolder) await store.deleteFolderForever(entity.id); else await store.deleteItemForever(entity.id);
          render();
          toast('Deleted for good');
        },
      },
    ];
  }
  const items = [];
  if (isFolder) {
    items.push({ label: 'Open', icon: 'folder', onClick: () => openFolder(entity.id) });
    items.push({ label: 'Download as .zip', icon: 'download', onClick: () => downloadFolder(entity) });
    items.push({
      label: 'Rename', icon: 'pencil',
      onClick: async () => {
        const name = await promptDialog({ title: 'Rename folder', label: 'Name', value: entity.name });
        if (name && name !== entity.name) { await store.renameFolder(entity.id, name); render(); }
      },
    });
  } else {
    if (isPlayableAudio(entity)) {
      items.push({ label: 'Play', icon: 'play', onClick: () => playItem(entity, currentAudioQueue()) });
    }
    items.push({ label: 'Download', icon: 'download', onClick: () => downloadEntity(entity) });
    items.push({
      label: 'Rename', icon: 'pencil',
      onClick: async () => {
        const name = await promptDialog({ title: 'Rename file', label: 'Name', value: entity.name });
        if (name && name !== entity.name) { await store.renameItem(entity.id, name); render(); }
      },
    });
  }
  items.push({ label: 'Move to…', icon: 'folder-input', onClick: () => moveDialog(entity, isFolder) });
  items.push({
    label: 'Move to trash', icon: 'trash-2', danger: true,
    onClick: async () => {
      if (isFolder) await store.trashFolder(entity.id); else await store.trashItem(entity.id);
      render();
      toast(`"${entity.name}" moved to trash`);
    },
  });
  return items;
}

function moveDialog(entity, isFolder) {
  const body = el('div', { class: 'move-tree', role: 'tree', 'aria-label': 'Destination folder' });
  const selected = { id: null };
  const build = (nodes, depth) => {
    for (const n of nodes) {
      const row = el('button', {
        class: 'move-row', type: 'button', role: 'treeitem',
        'aria-selected': 'false',
        style: `padding-left:${8 + depth * 18}px`,
        onclick: () => {
          body.querySelectorAll('.move-row').forEach((r) => { r.classList.remove('selected'); r.setAttribute('aria-selected', 'false'); });
          row.classList.add('selected');
          row.setAttribute('aria-selected', 'true');
          selected.id = n.id;
        },
      }, icon('folder', 15), el('span', { text: n.name }));
      body.append(row);
      if (n.children) build(n.children, depth + 1);
    }
  };
  build(folderTree(isFolder ? entity.id : null), 0);
  openDialog({
    title: `Move "${entity.name}"`,
    width: 440,
    body,
    actions: [
      { label: 'Cancel', onClick: (close) => close() },
      {
        label: 'Move', kind: 'primary',
        onClick: async (close) => {
          if (!selected.id) { toast('Choose a destination folder'); return; }
          if (isFolder) {
            try { await store.moveFolder(entity.id, selected.id); } catch (err) { toast(err.message, 'error'); return; }
          } else {
            await store.moveItem(entity.id, selected.id);
          }
          close();
          render();
          toast(`Moved to ${store.doc.folders[selected.id]?.name || 'My Library'}`);
        },
      },
    ],
  });
}

function folderTree(excludeId) {
  const folders = Object.values(store.doc.folders).filter((f) => !f.trashed && f.id !== excludeId);
  const byParent = new Map();
  for (const f of folders) {
    if (!byParent.has(f.parent)) byParent.set(f.parent, []);
    byParent.get(f.parent).push(f);
  }
  const build = (parent) => (byParent.get(parent) || [])
    .map((f) => ({ id: f.id, name: f.name, children: build(f.id) }));
  return [{ id: 'root', name: 'My Library', children: build('root') }];
}

async function downloadEntity(item) {
  try {
    toast('Decrypting…');
    const pt = await fetchDecryptedBlob(item);
    const blob = new Blob([pt], { type: item.mime || guessMime(item) });
    const a = el('a', { href: URL.createObjectURL(blob), download: item.name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 30_000);
  } catch {
    toast('Could not download this file.', 'error');
  }
}

// Folder download: decrypt every file in the subtree and zip it locally.
async function downloadFolder(folder) {
  const ids = store.folderSubtree(folder.id);
  const items = Object.values(store.doc.items).filter((i) => !i.trashed && ids.includes(i.folderId));
  if (!items.length) { toast('This folder has no files to download.'); return; }
  toast(`Preparing ${items.length} file${items.length === 1 ? '' : 's'}…`);
  const entries = [];
  const used = new Set();
  for (const it of items) {
    try {
      const pt = await fetchDecryptedBlob(it);
      // Prefix with the subfolder path so nesting survives the zip.
      const sub = ids.includes(folder.id) && it.folderId !== folder.id
        ? store.folderPath(it.folderId).slice(1).map((f) => f.name).join('/') + '/'
        : '';
      let path = sub + it.name;
      let n = 2;
      while (used.has(path)) path = sub + it.name.replace(/(\.[^.]*)?$/, ` (${n++})$1`);
      used.add(path);
      entries.push({ path, data: pt, mtime: new Date(it.updatedAt || it.createdAt) });
    } catch {
      // skip files that cannot be decrypted rather than failing the whole zip
    }
  }
  if (!entries.length) { toast('Could not decrypt any of these files.', 'error'); return; }
  const zip = makeZip(entries);
  const blob = new Blob([zip], { type: 'application/zip' });
  const a = el('a', { href: URL.createObjectURL(blob), download: `${folder.name}.zip` });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 60_000);
  toast(`Downloaded ${entries.length} file${entries.length === 1 ? '' : 's'} as .zip`);
}

/* ================================================================ drag rows */

function attachDrag(node, entity, type) {
  node.addEventListener('dragstart', (e) => {
    e.dataTransfer.setData('application/x-mc-entity', JSON.stringify({ id: entity.id, type }));
    e.dataTransfer.effectAllowed = 'move';
    node.classList.add('dragging');
  });
  node.addEventListener('dragend', () => node.classList.remove('dragging'));

  if (type === 'folder') {
    node.addEventListener('dragover', (e) => {
      if (e.dataTransfer.types.includes('application/x-mc-entity')) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        node.classList.add('drop-target');
      }
    });
    node.addEventListener('dragleave', () => node.classList.remove('drop-target'));
    node.addEventListener('drop', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      node.classList.remove('drop-target');
      const raw = e.dataTransfer.getData('application/x-mc-entity');
      if (!raw) return;
      let payload;
      try { payload = JSON.parse(raw); } catch { return; }
      const { id, type: t } = payload;
      if (t === 'folder') {
        if (id === entity.id) return;
        try { await store.moveFolder(id, entity.id); render(); } catch (err) { toast(err.message, 'error'); }
      } else {
        await store.moveItem(id, entity.id);
        render();
        toast(`Moved to ${entity.name}`);
      }
    });
  }
}

/* ================================================================ meter + uploads */

function updateMeter() {
  const fill = window._mc?.meterFill;
  const label = window._mc?.meterLabel;
  if (!fill || !label) return;
  const QUOTA = 2 * 1024 * 1024 * 1024; // soft display quota
  const used = store.storageUsed();
  fill.style.width = `${Math.min(100, (used / QUOTA) * 100)}%`;
  label.replaceChildren(el('span', { text: `${fmt.bytes(used)} of ${fmt.bytes(QUOTA)} used` }));
}

function updateNav() {
  document.querySelectorAll('.side-link[data-view]').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === state.view);
  });
}

function renderUploadsPanel() {
  const panel = document.getElementById('uploads-panel');
  if (!panel) return;
  panel.replaceChildren();
  if (!state.uploads.size) { panel.classList.remove('visible'); return; }
  panel.classList.add('visible');
  for (const job of state.uploads.values()) {
    const finished = job.status === 'done' || job.status === 'error' || job.status === 'canceled';
    panel.append(el('div', { class: 'upload-row' },
      el('div', { class: 'upload-info' },
        el('div', { class: 'upload-name', text: job.name }),
        el('div', { class: 'upload-progress' }, el('div', { class: 'upload-fill', style: `width:${job.progress}%` })),
      ),
      finished
        ? el('span', { class: `upload-status ${job.status}` },
          job.status === 'done' ? icon('check', 14) : el('span', { text: job.status === 'canceled' ? 'Canceled' : 'Failed' }))
        : el('button', { class: 'icon-btn small', 'aria-label': `Cancel upload of ${job.name}`, onclick: () => cancelUpload(job.id) }, icon('x', 14)),
    ));
  }
}

onUploadProgress((job) => {
  state.uploads.set(job.id, job);
  if (job.status === 'done' || job.status === 'error' || job.status === 'canceled') {
    setTimeout(() => {
      state.uploads.delete(job.id);
      renderUploadsPanel();
      if (job.status === 'done') render();
    }, job.status === 'done' ? 1200 : 4000);
  }
  renderUploadsPanel();
});

/* ================================================================ boot */

boot();
void backendKind;

// UI primitives: element builder, formatters, dialogs, menus, toasts.

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

export const fmt = {
  bytes(n) {
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    const v = n / 1024 ** i;
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  },
  duration(sec) {
    if (!Number.isFinite(sec) || sec < 0) return '–:––';
    const s = Math.round(sec);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    return h > 0
      ? `${h}:${String(m).padStart(2, '0')}:${String(r).padStart(2, '0')}`
      : `${m}:${String(r).padStart(2, '0')}`;
  },
  date(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  },
};

// ---------------------------------------------------------------- focus trap + dialog

function trapFocus(dialog) {
  dialog.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    const focusables = dialog.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
    else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
  });
}

// Small modal dialog. Returns { close, root }. Escape cancels; backdrop click cancels.
export function openDialog({ title, body, actions, width = 400 }) {
  const overlay = el('div', { class: 'dialog-overlay' });
  const box = el('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, style: `max-width:${width}px` });
  const close = (value) => {
    overlay.remove();
    document.removeEventListener('keydown', escHandler, true);
    if (typeof value === 'function') value();
  };
  const escHandler = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', escHandler, true);
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) close(); });

  box.append(el('h2', { class: 'dialog-title', text: title }));
  if (body) box.append(body);
  if (actions) {
    const row = el('div', { class: 'dialog-actions' });
    for (const a of actions) {
      row.append(el('button', {
        class: `btn ${a.kind || ''}`,
        text: a.label,
        type: 'button',
        onclick: () => a.onClick?.(close),
      }));
    }
    box.append(row);
  }
  overlay.append(box);
  document.body.append(overlay);
  trapFocus(box);
  const firstInput = box.querySelector('input, button');
  if (firstInput) firstInput.focus();
  return { close, root: box };
}

// Prompt-style dialog with one text input. Returns Promise<string|null>.
export function promptDialog({ title, label, value = '', confirm = 'Save', placeholder = '', hint }) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const input = el('input', { class: 'input', type: 'text', value, placeholder, id: 'pd-input', maxlength: '200' });
    const submit = () => { done(input.value.trim() || null); cleanup(); };
    const cleanup = () => { dlg.close(); };
    const body = el('div', {},
      label ? el('label', { class: 'field-label', for: 'pd-input', text: label }) : null,
      input,
      hint ? el('p', { class: 'hint', text: hint }) : null,
    );
    const dlg = openDialog({
      title,
      body,
      actions: [
        { label: 'Cancel', onClick: (close) => { done(null); close(); } },
        { label: confirm, kind: 'primary', onClick: () => submit() },
      ],
    });
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
    input.select();
  });
}

export function confirmDialog({ title, message, confirmLabel = 'Delete' }) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    openDialog({
      title,
      body: el('p', { class: 'dialog-message', text: message }),
      actions: [
        { label: 'Cancel', onClick: (close) => { done(false); close(); } },
        { label: confirmLabel, kind: 'danger', onClick: (close) => { done(true); close(); } },
      ],
    });
  });
}

// ---------------------------------------------------------------- menus (dropdown)

// Anchored dropdown menu with full keyboard support. items: {label, icon, onClick, danger}
export function openMenu({ anchor, items, align = 'start', onClose }) {
  closeMenus();
  const menu = el('div', { class: 'menu', role: 'menu', 'aria-orientation': 'vertical' });
  const itemNodes = [];
  for (const it of items) {
    if (!it) continue;
    const btn = el('button', {
      class: `menu-item ${it.danger ? 'danger' : ''}`,
      role: 'menuitem',
      type: 'button',
      onclick: () => { cleanup(); it.onClick?.(); },
    });
    if (it.icon) btn.append(iconSpan(it.icon));
    btn.append(el('span', { text: it.label }));
    itemNodes.push(btn);
    menu.append(btn);
  }
  let cleanup = () => {
    menu.remove();
    document.removeEventListener('mousedown', outside, true);
    document.removeEventListener('keydown', key, true);
    if (onClose) onClose();
  };
  const outside = (e) => { if (!menu.contains(e.target) && e.target !== anchor && !anchor.contains(e.target)) cleanup(); };
  const key = (e) => {
    if (e.key === 'Escape') { e.stopPropagation(); cleanup(); anchor.focus(); return; }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const idx = itemNodes.indexOf(document.activeElement);
      const next = e.key === 'ArrowDown'
        ? itemNodes[idx + 1] || itemNodes[0]
        : itemNodes[idx - 1] || itemNodes[itemNodes.length - 1];
      next.focus();
    }
    if (e.key === 'Home') { e.preventDefault(); itemNodes[0]?.focus(); }
    if (e.key === 'End') { e.preventDefault(); itemNodes[itemNodes.length - 1]?.focus(); }
  };
  document.addEventListener('mousedown', outside, true);
  document.addEventListener('keydown', key, true);

  document.body.append(menu);
  const r = anchor.getBoundingClientRect();
  menu.style.visibility = 'hidden';
  requestAnimationFrame(() => {
    const mw = menu.offsetWidth;
    const mh = menu.offsetHeight;
    let left = align === 'end' ? r.right - mw : r.left;
    left = Math.max(8, Math.min(left, window.innerWidth - mw - 8));
    let top = r.bottom + 6;
    if (top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 6);
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
    menu.style.visibility = '';
    itemNodes[0]?.focus();
  });
  return cleanup;
}

export function closeMenus() {
  document.querySelectorAll('.menu').forEach((m) => m.remove());
}

// lazily import icons to avoid circular import at module init
import { iconEl as iconSpan } from './icons.js';

// ---------------------------------------------------------------- toast

export function toast(message, kind = 'info') {
  const region = document.getElementById('toasts') || (() => {
    const t = el('div', { id: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(t);
    return t;
  })();
  const node = el('div', { class: `toast ${kind}`, text: message });
  region.append(node);
  setTimeout(() => { node.classList.add('leaving'); setTimeout(() => node.remove(), 200); }, 3500);
}

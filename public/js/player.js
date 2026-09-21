// Persistent audio player. Plays decrypted-in-memory blobs; survives folder
// navigation because the module owns its queue independent of the view.

import { fmt, el } from './ui.js';
import { icon } from './icons.js';
import { store } from './store.js';
import { fetchDecryptedBlob } from './uploader.js';

const state = {
  queue: [],           // item ids in play order
  index: -1,
  playing: false,
  audio: null,
  objectUrl: null,
  duration: 0,
  currentItem: null,
};

const listeners = new Set();
export function onPlayerChange(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function emit() { for (const fn of listeners) fn(); }

function getAudio() {
  if (!state.audio) {
    state.audio = new Audio();
    state.audio.preload = 'metadata';
    state.audio.addEventListener('timeupdate', () => emit());
    state.audio.addEventListener('durationchange', () => { state.duration = state.audio.duration; emit(); });
    state.audio.addEventListener('ended', () => next());
    state.audio.addEventListener('play', () => { state.playing = true; emit(); });
    state.audio.addEventListener('pause', () => { state.playing = false; emit(); });
  }
  return state.audio;
}

async function itemUrl(item) {
  const pt = await fetchDecryptedBlob(item);
  const type = guessMime(item);
  const blob = new Blob([pt], { type });
  return URL.createObjectURL(blob);
}

export function guessMime(item) {
  if (item.mime && item.mime !== 'application/octet-stream' && item.mime !== '') return item.mime;
  const ext = (item.name.split('.').pop() || '').toLowerCase();
  const map = {
    mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', ogg: 'audio/ogg',
    oga: 'audio/ogg', opus: 'audio/ogg', m4a: 'audio/mp4', m4b: 'audio/mp4',
    aac: 'audio/aac', aiff: 'audio/aiff', aif: 'audio/aiff', wma: 'audio/x-ms-wma',
    weba: 'audio/webm', webm: 'audio/webm', caf: 'audio/x-caf',
  };
  return map[ext] || 'audio/mpeg';
}

let failureStreak = 0;

async function playIndex(i) {
  const audio = getAudio();
  if (i < 0 || i >= state.queue.length) return;
  const item = store.doc.items[state.queue[i]];
  if (!item) return;
  state.index = i;
  state.currentItem = item;
  state.duration = item.meta?.duration || 0;
  emit();

  if (state.objectUrl) { URL.revokeObjectURL(state.objectUrl); state.objectUrl = null; }
  audio.pause();
  try {
    const url = await itemUrl(item);
    if (state.index !== i) { URL.revokeObjectURL(url); return; } // user skipped ahead mid-load
    state.objectUrl = url;
    audio.src = url;
    audio.play().catch(() => { state.playing = false; emit(); });
    failureStreak = 0;
    updateMediaSession(item);
  } catch (err) {
    // Undecryptable or undecodable item: skip forward, but stop after failing
    // the whole queue so we never loop endlessly.
    failureStreak += 1;
    if (failureStreak < state.queue.length) next();
    else { failureStreak = 0; state.playing = false; emit(); }
  }
}

export function playItem(itemOrId, queueIds) {
  const id = typeof itemOrId === 'object' ? itemOrId.id : itemOrId;
  if (Array.isArray(queueIds) && queueIds.length) state.queue = queueIds.slice();
  else if (!state.queue.includes(id)) state.queue = [id, ...state.queue.filter((q) => q !== id)];
  const idx = state.queue.indexOf(id);
  playIndex(idx === -1 ? 0 : idx);
}

export function toggle() {
  const audio = getAudio();
  if (!state.currentItem) {
    // nothing loaded: play the first playable item of the last view if any
    return;
  }
  if (audio.paused) audio.play().catch(() => {});
  else audio.pause();
}

export function next() {
  if (!state.queue.length) return;
  playIndex((state.index + 1) % state.queue.length);
}

export function prev() {
  if (!state.queue.length) return;
  const audio = getAudio();
  if (audio.currentTime > 3) { audio.currentTime = 0; return; }
  playIndex((state.index - 1 + state.queue.length) % state.queue.length);
}

export function seek(fraction) {
  const audio = getAudio();
  if (Number.isFinite(audio.duration) && audio.duration > 0) {
    audio.currentTime = Math.max(0, Math.min(1, fraction)) * audio.duration;
  }
}

export function setVolume(v) {
  getAudio().volume = Math.max(0, Math.min(1, v));
  try { localStorage.setItem('mc-volume', String(v)); } catch { /* private mode */ }
}

export function getVolume() {
  const v = Number(localStorage.getItem('mc-volume'));
  return Number.isFinite(v) ? Math.max(0, Math.min(1, v)) : 0.9;
}

export function isPlaying() { return state.playing; }
export function currentItem() { return state.currentItem; }
export function currentTime() { return state.audio ? state.audio.currentTime : 0; }
export function currentDuration() { return state.audio?.duration || state.duration || 0; }
export function queuePosition() { return { index: state.index, length: state.queue.length }; }

function updateMediaSession(item) {
  if (!('mediaSession' in navigator)) return;
  const title = item.meta?.title || item.name;
  const artist = item.meta?.artist || 'Local file';
  const album = item.meta?.album || 'music cloud';
  const artwork = item.meta?.cover
    ? [{
      src: `data:${item.meta.cover.mime};base64,${item.meta.cover.data}`,
      sizes: '512x512', type: item.meta.cover.mime,
    }]
    : [];
  try {
    navigator.mediaSession.metadata = new MediaMetadata({ title, artist, album, artwork });
  } catch { /* older browsers */ }
}

// ---------------------------------------------------------------- player bar UI

let barBuilt = false;
export function buildPlayerBar(root) {
  if (barBuilt) return;
  barBuilt = true;
  getAudio().volume = getVolume();

  const bar = el('div', { class: 'player-bar' });
  const cover = el('div', { class: 'player-cover', 'aria-hidden': 'true' });
  const title = el('div', { class: 'player-title', text: 'Nothing playing' });
  const artist = el('div', { class: 'player-artist', text: ' ' });
  const metaCol = el('div', { class: 'player-meta' }, title, artist);

  const btnPrev = el('button', { class: 'icon-btn', 'aria-label': 'Previous track' }, icon('skip-back', 20));
  const btnPlay = el('button', { class: 'icon-btn play-btn', 'aria-label': 'Play or pause' }, icon('play', 22));
  const btnNext = el('button', { class: 'icon-btn', 'aria-label': 'Next track' }, icon('skip-forward', 20));

  const timeNow = el('span', { class: 'time', text: '0:00' });
  const timeDur = el('span', { class: 'time', text: '0:00' });
  const seekBar = el('input', { class: 'seek', type: 'range', min: '0', max: '1000', value: '0', 'aria-label': 'Seek' });
  const volIcon = el('button', { class: 'icon-btn small', 'aria-label': 'Mute' }, icon('volume-2', 18));
  const volBar = el('input', { class: 'volume', type: 'range', min: '0', max: '100', value: String(Math.round(getVolume() * 100)), 'aria-label': 'Volume' });

  btnPrev.onclick = () => prev();
  btnNext.onclick = () => next();
  btnPlay.onclick = () => toggle();
  seekBar.addEventListener('input', () => seek(Number(seekBar.value) / 1000));
  volBar.addEventListener('input', () => {
    setVolume(Number(volBar.value) / 100);
    volIcon.replaceChildren(icon(Number(volBar.value) === '0' ? 'volume-x' : 'volume-2', 18));
  });
  volIcon.onclick = () => {
    const muted = volBar.value === '0';
    setVolume(muted ? 0.9 : 0);
    volBar.value = muted ? '90' : '0';
    volIcon.replaceChildren(icon(muted ? 'volume-2' : 'volume-x', 18));
  };

  const center = el('div', { class: 'player-center' }, el('div', { class: 'seek-row' }, timeNow, seekBar, timeDur));
  bar.append(
    el('div', { class: 'player-left' }, cover, metaCol),
    center,
    el('div', { class: 'player-right' }, volIcon, volBar),
    el('div', { class: 'player-controls-mobile' }, btnPrev, btnPlay, btnNext),
  );
  root.append(bar);

  const render = () => {
    const item = state.currentItem;
    if (item) {
      title.textContent = item.meta?.title || item.name;
      artist.textContent = item.meta?.artist || item.name.replace(/\.[^.]+$/, '');
      if (item.meta?.cover) {
        if (!cover.firstChild) {
          cover.append(el('img', {
            src: `data:${item.meta.cover.mime};base64,${item.meta.cover.data}`,
            alt: '',
          }));
        }
      } else {
        cover.replaceChildren(icon('music', 18));
      }
    }
    btnPlay.replaceChildren(icon(state.playing ? 'pause' : 'play', 22));
    const cur = currentTime();
    const dur = currentDuration();
    timeNow.textContent = fmt.duration(cur);
    timeDur.textContent = fmt.duration(dur);
    if (!seekBar.matches(':active')) {
      seekBar.value = String(dur > 0 ? Math.round((cur / dur) * 1000) : 0);
    }
    center.classList.toggle('active', Boolean(item));
  };
  onPlayerChange(render);
  render();
}

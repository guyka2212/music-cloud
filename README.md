# music cloud

Private, end-to-end encrypted cloud storage for your music. Google-Drive-style
organization — folders, search, drag-and-drop, trash — with a player built for
audio, and a server that never sees a single plaintext byte.

## Quick start

```bash
npm start          # serves on http://localhost:8080
PORT=3000 npm start
npm test           # end-to-end server contract tests (client crypto simulated)
```

No runtime dependencies. Requires Node 22.5+ (uses built-in `node:sqlite`).

## How the encryption works

Everything the user stores is encrypted **in the browser**, before it is sent.
The server stores only ciphertext and can neither read your library nor help
you recover it.

| Secret | Derived from | Used for | Leaves the device? |
|---|---|---|---|
| Master key | `PBKDF2(password, per-user salt)` ×310k | Encrypts the library JSON; wraps per-file keys | Never |
| Auth hash | `PBKDF2(password, "auth:" + salt)` ×310k | Login only — constant-time compare | Yes (hash only) |
| Recovery key | The raw master key bytes (32B) | Shown once at signup; only path back after password loss | Never (server holds `SHA-256(recovery)`) |
| File keys | Random per file, wrapped with `HKDF(master)` | AES-256-GCM on audio/file bytes | Never |

- Library JSON (folders, names, metadata, settings) = one AES-256-GCM document.
- Files >4 MB are encrypted and uploaded in independent 4 MB GCM chunks
  (per-chunk IV = file IV XOR chunk index); smaller files are single-shot.
- Playback and downloads are decrypted in the browser via `/blob/:id`, which
  streams ciphertext back to an authenticated session only.

Losing the password *and* the recovery key means the data is unrecoverable —
by design. The signup screen says so plainly and offers a downloadable
recovery key.

## Features

- Email + password accounts, HttpOnly session cookies, per-email lockout and
  IP rate limits on auth routes.
- **+ New** dropdown: new folder / upload music / upload any file — keyboard
  navigable, closes on Escape or outside click.
- Uploads: any format, no extension rejection. Metadata (title, artist, album,
  duration, cover art) parsed client-side for ID3v2, FLAC, MP4/M4A; WAV
  duration from the header. Per-file progress with cancel; drag-and-drop
  anywhere.
- Folders: nest, rename, move (drag-drop or dialog), trash/restore/purge.
- Views: list (name, artist, duration, size, modified) and grid; sort by name,
  date, size, artist; library-wide search.
- Player: persistent bottom bar, folder-scoped queue, prev/next, seek, volume,
  cover art, MediaSession integration. Formats the browser can't decode show a
  download action instead of play.
- Storage meter in the sidebar; empty trash / restore anywhere.
- Light and dark themes designed separately; responsive with a drawer sidebar
  and FAB on mobile; reduced-motion supported.

## API surface

| Route | Purpose |
|---|---|
| `POST /api/auth/signup` | `{ email, authHash, recoveryHash }` |
| `POST /api/auth/login` | `{ email, authHash }` or `{ email, recoveryHash }` |
| `POST /api/auth/logout`, `GET /api/auth/me` | Session lifecycle |
| `GET/PUT /api/library` | The encrypted library document (`salt`, `iv`, `ct`) |
| `POST /api/blob/:id/init` | Start an upload (`salt`, base64 IV) |
| `PUT /api/blob/:id/chunk/:n` | One encrypted chunk (≤16 MB) |
| `POST /api/blob/:id/finalize` | Merge chunks, mark complete |
| `GET /api/blob/:id/status`, `DELETE /api/blob/:id` | Upload lifecycle |
| `GET /blob/:id` | Stream ciphertext back (session required) |

Every blob route is scoped by the session user; cross-account access returns
404. Every endpoint validates payloads server-side.

## Layout

```
server/   db, auth, blob routes, static router (zero dependencies)
public/   ES-module frontend: crypto, store, uploader, player, UI
test/     contract tests that simulate the browser's crypto end to end
```

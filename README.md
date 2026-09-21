# music cloud

Private, end-to-end encrypted cloud storage for your music. Google-Drive-style
organization — folders, search, drag-and-drop, trash — with a player built for
audio. Works two ways:

- **GitHub Pages (static)** — everything runs in your browser; your account,
  library, and encrypted audio live in that browser's IndexedDB. Nothing is
  ever uploaded anywhere.
- **Self-hosted** — `npm start` and the same app uses the zero-dependency
  Node server: encrypted data stored server-side, accessible from any device.

The same frontend drives both; it probes for the server and falls back to
local-only mode automatically.

## Run it

```bash
# Static (GitHub Pages) — no build step, no server needed:
#   push this repo, enable Pages on main / root. Done.

# Self-hosted:
npm start          # serves on http://localhost:8080
PORT=3000 npm start

npm test           # crypto tests + local-driver tests + server contract tests
```

## GitHub Pages

1. Push this repository to GitHub.
2. Settings → Pages → Source: **Deploy from a branch**, Branch: **main**,
   Folder: **/ (root)** → Save.
3. Your library is live at `https://<user>.github.io/<repo>/`.

`index.html` uses relative asset paths, so the app works at a project
subpath. `.nojekyll` is included so Pages serves files as-is. On Pages there
is no backend, so the app runs in **local mode**:

- Accounts, the encrypted library JSON, and encrypted audio files are stored
  in the browser's IndexedDB (stores: `users`, `library`, `blobs`, `chunks`).
- Each browser profile is its own "server": data does not sync across devices
  or browsers, and clearing site data deletes it.
- Encryption is identical to server mode — the password never leaves the
  device in either mode.

### GitHub sync mode (cross-device on Pages)

Local mode ties your library to one browser. **GitHub sync** removes that
limit while staying 100% static: data files live under `data/` **in this
repo**, read and written through GitHub's Contents API.

To enable it, click **“Use GitHub sync”** on the sign-in page and paste a
token:

1. GitHub → Settings → Developer settings → **Fine-grained tokens** →
   Generate new token.
2. Repository access: select **music-cloud** only.
3. Permissions: **Contents → Read and write** (nothing else needed).
4. Paste the token into the dialog. It is stored in that browser's
   localStorage only — never committed, never sent anywhere but api.github.com.

What lands in the repo:

```
data/
  users.json          ALL accounts in one file. A public index maps
                      SHA-256(email) → entry key; each entry is an
                      AES-GCM envelope holding { email, auth hash,
                      recovery hash, KDF salt, created }.
  files/<h>.json      encrypted library JSON (folders, items, metadata)
  files/<h>/<id>.json   manifest { iv, salt, size, parts }
  files/<h>/<id>/pN.enc encrypted part N (~4 MB of plaintext each)
```

Entry keys = SHA-256(email ':' authHash) — computing one requires the email
**and** the password, so the public repo leaks nothing usable. The KDF salt is
deterministic per email, which lets every device derive the same key with no
pre-auth lookup.

Creating accounts from the terminal (no browser dance):

```bash
GITHUB_TOKEN=ghp_xxx node scripts/create-user.mjs friend@example.com 'their password'
```

Prints a recovery key to hand to the account owner. The token needs
Contents: Read and write on this repo.

Notes and limits:

- Sign in with the same email + password on any device to reach the same
  library; recovery-key login works too (via the pointer file).
- There is no hard per-file size limit: each ~4 MB encrypted chunk is
  committed as its own file, so storage scales with your repo (GitHub works
  best below ~1–5 GB; huge libraries may hit API rate limits while loading).
- Every save is a commit on `main`, so the repo's history grows with use —
  occasionally prune old `data/` blobs if it gets large.
- GitHub API rate limits (5000 req/h authenticated) apply; normal listening
  uses very few requests.

## How the encryption works

Everything the user stores is encrypted **in the browser**, before it is sent
(or, in local mode, before it touches disk). The server — when there is one —
stores only ciphertext and can neither read your library nor help you recover
it.

| Secret | Derived from | Used for | Leaves the device? |
|---|---|---|---|
| Master key | `PBKDF2(password, per-user salt)` ×310k | Encrypts the library JSON; wraps per-file keys | Never |
| Auth hash | `PBKDF2(password, "auth:" + salt)` ×310k | Login only — constant-time compare | Yes (hash only) |
| Recovery key | The raw master key bytes (32B) | Shown once at signup; only path back after password loss | Never (server holds `SHA-256(recovery)`) |
| File keys | Random per file, wrapped with `HKDF(master)` | AES-256-GCM on audio/file bytes | Never |

- Library JSON (folders, names, metadata, settings) = one AES-256-GCM document.
- Files >4 MB are encrypted and uploaded in independent 4 MB GCM chunks
  (per-chunk IV = file IV XOR chunk index); smaller files are single-shot.
- Playback and downloads are decrypted in the browser on demand.

Losing the password *and* the recovery key means the data is unrecoverable —
by design. The signup screen says so plainly and offers a downloadable
recovery key.

## Features

- **+ New** dropdown: new folder / upload music / upload any file — keyboard
  navigable, closes on Escape or outside click.
- Uploads: any format, no extension rejection. Metadata (title, artist, album,
  duration, cover art) parsed client-side for ID3v2, FLAC, MP4/M4A; WAV
  duration from the header. Per-file progress with cancel; drag-and-drop
  anywhere.
- Folders: nest, rename, move (drag-drop or dialog), trash/restore/purge;
  download a folder as a .zip (built locally).
- Views: list (name, artist, duration, size, modified) and grid; sort by name,
  date, size, artist; library-wide search.
- Player: persistent bottom bar, folder-scoped queue, prev/next, seek, volume,
  cover art, MediaSession integration. Formats the browser can't decode show a
  download action instead of play.
- Storage meter in the sidebar; empty trash / restore anywhere.
- Light and dark themes designed separately; responsive with a drawer sidebar
  and FAB on mobile; reduced-motion supported.

## API surface (server mode)

| Route | Purpose |
|---|---|
| `POST /api/auth/signup` | `{ email, authHash, recoveryHash, kdfSalt }` |
| `POST /api/auth/login` | `{ email, authHash }` or `{ email, recoveryHash }` |
| `GET /api/auth/salt?email=` | Public per-account KDF salt for key derivation |
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
index.html, js/, css/   the app (served by Pages *and* by the Node server)
server/                 zero-dependency Node backend (opt-in: npm start)
test/                   crypto, local-driver, and server contract tests
```

# music cloud

A shared, browser-based music library that lives entirely in a GitHub repo.
No accounts, no sign-in, no server: every visitor lands straight on the
dashboard, sees the same library, and can browse folders and play anything the
browser can decode. The site is just a dashboard — there is no user system of
any kind.

Live at: https://guyka2212.github.io/music-cloud/

## How it works

```
data/
  library.json          the whole library: folders, items, metadata (public)
  files/<id>.json       manifest { v, size, parts }
  files/<id>/pN.enc     the bytes, split into ~4MB parts
```

- **Reading is anonymous.** Visitors fetch `data/library.json` and file parts
  straight from GitHub's Contents API — no token, no login, nothing sent
  anywhere else.
- **Writing needs a token, set from the console (owner only, no UI).** The page
  has no token dialog — you (the owner) enable uploading in your own browser
  once, via DevTools (F12) → Console:

  ```js
  localStorage.setItem('mc-gh-token', 'github_pat_yourtoken'); location.reload();
  ```

  Use a fine-grained token for this repo with **Contents: Read and write**
  (GitHub → Settings → Developer settings → Fine-grained tokens). It is stored
  in that browser's localStorage only and is never committed to the repo —
  GitHub's secret scanning would auto-revoke any token found in a commit. Every
  change is a commit to `main`. Everyone else stays read-only.
- **No encryption, by design.** The library is meant to be public — the repo
  itself is the shared storage. Don't upload anything you wouldn't put on a
  public playlist.

## Notes and limits

- There is no per-file size limit: each ~4MB part is its own commit, so
  storage scales with the repo (GitHub works best below ~1–5 GB).
- Every save is a commit, so history grows with use — prune old `data/`
  commits occasionally if it gets large.
- Anonymous GitHub requests are limited to ~60/hour per IP; a token (even
  read-only) raises that to 5000/hour. Normal listening uses very few.
- Concurrent edits merge: the library save flow re-reads the latest copy and
  merges by `updatedAt`, so two people uploading at once won't lose files.

## Tests

```bash
npm test
```

Covers the driver end-to-end against a mock Contents API: library
round-trip, blob lifecycle, multi-part reassembly, duplicate rejection.

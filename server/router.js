// Tiny HTTP router: pattern-matched API dispatch plus static file serving.
// Static assets live in the repo root (same layout GitHub Pages serves), so
// self-hosting and Pages host identical files.
import path from 'node:path';
import fs from 'node:fs';
import url from 'node:url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, '..');

// Never serve these over HTTP.
const DENY = new Set(['server', 'test', 'node_modules', '.git', 'data', 'data-test', 'data-smoke']);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.webmanifest': 'application/manifest+json',
};

function serveStatic(req, res, pathname) {
  const safe = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
  const firstSeg = safe.split(/[/\\]/)[0] || '';
  const candidates = safe === '/' ? ['index.html'] : [safe, `${safe}index.html`, `${safe.replace(/\/$/, '')}.html`];
  let filePath = null;
  for (const c of candidates) {
    if (DENY.has(c.split(/[/\\]/)[0])) break; // never leak server/test/data files
    const p = path.join(publicDir, c);
    if (!p.startsWith(publicDir)) continue; // path traversal guard
    try {
      if (fs.statSync(p).isFile()) { filePath = p; break; }
    } catch { /* keep looking */ }
  }
  void firstSeg;
  if (!filePath) {
    // SPA fallback — the client app resolves unknown paths itself.
    filePath = path.join(publicDir, 'index.html');
  }
  const ext = path.extname(filePath).toLowerCase();
  const immutable = filePath.includes(`${path.sep}assets${path.sep}`);
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Cache-Control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  });
  fs.createReadStream(filePath).pipe(res);
}

export function createRouter(routes) {
  return async function handle(req, res) {
    const u = new URL(req.url, 'http://localhost');
    const pathname = decodeURIComponent(u.pathname);

    if (pathname.startsWith('/api/') || pathname.startsWith('/blob/')) {
      for (const r of routes) {
        const m = r.pattern.exec(pathname);
        if (!m) continue;
        if (r.method && req.method !== r.method) continue;
        try {
          await r.handler({ req, res, params: m.groups || {}, url: u });
        } catch (err) {
          const status = err.statusCode || 500;
          if (status >= 500) console.error('[api]', err);
          if (!res.headersSent) {
            res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: status >= 500 ? 'Internal error' : err.message }));
          } else {
            res.end();
          }
        }
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method not allowed');
      return;
    }

    serveStatic(req, res, pathname);
  };
}

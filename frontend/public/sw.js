/*
 * MySSO service worker.
 *
 * Deliberately conservative for an identity provider:
 *  - only same-origin GET requests are handled: API calls (other origin), tokens and
 *    form submissions always go straight to the network;
 *  - pages (navigations) are never cached: they are always fetched fresh, and an
 *    offline page is shown when the network is down;
 *  - only immutable build assets (/_next/static, icons) are cached.
 */
const VERSION = 'v1';
const STATIC_CACHE = `mysso-static-${VERSION}`;
const PRECACHE = ['/icons/icon-192.png', '/icons/icon-512.png', '/icons/icon-maskable-192.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(STATIC_CACHE).then((cache) => cache.addAll(PRECACHE)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('mysso-') && k !== STATIC_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return; // API and third parties: untouched

  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => offlinePage()));
    return;
  }

  if (url.pathname.startsWith('/_next/static/') || url.pathname.startsWith('/icons/')) {
    event.respondWith(cacheFirst(request));
  }
});

async function cacheFirst(request) {
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(request);
  if (cached) return cached;
  const response = await fetch(request);
  if (response.ok) cache.put(request, response.clone());
  return response;
}

function offlinePage() {
  const html = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hors ligne · MySSO</title>
<style>
  :root { color-scheme: light dark; --bg:#f9fafb; --card:#fff; --fg:#1b1f27; --muted:#5d6472; --line:#e3e6eb; --accent:#1d8a63; }
  @media (prefers-color-scheme: dark) { :root { --bg:#16181d; --card:#1d2027; --fg:#eef0f3; --muted:#a4aab5; --line:#30343c; --accent:#5cc79b; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100dvh; display:grid; place-items:center; padding:24px; background:var(--bg); color:var(--fg);
         font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { width:100%; max-width:380px; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:28px; }
  img { width:44px; height:44px; border-radius:11px; }
  h1 { font-size:20px; margin:18px 0 6px; letter-spacing:-0.01em; }
  p { margin:0 0 20px; color:var(--muted); }
  button { width:100%; height:44px; border:0; border-radius:8px; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
  @media (prefers-color-scheme: dark) { button { color:#10261c; } }
</style>
</head>
<body>
<main>
  <img src="/icons/icon-192.png" alt="">
  <h1>Vous êtes hors ligne</h1>
  <p>MySSO a besoin d’une connexion pour vérifier votre identité. Vérifiez votre réseau, puis réessayez.</p>
  <button onclick="location.reload()">Réessayer</button>
</main>
</body>
</html>`;
  return new Response(html, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

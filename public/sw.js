'use strict';

/**
 * Minimal offline shell cache. We cache ONLY static app assets so the PWA
 * loads offline. We never cache chat traffic — messages and media are E2E
 * encrypted and flow exclusively over the WebSocket, which bypasses the SW.
 */

const CACHE = 'zangi-x-shell-v3';
const ASSETS = ['./', 'index.html', 'boot.js', 'app.js', 'libs/sodium.js', 'styles.css', 'manifest.webmanifest', 'icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only GET, same-origin, http(s) requests are eligible for the shell cache.
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // Never touch the websocket or any non-asset path.
  if (url.pathname === '/ws') return;

  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req)
        .then((res) => {
          // Cache successful same-origin basic responses for the known shell only.
          if (res && res.ok && res.type === 'basic' && ASSETS.some((a) => url.pathname.endsWith(a.replace('./', '/')))) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(() => caches.match('index.html'));
    })
  );
});

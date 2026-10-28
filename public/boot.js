'use strict';

/**
 * Bootstrap for the vendored, SRI-pinned libsodium build (public/libs/sodium.js).
 *
 * This lives in an external file (not an inline <script>) so the page can run
 * under a strict `script-src 'self' 'wasm-unsafe-eval'` CSP with no
 * 'unsafe-inline'. The three scripts in index.html are all `defer`, so they
 * execute in order:
 *     boot.js  →  libs/sodium.js  →  app.js
 * libsodium's standalone build calls window.sodium.onload once its WASM is
 * ready; we expose that as a promise app.js awaits.
 *
 * If the integrity check fails, the browser refuses to execute sodium.js, so
 * onload never fires — we reject after a timeout so the UI can surface it
 * instead of hanging forever.
 */
window.ghostSodiumReady = new Promise((resolve, reject) => {
  window.sodium = { onload: (s) => resolve(s) };
  setTimeout(() => reject(new Error('sodium-load-timeout')), 20000);
});

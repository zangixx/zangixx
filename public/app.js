'use strict';

/**
 * Zangi X client.
 *
 * Trust model: the server is a dumb relay and may be hostile. Every byte of
 * content is sealed with XChaCha20-Poly1305 under a key that lives ONLY in the
 * URL fragment — either a random key (`#k=...`) or, for a locked room, a key
 * derived from a passphrase + a non-secret salt (`#lock=1&s=...`). The fragment
 * is never sent in any HTTP request. The server sees ciphertext and routing
 * metadata only; see README "Threat Model" for exactly what still leaks.
 */

(function () {
  // ---- constants ---------------------------------------------------------
  const CHUNK = 128 * 1024; // plaintext bytes per media chunk
  const MAX_UPLOAD = 40 * 1024 * 1024; // client ceiling (keeps us under server caps)
  const PREVIEW_THRESHOLD = 2 * 1024 * 1024; // images above this get a thumbnail preview
  const MEDIA_TTL_MS = 5 * 60 * 1000; // revoke blob URLs after this
  const MAX_MESSAGES = 300;
  const COVER_INTERVAL_MS = 1200;
  const BACKPRESSURE = 4 * 1024 * 1024;

  // ---- state -------------------------------------------------------------
  let sodium = null;
  let KEY = null;
  let ROOM = null;
  let LOCKED = false;
  let UID = null;
  let NICK = null;
  let ws = null;
  let backoff = 500;
  let reconnectTimer = null;
  let manualClose = false;
  let typingTimer = null;
  let coverTimer = null;
  let heartbeatTimer = null;
  let wakeTimer = null;
  let connectedOnce = false;
  let dead = false; // room destroyed / burned
  const HEARTBEAT_MS = 10000; // keep-alive ping cadence (see README free-tier notes)
  const CRYPTO_BUILD = '0.7.15'; // vendored libsodium.js version, sent in the hello handshake
  const KEYCHECK_MARKER = 'zangi-keycheck-v1'; // sealed + relayed peer-to-peer to confirm shared key
  let keyMismatchWarned = false;

  const outbox = [];
  const incoming = new Map(); // mediaId -> receive assembler
  const uploads = new Map(); // mediaId -> upload record (for progress + resume)
  const blobUrls = new Set();
  const knownMedia = new Set();

  const $ = (id) => document.getElementById(id);
  const els = {};

  // ===== bootstrap ========================================================
  window.addEventListener('DOMContentLoaded', init);

  async function init() {
    Object.assign(els, {
      dot: $('status-dot'), messages: $('messages'), input: $('input'),
      composer: $('composer'), send: $('btn-send'), file: $('file'),
      attach: $('btn-attach'), typing: $('typing'), banner: $('banner'),
      paranoid: $('paranoid'), overlay: $('overlay'), lockBadge: $('lock-badge'),
    });

    try {
      sodium = await window.ghostSodiumReady;
    } catch {
      return fatal('Could not load the crypto library.');
    }

    setupIdentity();
    if (!(await setupRoom())) return;

    wireUI();
    registerServiceWorker();
    connect();
    // Cold start: if we aren't connected within 5s, assume the free-tier
    // instance is asleep and show the wake-up overlay.
    wakeTimer = setTimeout(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) showWake('Waking up the server…');
    }, 5000);
  }

  // ===== identity =========================================================
  function setupIdentity() {
    try {
      UID = sessionStorage.getItem('zx_uid');
      NICK = sessionStorage.getItem('zx_nick');
    } catch {
      /* storage blocked */
    }
    if (!UID) UID = cryptoRandomId(8);
    if (!NICK) NICK = randomNick();
    try {
      sessionStorage.setItem('zx_uid', UID);
      sessionStorage.setItem('zx_nick', NICK);
    } catch {
      /* ignore */
    }
  }

  // ===== key & room =======================================================
  const URLB64 = () => sodium.base64_variants.URLSAFE_NO_PADDING;

  async function setupRoom() {
    const params = new URLSearchParams(location.hash.replace(/^#/, ''));
    const keyB64 = params.get('k');
    const saltB64 = params.get('s');
    const isLocked = params.get('lock') === '1';

    if (keyB64) {
      KEY = parseKey(keyB64);
      if (!KEY) return fatalReturn('This link’s key is malformed. Ask for a fresh link.');
      LOCKED = false;
    } else if (isLocked && saltB64) {
      const salt = fromUrlB64(saltB64);
      if (!salt || salt.length !== sodium.crypto_pwhash_SALTBYTES) {
        return fatalReturn('This locked link is malformed. Ask for a fresh link.');
      }
      const pass = await passphraseModal({ title: 'Locked room', note: 'Enter the passphrase to unlock this chat.', confirm: false });
      if (!pass) return fatalReturn('A passphrase is required to open this room.');
      KEY = await deriveKey(pass, salt);
      LOCKED = true;
    } else {
      const choice = await startModal();
      if (choice === 'locked') {
        const pass = await passphraseModal({ title: 'New locked room', note: 'Choose a passphrase. Share it with people separately from the link — a leaked link alone will not open the room.', confirm: true });
        if (!pass) return setupRoom(); // cancelled → back to chooser
        const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
        KEY = await deriveKey(pass, salt);
        LOCKED = true;
        location.hash = 'lock=1&s=' + toUrlB64(salt);
      } else {
        KEY = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
        location.hash = 'k=' + toUrlB64(KEY);
        LOCKED = false;
      }
      showShareBanner(true);
    }

    // Opaque room handle = BLAKE2b(key). Only link/passphrase holders can
    // compute it; the server cannot tie it back to the key.
    ROOM = toUrlB64(sodium.crypto_generichash(16, KEY));
    if (LOCKED) els.lockBadge.classList.remove('hidden');
    return true;
  }

  function parseKey(b64) {
    try {
      const k = sodium.from_base64(b64, URLB64());
      return k.length === sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES ? k : null;
    } catch {
      return null;
    }
  }

  // Argon2id (libsodium crypto_pwhash) — stronger than PBKDF2. INTERACTIVE
  // limits keep it usable on phones; raise to MODERATE/SENSITIVE for a tougher
  // KDF at the cost of time and memory (see README).
  async function deriveKey(pass, salt) {
    showBusy('Deriving key…');
    await sleep(60); // let the spinner paint before the blocking KDF
    const key = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      pass,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    hideOverlay();
    return key;
  }

  // ===== AEAD helpers (wire payloads use STANDARD base64) =================
  const B64 = () => sodium.base64_variants.ORIGINAL;

  function seal(bytes) {
    const npub = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, null, null, npub, KEY);
    const out = new Uint8Array(npub.length + ct.length);
    out.set(npub, 0);
    out.set(ct, npub.length);
    return sodium.to_base64(out, B64());
  }

  function open(b64) {
    let data;
    try {
      data = sodium.from_base64(b64, B64());
    } catch {
      return null;
    }
    const nb = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const ab = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (data.length < nb + ab) return null;
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, data.subarray(nb), null, data.subarray(0, nb), KEY);
    } catch {
      return null;
    }
  }

  const BUCKETS = [128, 512, 2048, 8192, 32768, 131072];
  function padToBucket(bytes) {
    const need = bytes.length + 4;
    let target = BUCKETS.find((b) => b >= need) || Math.ceil(need / 131072) * 131072;
    const out = new Uint8Array(target);
    new DataView(out.buffer).setUint32(0, bytes.length, false);
    out.set(bytes, 4);
    return out;
  }
  function unpad(bytes) {
    if (bytes.length < 4) return bytes;
    const len = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
    return len > bytes.length - 4 ? null : bytes.subarray(4, 4 + len);
  }
  function sealJSON(obj) {
    return seal(padToBucket(utf8(JSON.stringify(obj))));
  }
  function openJSON(b64) {
    const raw = open(b64);
    if (!raw) return null;
    const body = unpad(raw);
    if (!body) return null;
    try {
      return JSON.parse(fromUtf8(body));
    } catch {
      return null;
    }
  }

  async function sha256hex(buf) {
    const d = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // ===== websocket ========================================================
  function connect() {
    if (dead) return;
    manualClose = false;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    try {
      ws = new WebSocket(`${proto}://${location.host}/ws`);
    } catch {
      return scheduleReconnect();
    }
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      backoff = 500;
      connectedOnce = true;
      clearTimeout(wakeTimer);
      hideWake();
      setStatus('online');
      // Handshake first: declare our crypto build so an upgraded server can
      // force stale clients to reload. We send NO key-derived material.
      wsSend({ t: 'hello', anonId: UID, sodiumVersion: CRYPTO_BUILD });
      wsSend({ t: 'join', room: ROOM });
      startHeartbeat();
      // Resume any uploads interrupted by a previous disconnect.
      for (const up of uploads.values()) {
        if (!up.complete && !up.aborted) wsSend({ t: 'media-have', id: up.id });
      }
    };

    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(typeof ev.data === 'string' ? ev.data : fromUtf8(new Uint8Array(ev.data)));
      } catch {
        return;
      }
      onServerFrame(msg);
    };

    ws.onclose = () => {
      setStatus('offline');
      stopHeartbeat();
      if (!manualClose && !dead) {
        showWake(connectedOnce ? 'Reconnecting…' : 'Waking up the server…');
        scheduleReconnect();
      }
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }

  function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    // Until we've connected once (likely a sleeping free-tier instance), poke an
    // HTTP endpoint — that is what actually wakes the platform; a WS handshake to
    // a sleeping instance may simply time out.
    if (!connectedOnce) nudgeWake();
    reconnectTimer = setTimeout(connect, Math.min(backoff, 30000) + Math.random() * 500);
    backoff = Math.min(Math.round(backoff * 1.8), 30000); // exponential, capped at 30s
  }

  function showWake(msg) {
    const o = document.getElementById('wake-up-overlay');
    if (!o) return;
    if (msg) {
      const t = document.getElementById('wake-title');
      if (t) t.textContent = msg;
    }
    o.classList.remove('hidden');
  }
  function hideWake() {
    const o = document.getElementById('wake-up-overlay');
    if (o) o.classList.add('hidden');
  }
  function nudgeWake() {
    // An HTTP request is what spins a sleeping free-tier instance back up.
    fetch('/health', { cache: 'no-store' }).catch(() => {});
  }

  // Application-level keep-alive. While a user is actively connected this keeps
  // the socket — and the free-tier instance — awake. It does NOT (and must not)
  // try to defeat spin-down when nobody is here; see README.
  function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(() => wsSend({ t: 'ping' }), HEARTBEAT_MS);
  }
  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
  }

  function wsSend(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    try {
      ws.send(JSON.stringify(obj));
      return true;
    } catch {
      return false;
    }
  }

  async function waitForDrain() {
    while (ws && ws.readyState === WebSocket.OPEN && ws.bufferedAmount > BACKPRESSURE) {
      await sleep(25);
    }
  }

  // ===== inbound frames ===================================================
  function onServerFrame(msg) {
    switch (msg.t) {
      case 'joined':
        system(`Connected · ${msg.peers} other${msg.peers === 1 ? '' : 's'} here`);
        sendKeyCheck(); // prove our key to whoever is already here
        if (Array.isArray(msg.media)) {
          for (const id of msg.media) if (!knownMedia.has(id) && !uploads.has(id)) wsSend({ t: 'media-get', id });
        }
        break;
      case 'full':
        return fatal('This room is full.');
      case 'peer-join':
        system('A participant joined');
        sendKeyCheck(); // re-announce so the newcomer can verify us too
        return;
      case 'keycheck':
        return onKeyCheck(msg.ct);
      case 'peer-leave':
        return system('A participant left');
      case 'destroyed':
        return onDestroyed(msg.reason);
      case 'error':
        return onServerError(msg);
      case 'pong':
        return; // keep-alive acknowledged
      case 'msg':
        return onText(msg.ct);
      case 'typing':
        return showTyping();
      case 'media-init':
        return onMediaInit(msg);
      case 'media-chunk':
        return onMediaChunk(msg);
      case 'media-done':
        return onMediaDone(msg);
      case 'media-have':
        return onMediaHave(msg);
      case 'media-blocked':
        return onMediaBlocked(msg);
      case 'media-missing':
        knownMedia.delete(msg.id);
        return;
      case 'media-expired':
        return onMediaExpired(msg.id);
      case 'media-fail':
        return system('A media transfer failed');
      default:
        return;
    }
  }

  function onText(ct) {
    const data = openJSON(ct);
    if (!data || data.k !== 'text' || typeof data.body !== 'string') return;
    renderMessage({ uid: data.uid, nick: data.nick, ts: data.ts, body: data.body });
  }

  // Key-confirmation: each client seals a fixed marker under the room key and
  // broadcasts it (relayed as ciphertext). If a peer's beacon fails to decrypt,
  // that peer holds a different key/passphrase and cannot read this chat. This
  // gives the "key integrity" signal WITHOUT sending any key-derived value to
  // the server — the server only ever relays opaque ciphertext.
  function sendKeyCheck() {
    wsSend({ t: 'keycheck', ct: seal(utf8(KEYCHECK_MARKER)) });
  }

  function onKeyCheck(ct) {
    const bytes = open(ct);
    if (bytes && fromUtf8(bytes) === KEYCHECK_MARKER) return; // verified: same key
    if (keyMismatchWarned) return;
    keyMismatchWarned = true;
    system('⚠ A participant has a different key or passphrase and cannot read this chat.');
  }

  function onServerError(msg) {
    if (msg.error === 'crypto_mismatch') {
      dead = true;
      manualClose = true;
      clearTimeout(wakeTimer);
      hideWake();
      try {
        ws && ws.close();
      } catch {
        /* ignore */
      }
      fatal('This app version is out of date. Reload the page to update to the current build.');
    }
  }

  function onDestroyed(reason) {
    dead = true;
    manualClose = true;
    try {
      ws && ws.close();
    } catch {
      /* ignore */
    }
    system(reason === 'expired' ? 'Room reached its lifetime limit and self-destructed.' : 'Room self-destructed after inactivity.');
    disableComposer();
    cleanup();
  }

  // ===== media receive ====================================================
  function onMediaInit(msg) {
    const id = msg.id;
    if (!id || incoming.has(id) || uploads.has(id)) return; // skip our own echoes
    knownMedia.add(id);
    const meta = msg.ct ? openJSON(msg.ct) : null;
    const asm = {
      n: msg.n | 0,
      received: 0,
      chunks: new Array(msg.n | 0),
      mime: meta && typeof meta.mime === 'string' ? meta.mime : 'application/octet-stream',
      kind: meta && meta.kind ? meta.kind : 'file',
      uid: meta ? meta.uid : null,
      nick: meta ? meta.nick : 'anon',
      ts: meta ? meta.ts : Date.now(),
      el: null,
    };
    incoming.set(id, asm);
    asm.el = renderMediaPlaceholder(asm);

    // Instant low-res preview for large images.
    if (msg.preview) {
      const pv = open(msg.preview);
      if (pv) paintPreview(asm.el, pv);
    }
    showProgress(asm.el, 0);
  }

  function onMediaChunk(msg) {
    const asm = incoming.get(msg.id);
    if (!asm) return;
    const seq = msg.seq | 0;
    if (seq < 0 || seq >= asm.n || asm.chunks[seq] !== undefined) return;
    const bytes = open(msg.ct);
    if (!bytes) return;
    asm.chunks[seq] = bytes;
    asm.received++;
    showProgress(asm.el, asm.received / asm.n);
    if (asm.received === asm.n) finalizeMedia(msg.id);
  }

  function onMediaDone(msg) {
    const asm = incoming.get(msg.id);
    if (!asm) return;
    if (asm.received === asm.n) finalizeMedia(msg.id);
    else if (!knownMedia.has(msg.id + ':retry')) {
      knownMedia.add(msg.id + ':retry');
      wsSend({ t: 'media-get', id: msg.id }); // request a full replay once
    }
  }

  function finalizeMedia(id) {
    const asm = incoming.get(id);
    if (!asm || asm.finalized) return;
    asm.finalized = true;
    let total = 0;
    for (const c of asm.chunks) total += c ? c.length : 0;
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of asm.chunks) {
      if (c) {
        merged.set(c, off);
        off += c.length;
      }
    }
    paintMedia(asm.el, asm.kind, asm.mime, trackedURL(new Blob([merged], { type: asm.mime })));
    hideProgress(asm.el);
    asm.chunks.length = 0;
    incoming.delete(id);
  }

  function onMediaHave(msg) {
    const up = uploads.get(msg.id);
    if (!up || up.complete || up.aborted) return;
    if (!msg.exists) {
      // Server lost the object (e.g. room was swept). Re-announce from scratch.
      if (up.hash) wsSend({ t: 'hash-check', id: up.id, hash: up.hash });
      wsSend({ t: 'media-init', id: up.id, n: up.n, ct: up.metaCt, preview: up.previewCt });
      up.have = new Set();
    } else {
      up.have = new Set(msg.have || []);
    }
    pumpChunks(up);
  }

  function onMediaBlocked(msg) {
    const up = uploads.get(msg.id);
    if (up) {
      up.aborted = true;
      if (up.el) {
        const holder = up.el.querySelector('.media-holder');
        if (holder) {
          holder.innerHTML = '';
          const d = document.createElement('div');
          d.className = 'blocked';
          d.textContent = 'Blocked: this file matches a known-bad content hash and was not sent.';
          holder.appendChild(d);
        }
        hideProgress(up.el);
      }
    }
    toast('Upload blocked by content policy');
  }

  // Server evicted this media from its cache (per-room 50 MB cap or memory
  // pressure). Anyone still assembling it won't complete; clean up the stub.
  function onMediaExpired(id) {
    knownMedia.delete(id);
    const asm = incoming.get(id);
    if (!asm) return;
    if (asm.el && !asm.finalized) {
      const holder = asm.el.querySelector('.media-holder');
      if (holder) {
        holder.innerHTML = '';
        const d = document.createElement('div');
        d.className = 'blocked';
        d.textContent = 'Media expired from the relay before it finished transferring.';
        holder.appendChild(d);
      }
      hideProgress(asm.el);
    }
    asm.chunks && (asm.chunks.length = 0);
    incoming.delete(id);
  }

  // ===== media send (hash-check → preview → chunks, with resume) ==========
  async function sendMedia(file) {
    if (!file || dead) return;

    let originalBytes;
    try {
      originalBytes = new Uint8Array(await file.arrayBuffer());
    } catch {
      return toast('Could not read that file');
    }
    // Hash of the ORIGINAL bytes for abuse screening (see README for limits).
    // crypto.subtle is only available in secure contexts (https/localhost/onion);
    // if it's missing we simply skip screening rather than failing the upload.
    let hash = '';
    try {
      hash = await sha256hex(originalBytes.buffer.slice(0));
    } catch {
      /* no SubtleCrypto here */
    }

    let blob = file;
    let kind = 'file';
    let mime = file.type || 'application/octet-stream';
    try {
      if (file.type.startsWith('image/')) {
        blob = await compressImage(file); // re-encode also strips EXIF/GPS
        kind = 'image';
        mime = 'image/webp';
      } else if (file.type.startsWith('video/')) {
        kind = 'video';
      }
    } catch {
      return toast('Could not process that file');
    }

    const bytes = blob === file ? originalBytes : new Uint8Array(await blob.arrayBuffer());
    if (bytes.length > MAX_UPLOAD) return toast('File too large (max 40 MB)');

    const id = cryptoRandomId(12);
    const n = Math.max(1, Math.ceil(bytes.length / CHUNK));
    knownMedia.add(id);

    let previewCt = '';
    if (kind === 'image' && originalBytes.length > PREVIEW_THRESHOLD) {
      try {
        const pv = await makeThumb(blob);
        if (pv) previewCt = seal(pv);
      } catch {
        /* preview is best-effort */
      }
    }
    const metaCt = sealJSON({ k: 'media-meta', mime, kind, size: bytes.length, uid: UID, nick: NICK, ts: Date.now() });

    // Local echo (sender sees the full media immediately).
    const el = renderMediaPlaceholder({ uid: UID, nick: NICK, ts: Date.now(), kind });
    paintMedia(el, kind, mime, trackedURL(new Blob([bytes], { type: mime })));

    const up = { id, bytes, n, hash, metaCt, previewCt, el, have: new Set(), complete: false, aborted: false };
    uploads.set(id, up);

    if (hash) {
      if (!wsSend({ t: 'hash-check', id, hash })) return toast('Not connected');
    } else if (!ws || ws.readyState !== WebSocket.OPEN) {
      return toast('Not connected');
    }
    wsSend({ t: 'media-init', id, n, ct: metaCt, preview: previewCt });
    showProgress(el, 0, 'uploading');
    await pumpChunks(up);
  }

  async function pumpChunks(up) {
    for (let seq = 0; seq < up.n; seq++) {
      if (up.aborted || dead) return;
      if (up.have.has(seq)) continue;
      await waitForDrain();
      if (!ws || ws.readyState !== WebSocket.OPEN) return; // resume kicks in on reconnect
      const slice = up.bytes.subarray(seq * CHUNK, Math.min((seq + 1) * CHUNK, up.bytes.length));
      if (!wsSend({ t: 'media-chunk', id: up.id, seq, ct: seal(slice) })) return;
      up.have.add(seq);
      showProgress(up.el, up.have.size / up.n, 'uploading');
    }
    if (up.aborted || dead) return;
    wsSend({ t: 'media-done', id: up.id });
    up.complete = true;
    hideProgress(up.el);
    // Free the retained bytes a little after completion.
    setTimeout(() => {
      const u = uploads.get(up.id);
      if (u && u.complete) {
        u.bytes = null;
        uploads.delete(up.id);
      }
    }, 30000);
  }

  async function compressImage(file) {
    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
    const w = Math.round(bitmap.width * scale);
    const h = Math.round(bitmap.height * scale);
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
    if (bitmap.close) bitmap.close();
    const out = await new Promise((res) => canvas.toBlob(res, 'image/webp', 0.82));
    return out || file;
  }

  async function makeThumb(blob) {
    const bmp = await createImageBitmap(blob);
    const scale = Math.min(1, 48 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const c = document.createElement('canvas');
    c.width = w;
    c.height = h;
    c.getContext('2d').drawImage(bmp, 0, 0, w, h);
    if (bmp.close) bmp.close();
    const tb = await new Promise((r) => c.toBlob(r, 'image/webp', 0.5));
    return tb ? new Uint8Array(await tb.arrayBuffer()) : null;
  }

  // ===== send text ========================================================
  function sendText() {
    if (dead) return;
    const body = els.input.value.trim();
    if (!body) return;
    els.input.value = '';
    autoGrow();
    renderMessage({ uid: UID, nick: NICK, ts: Date.now(), body });
    const frame = { t: 'msg', ct: sealJSON({ k: 'text', body, uid: UID, nick: NICK, ts: Date.now() }) };
    if (els.paranoid.checked) {
      outbox.push(frame);
      ensureCoverTimer();
    } else {
      wsSend(frame);
    }
  }

  function ensureCoverTimer() {
    if (coverTimer) return;
    coverTimer = setInterval(() => {
      if (outbox.length) wsSend(outbox.shift());
    }, COVER_INTERVAL_MS);
  }

  // ===== rendering ========================================================
  function renderMessage({ uid, nick, ts, body }) {
    const li = baseBubble(uid);
    li.appendChild(metaRow(nick, ts));
    const b = document.createElement('div');
    b.className = 'body';
    b.textContent = body; // textContent, never innerHTML → no XSS
    li.appendChild(b);
    append(li);
  }

  function renderMediaPlaceholder({ uid, nick, ts, kind }) {
    const li = baseBubble(uid);
    li.appendChild(metaRow(nick, ts));
    const holder = document.createElement('div');
    holder.className = 'media-holder';
    const loading = document.createElement('span');
    loading.className = 'loading';
    loading.textContent = kind === 'video' ? 'Receiving video…' : kind === 'image' ? 'Receiving image…' : 'Receiving file…';
    holder.appendChild(loading);
    li.appendChild(holder);
    const prog = document.createElement('div');
    prog.className = 'progress hidden';
    prog.innerHTML = '<span class="bar"></span><em class="pct"></em>';
    li.appendChild(prog);
    append(li);
    return li;
  }

  function paintPreview(li, bytes) {
    const holder = li && li.querySelector('.media-holder');
    if (!holder) return;
    holder.innerHTML = '';
    const img = document.createElement('img');
    img.className = 'preview';
    img.src = trackedURL(new Blob([bytes], { type: 'image/webp' }));
    holder.appendChild(img);
  }

  function paintMedia(li, kind, mime, url) {
    const holder = li && li.querySelector('.media-holder');
    if (!holder) return;
    holder.innerHTML = '';
    if (kind === 'image') {
      const img = document.createElement('img');
      img.loading = 'lazy';
      img.src = url;
      holder.appendChild(img);
    } else if (kind === 'video') {
      const v = document.createElement('video');
      v.controls = true;
      v.playsInline = true;
      v.preload = 'metadata';
      v.src = url;
      holder.appendChild(v);
    } else {
      const a = document.createElement('a');
      a.href = url;
      a.download = 'file';
      a.textContent = 'Download file';
      a.className = 'link';
      holder.appendChild(a);
    }
  }

  function showProgress(li, frac, label) {
    const p = li && li.querySelector('.progress');
    if (!p) return;
    p.classList.remove('hidden');
    p.querySelector('.bar').style.width = Math.round(frac * 100) + '%';
    p.querySelector('.pct').textContent = (label ? label + ' ' : '') + Math.round(frac * 100) + '%';
  }
  function hideProgress(li) {
    const p = li && li.querySelector('.progress');
    if (p) p.classList.add('hidden');
  }

  function baseBubble(uid) {
    const li = document.createElement('li');
    li.className = 'msg' + (uid === UID ? ' me' : '');
    return li;
  }

  function metaRow(nick, ts) {
    const meta = document.createElement('div');
    meta.className = 'meta';
    const n = document.createElement('span');
    n.className = 'nick';
    n.textContent = nick || 'anon';
    const t = document.createElement('span');
    t.textContent = fmtTime(ts);
    meta.appendChild(n);
    meta.appendChild(t);
    return meta;
  }

  function system(text) {
    const li = document.createElement('li');
    li.className = 'msg system';
    li.textContent = text;
    append(li);
  }

  function append(li) {
    const atBottom = els.messages.scrollHeight - els.messages.scrollTop - els.messages.clientHeight < 80;
    els.messages.appendChild(li);
    pruneMessages();
    if (atBottom) els.messages.scrollTop = els.messages.scrollHeight;
  }

  function pruneMessages() {
    while (els.messages.children.length > MAX_MESSAGES) {
      const first = els.messages.firstChild;
      first.querySelectorAll('img, video, a').forEach((m) => {
        const u = m.src || m.href;
        if (u && u.startsWith('blob:')) revokeURL(u);
      });
      els.messages.removeChild(first);
    }
  }

  function showTyping() {
    els.typing.textContent = 'Someone is typing…';
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => (els.typing.textContent = ''), 2500);
  }

  // ===== blob URL lifecycle ==============================================
  function trackedURL(blob) {
    const url = URL.createObjectURL(blob);
    blobUrls.add(url);
    setTimeout(() => revokeURL(url), MEDIA_TTL_MS);
    return url;
  }
  function revokeURL(url) {
    if (!blobUrls.has(url)) return;
    try {
      URL.revokeObjectURL(url);
    } catch {
      /* ignore */
    }
    blobUrls.delete(url);
  }

  // ===== modals ===========================================================
  function startModal() {
    return new Promise((resolve) => {
      const m = modalShell();
      m.innerHTML =
        '<h2>Start a room</h2><p>Your messages are end-to-end encrypted in this browser. Pick how the key is shared.</p>' +
        '<div class="stack">' +
        '<button class="ghost-btn choice" data-v="open">Instant room<small>Key lives in the link. Anyone with the link can read it.</small></button>' +
        '<button class="send-btn choice" data-v="locked">Locked room (passphrase)<small>Key derived from a passphrase. A leaked link alone cannot open it.</small></button>' +
        '</div>';
      m.querySelectorAll('button[data-v]').forEach((b) =>
        b.addEventListener('click', () => {
          hideOverlay();
          resolve(b.getAttribute('data-v'));
        })
      );
      showOverlay();
    });
  }

  function passphraseModal({ title, note, confirm }) {
    return new Promise((resolve) => {
      const m = modalShell();
      m.innerHTML =
        `<h2>${esc(title)}</h2><p>${esc(note)}</p>` +
        '<div class="err" id="pp-err"></div>' +
        '<input type="password" id="pp1" autocomplete="off" placeholder="Passphrase" />' +
        (confirm ? '<input type="password" id="pp2" autocomplete="off" placeholder="Confirm passphrase" />' : '') +
        `<div class="row"><button class="ghost-btn" id="pp-cancel">Cancel</button><button class="send-btn" id="pp-ok">${confirm ? 'Create' : 'Unlock'}</button></div>`;
      const pp1 = m.querySelector('#pp1');
      const pp2 = m.querySelector('#pp2');
      const err = m.querySelector('#pp-err');
      const done = (v) => {
        hideOverlay();
        resolve(v);
      };
      m.querySelector('#pp-cancel').addEventListener('click', () => done(null));
      m.querySelector('#pp-ok').addEventListener('click', () => {
        const v = pp1.value;
        if (v.length < 8) return (err.textContent = 'Use at least 8 characters.');
        if (confirm && v !== pp2.value) return (err.textContent = 'Passphrases do not match.');
        done(v);
      });
      pp1.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !confirm) m.querySelector('#pp-ok').click();
      });
      showOverlay();
      setTimeout(() => pp1.focus(), 30);
    });
  }

  function showBusy(label) {
    const m = modalShell();
    m.innerHTML = `<h2>${esc(label)}</h2><div class="spinner"></div>`;
    showOverlay();
  }

  function modalShell() {
    els.overlay.innerHTML = '';
    const m = document.createElement('div');
    m.className = 'modal';
    els.overlay.appendChild(m);
    return m;
  }
  function showOverlay() {
    els.overlay.classList.remove('hidden');
  }
  function hideOverlay() {
    els.overlay.classList.add('hidden');
    els.overlay.innerHTML = '';
  }

  // ===== UI wiring ========================================================
  function wireUI() {
    els.composer.addEventListener('submit', (e) => {
      e.preventDefault();
      const fd = new FormData(els.composer);
      if ((fd.get('website') || '').toString() || (fd.get('contact_email') || '').toString()) {
        wsSend({ t: '__probe' }); // honeypot tripped → server drops us
        manualClose = true;
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        return;
      }
      sendText();
    });

    els.input.addEventListener('input', () => {
      autoGrow();
      throttledTyping();
    });
    els.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        els.composer.requestSubmit();
      }
    });

    els.attach.addEventListener('click', () => els.file.click());
    els.file.addEventListener('change', () => {
      const f = els.file.files && els.file.files[0];
      els.file.value = '';
      if (f) sendMedia(f);
    });

    const stop = (e) => {
      e.preventDefault();
      e.stopPropagation();
    };
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach((ev) => document.addEventListener(ev, stop));
    document.addEventListener('drop', (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) sendMedia(f);
    });

    $('btn-share').addEventListener('click', () => showShareBanner(false));
    $('btn-leave').addEventListener('click', burn);

    const forceWake = $('btn-force-wake');
    if (forceWake)
      forceWake.addEventListener('click', () => {
        showWake('Waking up the server…');
        nudgeWake();
        backoff = 500;
        clearTimeout(reconnectTimer);
        connect();
      });

    els.paranoid.addEventListener('change', () => {
      if (!els.paranoid.checked && coverTimer) {
        clearInterval(coverTimer);
        coverTimer = null;
        while (outbox.length) wsSend(outbox.shift());
      }
    });

    window.addEventListener('pagehide', cleanup);
  }

  let typingThrottle = 0;
  function throttledTyping() {
    const now = Date.now();
    if (now - typingThrottle < 1500) return;
    typingThrottle = now;
    if (!els.paranoid.checked) wsSend({ t: 'typing' });
  }

  function autoGrow() {
    els.input.style.height = 'auto';
    els.input.style.height = Math.min(els.input.scrollHeight, 140) + 'px';
  }

  function showShareBanner(firstTime) {
    const url = location.href;
    els.banner.innerHTML = '';
    const p = document.createElement('div');
    if (LOCKED) {
      p.innerHTML = firstTime
        ? '<strong>Locked room created.</strong> Share this link, and share the <strong>passphrase separately</strong> over a channel you trust. The link alone cannot open the room.'
        : '<strong>Invite link (locked)</strong> — the passphrase is needed too; share it separately.';
    } else {
      p.innerHTML = firstTime
        ? '<strong>New room created.</strong> Anyone with this link can read the chat — the key is in the link itself. Share it only over a channel you trust.'
        : '<strong>Invite link</strong> — contains the encryption key. Share only with people you trust.';
    }
    const link = document.createElement('div');
    link.className = 'link';
    link.textContent = url;
    const copy = document.createElement('button');
    copy.className = 'ghost-btn';
    copy.textContent = 'Copy link';
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(url);
        toast('Link copied');
      } catch {
        toast('Copy failed — select the text manually');
      }
    });
    els.banner.appendChild(p);
    els.banner.appendChild(link);
    els.banner.appendChild(copy);
    els.banner.classList.remove('hidden');
  }

  function burn() {
    dead = true;
    manualClose = true;
    cleanup();
    try {
      ws && ws.close();
    } catch {
      /* ignore */
    }
    try {
      sessionStorage.clear();
    } catch {
      /* ignore */
    }
    els.messages.innerHTML = '';
    history.replaceState(null, '', location.pathname);
    system('Session burned. Reload with your link to start again.');
    disableComposer();
  }

  function disableComposer() {
    els.composer.querySelectorAll('button, textarea, input').forEach((n) => (n.disabled = true));
    setStatus('offline');
  }

  function cleanup() {
    for (const url of [...blobUrls]) revokeURL(url);
    if (coverTimer) clearInterval(coverTimer);
  }

  // ===== service worker ===================================================
  function registerServiceWorker() {
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  }

  // ===== helpers ==========================================================
  function setStatus(s) {
    els.dot.classList.remove('online', 'offline');
    els.dot.classList.add(s);
    if (!dead) els.send.disabled = s !== 'online';
  }

  function fatal(text) {
    document.body.innerHTML = '';
    const d = document.createElement('div');
    d.style.cssText = 'max-width:520px;margin:18vh auto;padding:24px;font:16px system-ui;color:#e7eaf0;text-align:center';
    d.textContent = text;
    document.body.appendChild(d);
  }
  function fatalReturn(text) {
    fatal(text);
    return false;
  }

  function toast(text) {
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = text;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2600);
  }

  function cryptoRandomId(bytes) {
    const b = new Uint8Array(bytes);
    crypto.getRandomValues(b);
    return sodium.to_base64(b, URLB64());
  }
  function toUrlB64(bytes) {
    return sodium.to_base64(bytes, URLB64());
  }
  function fromUrlB64(s) {
    try {
      return sodium.from_base64(s, URLB64());
    } catch {
      return null;
    }
  }

  function randomNick() {
    const adj = ['Quiet', 'Hidden', 'Faint', 'Dim', 'Pale', 'Still', 'Vague', 'Grey', 'Soft', 'Dusk'];
    const noun = ['Fox', 'Heron', 'Moth', 'Wren', 'Lynx', 'Crow', 'Owl', 'Hare', 'Vole', 'Stoat'];
    const r = (a) => a[Math.floor(Math.random() * a.length)];
    return r(adj) + r(noun);
  }

  function fmtTime(ts) {
    return new Date(ts || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function utf8(s) {
    return new TextEncoder().encode(s);
  }
  function fromUtf8(b) {
    return new TextDecoder().decode(b);
  }
  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }
})();

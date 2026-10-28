'use strict';

/**
 * Zangi X relay server — tuned for a single small free-tier instance
 * (512 MB RAM, limited CPU, spins down when idle).
 *
 * Design principle: data minimization. This process is a *dumb relay* for
 * end-to-end-encrypted frames. It does NO cryptography itself (so there is no
 * CPU-bound work to move to worker_threads), cannot read content, writes
 * nothing to disk, and holds all state in a memory-bounded LRU cache.
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { LRUCache } = require('lru-cache');

// --------------------------------------------------------------------------
// Configuration (all via env so nothing sensitive is baked into the image).
// --------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');

const ROOM_TTL_MS = intEnv('ROOM_TTL_MS', 5 * 60 * 1000); // inactivity self-destruct window
const ROOM_MAX_LIFETIME_MS = intEnv('ROOM_MAX_LIFETIME_MS', 0); // hard cap (0 = disabled)
const SWEEP_INTERVAL_MS = intEnv('SWEEP_INTERVAL_MS', 15 * 1000);
const HEARTBEAT_MS = intEnv('HEARTBEAT_MS', 30 * 1000);
const MAX_FRAME_BYTES = intEnv('MAX_FRAME_BYTES', 320 * 1024);
const MAX_ROOM_CLIENTS = intEnv('MAX_ROOM_CLIENTS', 50);
const MAX_ROOMS = intEnv('MAX_ROOMS', 5000);
const MAX_MEDIA_BYTES = intEnv('MAX_MEDIA_BYTES', 25 * 1024 * 1024); // per media object
const MAX_ROOM_MEDIA_BYTES = intEnv('MAX_ROOM_MEDIA_BYTES', 50 * 1024 * 1024); // per room (brief: 50MB)
const MAX_TOTAL_MEDIA_BYTES = intEnv('MAX_TOTAL_MEDIA_BYTES', 300 * 1024 * 1024); // global LRU ceiling
const MEM_LIMIT_BYTES = intEnv('MEM_LIMIT_BYTES', 512 * 1024 * 1024); // platform RAM budget
const MEM_EVICT_RATIO = floatEnv('MEM_EVICT_RATIO', 0.85); // evict LRU rooms above this fraction of the budget
const RATE_WINDOW_MS = intEnv('RATE_WINDOW_MS', 10 * 1000);
const RATE_MAX_FRAMES = intEnv('RATE_MAX_FRAMES', 600);
const BACKPRESSURE_LIMIT = intEnv('BACKPRESSURE_LIMIT', 8 * 1024 * 1024); // hard cap: drop a dead consumer
const WS_HIGH_WATER = intEnv('WS_HIGH_WATER', 1 * 1024 * 1024); // pause the producer above this
const WS_LOW_WATER = intEnv('WS_LOW_WATER', 256 * 1024); // resume it below this
const ABUSE_DROP_THRESHOLD = intEnv('ABUSE_DROP_THRESHOLD', 3);

// Accepted client crypto-build versions (a COMPATIBILITY gate, not tamper
// detection — a modified client can spoof this; SRI is what detects tampering).
const GOOD_SODIUM_VERSIONS = (process.env.GOOD_SODIUM_VERSIONS || '0.7.15')
  .split(/[\s,]+/)
  .filter(Boolean);

function intEnv(name, dflt) {
  const v = parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) && v >= 0 ? v : dflt;
}
function floatEnv(name, dflt) {
  const v = parseFloat(process.env[name] || '');
  return Number.isFinite(v) && v > 0 && v <= 1 ? v : dflt;
}

// --------------------------------------------------------------------------
// Logging: level-gated and PII-scrubbed. We already never read IPs or headers,
// but this is defense in depth — it guarantees that nothing identifying (IPs,
// UUIDs, room handles, key-like tokens) can reach stdout/stderr, which Render
// captures. Control verbosity with LOG_LEVEL ∈ {error,warn,info,debug}.
// --------------------------------------------------------------------------
const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const LOG_LEVEL = LOG_LEVELS[(process.env.LOG_LEVEL || 'info').toLowerCase()] ?? LOG_LEVELS.info;

function scrub(s) {
  return String(s)
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '[ip]') // IPv4
    .replace(/\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b/g, '[ip6]') // IPv6-ish
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[uuid]')
    .replace(/[A-Za-z0-9_-]{22,}/g, '[token]'); // base64url session ids / keys / room handles
}

function log(level, ...parts) {
  if ((LOG_LEVELS[level] ?? LOG_LEVELS.info) > LOG_LEVEL) return;
  const line = parts.map((p) => (typeof p === 'string' ? p : JSON.stringify(p))).join(' ');
  process.stderr.write(`[${level}] ${scrub(line)}\n`);
}

// --------------------------------------------------------------------------
// Known-bad content hashes (abuse screening). Reloadable with SIGHUP.
// --------------------------------------------------------------------------
let badHashes = new Set();
function loadBadHashes() {
  const set = new Set();
  const add = (h) => {
    const v = String(h).trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(v)) set.add(v);
  };
  (process.env.BAD_HASHES || '').split(/[\s,]+/).forEach(add);
  if (process.env.BAD_HASHES_FILE) {
    try {
      fs.readFileSync(process.env.BAD_HASHES_FILE, 'utf8').split(/\r?\n/).forEach(add);
    } catch {
      log('warn', 'could not read BAD_HASHES_FILE');
    }
  }
  badHashes = set;
}
loadBadHashes();
process.on('SIGHUP', () => {
  loadBadHashes();
  log('info', `bad-hash list reloaded (${badHashes.size} entries)`);
});

// --------------------------------------------------------------------------
// Aggregate metrics (no per-user data, no IPs). Exposed via /stats.
// --------------------------------------------------------------------------
const metrics = {
  startedAt: Date.now(),
  connectionsTotal: 0,
  roomsCreatedTotal: 0,
  roomsDestroyedTotal: 0,
  roomsEvictedMemory: 0,
  messagesRelayed: 0,
  mediaObjects: 0,
  mediaBytesProcessed: 0,
  hashChecks: 0,
  hashBlocks: 0,
};

// --------------------------------------------------------------------------
// MemoryManager: rooms live in an LRU cache bounded by count, by total media
// bytes, and by a per-room inactivity TTL. Eviction/expiry runs `disposeRoom`,
// which force-disconnects any clients and frees buffers. This is what keeps a
// 512 MB instance from being OOM-killed.
// --------------------------------------------------------------------------
const LRU_MAX_SIZE = Math.max(MAX_TOTAL_MEDIA_BYTES, MAX_ROOM_MEDIA_BYTES * 2 + 1);

const rooms = new LRUCache({
  max: MAX_ROOMS, // cap room count
  maxSize: LRU_MAX_SIZE, // cap total cached media bytes
  sizeCalculation: (room) => Math.min(LRU_MAX_SIZE, Math.max(1, room.bytes)),
  ttl: ROOM_TTL_MS, // inactivity self-destruct
  ttlAutopurge: true, // fire expiry even with no traffic
  updateAgeOnGet: false, // routing reads must NOT extend the self-destruct timer
  noDisposeOnSet: true, // re-setting the same room on activity is not a disposal
  dispose: disposeRoom,
});

function disposeRoom(room, roomId, reason) {
  // reason: 'evict' (count/size pressure), 'expire' (inactivity TTL),
  // 'delete' (burn/shutdown/memory sweep). 'set' never reaches here.
  const why = room.destroyReason || (reason === 'expire' ? 'inactive' : reason === 'evict' ? 'busy' : 'closed');
  for (const c of room.clients) {
    try {
      if (c.readyState === c.OPEN) c.send(JSON.stringify({ t: 'destroyed', reason: why }));
    } catch {
      /* ignore */
    }
    setTimeout(() => drop(c, 'destroyed'), 50);
  }
  for (const m of room.media.values()) {
    m.chunks.length = 0;
    m.meta = null;
    m.preview = null;
  }
  room.media.clear();
  room.clients.clear();
  room.blocked.clear();
  metrics.roomsDestroyedTotal++;
}

function getRoom(roomId) {
  let room = rooms.get(roomId); // moves to MRU; does not reset TTL
  if (!room) {
    room = { id: roomId, clients: new Set(), media: new Map(), blocked: new Set(), bytes: 0, created: Date.now() };
    rooms.set(roomId, room);
    metrics.roomsCreatedTotal++;
  }
  return room;
}

// Reset the inactivity TTL (and recency, and cached size) on genuine activity.
// Re-setting the same object reference is cheap and, with noDisposeOnSet, does
// not fire disposal. Heartbeat pings and typing do NOT call this.
function touch(room) {
  rooms.set(room.id, room);
}

function destroy(roomId, reason) {
  const room = rooms.peek(roomId);
  if (!room) return;
  room.destroyReason = reason;
  rooms.delete(roomId); // → disposeRoom
}

// Memory-pressure eviction. We key off RSS, NOT heapUsed: media is stored in
// Buffers, which live in external memory outside the V8 heap, so a heapUsed
// gauge would under-report our real footprint badly. When RSS crosses the
// budget we try a GC first, then drop least-recently-used rooms (keys() yields
// MRU→LRU, so we evict from the tail) until back under.
function memoryManager() {
  const limit = MEM_LIMIT_BYTES * MEM_EVICT_RATIO;
  if (process.memoryUsage().rss <= limit) return;
  if (global.gc) {
    try {
      global.gc();
    } catch {
      /* ignore */
    }
  }
  if (process.memoryUsage().rss <= limit) return;
  const keys = [...rooms.keys()];
  let i = keys.length - 1;
  let evicted = 0;
  while (i >= 0 && evicted < 50 && process.memoryUsage().rss > limit) {
    const id = keys[i--];
    if (rooms.has(id)) {
      destroy(id, 'busy');
      evicted++;
      metrics.roomsEvictedMemory++;
    }
  }
  if (evicted) {
    if (global.gc) {
      try {
        global.gc();
      } catch {
        /* ignore */
      }
    }
    log('warn', `memory pressure — evicted ${evicted} LRU room(s)`);
  }
}

// --------------------------------------------------------------------------
// HTTP: ops endpoints, honeypot, and a hardened static fallback.
// --------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.png': 'image/png', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8',
};

const CSP = [
  "default-src 'self'",
  // libsodium is vendored locally; 'wasm-unsafe-eval' lets its WASM compile
  // (it does not permit JS eval). No CDNs.
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' blob: data:",
  "media-src 'self' blob:",
  "connect-src 'self' ws: wss:",
  "worker-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

function securityHeaders(extra) {
  return Object.assign(
    {
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
    },
    extra || {}
  );
}

const HONEYPOT_PATHS = new Set([
  '/wp-login.php', '/wp-admin', '/.env', '/.git/config',
  '/admin.php', '/phpmyadmin', '/config.json', '/server-status',
]);

function handleHttp(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, securityHeaders({ Allow: 'GET, HEAD' }));
    return res.end();
  }
  let urlPath;
  try {
    urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    res.writeHead(400, securityHeaders());
    return res.end();
  }
  if (urlPath === '/health') return serveHealth(req, res);
  if (urlPath === '/stats') return serveStats(req, res);
  if (HONEYPOT_PATHS.has(urlPath)) return tarpit(res);
  serveStatic(req, res, urlPath === '/' ? '/index.html' : urlPath);
}

function serveHealth(req, res) {
  const mem = process.memoryUsage();
  const body = JSON.stringify({
    status: 'ok',
    uptime: Math.round(process.uptime()), // seconds — what Render's health check reads
    rooms: rooms.size,
    clients: wss.clients.size,
    memory: { rss: mem.rss, heapUsed: mem.heapUsed, limit: MEM_LIMIT_BYTES },
  });
  res.writeHead(200, securityHeaders({ 'Content-Type': MIME['.json'], 'Cache-Control': 'no-store' }));
  res.end(req.method === 'HEAD' ? undefined : body);
}

function serveStats(req, res) {
  if (!checkStatsSecret(req)) {
    res.writeHead(404, securityHeaders());
    return res.end();
  }
  const mem = process.memoryUsage();
  const body = JSON.stringify({
    uptimeSec: Math.round(process.uptime()),
    rooms: rooms.size,
    clients: wss.clients.size,
    badHashes: badHashes.size,
    memory: { rss: mem.rss, heapUsed: mem.heapUsed, limit: MEM_LIMIT_BYTES, cachedMediaBytes: rooms.calculatedSize },
    totals: metrics,
  });
  res.writeHead(200, securityHeaders({ 'Content-Type': MIME['.json'], 'Cache-Control': 'no-store' }));
  res.end(req.method === 'HEAD' ? undefined : body);
}

function checkStatsSecret(req) {
  const secret = process.env.STATS_SECRET || '';
  if (!secret) return false;
  const got = req.headers['x-stats-secret'];
  if (typeof got !== 'string') return false;
  const a = Buffer.from(got);
  const b = Buffer.from(secret);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function serveStatic(req, res, urlPath) {
  const resolved = path.join(PUBLIC_DIR, path.normalize(urlPath));
  if (resolved !== PUBLIC_DIR && !resolved.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403, securityHeaders());
    return res.end();
  }
  fs.stat(resolved, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, securityHeaders());
      return res.end();
    }
    const ext = path.extname(resolved).toLowerCase();
    res.writeHead(200, securityHeaders({
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': 'no-cache',
    }));
    if (req.method === 'HEAD') return res.end();
    const stream = fs.createReadStream(resolved);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });
}

function tarpit(res) {
  setTimeout(() => {
    try {
      res.writeHead(404, securityHeaders());
      res.end();
    } catch {
      /* gone */
    }
  }, 3000);
}

// --------------------------------------------------------------------------
// HTTP + WebSocket wiring.
// --------------------------------------------------------------------------
const server = http.createServer(handleHttp);
server.on('clientError', (_err, socket) => socket.destroyed || socket.destroy());

// permessage-deflate is OFF by default: media is already compressed client-side
// (WebP/WebM), text is tiny and bucket-padded, and ws deflate has a real
// per-connection memory cost we can't afford on a 512 MB box. Opt in with
// WS_COMPRESS=1 if your workload is text-heavy and RAM is comfortable.
const perMessageDeflate =
  process.env.WS_COMPRESS === '1'
    ? { threshold: 1024, serverNoContextTakeover: true, clientNoContextTakeover: true, concurrencyLimit: 4, zlibDeflateOptions: { level: 6, memLevel: 7 } }
    : false;

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES, perMessageDeflate });

server.on('upgrade', (req, socket, head) => {
  let pathname;
  try {
    pathname = new URL(req.url, 'http://x').pathname;
  } catch {
    return socket.destroy();
  }
  if (pathname !== '/ws') return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

// --------------------------------------------------------------------------
// Connection lifecycle.
// --------------------------------------------------------------------------
wss.on('connection', (ws) => {
  metrics.connectionsTotal++;
  ws.roomId = null;
  ws.rooms = new Set();
  ws.alive = true;
  ws.abuse = 0;
  ws.rateCount = 0;
  ws.rateReset = Date.now() + RATE_WINDOW_MS;

  ws.on('pong', () => {
    ws.alive = true;
  });

  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    if (!rateOk(ws)) return drop(ws, 'rate');
    let msg;
    try {
      msg = JSON.parse(data.toString('utf8'));
    } catch {
      return drop(ws, 'badjson');
    }
    if (!msg || typeof msg.t !== 'string') return drop(ws, 'badframe');
    try {
      handleFrame(ws, msg);
    } catch {
      drop(ws, 'error');
    }
  });

  ws.on('close', () => leaveRoom(ws));
  ws.on('error', () => leaveRoom(ws));
});

function rateOk(ws) {
  const now = Date.now();
  if (now > ws.rateReset) {
    ws.rateCount = 0;
    ws.rateReset = now + RATE_WINDOW_MS;
  }
  return ++ws.rateCount <= RATE_MAX_FRAMES;
}

function drop(ws, _reason) {
  try {
    ws.close(1008, 'policy');
  } catch {
    /* ignore */
  }
  try {
    ws.terminate();
  } catch {
    /* ignore */
  }
}

function getWsRoom(ws, msg) {
  const reqRoom = msg && str(msg.room);
  if (reqRoom && ws.rooms && ws.rooms.has(reqRoom)) {
    return rooms.get(reqRoom);
  }
  return ws.roomId ? rooms.get(ws.roomId) : null;
}

// --------------------------------------------------------------------------
// Frame handling. `ct`/`preview` are opaque base64 ciphertext; the server
// never parses them. `id`/`seq`/`n`/`hash` are routing/abuse metadata.
// --------------------------------------------------------------------------
function handleFrame(ws, msg) {
  switch (msg.t) {
    case 'hello':
      return onHello(ws, msg);
    case 'join':
      return onJoin(ws, msg);
    case 'leave':
      return leaveRoom(ws, msg.room ? str(msg.room) : null);
    case 'ping':
      // Keep-alive: keeps the socket (and the platform instance) awake while a
      // user is present. Intentionally does NOT reset the self-destruct TTL.
      return send(ws, { t: 'pong' });
    case 'msg':
      metrics.messagesRelayed++;
      return onRelay(ws, { t: 'msg', ct: str(msg.ct) }, false, msg);
    case 'typing':
      return onRelay(ws, { t: 'typing' }, true, msg);
    case 'keycheck':
      // Opaque, client-to-client key-confirmation beacon. The server relays the
      // ciphertext and learns nothing (no key material ever reaches it).
      return onRelay(ws, { t: 'keycheck', ct: str(msg.ct) }, true, msg);
    case 'reaction':
      return onRelay(ws, { t: 'reaction', ct: str(msg.ct) }, false, msg);
    case 'dm-invite':
      return onRelay(ws, { t: 'dm-invite', ct: str(msg.ct) }, false, msg);
    case 'hash-check':
      return onHashCheck(ws, msg);
    case 'media-init':
      return onMediaInit(ws, msg);
    case 'media-chunk':
      return onMediaChunk(ws, msg);
    case 'media-done':
      return onMediaDone(ws, msg);
    case 'media-get':
      return onMediaGet(ws, msg);
    case 'media-have':
      return onMediaHave(ws, msg);
    case '__probe':
      return drop(ws, 'honeypot');
    default:
      return;
  }
}

// Handshake. We validate ONLY the self-reported crypto-build version against an
// allow-list — a compatibility gate so an upgraded server can force stale
// clients to reload. It is NOT tamper detection (a modified client spoofs it;
// SRI is the real integrity control). We deliberately ignore anonId (no need to
// learn it) and accept no key-derived material here: hashing the room key to the
// server would leak key material for zero benefit, so the client never sends it.
function onHello(ws, msg) {
  const v = str(msg.sodiumVersion);
  if (v && !GOOD_SODIUM_VERSIONS.includes(v)) {
    send(ws, { t: 'error', error: 'crypto_mismatch', expected: GOOD_SODIUM_VERSIONS });
    return drop(ws, 'crypto');
  }
  ws.helloOk = true;
}

function onJoin(ws, msg) {
  const roomId = str(msg.room);
  if (!roomId || roomId.length > 64) return drop(ws, 'badroom');
  if (!ws.rooms) ws.rooms = new Set();
  
  if (ws.rooms.has(roomId)) {
    const room = rooms.get(roomId);
    if (room) {
      touch(room);
      send(ws, { t: 'joined', room: roomId, peers: room.clients.size - 1, media: [...room.media.keys()] });
    }
    return;
  }

  if (ws.rooms.size >= 30) return send(ws, { t: 'full', error: 'max_rooms' });
  const room = getRoom(roomId);
  if (room.clients.size >= MAX_ROOM_CLIENTS) return send(ws, { t: 'full', room: roomId });

  ws.roomId = roomId;
  ws.rooms.add(roomId);
  room.clients.add(ws);
  touch(room);
  send(ws, { t: 'joined', room: roomId, peers: room.clients.size - 1, media: [...room.media.keys()] });
  broadcast(room, ws, { t: 'peer-join', room: roomId, peers: room.clients.size });
}

function onRelay(ws, frame, noTouch, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  if (!noTouch) touch(room);
  frame.room = room.id;
  broadcast(room, ws, frame);
  applyBackpressure(ws, room);
}

function onHashCheck(ws, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  const id = str(msg.id);
  const hash = str(msg.hash).toLowerCase();
  if (!id || !/^[0-9a-f]{64}$/.test(hash)) return;
  metrics.hashChecks++;
  touch(room);
  if (badHashes.has(hash)) {
    metrics.hashBlocks++;
    room.blocked.add(id);
    ws.abuse++;
    send(ws, { t: 'media-blocked', id, room: room.id });
    if (ws.abuse >= ABUSE_DROP_THRESHOLD) drop(ws, 'abuse');
  }
}

function onMediaInit(ws, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  const id = str(msg.id);
  const n = Number(msg.n);
  if (!id || id.length > 64 || !Number.isInteger(n) || n < 1 || n > 4096) return drop(ws, 'badmedia');
  if (room.blocked.has(id) || room.media.has(id)) return;
  room.media.set(id, {
    chunks: new Array(n), meta: bufFromB64(msg.ct), preview: bufFromB64(msg.preview),
    received: 0, n, done: false, bytes: 0,
  });
  metrics.mediaObjects++;
  touch(room);
  broadcast(room, ws, { t: 'media-init', room: room.id, id, n, ct: str(msg.ct), preview: str(msg.preview) });
}

function onMediaChunk(ws, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  const id = str(msg.id);
  if (room.blocked.has(id)) return;
  const media = room.media.get(id);
  if (!media || media.done) return;
  const seq = Number(msg.seq);
  if (!Number.isInteger(seq) || seq < 0 || seq >= media.n) return;
  if (media.chunks[seq] !== undefined) return; // duplicate (resume) — ignore

  const buf = bufFromB64(msg.ct);
  if (!buf) return drop(ws, 'badchunk');
  if (media.bytes + buf.length > MAX_MEDIA_BYTES) return failMedia(ws, room, id, 'too-big');

  // Per-room media cap: evict this room's OLDEST media (FIFO) to make room,
  // rather than rejecting the new upload outright.
  if (room.bytes + buf.length > MAX_ROOM_MEDIA_BYTES) {
    evictRoomMedia(room, buf.length, id);
    if (room.bytes + buf.length > MAX_ROOM_MEDIA_BYTES) return failMedia(ws, room, id, 'room-full');
  }

  media.chunks[seq] = buf;
  media.bytes += buf.length;
  media.received += 1;
  room.bytes += buf.length;
  metrics.mediaBytesProcessed += buf.length;
  touch(room); // also updates this room's cached size in the LRU
  broadcast(room, ws, { t: 'media-chunk', room: room.id, id, seq, ct: str(msg.ct) });
  applyBackpressure(ws, room); // throttle this uploader if peers are backing up
}

function evictRoomMedia(room, need, keepId) {
  for (const [mid, m] of room.media) {
    if (room.bytes + need <= MAX_ROOM_MEDIA_BYTES) break;
    if (mid === keepId) continue;
    room.bytes -= m.bytes;
    m.chunks.length = 0;
    m.meta = null;
    m.preview = null;
    room.media.delete(mid);
    broadcast(room, null, { t: 'media-expired', room: room.id, id: mid });
  }
}

function onMediaDone(ws, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  const id = str(msg.id);
  if (room.blocked.has(id)) return;
  const media = room.media.get(id);
  if (!media) return;
  media.done = true;
  touch(room);
  broadcast(room, ws, { t: 'media-done', room: room.id, id });
}

function onMediaGet(ws, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  const id = str(msg.id);
  const media = room.media.get(id);
  if (!media) return send(ws, { t: 'media-missing', room: room.id, id });
  touch(room);
  send(ws, {
    t: 'media-init', room: room.id, id, n: media.n,
    ct: media.meta ? media.meta.toString('base64') : '',
    preview: media.preview ? media.preview.toString('base64') : '',
  });
  for (let seq = 0; seq < media.n; seq++) {
    if (media.chunks[seq]) send(ws, { t: 'media-chunk', room: room.id, id, seq, ct: media.chunks[seq].toString('base64') });
  }
  if (media.done) send(ws, { t: 'media-done', room: room.id, id });
}

function onMediaHave(ws, msg) {
  const room = getWsRoom(ws, msg);
  if (!room) return;
  const id = str(msg.id);
  const media = room.media.get(id);
  const have = [];
  if (media) for (let i = 0; i < media.n; i++) if (media.chunks[i] !== undefined) have.push(i);
  send(ws, { t: 'media-have', room: room.id, id, exists: !!media, n: media ? media.n : 0, have });
}

function failMedia(ws, room, id, reason) {
  const media = room.media.get(id);
  if (media) {
    room.bytes -= media.bytes;
    room.media.delete(id);
  }
  send(ws, { t: 'media-fail', room: room.id, id, reason });
}

function leaveRoom(ws, specificRoomId) {
  if (ws._bpTimer) {
    clearInterval(ws._bpTimer);
    ws._bpTimer = null;
    ws.bpPaused = false;
  }
  if (!ws.rooms) ws.rooms = new Set();
  const toLeave = specificRoomId
    ? [specificRoomId]
    : (ws.rooms.size > 0 ? [...ws.rooms] : (ws.roomId ? [ws.roomId] : []));

  for (const rId of toLeave) {
    ws.rooms.delete(rId);
    if (ws.roomId === rId) {
      ws.roomId = ws.rooms.size > 0 ? [...ws.rooms][0] : null;
    }
    const room = rooms.peek(rId);
    if (room) {
      room.clients.delete(ws);
      if (room.clients.size > 0) {
        broadcast(room, null, { t: 'peer-leave', room: rId, peers: room.clients.size });
      }
    }
  }
}

// --------------------------------------------------------------------------
// Sending helpers with backpressure protection.
// --------------------------------------------------------------------------
function send(ws, obj) {
  if (!ws || ws.readyState !== ws.OPEN) return;
  if (ws.bufferedAmount > BACKPRESSURE_LIMIT) return drop(ws, 'backpressure');
  ws.send(JSON.stringify(obj));
}

function broadcast(room, except, obj) {
  const payload = JSON.stringify(obj);
  for (const c of room.clients) {
    if (c === except || c.readyState !== c.OPEN) continue;
    if (c.bufferedAmount > BACKPRESSURE_LIMIT) {
      drop(c, 'backpressure');
      continue;
    }
    c.send(payload);
  }
}

function maxPeerBuffered(room, except) {
  let m = 0;
  for (const c of room.clients) {
    if (c === except || c.readyState !== c.OPEN) continue;
    if (c.bufferedAmount > m) m = c.bufferedAmount;
  }
  return m;
}

// Flow control for a relay: when a room's peers are buffering too much (a slow
// consumer), PAUSE the producer's socket so we stop ingesting frames we'd only
// have to buffer. ws.pause() pauses *reading*, which is exactly right here —
// pausing a slow consumer would do nothing for its send buffer. Resume when
// peers drain; cut loose any consumer stuck past the hard cap so one dead
// client can't stall the room forever.
function applyBackpressure(ws, room) {
  if (ws.bpPaused || maxPeerBuffered(room, ws) <= WS_HIGH_WATER) return;
  ws.bpPaused = true;
  try {
    ws.pause();
  } catch {
    /* ignore */
  }
  ws._bpTimer = setInterval(() => {
    for (const c of room.clients) {
      if (c !== ws && c.readyState === c.OPEN && c.bufferedAmount > BACKPRESSURE_LIMIT) drop(c, 'slow-consumer');
    }
    if (ws.readyState !== ws.OPEN || maxPeerBuffered(room, ws) <= WS_LOW_WATER) {
      clearInterval(ws._bpTimer);
      ws._bpTimer = null;
      ws.bpPaused = false;
      try {
        ws.resume();
      } catch {
        /* ignore */
      }
    }
  }, 100);
  if (ws._bpTimer.unref) ws._bpTimer.unref();
}

// --------------------------------------------------------------------------
// Small utilities.
// --------------------------------------------------------------------------
function str(v) {
  return typeof v === 'string' ? v : '';
}
function bufFromB64(v) {
  if (typeof v !== 'string' || v.length === 0) return null;
  try {
    return Buffer.from(v, 'base64');
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------------
// WS heartbeat: reap half-open sockets (distinct from the app-level keep-alive).
// --------------------------------------------------------------------------
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) {
      drop(ws, 'timeout');
      continue;
    }
    ws.alive = false;
    try {
      ws.ping();
    } catch {
      drop(ws, 'pingfail');
    }
  }
}, HEARTBEAT_MS);
heartbeat.unref();

// --------------------------------------------------------------------------
// Sweeper: hard-lifetime expiry + memory-pressure eviction. (Inactivity
// self-destruct is handled by the LRU's TTL + ttlAutopurge.)
// --------------------------------------------------------------------------
const sweeper = setInterval(() => {
  if (ROOM_MAX_LIFETIME_MS > 0) {
    const now = Date.now();
    for (const [id, room] of rooms.entries()) {
      if (now - room.created >= ROOM_MAX_LIFETIME_MS) destroy(id, 'expired');
    }
  }
  memoryManager();
}, SWEEP_INTERVAL_MS);
sweeper.unref();

// --------------------------------------------------------------------------
// Startup / graceful shutdown.
// --------------------------------------------------------------------------
server.listen(PORT, HOST, () => {
  log('info', `zangi x relay on ${HOST}:${PORT} · memLimit ${(MEM_LIMIT_BYTES / 1048576) | 0}MB · bad-hashes ${badHashes.size}`);
});

function shutdown() {
  clearInterval(heartbeat);
  clearInterval(sweeper);
  rooms.clear(); // disposes every room (closes clients, frees buffers)
  for (const ws of wss.clients) drop(ws, 'shutdown');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

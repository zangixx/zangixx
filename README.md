# Zangi X

An ephemeral, end-to-end-encrypted, in-memory relay chat. No accounts, no
database, no request logs. The server is a **dumb relay**: it moves opaque
ciphertext between participants and self-destructs rooms after inactivity.

This README is deliberately candid. A privacy tool is only worth anything if
its guarantees are *real*, so the Threat Model below spells out both what the
design protects and — just as important — what it does **not**.

---

## How it works (one paragraph)

Opening the app lets you create an **instant room** (a random 256-bit key goes
in the URL fragment, `#k=…`) or a **locked room** (you choose a passphrase; the
key is derived with Argon2id from the passphrase + a non-secret salt carried in
`#lock=1&s=…`, so the key is never in the URL at all). An opaque room handle is
derived as `BLAKE2b(key)`. The fragment is never sent in any HTTP request, so
the server only ever learns the room handle and sees ciphertext. Clients seal
every message and media chunk with **XChaCha20-Poly1305**. Share the link over
a channel you trust (and, for locked rooms, share the passphrase separately).
Close the tab or hit **Burn**, or let the room go idle, and everything is gone.

```
 Browser A ──seal()──►  ┌──────────────┐  ──►  Browser B
   (has key)            │  relay (node)│        (has key)
                        │  no key, no  │
 Browser C ◄────────────│  disk, self- │────────────► Browser D
   (has key)            │  destructing │        (has key)
                        └──────────────┘
          sees: room handle, ciphertext, chunk ids/sizes,
          timing, and (if enabled) a submitted content hash
```

---

## Quick start

### Local dev

```bash
npm install
npm start                      # http://localhost:8080
```

Open the link from the banner in a second browser profile to chat.

### Docker (Nginx + TLS 1.3)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/privkey.pem -out certs/fullchain.pem -subj "/CN=localhost"
touch bad-hashes.txt           # abuse-screening list (may start empty)
docker compose up --build      # https://localhost
```

---

## Features (v1.1)

| Area | What it does |
|------|--------------|
| **E2E encryption** | XChaCha20-Poly1305; key in URL fragment or Argon2id-derived from a passphrase. |
| **Room Lock** | Passphrase → Argon2id → key. Key never in the URL; a leaked link alone cannot open the room. |
| **Self-destruct** | Rooms are wiped after `ROOM_TTL_MS` of inactivity (connected clients are force-disconnected), plus an optional hard `ROOM_MAX_LIFETIME_MS`. |
| **Abuse screening** | Client hashes the original file (SHA-256) and sends it as `hash-check`; the server blocks relay of hashes on a configurable known-bad list. |
| **Media previews** | Images > 2 MB send an instant low-res thumbnail first, then stream the full blob. |
| **Progress + resume** | Upload/download progress bars; interrupted uploads resume via `media-have` (only missing chunks are resent). |
| **EXIF stripping** | Images are re-encoded to WebP client-side, dropping EXIF/GPS before encryption. |
| **Cover mode** | Optional batching + size-bucket padding of outbound text to blunt traffic analysis. |
| **Ops** | `/health` (aggregate liveness) and `/stats` (secret-gated aggregate metrics, no IPs). |
| **Honeypot** | Off-screen form fields + scanner-path tarpits + a drop-on-`__probe` rule. |
| **MemoryManager** | Rooms live in an `lru-cache` bounded by count, total media bytes, and inactivity TTL; an RSS watchdog evicts least-recently-used rooms above 80% of the RAM budget. Per-room media capped at 50 MB (oldest evicted first). |
| **Keep-alive** | Client pings every 10 s to keep the socket (and a free-tier instance) awake *while a user is present*. |
| **Supply-chain integrity** | libsodium is vendored locally and pinned with Subresource Integrity; strict CSP `script-src 'self' 'wasm-unsafe-eval'`, no CDNs. A `hello` handshake gates incompatible client crypto builds. |
| **Cold-start UX** | A wake-up overlay (+ Force-wake button) covers the 30–45 s free-tier cold start and auto-reconnects with backoff capped at 30 s. |
| **Backpressure** | A slow consumer pauses the *producer's* socket (`ws.pause()`) until peers drain; a truly-dead consumer is dropped at a hard cap — bounding server memory. |
| **Key confirmation** | Peers broadcast an encrypted `keycheck` beacon; a participant with the wrong key/passphrase is surfaced in the UI — no key material is sent to the server. |
| **Log scrubbing** | A level-gated logger (`LOG_LEVEL`) redacts IPs, UUIDs and key-like tokens before anything reaches stdout/stderr. |

---

## Abuse screening — scope and limits (read this)

Because content is end-to-end encrypted, **the server cannot see media to scan
it.** The only screening possible is one the client volunteers: it computes the
SHA-256 of the *original* file bytes and sends that hash; the server blocks
relay of any hash on its known-bad list.

Be clear-eyed about what this is:

- **It is exact-match only.** Changing a single byte (re-save, re-crop, one
  pixel) produces a different hash and evades the list. Real-world systems use
  *perceptual* hashing (e.g. PhotoDNA, pHash) for this reason; SHA-256 does not
  generalize.
- **It only binds the official client.** A modified client can skip or spoof the
  `hash-check`. This cannot be enforced server-side under E2E.
- **It leaks a little metadata.** The server learns the hash you submit, so it
  can confirm whether you sent a specific known file. That is the deliberate
  trade for having any screening at all.

It is still a worthwhile first-line control (it reliably stops the official
client from relaying known-bad files), but it is **not** a complete safety
solution. Treat it as one layer among your operational and legal measures.

**Updating the known-bad list**

- Inline: `BAD_HASHES="<hex>,<hex>"` (comma/space separated).
- File: `BAD_HASHES_FILE=/path/list.txt`, one SHA-256 hex per line (`#` comments ok).
- Build an entry: `sha256sum file` (Linux/macOS) or
  `Get-FileHash -Algorithm SHA256 file` (PowerShell).
- Hot-reload without downtime: send `SIGHUP`
  (`docker compose kill -s HUP zangi`).

---

## Operations

- **`GET /health`** → `{status, uptimeSec, rooms, clients, memory:{rss,heapUsed,heapTotal}}`. No secrets; used by the Docker healthcheck.
- **`GET /stats`** → aggregate counters (`messagesRelayed`, `mediaBytesProcessed`, `hashChecks`, `hashBlocks`, …). Requires header `X-Stats-Secret: $STATS_SECRET`; returns **404** if the secret is unset or wrong (so the endpoint isn't advertised). Contains **no per-user data and no IPs**.

Key env vars: `ROOM_TTL_MS`, `ROOM_MAX_LIFETIME_MS`, `MAX_ROOM_CLIENTS`,
`MAX_MEDIA_BYTES`, `MAX_ROOM_MEDIA_BYTES`, `ABUSE_DROP_THRESHOLD`,
`BAD_HASHES` / `BAD_HASHES_FILE`, `STATS_SECRET`.

---

## Threat Model & Operator's Responsibility

**The server CAN see**

- The **opaque room handle** (`BLAKE2b(key)`) — enough to group participants of
  the same room, not to derive the key.
- **Ciphertext** and its **length** (mitigated for text by bucket padding), plus
  **media chunk ids, counts and sizes**.
- **Timing**: when connections open/close and when frames arrive (mitigated, not
  eliminated, by Cover mode).
- **Submitted content hashes**, if the client sends `hash-check`.
- The **client IP at the TLS edge (Nginx only)** — used in memory for rate
  limiting and never forwarded to the relay (`X-Real-IP: 0.0.0.0`).

**The server CANNOT see**

- **Message or media content** — it holds no key and never receives the URL
  fragment or the passphrase.
- **The room key or passphrase.**
- **The client IP at the relay process** — stripped before proxying.
- **Any history after the fact** — nothing is written to disk; idle rooms are
  already wiped.

**Does NOT protect against**

- A **compromised endpoint** (malware, a malicious extension, shoulder-surfing).
- **Anyone you share the link/passphrase with** (screenshots, re-sharing).
- **No forward secrecy**: one static key per room lifetime. If the key leaks,
  traffic under it is readable. Mitigated by short-lived rooms; add a ratchet
  (MLS / Double Ratchet) for real PFS.
- **Global traffic analysis**: handles, sizes and timing still leak; padding and
  Cover mode only reduce this.
- A **hostile relay** dropping/reordering frames or denying service (AEAD stops
  content forgery, not disruption).

---

## Operator responsibility — read before you deploy

An anonymous, no-logs service that relays images and video **will attract abuse,
including CSAM.** Take it seriously:

- **E2E means you cannot moderate content.** The abuse-hash list above is the
  only server-side lever, and it is limited (exact-match, client-cooperative).
- **Running the service does not exempt you from the law.** Operator liability,
  reporting duties, retention mandates and lawful-process obligations vary by
  jurisdiction. Understand yours; get legal advice before running a public
  instance.
- **Prefer closed, invite-only use** (ideally locked rooms) over open public
  instances.
- **This is a privacy tool, not an evasion tool.** It exists to protect ordinary
  users, journalists and at-risk people from mass surveillance and breaches —
  not to shield criminal activity. No anti-forensic features aimed at defeating
  lawful investigation are included, and you should not add them.

**What the operator CAN do:** rotate the instance's IP by redeploying; wipe all
in-memory state by restarting the service; update the known-bad hash list
(`bad-hashes.txt`, hot-reloaded via `SIGHUP`); set abuse/rate limits.

**What the operator CANNOT do:** read messages or media (E2E — holds no key);
see client IPs at the relay (stripped at the edge; behind Cloudflare, hidden
from the public but not from Cloudflare or lawful process); stop a compromised
client from leaking its own room key.

**Legal & ethical:** the operator owns content moderation. Because E2E prevents
server-side scanning, that reduces to client-side known-bad hashing plus your
own policy and process. The deployment is "anonymous" only in that it isn't
publicly linked to you — Render, Cloudflare and your registrar can still be
compelled to disclose operator metadata.

---

## Supply-chain integrity

The entire cryptographic guarantee rests on the integrity of the client code, so
none of it is loaded from a third party:

- **libsodium is vendored** at `public/libs/sodium.js` (from
  `github.com/jedisct1/libsodium.js` tag `0.7.15`, `dist/browsers/sodium.js`) and
  **pinned with Subresource Integrity** in `index.html`. If the served bytes ever
  differ from the pinned `sha384-…`, the browser refuses to execute it. Regenerate
  after any update:
  ```bash
  openssl dgst -sha384 -binary public/libs/sodium.js | openssl base64 -A
  ```
- **Strict CSP, no CDNs.** `script-src 'self' 'wasm-unsafe-eval'` (the
  `'wasm-unsafe-eval'` is required for libsodium's WebAssembly to compile — it does
  **not** permit JS `eval`). Enforced both as a `<meta>` tag and as a response
  header (so it holds whether Node or Nginx serves the file).
- **The `hello` handshake is a compatibility gate, not tamper detection.** The
  client reports its crypto build; the server rejects builds not on
  `GOOD_SODIUM_VERSIONS` with `{"error":"crypto_mismatch"}`, which lets an upgraded
  server force stale clients to reload. A self-reported version is trivially
  spoofable by a modified client — **SRI is the control that actually detects
  tampering.** Don't mistake the version check for a security boundary.
- **No `keyHash` is sent to the server — key confirmation is done peer-to-peer.**
  Hashing the room key to the server was intentionally dropped: it leaks
  key-derived material for zero benefit (the server can't validate it against
  anything) and for passphrase rooms it only aids offline guessing. Instead, each
  client seals a fixed marker under the room key and broadcasts it as a `keycheck`
  beacon; the server relays only ciphertext. If a peer's beacon fails to decrypt,
  that peer holds a different key/passphrase and the UI warns you — the "key
  integrity" signal, with nothing key-derived ever reaching the server. The only
  key-derived value the server still sees is the routing handle `BLAKE2b(key)`
  (gated, for passphrase rooms, by Argon2id's cost).

## Free-tier hosting (Render / Fly.io)

A single free instance is enough — see **[DEPLOYMENT.md](DEPLOYMENT.md)** for the
step-by-step, and `render.yaml` / `fly.toml` for the blueprints. Two honest
engineering notes about the "free-tier" brief:

- **No `worker_threads` for crypto.** This server does *no* cryptography — it is
  a pure E2E relay — so there is no CPU-bound work to offload. Adding worker
  threads would only cost RAM and complexity on a 512 MB box, so it's omitted on
  purpose.
- **WS compression is off by default.** Media is already compressed client-side
  (WebP/WebM) and text is tiny and bucket-padded, while `permessage-deflate`
  carries a real per-connection memory cost. Enable it with `WS_COMPRESS=1` only
  if your traffic is text-heavy and RAM is comfortable.
- **Sleep is a feature here.** Free instances spin down when idle; because
  everything is in-memory, that simply wipes all rooms — the intended ephemeral
  behaviour. The keep-alive only holds the instance up while someone is actually
  connected; don't run external pingers to defeat sleep (ToS + wasted budget).

## Deployment Guide — hosting a privacy service responsibly

Legitimate reasons to host without exposing your personal/home infrastructure
include avoiding DDoS and harassment, and protecting at-risk operators
(this is how SecureDrop, and the onion services of Signal, the BBC, ProPublica
and others, operate). The techniques below are for that legitimate operational
security. They are **not** a way to escape accountability: you remain
responsible for what you run, and you should know your legal obligations.

### Option A — Tor onion service (recommended for operator-location privacy)

Keep TLS **and** serve **every asset from the onion itself** (see the warning
below). Minimal `torrc`:

```
HiddenServiceDir /var/lib/tor/zangi/
HiddenServicePort 80  127.0.0.1:8080     # proxy to the Nginx container's HTTP
HiddenServiceVersion 3
```

- Run the Docker stack bound to `127.0.0.1` only; let Tor publish the onion.
  Over Tor the `.onion` address already provides transport encryption and hides
  the server's network location, so plain HTTP to `127.0.0.1` is acceptable
  inside the host; you can still terminate TLS if you have a cert for the onion.
- Users reach it with Tor Browser; the in-fragment key model works unchanged.
- Consider publishing an `Onion-Location` header from your clearnet site if you
  run one, so Tor users are offered the onion automatically.

### Option B — VPS behind a reverse proxy

A normal VPS works too. For operator privacy: separate the service identity from
your personal identity (dedicated email, etc.), and put abuse-response contact
info in place. Keep the relay bound to the internal Docker network (as the
compose file does) so only the proxy is exposed.

### ⚠️ The Cloudflare-for-JS idea breaks the security model — don't do it

The original plan suggested serving the "non-sensitive" CSS/JS via a public
Cloudflare proxy while the app runs on an onion. **This silently destroys the
end-to-end guarantee.** All the cryptography runs in `app.js`. If a third party
(Cloudflare, a CDN, anyone who can tamper with that path) serves the JavaScript,
they can serve a *malicious* `app.js` that exfiltrates keys or plaintext — and
the user has no way to notice. The integrity of the code **is** the integrity of
the encryption.

So:

- **Serve `app.js`, `styles.css`, the service worker and libsodium from the same
  origin as the app** (the onion). Do not offload the crypto code to a CDN.
- **Vendor libsodium locally** (download `sodium.js` into `public/`), reference
  it with Subresource Integrity, and tighten the CSP `script-src` to `'self'`.
  Loading it from a CDN has the same tampering risk as above; the current CDN
  reference is a dev convenience, not a production setting.
- If you want a CDN at all, use it only for a *clearnet mirror's* truly static,
  non-executable assets, and keep the real app self-hosted.

### Deployment checklist

- [ ] Relay bound to the internal network only; proxy is the sole ingress.
- [ ] libsodium vendored locally + SRI; CSP `script-src 'self'`.
- [ ] Real TLS (or onion transport); `STATS_SECRET` set to a long random value.
- [ ] `bad-hashes.txt` populated for your context; SIGHUP reload tested.
- [ ] `ROOM_TTL_MS` / `ROOM_MAX_LIFETIME_MS` tuned; logging posture decided
      (`logging.driver: none` for true no-logs).
- [ ] An abuse-response process and an understanding of your legal obligations.

---

## Files

```
server.js            # relay, rooms, self-destruct sweeper, abuse screening, /health, /stats
public/index.html    # PWA shell (strict CSP), modals, wake-up overlay, honeypot
public/boot.js       # external bootstrap for the SRI-pinned libsodium (CSP-safe)
public/libs/sodium.js# vendored libsodium (SRI-pinned), no CDN
public/app.js        # crypto (XChaCha20/Argon2id), hashing, previews, chunked upload+resume, wake-up, UI
public/sw.js         # offline shell cache only
public/styles.css · icon.svg · manifest.webmanifest
nginx.conf           # TLS 1.3, IP masking, no logs, gzip (brotli optional), /health /stats /ws
Dockerfile · docker-compose.yml · bad-hashes.txt · .dockerignore
render.yaml · fly.toml · DEPLOYMENT.md   # free-tier deploy blueprints + guide
.gitignore · .gitattributes · pre-push.sh # repo hygiene + anonymity/SRI pre-push audit
```

## License

MIT. Provided as-is; you are responsible for how you deploy and operate it.

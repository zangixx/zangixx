# Zangi X — Anonymous Operator Deployment Guide (Render Free Tier)

A copy-paste guide a competent engineer can follow without guessing. Five phases.

## Read first (non-negotiable)

- **You are responsible for what you run.** A public, anonymous, no-logs media
  relay attracts abuse, including CSAM. Under E2E you cannot see content; the
  `bad-hashes.txt` list is your only server-side lever and it is weak
  (exact-match, client-cooperative). Know your jurisdiction's law before you
  expose a public instance; get legal advice if unsure.
- **"Anonymous" means "not publicly linked to you" — not "invisible to lawful
  process."** Render, Cloudflare, your registrar and your email provider all keep
  records, see your signup IP, and respond to subpoenas. These steps keep a
  volunteer project separate from your personal identity and reduce
  harassment/DDoS exposure. They are **not** a way to evade accountability, and
  you must not use them as one. (Use your own real, lawful identity details with
  these providers — do not impersonate anyone or use another person's data.)

---

## Phase 1 — The operator persona (identity decoupling)

The goal: the repo, the platform account and the commit history carry a *project*
identity, not your personal name/email. Example names below — **substitute your
own**.

1. Create a dedicated mailbox for the project (e.g. ProtonMail). Use it only here.
2. Create a GitHub account with that mailbox and a project handle (e.g. `zangi-ops`).
3. Create a Render account with the same mailbox.
4. **Rule:** never put your personal email, name, or IP in commit messages,
   issues, or platform metadata.

---

## Phase 2 — The repository (clean, no PII in history)

```bash
cd zangi-x                      # the directory holding all the generated files
git init
git branch -M main

# PROJECT identity only — never your personal name/email. Substitute your own.
git config user.name  "Ghost Architect"
git config user.email "ghost.architect@proton.me"
git config commit.gpgsign false # no GPG signature that could link a personal key

git add .
git commit -m "feat: zangi-x v1.2.0 - e2e encrypted ephemeral pwa"

# Audit BEFORE adding a remote or pushing — must print "PRE-PUSH AUDIT PASSED":
bash pre-push.sh

git remote add origin https://github.com/<project-handle>/zangi-x.git
git push -u origin main
```

The committed `.gitignore` keeps secrets (`.env`, `certs/`) out of the repo;
`.gitattributes` forces LF and marks `public/libs/sodium.js` binary so
cross-platform line-ending conversion can't silently change its bytes and break
the SRI hash. Keep `commit.gpgsign false` so no signature ties commits to a
personal key.

## Phase 2.5 — The persona audit

Before the first push (and after any history rewrite), confirm the git history is
itself a clean, anonymous artifact. `pre-push.sh` automates the first and last
checks; the middle two are manual on GitHub.

- [ ] **Authors:** every commit's author/committer is the persona —
      `git log --format='%an <%ae>' | sort -u` shows only
      `Ghost Architect <ghost.architect@proton.me>`. (`pre-push.sh` fails if any
      other email appears.)
- [ ] **GitHub metadata:** your account, issues and PRs use the project mailbox,
      not a personal one; the profile's name/email are the persona.
- [ ] **Repo description:** neutral and technical — no personal links, handles or
      "built by …".
- [ ] **Log messages free of PII:** set `PERSONAL_NAMES=(...)` in `pre-push.sh`
      with your real name(s) and re-run; it scans both tracked files and
      `git log`. (Manual spot check: `git log -p | grep -i "<your real name>"`.)

If any commit carries a personal identity, fix it **before** pushing:
`git commit --amend --reset-author` for the last commit, or re-init for a clean
history. A push is public and may be mirrored or cached — there is no clean undo.

---

## Phase 3 — The Render deployment (Docker blueprint)

1. Render Dashboard → **New +** → **Blueprint**.
2. Paste your repo URL (e.g. `https://github.com/<project-handle>/zangi-x`).
   Render detects `render.yaml` (`runtime: docker`, builds the `Dockerfile`).
3. Click **Apply**. Wait for the build (~5–10 min).
4. `STATS_SECRET` is generated and injected for you — copy it from the dashboard
   if you want to read `/stats` (via the `X-Stats-Secret` header).
5. Copy the URL (e.g. `https://zangi-x.onrender.com`).

Free tier = ephemeral disk only (no volumes/disks — the blueprint declares none).
The app writes nothing to disk, so that is a non-issue.

> Alternative: `fly.toml` is included for Fly.io (`flyctl launch --no-deploy
> --copy-config`; `flyctl secrets set STATS_SECRET=$(openssl rand -hex 24)`;
> `flyctl deploy`).

---

## Phase 4 — Custom domain + Cloudflare (optional, free) — with real caveats

Two things you must accept before doing this:

- **⚠️ Do not let Cloudflare (or any proxy) serve the app JS without integrity
  pinning.** All crypto runs in the client JS. A proxy that can rewrite it can
  serve a malicious build that steals keys, invisibly. libsodium is vendored +
  SRI-pinned and the CSP is strict, which is what makes proxying *survivable* —
  keep it that way; never move the crypto to a CDN origin you don't control.
- **Cloudflare's orange cloud hides your origin IP from the public, not from
  Cloudflare or lawful process.** It's DDoS/harassment protection, not anonymity.

Steps, if you accept the above:

1. Register a domain (Porkbun/Namecheap) with the project mailbox. **Whois
   privacy/redaction is the default now** and free — confirm it's on.
2. Add the domain to Cloudflare (Free plan); set the registrar's nameservers.
3. DNS: `CNAME www → zangi-x.onrender.com`. Enable proxy (orange cloud).
4. Render → **Settings → Custom Domains** → add your domain; Render
   auto-provisions a Let's Encrypt cert. Follow Render's exact record/verification
   prompts (it may ask for a specific CNAME/A target).
5. Cloudflare SSL/TLS mode: **Full (strict)**.

---

## Phase 5 — Verification & hardening

- [ ] **Cold-start test.** Close the tab, wait ~20 min (free instance sleeps),
      reopen. The **“Waking up the server…” overlay** should appear, then the chat
      loads once the WebSocket connects. (Hit **Force wake** to nudge it.)
- [ ] **SRI test.** DevTools → Network: `libs/sodium.js` loads from your origin
      with the `integrity="sha384-…"` attribute and **no CSP/SRI errors** in the
      console. Tamper one byte locally and confirm the browser refuses to run it.
- [ ] **Memory test.** Send ~10 images across a couple of rooms. Render → Metrics:
      RAM stays well under 512 MB (the MemoryManager evicts LRU rooms above the
      `MEM_LIMIT_BYTES` budget).
- [ ] **Log-scrubbing test.** Render → Logs: confirm **no IPs, UUIDs, room handles
      or key-like tokens** appear. Logs are level-gated by `LOG_LEVEL` (set to
      `warn` in `render.yaml`) and passed through a PII scrubber.
- [ ] **E2E sanity.** Open the invite link in two browsers; exchange a message and
      an image. For a **locked** room, open it with the wrong passphrase in a third
      browser and confirm the **“different key or passphrase” warning** appears and
      that client cannot read messages.
- [ ] `/health` returns `200`; `/stats` returns `404` without the secret and `200`
      with `-H "X-Stats-Secret: <secret>"`.

---

## Updating the crypto library (keep SRI + version gate in sync)

libsodium is vendored at `public/libs/sodium.js` and pinned by SRI. To update:

1. Replace the file with the new `dist/browsers/sodium.js` from the libsodium.js
   release you want.
2. Recompute and update `integrity="sha384-…"` in `public/index.html`:
   ```bash
   openssl dgst -sha384 -binary public/libs/sodium.js | openssl base64 -A
   ```
3. Bump `CRYPTO_BUILD` in `public/app.js` and add the new version to
   `GOOD_SODIUM_VERSIONS` (env) so the `hello` gate accepts it.
4. Bump the service-worker `CACHE` name in `public/sw.js` so clients fetch the
   new bytes instead of the cached old ones.

Skipping step 2 makes the browser (correctly) refuse to run the new file.

---

## Free-tier realities (don't fight them)

- **Sleep/cold start is expected.** The in-browser keep-alive (`ping` every 10 s)
  holds the instance up only *while a user is connected*. When everyone leaves it
  sleeps and all rooms vanish — the intended ephemeral behaviour.
- **Do not run an external pinger to defeat sleep.** It burns the free compute
  budget and commonly violates the platform's terms; it can get the account
  suspended. Always-on is a paid tier.
- **512 MB is the real limit.** `NODE_OPTIONS=--max-old-space-size=400` plus
  `MEM_LIMIT_BYTES` let the MemoryManager evict LRU rooms before the OOM killer.
- **One instance, no shared state.** Free tiers are single-instance; all state
  lives in that one process's memory — don't scale horizontally.

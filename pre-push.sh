#!/usr/bin/env bash
#
# Zangi X — pre-push opsec audit.
# Run from the repo root before `git push`:   bash pre-push.sh
# Or install it as a hook:   ln -s ../../pre-push.sh .git/hooks/pre-push
#
# Exits non-zero if anything that could deanonymize the operator, or break the
# crypto integrity, is about to be pushed. Nothing here contacts the network.

set -uo pipefail

# ============================ configure these ==============================
# Your project ("persona") identity — the ONLY author/email that should appear
# in history or tracked docs. Replace the examples with your own.
ALLOWED_EMAILS=(
  "ghost.architect@proton.me"
  "your-project-mailbox@proton.me"   # placeholder shipped in DEPLOYMENT.md
  "noreply@anthropic.com"
)
# Your REAL name(s)/handle(s) — listed here so the scan can catch accidental
# leaks of them in files or history. Leave empty to skip (not recommended).
PERSONAL_NAMES=()        # e.g. ("Jane Doe" "jdoe" "jane.doe")

RUN_DOCKER_BUILD="${RUN_DOCKER_BUILD:-0}"   # set to 1 to actually `docker build`
# ===========================================================================

fail=0
ok()   { printf '[ OK ] %s\n' "$*"; }
bad()  { printf '[FAIL] %s\n' "$*"; fail=1; }
warn() { printf '[WARN] %s\n' "$*"; }
note() { printf '       %s\n' "$*"; }

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root" || exit 2
have_git=0; git rev-parse --git-dir >/dev/null 2>&1 && have_git=1

# Tracked, operator-authored files only — exclude vendored libs, binaries and
# generated lockfiles so their contents don't trip the PII scan.
scan_files() {
  git ls-files -z -- . \
    ':(exclude)public/libs/*' ':(exclude)*.png' ':(exclude)*.ico' \
    ':(exclude)package-lock.json' 2>/dev/null
}

is_allowed_email() {
  local e="$1" a
  for a in "${ALLOWED_EMAILS[@]}"; do [ "$e" = "$a" ] && return 0; done
  return 1
}

echo "== Zangi X pre-push audit =="

# ---- 1. git author/committer identity -------------------------------------
echo "-- commit identity --"
if [ "$have_git" = 1 ] && git rev-parse HEAD >/dev/null 2>&1; then
  while IFS= read -r e; do
    [ -z "$e" ] && continue
    if is_allowed_email "$e"; then ok "author/committer email: $e"
    else bad "non-persona email in git history: $e  (rewrite history before pushing)"; fi
  done < <(git log --format='%ae%n%ce' | sort -u)
else
  warn "no commits yet — identity check skipped (commit first, then re-run)"
fi

# ---- 2. PII in tracked content --------------------------------------------
echo "-- PII in tracked content --"
if [ "$have_git" = 1 ]; then
  # 2a. emails not on the allowlist
  while IFS= read -r em; do
    [ -z "$em" ] && continue
    is_allowed_email "$em" || bad "unexpected email in tracked files: $em"
  done < <(scan_files | xargs -0 grep -hoIE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null | sort -u)

  # 2b. public IPv4 addresses (loopback/private/unspecified are fine)
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    case "$ip" in
      0.0.0.0|255.255.255.255|127.*|10.*|192.168.*|169.254.*) continue ;;
      172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) continue ;;
    esac
    bad "public IP address in tracked files: $ip"
  done < <(scan_files | xargs -0 grep -hoIE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null | sort -u)

  # 2c. personal names
  if [ "${#PERSONAL_NAMES[@]}" -gt 0 ]; then
    for n in "${PERSONAL_NAMES[@]}"; do
      if scan_files | xargs -0 grep -lIiF "$n" 2>/dev/null | grep -q .; then bad "personal name '$n' found in tracked files"; else ok "name '$n' not in files"; fi
      if git log --format='%an %cn %s %b' 2>/dev/null | grep -qiF "$n"; then bad "personal name '$n' found in git log"; fi
    done
  else
    warn "PERSONAL_NAMES is empty — add your real name(s) to catch accidental leaks"
  fi
  [ "$fail" = 0 ] && ok "no unexpected emails / public IPs in tracked content"
else
  warn "not a git repo — content scan skipped"
fi

# ---- 3. render.yaml is valid YAML -----------------------------------------
echo "-- render.yaml --"
if [ ! -f render.yaml ]; then
  bad "render.yaml missing"
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
  if python3 -c 'import yaml,sys; yaml.safe_load(open("render.yaml"))' >/dev/null 2>&1; then ok "render.yaml is valid YAML"; else bad "render.yaml is NOT valid YAML"; fi
elif command -v node >/dev/null 2>&1 && node -e "require('js-yaml')" >/dev/null 2>&1; then
  if node -e "require('js-yaml').load(require('fs').readFileSync('render.yaml','utf8'))" >/dev/null 2>&1; then ok "render.yaml is valid YAML"; else bad "render.yaml is NOT valid YAML"; fi
else
  warn "no YAML parser (pip install pyyaml, or npm i -D js-yaml) — validation skipped"
fi

# ---- 4. Dockerfile build (optional) ---------------------------------------
echo "-- Dockerfile --"
if [ "$RUN_DOCKER_BUILD" = 1 ]; then
  if command -v docker >/dev/null 2>&1; then
    if docker build -q -t zangi-x:prepush . >/dev/null 2>&1; then ok "docker build succeeded"; else bad "docker build FAILED"; fi
  else warn "RUN_DOCKER_BUILD=1 but docker is not installed"; fi
else
  if command -v docker >/dev/null 2>&1; then note "docker present — set RUN_DOCKER_BUILD=1 to test the build"; else note "docker not installed — build test skipped"; fi
fi

# ---- 5. vendored crypto present + SRI matches -----------------------------
echo "-- vendored crypto + SRI --"
sodium="public/libs/sodium.js"
html="public/index.html"
if [ ! -f "$sodium" ]; then
  bad "$sodium is missing — the vendored libsodium must be committed"
else
  if [ "$have_git" = 1 ] && git check-ignore -q "$sodium" 2>/dev/null; then bad "$sodium is gitignored — it must be committed"; else ok "$sodium present and trackable"; fi
  if command -v openssl >/dev/null 2>&1; then
    actual="sha384-$(openssl dgst -sha384 -binary "$sodium" | openssl base64 -A)"
    inhtml="$(grep -oE 'integrity="sha384-[^"]+"' "$html" 2>/dev/null | head -n1 | sed -E 's/.*"(sha384-[^"]+)".*/\1/')"
    if [ -z "$inhtml" ]; then bad "no integrity=\"sha384-…\" found in $html"
    elif [ "$actual" = "$inhtml" ]; then ok "SRI matches the vendored file"
    else bad "SRI MISMATCH — $html pins $inhtml but the file hashes to $actual"; fi
  else
    warn "openssl not found — SRI check skipped"
  fi
fi

echo
if [ "$fail" = 0 ]; then
  echo "PRE-PUSH AUDIT PASSED — safe to push."
else
  echo "PRE-PUSH AUDIT FAILED — resolve the [FAIL] items above before pushing."
fi
exit "$fail"

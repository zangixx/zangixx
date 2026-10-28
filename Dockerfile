# syntax=docker/dockerfile:1

# ---- deps: install production node_modules in isolation --------------------
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json ./
# If you commit a package-lock.json, prefer `npm ci --omit=dev` for
# reproducible, verifiable builds.
RUN npm install --omit=dev --no-audit --no-fund \
    && npm cache clean --force

# ---- runtime: minimal, non-root, read-only-friendly ------------------------
FROM node:20-alpine AS runtime
ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    MEM_LIMIT_BYTES=536870912 \
    NODE_OPTIONS=--max-old-space-size=400

# dumb-init gives us correct PID 1 signal forwarding → graceful SIGTERM.
RUN apk add --no-cache dumb-init

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY server.js ./
COPY bad-hashes.txt ./
COPY public ./public

# Keep any temp files off the (optionally read-only) root filesystem. The app
# writes nothing to disk; this just guarantees a writable /tmp exists even under
# a read-only root. (node:alpine ships /tmp as world-writable 1777, so the
# non-root user can use it.)
VOLUME ["/tmp"]

# Run as the unprivileged built-in user.
USER node

# EXPOSE is cosmetic on Render (it injects $PORT and routes to it); kept at 8080
# to match the local/compose default.
EXPOSE 8080

# Liveness check against /health. Shell form so ${PORT} (injected by platforms
# like Render) is expanded at runtime; falls back to 8080 locally. A generous
# start-period covers cold starts.
HEALTHCHECK --interval=30s --timeout=3s --start-period=25s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-8080}/health" || exit 1

# --expose-gc lets the stale-room sweeper nudge V8 to release freed buffers.
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "--expose-gc", "server.js"]

# AiSOC Web Frontend Dockerfile
# Multi-stage build for production. Build context = monorepo root.

FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
RUN npm install -g pnpm@8

# ─── Builder ──────────────────────────────────────────────────────────────────
# Single-stage install + build keeps pnpm's symlinked workspace layout
# intact (matches local dev). Splitting into a deps-only stage previously
# broke bin shims for tsup/tsc inside packages/*/node_modules.
FROM base AS builder
WORKDIR /app

COPY package.json pnpm-workspace.yaml ./
COPY pnpm-lock.yaml* ./
COPY turbo.json ./
COPY packages ./packages
COPY apps/web ./apps/web

ENV NEXT_TELEMETRY_DISABLED=1

# ─── Build-time rewrite targets (server-side) ───────────────────────────────
# Next.js bakes rewrite destinations into .next/routes-manifest.json at
# build time, so these args MUST be provided to docker build (e.g. via
# `args:` in docker-compose.demo.yml's `web.build:` block) when targeting
# anything other than a single-host localhost dev setup. Defaults match the
# Compose stack's Docker DNS so a no-arg `docker build` still yields a
# working image inside the demo network.
ARG API_URL=http://api:8000
ARG AGENTS_URL=http://agents:8084
ARG REALTIME_URL=http://realtime:4000
ENV API_URL=${API_URL}
ENV AGENTS_URL=${AGENTS_URL}
ENV REALTIME_URL=${REALTIME_URL}

# ─── Build-time public URLs (client-side bundle) ────────────────────────────
# Anything Next.js exposes to the browser via process.env.NEXT_PUBLIC_* is
# substituted at `next build` time (read from the build environment), then
# inlined as a string literal into the client JS chunks. Setting them only
# in the runtime container has no effect on the bundle.
#
# Defaults are empty so dev/local builds fall back to same-origin requests
# (apps/web/src/lib/api.ts checks for empty string and uses window.location).
# In Fly the values come from infra/fly/web/fly.toml's [build.args].
ARG NEXT_PUBLIC_API_URL=""
ARG NEXT_PUBLIC_WS_URL=""
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL}

# Use pnpm's default symlinked node_modules — same layout as local dev,
# so tsup/tsc bin shims resolve correctly inside each workspace package.
RUN pnpm install --no-frozen-lockfile

# Build workspace packages then the Next.js app.
RUN pnpm --filter @aisoc/types build && \
    pnpm --filter @aisoc/ui build && \
    pnpm --filter @aisoc/web build

# ─── Runner ───────────────────────────────────────────────────────────────────
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy the full workspace so symlinked workspace packages keep resolving.
COPY --from=builder --chown=nextjs:nodejs /app ./

USER nextjs
EXPOSE 3000
WORKDIR /app/apps/web

# pnpm resolves the workspace's next binary correctly under symlinked layout.
CMD ["pnpm", "start"]

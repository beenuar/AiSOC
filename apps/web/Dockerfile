# AiSOC Web Frontend Dockerfile
# Multi-stage build for production. Build context = monorepo root.

FROM node:22-alpine AS base
RUN apk add --no-cache libc6-compat
# Pinned to the exact version `package.json`'s `packageManager` field declares
# and `install.sh` installs. `pnpm@8` floats across the 8.x line, so the image
# could resolve the lockfile with a different pnpm than CI — two resolvers,
# two answers to what this commit installs.
RUN npm install -g pnpm@8.15.1

# ─── Builder ──────────────────────────────────────────────────────────────────
# Single-stage install + build keeps pnpm's symlinked workspace layout
# intact (matches local dev). Splitting into a deps-only stage previously
# broke bin shims for tsup/tsc inside packages/*/node_modules.
FROM base AS builder
WORKDIR /app

COPY package.json pnpm-workspace.yaml ./
# Not `pnpm-lock.yaml*`: the glob makes the lockfile optional, so a build with
# no lockfile in context would succeed and resolve its own dependency tree.
COPY pnpm-lock.yaml ./
COPY turbo.json ./
COPY tsconfig.base.json ./
COPY VERSION ./
COPY packages ./packages
COPY apps/web ./apps/web

ENV NEXT_TELEMETRY_DISABLED=1

# ─── Build-time rewrite targets (server-side) ───────────────────────────────
# Next.js bakes rewrite destinations into .next/routes-manifest.json at
# build time, so these args MUST be provided to docker build (e.g. via
# `args:` in infra/compose/docker-compose.demo.yml's `web.build:` block) when targeting
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

# ─── Build-time demo-mode flags (client-side bundle) ────────────────────────
# These drive the in-bundle demo experience read by `apps/web/src/lib/demoMode.ts`:
#   - NEXT_PUBLIC_DEMO_MODE: gates the banner, auto-login, and read-only UI
#   - NEXT_PUBLIC_DEMO_DEEPLINK: the case URL the onboarding "Try Demo" CTA targets
#   - NEXT_PUBLIC_DEMO_BANNER: top-of-page banner copy
#   - NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL/_PASSWORD: credentials DemoAutoLogin uses on
#     first paint so visitors land already authenticated and can roam
#
# `NEXT_PUBLIC_DEMO_MODE` defaults to **off**, so a no-arg `docker build`
# produces a self-host bundle rather than a demo one. It used to default to
# "true", which meant a self-hoster's console announced "Demo data resets
# daily at 00:00 UTC. All write actions are disabled." over their own real
# ingested alerts, disabled every write control, and offered them a
# "Self-host AiSOC" link inside their own self-hosted install. Next inlines
# `NEXT_PUBLIC_*` at build time, so there is no runtime escape from a bundle
# built this way — the operator has to rebuild the image.
#
# Every path that genuinely wants the demo sets the flag explicitly
# (`publish-images.yml`, `release.yml`, `infra/fly/web/fly.toml`,
# `infra/compose/docker-compose.demo.yml`), so the safe default costs those
# nothing. The api/agents/realtime images are unaffected — demo gating in
# those services is runtime via AISOC_DEMO_MODE, not build-time.
# The autologin credentials default to empty, and deliberately carry no
# fallback anywhere else either. They used to default to a real address and
# password here, which meant every image — including one built with demo mode
# off — inlined a working login pair into the JavaScript it serves to browsers.
# A build that does not ask for the demo should not be able to ship demo
# credentials by omission. Every demo path passes them explicitly
# (`publish-images.yml`, `release.yml`, `infra/fly/web/fly.toml`, the `build:`
# block below this file's consumers), so the empty default costs those nothing.
ARG NEXT_PUBLIC_DEMO_MODE=""
ARG NEXT_PUBLIC_DEMO_DEEPLINK="/cases/INC-RT-001?tab=ledger"
ARG NEXT_PUBLIC_DEMO_BANNER="Demo data resets daily at 00:00 UTC. All write actions are disabled."
ARG NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL=""
ARG NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD=""
ENV NEXT_PUBLIC_DEMO_MODE=${NEXT_PUBLIC_DEMO_MODE}
ENV NEXT_PUBLIC_DEMO_DEEPLINK=${NEXT_PUBLIC_DEMO_DEEPLINK}
ENV NEXT_PUBLIC_DEMO_BANNER=${NEXT_PUBLIC_DEMO_BANNER}
ENV NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL=${NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL}
ENV NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD=${NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD}

# Use pnpm's default symlinked node_modules — same layout as local dev,
# so tsup/tsc bin shims resolve correctly inside each workspace package.
#
# `--frozen-lockfile`, matching every workflow that installs this workspace.
# It was `--no-frozen-lockfile`, which made the production web image the one
# install path in the repository free to resolve its own answer: the bundle
# users are served could be built from a dependency set no CI job had ever
# installed. If this now fails, the lockfile is stale — run `pnpm install` and
# commit the result rather than relaxing the flag.
RUN pnpm install --frozen-lockfile

# Build workspace packages then the Next.js app. @aisoc/report-card must be
# built here too — the /tools/coverage page imports it, and without its dist the
# route silently drops from the build (404 in prod).
RUN pnpm --filter @aisoc/types build && \
    pnpm --filter @aisoc/ui build && \
    pnpm --filter @aisoc/report-card build && \
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

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

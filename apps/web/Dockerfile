# AiSOC Web Frontend Dockerfile
# Multi-stage build for production. Build context = monorepo root.

FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
RUN npm install -g pnpm@8

# ─── Dependencies ────────────────────────────────────────────────────────────
FROM base AS deps
WORKDIR /app

COPY package.json pnpm-workspace.yaml ./
COPY pnpm-lock.yaml* ./
COPY packages/types/package.json ./packages/types/
COPY packages/ui/package.json ./packages/ui/
COPY packages/ocsf/package.json ./packages/ocsf/
COPY apps/web/package.json ./apps/web/

# Hoisted node_modules so pnpm-installed bins are on PATH and Next.js can
# resolve workspace packages without symlink games.
RUN echo "node-linker=hoisted" > .npmrc && \
    echo "shamefully-hoist=true" >> .npmrc && \
    pnpm install --no-frozen-lockfile

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/.npmrc ./.npmrc

COPY package.json pnpm-workspace.yaml ./
COPY pnpm-lock.yaml* ./
COPY packages/types ./packages/types
COPY packages/ui ./packages/ui
COPY packages/ocsf ./packages/ocsf
COPY apps/web ./apps/web
COPY turbo.json ./

ENV NEXT_TELEMETRY_DISABLED=1

# Build workspace packages then the Next.js app.
RUN pnpm --filter @aisoc/types build && \
    pnpm --filter @aisoc/ui build && \
    pnpm --filter @aisoc/web build

# Prune dev dependencies for a smaller runtime.
RUN pnpm --filter @aisoc/web --prod deploy /app/deploy 2>/dev/null || true

# ─── Runner ───────────────────────────────────────────────────────────────────
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy hoisted node_modules (contains next + workspace deps).
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/next.config.js ./next.config.js

USER nextjs
EXPOSE 3000

# Use the next binary from hoisted node_modules.
CMD ["node_modules/.bin/next", "start"]

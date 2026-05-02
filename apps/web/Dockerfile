# AiSOC Web Frontend Dockerfile
# Multi-stage build for production

FROM node:20-alpine AS base

# ─── Dependencies ────────────────────────────────────────────────────────────
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install pnpm
RUN npm install -g pnpm@8

# Copy workspace config
COPY package.json pnpm-workspace.yaml ./
COPY pnpm-lock.yaml ./

# Copy package.json files for workspaces
COPY packages/types/package.json ./packages/types/
COPY packages/ui/package.json ./packages/ui/
COPY apps/web/package.json ./apps/web/

RUN pnpm install --frozen-lockfile

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

RUN npm install -g pnpm@8

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/types/node_modules ./packages/types/node_modules
COPY --from=deps /app/packages/ui/node_modules ./packages/ui/node_modules
COPY --from=deps /app/apps/web/node_modules ./apps/web/node_modules

# Copy source
COPY packages/types ./packages/types
COPY packages/ui ./packages/ui
COPY apps/web ./apps/web
COPY turbo.json ./

# Build
ENV NEXT_TELEMETRY_DISABLED=1
RUN cd packages/types && pnpm build
RUN cd packages/ui && pnpm build
RUN cd apps/web && pnpm build

# ─── Runner ───────────────────────────────────────────────────────────────────
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/apps/web/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]

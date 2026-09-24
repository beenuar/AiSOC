# AiSOC realtime (WebSocket / SSE) service.
#
# `npm ci`, not `npm install`, and the lockfile is copied in both stages.
# This image used to copy only `package.json` and run `npm install`, so the
# committed `package-lock.json` was never in the build context and every
# build re-resolved the whole tree — including a fresh answer for each `^`
# range. Spelling the command `npm ci` alone would not have helped: it would
# have failed for want of a file nobody copied. The two halves go together.
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
EXPOSE 8086
CMD ["node", "dist/index.js"]

# AiSOC realtime (WebSocket / SSE) service.
#
# `npm ci`, not `npm install`, and the lockfile is copied in both stages.
# This image used to copy only `package.json` and run `npm install`, so the
# committed `package-lock.json` was never in the build context and every
# build re-resolved the whole tree — including a fresh answer for each `^`
# range. Spelling the command `npm ci` alone would not have helped: it would
# have failed for want of a file nobody copied. The two halves go together.
#
# `--ignore-scripts` in the builder, and only in the builder. This stage
# installs devDependencies for exactly one reason — to run `tsc` — and `tsc`
# has no install script. What it also drags in is `esbuild`, a transitive of
# `tsx` that the image never executes, whose install script hardlinks the
# platform binary into place and then immediately execs it to read its
# version, with no retry. Under BuildKit that exec loses a race against the
# writer still holding the inode open and fails `ETXTBSY`, which is what broke
# this build: `npm error path /app/node_modules/esbuild`, `spawnSync
# /app/node_modules/esbuild/bin/esbuild ETXTBSY`. Skipping dependency install
# scripts removes the race by not running a script this stage never needed,
# and stops the image build from executing arbitrary third-party code for a
# toolchain it throws away. `npm run build` below is an explicit invocation
# and still runs.
#
# The runtime stage deliberately keeps its install scripts: what it installs
# is what actually ships, so it should be built the way it runs.
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
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

# AiSOC MCP server, served over streamable HTTP.
#
# Depth 9.1 (parity 6.6). Until this file existed the server was a stdio
# child process and nothing deployed it.
#
# Why the build context is the repository root
# --------------------------------------------
# `services/mcp` is a member of the root pnpm workspace (`pnpm-workspace.yaml`
# lists it by name), so its dependency versions live in the root
# `pnpm-lock.yaml`. Building from `services/mcp/` as the context would mean
# resolving `^1.31.0` fresh on every build, which is the exact defect the
# determinism work closed elsewhere in this tree: the same commit building two
# ways. `.dockerignore` excludes `services/` for the web build's sake and
# un-excludes this one directory, which costs the web context ~300 KB of
# TypeScript and buys a locked install here.
#
# pnpm is pinned to the same 8.15.1 the lockfile was written with and CI
# installs. `pnpm@8` floats across the 8.x line, so an unpinned image could
# resolve the lockfile with a different resolver than CI did.
FROM node:22-alpine AS base
RUN npm install -g pnpm@8.15.1

FROM base AS builder
WORKDIR /app
# Not `pnpm-lock.yaml*`: a glob makes the lockfile optional, so a build with a
# missing one would silently become a floating install instead of failing.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY services/mcp ./services/mcp
# --frozen-lockfile: if this fails the lockfile is stale, which is a thing to
# fix rather than to work around. --ignore-scripts because nothing in this
# dependency set needs a postinstall and the image should not execute
# third-party install code it does not need.
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @aisoc/mcp...
RUN pnpm --filter @aisoc/mcp build

FROM base AS runtime
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY services/mcp/package.json ./services/mcp/package.json
RUN pnpm install --frozen-lockfile --ignore-scripts --prod --filter @aisoc/mcp...
COPY --from=builder /app/services/mcp/dist ./services/mcp/dist

# Non-root. This process holds no credential of its own — every request
# carries the caller's — but it does hold them in memory for the life of a
# request, which is reason enough not to run it as uid 0.
RUN addgroup -g 10001 -S aisoc && adduser -u 10001 -S aisoc -G aisoc
USER aisoc

WORKDIR /app/services/mcp
EXPOSE 8096

# 0.0.0.0 inside the container because that is the only address a sibling
# service can reach; compose publishes the port on the loopback address the
# rest of the stack uses, so the bind inside the namespace is not the bind an
# operator sees.
ENV AISOC_MCP_HTTP=1 \
    AISOC_MCP_HTTP_HOST=0.0.0.0 \
    AISOC_MCP_HTTP_PORT=8096

# Liveness only. The endpoint deliberately reports nothing about where this
# server points or whose tenant it is serving.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.AISOC_MCP_HTTP_PORT||8096)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js", "serve"]

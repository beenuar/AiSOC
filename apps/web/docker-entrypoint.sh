#!/bin/sh
# Console container entrypoint.
#
# Resolves the upstream addresses the Next.js server proxies to against the
# environment this container was *started* with, rather than the one the image
# was *built* with, then hands off to the real command.
#
# Without this step `API_URL`, `AGENTS_URL` and `REALTIME_URL` are inert on a
# pulled image: `next build` compiles rewrite destinations into
# .next/routes-manifest.json and `next start` serves routing from there. See
# scripts/resolve-runtime-routes.mjs for the full reasoning.
#
# `exec` so the Next.js server becomes PID 1 and receives SIGTERM directly —
# without it `docker stop` waits out the full timeout on every shutdown.
set -e

node "$(dirname "$0")/scripts/resolve-runtime-routes.mjs"

exec "$@"

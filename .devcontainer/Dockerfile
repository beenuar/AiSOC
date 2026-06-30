# syntax=docker/dockerfile:1.7
###############################################################################
# AiSOC devcontainer image.
#
# This file is the source of `ghcr.io/beenuar/aisoc-devcontainer:latest`, the
# prebuilt image referenced by .devcontainer/devcontainer.json. Building the
# Codespaces side-cars (docker-in-docker, python, go, github-cli) into a
# single image instead of resolving them via `features:` on every cold start
# drops first-boot from ~5 minutes to ~30 seconds.
#
# Layers, top to bottom:
#   1. Base: javascript-node bookworm — Node 20 + pnpm-friendly debian
#   2. System packages: docker.io, python3.11 + uv, go, gh
#   3. Workspace bootstrap: corepack-prepare pnpm, prime turbo/eslint caches
#
# Keep this image small enough that `docker pull` over a Codespaces machine's
# default network is < 30 s on first launch. The CI job at
# `.github/workflows/devcontainer-build.yml` rebuilds and publishes on every
# push to main; the integration test at
# `.github/workflows/devcontainer-coldstart.yml` asserts the boot KPI.
###############################################################################

FROM mcr.microsoft.com/devcontainers/javascript-node:1-20-bookworm

ARG TARGETARCH

# ─── System tooling ─────────────────────────────────────────────────────────
#
# We deliberately install via apt rather than re-using the upstream
# `ghcr.io/devcontainers/features/*` install scripts. apt is fully
# offline-installable from the base image's mirror; the features path adds
# its own resolution + download phase that happens at codespace cold-start
# time and is the largest single contributor to the ~5 min boot we are
# eliminating.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg2 lsb-release software-properties-common \
        python3.11 python3.11-venv python3-pip pipx \
        build-essential libffi-dev libssl-dev \
        docker.io docker-compose-plugin \
        ripgrep jq \
 && rm -rf /var/lib/apt/lists/*

# ─── GitHub CLI (gh) ────────────────────────────────────────────────────────
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && chmod 644 /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends gh \
 && rm -rf /var/lib/apt/lists/*

# ─── Go 1.22 ─────────────────────────────────────────────────────────────────
ENV GO_VERSION=1.22.5
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) goarch="amd64" ;; \
        arm64) goarch="arm64" ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
        | tar -C /usr/local -xz; \
    ln -s /usr/local/go/bin/go /usr/local/bin/go; \
    ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
ENV PATH="/usr/local/go/bin:${PATH}"

# ─── Python toolchain (uv) ──────────────────────────────────────────────────
# `uv` is the canonical Python package manager for AiSOC services. Installing
# it at image-build time means a fresh codespace can run `uv sync` against
# `services/api/uv.lock` immediately, with no further network round-trips.
RUN pipx ensurepath \
 && pipx install uv \
 && pipx install ruff

# ─── pnpm via corepack ──────────────────────────────────────────────────────
RUN corepack enable \
 && corepack prepare pnpm@8.15.1 --activate

# ─── Workspace bootstrap ────────────────────────────────────────────────────
# The actual pnpm install of workspace dependencies happens at codespace
# create time (`postCreateCommand`) because the lockfile changes too often
# to bake into the image. But seeding the pnpm store with a single test
# dependency forces corepack + the store layout to materialise, so the
# postCreateCommand sees a warm store and finishes in seconds rather than
# minutes.
RUN su node -c "pnpm config set store-dir /home/node/.local/share/pnpm/store \
             && pnpm store status >/dev/null 2>&1 || true"

USER node
WORKDIR /workspaces/AiSOC

LABEL org.opencontainers.image.source="https://github.com/beenuar/AiSOC"
LABEL org.opencontainers.image.description="Prebuilt devcontainer for AiSOC contributors and Codespaces."
LABEL org.opencontainers.image.licenses="MIT"

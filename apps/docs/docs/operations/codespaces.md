# Codespaces & devcontainers

AiSOC ships a prebuilt devcontainer image so a fresh Codespace boots from
clone-link to a green `pnpm aisoc:demo` in **about 30 seconds**, down from
roughly 5 minutes when the same image was assembled from
`features:` on every cold start.

## What's prebuilt

The image is published at
[`ghcr.io/beenuar/aisoc-devcontainer:latest`](https://github.com/beenuar/AiSOC/pkgs/container/aisoc-devcontainer)
on every push to `main`. It carries:

- Node 20 + `pnpm@8.15.1` via `corepack`
- Python 3.11 + [`uv`](https://github.com/astral-sh/uv) + `ruff`
- Go 1.22
- `docker` + `docker-compose-plugin`
- GitHub CLI (`gh`)
- `ripgrep`, `jq`, `build-essential` (for native deps in `npm`/`pip`)
- A warm pnpm store directory so the codespace's first `pnpm install`
  resolves from cache rather than the network.

The source lives at
[`.devcontainer/Dockerfile`](https://github.com/beenuar/AiSOC/blob/main/.devcontainer/Dockerfile);
the publisher at
[`.github/workflows/devcontainer-build.yml`](https://github.com/beenuar/AiSOC/blob/main/.github/workflows/devcontainer-build.yml).

## Cold-start budget

| Phase | Budget | Source of truth |
|---|---|---|
| `docker pull` of the devcontainer image | 60 s | `PHASE_PULL_BUDGET` |
| `pnpm install --frozen-lockfile=false` (warm store) | included in pull phase | `onCreateCommand` |
| `pnpm aisoc:acceptance --cold` | 5 min | `PHASE_ACCEPTANCE_BUDGET` |

Both budgets are gated by
[`.github/workflows/devcontainer-coldstart.yml`](https://github.com/beenuar/AiSOC/blob/main/.github/workflows/devcontainer-coldstart.yml),
which runs on every `main` push and on every successful devcontainer
publish. A red run blocks the release that introduced the regression.

## Using it

### In GitHub Codespaces

Click [**Open in Codespaces**](https://codespaces.new/beenuar/AiSOC?quickstart=1).
The image is pulled automatically; `onCreateCommand` runs `pnpm install`;
then open a terminal and run:

```bash
# Real stack (Docker-in-Docker inside the codespace):
pnpm aisoc:demo --no-open
# …then click the forwarded port 3000.

# Or, no-Docker (zero-dependency simulator):
pip install -e packages/aisoc-sandbox
aisoc-sandbox demo
```

### Locally, with `devcontainer-cli`

If you have
[`@devcontainers/cli`](https://github.com/devcontainers/cli)
installed, the same image works as a local dev environment:

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . pnpm aisoc:demo --no-open
```

### Locally, with VS Code

VS Code's "Reopen in Container" command resolves
`.devcontainer/devcontainer.json` directly. Same prebuilt image as the
Codespaces flow.

## When the image is rebuilt

- **Every push to `main`** that touches `.devcontainer/**` or the build
  workflow.
- **Every Monday at 09:00 UTC** so security-relevant base-image updates
  land on schedule even if the surface itself didn't change.
- **On manual dispatch** from the Actions tab.

If you need to pin to a specific build (e.g. for a release branch),
every push gets a `sha-<short_sha>` tag in addition to `latest`. The
weekly cron job also tags `weekly` so an external dependency can pin to
"the most recent base-image hygiene refresh" if it wants to.

## If something breaks

1. The local fallback `build:` block in
   [`.devcontainer/devcontainer.json`](https://github.com/beenuar/AiSOC/blob/main/.devcontainer/devcontainer.json)
   means contributors without GHCR pull access can still build the image
   locally — at the cost of the ~5 min initial assembly time.
2. Open an [issue tagged
   `devex/devcontainer`](https://github.com/beenuar/AiSOC/issues/new?labels=devex%2Fdevcontainer)
   with the failing Codespace's name and the first error from the boot
   log. Most failures are dependency network blips, not image-content
   regressions.

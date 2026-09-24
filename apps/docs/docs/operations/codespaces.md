# Codespaces & devcontainers

AiSOC ships a prebuilt devcontainer image so a fresh Codespace boots from
clone-link to **a usable dev shell in about 30 seconds**, down from
roughly 5 minutes when the same image was assembled from `features:` on
every cold start. (Booting the full demo stack still takes a few
minutes — that's a docker-pull problem, not a devcontainer-assembly
problem — but you can start typing, running tests, and editing code
within ~30 s of the Codespace opening.)

## What's prebuilt

The image is published at
[`ghcr.io/beenuar/aisoc-devcontainer:latest`](https://github.com/beenuar/AiSOC/pkgs/container/aisoc-devcontainer)
on every push to `main`. It carries:

- Node 22 + `pnpm@8.15.1` via `corepack`
- Python 3.11 + [`uv`](https://github.com/astral-sh/uv) + `ruff`
- Go 1.22
- Docker CE 20.x (`docker.io`) + Compose v2 plugin
  (pinned at `v2.29.7`, fetched from the upstream binary release into
  `/usr/local/lib/docker/cli-plugins/` so `docker compose ...` works
  out of the box)
- GitHub CLI (`gh`)
- `ripgrep`, `jq`, `build-essential` (for native deps in `npm`/`pip`)
- A warm pnpm store directory so the codespace's first `pnpm install`
  resolves from cache rather than the network.

The source lives at
[`.devcontainer/Dockerfile`](https://github.com/beenuar/AiSOC/blob/main/.devcontainer/Dockerfile);
the publisher at
[`.github/workflows/devcontainer-build.yml`](https://github.com/beenuar/AiSOC/blob/main/.github/workflows/devcontainer-build.yml).

## Why the Docker daemon needs runtime options

Baking the toolchain into the image instead of resolving it through
`features:` is what buys the cold start, but it does not work for Docker, and
that distinction broke the quickstart for several releases
([#716](https://github.com/beenuar/AiSOC/issues/716)).

`ghcr.io/devcontainers/features/docker-in-docker` does two things:

1. **Installs the Docker binaries.** Reproducible in a Dockerfile — that is
   the `docker.io` package plus the pinned Compose v2 plugin above.
2. **Supplies container runtime options** (`--privileged`, `--init`, a volume
   at `/var/lib/docker`) and an entrypoint that launches `dockerd`.

Only the first has a Dockerfile equivalent. **Capabilities are granted at
container creation and cannot be self-granted from an image**, so an image
that bakes the binaries and stops there produces a container with `CapEff: 0`
and `CAP_SYS_ADMIN` outside the bounding set. `sudo` cannot help, because the
capability is not in the set to grant. `dockerd` dies on its first `iptables`
call:

```text
failed to start daemon: Error initializing network controller: ...
iptables -t nat -N DOCKER: Permission denied (you must be root)
```

The symptom is confusing because the CLI works perfectly — `docker --version`
answers, `docker ps` does not — which sends people looking for a missing
install rather than a missing capability.

`devcontainer.json` therefore passes the runtime half explicitly
(`runArgs`, a named volume for `/var/lib/docker` because overlay2 cannot run
on the container's own overlay filesystem), and
[`.devcontainer/start-docker.sh`](https://github.com/beenuar/AiSOC/blob/main/.devcontainer/start-docker.sh)
is the missing entrypoint. It runs from `postStartCommand` rather than
`onCreateCommand` so a Codespace stop and resume comes back with a working
daemon, and it is idempotent because that hook fires on every start.

## Cold-start budget

The KPI we hold ourselves to is _time-to-first-keystroke in a Codespace_,
not _time-to-running-demo-stack_. The full demo stack still needs to
pull multi-GB service images and start a Postgres / Redis / Kafka /
service ladder — that is measured separately by the WS-A buyer
acceptance gate.

| Phase | Budget | Source of truth |
|---|---|---|
| `docker pull` of the devcontainer image | 60 s | `PHASE_PULL_BUDGET` |
| Toolchain ready (every `--version` on PATH) | 30 s | `PHASE_TOOLCHAIN_BUDGET` |
| A Docker daemon actually starts | reported, not budgeted | Phase 3, `#716` |

Phase 3 exists because Phase 2 asserted the docker *CLI* was installed, which
it is with no daemon anywhere — so a container that could never run
`pnpm aisoc:demo` passed the gate for months. Phase 3 runs the real
`start-docker.sh` under the same flags `devcontainer.json` passes, then pulls
and runs a container as the non-root user. Remove `--privileged` or the
`/var/lib/docker` volume and it fails, which is the point.

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

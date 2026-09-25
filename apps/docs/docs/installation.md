---
sidebar_position: 2
---

# One-click install

The fastest way to a running AiSOC dashboard, with **zero assumed
prerequisites**, is the bootstrap installer. It works against a
freshly-imaged machine — no Docker, Node, pnpm, git, or even Homebrew
required up front. It detects your OS, installs everything idempotently,
clones the repo, starts the CORE stack, creates the first administrator,
and then pushes one real event through the pipeline to prove the
deployment works.

If you already have Docker + Node + pnpm and you want to run the same
three commands yourself, see the [Quick start](./quickstart). If you are
deploying to production, see [Deployment options](./deployment/docker).

## TL;DR

```bash
# Linux + macOS (one-liner):
curl -fsSL https://raw.githubusercontent.com/beenuar/AiSOC/main/install.sh | bash

# Windows (PowerShell as Administrator):
iwr -useb https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 | iex
```

When the installer finishes, the CORE stack is running at
`http://localhost:3000`, an administrator exists whose generated password
was printed once during the run, and one real event has been pushed
through the pipeline and read back out of the API as an alert.

## Supported platforms

| OS | Package manager | Tested versions |
|----|-----------------|-----------------|
| Ubuntu / Debian | `apt` | 22.04, 24.04, Debian 12 |
| Fedora / RHEL / Rocky / Alma | `dnf` | Fedora 39+, RHEL 9, Rocky 9, Alma 9 |
| Arch / Manjaro | `pacman` | rolling |
| openSUSE Leap / Tumbleweed | `zypper` | 15.5+, Tumbleweed |
| Alpine | `apk` | 3.19+ |
| macOS | `brew` (auto-installed) | 13 Ventura, 14 Sonoma, 15 Sequoia (Apple Silicon + Intel) |
| Windows 10 / 11 | `winget` | Pro, Home, Enterprise |

The installer auto-detects the OS and picks the correct package manager.
Re-running is safe: every step is idempotent and short-circuits if the
target component is already installed at a sufficient version.

## What gets installed

### Linux + macOS (`install.sh`)

1.  **`git`** — required to clone the repo. Skipped if already on PATH.
2.  **Docker Engine + Docker Compose v2** (Linux) or **Docker Desktop**
    (macOS via Homebrew cask). On Linux the script enables and starts
    the `docker` service, then adds the invoking user to the `docker`
    group with a one-shot `sg docker -c …` so you don't have to log
    out and back in for the same install run.
3.  **Node.js 22 LTS** via the official NodeSource APT repo, the Fedora
    NodeJS module, the relevant native package on Arch / openSUSE /
    Alpine, or `brew install node@22` on macOS.
4.  **pnpm 8+** via `corepack enable && corepack prepare pnpm@latest`.
5.  **Homebrew** (macOS only) — bootstrapped non-interactively if it
    isn't already installed.
6.  **The AiSOC repo itself** — cloned to `$HOME/aisoc` (override with
    `AISOC_DIR=/path/to/clone`). On a re-run the installer does
    `git fetch && git pull` instead.
7.  **`pnpm install --frozen-lockfile`** at the repo root to
    materialise the workspace.
8.  **`make up`** — checks the ports, brings up the CORE stack from the
    root `docker-compose.yml`, waits for every container to report
    healthy, and creates the first administrator, printing its
    generated password once.
9.  **`make smoke`** — posts one real event to the ingest API and
    follows it through Kafka, detection, correlation and Postgres, then
    reads the resulting alert back out of the public API. If that
    fails, the install has failed, whatever the containers say.

### Windows (`install.ps1`)

1.  **`winget`** must be present (it ships with Windows 10 21H2+ and
    all Windows 11 builds; the script tells you what to install if
    your machine is older than that).
2.  **`git`** via `winget install --id Git.Git`.
3.  **WSL2** — if Docker Desktop isn't already installed, the script
    enables the `Microsoft-Windows-Subsystem-Linux` and
    `VirtualMachinePlatform` features and sets WSL2 as the default
    version. A reboot is required after WSL2 is first enabled; the
    script tells you exactly when to reboot and which command to
    re-run after sign-in.
4.  **Docker Desktop** via `winget install --id Docker.DockerDesktop`.
    The script waits for the Docker Engine socket to come up before
    proceeding.
5.  **Node.js 22 LTS** via `winget install --id OpenJS.NodeJS.LTS`.
6.  **pnpm 8+** via `corepack enable && corepack prepare pnpm@latest`.
7.  **The AiSOC repo** — cloned to `$env:USERPROFILE\aisoc` (override
    with `-CloneDir 'C:\path\to\clone'`).
8.  **`pnpm install --frozen-lockfile`**, then the same three stages
    `make up` and `make smoke` perform on Linux and macOS. Windows has
    no `make`, so `install.ps1` runs them natively — the port
    pre-check, `docker compose up -d` with a wait for every container
    to report healthy, `docker compose run --rm -T api python -m
    app.scripts.bootstrap_admin`, and the golden-pipeline runner. Same
    stack, same administrator, same proof.

## Common cases

### "I already have everything installed"

That's fine. The installer is idempotent — it detects existing
sufficient versions and skips them. The end state is the same: a running
CORE stack that has demonstrably processed an event.

### "I want to install into a different directory"

```bash
# Linux/macOS — clone to ~/work/aisoc instead of ~/aisoc:
curl -fsSL https://raw.githubusercontent.com/beenuar/AiSOC/main/install.sh -o install.sh
bash install.sh --clone-dir "$HOME/work/aisoc"
```

```powershell
# Windows — clone to D:\src\aisoc instead of $HOME\aisoc:
iwr -useb https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 -OutFile $env:TEMP\aisoc-install.ps1
& $env:TEMP\aisoc-install.ps1 -CloneDir 'D:\src\aisoc'
```

### "I want to run the script after reading it"

Recommended for production-adjacent machines. Both scripts live at the
repo root and are short enough to read in one sitting:

- [`install.sh`](https://github.com/beenuar/AiSOC/blob/main/install.sh) — Linux + macOS (~620 lines, pure POSIX-friendly bash)
- [`install.ps1`](https://github.com/beenuar/AiSOC/blob/main/install.ps1) — Windows PowerShell

```bash
curl -fsSLO https://raw.githubusercontent.com/beenuar/AiSOC/main/install.sh
less install.sh         # read it
shellcheck install.sh   # optional: confirm it's lint-clean
bash install.sh
```

```powershell
iwr -useb https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 -OutFile install.ps1
notepad install.ps1     # read it
.\install.ps1
```

### "I want to skip the launch and just install dependencies"

```bash
# Linux/macOS:
bash install.sh --no-launch

# Windows:
.\install.ps1 -NoLaunch
```

The repo is still cloned and `pnpm install` still runs, but the stack is
not started, no administrator is created and the pipeline check does not
run — so you can configure `.env` / secrets / connectors before the first
startup. Both scripts print the commands to run afterwards.

### "I want to redirect the stack to a different host or port"

Edit `.env` after the clone step. The relevant variables are documented
inline in `.env.example` and in
[Deployment → Environment variables](./deployment/env-vars).

## Uninstall

Both installers ship with a matching uninstaller, also at the repo root
(`uninstall.sh` and `uninstall.ps1`). They are graduated — by default
they only stop the stack and drop its named volumes, leaving Docker
Desktop, Node, pnpm, and the repo untouched. Pass flags to escalate.

| Action | Linux / macOS | Windows |
|--------|----------------|---------|
| Stop stack + drop volumes | `./uninstall.sh` | `.\uninstall.ps1` |
| Also remove pulled images (~3 GB) | `./uninstall.sh --images` | `.\uninstall.ps1 -Images` |
| Also delete `node_modules` | `./uninstall.sh --node-modules` | `.\uninstall.ps1 -NodeModules` |
| Also delete the repo clone | `./uninstall.sh --repo` | `.\uninstall.ps1 -Repo` |
| Everything except shared deps | `./uninstall.sh --all` | `.\uninstall.ps1 -All` |
| Skip confirmation prompts | `./uninstall.sh --all --yes` | `.\uninstall.ps1 -All -Yes` |

The uninstaller intentionally **does not** remove Docker, Docker
Desktop, Node, pnpm, Homebrew, WSL2, or git — those are general-purpose
tools that other apps on your machine likely depend on. Remove them
manually if you really want a clean wipe.

## Troubleshooting

### `curl: command not found` (fresh Alpine container)

```sh
apk add --no-cache curl bash
```

Then re-run the one-liner.

### "Cannot connect to the Docker daemon" on the first run (Linux)

The installer has just added you to the `docker` group, but the
*current shell* still uses your old group set. The installer works around
this by running its own follow-up Docker commands through `sg docker -c …`.
For your **next interactive shell** to pick up the new group, log out and
back in (or `newgrp docker`).

### "Hyper-V is not enabled" on Windows Home

Windows Home doesn't include Hyper-V; Docker Desktop relies on the
WSL2 backend instead. The installer enables WSL2 automatically and
Docker Desktop will use it. If Docker Desktop still complains, open
`Settings → General` and confirm "Use the WSL 2 based engine" is
ticked, then `wsl --update` and restart Docker Desktop.

### I can't sign in

There are no default credentials. The installer creates
`admin@aisoc.internal` with a password generated on your machine and
printed once, at the end of the run — it is stored nowhere. If the
terminal has already scrolled away, mint a new one:

```bash
make bootstrap ARGS=--reset-password
```

```powershell
docker compose run --rm -T api python -m app.scripts.bootstrap_admin --reset-password
```

### The stack is already running

Both installers are idempotent — re-running one against a healthy stack
starts nothing new and reports the administrator that already exists. To
get a fully clean start:

```bash
make clean   # stop the stack and delete all volumes
make up      # bring it back up
```

```powershell
docker compose down -v
.\install.ps1 -NoInstall
```

### Anything else

The [troubleshooting page](./operations/troubleshooting) has runbooks
for the most common stack-level failure modes (healthchecks red,
Postgres OOM, Kafka cluster-id drift, …). For installer-specific bugs,
file an issue with the installer's full output —
[github.com/beenuar/AiSOC/issues](https://github.com/beenuar/AiSOC/issues).

## Security notes

- Both installers run as **your user**, not root. They invoke `sudo`
  only for package-manager calls on Linux. macOS Homebrew prompts for
  a password the first time it touches `/opt/homebrew` or `/usr/local`.
- The Linux script does **not** disable SELinux, AppArmor, or your
  firewall. The stack binds only to `127.0.0.1`, so nothing is exposed
  to your LAN by default.
- The Windows script enables WSL2 and starts Docker Desktop. It does
  **not** join AD, change Defender settings, or reconfigure Windows
  Update.
- The Docker images pulled by the demo
  (`ghcr.io/beenuar/aisoc-*`) are signed with [Cosign](https://docs.sigstore.dev/cosign/overview/);
  the [Docker deployment page](./deployment/docker#image-provenance)
  documents the signature verification workflow.
- The demo seeds **synthetic data only**. No real customer data, IOCs,
  or telemetry is shipped with the installer.
- The repo is cloned over HTTPS from `github.com/beenuar/AiSOC` —
  there is no opaque "phone home" URL involved.

## What's next

- [Quick start](./quickstart) — the underlying `make up` / `make smoke` flow + full developer stack
- [Architecture](./architecture) — how the services in the demo wire together
- [Connect your first source](./connectors) — point AiSOC at a real EDR / SIEM / cloud
- [Operations: Credentials](./operations/credentials) — credential vault key & rotation
- [Deploy to Kubernetes](./deployment/kubernetes) — production install via Helm

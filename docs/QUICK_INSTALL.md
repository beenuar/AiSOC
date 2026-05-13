# Quick install — zero-prerequisite bootstrap

AiSOC ships with two one-click bootstrap installers. They take a freshly-imaged
machine to a running AiSOC dashboard in your browser, with **zero assumed
prerequisites**, in a single command.

If you already have Docker, Node 20, pnpm 8+, and git installed, you don't need
these scripts — just run `pnpm aisoc:demo` from a clone. These installers exist
for the case where you don't (or you're handing the repo to someone who
doesn't).

## TL;DR

### Linux + macOS

```bash
curl -fsSL https://raw.githubusercontent.com/beenuar/AiSOC/main/install.sh | bash
```

### Windows 10 / 11

Open PowerShell **as Administrator** and run:

```powershell
iwr -useb https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 | iex
```

When the script finishes, your default browser opens at
`http://localhost:3000/cases/INC-RT-001?tab=ledger` with `demo@aisoc.dev`
already auto-logged-in and a real LockBit 3.0 investigation mid-flight.

## What gets installed

The installer is **surgical**. It installs only the four things AiSOC actually
needs, and only if they are missing or too old:

| Tool                   | Linux / macOS source              | Windows source         | Why                              |
| ---------------------- | --------------------------------- | ---------------------- | -------------------------------- |
| `git`                  | distro package manager            | `winget Git.Git`       | clone the repo                   |
| Docker Engine + Compose v2 | distro package manager (Linux), `brew install --cask docker` (macOS) | `winget Docker.DockerDesktop` (+ WSL2) | run the AiSOC stack |
| Node.js 20 LTS         | NodeSource (Linux), `brew` (macOS) | `winget OpenJS.NodeJS.LTS` | drive `pnpm aisoc:demo` |
| pnpm 8+                | `corepack enable` + `corepack prepare pnpm@latest` | same                  | install Node deps                |

**It does not install:** Python, Go, Rust, Postgres, Redis, Kafka,
ClickHouse, OpenSearch, Neo4j, Qdrant, or anything else. Those run inside
Docker containers via `pnpm aisoc:demo`, never on your host.

**It does not modify:** your dotfiles, your shell init, your existing Docker
installation, your existing Node installation, or any system packages outside
the four above.

## Supported environments

### Linux

| Distro | Package manager | Tested |
| --- | --- | --- |
| Ubuntu 22.04 / 24.04 | `apt` | ✅ |
| Debian 12+ | `apt` | ✅ |
| Fedora 39+ | `dnf` | ✅ |
| RHEL 9+ / Rocky / AlmaLinux | `dnf` | ✅ |
| Arch / Manjaro | `pacman` | ✅ |
| openSUSE Tumbleweed / Leap | `zypper` | ✅ |
| Alpine 3.18+ | `apk` | ✅ |

### macOS

| Version | Notes |
| --- | --- |
| macOS 12+ (Monterey or newer) | Apple Silicon and Intel both supported |

The macOS installer uses Homebrew. If `brew` is missing, the installer
bootstraps it for you.

### Windows

| Version | Notes |
| --- | --- |
| Windows 10 (build 19041+) | Required for WSL2 |
| Windows 11 | All editions |

The Windows installer uses `winget`. If `winget` is missing, the installer
points you at the App Installer in the Microsoft Store rather than trying to
hack around it (Microsoft updates `winget` itself through that channel).

After Docker Desktop installs you may need to log out / log back in once for
the `docker` group to take effect.

## Flags

### `install.sh` (Linux + macOS)

```text
--no-install        Skip the dependency-install phase (use what's on PATH).
--no-launch         Set everything up but don't run pnpm aisoc:demo at the end.
--no-pull           Forwarded to aisoc:demo to skip image pull.
--rebuild           Forwarded to aisoc:demo to build images from source.
--clone-dir DIR     Where to clone the repo when running as a one-liner.
                    Default: $HOME/aisoc
--branch BR         Git branch to clone. Default: main.
--skip-preflight    Skip the up-front environment checks and dive straight in.
                    Use only if you know your machine is fine and preflight is
                    misdiagnosing it.
--diagnose          Run preflight only and exit. No installs, no clone, no
                    Docker pulls. For "is this machine going to make it?"
                    triage before committing to a full install.
--non-interactive   Never prompt the user. Implied when stdin isn't a TTY
                    (e.g. CI, curl|bash). Pairs cleanly with --diagnose for
                    automated checks.
--help              Show this text and exit.
```

### `install.ps1` (Windows)

```text
-NoInstall          Skip the dependency-install phase.
-NoLaunch           Set everything up but don't run pnpm aisoc:demo.
-NoPull             Forwarded to aisoc:demo.
-Rebuild            Forwarded to aisoc:demo.
-CloneDir PATH      Where to clone. Default: $env:USERPROFILE\aisoc
-Branch NAME        Git branch. Default: main.
-SkipPreflight      Skip the up-front environment checks.
-Diagnose           Run preflight only and exit (no installs, no clone).
-NonInteractive     Never prompt. Implied in CI and over remote PowerShell.
                    On Windows, fresh Docker Desktop installs require an
                    interactive first-run, so -NonInteractive will refuse
                    to install Docker and instead instruct you to do it
                    manually before re-running.
```

### Exit codes

Both installers use these exit codes consistently. Useful if you're wiring
the installer into CI or wrapping it in a deployment script:

| Code | Meaning |
| --- | --- |
| `0` | Success. Stack is up (or, in `--diagnose` mode, preflight passed). |
| `1` | Generic / unhandled error. The friendly error trap should have printed a hint right above the failure. |
| `2` | Bad arguments. Usually a typo'd flag. |
| `3` | Refused for safety. Currently only the uninstaller emits this — it means the script declined to delete a path it didn't trust. |
| `4` | Preflight found a blocking issue. Re-run with `--skip-preflight` to override, or fix the items the preflight banner flagged. |
| `5` | `git clone` failed after retries. Usually network — check your proxy, or pre-clone the repo and re-run from inside it. |

## Preflight: the "will this work?" check

Before either installer touches your machine, it runs a **preflight** pass
that checks the things most likely to make AiSOC unhappy after install:

- **CPU architecture** — must be x86_64 / amd64 / arm64. (32-bit ARM, MIPS,
  RISC-V etc. won't work; the Docker images aren't built for them.)
- **RAM** — at least 4 GB free. AiSOC runs ~10 containers; less than 4 GB
  and Postgres or OpenSearch will OOM mid-investigation.
- **Disk** — at least 10 GB free in the install target.
- **Network** — can resolve and reach `github.com`, `ghcr.io`, and the
  appropriate package registry (`registry.npmjs.org`, `apt`/`dnf`/`brew`
  repos, etc.). Catches corp-proxy / firewall issues before you waste 10
  minutes pulling Docker images.
- **Ports** — checks that the ports AiSOC binds to (`3000`, `5432`, `6379`,
  `8000`, `8001`, `8086`, `9092`) are either free or already owned by an
  AiSOC container. If port 3000 is taken by another `next-server`, you'll
  see it in preflight rather than in a confusing demo crash later.
- **macOS Docker Desktop memory budget** — checks Docker Desktop has at
  least 4 GB allocated, and tells you exactly which menu to open if not.
- **Windows version + WSL2** — checks you're on a build new enough to
  install Docker Desktop, and that Hyper-V / Virtual Machine Platform are
  available.

Run `./install.sh --diagnose` (Linux/macOS) or `.\install.ps1 -Diagnose`
(Windows) to see the report without installing anything. It's safe to run
on a production machine — preflight is read-only.

If preflight reports a problem you've decided to ignore (for example, port
3000 is in use by a dev server you'll kill before launch), use
`--skip-preflight` / `-SkipPreflight` to bypass the gate.

## Common cases

**I already have Docker / Node / pnpm.** The installer detects them, prints
their versions, and skips reinstalling. Re-running the script is always safe.

**I want to install dependencies but not start the stack yet.**
`./install.sh --no-launch` (Linux/macOS) or `.\install.ps1 -NoLaunch` (Windows).

**I want to use a fork or branch.** `./install.sh --branch my-feature` will
clone that branch instead of `main`.

**I want to put the clone somewhere specific.** `./install.sh --clone-dir
~/code/aisoc` (default is `$HOME/aisoc`).

**I want to build images from source instead of pulling from GHCR.**
`./install.sh --rebuild` forwards `--rebuild` to `pnpm aisoc:demo`. This is
slower (~10-15 min cold) but lets you run an unreleased branch without waiting
for image publishing.

## Uninstalling

Both platforms have a graduated uninstaller that is **just as surgical as the
installer**. It will not remove Docker, Node, pnpm, or git, since those are
general-purpose tools you almost certainly use for other projects.

### Linux + macOS

```bash
./uninstall.sh                  # stop the demo stack, drop volumes
./uninstall.sh --images         # also remove ghcr.io/beenuar/aisoc-* images
./uninstall.sh --node-modules   # also delete node_modules trees
./uninstall.sh --repo           # also delete the repo clone
./uninstall.sh --all            # all of the above
./uninstall.sh --all --yes      # all of the above, no prompts
```

### Windows

```powershell
.\uninstall.ps1                 # stop the demo stack, drop volumes
.\uninstall.ps1 -Images         # also remove ghcr.io/beenuar/aisoc-* images
.\uninstall.ps1 -NodeModules    # also delete node_modules trees
.\uninstall.ps1 -Repo           # also delete the repo clone
.\uninstall.ps1 -All            # all of the above
.\uninstall.ps1 -All -Yes       # all of the above, no prompts
```

If you really want to uninstall Docker / Node / pnpm / git too, use your OS's
package manager directly:

```bash
# Ubuntu / Debian
sudo apt-get remove docker-ce docker-ce-cli containerd.io nodejs git

# Fedora / RHEL
sudo dnf remove docker-ce docker-ce-cli containerd.io nodejs git

# Arch
sudo pacman -R docker nodejs git

# macOS
brew uninstall --cask docker
brew uninstall node git
```

```powershell
# Windows
winget uninstall Docker.DockerDesktop
winget uninstall OpenJS.NodeJS.LTS
winget uninstall Git.Git
```

## Troubleshooting

### Preflight failed — what now?

`./install.sh --diagnose` (or `-Diagnose` on Windows) is the same engine
that runs at the top of every install. The output groups findings into
**FAIL** (will block install) and **WARN** (won't block, but worth knowing).
The lines below the finding tell you exactly what to do — there are no
"see logs for details" cliffhangers.

If you're sure preflight is wrong (e.g. it can't reach `ghcr.io` because
your corporate proxy intercepts TLS), you can pass `--skip-preflight` /
`-SkipPreflight` to bypass the gate. The installer will still try to do
its job; you'll just lose the early warning.

### Port conflicts

[port-conflicts]: # "Anchored from preflight output"

<a id="port-conflicts"></a>

AiSOC binds these host ports by default:

| Port | Container | Override env var |
| --- | --- | --- |
| `3000` | `aisoc-web` (Next.js dashboard) | `AISOC_WEB_PORT` |
| `5432` | `aisoc-postgres` | `AISOC_POSTGRES_PORT` |
| `6379` | `aisoc-redis` | `AISOC_REDIS_PORT` |
| `8000` | `aisoc-api` (FastAPI) | `AISOC_API_PORT` |
| `8001` | `aisoc-realtime` (WebSocket fan-out) | `AISOC_REALTIME_PORT` |
| `8086` | `aisoc-influx` (telemetry sink) | `AISOC_INFLUX_PORT` |
| `9092` | `aisoc-kafka` | `AISOC_KAFKA_PORT` |

If preflight flags one of these as in use:

1. Find what's holding it:
   - Linux/macOS: `lsof -nP -iTCP:3000 -sTCP:LISTEN`
   - Windows: `Get-NetTCPConnection -LocalPort 3000 | Select OwningProcess; Get-Process -Id <pid>`
2. Either stop that process, or set the matching `AISOC_*_PORT` env var
   in `.env` (or in your shell) and re-run `pnpm aisoc:demo`.

Preflight only **warns** if a port is taken by a process that looks like
an existing AiSOC container — re-running the installer on a machine that
already has the demo running won't fail preflight.

### Linux: "permission denied" talking to Docker

The installer adds you to the `docker` group, but the new membership only
takes effect for new shells. The installer works around this for the same
session by piping `pnpm aisoc:demo` through `sg docker -c`. If you open a
fresh terminal afterwards and still see the error, log out and back in (or
reboot) to pick up the new group.

### Linux: `systemctl start docker` fails on a container / WSL host

Docker Engine wants a real init system. If you're inside an unprivileged
container or a vanilla WSL distro, install Docker Desktop on the host instead
and use the host's Docker daemon. The Linux installer is for bare-metal /
VM Linux hosts.

### macOS: Docker Desktop won't start

Open Docker Desktop manually once. The first launch needs to grant the
"privileged helper" prompt — that requires a UI click that the installer
can't automate. After that, Docker Desktop autostarts on subsequent boots
and the installer hand-off works.

### macOS: preflight says "Docker Desktop appears installed but the daemon isn't running"

This is the friendly version of the old "Docker Desktop is allocated only
0 MB of RAM" message. It just means Docker Desktop hasn't booted yet.

`install.sh` will launch Docker Desktop for you and wait up to 90 seconds
for the daemon to come up. If you're running `--diagnose`, open Docker
Desktop yourself (or run `open -a Docker`) and re-run.

### Windows: `-NonInteractive` refused to install Docker Desktop

Docker Desktop's first-time setup requires UI clicks (accept the EULA,
grant the WSL update prompt, etc.) that the installer can't drive
automatically. In `-NonInteractive` mode (which is also auto-detected in
CI and remote PowerShell), the installer refuses rather than hanging
forever waiting for a button press.

The fix is to install Docker Desktop manually one time:

```powershell
winget install --id Docker.DockerDesktop --silent --accept-package-agreements --accept-source-agreements
# then open Docker Desktop, click through the first-run prompts,
# wait for the whale icon to go solid, then re-run the installer.
```

After Docker Desktop has been provisioned once, `-NonInteractive` works
fine for everything else.

### Windows: WSL is missing in `-NonInteractive` mode

Same shape as the Docker Desktop case — installing WSL requires a reboot
and elevated UAC, neither of which the installer can do non-interactively.
Open an elevated PowerShell and run:

```powershell
wsl --install
```

Reboot, then re-run the installer.

### Windows: WSL2 was just enabled — why do I have to reboot?

Enabling WSL2 changes a Windows Feature, which requires a kernel reboot.
The installer prints a clear "REBOOT REQUIRED" message, you reboot, and
re-running the installer picks up where it left off (it's idempotent).

### Windows: Docker Desktop says "WSL update required"

```powershell
wsl --update
```

then re-run the installer.

### Browser doesn't open

The installer launches your browser via `xdg-open` (Linux), `open` (macOS),
or `Start-Process` (Windows). If your environment doesn't have a browser
configured (e.g. SSH session, headless CI), open
`http://localhost:3000/cases/INC-RT-001?tab=ledger` in any browser on the
host yourself.

### `pnpm aisoc:demo` fails after a successful install

Run `pnpm aisoc:doctor` from inside the clone — it pinpoints which container
or port is unhealthy. Common causes:

- One of the bound ports is already in use → see
  [Port conflicts](#port-conflicts) above for the table of ports and
  the env vars to change them.
- Docker daemon out of disk → `docker system prune -a` and retry.
- Corporate proxy blocking `ghcr.io` → either configure Docker's
  HTTP proxy or run `./install.sh --rebuild` to build from source.

If `aisoc:demo` finishes "successfully" but no browser opens, that's
usually an `AISOC_NO_BROWSER=1` env var leaking from a previous CI run, or
a headless environment (SSH session, no `$DISPLAY`). The URL is printed in
the final banner — open it manually.

## Security notes

These installers run with **the privileges they need to install system
packages** — that means `sudo` on Linux/macOS and Administrator on Windows.

If you're piping `curl | bash` from the internet, you're trusting that:

1. The script at `https://raw.githubusercontent.com/beenuar/AiSOC/main/install.sh`
   matches the script in this repo (you can inspect the source link).
2. GitHub's TLS hasn't been MITM-ed.
3. The repo's owner hasn't been compromised.

If any of those make you uneasy, the alternative is to clone first and
inspect the script before running:

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
less install.sh        # or your editor of choice
./install.sh
```

The script does nothing the README couldn't tell you to do by hand. Reading
through it is encouraged.

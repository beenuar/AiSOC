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
--no-install     Skip the dependency-install phase (use what's on PATH).
--no-launch      Set everything up but don't run pnpm aisoc:demo at the end.
--no-pull        Forwarded to aisoc:demo to skip image pull.
--rebuild        Forwarded to aisoc:demo to build images from source.
--clone-dir DIR  Where to clone the repo when running as a one-liner.
                 Default: $HOME/aisoc
--branch BR      Git branch to clone. Default: main.
--help           Show this text and exit.
```

### `install.ps1` (Windows)

```text
-NoInstall       Skip the dependency-install phase.
-NoLaunch        Set everything up but don't run pnpm aisoc:demo.
-NoPull          Forwarded to aisoc:demo.
-Rebuild         Forwarded to aisoc:demo.
-CloneDir PATH   Where to clone. Default: $env:USERPROFILE\aisoc
-Branch NAME     Git branch. Default: main.
```

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

- Port 3000, 5432, 6379, or 9092 already in use → free them or set
  `AISOC_WEB_PORT=3001` in `.env` and re-run `pnpm aisoc:demo`.
- Docker daemon out of disk → `docker system prune -a` and retry.
- Corporate proxy blocking `ghcr.io` → either configure Docker's
  HTTP proxy or run `./install.sh --rebuild` to build from source.

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

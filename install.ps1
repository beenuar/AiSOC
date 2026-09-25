<#
.SYNOPSIS
    AiSOC — One-Click Installer for Windows.

.DESCRIPTION
    Bootstraps a freshly-imaged Windows 10/11 machine to a running AiSOC
    dashboard in a single command. Zero assumed prerequisites.

    What this script does, in order:
        1. Verifies you're on Windows 10 (build 19041+) or Windows 11.
        2. Verifies WSL2 is enabled (required by Docker Desktop).
        3. Installs (idempotently) the four prerequisites AiSOC needs:
             - Git
             - Docker Desktop (which bundles Docker Engine + Compose v2)
             - Node.js 22 LTS
             - pnpm 8+ (via corepack)
           All installs go through winget, the official Windows package
           manager. We never download random installers from the internet.
        4. Clones the AiSOC repo (if you ran the script as a one-liner) or
           reuses it (if you ran .\install.ps1 from inside a clone).
        5. Creates a .env from .env.example so the first boot has sane
           defaults.
        6. Runs `pnpm install --frozen-lockfile` to fetch the workspace's
           Node deps.
        7. Starts the CORE stack with `docker compose up -d` and waits for
           every container to report healthy.
        8. Creates the first administrator and prints its generated password
           once.
        9. Pushes one real event through the pipeline and verifies it comes
           back out of the API as an alert.

    Steps 7-9 are what `make up` and `make smoke` do on Linux and macOS.
    They are re-implemented here rather than invoked because Windows has no
    `make`, and the Makefile's recipes are POSIX shell (`seq`, `awk`,
    `./scripts/doctor.sh`) that GNU Make on Windows would hand to cmd.exe.
    The commands underneath are identical — `docker compose up -d`,
    `docker compose run --rm -T api python -m app.scripts.bootstrap_admin`,
    `python tests/e2e/golden_pipeline/run_golden_pipeline.py` — so the two
    installers start the same stack and prove it the same way. Anything that
    changes in the Makefile's `up`, `bootstrap` or `smoke` targets has to
    change here too; `tests/test_installer_parity_gate.py` fails the build
    if it does not.

    What this script does NOT do is hand off to `pnpm aisoc:demo`. That
    starts a different compose file with no ingest service, no fusion
    service and Kafka disabled, whose only content is a seed script writing
    rows straight into Postgres. It is a UI preview, not a deployment, and
    an evaluator who saw a populated console there would conclude the
    platform worked without ever having run it.

.PARAMETER NoInstall
    Skip the dependency-install phase (use what's on PATH).

.PARAMETER NoLaunch
    Set everything up but don't start the stack, create the administrator
    or run the pipeline check.

.PARAMETER NoPull
    Accepted for backwards compatibility and ignored with a warning.
    `docker compose up -d` only pulls images it does not already have, so
    there is no pull step left to skip.

.PARAMETER Rebuild
    Build the service images from source instead of using the published
    ones (`docker compose up -d --build`).

.PARAMETER CloneDir
    Where to clone the repo when running as a one-liner. Default:
    $env:USERPROFILE\aisoc.

.PARAMETER Branch
    Git branch to clone. Default: main.

.PARAMETER SkipPreflight
    Skip the preflight checks (RAM, disk, network, ports, WSL2, Docker reach).
    Use only if you know exactly what you're doing — preflight catches >80%
    of "doesn't work for me" reports.

.PARAMETER Diagnose
    Run preflight checks and exit. No installs, no demo. Useful for triaging
    a half-broken machine without committing to a full install.

.PARAMETER NonInteractive
    Don't prompt for anything; refuse to do any step that needs user input
    (e.g. accepting Docker Desktop's EULA on first launch). Auto-enabled
    when stdin is redirected (iwr | iex) or when $env:CI is set.

.EXAMPLE
    # One-liner from PowerShell (run as your normal user, not Administrator —
    # winget will elevate per-package as needed):
    iwr -useb https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 | iex

.EXAMPLE
    # From inside a clone:
    .\install.ps1

.EXAMPLE
    # Custom clone directory and skip the launch:
    .\install.ps1 -CloneDir D:\code\aisoc -NoLaunch

.NOTES
    Exit codes (the same set install.sh uses, for the same conditions):
        0  success — the stack is up and a real event reached the API
        1  prerequisite install failed
        2  Docker Desktop refused to come up / WSL2 not enabled
        3  the stack did not start, or a container never became healthy
        4  preflight checks failed (machine doesn't meet minimums)
        5  git clone failed (network / branch / disk), or the pipeline
           check failed — the stack started but no event became an alert

    Tested on:
        - Windows 11 23H2 (x64 + ARM64)
        - Windows 10 22H2 (x64)
        - Windows Server 2022 (x64; you must install Docker Desktop manually
          on Server SKUs — winget can't, server doesn't have the Store)

    The script is safe to re-run. Each install step checks "is this already
    present and the right version?" before doing anything.

.LINK
    https://github.com/beenuar/AiSOC
#>

[CmdletBinding()]
param(
    [switch]$NoInstall,
    [switch]$NoLaunch,
    [switch]$NoPull,
    [switch]$Rebuild,
    [switch]$SkipPreflight,
    [switch]$Diagnose,
    [switch]$NonInteractive,
    [string]$CloneDir = (Join-Path $env:USERPROFILE 'aisoc'),
    [string]$Branch = 'main'
)

# Strict mode catches typos in variable names — really easy to do in a long
# script and PowerShell silently substitutes $null otherwise.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Auto-detect non-interactive contexts. The classic case is `iwr | iex` from
# a CI runner — there's no terminal to prompt at, and any Read-Host or winget
# UAC dialog would silently hang the pipeline.
if (-not $NonInteractive) {
    if ([Console]::IsInputRedirected -or $env:CI -eq 'true' -or $env:CI -eq '1') {
        $NonInteractive = $true
    }
}

# ─── Logging helpers ──────────────────────────────────────────────────────
# Write-Host with -ForegroundColor is safe even when stdout is redirected —
# PowerShell strips ANSI codes for non-console hosts. So we don't need a
# UseColor flag; the runtime DTRT.

function Write-Log    { param([string]$Msg) Write-Host "[aisoc] $Msg" -ForegroundColor DarkGray }
function Write-Info   { param([string]$Msg) Write-Host "[aisoc] $Msg" -ForegroundColor Blue }
function Write-Ok     { param([string]$Msg) Write-Host "[aisoc] $Msg" -ForegroundColor Green }
function Write-Warn   { param([string]$Msg) Write-Warning "[aisoc] $Msg" }
function Write-Err    { param([string]$Msg) Write-Host "[aisoc] $Msg" -ForegroundColor Red }
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('━━━ {0} ━━━' -f $Title) -ForegroundColor Cyan
    Write-Host ''
}

function Stop-WithError {
    param([string]$Msg, [int]$Code = 1)
    Write-Err $Msg
    exit $Code
}

# ─── Windows version + arch sanity check ──────────────────────────────────
# Docker Desktop requires:
#   - Windows 10 64-bit Pro/Enterprise/Education build 19041+, OR
#   - Windows 10/11 Home build 19041+ with WSL2 backend, OR
#   - Windows 11.
# We don't fully discriminate Pro vs Home — if WSL2 is available, the user
# is fine regardless of edition.

function Test-WindowsVersion {
    Write-Section 'Windows version check'
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build = [int]($os.BuildNumber)
    Write-Info "OS: $($os.Caption) (build $build, $env:PROCESSOR_ARCHITECTURE)"
    if ($build -lt 19041) {
        Stop-WithError "AiSOC requires Windows 10 build 19041 (May 2020 update) or newer. Your build is $build. Update Windows and re-run."
    }
    Write-Ok "Windows version supported."
}

# ─── WSL2 check ───────────────────────────────────────────────────────────
# Docker Desktop's recommended (and on Home, only) backend is WSL2. If WSL2
# isn't enabled, Docker Desktop install will succeed but the daemon won't
# start. We catch this up-front so users don't waste 10 minutes on a 1 GB
# Docker Desktop download only to be told to enable WSL2 afterwards.

function Test-WSL2 {
    Write-Section 'WSL2 check'
    $hasWsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $hasWsl) {
        if ($NonInteractive) {
            # `wsl --install` needs admin, can't be silenced, and forces a
            # reboot. None of those work in CI / iwr|iex pipelines.
            Stop-WithError @"
WSL is not installed and we're running non-interactively.
WSL installation requires administrator privileges and a reboot.

Please run the following from an elevated PowerShell, reboot, then re-run
this installer interactively:

  wsl --install
"@ 2
        }
        Write-Warn "WSL is not installed. Installing now (this requires admin and a reboot)..."
        Write-Info "Running: wsl --install --no-launch"
        & wsl.exe --install --no-launch
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "wsl --install failed (exit $LASTEXITCODE). Run an elevated PowerShell and try: wsl --install" 2
        }
        Write-Warn "WSL2 was installed but Windows must reboot before Docker Desktop can use it."
        Write-Warn "Reboot now, then re-run this installer."
        exit 0
    }
    # `wsl --status` returns nonzero if WSL is installed but no distros are
    # registered — that's fine for Docker Desktop, which ships its own
    # docker-desktop distro. We only fail if WSL itself is broken.
    $statusOutput = & wsl.exe --status 2>&1
    if ($LASTEXITCODE -ne 0 -and $statusOutput -match 'WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED') {
        if ($NonInteractive) {
            Stop-WithError @"
WSL needs the 'Virtual Machine Platform' Windows feature, which requires
admin + reboot to enable. Run the following from an elevated PowerShell,
reboot, then re-run this installer interactively:

  Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All
"@ 2
        }
        Write-Warn "WSL needs the Virtual Machine Platform Windows feature."
        Write-Info "Enabling Virtual Machine Platform (you may need to reboot)..."
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Stop-WithError "Virtual Machine Platform enabled. Reboot Windows and re-run this installer." 2
    }
    Write-Ok "WSL is available."
}

# ─── winget bootstrap ─────────────────────────────────────────────────────
# winget ships with App Installer on Windows 11 and on Windows 10 with the
# October 2023 cumulative update. If it's missing we ask the user to install
# App Installer from the Microsoft Store — we don't try to side-load it
# because that requires manual MSIX-bundle downloads from GitHub Releases
# and is brittle.

function Test-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $ver = (& winget --version) -replace '^v',''
        Write-Ok "winget available: v$ver"
        return $true
    }
    Write-Err "winget (Windows Package Manager) is not installed."
    Write-Err ""
    Write-Err "Please install 'App Installer' from the Microsoft Store, then re-run this script:"
    Write-Err "  https://apps.microsoft.com/detail/9NBLGGH4NNS1"
    Write-Err ""
    Write-Err "Alternatively, install winget manually from:"
    Write-Err "  https://github.com/microsoft/winget-cli/releases"
    return $false
}

# ─── Generic version helpers ──────────────────────────────────────────────

function Test-CommandExists {
    param([string]$Name)
    [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-CommandMajorVersion {
    param([string]$Name, [string]$VersionFlag = '--version')
    if (-not (Test-CommandExists $Name)) { return $null }
    try {
        $out = & $Name $VersionFlag 2>&1 | Select-Object -First 1
        if ($out -match '(\d+)(\.\d+)*') {
            return [int]$Matches[1]
        }
    } catch {
        # Some tools (looking at you, docker on a stopped daemon) error out
        # rather than print a version. Treat that as "version unknown".
        return $null
    }
    return $null
}

# Wrapper around winget install that tolerates the "already installed" exit
# code (-1978335189 / 0x8A150019) and forces silent install where supported.
function Install-WingetPackage {
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$DisplayName = $null
    )
    if (-not $DisplayName) { $DisplayName = $Id }
    Write-Info "Installing $DisplayName via winget (id: $Id)..."

    # Heads-up for the iwr|iex crowd: winget triggers UAC for installers that
    # need elevation. There's no clean way to detect that ahead of time, but
    # we can at least warn so the user knows to look for the prompt.
    if ($NonInteractive) {
        Write-Warn "winget may trigger a UAC elevation prompt for $DisplayName."
        Write-Warn "If running unattended, the script will hang here until UAC is acknowledged."
    }

    # NOTE: don't name this `$args` — that's a PowerShell automatic variable
    # for unbound positional args and shadowing it triggers StrictMode warnings.
    $wingetArgs = @(
        'install',
        '--id', $Id,
        '--exact',                   # match Id exactly, no fuzzy suggestions
        '--silent',                  # suppress installer UI where supported
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--source', 'winget'         # pin to the official source, not msstore
    )
    $proc = Start-Process -FilePath 'winget' -ArgumentList $wingetArgs -Wait -PassThru -NoNewWindow
    switch ($proc.ExitCode) {
        0 { Write-Ok "$DisplayName installed." }
        -1978335189 { Write-Ok "$DisplayName already installed (winget said no upgrade needed)." }  # APPINSTALLER_CLI_ERROR_NO_APPLICABLE_INSTALLER
        -1978335212 { Write-Ok "$DisplayName already installed." }                                  # APPINSTALLER_CLI_ERROR_PACKAGE_ALREADY_INSTALLED
        default {
            Stop-WithError "winget install $Id failed with exit code $($proc.ExitCode)."
        }
    }
    # winget mutates PATH for *new* shells but the current session doesn't
    # see the change. Refresh PATH from the registry so the next command
    # we try to run finds the freshly-installed binary.
    Update-PathFromRegistry
}

# Reload the current process PATH from the User and Machine registry hives.
# Without this, immediately after `winget install Git.Git` the `git` command
# is still "not found" in this session, even though every new terminal sees
# it. This is the single biggest gotcha when scripting winget.
function Update-PathFromRegistry {
    $machine = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user    = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = ($machine, $user -join ';') -replace ';;', ';'
}

# ─── Preflight integration ────────────────────────────────────────────────
# preflight.ps1 lives at scripts\install\preflight.ps1 in the repo. When
# the user runs install.ps1 from inside a clone, we source it directly.
# When they ran the one-liner (`iwr | iex`), $PSScriptRoot is empty and
# we have no clone yet, so we fetch preflight.ps1 from the same branch
# we're going to clone shortly and dot-source it from a temp file.

function Invoke-Preflight {
    if ($SkipPreflight) {
        Write-Warn "Skipping preflight checks (--SkipPreflight given)."
        return
    }

    Write-Section 'Preflight checks'

    $preflightLocal = $null
    if ($PSScriptRoot) {
        $candidate = Join-Path $PSScriptRoot 'scripts\install\preflight.ps1'
        if (Test-Path $candidate) {
            $preflightLocal = $candidate
        }
    }

    if (-not $preflightLocal) {
        # We're running as a one-liner. Fetch preflight.ps1 from the same
        # branch we're about to clone. We use a temp file rather than
        # `iex (iwr ...)` because dot-sourcing is cleaner and the file
        # has multiple functions we want in scope.
        $url = "https://raw.githubusercontent.com/beenuar/AiSOC/$Branch/scripts/install/preflight.ps1"
        $preflightLocal = Join-Path $env:TEMP "aisoc-preflight-$([guid]::NewGuid().ToString('N')).ps1"
        Write-Info "Fetching preflight.ps1 from $url ..."
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $preflightLocal -ErrorAction Stop
        } catch {
            Write-Warn "Could not fetch preflight.ps1: $($_.Exception.Message)"
            Write-Warn "Continuing without preflight (re-run with -SkipPreflight to suppress this warning)."
            return
        }
    }

    # Dot-source so its functions land in our scope.
    try {
        . $preflightLocal
    } catch {
        Write-Warn "Failed to load preflight library: $($_.Exception.Message)"
        Write-Warn "Continuing without preflight."
        return
    }

    if (-not (Get-Command -Name 'Invoke-AiSOCPreflight' -ErrorAction SilentlyContinue)) {
        Write-Warn "preflight.ps1 loaded but didn't expose Invoke-AiSOCPreflight; skipping."
        return
    }

    try {
        $ok = Invoke-AiSOCPreflight
    } catch {
        Write-Err "Preflight crashed: $($_.Exception.Message)"
        Stop-WithError "Preflight could not complete. Re-run with -SkipPreflight to bypass at your own risk." 4
    }

    if (-not $ok) {
        Stop-WithError "Preflight failed. Fix the issues above and re-run, or pass -SkipPreflight to override." 4
    }
}

# ─── Step 1: Git ──────────────────────────────────────────────────────────

function Install-Git {
    if (Test-CommandExists git) {
        Write-Ok "git already installed: $((& git --version))"
        return
    }
    Install-WingetPackage -Id 'Git.Git' -DisplayName 'Git for Windows'
    if (-not (Test-CommandExists git)) {
        Stop-WithError "git was installed via winget but isn't on PATH. Open a new PowerShell window and re-run this script."
    }
    Write-Ok "git installed: $((& git --version))"
}

# ─── Step 2: Docker Desktop ───────────────────────────────────────────────
# Docker Desktop on Windows is huge (~ 1 GB download + ~ 4 GB on disk after
# WSL2 distro provisioning). The first launch also requires the user to
# accept the licence agreement and lets Docker provision its WSL2 distro.
# We can install silently but we cannot complete first-run setup
# headlessly — the user has to launch Docker Desktop once.

function Install-Docker {
    if ((Test-CommandExists docker) -and ((& docker compose version) 2>$null)) {
        Write-Ok "docker + compose v2 already installed: $((& docker --version))"
        Test-DockerDaemon
        return
    }

    if ($NonInteractive) {
        # Docker Desktop's first-run flow is interactive (EULA + WSL2 prompt).
        # Refusing to install in non-interactive mode is much safer than
        # silently installing a Docker that the user can't actually start.
        Stop-WithError @"
Docker Desktop is not installed and we're running non-interactively.
Docker Desktop's first run requires accepting an EULA from a UI, which can't
happen in this context.

Please either:
  1. Install Docker Desktop manually from https://docker.com/products/docker-desktop
     and re-run this installer, OR
  2. Re-run this installer from an interactive PowerShell window:
       irm https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 | iex
"@ 2
    }

    Install-WingetPackage -Id 'Docker.DockerDesktop' -DisplayName 'Docker Desktop'

    # Docker Desktop install puts docker.exe at:
    #   C:\Program Files\Docker\Docker\resources\bin\docker.exe
    # That dir is on the system PATH after a reboot but might not be in
    # *this* session even after Update-PathFromRegistry. Add it manually
    # if needed.
    $dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
    if ((Test-Path $dockerBin) -and ($env:Path -notlike "*$dockerBin*")) {
        $env:Path += ";$dockerBin"
    }

    if (-not (Test-CommandExists docker)) {
        Write-Warn "docker installed but isn't on PATH yet. You may need to:"
        Write-Warn "  1. Reboot Windows."
        Write-Warn "  2. Open a new PowerShell window."
        Write-Warn "  3. Re-run this installer."
        exit 2
    }
    Write-Ok "docker installed: $((& docker --version))"

    # Try to start Docker Desktop. The shortcut path is consistent across
    # versions. Start-Process is fire-and-forget; the actual daemon takes
    # 30-90 s more to come up on the first run because the WSL2 distro
    # has to be created.
    $dockerDesktop = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktop) {
        Write-Info "Launching Docker Desktop..."
        Start-Process -FilePath $dockerDesktop -ErrorAction SilentlyContinue | Out-Null
    } else {
        Write-Warn "Docker Desktop executable not found at expected path:"
        Write-Warn "  $dockerDesktop"
        Write-Warn "Please launch Docker Desktop manually from the Start Menu."
    }

    Test-DockerDaemon
}

function Test-DockerDaemon {
    # First-run Docker Desktop on Windows can take 2-3 minutes because it
    # provisions a WSL2 distro and installs the Linux kernel. We poll for
    # up to 3 minutes, with progress messages every 30 s so the user
    # doesn't think we're hung.
    $timeoutSeconds = 180
    Write-Info "Waiting for Docker daemon (up to $timeoutSeconds s — first run can be slow)..."
    $deadline   = (Get-Date).AddSeconds($timeoutSeconds)
    $lastNotice = Get-Date
    while ((Get-Date) -lt $deadline) {
        try {
            & docker info *>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Docker daemon is responsive."
                return
            }
        } catch { }

        if (((Get-Date) - $lastNotice).TotalSeconds -gt 30) {
            $remaining = [int](($deadline - (Get-Date)).TotalSeconds)
            Write-Info "  ... still waiting (${remaining}s remaining). If this is your first run, accept any prompts from Docker Desktop."
            $lastNotice = Get-Date
        }
        Start-Sleep -Seconds 3
    }
    Write-Err "Docker daemon is not responding after $timeoutSeconds s."
    Write-Err ""
    Write-Err "First-time Docker Desktop setup is interactive:"
    Write-Err "  1. Find 'Docker Desktop' in the Start Menu and launch it."
    Write-Err "  2. Accept the licence agreement."
    Write-Err "  3. If asked, install the WSL2 kernel update."
    Write-Err "  4. Wait for the whale icon in the system tray to stop animating."
    Write-Err "  5. Re-run this installer."
    exit 2
}

# ─── Step 3: Node.js 22 LTS ───────────────────────────────────────────────

function Install-Node {
    $major = Get-CommandMajorVersion -Name 'node'
    # Node 22, the version every workflow tests on and both Node images ship.
    # Accepting 20 here handed a self-hoster a different runtime from the one
    # the project builds and tests against, and Node 20 left security support
    # in April 2026. install.sh requires the same major.
    #
    # $null on the LHS is the PowerShell idiom — putting $null on the right
    # unboxes the LHS if it's an array, which Get-CommandMajorVersion can
    # technically return if Select-Object -First 1 misbehaves.
    if (($null -ne $major) -and ($major -ge 22)) {
        Write-Ok "node already installed: $((& node --version))"
        return
    }
    Install-WingetPackage -Id 'OpenJS.NodeJS.LTS' -DisplayName 'Node.js 22 LTS'
    if (-not (Test-CommandExists node)) {
        Stop-WithError "node was installed via winget but isn't on PATH. Open a new PowerShell window and re-run this script."
    }
    $major = Get-CommandMajorVersion -Name 'node'
    if (($null -ne $major) -and ($major -lt 22)) {
        Write-Warn "Installed Node version ($((& node --version))) is older than 22; AiSOC may misbehave."
    } else {
        Write-Ok "node installed: $((& node --version))"
    }
}

# ─── Step 4: pnpm 8+ via corepack ─────────────────────────────────────────

function Install-Pnpm {
    $major = Get-CommandMajorVersion -Name 'pnpm'
    if ($null -ne $major -and $major -ge 8) {
        Write-Ok "pnpm already installed: $((& pnpm --version))"
        return
    }

    # Try corepack first (the modern Node-bundled package-manager manager).
    # Fall back to a global npm install if corepack misbehaves — older Node
    # bundles, locked-down corporate networks, or registry hiccups all
    # break corepack in different ways.
    Write-Info "Enabling corepack and activating pnpm 8.15.1..."
    $corepackOk = $true
    & corepack enable 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $corepackOk = $false }
    if ($corepackOk) {
        & corepack prepare pnpm@8.15.1 --activate 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { $corepackOk = $false }
    }

    if (-not $corepackOk -or -not (Test-CommandExists pnpm)) {
        Write-Warn "corepack route failed; falling back to: npm install -g pnpm@8.15.1"
        & npm install -g pnpm@8.15.1 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError @"
Could not install pnpm via corepack OR npm.

Workaround: install pnpm manually, then re-run this script:
  npm install -g pnpm@8.15.1
  irm https://raw.githubusercontent.com/beenuar/AiSOC/main/install.ps1 | iex
"@
        }
    }

    if (-not (Test-CommandExists pnpm)) {
        # PATH refresh hasn't picked up the new global bin yet.
        Update-PathFromRegistry
    }
    if (-not (Test-CommandExists pnpm)) {
        Stop-WithError "pnpm was installed but isn't on PATH. Open a new PowerShell window and re-run this script."
    }
    Write-Ok "pnpm installed: $((& pnpm --version))"
}

# ─── Step 5: clone or locate repo ─────────────────────────────────────────

$script:RepoRoot = $null

function Resolve-Repo {
    # If this script lives inside an AiSOC clone, use that. Otherwise clone
    # fresh into $CloneDir.
    $selfDir = $PSScriptRoot
    if ($selfDir -and (Test-Path (Join-Path $selfDir '.git')) -and (Test-Path (Join-Path $selfDir 'package.json'))) {
        $pkgJson = Get-Content (Join-Path $selfDir 'package.json') -Raw
        if ($pkgJson -match '"name":\s*"aisoc') {
            $script:RepoRoot = $selfDir
            Write-Ok "Using existing AiSOC clone at $RepoRoot"
            return
        }
    }

    if (Test-Path $CloneDir) {
        $hasGit  = Test-Path (Join-Path $CloneDir '.git')
        $hasPkg  = Test-Path (Join-Path $CloneDir 'package.json')
        if ($hasGit -and $hasPkg -and ((Get-Content (Join-Path $CloneDir 'package.json') -Raw) -match '"name":\s*"aisoc')) {
            Write-Info "Updating existing clone at $CloneDir..."
            Push-Location $CloneDir
            try {
                # PowerShell try/catch doesn't catch non-zero native exit
                # codes, so check $LASTEXITCODE explicitly. We don't fail
                # hard on update failure — the user might have local edits
                # or be offline; we'd rather use what's on disk than abort.
                & git fetch --quiet origin 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "git fetch failed; using local state."
                } else {
                    & git checkout --quiet $Branch 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warn "git checkout $Branch failed; staying on current branch."
                    } else {
                        & git pull --ff-only --quiet 2>&1 | Out-Null
                        if ($LASTEXITCODE -ne 0) {
                            Write-Warn "git pull failed (likely local commits); using local state."
                        }
                    }
                }
            } finally {
                Pop-Location
            }
            $script:RepoRoot = $CloneDir
            Write-Ok "Updated clone at $RepoRoot"
            return
        }
        Stop-WithError "$CloneDir exists but isn't an AiSOC clone. Pass -CloneDir to choose a different location, or remove it first."
    }

    Write-Info "Cloning AiSOC into $CloneDir (branch: $Branch)..."

    # Retry up to 3 times with backoff. The most common failure on Windows
    # is corporate-proxy-related (407, SSL handshake failures) on the first
    # attempt but fine after a retry once the proxy creds are cached.
    $maxAttempts = 3
    $attempt     = 0
    while ($attempt -lt $maxAttempts) {
        $attempt++
        & git clone --branch $Branch --depth 50 https://github.com/beenuar/AiSOC.git $CloneDir
        if ($LASTEXITCODE -eq 0) {
            $script:RepoRoot = $CloneDir
            Write-Ok "Cloned AiSOC to $RepoRoot"
            return
        }

        if ($attempt -lt $maxAttempts) {
            Write-Warn "git clone failed (attempt $attempt/$maxAttempts). Retrying in 3 s..."
            # Clean up partial clone so the retry doesn't trip over an
            # existing dir.
            if (Test-Path $CloneDir) {
                try { Remove-Item -Recurse -Force $CloneDir -ErrorAction Stop } catch { }
            }
            Start-Sleep -Seconds 3
        }
    }

    Stop-WithError @"
git clone failed after $maxAttempts attempts.

Common causes:
  * No internet (try: Test-NetConnection github.com -Port 443)
  * Corporate proxy not configured for git
    (try: git config --global http.proxy http://proxy:port)
  * Branch '$Branch' doesn't exist on the remote
    (try: git ls-remote --heads https://github.com/beenuar/AiSOC.git)

Then re-run this installer.
"@ 5
}

# ─── Step 6: .env bootstrap ───────────────────────────────────────────────

function Initialize-EnvFile {
    $envPath     = Join-Path $RepoRoot '.env'
    $exampleEnv  = Join-Path $RepoRoot '.env.example'
    if (Test-Path $envPath) {
        Write-Ok ".env already exists at $envPath"
        return
    }
    if (Test-Path $exampleEnv) {
        Copy-Item $exampleEnv $envPath
        Write-Ok "Created $envPath from .env.example"
        Write-Info "  (Optional: edit .env to add your OpenAI/Anthropic API key for richer agent runs.)"
    } else {
        Write-Warn "No .env.example found in repo; skipping .env creation."
    }
}

# ─── Step 7: pnpm install + handoff ───────────────────────────────────────

function Install-Workspace {
    Write-Info "Installing JS workspace deps (pnpm install)..."
    Push-Location $RepoRoot
    try {
        # `--frozen-lockfile`, the same flag CI, the web image and install.sh
        # use. Without it a self-hoster's install is free to resolve a
        # dependency set nobody tested, which is the one thing an installer
        # must not do quietly.
        & pnpm install --prefer-offline --frozen-lockfile
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError @"
pnpm install failed.

If it reported a lockfile mismatch, your checkout's package.json and
pnpm-lock.yaml disagree — re-clone, or run:
  git checkout pnpm-lock.yaml
"@
        }
    } finally {
        Pop-Location
    }
    Write-Ok "pnpm dependencies installed."
}

# The host ports CORE publishes, as service + container port, in the same
# order and with the same owners scripts/doctor.sh checks under --ports-only.
$script:CorePortSpecs = @(
    @{ Port = 5432; Service = 'postgres';      ContainerPort = 5432 },
    @{ Port = 6379; Service = 'redis';         ContainerPort = 6379 },
    @{ Port = 9092; Service = 'kafka';         ContainerPort = 9092 },
    @{ Port = 8000; Service = 'api';           ContainerPort = 8000 },
    @{ Port = 8081; Service = 'ingest-worker'; ContainerPort = 8080 },
    @{ Port = 3000; Service = 'web';           ContainerPort = 3000 }
)

# The host port this deployment's own container publishes for a service, or
# $null. Asking compose is what distinguishes "someone else has 5432" from
# "our own postgres has 5432" — re-running the installer against a running
# stack must not be reported as a conflict with itself.
function Get-ComposePublishedPort {
    param([Parameter(Mandatory)][string]$Service, [Parameter(Mandatory)][int]$ContainerPort)
    $mapped = & docker compose port $Service $ContainerPort 2>$null | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($mapped)) { return $null }
    $tail = ("$mapped" -split ':')[-1]
    $parsed = 0
    if ([int]::TryParse($tail.Trim(), [ref]$parsed)) { return $parsed }
    return $null
}

function Test-PortBusy {
    param([Parameter(Mandatory)][int]$Port)
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        # Throws rather than returning empty when nothing is listening.
        try { $null = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop; return $true }
        catch { return $false }
    }
    # Get-NetTCPConnection is absent from PowerShell 7 builds without the
    # Windows compatibility modules. netstat ships with every Windows.
    $hit = & netstat -ano -p TCP 2>$null |
        Select-String -Pattern 'LISTENING' |
        Select-String -Pattern (":{0}\s" -f $Port)
    return [bool]$hit
}

# Names whatever is holding a port. "Something else has it" is only
# actionable if the operator can tell what, so this reports a container name
# when Docker published the port and the listening process otherwise.
function Get-PortHolder {
    param([Parameter(Mandatory)][int]$Port)
    if (Test-CommandExists docker) {
        $name = & docker ps --filter "publish=$Port" --format '{{.Names}}' 2>$null | Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace($name)) { return "container $name" }
    }
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $conn) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($null -ne $proc) { return "$($proc.ProcessName) (pid $($conn.OwningProcess))" }
                return "pid $($conn.OwningProcess)"
            }
        } catch {
            # Fall through to the generic answer below.
        }
    }
    return 'an unidentified process'
}

# Names a port conflict before compose hits it. `docker compose up` reports a
# clash as `Bind for 0.0.0.0:5432 failed: port is already allocated` against
# whichever container lost the race, which names neither the process holding
# the port nor what to do about it — and arrives after half the stack has
# already started.
function Test-CorePortsFree {
    $conflicts = @()
    foreach ($spec in $script:CorePortSpecs) {
        $ours = Get-ComposePublishedPort -Service $spec.Service -ContainerPort $spec.ContainerPort
        if (($null -ne $ours) -and ($ours -eq $spec.Port)) {
            Write-Ok "port $($spec.Port) in use by aisoc $($spec.Service)"
        } elseif ($null -ne $ours) {
            # Already remapped. The canonical port being busy is then
            # irrelevant, and failing on it would send the operator off to
            # fix something that is working.
            Write-Ok "aisoc $($spec.Service) is published on $ours (not the default $($spec.Port))"
        } elseif (Test-PortBusy -Port $spec.Port) {
            $conflicts += "port $($spec.Port) is held by $(Get-PortHolder -Port $spec.Port) — aisoc $($spec.Service) needs it"
        } else {
            Write-Log "port $($spec.Port) free"
        }
    }
    if ($conflicts.Count -eq 0) { return }
    Write-Host ''
    foreach ($conflict in $conflicts) { Write-Err $conflict }
    Write-Host ''
    Write-Err 'Not starting: the ports above are taken by something else.'
    Write-Err 'Stop that process, or edit the host port in docker-compose.yml.'
    Write-Err "(A docker-compose.override.yml needs 'ports: !override' — a plain"
    Write-Err ' override appends, leaving the conflicting binding in place.)'
    exit 3
}

# Waits on the services that declare a healthcheck, and refuses to call a
# stack up while any container is dead.
#
# Reading `ps` without `-a` cannot see an *exited* container at all, and a
# *restarting* one reports no health, so both are invisible to the obvious
# loop and the stack gets declared up with services crash-looping behind it.
# A container that is not running is the one thing a wait loop must never
# score as success.
function Wait-StackHealthy {
    Write-Host ''
    Write-Info 'Waiting for services to become healthy...'
    $pending = @()
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $lines = @(& docker compose ps -a --format '{{.Service}} {{.State}} {{.Health}}' 2>$null)
        $broken = @()
        $pending = @()
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $parts = @("$line".Trim() -split '\s+')
            if ($parts.Count -lt 2) { continue }
            $state  = $parts[1]
            $health = if ($parts.Count -ge 3) { $parts[2] } else { '' }
            if (($state -in @('exited', 'dead', 'restarting')) -or ($health -eq 'unhealthy')) {
                $broken += $parts[0]
            } elseif ($health -eq 'starting') {
                $pending += $parts[0]
            }
        }
        if ($broken.Count -gt 0) {
            Write-Host ''
            Write-Err "These services are not running: $($broken -join ' ')"
            foreach ($service in $broken) { Write-Err "  docker compose logs $service" }
            exit 3
        }
        # An empty listing is not health — compose reported success but there
        # is nothing to be healthy, so keep waiting rather than pass.
        if (($lines.Count -gt 0) -and ($pending.Count -eq 0)) {
            Write-Ok 'Every service reports healthy.'
            return
        }
        Start-Sleep -Seconds 3
    }
    Write-Host ''
    if ($pending.Count -gt 0) {
        Write-Err "Still not healthy after 3 minutes: $($pending -join ' ')"
    } else {
        Write-Err 'No containers are running 3 minutes after compose reported success.'
    }
    Write-Err 'Inspect them with:  docker compose ps -a'
    exit 3
}

function Start-Stack {
    if ($NoLaunch) {
        Write-Info '-NoLaunch: not starting the stack. To start it later:'
        Write-Info "  cd $RepoRoot"
        Write-Info '  docker compose up -d'
        Write-Info '  docker compose run --rm -T api python -m app.scripts.bootstrap_admin'
        Write-Info '  python tests\e2e\golden_pipeline\run_golden_pipeline.py'
        Write-Info 'Or simply re-run this installer without -NoLaunch.'
        return
    }
    Write-Section 'Starting AiSOC (CORE profile)'
    Write-Info 'Starting the CORE stack: postgres, redis, kafka, the LLM gateway,'
    Write-Info 'ingest, fusion, api, agents, realtime and the web console.'
    Write-Info ''
    Write-Info "This is the same stack 'make up' starts on Linux and macOS and the"
    Write-Info 'same one CI tests. It runs the real pipeline: an event you send is'
    Write-Info 'normalized, placed on the event spine, evaluated against the'
    Write-Info 'detection corpus, correlated and written as an alert.'
    Write-Host ''

    Push-Location $RepoRoot
    try {
        Test-CorePortsFree

        $composeArgs = @('compose', 'up', '-d')
        if ($Rebuild) { $composeArgs += '--build' }
        & docker @composeArgs
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "'docker compose up -d' exited non-zero. Run 'docker compose ps -a' to see which service failed." 3
        }
        Wait-StackHealthy
    } finally {
        Pop-Location
    }
}

# ─── Step 8: the first administrator ──────────────────────────────────────
#
# Creates the first administrator and prints its password once. Idempotent:
# a second run reports the existing account and changes nothing, which is why
# this runs unconditionally after every start.
#
# Failure here is reported but does not fail the install. The stack is
# genuinely running at this point, and aborting over an account the operator
# can create with one more command would be the wrong signal — but it must
# say so, because silence would leave them at a login form with no credential
# and no explanation.
function New-AdminAccount {
    if ($NoLaunch) { return }
    Write-Section 'Creating the first administrator'
    Push-Location $RepoRoot
    try {
        # Output is deliberately neither captured nor suppressed: the
        # generated password is printed here, once, and stored nowhere.
        & docker compose run --rm -T api python -m app.scripts.bootstrap_admin
        if ($LASTEXITCODE -ne 0) {
            Write-Host ''
            Write-Warn 'Could not create the administrator — the stack is up, but you cannot sign in yet.'
            Write-Warn 'Find out why, then try again:'
            Write-Warn '  docker compose logs api'
            Write-Warn '  docker compose run --rm -T api python -m app.scripts.bootstrap_admin'
        }
    } finally {
        Pop-Location
    }
}

# ─── Step 9: post-install verification ────────────────────────────────────
#
# "The containers started" is not "the application works", and this installer
# used to print a success banner purely because the handoff exited 0. A user
# whose pipeline was broken was told everything was fine.
#
# The golden pipeline posts one real event and follows it through Kafka,
# fusion, detection and Postgres, then reads the alert back from the API. If
# that fails, the install has failed, whatever the containers say.

# Only set once an event has actually come back out of the API. The closing
# banner reads this rather than assuming, because the check can legitimately
# be skipped (no interpreter) and a banner that claims it ran anyway is the
# defect the check exists to catch.
$script:PipelineVerified = $false

# Windows spells python at least three ways and ships a Microsoft Store stub
# called `python.exe` that is not an interpreter, so the version output is
# checked rather than the name.
function Resolve-Python {
    $candidates = @(
        @{ Exe = 'python3'; Prefix = @() },
        @{ Exe = 'python';  Prefix = @() },
        @{ Exe = 'py';      Prefix = @('-3') }
    )
    foreach ($candidate in $candidates) {
        if (-not (Test-CommandExists $candidate.Exe)) { continue }
        try {
            $probeArgs = @($candidate.Prefix) + @('--version')
            # Deliberately not `| Select-Object -First 1`: that stops the
            # pipeline before the native command finishes, so $LASTEXITCODE is
            # never assigned — and under Set-StrictMode *reading* an unassigned
            # $LASTEXITCODE throws, which the catch below would swallow into
            # "no interpreter" for every candidate. The installer would then
            # skip the pipeline check on every machine, silently.
            $out = (& $candidate.Exe @probeArgs 2>&1 | Out-String)
            $code = if (Test-Path Variable:LASTEXITCODE) { $LASTEXITCODE } else { 0 }
            # The version string is the real test. Windows ships a Microsoft
            # Store stub named python.exe that prints a "not found" notice
            # instead of a version, and it is on PATH by default.
            if (($code -eq 0) -and ($out -match 'Python\s+3\.')) { return $candidate }
        } catch {
            # Not a usable interpreter; try the next spelling.
        }
    }
    return $null
}

function Invoke-SmokeTest {
    if ($NoLaunch) { return }
    Write-Section 'Verifying the pipeline end to end'

    $runner = Join-Path $RepoRoot 'tests\e2e\golden_pipeline\run_golden_pipeline.py'
    if (-not (Test-Path $runner)) {
        Write-Warn "Golden pipeline runner not found at $runner — skipping verification."
        return
    }

    $python = Resolve-Python
    if ($null -eq $python) {
        Write-Warn 'No Python 3 interpreter on PATH — skipping pipeline verification.'
        Write-Warn 'Install one, then verify manually:'
        Write-Warn '  winget install --id Python.Python.3.12'
        Write-Warn '  python tests\e2e\golden_pipeline\run_golden_pipeline.py'
        return
    }

    $rc = 1
    Push-Location $RepoRoot
    try {
        $runnerArgs = @($python.Prefix) + @($runner)
        & $python.Exe @runnerArgs
        $rc = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    if ($rc -eq 0) {
        $script:PipelineVerified = $true
        Write-Ok 'Pipeline verified: a real event became a retrievable alert.'
        return
    }

    Write-Host ''
    Write-Err 'The stack started, but a real event did not become an alert.'
    Write-Err 'This is a genuine failure, not a warning: AiSOC is not working yet.'
    Write-Err ''
    Write-Err 'Diagnose it with:'
    Write-Err '    docker compose ps -a'
    Write-Err '    docker compose logs fusion'
    Write-Err ''
    Write-Err 'Then re-run the check:'
    Write-Err "    $($python.Exe) tests\e2e\golden_pipeline\run_golden_pipeline.py"
    exit 5
}

# ─── Final banner ─────────────────────────────────────────────────────────

function Write-SuccessBanner {
    if ($NoLaunch) {
        Write-Host ''
        Write-Host 'Prerequisites installed and the repository is ready.' -ForegroundColor Green
        Write-Host 'The stack was not started (-NoLaunch).' -ForegroundColor DarkGray
        Write-Host ''
        return
    }

    $adminEmail = if ([string]::IsNullOrWhiteSpace($env:AISOC_ADMIN_EMAIL)) { 'admin@aisoc.internal' } else { $env:AISOC_ADMIN_EMAIL }

    Write-Host ''
    if ($script:PipelineVerified) {
        Write-Host 'AiSOC is up and running, and a real event reached the API.' -ForegroundColor Green
    } else {
        # The pipeline check was skipped, so the stack being healthy is all
        # that is actually known. Saying more would be the exact failure this
        # verification step exists to prevent.
        Write-Host 'AiSOC is up and every service reports healthy.' -ForegroundColor Green
        Write-Host 'The end-to-end pipeline check did not run — see the note above.' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  Web console:    http://localhost:3000'
    Write-Host '  API + Swagger:  http://localhost:8000/api/docs'
    Write-Host '  Realtime WS:    ws://localhost:8086'
    Write-Host ''
    Write-Host "  Sign in as:     $adminEmail"
    Write-Host '  The password was printed above, once, when the administrator was'
    Write-Host '  created. It is not stored anywhere. Lost it? Mint a new one with the'
    Write-Host '  reset command below.'
    Write-Host ''
    Write-Host "Useful commands (run from $RepoRoot):" -ForegroundColor DarkGray
    Write-Host '  docker compose ps                          # every service and its health'
    Write-Host '  docker compose logs -f --tail=200          # follow logs (add a service name to narrow)'
    Write-Host '  python tests\e2e\golden_pipeline\run_golden_pipeline.py'
    Write-Host '                                             # re-run the end-to-end pipeline check'
    Write-Host '  docker compose run --rm -T api python -m app.scripts.bootstrap_admin --reset-password'
    Write-Host '                                             # mint a new administrator password'
    Write-Host '  docker compose run --rm -e AISOC_ALLOW_SEED=1 api python -m app.scripts.seed_demo'
    Write-Host '                                             # load clearly-labelled synthetic data'
    Write-Host '  docker compose down                        # stop the stack, keep your data'
    Write-Host '  docker compose down -v                     # stop the stack and delete all volumes'
    Write-Host '  .\uninstall.ps1                            # full uninstall (containers + images + repo)'
    Write-Host ''
    Write-Host 'The demo dataset is synthetic. Every row is marked is_synthetic=true' -ForegroundColor DarkGray
    Write-Host 'and labelled in the console. See "Real vs synthetic data" in README.md.' -ForegroundColor DarkGray
    Write-Host ''
}

# ─── Main ─────────────────────────────────────────────────────────────────

function Invoke-Main {
    # Friendly error handler. Without this, an unhandled exception dumps a
    # gnarly red PowerShell stack trace at the user with no context. We catch
    # it, surface the most useful info, and link them to where to file an
    # issue with that info pre-filled.
    trap {
        $err = $_
        Write-Host ''
        Write-Host '┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓' -ForegroundColor Red
        Write-Host '┃  AiSOC installer hit an unexpected error.                                    ┃' -ForegroundColor Red
        Write-Host '┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛' -ForegroundColor Red
        Write-Host ''
        Write-Host "  Error: $($err.Exception.Message)" -ForegroundColor Yellow
        if ($err.InvocationInfo) {
            Write-Host "  At:    $($err.InvocationInfo.ScriptName):$($err.InvocationInfo.ScriptLineNumber)" -ForegroundColor DarkGray
            Write-Host "         $($err.InvocationInfo.Line.Trim())" -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-Host '  What to try:' -ForegroundColor Cyan
        Write-Host '    1. Re-run with: .\install.ps1 -Diagnose'
        Write-Host '       (preflight only — no installs)'
        Write-Host '    2. Read the troubleshooting guide:'
        Write-Host '       https://github.com/beenuar/AiSOC/blob/main/docs/QUICK_INSTALL.md#troubleshooting'
        Write-Host '    3. File an issue with the system info below:'
        Write-Host '       https://github.com/beenuar/AiSOC/issues/new?template=installer-bug.md'
        Write-Host ''
        Write-Host '  System info:' -ForegroundColor DarkGray
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($os) {
                Write-Host "    OS:      $($os.Caption) build $($os.BuildNumber) ($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor DarkGray
            }
        } catch { }
        Write-Host "    PSVer:   $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
        if (Test-CommandExists docker) {
            try { Write-Host "    Docker:  $((& docker --version) 2>$null)" -ForegroundColor DarkGray } catch { }
        }
        if (Test-CommandExists node) {
            try { Write-Host "    Node:    $((& node --version) 2>$null)" -ForegroundColor DarkGray } catch { }
        }
        Write-Host ''
        exit 1
    }

    Write-Section 'AiSOC One-Click Installer (Windows)'

    if ($NoPull) {
        # Kept as a parameter so an existing invocation does not become a
        # parameter-binding error, but it no longer means anything: the
        # installer starts the stack with `docker compose up -d`, which pulls
        # only the images it does not already have. Saying so is better than
        # accepting the flag and silently ignoring it.
        Write-Warn '-NoPull no longer applies: the stack starts with `docker compose up -d`,'
        Write-Warn 'which pulls only images that are missing. The flag is ignored.'
    }

    Test-WindowsVersion

    # Preflight before we touch anything. In Diagnose mode this is also
    # the only thing we run.
    Invoke-Preflight

    if ($Diagnose) {
        Write-Host ''
        Write-Ok "Diagnose complete. No changes were made."
        Write-Info "Drop -Diagnose to continue with the full install."
        exit 0
    }

    if (-not $NoInstall) {
        Test-WSL2
        if (-not (Test-Winget)) { exit 1 }

        Write-Section 'Installing prerequisites'
        Install-Git
        Install-Docker
        Install-Node
        Install-Pnpm
    } else {
        Write-Info "-NoInstall: skipping prerequisite install. Verifying what's on PATH..."
        if (-not (Test-CommandExists git))    { Stop-WithError "git missing (and -NoInstall was given)" }
        if (-not (Test-CommandExists docker)) { Stop-WithError "docker missing (and -NoInstall was given)" }
        & docker compose version *>&1 | Out-Null
        if ($LASTEXITCODE -ne 0)              { Stop-WithError "docker compose v2 missing (and -NoInstall was given)" }
        if (-not (Test-CommandExists node))   { Stop-WithError "node missing (and -NoInstall was given)" }
        if (-not (Test-CommandExists pnpm))   { Stop-WithError "pnpm missing (and -NoInstall was given)" }
        Test-DockerDaemon
    }

    Write-Section 'Setting up the AiSOC repository'
    Resolve-Repo
    Initialize-EnvFile
    Install-Workspace
    Start-Stack
    New-AdminAccount
    Invoke-SmokeTest
    Write-SuccessBanner
}

Invoke-Main

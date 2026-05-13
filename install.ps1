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
             - Node.js 20 LTS
             - pnpm 8+ (via corepack)
           All installs go through winget, the official Windows package
           manager. We never download random installers from the internet.
        4. Clones the AiSOC repo (if you ran the script as a one-liner) or
           reuses it (if you ran .\install.ps1 from inside a clone).
        5. Creates a .env from .env.example so the first boot has sane
           defaults.
        6. Runs `pnpm install` to fetch the orchestrator's Node deps.
        7. Hands off to `pnpm aisoc:demo`, which pulls prebuilt images,
           brings up the slim demo profile, seeds the showcase ransomware
           case, and opens your browser at the case ledger view.

.PARAMETER NoInstall
    Skip the dependency-install phase (use what's on PATH).

.PARAMETER NoLaunch
    Set everything up but don't run pnpm aisoc:demo at the end.

.PARAMETER NoPull
    Forwarded to aisoc:demo to skip image pull.

.PARAMETER Rebuild
    Forwarded to aisoc:demo to build images from source.

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
    Exit codes:
        0  success — demo stack is up and your browser opened
        1  prerequisite install failed
        2  Docker Desktop refused to come up / WSL2 not enabled
        3  pnpm aisoc:demo failed (stack didn't boot or seed)
        4  preflight checks failed (machine doesn't meet minimums)
        5  git clone failed (network / branch / disk)

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

# ─── Step 3: Node.js 20 LTS ───────────────────────────────────────────────

function Install-Node {
    $major = Get-CommandMajorVersion -Name 'node'
    # $null on the LHS is the PowerShell idiom — putting $null on the right
    # unboxes the LHS if it's an array, which Get-CommandMajorVersion can
    # technically return if Select-Object -First 1 misbehaves.
    if (($null -ne $major) -and ($major -ge 20)) {
        Write-Ok "node already installed: $((& node --version))"
        return
    }
    Install-WingetPackage -Id 'OpenJS.NodeJS.LTS' -DisplayName 'Node.js 20 LTS'
    if (-not (Test-CommandExists node)) {
        Stop-WithError "node was installed via winget but isn't on PATH. Open a new PowerShell window and re-run this script."
    }
    Write-Ok "node installed: $((& node --version))"
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
        if ($pkgJson -match '"name":\s*"aisoc"') {
            $script:RepoRoot = $selfDir
            Write-Ok "Using existing AiSOC clone at $RepoRoot"
            return
        }
    }

    if (Test-Path $CloneDir) {
        $hasGit  = Test-Path (Join-Path $CloneDir '.git')
        $hasPkg  = Test-Path (Join-Path $CloneDir 'package.json')
        if ($hasGit -and $hasPkg -and ((Get-Content (Join-Path $CloneDir 'package.json') -Raw) -match '"name":\s*"aisoc"')) {
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
        & pnpm install --prefer-offline --no-frozen-lockfile
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "pnpm install failed."
        }
    } finally {
        Pop-Location
    }
    Write-Ok "pnpm dependencies installed."
}

function Start-Demo {
    if ($NoLaunch) {
        Write-Info "-NoLaunch: skipping pnpm aisoc:demo. To start the stack later:"
        Write-Info "  cd $RepoRoot; pnpm aisoc:demo"
        return
    }
    Write-Section 'Launching AiSOC demo stack'
    Write-Info "Handing off to 'pnpm aisoc:demo' — this will pull images, start the"
    Write-Info "stack, seed the showcase ransomware case, and open your browser."
    Write-Host ''

    $demoArgs = @()
    if ($NoPull)  { $demoArgs += '--no-pull' }
    if ($Rebuild) { $demoArgs += '--rebuild' }

    Push-Location $RepoRoot
    try {
        if ($demoArgs.Count -gt 0) {
            & pnpm aisoc:demo @demoArgs
        } else {
            & pnpm aisoc:demo
        }
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "pnpm aisoc:demo exited non-zero." 3
        }
    } finally {
        Pop-Location
    }
}

# ─── Final banner ─────────────────────────────────────────────────────────

function Write-SuccessBanner {
    Write-Host ''
    Write-Host 'AiSOC is up and running.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Web console:    http://localhost:3000'
    Write-Host '  Showcase case:  http://localhost:3000/cases/INC-RT-001?tab=ledger'
    Write-Host '  API + Swagger:  http://localhost:8000/docs'
    Write-Host '  Realtime WS:    ws://localhost:8086'
    Write-Host ''
    Write-Host "Useful commands (run from $RepoRoot):" -ForegroundColor DarkGray
    Write-Host '  pnpm aisoc:doctor                          # health-check the stack'
    Write-Host '  pnpm aisoc:demo:logs                       # tail logs'
    Write-Host '  pnpm aisoc:demo:down                       # stop everything and wipe demo data'
    Write-Host '  .\scripts\install\uninstall.ps1            # full uninstall'
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
    Start-Demo
    Write-SuccessBanner
}

Invoke-Main

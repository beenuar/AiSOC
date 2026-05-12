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
    [string]$CloneDir = (Join-Path $env:USERPROFILE 'aisoc'),
    [string]$Branch = 'main'
)

# Strict mode catches typos in variable names — really easy to do in a long
# script and PowerShell silently substitutes $null otherwise.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Logging helpers ──────────────────────────────────────────────────────
# We deliberately avoid Write-Host's color params for non-interactive runs
# (CI, redirected stdout). Detection: $Host.UI.RawUI is null when there's
# no console (e.g. piped through iex from iwr in a non-interactive context).

$script:UseColor = ($null -ne $Host.UI.RawUI) -and ($null -eq $env:NO_COLOR)

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
        Write-Warn "WSL is not installed. Installing now (this requires a reboot)..."
        Write-Info "Running: wsl --install --no-launch"
        & wsl.exe --install --no-launch
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "wsl --install failed. Run an elevated PowerShell and try: wsl --install" 2
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
    $args = @(
        'install',
        '--id', $Id,
        '--exact',                   # match Id exactly, no fuzzy suggestions
        '--silent',                  # suppress installer UI where supported
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--source', 'winget'         # pin to the official source, not msstore
    )
    $proc = Start-Process -FilePath 'winget' -ArgumentList $args -Wait -PassThru -NoNewWindow
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
    # versions. Start-Process with -PassThru lets us check the spawn
    # succeeded; the actual daemon takes 10-30 s more to come up.
    $dockerDesktop = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktop) {
        Write-Info "Launching Docker Desktop..."
        Start-Process -FilePath $dockerDesktop -ErrorAction SilentlyContinue | Out-Null
    }

    Test-DockerDaemon
}

function Test-DockerDaemon {
    Write-Info "Waiting for Docker daemon (up to 90 s)..."
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        try {
            & docker info *>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Docker daemon is responsive."
                return
            }
        } catch { }
        Start-Sleep -Seconds 3
    }
    Write-Err "Docker daemon is not responding after 90 s."
    Write-Err ""
    Write-Err "First-time Docker Desktop setup is interactive:"
    Write-Err "  1. Find 'Docker Desktop' in the Start Menu and launch it."
    Write-Err "  2. Accept the licence agreement."
    Write-Err "  3. Wait for the whale icon in the system tray to stop animating."
    Write-Err "  4. Re-run this installer."
    exit 2
}

# ─── Step 3: Node.js 20 LTS ───────────────────────────────────────────────

function Install-Node {
    $major = Get-CommandMajorVersion -Name 'node'
    if ($major -ne $null -and $major -ge 20) {
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
    if ($major -ne $null -and $major -ge 8) {
        Write-Ok "pnpm already installed: $((& pnpm --version))"
        return
    }
    Write-Info "Enabling corepack and activating pnpm 8.15.1..."
    & corepack enable 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "corepack enable failed. Make sure node was installed correctly."
    }
    & corepack prepare pnpm@8.15.1 --activate 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "corepack prepare pnpm failed."
    }
    if (-not (Test-CommandExists pnpm)) {
        Stop-WithError "pnpm was activated but isn't on PATH. Open a new PowerShell window and re-run this script."
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
                & git fetch --quiet origin
                & git checkout --quiet $Branch
                & git pull --ff-only --quiet
            } catch {
                Write-Warn "git pull failed; using whatever is on disk."
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
    & git clone --branch $Branch --depth 50 https://github.com/beenuar/AiSOC.git $CloneDir
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "git clone failed."
    }
    $script:RepoRoot = $CloneDir
    Write-Ok "Cloned AiSOC to $RepoRoot"
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
    Write-Section 'AiSOC One-Click Installer (Windows)'

    Test-WindowsVersion

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

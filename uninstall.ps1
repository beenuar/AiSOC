<#
.SYNOPSIS
    AiSOC — Uninstaller for Windows.

.DESCRIPTION
    Tears down whatever install.ps1 + `pnpm aisoc:demo` brought up, in
    decreasing levels of aggressiveness:

        default          Stop the demo stack and delete its named volumes.
                         (Equivalent to: pnpm aisoc:demo:down)
        -RemoveImages    Also remove ghcr.io/beenuar/aisoc-* images
                         (saves ~2-3 GB of disk).
        -RemoveNodeModules
                         Also delete node_modules trees in the repo (~1 GB).
        -RemoveRepo      Also delete the AiSOC repo clone itself.
        -All             Equivalent to all three above.

    What this script DOES NOT do:
        - Uninstall Docker Desktop, Node, pnpm, or git. Those are
          general-purpose tools you almost certainly want for other projects.
          To remove them anyway:
              winget uninstall --id Git.Git
              winget uninstall --id OpenJS.NodeJS.LTS
              winget uninstall --id Docker.DockerDesktop
        - Touch any other Docker containers, images, or volumes outside the
          aisoc-demo project. We're surgical here.

.PARAMETER RemoveImages
    Also remove the ghcr.io/beenuar/aisoc-* container images.

.PARAMETER RemoveNodeModules
    Also delete node_modules trees inside the repo.

.PARAMETER RemoveRepo
    Also delete the AiSOC repo clone.

.PARAMETER All
    Shorthand for -RemoveImages -RemoveNodeModules -RemoveRepo.

.PARAMETER Yes
    Skip all confirmation prompts (for CI / scripted use).

.EXAMPLE
    .\uninstall.ps1
    # Stop stack and drop volumes only.

.EXAMPLE
    .\uninstall.ps1 -All -Yes
    # Nuke everything, no prompts (good for clean-room CI runs).

.NOTES
    Exit codes:
        0  success
        1  invalid arguments / unexpected error
        2  not run from inside an AiSOC clone (and -RemoveRepo wasn't given)
        3  refused to delete a path for safety reasons (system dir, not an
           AiSOC clone, etc.) — visible separately so CI scripts don't
           silently treat a refusal as "all done"
#>

[CmdletBinding()]
param(
    [switch]$RemoveImages,
    [switch]$RemoveNodeModules,
    [switch]$RemoveRepo,
    [switch]$All,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

if ($All) {
    $RemoveImages = $true
    $RemoveNodeModules = $true
    $RemoveRepo = $true
}

# Tracks whether we refused a delete for safety reasons. We don't fail-fast
# on refusals (the user might still want to clean up volumes / images), but
# we do exit non-zero at the end so CI scripts notice.
$script:SafetyRefused = $false

# ─── Logging helpers (match install.ps1 style) ──────────────────────────────

function Write-Log     { param([string]$m) Write-Host "[aisoc] $m" -ForegroundColor DarkGray }
function Write-Info    { param([string]$m) Write-Host "[aisoc] $m" -ForegroundColor Blue }
function Write-Ok      { param([string]$m) Write-Host "[aisoc] $m" -ForegroundColor Green }
function Write-Warn    { param([string]$m) Write-Host "[aisoc] $m" -ForegroundColor Yellow }
function Write-Err     { param([string]$m) Write-Host "[aisoc] $m" -ForegroundColor Red }
function Write-Section {
    param([string]$m)
    Write-Host ""
    Write-Host "━━━ $m ━━━" -ForegroundColor Cyan
    Write-Host ""
}

function Confirm-Action {
    param([string]$Prompt)
    # In non-interactive contexts (no console host) or with -Yes, just say yes.
    if ($Yes -or -not [Environment]::UserInteractive) { return $true }
    $resp = Read-Host "$Prompt [y/N]"
    return ($resp -match '^[yY]')
}

# ─── Locate the AiSOC repo ──────────────────────────────────────────────────
# We need the path to infra/compose/docker-compose.demo.yml so `docker compose down -v` can
# resolve project resources cleanly. Prefer the directory two levels above
# this script (script lives in <repo>/scripts/install/), then fall back to
# the canonical $env:USERPROFILE\aisoc.

function Find-RepoRoot {
    # The uninstaller lives at the repo root, alongside install.ps1.
    $selfDir = Split-Path -Parent $PSCommandPath
    if ($selfDir -and
        (Test-Path (Join-Path $selfDir 'infra/compose/docker-compose.demo.yml')) -and
        (Test-Path (Join-Path $selfDir 'package.json'))) {
        $pkg = Get-Content (Join-Path $selfDir 'package.json') -Raw -ErrorAction SilentlyContinue
        if ($pkg -match '"name"\s*:\s*"aisoc"') {
            return $selfDir
        }
    }
    # Fallback 1: $HOME/aisoc (where install.ps1 clones by default).
    $homePath = Join-Path $env:USERPROFILE 'aisoc'
    if (Test-Path (Join-Path $homePath 'infra/compose/docker-compose.demo.yml')) {
        return $homePath
    }
    # Fallback 2: cwd is an aisoc clone.
    if ((Test-Path (Join-Path (Get-Location) 'infra/compose/docker-compose.demo.yml')) -and
        (Test-Path (Join-Path (Get-Location) 'package.json'))) {
        $pkg = Get-Content (Join-Path (Get-Location) 'package.json') -Raw -ErrorAction SilentlyContinue
        if ($pkg -match '"name"\s*:\s*"aisoc"') {
            return (Get-Location).Path
        }
    }
    return $null
}

$RepoRoot = Find-RepoRoot

if (-not $RepoRoot) {
    if ($RemoveImages -or $RemoveRepo) {
        Write-Warn "Couldn't locate AiSOC clone. Skipping 'compose down' (orphan containers may remain)."
    } else {
        Write-Err "Run this from inside an AiSOC clone, or pass -RemoveRepo to clean up the cloned repo at `$env:USERPROFILE\aisoc."
        exit 2
    }
}

# ─── Step 1: stop the demo stack ────────────────────────────────────────────

function Test-DockerReachable {
    # PowerShell native commands don't throw on non-zero exit, so try/catch
    # around `docker info` is a no-op. Check $LASTEXITCODE explicitly.
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) { return $false }
    & docker info *> $null
    return ($LASTEXITCODE -eq 0)
}

function Stop-DemoStack {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Warn "docker not on PATH; skipping compose down."
        return
    }
    if (-not (Test-DockerReachable)) {
        Write-Warn "docker daemon not reachable; skipping compose down."
        return
    }
    if (-not $RepoRoot) { return }

    Write-Info "Stopping AiSOC demo stack and removing its volumes..."
    Push-Location $RepoRoot
    try {
        docker compose -f infra/compose/docker-compose.demo.yml down -v --remove-orphans
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "compose down exited with code $LASTEXITCODE; some resources may not have been cleaned up."
        } else {
            Write-Ok "Demo stack stopped, named volumes deleted."
        }
    } finally {
        Pop-Location
    }
}

# ─── Step 2: remove AiSOC images ────────────────────────────────────────────
# Only ghcr.io/beenuar/aisoc-* — leaves alpine/postgres/redis/kafka alone
# because those are widely shared and cheap to re-pull.

function Remove-AiSOCImages {
    if (-not $RemoveImages) { return }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Warn "docker unreachable; skipping image removal."
        return
    }
    if (-not (Test-DockerReachable)) {
        Write-Warn "docker daemon not reachable; skipping image removal."
        return
    }
    Write-Section "Removing AiSOC container images"
    $images = docker images --format '{{.Repository}}:{{.Tag}}' | Where-Object { $_ -like 'ghcr.io/beenuar/aisoc-*' }
    if (-not $images) {
        Write-Info "No ghcr.io/beenuar/aisoc-* images found."
        return
    }
    $images | ForEach-Object { Write-Host "  $_" }
    if (Confirm-Action "Remove the images above?") {
        foreach ($img in $images) {
            docker rmi -f $img | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warn "Could not remove $img (in use?)" }
        }
        Write-Ok "Images removed."
    }
}

# ─── Step 3: node_modules cleanup ───────────────────────────────────────────

function Remove-NodeModulesTrees {
    if (-not $RemoveNodeModules) { return }
    if (-not $RepoRoot) { return }
    Write-Section "Removing node_modules"
    # pnpm symlinks aggressively, so we walk the tree to catch all of them
    # under apps/* and packages/* — not just the root one.
    $dirs = Get-ChildItem -Path $RepoRoot -Filter 'node_modules' -Recurse -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\node_modules\\.+\\node_modules$' }  # don't double-walk
    Write-Info "Found $($dirs.Count) node_modules directories under $RepoRoot"
    if ($dirs.Count -eq 0) { return }
    if (Confirm-Action "Remove them all?") {
        foreach ($d in $dirs) {
            try {
                Remove-Item -Recurse -Force -LiteralPath $d.FullName -ErrorAction Stop
            } catch {
                Write-Warn "Failed to remove $($d.FullName): $($_.Exception.Message)"
            }
        }
        Write-Ok "node_modules removed."
    }
}

# ─── Step 4: blow away the repo clone ───────────────────────────────────────

function Test-DangerousPath {
    # Refuse rm -rf on system or home-root directories. The "Steam deleted
    # my home" defense — better paranoid than apologetic.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $abs = $Path
    try { $abs = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath } catch {}
    # Normalise: strip trailing slash and lower-case for matching.
    $norm = $abs.TrimEnd('\', '/').ToLowerInvariant()

    # Bare drive roots (C:, D:\, etc.) — refuse before doing anything else.
    if ($norm -match '^[a-z]:$' -or $norm -match '^[a-z]:\\?$') { return $true }

    # Build the blocklist defensively — any of these env vars could in theory
    # be empty on a weird system, and calling .ToLowerInvariant() on $null
    # throws. We collect candidates as nullable strings, then filter empties.
    $candidates = New-Object System.Collections.Generic.List[string]
    $candidates.Add($env:SystemDrive)
    $candidates.Add($env:windir)
    $candidates.Add($env:ProgramFiles)
    $candidates.Add(${env:ProgramFiles(x86)})
    $candidates.Add($env:USERPROFILE)
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates.Add((Join-Path $env:USERPROFILE 'Desktop'))
        $candidates.Add((Join-Path $env:USERPROFILE 'Documents'))
        $candidates.Add((Join-Path $env:USERPROFILE 'Downloads'))
    }
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $b = $c.TrimEnd('\', '/').ToLowerInvariant()
        if ($norm -eq $b) { return $true }
    }
    return $false
}

function Remove-RepoClone {
    if (-not $RemoveRepo) { return }
    $target = if ($RepoRoot) { $RepoRoot } else { Join-Path $env:USERPROFILE 'aisoc' }
    if (-not (Test-Path $target)) {
        Write-Warn "No repo found at $target; nothing to remove."
        return
    }
    # Final sanity check: target must look like an AiSOC clone. Stops us
    # from rm -rf'ing some unrelated dir the user happened to put in
    # %USERPROFILE%\aisoc.
    $composeFile = Join-Path $target 'infra/compose/docker-compose.demo.yml'
    $pkgFile = Join-Path $target 'package.json'
    $looksLikeAiSOC = $false
    if ((Test-Path $composeFile) -and (Test-Path $pkgFile)) {
        $pkgContent = Get-Content $pkgFile -Raw -ErrorAction SilentlyContinue
        if ($pkgContent -and $pkgContent -match '"name"\s*:\s*"aisoc"') {
            $looksLikeAiSOC = $true
        }
    }
    if (-not $looksLikeAiSOC) {
        Write-Warn "$target doesn't look like an AiSOC clone (missing compose file or package.json marker)."
        Write-Warn "Refusing to delete it — clean it up manually if you really want to."
        $script:SafetyRefused = $true
        return
    }
    if (Test-DangerousPath -Path $target) {
        Write-Err "Refusing to delete $target — looks like a system or profile root directory."
        Write-Err "If you really meant to delete this path, do it by hand."
        $script:SafetyRefused = $true
        return
    }
    Write-Section "Removing AiSOC repo"
    Write-Warn "About to recursively delete: $target"
    if (Confirm-Action "Are you absolutely sure?") {
        # cd somewhere safe before deleting — PowerShell holds a lock on
        # the cwd, so deleting it can fail or leave orphan handles.
        try { Set-Location $env:TEMP } catch { try { Set-Location $env:SystemDrive } catch {} }
        try {
            Remove-Item -Recurse -Force -LiteralPath $target -ErrorAction Stop
            Write-Ok "Repo deleted."
        } catch {
            Write-Err "Failed to delete: $($_.Exception.Message)"
        }
    }
}

# ─── Main ───────────────────────────────────────────────────────────────────

Write-Section "AiSOC Uninstaller"
Stop-DemoStack
Remove-AiSOCImages
Remove-NodeModulesTrees
Remove-RepoClone

Write-Host ""
if ($script:SafetyRefused) {
    Write-Host "AiSOC uninstall finished — but at least one delete was refused for safety." -ForegroundColor Yellow
    Write-Host "See messages above. Exiting with code 3 so CI/scripts notice." -ForegroundColor Yellow
} else {
    Write-Host "AiSOC uninstall complete." -ForegroundColor Green
}
Write-Host ""
Write-Host "Things this script intentionally did NOT remove:" -ForegroundColor DarkGray
Write-Host "  - Docker Desktop, Node, pnpm, git (shared dev tools)"
Write-Host "  - WSL2 distros"
Write-Host "  - Other Docker images (postgres, redis, kafka, zookeeper, alpine)"
Write-Host "  - Cached pnpm store at `$env:LOCALAPPDATA\pnpm-store"
Write-Host ""
Write-Host "To remove the leftover infrastructure images too:" -ForegroundColor DarkGray
Write-Host "  docker image prune -a    # removes ALL dangling+unused images, not just AiSOC's"
Write-Host ""

if ($script:SafetyRefused) { exit 3 }

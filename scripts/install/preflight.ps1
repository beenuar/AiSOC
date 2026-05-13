<#
.SYNOPSIS
    AiSOC preflight checks for Windows.

.DESCRIPTION
    Mirror of scripts/install/preflight.sh, but for the Windows + WSL2
    + Docker Desktop world. Designed to be dot-sourced by install.ps1
    *before* any prerequisite work, but can also be run standalone:

        powershell -ExecutionPolicy Bypass -File scripts\install\preflight.ps1

    The goal is to catch the failures that would happen 4 minutes from
    now — no disk, can't talk to ghcr.io, port 3000 is held by IIS, WSL2
    isn't installed, Docker Desktop is using Hyper-V instead of WSL2 —
    *before* we ask the user to download a gigabyte of images.

    Checks performed (in order):

        1.  Windows version (build 19041 / 20H1+ for WSL2)
        2.  CPU architecture (amd64 / arm64 only)
        3.  RAM (>= 4 GB hard, >= 8 GB recommended)
        4.  Free disk on the install drive (>= 10 GB hard, >= 20 GB rec)
        5.  Internet reachability (api.github.com, ghcr.io, npmjs.org)
        6.  WSL2 is installed and has a default distro
        7.  Docker Desktop service / engine is reachable (best effort)
        8.  Required ports (3000/5432/6379/8000/8001/8086/9092) are free
            OR held by an existing AiSOC container we can reuse
        9.  No leftover/conflicting AiSOC containers from a prior run
        10. Hyper-V vs WSL2 sanity check (warn if both seem half-on)

    Each check produces one of three states:

        PASS  - silent, just increments the success counter
        WARN  - yellow line, doesn't block install
        FAIL  - red line, increments fail counter

.PARAMETER Soft
    If set, the script writes the summary and exits 0 even with
    failures. install.ps1 uses this on its second pass after auto-fix.

.PARAMETER SkipNetwork
    Skip the connectivity probes (for air-gapped install testing).
    Failures become warnings.

.PARAMETER InstallRoot
    Root path used for the disk space check. Defaults to the parent of
    this script (so the repo root) when dot-sourced, or the current
    working directory when run standalone.

.OUTPUTS
    Exit code 0 = all checks passed (or only warnings)
    Exit code 1 = at least one hard failure
    Exit code 2 = preflight itself failed to gather data

.NOTES
    This script intentionally does NOT modify anything on the system.
    It only reads. install.ps1 is responsible for any fixes.
#>
[CmdletBinding()]
param(
    [switch]$Soft,
    [switch]$SkipNetwork,
    [string]$InstallRoot
)

# We rely on $PSScriptRoot when dot-sourced.
if (-not $InstallRoot) {
    if ($PSScriptRoot) {
        $InstallRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    } else {
        $InstallRoot = (Get-Location).Path
    }
}

# These ports must match docker-compose.demo.yml. If you change ports
# there, change them here, otherwise users get false negatives.
$script:PfRequiredPorts = @(
    @{ Port = 3000; Name = "web console"      },
    @{ Port = 5432; Name = "postgres"         },
    @{ Port = 6379; Name = "redis"            },
    @{ Port = 8000; Name = "api"              },
    @{ Port = 8001; Name = "agents"           },
    @{ Port = 8086; Name = "realtime ws"      },
    @{ Port = 9092; Name = "kafka"            }
)

# Hosts and specific endpoints we know return a valid 2xx/3xx/401.
# (See preflight.sh for the rationale on /v2/ vs root.)
$script:PfNetHosts = @(
    "https://api.github.com/zen",
    "https://ghcr.io/v2/",
    "https://registry.npmjs.org/"
)

$script:PfPass = 0
$script:PfWarn = 0
$script:PfFail = 0

#region Output helpers — keep these terse, the user is staring at it
function script:Pf-Pass($msg) {
    $script:PfPass++
    Write-Host "  " -NoNewline
    Write-Host "PASS " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function script:Pf-Warn($msg, $hint) {
    $script:PfWarn++
    Write-Host "  " -NoNewline
    Write-Host "WARN " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
    if ($hint) {
        Write-Host "       hint: " -ForegroundColor DarkYellow -NoNewline
        Write-Host $hint
    }
}

function script:Pf-Fail($msg, $hint) {
    $script:PfFail++
    Write-Host "  " -NoNewline
    Write-Host "FAIL " -ForegroundColor Red -NoNewline
    Write-Host $msg
    if ($hint) {
        Write-Host "       fix: " -ForegroundColor DarkRed -NoNewline
        Write-Host $hint
    }
}
#endregion

function script:Pf-CheckWindowsVersion {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $build = [int]($os.BuildNumber)
        if ($build -lt 19041) {
            Pf-Fail "Windows build $build is too old for WSL2 (need 19041+)." `
                "Run Windows Update until you reach Windows 10 21H2 or newer."
        } else {
            Pf-Pass "Windows build $build supports WSL2"
        }
    } catch {
        Pf-Warn "Couldn't query Windows version via CIM." `
            "If install.ps1 fails, check your PowerShell + WMI repo."
    }
}

function script:Pf-CheckArch {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { Pf-Pass "CPU architecture: amd64"; return }
        "ARM64" { Pf-Pass "CPU architecture: arm64"; return }
        default {
            Pf-Fail "CPU architecture '$arch' is not supported." `
                "AiSOC requires amd64 or arm64. ARM32/x86 won't work — Docker Desktop doesn't even run there."
        }
    }
}

function script:Pf-CheckRam {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $ramMb = [int]($cs.TotalPhysicalMemory / 1MB)
        if ($ramMb -lt 4096) {
            Pf-Fail "Only ${ramMb} MB of RAM detected (need >= 4096 MB)." `
                "AiSOC won't fit. Close apps, reboot, or run on a bigger machine."
        } elseif ($ramMb -lt 8192) {
            Pf-Warn "Only ${ramMb} MB of RAM detected (recommend 8 GB+)." `
                "The demo will run but may be slow. Close other heavy apps before launching."
        } else {
            Pf-Pass "RAM: ${ramMb} MB total"
        }
    } catch {
        Pf-Warn "Couldn't measure system RAM." `
            "If install fails OOM, you have less than 8 GB free."
    }
}

function script:Pf-CheckDisk {
    try {
        $drive = (Get-Item $InstallRoot).PSDrive.Name
        $info = Get-PSDrive -Name $drive -ErrorAction Stop
        $freeGb = [math]::Round($info.Free / 1GB, 1)
        if ($freeGb -lt 10) {
            Pf-Fail "Only ${freeGb} GB free on ${drive}: (need >= 10 GB)." `
                "Free up disk space or pick a different install drive with -InstallRoot."
        } elseif ($freeGb -lt 20) {
            Pf-Warn "Only ${freeGb} GB free on ${drive}: (recommend 20 GB+)." `
                "Docker images alone are ~5 GB; add data + logs + builds and you'll fill up fast."
        } else {
            Pf-Pass "Disk: ${freeGb} GB free on ${drive}:"
        }
    } catch {
        Pf-Warn "Couldn't check free disk space at $InstallRoot." `
            "Make sure that path exists and is on an NTFS volume."
    }
}

function script:Pf-CheckNetwork {
    if ($SkipNetwork) {
        Pf-Warn "Network checks skipped (-SkipNetwork)." `
            "If image pulls fail, the cause is probably a corporate proxy."
        return
    }
    $failed = 0
    foreach ($url in $script:PfNetHosts) {
        try {
            # Invoke-WebRequest has no equivalent of curl --max-time; use
            # a HttpClient with a 6 s timeout. We only care about *some*
            # response — any 2xx/3xx/401/403 means the host is reachable.
            $req = [System.Net.WebRequest]::Create($url)
            $req.Timeout = 6000
            $req.Method = "HEAD"
            $resp = $null
            try {
                $resp = $req.GetResponse()
                $code = [int]$resp.StatusCode
            } catch [System.Net.WebException] {
                if ($_.Exception.Response) {
                    $code = [int]$_.Exception.Response.StatusCode
                } else {
                    $code = 0
                }
            } finally {
                if ($resp) { $resp.Close() }
            }
            if ($code -ge 200 -and $code -lt 400) { continue }
            if ($code -eq 401 -or $code -eq 403) { continue }
            Pf-Warn "Couldn't reach $url (HTTP $code)." `
                "If you're behind a corporate proxy, set HTTP_PROXY + HTTPS_PROXY before continuing."
            $failed++
        } catch {
            Pf-Warn "Couldn't reach $url ($($_.Exception.Message.Split([Environment]::NewLine)[0]))." `
                "If you're behind a corporate proxy, set HTTP_PROXY + HTTPS_PROXY before continuing."
            $failed++
        }
    }
    if ($failed -eq 0) {
        Pf-Pass "Network: github.com, ghcr.io, npmjs.org all reachable"
    }
}

function script:Pf-CheckWsl2 {
    $wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wslExe) {
        Pf-Fail "WSL2 isn't installed (wsl.exe not found)." `
            "Run 'wsl --install' from an elevated PowerShell, then reboot."
        return
    }
    try {
        # 'wsl --status' returns useful text on success, nothing on
        # missing-distro. We just check exit code + non-empty output.
        $statusOutput = & wsl.exe --status 2>&1
        if ($LASTEXITCODE -ne 0) {
            Pf-Fail "WSL is installed but 'wsl --status' failed (exit $LASTEXITCODE)." `
                "Try 'wsl --update' from an elevated PowerShell, then re-run preflight."
            return
        }
        $hasDistro = (& wsl.exe --list --quiet 2>&1) -match '\S'
        if (-not $hasDistro) {
            Pf-Warn "WSL2 has no default distro installed." `
                "Docker Desktop will set this up, but it'll add ~2 minutes to first launch."
        } else {
            Pf-Pass "WSL2 is installed with at least one distro"
        }
    } catch {
        Pf-Warn "Couldn't query 'wsl --status'." `
            "If Docker Desktop fails to start, run 'wsl --update' first."
    }
}

function script:Pf-CheckDockerDesktop {
    # We don't require Docker to be *running* during preflight (install.ps1
    # may install it), but if it IS installed, sanity-check it.
    $dockerExe = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $dockerExe) {
        return  # install.ps1 will install it; nothing to check here
    }
    try {
        $out = & docker info --format '{{.ServerVersion}}' 2>&1
        if ($LASTEXITCODE -eq 0 -and $out) {
            Pf-Pass "Docker daemon is reachable (server $out)"
        } else {
            Pf-Warn "Docker is installed but the daemon isn't responding." `
                "Open Docker Desktop and wait for the whale icon to go solid before re-running."
        }
    } catch {
        Pf-Warn "Docker is installed but 'docker info' threw." `
            "Open Docker Desktop and wait for it to finish provisioning."
    }
}

function script:Pf-CheckPorts {
    $conflicts = 0
    $reused = 0
    foreach ($spec in $script:PfRequiredPorts) {
        $port = $spec.Port
        $name = $spec.Name
        $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
                    Select-Object -First 1
        if (-not $listener) { continue }

        $owner = "an unknown process"
        try {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $owner = "$($proc.ProcessName) (pid $($proc.Id))" }
        } catch { }

        if ($owner -match 'docker|com\.docker|aisoc') {
            Pf-Warn "Port $port ($name) is held by an existing AiSOC/Docker container ($owner)." `
                "We'll reuse it — but if a previous demo crashed, run 'pnpm aisoc:demo:down' first."
            $reused++
        } else {
            Pf-Fail "Port $port ($name) is in use by $owner." `
                "Stop that process, or set the corresponding *_PORT env var. See docs/QUICK_INSTALL.md#port-conflicts."
            $conflicts++
        }
    }
    if ($conflicts -eq 0 -and $reused -eq 0) {
        $portList = ($script:PfRequiredPorts | ForEach-Object { $_.Port }) -join ', '
        Pf-Pass "All required ports ($portList) are free"
    }
}

function script:Pf-CheckStaleContainers {
    $dockerExe = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $dockerExe) { return }
    try {
        # Containers in 'created' or 'exited' state from a previous run
        # will block 'docker compose up' with a name conflict. Detect
        # them so install.ps1 can offer to clean up.
        $stale = & docker ps -a --filter "name=aisoc-" --filter "status=exited" --filter "status=created" --format "{{.Names}}" 2>$null
        if ($LASTEXITCODE -eq 0 -and $stale) {
            $count = ($stale -split "`n" | Where-Object { $_ -ne '' }).Count
            Pf-Warn "Found $count stopped AiSOC container(s) from a previous run." `
                "Run 'docker rm -f `$(docker ps -aq --filter name=aisoc-)' or 'pnpm aisoc:demo:down' to clean up."
        }
    } catch {
        # Don't fail preflight just because docker query was flaky
    }
}

function script:Pf-CheckHyperVConflict {
    # This is a soft check. WSL2 backend is the recommended Docker
    # Desktop setup. If Hyper-V is enabled but WSL2 isn't, Docker
    # Desktop can still work but is much slower and uses more RAM.
    # We only warn — never fail — because some users have legit reasons.
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        $wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue
        if ($hyperv -and $hyperv.State -eq 'Enabled' -and -not $wslExe) {
            Pf-Warn "Hyper-V is enabled but WSL2 isn't." `
                "Docker Desktop will run on the Hyper-V backend (slower, more RAM). Install WSL2 with 'wsl --install' for best perf."
        }
    } catch {
        # Get-WindowsOptionalFeature requires elevation on some systems
    }
}

# Returns $true if preflight passed (or only warnings), $false if any
# hard failures. install.ps1 treats this as a boolean — we deliberately
# don't return exit codes here because PowerShell makes 0 falsy, which
# would invert the meaning at the call site (a hilarious source of bugs).
function script:Pf-Summary {
    Write-Host ""
    Write-Host "  Summary: $script:PfPass passed, $script:PfWarn warnings, $script:PfFail failures"
    Write-Host ""
    if ($script:PfFail -gt 0) {
        if ($Soft) {
            Write-Host "Preflight reported failures (continuing because -Soft was set)." -ForegroundColor Yellow
            Write-Host "Full troubleshooting: docs/QUICK_INSTALL.md#troubleshooting"
            return $true
        }
        Write-Host "Preflight FAILED. Address the items above and re-run." -ForegroundColor Red
        Write-Host "Full troubleshooting: docs/QUICK_INSTALL.md#troubleshooting"
        return $false
    }
    if ($script:PfWarn -gt 0) {
        Write-Host "Preflight passed with warnings — installer will continue." -ForegroundColor Yellow
        return $true
    }
    Write-Host "Preflight passed cleanly. Ready to install." -ForegroundColor Green
    return $true
}

# Note the casing — install.ps1 calls this as Invoke-AiSOCPreflight to
# match the project name. PowerShell function names are case-insensitive,
# but matching the project casing makes greps useful.
function Invoke-AiSOCPreflight {
    Write-Host ""
    Write-Host "Preflight checks" -ForegroundColor Cyan
    Pf-CheckWindowsVersion
    Pf-CheckArch
    Pf-CheckRam
    Pf-CheckDisk
    Pf-CheckNetwork
    Pf-CheckWsl2
    Pf-CheckDockerDesktop
    Pf-CheckPorts
    Pf-CheckStaleContainers
    Pf-CheckHyperVConflict
    return (Pf-Summary)
}

# When run standalone (not dot-sourced), execute and exit with a
# conventional shell exit code. When dot-sourced, install.ps1 calls
# Invoke-AiSOCPreflight itself and inspects the boolean return value.
if ($MyInvocation.InvocationName -ne '.') {
    if (Invoke-AiSOCPreflight) { exit 0 } else { exit 1 }
}

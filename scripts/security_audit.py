"""Dependency CVE scanner for AiSOC CI.

Subcommands:
  validate-ignores  — check the ignores file is well-formed
  pnpm              — run pnpm audit (staged: high/critical fail, moderate warns)
  python            — run pip-audit per Python service (any finding fails)
  go                — run govulncheck per Go module (any finding fails)

Usage (local):
  python scripts/security_audit.py validate-ignores
  python scripts/security_audit.py pnpm
  python scripts/security_audit.py python
  python scripts/security_audit.py go

Environment variables (CI):
  GITHUB_STEP_SUMMARY  — path to markdown summary file (set by Actions)
  GITHUB_WORKSPACE     — repo root (set by Actions; defaults to cwd)
  PNPM_AUDIT_REGISTRY  — fallback registry if primary returns 403
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__, ["python"])

# ─── Data types ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}

IGNORE_ID_PATTERN = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d{4,}|PYSEC-\d{4}-\d+)$")


@dataclass
class Ignore:
    tool: str
    vuln_id: str
    reason: str
    expires: dt.date


@dataclass
class Finding:
    tool: str
    severity: str
    vuln_id: str
    package: str
    location: str
    title: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    ignored: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Services that could not be scanned at all. Tracked separately from
    #: `warnings` because they mean something categorically different: not "we
    #: scanned and found something questionable" but "we did not scan this".
    #:
    #: A dependency gate that quietly skips a service is worse than one that
    #: fails, because it reads as coverage that is not there. `services/slack-bot`
    #: was dropped this way by a stale poetry.lock, and while it was missing its
    #: lock resolved an idna and a pydantic-settings version with known
    #: advisories that every other service had already moved past (#650).
    unscanned: list[str] = field(default_factory=list)

    @property
    def high_critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in ("high", "critical")]

    @property
    def moderate(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "moderate"]

    @property
    def low_info(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in ("low", "info", "unknown")]


# ─── Ignore loading ──────────────────────────────────────────────────────────


def load_ignores(path: Path, today: dt.date | None = None) -> list[Ignore]:
    """Load and validate the ignores file.

    Format per line: tool|ID|reason|YYYY-MM-DD
    Lines starting with # and blank lines are skipped.
    """
    if today is None:
        today = dt.date.today()

    max_expiry = today + dt.timedelta(days=90)
    allowed_tools = {"pnpm", "python", "go"}
    ignores: list[Ignore] = []

    if not path.exists():
        return ignores

    for line_no, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4:
            raise ValueError(f"Line {line_no}: expected 4 pipe-delimited fields, got {len(parts)}")

        tool, vuln_id, reason, expiry_str = parts

        if tool not in allowed_tools:
            raise ValueError(f"Line {line_no}: invalid tool '{tool}' (expected: {sorted(allowed_tools)})")

        if not IGNORE_ID_PATTERN.match(vuln_id):
            raise ValueError(
                f"Line {line_no}: invalid ID '{vuln_id}' (expected CVE-YYYY-NNNNN, GHSA-xxxx-xxxx-xxxx, GO-YYYY-NNNN, or PYSEC-YYYY-N)"
            )

        if not reason:
            raise ValueError(f"Line {line_no}: reason must not be empty")

        try:
            expiry = dt.date.fromisoformat(expiry_str)
        except ValueError:
            raise ValueError(f"Line {line_no}: invalid date '{expiry_str}' (expected YYYY-MM-DD)")

        if expiry < today:
            raise ValueError(f"Line {line_no}: ignore for {vuln_id} expired on {expiry_str}")

        if expiry > max_expiry:
            raise ValueError(f"Line {line_no}: expiry {expiry_str} exceeds 90-day maximum from today ({max_expiry})")

        ignores.append(Ignore(tool=tool, vuln_id=vuln_id, reason=reason, expires=expiry))

    return ignores


def is_ignored(tool: str, vuln_ids: list[str], ignores: list[Ignore]) -> Ignore | None:
    """Return the matching Ignore if any of the vuln_ids are ignored for this tool."""
    tool_ignores = {ig.vuln_id for ig in ignores if ig.tool == tool}
    for vid in vuln_ids:
        if vid in tool_ignores:
            return next(ig for ig in ignores if ig.tool == tool and ig.vuln_id == vid)
    return None


# ─── pnpm scanner ────────────────────────────────────────────────────────────


def pnpm_install_roots(repo_root: Path) -> list[str]:
    """Every directory holding its own ``pnpm-lock.yaml``, relative to the repo root.

    Read from the tree rather than listed, because a listed set is the artefact
    that drifts. ``apps/mobile`` is a deliberately separate install root — it
    has its own ``pnpm-workspace.yaml`` so its installs stop rewriting the root
    lock — and auditing only the repo root never saw it. Two high-severity
    advisories stood open there while this arm reported a clean workspace.
    """
    proc = subprocess.run(
        ["git", "ls-files", "-z", "*pnpm-lock.yaml"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return sorted({str(Path(p).parent) for p in proc.stdout.split("\0") if p})


def classify_pnpm_audit(
    audit_json: dict[str, Any],
    ignores: list[Ignore],
    location: str = "pnpm workspace",
) -> Report:
    """Classify pnpm audit JSON into a Report using native severity."""
    report = Report()

    for advisory in audit_json.get("advisories", {}).values():
        ghsa = advisory.get("github_advisory_id", "")
        cves = advisory.get("cves", []) or []
        all_ids = [i for i in [ghsa, *cves] if i]
        severity = (advisory.get("severity") or "unknown").lower()
        if severity not in SEVERITY_ORDER:
            severity = "unknown"

        finding = Finding(
            tool="pnpm",
            severity=severity,
            vuln_id=all_ids[0] if all_ids else str(advisory.get("id", "unknown")),
            package=advisory.get("module_name", "unknown"),
            location=location,
            title=advisory.get("title") or advisory.get("overview") or "",
        )

        if is_ignored("pnpm", all_ids, ignores):
            report.ignored.append(finding)
        else:
            report.findings.append(finding)

    return report


def run_pnpm_audit(repo_root: Path, ignores: list[Ignore]) -> Report:
    """Audit every pnpm install root in the tree, not only the repo root."""
    roots = pnpm_install_roots(repo_root)
    merged = Report()
    if not roots:
        # Zero install roots is not zero workspaces vulnerable. Without this the
        # arm prints "pnpm: 0 findings" over a tree with no lockfile in it,
        # which is the sentence a clean audit also prints.
        merged.unscanned.append(f"no pnpm-lock.yaml anywhere in {repo_root} — NOTHING was scanned")
        return merged

    for rel in roots:
        label = "pnpm workspace" if rel == "." else f"pnpm workspace {rel}"
        part = run_pnpm_audit_at(repo_root / rel, label, ignores)
        merged.findings.extend(part.findings)
        merged.ignored.extend(part.ignored)
        merged.warnings.extend(part.warnings)
        merged.unscanned.extend(part.unscanned)
    return merged


def run_pnpm_audit_at(root: Path, label: str, ignores: list[Ignore]) -> Report:
    """Run pnpm audit in one install root, with fallback registry on 403."""
    lockfile = root / "pnpm-lock.yaml"
    if not lockfile.is_file():
        # `pnpm audit` in a directory with no lockfile has nothing to resolve
        # and can still answer with an empty advisory set. Refuse instead:
        # the workspace the audit is supposed to cover is not there.
        report = Report()
        report.unscanned.append(f"no pnpm-lock.yaml at {lockfile} — the workspace was NOT scanned")
        return report

    fallback = os.environ.get("PNPM_AUDIT_REGISTRY", "https://registry.npmjs.org/")

    for attempt, registry in enumerate([None, fallback]):
        env = os.environ.copy()
        if registry:
            env["npm_config_registry"] = registry

        proc = subprocess.run(
            ["pnpm", "audit", "--json"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )

        output = proc.stdout + proc.stderr
        if ("403" in output or "Forbidden" in output) and attempt == 0:
            print(f"Primary registry returned 403; retrying with {fallback}")
            continue

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            print(f"Failed to parse pnpm audit output:\n{output}", file=sys.stderr)
            report = Report()
            # Unparseable output means the workspace was not audited. Recorded
            # as a coverage gap rather than a warning for the same reason the
            # Python arm does it: a warning still exits 0, so the job would
            # report "pnpm: 0 findings" having scanned nothing at all.
            report.unscanned.append(f"{label}: audit returned unparseable output — NOT scanned")
            return report

        return classify_pnpm_audit(data, ignores, label)

    report = Report()
    report.unscanned.append(f"{label}: audit failed on every registry — NOT scanned")
    return report


# ─── Python scanner ──────────────────────────────────────────────────────────


def parse_pip_audit_json(raw: str) -> list[dict[str, Any]]:
    """Parse pip-audit --format=json output."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    if isinstance(data, dict):
        return data.get("dependencies", [])
    if isinstance(data, list):
        return data
    return []


def classify_pip_audit(target: str, dependencies: list[dict[str, Any]], ignores: list[Ignore]) -> Report:
    """Classify pip-audit findings. All findings are treated as high (fail-closed)."""
    report = Report()

    for dep in dependencies:
        for vuln in dep.get("vulns", []):
            aliases = vuln.get("aliases", []) or []
            vuln_id = vuln.get("id", "")
            all_ids = [i for i in [vuln_id, *aliases] if i]

            finding = Finding(
                tool="python",
                severity="high",
                vuln_id=vuln_id or (aliases[0] if aliases else dep.get("name", "unknown")),
                package=f"{dep.get('name', '?')}=={dep.get('version', '?')}",
                location=target,
                title=vuln.get("description", ""),
            )

            if is_ignored("python", all_ids, ignores):
                report.ignored.append(finding)
            else:
                report.findings.append(finding)

    return report


def _export_requirements(service_dir: Path, work_dir: Path) -> Path | None:
    """Export a Poetry project to requirements.txt. Returns path or None on failure."""
    pyproject = service_dir / "pyproject.toml"
    shutil.copy2(pyproject, work_dir / "pyproject.toml")

    lock = service_dir / "poetry.lock"
    if lock.exists():
        shutil.copy2(lock, work_dir / "poetry.lock")

    # Poetry needs a README to avoid warnings
    readme = service_dir / "README.md"
    if readme.exists():
        shutil.copy2(readme, work_dir / "README.md")

    try:
        # Generate lock if missing
        if not (work_dir / "poetry.lock").exists():
            proc = subprocess.run(
                ["poetry", "lock", "--no-interaction"],
                cwd=work_dir,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                return None

        # Export to requirements.txt
        req_path = work_dir / "requirements.txt"
        proc = subprocess.run(
            [
                "poetry",
                "export",
                "--format",
                "requirements.txt",
                "--without-hashes",
                "--output",
                str(req_path),
            ],
            cwd=work_dir,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return None
    except FileNotFoundError:
        return None

    return req_path


def _python_manifests(repo_root: Path) -> list[Path]:
    """Every service or package directory holding a ``pyproject.toml``."""
    found: list[Path] = []
    for search_dir in ("services", "packages"):
        parent = repo_root / search_dir
        if not parent.is_dir():
            continue
        found.extend(child for child in sorted(parent.iterdir()) if child.is_dir() and (child / "pyproject.toml").exists())
    return found


def run_pip_audit(repo_root: Path, ignores: list[Ignore]) -> Report:
    """Run pip-audit on all Python services with pyproject.toml.

    Steps per service:
      1. poetry export → requirements.txt (in a temp dir)
      2. pip-audit -r requirements.txt --format json
    """
    combined = Report()
    manifests = _python_manifests(repo_root)
    if not manifests:
        # Zero manifests discovered is not zero manifests vulnerable. The arm
        # would otherwise print "python: 0 findings" over a tree with nothing
        # in it, which is the same sentence a clean audit of twenty services
        # prints. Recorded as unscanned so `exit_code_for` fails.
        combined.unscanned.append(f"no pyproject.toml under services/ or packages/ in {repo_root} — NOTHING was scanned")
        return combined

    with tempfile.TemporaryDirectory(prefix="security_audit_py_") as tmp:
        tmp_root = Path(tmp)

        for child in manifests:
            target = str(child.relative_to(repo_root))
            safe_name = target.replace("/", "__")
            work_dir = tmp_root / safe_name
            work_dir.mkdir(parents=True, exist_ok=True)

            req_path = _export_requirements(child, work_dir)
            if req_path is None:
                # Not a warning: this service is now unscanned, and the
                # usual cause is a poetry.lock whose content hash no longer
                # matches pyproject.toml. Recorded so `exit_code_for` can
                # fail rather than letting coverage silently shrink.
                combined.unscanned.append(f"{target}: poetry export failed (stale poetry.lock?) — NOT scanned")
                continue

            try:
                cmd = [
                    "pip-audit",
                    "-r",
                    str(req_path),
                    "--format",
                    "json",
                    "--progress-spinner",
                    "off",
                ]

                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_root)
            except FileNotFoundError:
                combined.unscanned.append("pip-audit not found on PATH — NO Python service was scanned")
                break

            if proc.returncode not in (0, 1):
                # pip-audit returns 1 when vulns found; anything else means
                # it did not complete, so this service is unscanned too.
                combined.unscanned.append(f"{target}: pip-audit exited {proc.returncode} — NOT scanned ({proc.stderr[:160].strip()})")
                continue

            deps = parse_pip_audit_json(proc.stdout)
            sub = classify_pip_audit(target, deps, ignores)
            combined.findings.extend(sub.findings)
            combined.ignored.extend(sub.ignored)

    return combined


# ─── Go scanner ──────────────────────────────────────────────────────────────


def parse_govulncheck_json(stdout: str) -> list[dict[str, Any]]:
    """Parse govulncheck -json output (newline-delimited JSON objects)."""
    osv_by_id: dict[str, dict] = {}
    finding_ids: set[str] = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if "osv" in entry:
            osv = entry["osv"]
            osv_by_id[osv["id"]] = osv
        if "finding" in entry:
            finding_ids.add(entry["finding"]["osv"])

    results = []
    for osv_id in sorted(finding_ids):
        osv = osv_by_id.get(osv_id, {})
        results.append(
            {
                "id": osv_id,
                "aliases": osv.get("aliases", []),
                "summary": osv.get("summary", ""),
            }
        )

    return results


def classify_govulncheck(module: str, vulns: list[dict[str, Any]], ignores: list[Ignore]) -> Report:
    """Classify govulncheck findings. All findings are treated as high (fail-closed)."""
    report = Report()

    for vuln in vulns:
        vuln_id = vuln.get("id", "")
        aliases = vuln.get("aliases", []) or []
        all_ids = [i for i in [vuln_id, *aliases] if i]

        finding = Finding(
            tool="go",
            severity="high",
            vuln_id=vuln_id,
            package=module,
            location=module,
            title=vuln.get("summary", ""),
        )

        if is_ignored("go", all_ids, ignores):
            report.ignored.append(finding)
        else:
            report.findings.append(finding)

    return report


def run_govulncheck(repo_root: Path, ignores: list[Ignore]) -> Report:
    """Run govulncheck on all Go modules."""
    combined = Report()

    go_mods: list[Path] = []
    for search_dir in ["services", "packages"]:
        parent = repo_root / search_dir
        if parent.exists():
            go_mods.extend(sorted(parent.rglob("go.mod")))

    if not go_mods:
        # Same reason as the Python arm: "go: 0 findings" over a tree with no
        # go.mod in it reads exactly like a clean scan of every Go module.
        combined.unscanned.append(f"no go.mod under services/ or packages/ in {repo_root} — NOTHING was scanned")
        return combined

    for go_mod in go_mods:
        module_dir = go_mod.parent
        module = str(module_dir.relative_to(repo_root))

        try:
            proc = subprocess.run(
                ["govulncheck", "-json", "./..."],
                cwd=module_dir,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            combined.unscanned.append("govulncheck not found on PATH — NO Go module was scanned")
            break

        if proc.returncode not in (0, 3):
            # govulncheck exits 0 (clean) or 3 (vulnerabilities found); anything
            # else — a build failure, a missing toolchain, an unresolvable
            # module — means this module was not analysed. That is a coverage
            # gap, not a warning: a warning exits 0 and the arm would print
            # "go: 0 findings" for a module it never managed to read.
            combined.unscanned.append(f"{module}: govulncheck exited {proc.returncode} — NOT scanned ({proc.stderr[:160].strip()})")
            continue

        vulns = parse_govulncheck_json(proc.stdout)
        sub = classify_govulncheck(module, vulns, ignores)
        combined.findings.extend(sub.findings)
        combined.ignored.extend(sub.ignored)

    return combined


# ─── Output ──────────────────────────────────────────────────────────────────


def emit_annotations(report: Report) -> None:
    """Emit GitHub Actions annotations."""
    for f in report.high_critical:
        print(f"::error title=security-audit::{f.tool} {f.severity}: {f.vuln_id} in {f.package}")
    for f in report.moderate:
        print(f"::warning title=security-audit::{f.tool} {f.severity}: {f.vuln_id} in {f.package}")
    for f in report.low_info:
        print(f"::notice title=security-audit::{f.tool} {f.severity}: {f.vuln_id} in {f.package}")
    for w in report.warnings:
        print(f"::warning title=security-audit::{w}")
    for gap in report.unscanned:
        # An error, because an unscanned service is a hole in the gate rather
        # than a noteworthy observation about it.
        print(f"::error title=security-audit-coverage::{gap}")


def emit_summary(report: Report) -> None:
    """Write GitHub step summary markdown."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## Dependency Security Audit\n",
        f"- **High/Critical**: {len(report.high_critical)}",
        f"- **Moderate**: {len(report.moderate)}",
        f"- **Low/Info**: {len(report.low_info)}",
        f"- **Ignored**: {len(report.ignored)}",
        "",
    ]

    if report.unscanned:
        lines.append("### Not scanned — coverage gap")
        lines.append("")
        lines.append("These were skipped, so no claim is made about them:")
        lines.append("")
        for gap in report.unscanned:
            lines.append(f"- `{gap}`")
        lines.append("")

    if report.findings:
        lines.append("| Tool | Severity | ID | Package | Location |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(report.findings, key=lambda x: (-SEVERITY_ORDER.get(x.severity, 0), x.tool)):
            lines.append(f"| {f.tool} | {f.severity} | `{f.vuln_id}` | `{f.package}` | {f.location} |")
        lines.append("")

    if report.ignored:
        lines.append("### Suppressed (with expiry)")
        lines.append("| Tool | ID | Package |")
        lines.append("|---|---|---|")
        for f in report.ignored:
            lines.append(f"| {f.tool} | `{f.vuln_id}` | `{f.package}` |")
        lines.append("")

    with open(summary_path, "a") as fh:
        fh.write("\n".join(lines) + "\n")


def exit_code_for(report: Report) -> int:
    """Staged policy: high/critical → 1, a coverage gap → 1, otherwise 0.

    A service that could not be scanned fails the job. That is a deliberate
    change from treating it as a warning, because the two failure modes are
    not comparable: a finding means the gate worked, while an unscanned
    service means the gate did not run and reported success anyway.

    `services/slack-bot` sat in that state — dropped by a stale poetry.lock —
    and while it was missing, its lock resolved an idna and a
    pydantic-settings version with known advisories that every other service
    had already moved past. Nothing in CI would ever have said so (#650).
    """
    if report.high_critical:
        return 1
    if report.unscanned:
        return 1
    return 0


# ─── CLI ─────────────────────────────────────────────────────────────────────


def get_repo_root() -> Path:
    """The repository, per git.

    This used to prefer ``GITHUB_WORKSPACE``, then a ``.git`` probe two levels
    above this file, then ``Path.cwd()``. The last of those is the dangerous
    one: run from anywhere else it returns that directory, and the audit then
    scans whatever manifests happen to be under it and reports success. Under
    Actions the environment variable and ``git rev-parse`` name the same
    directory anyway, so nothing is lost by asking git.
    """
    return repo_root()


def get_ignores_path() -> Path:
    return get_repo_root() / "scripts" / "security_audit_ignores.txt"


def cmd_validate_ignores(args: argparse.Namespace) -> int:
    """Validate the suppression file, and refuse to validate one that is not there.

    ``load_ignores`` returns an empty list for a file that does not exist, so
    this printed "Validated 0 ignore entries." and exited 0 against a
    repository containing nothing at all — the same sentence, and the same
    exit status, as a real run over a file with every suppression retired.
    Found nothing and scanned nothing are not the same result, and the one
    that matters here is the one where the policy file has gone missing.
    """
    path = get_ignores_path()
    if not path.is_file():
        print(f"Ignore policy error: {path} does not exist — refusing to report a validated policy with no policy file.", file=sys.stderr)
        return 1
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        ignores = load_ignores(path)
    except ValueError as e:
        print(f"Ignore policy error: {e}", file=sys.stderr)
        return 1
    print(f"Validated {len(ignores)} ignore entries from {path} ({len(lines)} lines read).")
    return 0


def cmd_pnpm(args: argparse.Namespace) -> int:
    ignores = load_ignores(get_ignores_path())
    report = run_pnpm_audit(get_repo_root(), ignores)
    emit_annotations(report)
    emit_summary(report)
    code = exit_code_for(report)
    n = len(report.findings)
    print(
        f"pnpm: {n} findings ({len(report.high_critical)} high/critical, "
        f"{len(report.moderate)} moderate, {len(report.low_info)} low/info), "
        f"{len(report.ignored)} ignored"
    )
    return code


def cmd_python(args: argparse.Namespace) -> int:
    ignores = load_ignores(get_ignores_path())
    report = run_pip_audit(get_repo_root(), ignores)
    emit_annotations(report)
    emit_summary(report)
    code = exit_code_for(report)
    n = len(report.findings)
    print(f"python: {n} findings, {len(report.ignored)} ignored")
    return code


def cmd_go(args: argparse.Namespace) -> int:
    ignores = load_ignores(get_ignores_path())
    report = run_govulncheck(get_repo_root(), ignores)
    emit_annotations(report)
    emit_summary(report)
    code = exit_code_for(report)
    n = len(report.findings)
    print(f"go: {n} findings, {len(report.ignored)} ignored")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="security_audit",
        description="Dependency CVE scanner for AiSOC CI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate-ignores", help="Validate the ignores file")
    sub.add_parser("pnpm", help="Audit pnpm dependencies")
    sub.add_parser("python", help="Audit Python dependencies")
    sub.add_parser("go", help="Audit Go dependencies")

    args = parser.parse_args()

    handlers = {
        "validate-ignores": cmd_validate_ignores,
        "pnpm": cmd_pnpm,
        "python": cmd_python,
        "go": cmd_go,
    }

    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

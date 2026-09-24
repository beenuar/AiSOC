#!/usr/bin/env python3
"""Quick-win on-ramp CI gates for the AiSOC GitHub front door.

This script bundles every assertion the v0 onramp plan promised would gate
PRs that touch the README front door:

1. README line count ≤ 250 (the README diet target).
2. Every npm / PyPI package referenced in README either resolves on the
   registry today, or is paired with a `Coming … in v8.0` guard so users
   are not directed to a 404.
3. Every reference to `apps/web/public/demo/<asset>` in README is paired
   with an actually-existing file (or is paired with an explicit
   "rendered .mp4 lands with v8.0" guard).

The four-th gate (`aisoc-sandbox` cross-platform smoke test) lives in a
separate matrix job in `.github/workflows/readme-gates.yml` because it
needs Linux + macOS runners.

Usage:
    python3 scripts/readme_gates.py
        # exit 0 on pass, non-zero on first failure.

    python3 scripts/readme_gates.py --no-network
        # skip the npm / PyPI registry probe; useful for offline / sandboxed
        # CI runners that block egress to the public registries.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

# Anything in this list is permitted to appear in README without resolving
# on a public package registry, provided the same line / surrounding block
# carries a "Coming … in v8.0" guard.
KNOWN_UNPUBLISHED = {
    "npm": {"@aisoc/mcp", "@aisoc/sdk", "aisoc-cli"},
    "pypi": {"aisoc-cli", "aisoc-plugin-sdk", "aisoc-sdk", "aisoc-sandbox"},
}

# Maximum number of lines we promise to keep the README at.
README_MAX_LINES = 250

# Phrases that count as a "this is intentionally not yet published" guard.
# The packaging milestone has moved twice, for the same reason each time: the
# blocker is registry credentials, not code, so it cannot be scheduled by
# writing a version number. v8.0 became "close the loop" and packaging moved
# to v8.1; v8.1 became wave-2 features and it moved to v8.2. Older spellings
# are kept so existing docs and blog posts are not flagged, but new README
# text must use the current one — a README shipped *as* vX cannot coherently
# promise that something lands in vX.
#
# v9.0 stops moving the number. The README no longer says packaging "comes
# in" any version, because a README shipped *as* v9.0 promising v9.0 is the
# incoherence this list was created to police, and promising v9.1 would just
# be the fourth slip. It says what is true instead: the pipeline builds and
# packs all eight packages on every tag, and the upload is blocked on
# registry credentials — which is an account action and cannot be scheduled.
#
# Do not add the next version here speculatively. The phrase should move when
# the milestone does, so the list is a record of what was actually promised.
V8_GUARDS = (
    "coming in v8.0",
    "coming in v8.1",
    "coming in v8.2",
    "coming to npm in v8.0",
    "coming to npm in v8.1",
    "coming to npm in v8.2",
    "lands in v8.0",
    "lands in v8.1",
    "lands in v8.2",
    "lands with v8.0",
    "lands with v8.1",
    "lands with v8.2",
    "lands with the v8.0",
    "lands with the v8.1",
    "lands with the v8.2",
    "packaging release",
    # The v9.0 phrasing: a state, not a date.
    "blocked on registry credentials",
    "ready, unpublished",
    "publish lands in v8.0",
    "publish lands in v8.1",
    "publish lands in v8.2",
    "ships in v8.0",
    "ships in v8.1",
    "ships in v8.2",
    "ships with v8.0",
    "ships with v8.1",
    "ships with v8.2",
    "ships with the v8.0",
    "ships with the v8.1",
    "ships with the v8.2",
    "v8.0 launch",
    "with the next phase 2 visuals rollup",
    # Treat explicit monorepo-source-install references as their own guard:
    # if README directs the reader to `pip install -e packages/<pkg>` or
    # links to the in-tree `packages/<pkg>` folder, we're not directing them
    # to a registry path, so the registry-404 risk does not apply.
    "pip install -e packages/aisoc-sandbox",
    "pip install -e packages/aisoc-cli",
    "pip install -e packages/aisoc-sdk",
    "pip install -e packages/aisoc-plugin-sdk",
    "packages/aisoc-sandbox/",
    "packages/aisoc-cli/",
    "packages/aisoc-sdk/",
    "packages/aisoc-plugin-sdk/",
    "pnpm --filter @aisoc/mcp",
    "pnpm --filter @aisoc/sdk",
    "monorepo source build",
    "monorepo source-build",
)


@dataclass
class GateFailure:
    gate: str
    detail: str

    def render(self) -> str:
        return f"FAIL [{self.gate}] {self.detail}"


def _read(text_path: Path) -> str:
    return text_path.read_text(encoding="utf-8")


def _has_guard(window: str) -> bool:
    lowered = window.lower()
    return any(phrase in lowered for phrase in V8_GUARDS)


# ── Gate 1: README line count ────────────────────────────────────────────────


def gate_readme_line_count() -> list[GateFailure]:
    """README must stay ≤ README_MAX_LINES lines."""
    actual = sum(1 for _ in README.read_text(encoding="utf-8").splitlines())
    if actual > README_MAX_LINES:
        return [
            GateFailure(
                "readme-line-count",
                f"README has {actual} lines; budget is {README_MAX_LINES}. " f"Move detail to apps/docs/ or RELEASES.md.",
            )
        ]
    return []


# ── Gate 2: Package references resolve or are guarded ────────────────────────


def _npm_exists(package: str) -> bool:
    """Return True iff the npm registry returns a 200 for the package."""
    url = f"https://registry.npmjs.org/{package}"
    request = Request(url, method="HEAD")
    try:
        with urlopen(request, timeout=15) as response:
            return 200 <= response.status < 300
    except HTTPError as exc:
        if exc.code == 404:
            return False
        return False
    except URLError:
        return False


def _pypi_exists(package: str) -> bool:
    """Return True iff the PyPI JSON endpoint returns a 200 for the package."""
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urlopen(url, timeout=15) as response:
            return 200 <= response.status < 300
    except HTTPError as exc:
        if exc.code == 404:
            return False
        return False
    except URLError:
        return False


_NPM_PATTERN = re.compile(r"@aisoc/[a-z0-9][a-z0-9-]*")
_PIP_PATTERN = re.compile(r"\baisoc-(?:cli|plugin-sdk|sdk|sandbox)\b")


def _surrounding_lines(text: str, line_idx: int, radius: int = 3) -> str:
    lines = text.splitlines()
    start = max(0, line_idx - radius)
    end = min(len(lines), line_idx + radius + 1)
    return "\n".join(lines[start:end])


def gate_package_references(check_network: bool) -> list[GateFailure]:
    """Every package referenced in README must resolve or be guarded."""
    text = _read(README)
    lines = text.splitlines()
    failures: list[GateFailure] = []

    npm_to_lines: dict[str, list[int]] = {}
    pip_to_lines: dict[str, list[int]] = {}

    for idx, line in enumerate(lines):
        for match in _NPM_PATTERN.findall(line):
            npm_to_lines.setdefault(match, []).append(idx)
        for match in _PIP_PATTERN.findall(line):
            pip_to_lines.setdefault(match, []).append(idx)

    def _check_package(
        name: str,
        registry: str,
        line_idxs: list[int],
        exists: Callable[[str], bool],
        known_unpublished: set[str],
    ) -> None:
        any_line_guarded = any(_has_guard(_surrounding_lines(text, idx)) for idx in line_idxs)
        if any_line_guarded:
            return
        if name in known_unpublished:
            failures.append(
                GateFailure(
                    f"package-resolves[{registry}]",
                    f"{name} is on the known-unpublished list but no v8.0 "
                    f"guard was found within 3 lines of any reference in "
                    f"README. Add one of: " + ", ".join(sorted(V8_GUARDS)),
                )
            )
            return
        if not check_network:
            return
        if not exists(name):
            failures.append(
                GateFailure(
                    f"package-resolves[{registry}]",
                    f"{name} does not resolve on {registry} and has no "
                    f"v8.0 guard within 3 lines of any reference in README. "
                    f"Either publish it, drop the reference, or add a "
                    f"'Coming in v8.0' guard.",
                )
            )

    for name, indices in sorted(npm_to_lines.items()):
        _check_package(name, "npm", indices, _npm_exists, KNOWN_UNPUBLISHED["npm"])
    for name, indices in sorted(pip_to_lines.items()):
        _check_package(name, "PyPI", indices, _pypi_exists, KNOWN_UNPUBLISHED["pypi"])
    return failures


# ── Gate 3: Demo asset references are honest ────────────────────────────────


# Both directories the README embeds from. `screenshots/` carries the four
# console tiles above the fold and was previously unchecked entirely, so a
# renamed or deleted tile would have rendered as a broken image on the busiest
# page the project has without failing anything.
_VISUAL_ASSET_PATTERN = re.compile(
    r"apps/web/public/(?P<dir>demo|screenshots)/" r"(?P<asset>[A-Za-z0-9._-]+\.(?:mp4|gif|webm|webp|png|jpg|svg))"
)


def gate_demo_asset_references() -> list[GateFailure]:
    """If README points at an `apps/web/public/{demo,screenshots}/<asset>`
    file, the file must either exist on disk or sit next to an explicit
    "rendered ... lands with v8.0" guard."""
    text = _read(README)
    failures: list[GateFailure] = []
    for match in _VISUAL_ASSET_PATTERN.finditer(text):
        directory = match.group("dir")
        asset = match.group("asset")
        path = REPO_ROOT / "apps" / "web" / "public" / directory / asset
        if path.exists():
            continue
        # Find the line containing this match.
        line_idx = text.count("\n", 0, match.start())
        window = _surrounding_lines(text, line_idx, radius=4)
        if _has_guard(window):
            continue
        failures.append(
            GateFailure(
                "demo-asset",
                f"README references apps/web/public/{directory}/{asset} but "
                f"the file does not exist and no v8.0 guard was found within "
                f"4 lines of the reference. Refresh the visuals with the "
                f"console-visuals workflow, or fix the path.",
            )
        )
    return failures


# ── Gate 4 placeholder ──────────────────────────────────────────────────────
#
# The aisoc-sandbox cross-platform offline smoke test does not run in this
# script — it lives in the CI matrix at .github/workflows/readme-gates.yml.
# This gate placeholder records that fact so a contributor running the
# script locally on (say) macOS still sees an unambiguous "you must also
# verify aisoc-sandbox" hint in the output.


def gate_sandbox_offline_smoke() -> list[GateFailure]:
    """Run `aisoc-sandbox demo --scenario <each>` against the local source."""
    package_root = REPO_ROOT / "packages" / "aisoc-sandbox"
    src = package_root / "src"
    if not src.exists():
        return [
            GateFailure(
                "sandbox-offline",
                "packages/aisoc-sandbox/src is missing — the sandbox package " "was deleted or moved. Check phase3-sandbox.",
            )
        ]
    failures: list[GateFailure] = []
    scenarios = [
        "lateral-movement",
        "aws-credential-exfil",
        "phishing-payload",
        "kubernetes-privesc",
        "github-token-theft",
    ]
    env = {"PYTHONPATH": str(src), "PATH": __import__("os").environ.get("PATH", "")}
    for scenario in scenarios:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aisoc_sandbox.cli",
                "demo",
                "--scenario",
                scenario,
                "--json",
            ],
            capture_output=True,
            env=env,
            timeout=30,
        )
        if result.returncode != 0:
            failures.append(
                GateFailure(
                    "sandbox-offline",
                    f"`aisoc-sandbox demo --scenario {scenario}` exited "
                    f"with code {result.returncode}:\n" + result.stderr.decode("utf-8", errors="replace")[:400],
                )
            )
            continue
        try:
            payload = json.loads(result.stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(
                GateFailure(
                    "sandbox-offline",
                    f"`aisoc-sandbox demo --scenario {scenario}` did not " f"emit valid JSON: {exc}",
                )
            )
            continue
        steps = payload.get("ledger", [])
        if len(steps) != 4:
            failures.append(
                GateFailure(
                    "sandbox-offline",
                    f"Scenario {scenario} produced {len(steps)} ledger " f"steps; expected exactly 4 (Detect/Triage/Hunt/" f"Respond).",
                )
            )
    return failures


# ── Driver ──────────────────────────────────────────────────────────────────


# ── Gate 4: README figures must match their generated source of truth ────────
#
# The README quotes two numbers that are generated elsewhere: how many detection
# rules actually execute, and how many product claims are CI-gated. Both drifted
# — the README advertised 947 executable rules while the truth table said 833,
# and 62 GATED while the matrix said 72. Neither is a typo class of error: a
# reader has no way to tell the front page from the generated artifact, so the
# larger number is simply believed. This gate makes the README unable to quote a
# figure its source disagrees with.

TRUTH_TABLE = REPO_ROOT / "docs" / "detections" / "truth-table.md"
CLAIM_MATRIX = REPO_ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"

#: Other documents that quote the claim-gate tally. Each is checked the
#: same way the README is: a figure repeated in prose drifts from its
#: source the first time the source changes, and a compliance page
#: quoting a stale number is worse than one quoting none.
FIGURE_DOCS = (REPO_ROOT / "apps" / "docs" / "docs" / "compliance" / "evidence-pack.md",)


def _truth_table_executable() -> int | None:
    """The executable-rule count from the generated truth table."""
    if not TRUTH_TABLE.exists():
        return None
    m = re.search(
        r"\|\s*\*\*executable \(loaded by the engine\)\*\*\s*\|\s*\*\*(\d+)\*\*",
        _read(TRUTH_TABLE),
    )
    return int(m.group(1)) if m else None


def _matrix_counts() -> tuple[int, int] | None:
    """(gated, partial) counted from the matrix rows themselves, not its prose."""
    if not CLAIM_MATRIX.exists():
        return None
    gated = partial = 0
    for line in _read(CLAIM_MATRIX).splitlines():
        if not line.lstrip().startswith("|"):
            continue
        if "NO GATE" in line:
            continue
        if "PARTIAL" in line:
            partial += 1
        elif "GATED" in line:
            gated += 1
    return (gated, partial) if (gated or partial) else None


def gate_readme_figures() -> list[GateFailure]:
    """Detection and claim-gate figures in the README must match their source."""
    failures: list[GateFailure] = []
    readme = _read(README)

    executable = _truth_table_executable()
    if executable is not None:
        # Any "<n> executable" or "corpus (<n> rules)" phrasing in the README.
        quoted = {
            int(n) for n in re.findall(r"(\d{3,5})\s+executable", readme) + re.findall(r"detection corpus \((\d{3,5}) rules\)", readme)
        }
        for n in sorted(quoted - {executable}):
            failures.append(
                GateFailure(
                    "readme-figures",
                    f"README claims {n} executable detection rules; "
                    f"docs/detections/truth-table.md says {executable}. "
                    f"Regenerate with scripts/detection_truth_table.py and use its number.",
                )
            )

    counts = _matrix_counts()
    if counts is not None:
        gated, partial = counts
        # The matrix's own Summary block is checked first, and it is the one
        # this gate used to skip. Every prose restatement elsewhere was
        # compared against the rows while the document doing the claiming was
        # not — so the summary read "GATED: 108" against 109 counted rows and
        # every check in the repository passed. The file even carries a
        # counting note about this exact failure; it recurred because the gate
        # written afterwards pointed outward only.
        sources: list[tuple[str, str]] = [
            (
                str(CLAIM_MATRIX.relative_to(REPO_ROOT)) if CLAIM_MATRIX.is_relative_to(REPO_ROOT) else CLAIM_MATRIX.name,
                _read(CLAIM_MATRIX),
            ),
            ("README", readme),
        ]
        for path in FIGURE_DOCS:
            if not path.exists():
                continue
            try:
                label = str(path.relative_to(REPO_ROOT))
            except ValueError:
                # The tests repoint REPO_ROOT at a scratch tree; the label is
                # cosmetic and must not take the gate down with it.
                label = path.name
            sources.append((label, _read(path)))

        for label, text in sources:
            for m in re.finditer(r"(\d+)\s+(?:rows\s+)?`?GATED`?[,/\s]+(?:and\s+)?(\d+)\s+`?PARTIAL", text):
                if (int(m.group(1)), int(m.group(2))) != (gated, partial):
                    failures.append(
                        GateFailure(
                            "readme-figures",
                            f"{label} claims {m.group(1)} GATED / {m.group(2)} "
                            f"PARTIAL; docs/audit/CLAIM_TO_GATE_MATRIX.md has "
                            f"{gated} GATED / {partial} PARTIAL.",
                        )
                    )
            # The bullet-list form the matrix's Summary uses. The inline
            # pattern above needs both figures on one line and silently
            # matched nothing here, which is how the stale count survived.
            for label_word, expected in (("GATED", gated), ("PARTIAL", partial)):
                for m in re.finditer(rf"^[-*]\s+`?{label_word}`?:\s*(\d+)", text, re.MULTILINE):
                    if int(m.group(1)) != expected:
                        failures.append(
                            GateFailure(
                                "readme-figures",
                                f"{label} summarises {label_word}: {m.group(1)}; "
                                f"docs/audit/CLAIM_TO_GATE_MATRIX.md has {expected} "
                                f"{label_word} rows. Recompute with "
                                f"scripts/check_claim_gate_matrix.py rather than editing the number.",
                            )
                        )

    return failures


def _run_all(check_network: bool, skip_sandbox: bool) -> list[GateFailure]:
    failures: list[GateFailure] = []
    failures.extend(gate_readme_line_count())
    failures.extend(gate_package_references(check_network))
    failures.extend(gate_demo_asset_references())
    failures.extend(gate_readme_figures())
    if not skip_sandbox:
        failures.extend(gate_sandbox_offline_smoke())
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip the npm / PyPI registry probe.",
    )
    parser.add_argument(
        "--skip-sandbox",
        action="store_true",
        help="Skip the local aisoc-sandbox offline smoke test (the CI " "matrix runs this independently).",
    )
    args = parser.parse_args(argv)
    failures = _run_all(
        check_network=not args.no_network,
        skip_sandbox=args.skip_sandbox,
    )
    if not failures:
        print("readme-gates: OK")
        return 0
    for failure in failures:
        print(failure.render(), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

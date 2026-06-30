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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
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
V8_GUARDS = (
    "coming in v8.0",
    "coming to npm in v8.0",
    "lands in v8.0",
    "lands with v8.0",
    "lands with the v8.0",
    "publish lands in v8.0",
    "ships in v8.0",
    "ships with v8.0",
    "ships with the v8.0",
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
                f"README has {actual} lines; budget is {README_MAX_LINES}. "
                f"Move detail to apps/docs/ or RELEASES.md.",
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
        any_line_guarded = any(
            _has_guard(_surrounding_lines(text, idx)) for idx in line_idxs
        )
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


_DEMO_ASSET_PATTERN = re.compile(
    r"apps/web/public/demo/(?P<asset>[A-Za-z0-9._-]+\.(?:mp4|gif|webm|webp|png|jpg))"
)


def gate_demo_asset_references() -> list[GateFailure]:
    """If README points at an `apps/web/public/demo/<asset>` file, the file
    must either exist on disk or sit next to an explicit "rendered ... lands
    with v8.0" guard."""
    text = _read(README)
    failures: list[GateFailure] = []
    for match in _DEMO_ASSET_PATTERN.finditer(text):
        asset = match.group("asset")
        path = REPO_ROOT / "apps" / "web" / "public" / "demo" / asset
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
                f"README references apps/web/public/demo/{asset} but the "
                f"file does not exist and no v8.0 guard was found within "
                f"4 lines of the reference.",
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
                "packages/aisoc-sandbox/src is missing — the sandbox package "
                "was deleted or moved. Check phase3-sandbox.",
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
                    f"with code {result.returncode}:\n"
                    + result.stderr.decode("utf-8", errors="replace")[:400],
                )
            )
            continue
        try:
            payload = json.loads(result.stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(
                GateFailure(
                    "sandbox-offline",
                    f"`aisoc-sandbox demo --scenario {scenario}` did not "
                    f"emit valid JSON: {exc}",
                )
            )
            continue
        steps = payload.get("ledger", [])
        if len(steps) != 4:
            failures.append(
                GateFailure(
                    "sandbox-offline",
                    f"Scenario {scenario} produced {len(steps)} ledger "
                    f"steps; expected exactly 4 (Detect/Triage/Hunt/"
                    f"Respond).",
                )
            )
    return failures


# ── Driver ──────────────────────────────────────────────────────────────────


def _run_all(check_network: bool, skip_sandbox: bool) -> list[GateFailure]:
    failures: list[GateFailure] = []
    failures.extend(gate_readme_line_count())
    failures.extend(gate_package_references(check_network))
    failures.extend(gate_demo_asset_references())
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
        help="Skip the local aisoc-sandbox offline smoke test (the CI "
        "matrix runs this independently).",
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

#!/usr/bin/env python3
"""Recount every figure the README publishes, from the tree.

A number typed into a README is a number that goes stale silently. This
script is the single source for the project's quantitative claims, and
`--check` fails when the README disagrees with it — so a figure cannot drift
without a red build.

Each figure counts the thing the claim is *about*, which is not always the
obvious file count:

* **Connectors** come from the registry the service actually loads, not from
  the number of files in the connectors directory. A module that is not
  registered is not a connector a user can configure.
* **Detections** count what the *engine* loads. `detections/*.yaml` is a
  generated projection and includes thousands of quarantined imports the
  engine never evaluates; publishing that number would overstate coverage by
  an order of magnitude.
* **Services** count deployable compose services, split by profile, because
  "19 services" means something very different if 10 of them are optional.

Usage:
    python3 scripts/project_stats.py            # human-readable
    python3 scripts/project_stats.py --json     # machine-readable
    python3 scripts/project_stats.py --check    # fail if README disagrees
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()


def _connectors() -> int | None:
    """Registered connector classes, read from the registry literal."""
    init = ROOT / "services" / "connectors" / "app" / "connectors" / "__init__.py"
    if not init.is_file():
        return None
    text = init.read_text(encoding="utf-8")
    match = re.search(r"_CONNECTOR_CLASSES\s*[:=][^=]*=\s*[\(\[\{](.*?)[\)\]\}]\s*\n", text, re.S)
    if not match:
        return None
    # Count class references, not commas: a trailing comma would inflate it.
    return len(re.findall(r"\b[A-Z]\w*Connector\b", match.group(1)))


def _executable_detections() -> int | None:
    """Rules the fusion engine loads — the only ones that can fire.

    Both compiled rulesets count. The engine reads the native specs and the
    imported rules the Sigma compiler translated and proved fireable, so
    counting one of them reports a number no deployment runs.
    """
    data_dir = ROOT / "services" / "fusion" / "app" / "data"
    total: int | None = None
    for name in ("detection_ruleset.json", "detection_ruleset_imported.json"):
        path = data_dir / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return None
        rules = data.get("rules") if isinstance(data, dict) else data
        if not isinstance(rules, list):
            return None
        total = len(rules) if total is None else total + len(rules)
    return total


def _detection_files_on_disk() -> int:
    """Every YAML under detections/, including the quarantine.

    Reported alongside the executable count so the gap is visible rather than
    conflated. The two numbers have been published interchangeably before.
    """
    d = ROOT / "detections"
    return sum(1 for _ in d.rglob("*.yaml")) if d.is_dir() else 0


def _compose_services() -> dict[str, int]:
    """Deployable services, split by profile."""
    try:
        import yaml
    except ImportError:
        return {}
    f = ROOT / "docker-compose.yml"
    if not f.is_file():
        return {}
    doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    services = doc.get("services") or {}
    core = [n for n, s in services.items() if not (s or {}).get("profiles")]
    return {"core": len(core), "total": len(services), "optional": len(services) - len(core)}


def _claim_gate_rows() -> dict[str, int]:
    """Claim-to-gate matrix rows by status."""
    f = ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"
    if not f.is_file():
        return {}
    counts = {"GATED": 0, "PARTIAL": 0, "NO GATE": 0}
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        status = cells[3].upper()
        # `GATED (ratchet)` counts as gated; check NO GATE first so the
        # substring "GATE" does not swallow it.
        if "NO GATE" in status:
            counts["NO GATE"] += 1
        elif "PARTIAL" in status:
            counts["PARTIAL"] += 1
        elif "GATED" in status:
            counts["GATED"] += 1
    counts["total"] = counts["GATED"] + counts["PARTIAL"] + counts["NO GATE"]
    return counts


def _python_services() -> int:
    d = ROOT / "services"
    return sum(1 for p in d.iterdir() if p.is_dir() and not p.name.startswith(".")) if d.is_dir() else 0


def collect() -> dict:
    stats: dict = {
        "connectors": _connectors(),
        "detections_executable": _executable_detections(),
        "detections_files_on_disk": _detection_files_on_disk(),
        "services_in_repo": _python_services(),
        "compose": _compose_services(),
        "claim_gate": _claim_gate_rows(),
    }
    version = ROOT / "VERSION"
    if version.is_file():
        stats["version"] = version.read_text(encoding="utf-8").strip()
    return stats


def _render(stats: dict) -> str:
    c = stats["compose"]
    g = stats["claim_gate"]
    lines = [
        "",
        f"  AiSOC {stats.get('version', '?')} — figures recounted from the tree",
        "",
        f"  Connectors (registered)        {stats['connectors']}",
        f"  Detections (engine loads)      {stats['detections_executable']}",
        f"  Detection files on disk        {stats['detections_files_on_disk']}  (includes quarantined imports the engine never evaluates)",
        f"  Services in repo               {stats['services_in_repo']}",
    ]
    if c:
        lines.append(f"  Compose services               {c['core']} core + {c['optional']} optional = {c['total']}")
    if g:
        lines.append(
            f"  Claim-to-gate matrix           {g['total']} rows — {g['GATED']} gated, {g['PARTIAL']} partial, {g['NO GATE']} ungated"
        )
    lines.append("")
    return "\n".join(lines)


#: README phrases that must agree with the counts above. Each is a
#: (regex, stat-path) pair; the regex must capture the number in group 1.
README_CLAIMS: list[tuple[str, tuple[str, ...]]] = [
    (r"\*\*(\d+) click-and-connect data connectors\*\*", ("connectors",)),
    (r"(\d+) executable detection", ("detections_executable",)),
    (r"(\d+) GATED", ("claim_gate", "GATED")),
]


def _lookup(stats: dict, path: tuple[str, ...]):
    cur = stats
    for key in path:
        cur = cur.get(key) if isinstance(cur, dict) else None
        if cur is None:
            return None
    return cur


def check(stats: dict) -> int:
    readme = ROOT / "README.md"
    if not readme.is_file():
        print("README.md not found", file=sys.stderr)
        return 1
    text = readme.read_text(encoding="utf-8")
    failures = []
    for pattern, path in README_CLAIMS:
        expected = _lookup(stats, path)
        if expected is None:
            continue
        for match in re.finditer(pattern, text):
            claimed = int(match.group(1))
            if claimed != expected:
                failures.append(f"README claims {claimed} for {'.'.join(path)}; the tree has {expected} (pattern: {pattern})")
    if failures:
        print("project-stats: README disagrees with the tree\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print("\nRe-run `make stats` and correct the README.\n", file=sys.stderr)
        return 1
    print("project-stats: OK — every checked README figure matches the tree")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--check", action="store_true", help="fail if the README disagrees")
    args = ap.parse_args()

    stats = collect()
    if args.check:
        return check(stats)
    print(json.dumps(stats, indent=2) if args.json else _render(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())

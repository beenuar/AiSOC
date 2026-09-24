#!/usr/bin/env python3
"""Gate: every dashboard panel queries a metric some service emits.

A panel for a metric nothing exports renders "No data" forever. That is
worse than having no panel, because it teaches people that empty panels are
normal — and once they believe that, a genuinely dead service looks exactly
like an uninstrumented one.

Also checks datasource references resolve. Grafana does not warn about a
dangling datasource uid: the panel just shows nothing, and a trace-to-metrics
link silently does nothing when clicked, which reads as "tracing is not
wired up" rather than as a typo. The Tempo datasource shipped pointing at
`aisoc-prometheus` before any datasource declared that uid.

Run:  python3 scripts/check_grafana_dashboards.py
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

REPO_ROOT = repo_root()
GRAFANA = REPO_ROOT / "infra" / "docker" / "grafana"
DASHBOARDS = GRAFANA / "dashboards"
DATASOURCES = GRAFANA / "datasources"
SERVICES = REPO_ROOT / "services"

#: Metric names a PromQL expression may reference. Recovered from the
#: expression rather than parsed properly: a full PromQL parser is a
#: dependency this gate does not need, and the names are the only part that
#: has to be right.
_METRIC_RE = re.compile(r"\b([a-z][a-z0-9_]*_(?:total|seconds|bytes|count|info))\b")

#: Prometheus appends these to a histogram or summary, so a dashboard
#: legitimately references a name no service literally declares.
_DERIVED_SUFFIXES = ("_bucket", "_sum", "_count")

#: Metrics exported by something other than our own code — the exporters
#: bundled into the compose stack. Listed so the exemption is reviewable
#: rather than implied by a loose regex.
KNOWN_EXTERNAL: frozenset[str] = frozenset(
    {
        "up",
        "scrape_duration_seconds",
        "process_cpu_seconds_total",
        "process_resident_memory_bytes",
    }
)


def declared_metrics() -> set[str]:
    """Metric names declared anywhere under services/.

    A string-literal scan rather than an import: collecting metric names
    should not need every service's dependencies installed, and a gate
    that needs a database container is a gate that gets disabled.
    """
    names: set[str] = set()
    for path in SERVICES.rglob("*"):
        if path.suffix not in {".py", ".go", ".ts"} or not path.is_file():
            continue
        if "/tests/" in str(path) or "/node_modules/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        names |= set(_METRIC_RE.findall(text))
    return names


def dashboard_metrics(dashboard: dict) -> set[str]:
    names: set[str] = set()
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            expr = target.get("expr", "")
            names |= set(_METRIC_RE.findall(expr))
            # Histogram buckets: `foo_seconds_bucket` -> `foo_seconds`.
            names |= {m.removesuffix("_bucket") for m in re.findall(r"\b([a-z][a-z0-9_]*_bucket)\b", expr)}
    return names


def declared_datasource_uids() -> set[str]:
    uids: set[str] = set()
    for path in DATASOURCES.glob("*.yaml"):
        for match in re.finditer(r"^\s*uid:\s*(\S+)\s*$", path.read_text(), re.M):
            uids.add(match.group(1))
    return uids


def referenced_datasource_uids() -> set[str]:
    uids: set[str] = set()
    for path in DASHBOARDS.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        uids |= set(re.findall(r'"uid"\s*:\s*"([^"]+)"', text))
    # Cross-datasource links (trace-to-metrics, exemplars) are references too.
    for path in DATASOURCES.glob("*.yaml"):
        for match in re.finditer(r"^\s*datasourceUid:\s*(\S+)\s*$", path.read_text(), re.M):
            uids.add(match.group(1))
    return uids


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)

    # These two branches used to disagree about the same thing. An empty
    # dashboards directory failed; a *missing* one printed "nothing to check"
    # and passed — so the larger loss was the one the gate forgave, and
    # deleting the directory was enough to make it green. Both are now the
    # same answer, because neither is distinguishable from "the walk broke".
    if not DASHBOARDS.is_dir():
        print(
            f"grafana-dashboards: no dashboards directory at {DASHBOARDS}. "
            f"Nothing to check and nothing checked are the same word here, so this fails: "
            f"the dashboards are the artefact the SLO alerts and the observability claims "
            f"point at.",
            file=sys.stderr,
        )
        return 1

    files = sorted(DASHBOARDS.glob("*.json"))
    if not files:
        print(
            "grafana-dashboards: dashboards directory exists but is empty",
            file=sys.stderr,
        )
        return 1

    errors: list[str] = []
    exported = declared_metrics()

    for path in files:
        try:
            dashboard = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}: invalid JSON ({exc})")
            continue

        # A dashboard uid is what links and alerts reference; without one
        # Grafana assigns a random one per import and every link rots.
        if not dashboard.get("uid"):
            errors.append(f"{path.name}: no uid, so links to it cannot be stable")

        for metric in sorted(dashboard_metrics(dashboard)):
            if metric in KNOWN_EXTERNAL or metric in exported:
                continue
            if any(metric.removesuffix(suffix) in exported for suffix in _DERIVED_SUFFIXES):
                continue
            errors.append(
                f"{path.name}: panel queries {metric!r}, which no service "
                f"declares. The panel will read 'No data' forever, which "
                f"teaches people to ignore empty panels."
            )

    declared = declared_datasource_uids()
    for uid in sorted(referenced_datasource_uids()):
        # Panel-level uids are datasource uids; anything else in a dashboard
        # JSON matching "uid" is the dashboard's own, which is fine.
        if uid in declared:
            continue
        if any(json.loads(p.read_text()).get("uid") == uid for p in files):
            continue
        errors.append(
            f"datasource uid {uid!r} is referenced but no datasource declares "
            f"it. Grafana does not warn about this — the panel or link simply "
            f"does nothing."
        )

    if errors:
        print("GRAFANA DASHBOARD GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        f"grafana-dashboards: OK — {len(files)} dashboard(s), every panel "
        f"queries a metric a service emits and every datasource resolves"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

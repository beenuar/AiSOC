#!/usr/bin/env python3
"""
Phase 2.6 — audit that every FastAPI service installs the shared
``/livez`` + ``/readyz`` probes from :mod:`app._health`.

Background
----------

Before Phase 2.6 most services exposed only a ``/health`` endpoint
that conflated liveness ("the process is running") and readiness
("the process is wired up to its dependencies and can serve
traffic"). Kubernetes-style orchestrators need both signals
separately so they can keep a slow-starting pod in the cluster
while still draining it cleanly on shutdown.

This script enforces the invariant that every service which
ships a ``main.py`` under ``services/<svc>/app/`` also ships a
copy of ``_health.py`` next to it AND wires the probes into
that ``main.py``. Without this gate a new service can be added
that boots fine but never produces readiness signal — a silent
operational gap that wouldn't surface until a 3am page.

Usage
-----

::

    # Print the audit table.
    python3 scripts/audit_health_probes.py

    # Exit non-zero on drift (use this in CI).
    python3 scripts/audit_health_probes.py --check
"""

from __future__ import annotations

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVICES_DIR = REPO_ROOT / "services"

# Services that are Python FastAPI apps (excludes the Go ingest
# service, the Node realtime service, and any service without an
# ``app/main.py`` file).
def discover_fastapi_services() -> list[str]:
    out: list[str] = []
    for svc in sorted(SERVICES_DIR.iterdir()):
        if not svc.is_dir():
            continue
        main = svc / "app" / "main.py"
        if main.is_file():
            out.append(svc.name)
    return out


def audit_service(svc: str) -> tuple[bool, bool, bool]:
    """Return ``(has_module, imports_helper, wires_routes)``.

    * ``has_module``    — ``services/<svc>/app/_health.py`` exists.
    * ``imports_helper``— ``app/main.py`` imports ``install_health_routes``.
    * ``wires_routes``  — ``app/main.py`` calls ``install_health_routes``.
    """
    base = SERVICES_DIR / svc / "app"
    has_module = (base / "_health.py").is_file()
    main_text = (base / "main.py").read_text(encoding="utf-8")
    imports_helper = "from app._health import install_health_routes" in main_text
    wires_routes = "install_health_routes(app" in main_text
    return has_module, imports_helper, wires_routes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any FastAPI service is missing the probes",
    )
    args = parser.parse_args()

    services = discover_fastapi_services()
    print(f"{'service':<18} {'_health.py':<11} {'import':<7} {'wire':<5}")
    print(f"{'-' * 18} {'-' * 11} {'-' * 7} {'-' * 5}")
    drift: list[str] = []
    for svc in services:
        has_mod, has_import, has_wire = audit_service(svc)
        marker_mod = "yes" if has_mod else "NO"
        marker_import = "yes" if has_import else "NO"
        marker_wire = "yes" if has_wire else "NO"
        print(f"{svc:<18} {marker_mod:<11} {marker_import:<7} {marker_wire:<5}")
        if not (has_mod and has_import and has_wire):
            drift.append(svc)

    if args.check and drift:
        print(
            "\nFAIL: the following FastAPI services do not install the "
            "Phase 2.6 /livez + /readyz probes from app._health:\n  - "
            + "\n  - ".join(drift),
            file=sys.stderr,
        )
        print(
            "\nFix: copy services/api/app/_health.py into "
            "services/<svc>/app/_health.py and call install_health_routes("
            "app, service_name='aisoc-<svc>') in app/main.py.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

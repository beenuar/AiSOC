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

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
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


#: The copy every other one is compared against. Arbitrary but fixed: what
#: matters is that there is one answer to "which is right" rather than
#: thirteen files that each look plausible on their own.
REFERENCE_SERVICE = "api"


def audit_service(svc: str, reference: bytes | None) -> tuple[bool, bool, bool, bool]:
    """Return ``(has_module, imports_helper, wires_routes, in_sync)``.

    * ``has_module``    — ``services/<svc>/app/_health.py`` exists.
    * ``imports_helper``— ``app/main.py`` imports ``install_health_routes``.
    * ``wires_routes``  — ``app/main.py`` calls ``install_health_routes``.
    * ``in_sync``       — that copy is byte-identical to the reference one.

    ``in_sync`` is checked because the module's own docstring claims the
    thirteen copies are kept in sync and nothing verified it. They happened
    to be identical, so the claim was true by luck: any change landing in one
    tree would have left the other twelve serving the older contract, and a
    probe that answers differently per service is worse than one that is
    wrong everywhere — it makes a fleet-wide readiness answer unreadable.
    The docstring also pointed at ``scripts/sync_health_module.py``, which
    does not exist in this tree.
    """
    base = SERVICES_DIR / svc / "app"
    module = base / "_health.py"
    has_module = module.is_file()
    main_text = (base / "main.py").read_text(encoding="utf-8")
    imports_helper = "from app._health import install_health_routes" in main_text
    wires_routes = "install_health_routes(app" in main_text
    # Unknown rather than false when there is nothing to compare against, so a
    # missing reference is reported as the missing module it is.
    in_sync = True if reference is None or not has_module else module.read_bytes() == reference
    return has_module, imports_helper, wires_routes, in_sync


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any FastAPI service is missing the probes",
    )
    args = parser.parse_args()

    services = discover_fastapi_services()
    if not services:
        # Discovery walks `services/*/app/main.py`. An empty result printed a
        # table header, no rows, and exit 0 — the audit passing because it
        # found no service to hold to the standard, which reads identically
        # to every service meeting it.
        print(
            f"health-probes: found no FastAPI service under {SERVICES_DIR}. "
            f"Zero services audited is not zero services missing the probes.",
            file=sys.stderr,
        )
        return 1

    reference_path = SERVICES_DIR / REFERENCE_SERVICE / "app" / "_health.py"
    reference = reference_path.read_bytes() if reference_path.is_file() else None
    if reference is None:
        print(
            f"health-probes: reference module {reference_path} is missing, so the " f"copies have nothing to be in sync with.",
            file=sys.stderr,
        )
        return 1

    print(f"{'service':<18} {'_health.py':<11} {'import':<7} {'wire':<5} {'in-sync':<7}")
    print(f"{'-' * 18} {'-' * 11} {'-' * 7} {'-' * 5} {'-' * 7}")
    drift: list[str] = []
    out_of_sync: list[str] = []
    for svc in services:
        has_mod, has_import, has_wire, in_sync = audit_service(svc, reference)
        marker_mod = "yes" if has_mod else "NO"
        marker_import = "yes" if has_import else "NO"
        marker_wire = "yes" if has_wire else "NO"
        marker_sync = "yes" if in_sync else "NO"
        print(f"{svc:<18} {marker_mod:<11} {marker_import:<7} {marker_wire:<5} {marker_sync:<7}")
        if not (has_mod and has_import and has_wire):
            drift.append(svc)
        if not in_sync:
            out_of_sync.append(svc)

    if not args.check:
        return 0

    if drift:
        print(
            "\nFAIL: the following FastAPI services do not install the "
            "Phase 2.6 /livez + /readyz probes from app._health:\n  - " + "\n  - ".join(drift),
            file=sys.stderr,
        )
        print(
            "\nFix: copy services/api/app/_health.py into "
            "services/<svc>/app/_health.py and call install_health_routes("
            "app, service_name='aisoc-<svc>') in app/main.py.",
            file=sys.stderr,
        )
    if out_of_sync:
        print(
            f"\nFAIL: these copies of app/_health.py differ from "
            f"services/{REFERENCE_SERVICE}/app/_health.py:\n  - " + "\n  - ".join(out_of_sync),
            file=sys.stderr,
        )
        print(
            f"\nFix: cp services/{REFERENCE_SERVICE}/app/_health.py "
            f"services/<svc>/app/_health.py for each one above. The probes are a "
            f"contract the whole fleet answers; one tree answering an older "
            f"version of it cannot be read off a dashboard.",
            file=sys.stderr,
        )
    return 1 if (drift or out_of_sync) else 0


if __name__ == "__main__":
    sys.exit(main())

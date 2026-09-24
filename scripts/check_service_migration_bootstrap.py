#!/usr/bin/env python3
"""A migration chain nothing invokes is not a migration chain.

Why this exists
---------------

Four services own their schema through alembic — ``ueba``, ``honeytokens``,
``purple-team`` and ``osquery-tls``. Their chains were correct: run by hand
they applied cleanly, nine tables each with a row-level-security policy, each
with its own version table. **No compose path invoked any of them.** Every
container command was a plain ``uvicorn``, so on the documented quickstart
those services booted healthy with empty schemas and no policies.

That is how two services shipped with no tables while every command in the
sequence reported success. The chain existing, the chain being correct, and
the chain having run are three different facts, and only the third one
matters to a running deployment.

What it checks
--------------

For every service with an ``alembic.ini`` — discovered from the file, not
from a list kept here, so a fifth service cannot be added without being
held to this:

``no-bootstrap-module``
    ``app/_migrate.py`` is missing. That is the module that applies the
    chain and verifies it reached head.

``bootstrap-not-invoked``
    The Dockerfile never runs it. This is the defect as it actually was: the
    module could have been present and the ``CMD`` still a bare ``uvicorn``.
    Checked against the ``CMD``/``ENTRYPOINT`` lines rather than the whole
    file, so a mention in a comment does not satisfy it.

``bootstrap-module-drift``
    The copy differs from the reference one. The four are vendored because
    services share no Python path, and a wrapper that verifies "reached
    head" in one tree and not in another is worse than none: the fleet-wide
    claim becomes unreadable.

``no-owner-credential``
    ``docker-compose.yml`` does not give the service a ``*DATABASE_MIGRATION_URL``.
    Alembic issues DDL and the runtime role deliberately holds no ``CREATE``
    on schema public — that is what stops it turning RLS off — so a chain
    applied as the runtime credential dies on the first ``CREATE TABLE``.

``no-healthcheck``
    The service has no compose healthcheck, so a container that refused to
    start still reads as ``running``. Invisibility is the whole reason both
    of these defects survived a full acceptance pass.

And the other direction: a service shipping ``app/_migrate.py`` with no
``alembic.ini`` is reported too, because a bootstrap for a chain that is not
there will exit 1 on every start of a service that has nothing to migrate.

Usage
-----

::

    python3 scripts/check_service_migration_bootstrap.py           # table
    python3 scripts/check_service_migration_bootstrap.py --check    # gate
    python3 scripts/check_service_migration_bootstrap.py --json
    python3 scripts/check_service_migration_bootstrap.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

REPO_ROOT = repo_root()
SERVICES_DIR = REPO_ROOT / "services"
COMPOSE = REPO_ROOT / "docker-compose.yml"

#: The module each service runs before its server, and the reference copy the
#: others are compared against.
BOOTSTRAP = pathlib.Path("app") / "_migrate.py"
REFERENCE_SERVICE = "ueba"

#: How the Dockerfile must invoke it. Matched on the module path so the shell
#: spelling is free to change.
INVOCATION = "app._migrate"


def _compose_block(text: str, service: str) -> str:
    """The ``docker-compose.yml`` stanza for one service.

    Sliced on indentation rather than parsed with a YAML library: this gate
    runs on a bare interpreter in CI before any ``pip install``, and pulling
    in PyYAML to read two keys would take that away from it.
    """
    match = re.search(rf"^  {re.escape(service)}:$", text, re.M)
    if not match:
        return ""
    rest = text[match.end() :]
    end = re.search(r"^  \S", rest, re.M)
    return rest[: end.start()] if end else rest


def _command_lines(dockerfile: str) -> str:
    """Just the CMD / ENTRYPOINT lines, so a comment cannot satisfy the check."""
    return "\n".join(line for line in dockerfile.splitlines() if line.strip().upper().startswith(("CMD", "ENTRYPOINT")))


def scan() -> dict:
    if not SERVICES_DIR.is_dir():
        return {"error": f"no services directory at {SERVICES_DIR}"}

    compose_text = COMPOSE.read_text(encoding="utf-8") if COMPOSE.is_file() else ""
    reference_path = SERVICES_DIR / REFERENCE_SERVICE / BOOTSTRAP
    reference = reference_path.read_bytes() if reference_path.is_file() else None

    services: list[dict] = []
    findings: list[dict] = []

    candidates = sorted(p for p in SERVICES_DIR.iterdir() if p.is_dir())

    for service in candidates:
        has_chain = (service / "alembic.ini").is_file()
        module = service / BOOTSTRAP

        # The other direction: a bootstrap with no chain to apply.
        if module.is_file() and not has_chain:
            findings.append(
                {
                    "service": service.name,
                    "kind": "bootstrap-without-chain",
                    "detail": f"ships {BOOTSTRAP} but has no alembic.ini; it would exit 1 on every start",
                }
            )
        if not has_chain:
            continue

        dockerfile = service / "Dockerfile"
        commands = _command_lines(dockerfile.read_text(encoding="utf-8")) if dockerfile.is_file() else ""
        block = _compose_block(compose_text, service.name)

        row = {
            "service": service.name,
            "module": module.is_file(),
            "in_sync": reference is not None and module.is_file() and module.read_bytes() == reference,
            "invoked": INVOCATION in commands,
            "owner_credential": bool(re.search(r"^\s+\w*DATABASE_MIGRATION_URL:", block, re.M)),
            "healthcheck": "healthcheck:" in block,
            "in_compose": bool(block),
        }
        services.append(row)

        if not row["module"]:
            findings.append(
                {
                    "service": service.name,
                    "kind": "no-bootstrap-module",
                    "detail": f"{BOOTSTRAP} is missing; nothing applies this service's chain",
                }
            )
        elif not row["in_sync"]:
            findings.append(
                {
                    "service": service.name,
                    "kind": "bootstrap-module-drift",
                    "detail": f"{BOOTSTRAP} differs from services/{REFERENCE_SERVICE}/{BOOTSTRAP}",
                }
            )
        if not row["invoked"]:
            findings.append(
                {
                    "service": service.name,
                    "kind": "bootstrap-not-invoked",
                    "detail": f"no CMD/ENTRYPOINT runs {INVOCATION}; this service would boot on whatever schema is there",
                }
            )
        if row["in_compose"] and not row["owner_credential"]:
            findings.append(
                {
                    "service": service.name,
                    "kind": "no-owner-credential",
                    "detail": (
                        "no *DATABASE_MIGRATION_URL in its compose environment; the chain would be "
                        "applied as the runtime role and fail on the first CREATE TABLE"
                    ),
                }
            )
        if row["in_compose"] and not row["healthcheck"]:
            findings.append(
                {
                    "service": service.name,
                    "kind": "no-healthcheck",
                    "detail": "no compose healthcheck, so a container that refused to start still reads as running",
                }
            )

    return {"root": str(REPO_ROOT), "services": services, "findings": findings}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _detects_uninvoked_chain() -> list[tuple[str, bool]]:
    """Prove each kind is still detected, on a tree built for the purpose."""
    import tempfile

    global REPO_ROOT, SERVICES_DIR, COMPOSE  # noqa: PLW0603 — restored below
    saved = (REPO_ROOT, SERVICES_DIR, COMPOSE)
    try:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            service = root / "services" / "widgetry"
            (service / "app").mkdir(parents=True)
            (service / "alembic.ini").write_text("[alembic]\nscript_location = alembic\n")
            # The defect exactly as it was: a chain, and a bare uvicorn CMD.
            (service / "Dockerfile").write_text('FROM python:3.11-slim\nCMD ["uvicorn", "app.main:app", "--port", "8000"]\n')
            (root / "docker-compose.yml").write_text("services:\n  widgetry:\n    image: x\n")

            # A second service with the bootstrap and no chain — the other
            # direction.
            stray = root / "services" / "strayville"
            (stray / "app").mkdir(parents=True)
            (stray / "app" / "_migrate.py").write_text("# stub\n")

            REPO_ROOT, SERVICES_DIR, COMPOSE = root, root / "services", root / "docker-compose.yml"
            kinds = {f["kind"] for f in scan()["findings"]}
    finally:
        REPO_ROOT, SERVICES_DIR, COMPOSE = saved

    return [
        ("detects a chain with no bootstrap module", "no-bootstrap-module" in kinds),
        ("detects a bootstrap module the Dockerfile never runs", "bootstrap-not-invoked" in kinds),
        ("detects a service with no owner credential", "no-owner-credential" in kinds),
        ("detects a service with no compose healthcheck", "no-healthcheck" in kinds),
        ("detects a bootstrap module with no chain to apply", "bootstrap-without-chain" in kinds),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="alembic chains must be invoked on the way up")
    parser.add_argument("--check", action="store_true", help="exit non-zero on findings")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--self-test", action="store_true", help="prove this gate still detects drift")
    args = parser.parse_args()

    if args.self_test:
        return self_test_main(pathlib.Path(__file__).name, ["--check"], extra=_detects_uninvoked_chain())

    result = scan()
    if "error" in result:
        print(f"migration-bootstrap: {result['error']}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"migration-bootstrap: root {result['root']}")
        print(f"{'service':<14} {'_migrate':<9} {'in-sync':<8} {'invoked':<8} {'owner':<6} {'health':<7}")
        print(f"{'-' * 14} {'-' * 9} {'-' * 8} {'-' * 8} {'-' * 6} {'-' * 7}")
        for row in result["services"]:
            mark = lambda flag: "yes" if flag else "NO"  # noqa: E731 — table formatting only
            print(
                f"{row['service']:<14} {mark(row['module']):<9} {mark(row['in_sync']):<8} "
                f"{mark(row['invoked']):<8} {mark(row['owner_credential']):<6} {mark(row['healthcheck']):<7}"
            )

    if not result["services"]:
        # The corpus refusal. No service with an alembic.ini means this gate
        # inspected nothing, and "nothing to check" must not print the same
        # verdict as "everything checked out".
        print(
            f"\nmigration-bootstrap: found no service with an alembic.ini under {SERVICES_DIR}. "
            f"Four services own their schema that way; zero found means the root above is not "
            f"the tree you meant.",
            file=sys.stderr,
        )
        return 1

    if not result["findings"]:
        print(f"\nOK: {len(result['services'])} alembic-managed service(s) apply their chain before serving")
        return 0

    print(f"\nFAIL: {len(result['findings'])} finding(s):", file=sys.stderr)
    for finding in result["findings"]:
        print(f"  [{finding['kind']}] {finding['service']}: {finding['detail']}", file=sys.stderr)
    print(
        f"\nFix: copy services/{REFERENCE_SERVICE}/{BOOTSTRAP} into the service, and make its "
        f"Dockerfile CMD run `python -m {INVOCATION} -- <server command>`.",
        file=sys.stderr,
    )
    return 1 if args.check else 0


if __name__ == "__main__":
    sys.exit(main())

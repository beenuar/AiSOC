#!/usr/bin/env python3
"""Inbox templates on disk and mintable template ids must agree, both ways.

Two sets have to stay in lock-step:

*   the YAML files under ``services/ingest/internal/normalizer/templates/``,
    which are what the Go ingest service can actually apply to a payload;
*   ``ALLOWED_TEMPLATE_IDS`` in
    ``services/api/app/api/v1/endpoints/inbox.py``, which is what the mint
    API will accept.

Drift in either direction is silent and neither one is harmless:

*   **Allow-listed with no YAML.** The operator mints a URL, pastes it into
    the vendor, and every delivery is dropped because the ingest build has
    no template of that name. The mint is the last moment anyone can tell
    them, which is exactly why the allow-list is validated at mint time.
*   **YAML with no allow-list entry.** The template ships, gets documented,
    and cannot be reached — the mint call answers 400. This is the direction
    that actually bit: ``ai-runtime``, ``ai-finding`` and ``k8s-audit`` all
    shipped with YAML, were named in the AI SDK's own setup instructions and
    in the Kubernetes connector docs, and no token could be minted for any
    of them.

A one-directional check would have reported OK throughout that, which is
the shape of gate this repository keeps rediscovering. So this compares both
directions, and every exemption has to be written down with a reason rather
than simply omitted.

Usage:
    python3 scripts/check_inbox_templates.py
    python3 scripts/check_inbox_templates.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO_ROOT / "services/ingest/internal/normalizer/templates"
INBOX_ENDPOINT = REPO_ROOT / "services/api/app/api/v1/endpoints/inbox.py"

#: Mintable ids that deliberately have no YAML, and why. An id may only be
#: in ``ALLOWED_TEMPLATE_IDS`` without a template file if it is listed here.
MINTABLE_WITHOUT_TEMPLATE: dict[str, str] = {
    "itsm-inbound": (
        "Terminates at services/api (/api/v1/inbox/itsm/...), not at the Go "
        "ingest service: it needs a database transaction to mirror status "
        "onto aisoc_cases, so there is no OCSF payload mapping to apply."
    ),
    "connector-push": (
        "Names a credential purpose, not a payload mapping. Tokens minted "
        "with it authenticate POST /v1/ingest[/batch], which normalizes "
        "through the ingest service's connector profiles."
    ),
}

#: Templates that ship but are deliberately not mintable, and why. Empty
#: today; kept so that excluding one is a written decision rather than an
#: omission nobody notices.
TEMPLATE_WITHOUT_MINT_PATH: dict[str, str] = {}


def declared_template_ids() -> set[str]:
    """Parse ALLOWED_TEMPLATE_IDS out of the endpoint module.

    Parsed with ``ast`` rather than imported: this runs in CI without the
    API service's dependencies installed, and importing the module would
    drag in FastAPI, SQLAlchemy and the settings object.
    """
    tree = ast.parse(INBOX_ENDPOINT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "ALLOWED_TEMPLATE_IDS":
                value = node.value
                if value is None or not isinstance(value, (ast.Tuple, ast.List)):
                    raise SystemExit(f"{INBOX_ENDPOINT}: ALLOWED_TEMPLATE_IDS is not a literal tuple/list")
                ids = set()
                for element in value.elts:
                    if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                        raise SystemExit(f"{INBOX_ENDPOINT}: ALLOWED_TEMPLATE_IDS holds a non-string entry")
                    ids.add(element.value)
                return ids
    raise SystemExit(f"{INBOX_ENDPOINT}: ALLOWED_TEMPLATE_IDS not found")


def declared_catalog_ids() -> set[str]:
    """Parse the keys of _TEMPLATE_CATALOG.

    The catalog is what the onboarding wizard renders. ``list_templates``
    silently skips an id with no catalog entry, so an allow-listed template
    with no metadata is mintable over the API and invisible in the console
    — a third drift direction, and the one an operator would experience as
    "the feature does not exist".
    """
    tree = ast.parse(INBOX_ENDPOINT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        targets = list(node.targets) if isinstance(node, ast.Assign) else ([node.target] if isinstance(node, ast.AnnAssign) else [])
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "_TEMPLATE_CATALOG":
                value = node.value
                if not isinstance(value, ast.Dict):
                    raise SystemExit(f"{INBOX_ENDPOINT}: _TEMPLATE_CATALOG is not a dict literal")
                return {k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    raise SystemExit(f"{INBOX_ENDPOINT}: _TEMPLATE_CATALOG not found")


def template_files() -> set[str]:
    if not TEMPLATE_DIR.is_dir():
        raise SystemExit(f"{TEMPLATE_DIR}: template directory not found")
    return {p.stem for p in sorted(TEMPLATE_DIR.glob("*.yaml"))}


def self_test() -> int:
    """Inject drift in each direction and require the gate to catch each one.

    A one-directional gate prints OK while drift accumulates in the
    direction it does not look, which is how three templates shipped
    unmintable. This asserts both directions still fail, so a refactor that
    quietly stops checking one of them fails here rather than going quiet.
    """
    on_disk = template_files()
    mintable = declared_template_ids()
    catalogued = declared_catalog_ids()

    cases: list[tuple[str, set[str], set[str], set[str]]] = [
        # A template ships but nothing can mint it.
        (
            "shipped template with no mint path",
            on_disk | {"__drift_unmintable"},
            mintable,
            catalogued,
        ),
        # An id is mintable but the template is not there to apply.
        (
            "mintable id with no template file",
            on_disk,
            mintable | {"__drift_missing_yaml"},
            catalogued | {"__drift_missing_yaml"},
        ),
        # Mintable over the API, invisible in the console.
        (
            "mintable id with no catalog entry",
            on_disk | {"__drift_uncatalogued"},
            mintable | {"__drift_uncatalogued"},
            catalogued,
        ),
    ]

    failures = []
    for label, disk, mint, cat in cases:
        if not evaluate(disk, mint, cat):
            failures.append(f"the gate did NOT catch: {label}")

    # The undisturbed tree must be clean, or "the gate catches drift" would
    # be indistinguishable from "the gate fails on everything".
    if evaluate(on_disk, mintable, catalogued):
        failures.append("the undisturbed tree already reports drift, so a caught case proves nothing")

    if failures:
        for failure in failures:
            print(f"self-test FAILED — {failure}", file=sys.stderr)
        return 1
    print(f"self-test OK: the gate catches drift in all {len(cases)} directions.")
    return 0


def evaluate(on_disk: set[str], mintable: set[str], catalogued: set[str]) -> list[str]:
    """Return the list of drift problems for one (disk, mintable, catalog) triple."""
    failures: list[str] = []

    for template_id in sorted(mintable - on_disk):
        if not MINTABLE_WITHOUT_TEMPLATE.get(template_id):
            failures.append(
                f"'{template_id}' is in ALLOWED_TEMPLATE_IDS but there is no "
                f"{TEMPLATE_DIR.relative_to(REPO_ROOT)}/{template_id}.yaml. "
                f"Tokens minted with it would silently drop every delivery. "
                f"Ship the template, or record the exemption with a reason in "
                f"MINTABLE_WITHOUT_TEMPLATE in {Path(__file__).name}."
            )

    for template_id in sorted(on_disk - mintable):
        if not TEMPLATE_WITHOUT_MINT_PATH.get(template_id):
            failures.append(
                f"'{template_id}.yaml' ships but '{template_id}' is not in "
                f"ALLOWED_TEMPLATE_IDS, so no token can be minted for it and "
                f"the template is unreachable. Add it to the allow-list and to "
                f"_TEMPLATE_CATALOG, or record the exemption with a reason in "
                f"TEMPLATE_WITHOUT_MINT_PATH in {Path(__file__).name}."
            )

    for template_id in sorted(mintable - catalogued):
        failures.append(
            f"'{template_id}' is mintable but has no _TEMPLATE_CATALOG entry, "
            f"so GET /api/v1/inbox/templates omits it and the onboarding "
            f"wizard cannot offer it."
        )

    for template_id in sorted(catalogued - mintable):
        failures.append(f"'{template_id}' has a _TEMPLATE_CATALOG entry but is not in ALLOWED_TEMPLATE_IDS, so minting it returns 400.")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="assert the gate catches injected drift in every direction",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    on_disk = template_files()
    mintable = declared_template_ids()
    catalogued = declared_catalog_ids()
    failures: list[str] = list(evaluate(on_disk, mintable, catalogued))

    # Stale exemptions are their own drift: an entry justifying something
    # that no longer exists reads as a reviewed decision while covering
    # nothing, which is how the gitleaks allow-list rotted.
    for template_id in sorted(set(MINTABLE_WITHOUT_TEMPLATE) - mintable):
        failures.append(f"'{template_id}' is exempted in MINTABLE_WITHOUT_TEMPLATE but is not mintable; drop the stale exemption.")
    for template_id in sorted(set(TEMPLATE_WITHOUT_MINT_PATH) - on_disk):
        failures.append(f"'{template_id}' is exempted in TEMPLATE_WITHOUT_MINT_PATH but ships no YAML; drop the stale exemption.")

    if failures:
        print("Inbox template drift:\n", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}\n", file=sys.stderr)
        return 1

    exempt = len(MINTABLE_WITHOUT_TEMPLATE) + len(TEMPLATE_WITHOUT_MINT_PATH)
    print(f"OK: {len(on_disk)} template files, {len(mintable)} mintable ids, {exempt} recorded exemption(s); both directions agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Generate the connector catalog the API image falls back to.

Why this exists
---------------
``services/api`` proxies ``GET /api/v1/connectors/catalog`` to the connectors
service and keeps a copy of the catalog bundled in its own image for when that
service is not deployed or not answering. The proxy sent no credential, so the
connectors service — default-deny on every route — answered 401 every time and
the proxy fell through to the bundle on *every single request*. The bundle had
26 entries. The registry had 84.

Nothing failed. The wizard rendered a confident list of connectors that was
missing 58 of them, and because the API also validates ``connector_type``
against that list, the 58 it had never heard of were rejected with 422 as
"unknown connector_type" — the type existed, the copy of the list did not
know about it.

The authentication is fixed in the proxy. This exists so the second half
cannot come back: the bundle is now *generated* from the registry rather than
refreshed by hand, and ``--check`` fails the build when the committed artefact
is not what generation produces. A hand-refresh is a step somebody has to
remember, and the evidence that nobody remembered is the 58.

What it credits as correct
--------------------------
The question worth asking about a gate is not what it flags but what it lets
through. This one compares **three independent readings of connector
identity**, in both directions, because two of them are separate declarations
that can silently disagree:

``declared``
    ``_CONNECTOR_CLASSES`` in ``services/connectors/app/connectors/__init__.py``
    resolved to each class's ``connector_id``, read through the AST by
    ``generate_connector_types.parse_registry``. Imported from there rather
    than re-implemented: two scanners drift the first time either learns
    something the other has not.
``registered``
    ``CONNECTOR_REGISTRY`` keys at runtime. Differs from ``declared`` if a
    connector module fails to import, or if registration is skipped.
``advertised``
    The ``connector_id`` field of each catalog entry — which comes from
    ``cls.schema()``, **not** from the registry key. That is the blind spot.
    ``list_connector_schemas()`` iterates the registry but takes each entry's
    identity from the schema, so a class registered as ``tenable_io`` whose
    ``schema()`` says ``tenable`` would be advertised under a name the service
    cannot resolve: the wizard offers it, the operator picks it, and
    ``get_connector_class()`` returns None. No check in this tree looked at
    that, and the two are 84 independent opportunities to disagree.

Identity is read off the class, never the filename. ``jira_connector.py``
declares ``jira`` and ``tenable.py`` declares ``tenable_io``, so a filename
slug would misname both — the defect that had
``scripts/generate_connector_docs.py`` emitting duplicate pages while its
coverage gate reported 100%. ``--self-test`` asserts that property holds
rather than trusting the comment.

Nothing here is positional
--------------------------
Entries are sorted by ``connector_id``, so reordering ``_CONNECTOR_CLASSES``
cannot change a byte of the output and no lock file is needed. (Contrast
``generate_detections.py``, which assigned ids by position and therefore did.)

Usage
-----
    python3 scripts/generate_connector_catalog_fallback.py            # write
    python3 scripts/generate_connector_catalog_fallback.py --check    # gate
    python3 scripts/generate_connector_catalog_fallback.py --json
    python3 scripts/generate_connector_catalog_fallback.py --self-test

``--repo-root`` overrides the tree under inspection. The resolved root comes
from ``git rev-parse``, every file read is printed before the verdict, and an
empty read is a hard error rather than a quiet zero: a bundle generated from a
registry nobody opened is the failure this replaces, one level up.

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. Its siblings sit beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402
from generate_connector_types import GateError, parse_registry  # noqa: E402

CONNECTORS_REL = Path("services/connectors")
REGISTRY_REL = Path("services/connectors/app/connectors/__init__.py")
OUT_REL = Path("services/api/app/data/connector_catalog_fallback.json")
CONSUMER_REL = Path("services/api/app/api/v1/endpoints/connectors.py")


def load_runtime_catalog(root: Path) -> tuple[list[dict[str, Any]], set[str]]:
    """``(catalog entries, registry keys)`` from the connectors package.

    The directory is checked before the import is attempted, on purpose. In a
    tree with no ``services/`` the refusal must be "the corpus is not here",
    not ``ModuleNotFoundError``, so that a genuinely missing third-party
    dependency stays distinguishable from an empty tree.
    """
    package_root = root / CONNECTORS_REL
    if not (root / REGISTRY_REL).exists():
        raise GateError(f"expected input does not exist: {root / REGISTRY_REL}")

    sys.path.insert(0, str(package_root))
    try:
        from app.connectors import CONNECTOR_REGISTRY, list_connector_schemas
    except ImportError as exc:
        raise GateError(
            f"could not import the connector registry from {package_root}: {exc}. "
            "The gate reads every connector's schema() at runtime, so it needs what those "
            "modules import at module scope (httpx, pydantic, structlog, cryptography)."
        ) from exc

    entries = list_connector_schemas()
    registered = set(CONNECTOR_REGISTRY)
    if not entries:
        raise GateError("the connector registry produced zero schemas — refusing to generate from an empty read")
    if not registered:
        raise GateError("CONNECTOR_REGISTRY is empty — refusing to generate from an empty read")
    return entries, registered


def render(entries: list[dict[str, Any]]) -> str:
    """The canonical on-disk form: sorted by id, stable key order, one file."""
    ordered = sorted(entries, key=lambda e: str(e.get("connector_id", "")))
    return json.dumps(ordered, indent=2, sort_keys=True) + "\n"


def evaluate(
    declared: set[str],
    registered: set[str],
    entries: list[dict[str, Any]],
    on_disk: str | None,
    consumer: str | None,
) -> list[tuple[str, str]]:
    """Every finding, each named by a code the self-test can require."""
    failures: list[tuple[str, str]] = []
    advertised = {str(e.get("connector_id", "")) for e in entries if e.get("connector_id")}

    # An empty set here would make every comparison below vacuously clean.
    for name, values in (("declared", declared), ("registered", registered), ("advertised", advertised)):
        if not values:
            failures.append(("empty-corpus", f"the {name} connector-id set is empty; every comparison below would pass vacuously"))
    if failures:
        return failures

    # Both directions for each pair. The dominant failure shape in this tree
    # is a gate that compares A against B and never B against A, so drift in
    # the direction things actually change slips through while it prints OK.
    pairs = (
        ("declared", declared, "registered", registered),
        ("registered", registered, "advertised", advertised),
    )
    for left_name, left, right_name, right in pairs:
        for missing in sorted(left - right):
            failures.append(
                (
                    f"{right_name}-missing",
                    f"{missing!r} is {left_name} but not {right_name}"
                    + (
                        "; the wizard cannot offer a connector the build ships"
                        if right_name == "advertised"
                        else "; the class does not reach the registry"
                    ),
                )
            )
        for extra in sorted(right - left):
            failures.append(
                (
                    f"{right_name}-unknown",
                    f"{extra!r} is {right_name} but not {left_name}"
                    + (
                        "; the wizard would offer a type get_connector_class() cannot resolve"
                        if right_name == "advertised"
                        else "; the registry holds a class the source does not declare"
                    ),
                )
            )

    expected = render(entries)
    if on_disk is None:
        failures.append(("output-missing", f"{OUT_REL} does not exist; run the generator"))
    elif on_disk != expected:
        failures.append(
            (
                "output-drifted",
                f"{OUT_REL} is not what generation produces; run the generator and commit the result",
            )
        )

    # A generated artefact nobody reads is current and useless. This is the
    # same rule generate_connector_types.py applies to its consumer.
    if consumer is None:
        failures.append(("consumer-missing", f"{CONSUMER_REL} does not exist"))
    elif OUT_REL.name not in consumer:
        failures.append(
            (
                "consumer-not-reading",
                f"{CONSUMER_REL} no longer names {OUT_REL.name}; the generated catalog would sit in the tree unread",
            )
        )
    return failures


def load(root: Path) -> dict[str, Any]:
    entries, registered = load_runtime_catalog(root)
    return {
        "declared": set(parse_registry(root)),
        "registered": registered,
        "entries": entries,
    }


def _read(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.exists() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=repo_root())
    parser.add_argument("--check", action="store_true", help="fail (exit 1) on drift instead of rewriting the output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift in each direction")
    args = parser.parse_args(argv)

    root = args.repo_root.resolve()
    if args.self_test:
        return self_test(root)

    try:
        inputs = load(root)
    except GateError as exc:
        print(f"generate_connector_catalog_fallback: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    out_path = root / OUT_REL
    # Written only after the read is known to be non-empty, so a broken read
    # can never overwrite a good artefact with nothing.
    if not args.check:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render(inputs["entries"]), encoding="utf-8")

    failures = evaluate(
        inputs["declared"],
        inputs["registered"],
        inputs["entries"],
        _read(out_path),
        _read(root / CONSUMER_REL),
    )

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "declared": sorted(inputs["declared"]),
                    "registered": sorted(inputs["registered"]),
                    "advertised": sorted(str(e.get("connector_id", "")) for e in inputs["entries"]),
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    print(f"repo root        {root}")
    print(f"registry         {REGISTRY_REL}  ({len(inputs['declared'])} declared connector ids)")
    print(f"runtime          app.connectors from {CONNECTORS_REL}  ({len(inputs['registered'])} registered)")
    print(f"output           {OUT_REL}  ({len(inputs['entries'])} catalog entries)")
    print(f"consumer         {CONSUMER_REL}")
    print()
    print(
        f"identity         declared {len(inputs['declared'])} = registered {len(inputs['registered'])} = advertised "
        f"{len({str(e.get('connector_id', '')) for e in inputs['entries']})}, compared in both directions"
    )
    print()

    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print("OK — the bundled catalog is what the connector registry generates, and every")
    print("     connector_id it advertises is one the connectors service can resolve.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test(root: Path) -> int:
    """Inject drift in each direction and require the gate to catch each one."""
    try:
        inputs = load(root)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    declared: set[str] = inputs["declared"]
    registered: set[str] = inputs["registered"]
    entries: list[dict[str, Any]] = inputs["entries"]
    good = render(entries)
    consumer = _read(root / CONSUMER_REL) or ""

    clean = evaluate(declared, registered, entries, good, consumer)
    if clean:
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in clean:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    a_connector = sorted(declared)[0]
    dropped = [e for e in entries if e.get("connector_id") != a_connector]
    renamed = [dict(e, connector_id="not_a_registered_id") if e.get("connector_id") == a_connector else e for e in entries]

    cases: list[tuple[str, str, tuple]] = [
        (
            "the bundled catalog is short a connector the registry ships (the 26-vs-84 defect)",
            "advertised-missing",
            (declared, registered, dropped, render(dropped), consumer),
        ),
        (
            "the bundled catalog offers a type the registry does not declare",
            "advertised-unknown",
            (declared, registered, renamed, render(renamed), consumer),
        ),
        (
            "a class declares one connector_id and its schema() advertises another",
            "advertised-unknown",
            (declared, registered, renamed, render(renamed), consumer),
        ),
        (
            "a declared class never reaches the runtime registry",
            "registered-missing",
            (declared, registered - {a_connector}, entries, good, consumer),
        ),
        (
            "the registry holds a class the source does not declare",
            "registered-unknown",
            (declared - {a_connector}, registered, entries, good, consumer),
        ),
        (
            "a hand edit changes the committed artefact",
            "output-drifted",
            (declared, registered, entries, good.replace('"category"', '"catagory"', 1), consumer),
        ),
        (
            "the committed artefact is deleted",
            "output-missing",
            (declared, registered, entries, None, consumer),
        ),
        (
            "the API stops reading the generated catalog",
            "consumer-not-reading",
            (declared, registered, entries, good, consumer.replace(OUT_REL.name, "some_other_file.json")),
        ),
        (
            "every input is empty, so each comparison would pass vacuously",
            "empty-corpus",
            (set(), set(), [], "[]\n", consumer),
        ),
    ]

    print(f"self-test against {root}")
    print(f"clean tree: {len(entries)} catalog entries, 0 failures (the baseline every case below perturbs)")
    print(f"            a declared id is {a_connector!r}\n")
    extra: list[tuple[str, bool]] = []
    for description, expected, call in cases:
        codes = {code for code, _ in evaluate(*call)}
        caught = expected in codes
        extra.append((f"{description}  [{expected}]", caught))

    # Identity must come off the class: two connectors in this tree are
    # registered under an id their filename does not spell, so a filename slug
    # would misname them and every comparison above would be against the wrong
    # names. Asserted, not commented.
    registry = parse_registry(root)
    mismatched = sorted(cid for cid, info in registry.items() if info["module"][:-3] != cid)
    extra.append(
        (
            f"IDENTITY: connector_id comes from the class, not the filename "
            f"({len(mismatched)} would be misnamed by a filename slug: {', '.join(mismatched) or 'none'})",
            bool(mismatched),
        )
    )

    # Every advertised id must resolve through the same lookup the connectors
    # service uses when the wizard posts the type back.
    sys.path.insert(0, str(root / CONNECTORS_REL))
    from app.connectors import get_connector_class

    unresolvable = sorted(cid for cid in {str(e.get("connector_id", "")) for e in entries} if get_connector_class(cid) is None)
    extra.append(
        (
            f"RESOLVABLE: every advertised connector_id resolves through get_connector_class() "
            f"({len(unresolvable)} unresolvable: {', '.join(unresolvable) or 'none'})",
            not unresolvable,
        )
    )

    return self_test_main(Path(__file__).name, ["--check"], extra=extra)


if __name__ == "__main__":
    sys.exit(main())

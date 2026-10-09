#!/usr/bin/env python3
"""Cloud estates do not hand you their logs over a REST list call.

Depth plan 4.1. The three hyperscalers each publish their control-plane and
identity telemetry onto a *queue or object store* once an estate is bigger
than a toy account, and the API-polling shape every connector in this tree
used before now cannot read any of them:

* **AWS** — an organisation trail writes gzipped JSON objects to S3 and
  notifies an SQS queue. ``cloudtrail:LookupEvents``, which
  ``aws_cloudtrail.py`` uses, is capped at two transactions per second per
  region per account, returns management events only, and is documented by
  AWS as unsuitable for continuous delivery. Data events and VPC flow logs
  never appear in it at all.
* **GCP** — a log sink publishes ``LogEntry`` messages to a Pub/Sub topic.
* **Azure** — a diagnostic setting streams Entra sign-in logs, Entra audit
  logs and the Activity log to an Event Hub.

Three properties separate a collector that survives a real estate from one
that looks right in a demo, and each is a rule here:

**It resumes.** A queue collector that restarts and re-reads from "now"
loses every object delivered while it was down; one that re-reads from the
beginning replays the whole bucket. Both are silent. The connector has to
declare the cursor fields the base class's ``apply_checkpoint`` orders and
de-duplicates on.

**It stops.** A backlog can be arbitrarily deep — an SQS queue after an
outage, a Pub/Sub subscription with a week of retention — and a poll that
drains it in one pass turns a recovery into an out-of-memory kill or a
flood through ingest. The connector has to declare a bounded per-poll
budget *and* say, in the declaration, that leaving the remainder on the
queue is what applies backpressure.

**It is tested against what the vendor actually sends.** A fixture written
from the connector's own output proves the connector agrees with itself.
These have to be vendor-shaped payloads recorded under
``services/connectors/tests/fixtures/``.

Plus the two things a reader needs to use it at all: a setup guide and a
marketplace manifest.

Parsed with ``ast`` rather than imported, because this runs on a bare
interpreter in CI before any service venv exists — and because importing
``app.connectors`` here would make the gate depend on boto3 resolving.

Usage:
    python3 scripts/check_cloud_native_collection.py
    python3 scripts/check_cloud_native_collection.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

# ``scripts/`` is on sys.path when this file runs as a program but not when a
# test loads it by path; gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import TREE_SHAPES, refuses_an_empty_tree, repo_root  # noqa: E402

REPO_ROOT = repo_root()
CONNECTORS_PKG = Path("services/connectors/app/connectors")
REGISTRY_REL = CONNECTORS_PKG / "__init__.py"
FIXTURES_REL = Path("services/connectors/tests/fixtures")
DOCS_REL = Path("apps/docs/docs/connectors")
PLUGINS_REL = Path("plugins")


@dataclass(frozen=True)
class CollectionPath:
    """One cloud-native collection path the plan names."""

    connector_id: str
    module: str
    #: What the operator points at. Named so the failure text tells a reader
    #: which vendor surface is missing rather than only which file is.
    surface: str


#: The three the plan names. Adding a fourth is adding a row here; the gate
#: then fails until the connector, its fixtures, its guide and its manifest
#: all exist, which is the order that keeps a half-built collector from
#: shipping as a catalogue entry.
REQUIRED_PATHS: tuple[CollectionPath, ...] = (
    CollectionPath(
        connector_id="aws_cloudtrail_s3",
        module="aws_cloudtrail_s3",
        surface="CloudTrail organisation trail on S3, notified over SQS (management events, data events, VPC flow logs)",
    ),
    CollectionPath(
        connector_id="gcp_pubsub",
        module="gcp_pubsub",
        surface="Pub/Sub subscription fed by a Cloud Logging sink",
    ),
    CollectionPath(
        connector_id="azure_event_hubs",
        module="azure_event_hubs",
        surface="Event Hubs carrying Entra sign-in logs, Entra audit logs and the Activity log",
    ),
)

#: Class attribute carrying the per-poll budget. One name, so the gate and
#: the base class cannot disagree about the spelling.
BUDGET_ATTR = "collection_budget"


@dataclass(frozen=True)
class Declared:
    """What one connector module says about itself, read from its source."""

    module_exists: bool
    checkpoint_time: bool
    checkpoint_id: bool
    budget: bool
    budget_leaves_backlog: bool


def _class_attribute_values(tree: ast.Module, attr: str) -> list[ast.expr]:
    """Every value assigned to ``attr`` at class scope anywhere in the module."""
    out: list[ast.expr] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            targets: list[ast.expr] = []
            if isinstance(stmt, ast.Assign):
                targets = list(stmt.targets)
            elif isinstance(stmt, ast.AnnAssign):
                targets = [stmt.target]
            else:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id == attr and stmt.value is not None:
                    out.append(stmt.value)
    return out


def _is_nonempty_tuple(value: ast.expr) -> bool:
    return isinstance(value, ast.Tuple) and len(value.elts) > 0


def _budget_keywords(value: ast.expr) -> dict[str, ast.expr]:
    """Keyword arguments of a ``CollectionBudget(...)`` call, if that is what this is."""
    if not isinstance(value, ast.Call):
        return {}
    func = value.func
    name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
    if name != "CollectionBudget":
        return {}
    return {kw.arg: kw.value for kw in value.keywords if kw.arg}


def _positive_int(value: ast.expr | None) -> bool:
    return isinstance(value, ast.Constant) and isinstance(value.value, int) and not isinstance(value.value, bool) and value.value > 0


def read_declaration(root: Path, path: CollectionPath) -> Declared:
    source = root / CONNECTORS_PKG / f"{path.module}.py"
    if not source.is_file():
        return Declared(False, False, False, False, False)
    tree = ast.parse(source.read_text(encoding="utf-8"))

    checkpoint_time = any(_is_nonempty_tuple(v) for v in _class_attribute_values(tree, "checkpoint_time_field"))
    checkpoint_id = any(_is_nonempty_tuple(v) for v in _class_attribute_values(tree, "checkpoint_id_field"))

    budget = False
    leaves_backlog = False
    for value in _class_attribute_values(tree, BUDGET_ATTR):
        kwargs = _budget_keywords(value)
        if not kwargs:
            continue
        bounded = _positive_int(kwargs.get("max_batches_per_poll")) and _positive_int(kwargs.get("max_events_per_poll"))
        if bounded:
            budget = True
            reason = kwargs.get("backlog_stays_on_the_queue")
            if isinstance(reason, ast.Constant) and isinstance(reason.value, str) and reason.value.strip():
                leaves_backlog = True
    return Declared(True, checkpoint_time, checkpoint_id, budget, leaves_backlog)


def registered_ids(root: Path) -> set[str]:
    """Connector ids the build knows about, from ``_CONNECTOR_CLASSES``.

    Read as "which classes are in the registry tuple", then resolved back to
    ids through each module's ``connector_id``. A class present in the file
    but absent from that tuple is not reachable from the API, which is the
    direction that ships a connector nobody can select.
    """
    registry = root / REGISTRY_REL
    if not registry.is_file():
        return set()
    tree = ast.parse(registry.read_text(encoding="utf-8"))
    class_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "_CONNECTOR_CLASSES" and isinstance(node.value, ast.Tuple):
                class_names |= {e.id for e in node.value.elts if isinstance(e, ast.Name)}

    ids: set[str] = set()
    for module in sorted((root / CONNECTORS_PKG).glob("*.py")):
        try:
            tree = ast.parse(module.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name not in class_names:
                continue
            for value in _class_attribute_values(ast.Module(body=[node], type_ignores=[]), "connector_id"):
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    ids.add(value.value)
    return ids


def evaluate(root: Path, paths: tuple[CollectionPath, ...] = REQUIRED_PATHS) -> list[str]:
    """Every rule, over every required path. Returns one line per violation."""
    failures: list[str] = []
    registry = registered_ids(root)

    for path in paths:
        where = f"{CONNECTORS_PKG}/{path.module}.py"
        declared = read_declaration(root, path)

        if not declared.module_exists:
            failures.append(
                f"{path.connector_id}: no {where}. The plan's collection path — {path.surface} — has no collector, "
                f"so an estate of any size cannot be read."
            )
            continue

        if path.connector_id not in registry:
            failures.append(
                f"{path.connector_id}: the module exists but the class is not in _CONNECTOR_CLASSES "
                f"({REGISTRY_REL}), so the catalogue, the setup wizard and the scheduler cannot reach it."
            )

        if not (declared.checkpoint_time and declared.checkpoint_id):
            failures.append(
                f"{path.connector_id}: declares no resumable cursor "
                f"(needs a non-empty checkpoint_time_field and checkpoint_id_field in {where}). "
                f"A queue collector without one either loses everything delivered while it was down "
                f"or replays the backlog, and both are silent."
            )

        if not declared.budget:
            failures.append(
                f"{path.connector_id}: declares no {BUDGET_ATTR} with positive max_batches_per_poll and "
                f"max_events_per_poll in {where}. A poll that drains an arbitrarily deep backlog in one pass "
                f"turns a recovery into an out-of-memory kill."
            )
        elif not declared.budget_leaves_backlog:
            failures.append(
                f"{path.connector_id}: {BUDGET_ATTR} is bounded but does not say what happens to the remainder. "
                f"Set backlog_stays_on_the_queue to the sentence describing it — a bound that drops the overflow "
                f"is data loss wearing the same shape as backpressure."
            )

        fixtures = root / FIXTURES_REL / path.connector_id
        if not fixtures.is_dir() or not any(fixtures.iterdir()):
            failures.append(
                f"{path.connector_id}: no vendor-shaped fixtures under {FIXTURES_REL}/{path.connector_id}/. "
                f"A test that builds its input from the connector's own normalize() only proves the connector "
                f"agrees with itself."
            )

        guide = root / DOCS_REL / f"{path.connector_id.replace('_', '-')}.md"
        legacy_guide = root / DOCS_REL / f"{path.connector_id}.md"
        if not guide.is_file() and not legacy_guide.is_file():
            failures.append(f"{path.connector_id}: no setup guide at {DOCS_REL}/{guide.name}.")

        manifest = root / PLUGINS_REL / path.connector_id.replace("_", "-") / "plugin.yaml"
        legacy_manifest = root / PLUGINS_REL / path.connector_id / "plugin.yaml"
        if not manifest.is_file() and not legacy_manifest.is_file():
            failures.append(f"{path.connector_id}: no marketplace manifest at {PLUGINS_REL}/{manifest.parent.name}/plugin.yaml.")

    return failures


def _self_test() -> int:
    """One injected violation per rule, each required to be caught.

    Injected into a copy of the real tree rather than asserted in prose: a
    rule whose detector silently stopped matching reports OK, and the only
    thing that tells them apart is watching a known-bad tree fail.
    """
    import shutil
    import tempfile

    results: list[tuple[str, bool]] = []

    baseline = evaluate(REPO_ROOT)
    results.append(("the undisturbed tree is clean, so a caught case means something", not baseline))
    if baseline:
        for line in baseline[:6]:
            print(f"        {line}")

    cases: list[tuple[str, str, str]] = [
        # (label, file to rewrite, substitution applied to its text)
        ("a missing collector module", "DELETE_MODULE", ""),
        ("a collector that is not in the registry", "REGISTRY", ""),
        ("a collector with no resumable cursor", "CHECKPOINT", ""),
        ("a collector with no bounded per-poll budget", "BUDGET", ""),
        ("a bounded budget that does not say where the remainder goes", "BACKLOG_REASON", ""),
        ("a collector with no vendor-shaped fixtures", "FIXTURES", ""),
        ("a collector with no setup guide", "GUIDE", ""),
        ("a collector with no marketplace manifest", "MANIFEST", ""),
    ]

    victim = REQUIRED_PATHS[0]
    for label, kind, _ in cases:
        tmp = Path(tempfile.mkdtemp(prefix="aisoc-cnc-selftest-"))
        try:
            for rel in (CONNECTORS_PKG, FIXTURES_REL, DOCS_REL, PLUGINS_REL):
                src = REPO_ROOT / rel
                if src.is_dir():
                    shutil.copytree(src, tmp / rel, dirs_exist_ok=True)
            module = tmp / CONNECTORS_PKG / f"{victim.module}.py"
            if kind == "DELETE_MODULE":
                module.unlink(missing_ok=True)
            elif kind == "REGISTRY":
                registry = tmp / REGISTRY_REL
                registry.write_text(
                    registry.read_text(encoding="utf-8").replace("AWSCloudTrailS3Connector,\n", "", 1),
                    encoding="utf-8",
                )
            elif kind == "CHECKPOINT" and module.is_file():
                module.write_text(
                    module.read_text(encoding="utf-8").replace("checkpoint_id_field = (", "checkpoint_id_field_disabled = ("),
                    encoding="utf-8",
                )
            elif kind == "BUDGET" and module.is_file():
                module.write_text(
                    module.read_text(encoding="utf-8").replace("max_events_per_poll=", "max_events_per_poll_disabled="),
                    encoding="utf-8",
                )
            elif kind == "BACKLOG_REASON" and module.is_file():
                module.write_text(
                    module.read_text(encoding="utf-8").replace("backlog_stays_on_the_queue=", "backlog_note="),
                    encoding="utf-8",
                )
            elif kind == "FIXTURES":
                shutil.rmtree(tmp / FIXTURES_REL / victim.connector_id, ignore_errors=True)
            elif kind == "GUIDE":
                (tmp / DOCS_REL / f"{victim.connector_id.replace('_', '-')}.md").unlink(missing_ok=True)
            elif kind == "MANIFEST":
                (tmp / PLUGINS_REL / victim.connector_id.replace("_", "-") / "plugin.yaml").unlink(missing_ok=True)

            caught = bool(evaluate(tmp, (victim,)))
            results.append((f"catches {label}", caught))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # Both shapes: the directories absent, and the directories present and
    # empty. They are different questions — a gate whose first act is "is the
    # directory there" refuses the first for a reason that says nothing about
    # its corpus, and reports the second clean.
    details: list[str] = []
    for shape in TREE_SHAPES:
        refused, detail = refuses_an_empty_tree(Path(__file__).name, shape=shape)
        results.append((f"refuses a {shape} tree rather than reporting it clean", refused))
        details.append(f"{shape}: {detail}")

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    for line in "\n".join(details).splitlines():
        print(f"        {line}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    if not (REPO_ROOT / CONNECTORS_PKG).is_dir():
        print(
            f"check_cloud_native_collection: {CONNECTORS_PKG} is not there — nothing to render a verdict about.",
            file=sys.stderr,
        )
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("Cloud-native collection (depth plan 4.1) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s) across {len(REQUIRED_PATHS)} required collection path(s).", file=sys.stderr)
        return 1

    print(
        f"OK — {len(REQUIRED_PATHS)} cloud-native collection path(s): "
        f"each registered, resumable, bounded, fixtured, documented and published."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

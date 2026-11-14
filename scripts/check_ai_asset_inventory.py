#!/usr/bin/env python3
"""An AI estate you cannot enumerate is one you cannot govern.

Depth plan 6.1. Every AI app, coding agent, MCP server, IDE extension,
model-provider key and OAuth grant a tenant runs, each linked to the person
who uses it, the device it ran on, and the permissions behind it.

Why this is a gate and not a test
---------------------------------
An inventory is a stored value a surface reads, and this repository's second
most expensive defect is exactly that shape: the code runs, the page renders,
and the table it reads is one nothing writes. A unit test on the recorder
passes whether or not the recorder is on the path, and a test on the route
passes against a table seeded by the test itself. So the question this gate
asks of every rule below is the one no test asks:

    which code path writes this, and does it run on the default profile?

The writer rule (``WRITER``) is therefore the load-bearing one. It is not
satisfied by the recorder existing, nor by it being imported: it requires the
fusion consumer to call it on the raw-events branch *and* the fusion service
to construct it during startup, because an unconstructed recorder is a
``None`` that every call site skips in silence.

Why reads are authorized too
----------------------------
Most read routes in this service authenticate and stop. This inventory is
different in kind: it names which agent on which laptop holds which provider
key, which is a target list. ``ai_estate:read`` is a real permission held by
real roles rather than a decoration, and ``PERMISSIONS`` checks both halves —
that the vocabulary knows it, and that at least one role actually holds it.
``hunts:read`` was in the vocabulary and held by no role at all, so a key
minted with it worked and no human could ever use it.

Parsed with ``ast`` and plain text rather than imported, because this runs on
a bare interpreter in CI before any service venv exists.

Usage:
    python3 scripts/check_ai_asset_inventory.py
    python3 scripts/check_ai_asset_inventory.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
import tempfile
from pathlib import Path

# `scripts/` is on sys.path when this file runs as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

# Resolved through `git rev-parse`, not from `__file__`. Two levels above this
# script is whatever happens to be there -- `scripts/` copied into an empty
# repository is exactly that, and a gate that reads it reports a tree clean
# without ever seeing the product. `check_gate_contract.py` refuses it.
REPO_ROOT = repo_root()

#: The table the whole item hangs on.
TABLE = "aisoc_ai_assets"

#: The six kinds the plan names. An inventory missing one of these is an
#: inventory of something else.
REQUIRED_KINDS = (
    "ai_app",
    "coding_agent",
    "mcp_server",
    "ide_extension",
    "provider_key",
    "oauth_grant",
)

#: Graph label for an AI asset. One label with a ``kind`` property rather than
#: six labels, mirroring how ``Identity`` superclasses ``User`` and
#: ``ServiceAccount``: six labels would be six places for the vocabulary to
#: drift and six traversals to keep in step.
GRAPH_LABEL = "AIAsset"

MIGRATIONS_DIR = Path("services/api/migrations")
MODEL_PATH = Path("services/api/app/models/ai_asset.py")
MODELS_INIT = Path("services/api/app/models/__init__.py")
ROUTES_PATH = Path("services/api/app/api/v1/endpoints/ai_assets.py")
ROUTER_PATH = Path("services/api/app/api/v1/router.py")
SECURITY_PATH = Path("services/api/app/core/security.py")
SCOPES_PATH = Path("services/api/app/api/v1/endpoints/api_keys.py")
RECORDER_PATH = Path("services/fusion/app/services/ai_asset_recorder.py")
CONSUMER_PATH = Path("services/fusion/app/workers/consumer.py")
FUSION_MAIN = Path("services/fusion/app/main.py")
GRAPH_YAML = Path("schemas/graph-schema.yaml")
GRAPH_GO = Path("services/ingest/internal/graph/schema.go")
EXTRACTOR_GO = Path("services/ingest/internal/graph/extractor.go")
CONSOLE_PAGE = Path("apps/web/src/components/ai-estate/AiEstateView.tsx")

#: Every file the gate reads. The self-test copies exactly these, so a new
#: rule that reads a new path must add it here or its injection silently
#: lands in a file the temporary tree does not contain.
READ_PATHS = (
    MODEL_PATH,
    MODELS_INIT,
    ROUTES_PATH,
    ROUTER_PATH,
    SECURITY_PATH,
    SCOPES_PATH,
    RECORDER_PATH,
    CONSUMER_PATH,
    FUSION_MAIN,
    GRAPH_YAML,
    GRAPH_GO,
    EXTRACTOR_GO,
    CONSOLE_PAGE,
)


def _read(root: Path, rel: Path) -> str:
    path = root / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _check_migration(root: Path) -> list[str]:
    """The table exists, is tenant-scoped, and row-level security is forced."""
    failures: list[str] = []
    migrations = sorted((root / MIGRATIONS_DIR).glob("*.sql")) if (root / MIGRATIONS_DIR).is_dir() else []
    creating = [p for p in migrations if f"CREATE TABLE IF NOT EXISTS {TABLE}" in p.read_text(encoding="utf-8")]
    if not creating:
        return [f"MIGRATION: no file under {MIGRATIONS_DIR} creates {TABLE}. The console would read a table nothing created."]
    sql = creating[0].read_text(encoding="utf-8")
    name = creating[0].name
    if "tenant_id" not in sql:
        failures.append(f"MIGRATION: {name} creates {TABLE} with no tenant_id column, so nothing can scope a read to one tenant.")
    for needle, why in (
        (f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY", "row-level security is never enabled"),
        (f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY", "the table owner walks past the policy"),
        ("current_tenant_id()", "no policy compares the row's tenant to the session's"),
        ("aisoc_app", "the DML-only runtime role is never granted access, so every query fails as the app user"),
    ):
        if needle not in sql:
            failures.append(f"MIGRATION: {name} does not contain {needle!r} — {why}.")
    return failures


def _check_model(root: Path) -> list[str]:
    source = _read(root, MODEL_PATH)
    if not source:
        return [f"MODEL: {MODEL_PATH} is absent; nothing maps {TABLE} into the API service."]
    failures: list[str] = []
    if f'__tablename__ = "{TABLE}"' not in source:
        failures.append(f'MODEL: {MODEL_PATH} does not declare __tablename__ = "{TABLE}".')
    init = _read(root, MODELS_INIT)
    if "ai_asset" not in init:
        failures.append(
            f"MODEL: {MODELS_INIT} does not import the model. SQLAlchemy never registers the mapper, "
            f"so metadata-driven tooling and the test harness do not know the table exists."
        )
    return failures


def _route_functions(source: str) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    tree = ast.parse(source)
    out: list[ast.AsyncFunctionDef | ast.FunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            func = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(func, ast.Attribute) and func.attr in {"get", "post", "put", "patch", "delete"}:
                out.append(node)
                break
    return out


def _required_permissions(func: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    """Permissions a route enforces, read from its signature.

    Only ``Depends(require_permission("x"))`` counts. A bare
    ``Annotated[Any, require_permission("x")]`` with no ``Depends`` is the
    shape FastAPI silently discards — it reads as gated and enforces nothing,
    and eleven routes shipped that way — so it must not satisfy this rule.
    """
    found: set[str] = set()
    for arg in list(func.args.args) + list(func.args.kwonlyargs):
        if arg.annotation is None:
            continue
        for node in ast.walk(arg.annotation):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Depends"):
                continue
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == "require_permission"
                    and inner.args
                    and isinstance(inner.args[0], ast.Constant)
                ):
                    found.add(str(inner.args[0].value))
    return found


def _check_routes(root: Path) -> list[str]:
    source = _read(root, ROUTES_PATH)
    if not source:
        return [f"ROUTES: {ROUTES_PATH} is absent; the inventory has no reader."]
    failures: list[str] = []
    routes = _route_functions(source)
    if not routes:
        failures.append(f"ROUTES: {ROUTES_PATH} declares no routes.")
    for func in routes:
        if not _required_permissions(func):
            failures.append(
                f"ROUTES: {ROUTES_PATH}::{func.name} enforces no permission through Depends(require_permission(...)). "
                f"This inventory names which agent on which device holds which provider key; a route that only "
                f"authenticates hands that to anyone with a session."
            )
    router = _read(root, ROUTER_PATH)
    if "ai_assets" not in router:
        failures.append(f"ROUTES: {ROUTER_PATH} does not include the ai_assets router, so no path is served.")
    return failures


def _check_permissions(root: Path) -> list[str]:
    """Every permission the routes name is mintable and held by a role."""
    source = _read(root, ROUTES_PATH)
    if not source:
        return []
    needed: set[str] = set()
    for func in _route_functions(source):
        needed |= _required_permissions(func)
    if not needed:
        return []
    security = _read(root, SECURITY_PATH)
    scopes = _read(root, SCOPES_PATH)
    failures: list[str] = []
    for permission in sorted(needed):
        # A wildcard role holding it is not a role holding it: `admin` and
        # `platform_admin` hold `*`, so looking for the literal string is the
        # only way to see a grant somebody deliberately made.
        if f'"{permission}"' not in security:
            failures.append(
                f"PERMISSIONS: no role in {SECURITY_PATH} holds {permission!r}. Only the wildcard roles could "
                f"use the route, which is the shape hunts:read shipped in — in the vocabulary, held by nobody."
            )
        if f'"{permission}"' not in scopes:
            failures.append(
                f"PERMISSIONS: {permission!r} is absent from VALID_SCOPES in {SCOPES_PATH}, so no API key or "
                f"workload identity can be minted with it and only a wildcard key works."
            )
    return failures


def _calls_within(source: str, function_name: str, needles: tuple[str, ...]) -> bool:
    """True when ``function_name``'s body mentions every needle.

    Scoped to the one function rather than the file, because a recorder
    imported at the top and called from a path that only runs under a flag is
    the defect, not the fix.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == function_name:
            body = ast.unparse(node)
            return all(needle in body for needle in needles)
    return False


def _check_writer(root: Path) -> list[str]:
    """Something writes the table, on the profile the console runs on."""
    failures: list[str] = []
    recorder = _read(root, RECORDER_PATH)
    if not recorder:
        return [
            f"WRITER: {RECORDER_PATH} is absent. The inventory page would render an empty table forever and "
            f"look like a tenant with no AI estate rather than a feature nobody wired."
        ]
    if TABLE not in recorder:
        failures.append(f"WRITER: {RECORDER_PATH} never names {TABLE}, so whatever it writes, it is not the inventory.")

    consumer = _read(root, CONSUMER_PATH)
    if not _calls_within(consumer, "_process_message", ("_ai_assets.observe",)):
        failures.append(
            f"WRITER: {CONSUMER_PATH}::_process_message does not reach the recorder. Module reachability cannot "
            f"see this: the module imports, the tests pass, and no event ever reaches it."
        )
    main = _read(root, FUSION_MAIN)
    if "AiAssetRecorder(" not in main:
        failures.append(
            f"WRITER: {FUSION_MAIN} never constructs AiAssetRecorder, so the consumer's reference is None on "
            f"every deployment and each call site skips it in silence."
        )
    return failures


def _check_kinds(root: Path) -> list[str]:
    recorder = _read(root, RECORDER_PATH)
    if not recorder:
        return []
    missing = [kind for kind in REQUIRED_KINDS if f'"{kind}"' not in recorder]
    if missing:
        return [
            f"KINDS: the recorder classifies nothing as {', '.join(missing)}. The plan names six kinds of AI "
            f"asset and an inventory that cannot hold one of them is silently partial."
        ]
    return []


def _all_node_labels(go_text: str) -> set[str]:
    """Members of the ``AllNodeLabels`` literal, comments excluded."""
    match = re.search(r"AllNodeLabels\s*=\s*\[\]NodeLabel\{(.*?)\n\}", go_text, re.DOTALL)
    if not match:
        return set()
    members: set[str] = set()
    for line in match.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        members.add(stripped.rstrip(","))
    return members


def _check_graph(root: Path) -> list[str]:
    """The label is declared on both sides and something emits it."""
    failures: list[str] = []
    yaml_text = _read(root, GRAPH_YAML)
    go_text = _read(root, GRAPH_GO)
    extractor = _read(root, EXTRACTOR_GO)
    if f"label: {GRAPH_LABEL}" not in yaml_text:
        failures.append(f"GRAPH: {GRAPH_YAML} does not declare node label {GRAPH_LABEL}.")
    if f'NodeAIAsset NodeLabel = "{GRAPH_LABEL}"' not in go_text.replace("\t", " ").replace("  ", " "):
        failures.append(f"GRAPH: {GRAPH_GO} does not declare NodeAIAsset = {GRAPH_LABEL!r}.")
    # Declared and never enumerated is the drift a schema gate is blind to:
    # the YAML lists the label, the Go constant exists, and AllNodeLabels —
    # the list every consumer reads — does not. Parsed out of the literal
    # rather than substring-matched, because `// NodeAIAsset,` contains the
    # substring and means the opposite.
    if "NodeAIAsset" not in _all_node_labels(go_text):
        failures.append(f"GRAPH: NodeAIAsset is not in AllNodeLabels in {GRAPH_GO}, so no consumer enumerates it.")
    if "NodeAIAsset" not in extractor:
        failures.append(
            f"GRAPH: {EXTRACTOR_GO} never emits an {GRAPH_LABEL} node. The label would exist in the vocabulary and in no database."
        )
    return failures


def _strip_ts_comments(source: str) -> str:
    """Drop `//` and `/* */` so the gate does not read its own prose.

    `check_gate_coverage.py` counted a gate named only in a docstring as
    invoked, and reported "all reachable" while the gate ran in no workflow.
    The same mistake here would be a component documenting that it does not
    fabricate, failing for saying so.
    """
    without_block = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"^\s*//.*$", "", without_block, flags=re.MULTILINE)


def _check_console(root: Path) -> list[str]:
    source = _read(root, CONSOLE_PAGE)
    if not source:
        return [f"CONSOLE: {CONSOLE_PAGE} is absent; the plan requires a page that lists the estate."]
    failures: list[str] = []
    for needle, label in (("firstSeen", "first seen"), ("lastSeen", "last seen"), ("risk", "risk")):
        if needle not in source:
            failures.append(f"CONSOLE: {CONSOLE_PAGE} does not render {label}, which the plan names as a required column.")
    code = _strip_ts_comments(source)
    if re.search(r"\?\?\s*(MOCK|SAMPLE|DEMO_[A-Z_]*ASSET)", code) or "fallbackData" in code:
        failures.append(
            f"CONSOLE: {CONSOLE_PAGE} falls back to fabricated rows. An invented AI inventory is worse than an "
            f"empty one: it is a security surface a reader would act on."
        )
    return failures


RULES = (
    ("MIGRATION", _check_migration),
    ("MODEL", _check_model),
    ("ROUTES", _check_routes),
    ("PERMISSIONS", _check_permissions),
    ("WRITER", _check_writer),
    ("KINDS", _check_kinds),
    ("GRAPH", _check_graph),
    ("CONSOLE", _check_console),
)


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []
    for _, rule in RULES:
        failures.extend(rule(root))
    return failures


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

#: One injected violation per rule. Each is a plausible edit rather than a
#: deletion where that is possible, because deleting a file proves only that
#: the gate notices an absent file.
INJECTIONS: tuple[tuple[str, Path, str, str], ...] = (
    ("MIGRATION", MIGRATIONS_DIR, f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY;", "-- force removed"),
    ("MODEL", MODEL_PATH, f'__tablename__ = "{TABLE}"', '__tablename__ = "aisoc_ai_assets_v2"'),
    ("ROUTES", ROUTES_PATH, "Depends(require_permission", "Annotated_discarded(require_permission"),
    ("PERMISSIONS", SECURITY_PATH, '"ai_estate:read"', '"ai_estate:read_TYPO"'),
    ("WRITER", CONSUMER_PATH, "await self._ai_assets.observe(payload)", "await _noop(payload)"),
    ("KINDS", RECORDER_PATH, '"coding_agent"', '"coding_agent_TYPO"'),
    # Commenting the member out, not deleting it — the shape a reviewer waves
    # through, and the one a substring match cannot see.
    ("GRAPH", GRAPH_GO, "\tNodeAIAsset,", "\t// NodeAIAsset,"),
    # Renamed rather than suffixed: `firstSeenXX` still contains `firstSeen`,
    # so a suffix injection would be caught by a gate that does nothing.
    ("CONSOLE", CONSOLE_PAGE, "firstSeen", "createdOn"),
)


def _materialise(dest: Path) -> None:
    for rel in READ_PATHS:
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / rel)
    src_dir = REPO_ROOT / MIGRATIONS_DIR
    if src_dir.is_dir():
        (dest / MIGRATIONS_DIR).mkdir(parents=True, exist_ok=True)
        for sql in src_dir.glob("*.sql"):
            shutil.copy2(sql, dest / MIGRATIONS_DIR / sql.name)


#: Injections where renaming one occurrence proves nothing: four roles hold
#: the permission, and `firstSeen` appears in both the wire type and the cell
#: that renders it, so renaming the declaration alone leaves the column there.
_REPLACE_ALL = {"PERMISSIONS", "CONSOLE"}


def _apply(root: Path, target: Path, old: str, new: str, *, replace_all: bool = False) -> bool:
    if target == MIGRATIONS_DIR:
        for sql in (root / MIGRATIONS_DIR).glob("*.sql"):
            text = sql.read_text(encoding="utf-8")
            if old in text:
                sql.write_text(text.replace(old, new, -1 if replace_all else 1), encoding="utf-8")
                return True
        return False
    path = root / target
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return False
    path.write_text(text.replace(old, new, -1 if replace_all else 1), encoding="utf-8")
    return True


def _self_test() -> int:
    print(f"{Path(__file__).name} --self-test\n")
    results: list[tuple[str, bool]] = []

    clean = Path(tempfile.mkdtemp(prefix="ai-inv-clean-"))
    try:
        _materialise(clean)
        baseline = evaluate(clean)
        results.append(("the unmodified tree passes", not baseline))
        if baseline:
            for line in baseline:
                print(f"        baseline: {line}")
    finally:
        shutil.rmtree(clean, ignore_errors=True)

    for rule_name, target, old, new in INJECTIONS:
        tmp = Path(tempfile.mkdtemp(prefix="ai-inv-"))
        try:
            _materialise(tmp)
            applied = _apply(tmp, target, old, new, replace_all=rule_name in _REPLACE_ALL)
            if not applied:
                results.append((f"{rule_name}: injection applies", False))
                continue
            failures = evaluate(tmp)
            caught = any(line.startswith(f"{rule_name}:") for line in failures)
            results.append((f"{rule_name}: catches {old!r} -> {new!r}", caught))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # An empty tree must be refused, not reported clean. A gate whose silent
    # answer to "nothing is here" is OK certifies a deleted feature.
    empty = Path(tempfile.mkdtemp(prefix="ai-inv-empty-"))
    try:
        results.append(("refuses an empty tree rather than reporting it clean", bool(evaluate(empty))))
    finally:
        shutil.rmtree(empty, ignore_errors=True)

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
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

    if not (REPO_ROOT / MIGRATIONS_DIR).is_dir():
        print("check_ai_asset_inventory: no migrations directory — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("AI asset inventory (depth plan 6.1) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s) across {len(RULES)} rule(s).", file=sys.stderr)
        return 1

    print(
        f"OK — {TABLE} created with forced RLS, authorized routes, a writer on the "
        f"fusion path, {len(REQUIRED_KINDS)} asset kinds, a graph label emitted at "
        f"ingest, and a console page."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

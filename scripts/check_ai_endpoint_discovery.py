#!/usr/bin/env python3
"""Endpoint discovery of the AI estate, with no new agent.

Depth plan 6.2.

The defect this gate exists to prevent
--------------------------------------
The endpoint branch of the AI-asset recorder read `process.name` off the OCSF
event. The canonical OCSF profile carries `title`, `external_id` and the
identity aliases and **nothing else**, so that field is `None` for every
endpoint source this product has — `fleetdm`, `osctrl`, `auditd` and
`windows_event` all put their process fields in the connector payload under
`raw_data`. The module imported, the unit tests passed against events built
in the shape the module expected, and endpoint discovery could never have
produced one row on a real deployment.

So the first rule is not "is there a classifier" but **"does it read the
namespace the connectors actually produce"**, and the second is that each of
those four connectors' own field names is recognised. Both are checked by
parsing the recorder rather than by calling it, so the gate runs on a bare
interpreter before any service venv exists.

Why the capability table is a rule
----------------------------------
The plan asks, in words, to *record what each source can and cannot see*. A
table listing only what a source provides reads as complete coverage. The
blind spots are the half an analyst needs when a column on the inventory page
is empty, because "no device" and "this source has never carried a device"
are different facts and only one of them is a finding. The rule therefore
requires **both** halves for every source, and checks the set in both
directions: every source the recorder can emit must be in the table, and
every source in the table must be one the recorder can emit.

Usage:
    python3 scripts/check_ai_endpoint_discovery.py
    python3 scripts/check_ai_endpoint_discovery.py --self-test
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

RECORDER_PATH = Path("services/fusion/app/services/ai_asset_recorder.py")
PACK_PATH = Path("packs/aisoc-ai-estate.yaml")
PACK_README = Path("packs/README.md")
DOC_PATH = Path("apps/docs/docs/concepts/ai-estate-discovery.md")

READ_PATHS = (RECORDER_PATH, PACK_PATH, PACK_README, DOC_PATH)

#: Field names the four endpoint connectors put a process in. Read out of
#: each connector's own `normalize()`, not assumed:
#:
#:   windows_event -> `process_name` at the top level, `Image` lifted out of
#:                    `EventData` into `raw_event`
#:   auditd        -> `exe`
#:   fleetdm       -> the osquery row's columns, flattened; `name` and `path`
#:                    for the `processes` table
REQUIRED_PROCESS_FIELDS = ("process_name", "Image", "exe", "name", "path")

#: Command-line field names, same sources. The command line is where a
#: disabled-permission-prompt flag appears and nowhere else.
REQUIRED_COMMAND_FIELDS = ("CommandLine", "cmdline", "argv")

#: The MCP clients depth 6.2 names as "popular". Each must be recognised by
#: the configuration file it reads.
REQUIRED_MCP_CLIENTS = ("Claude Desktop", "Cursor", "Windsurf", "VS Code", "Continue", "Amazon Q")

#: Queries the osquery pack must carry. Named individually because a pack
#: with four of the five is silently partial.
REQUIRED_PACK_QUERIES = (
    "coding_agent_processes",
    "mcp_server_processes",
    "mcp_client_configurations",
    "ai_ide_extensions",
)

#: Columns the recorder classifies on. A pack that stops selecting one of
#: these keeps running and stops producing assets, with nothing to say so.
REQUIRED_PACK_COLUMNS = ("name", "path", "cmdline", "directory")


def _read(root: Path, rel: Path) -> str:
    path = root / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _module(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _assigned_collection(tree: ast.Module, name: str) -> list[str]:
    """String literals in a module-level assignment to `name`."""
    for node in tree.body:
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if node.value is None:
            return []
        return [n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return []


def _function_body(tree: ast.Module, name: str) -> str:
    """The function's code, with its docstring removed.

    Dropping the docstring is not tidiness. `check_gate_coverage.py` counted a
    gate named only in a docstring as invoked and reported "all reachable"
    while the gate ran in no workflow at all; a rule here that matched a
    function's own prose would pass on a body that had stopped calling the
    thing the prose describes — which is precisely the injection the
    self-test performs.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == name:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            return "\n".join(ast.unparse(stmt) for stmt in body)
    return ""


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _check_namespace(root: Path) -> list[str]:
    """The endpoint branch reads the connector payload, not only OCSF."""
    source = _read(root, RECORDER_PATH)
    if not source:
        return [f"NAMESPACE: {RECORDER_PATH} is absent."]
    tree = _module(source)
    if tree is None:
        return [f"NAMESPACE: {RECORDER_PATH} does not parse."]

    failures: list[str] = []
    reconstructor = _function_body(tree, "_connector_fields")
    if not reconstructor:
        return [
            f"NAMESPACE: {RECORDER_PATH} has no _connector_fields. Every endpoint field this item "
            f"needs lives in the connector payload under raw_data, and the canonical OCSF profile maps "
            f"none of them, so a reader without this finds None on every real source."
        ]
    for needle, why in (
        ("raw_data", "the connector payload is stored there as a JSON string by services/ingest"),
        ("raw_event", "connectors nest the untouched vendor payload one level deeper"),
    ):
        if needle not in reconstructor:
            failures.append(f"NAMESPACE: _connector_fields never reads {needle!r} — {why}.")

    endpoint = _function_body(tree, "_from_endpoint")
    if not endpoint:
        failures.append(f"NAMESPACE: {RECORDER_PATH} has no _from_endpoint, so nothing classifies endpoint telemetry.")
    elif "_connector_fields" not in endpoint:
        failures.append(
            "NAMESPACE: _from_endpoint does not call _connector_fields, so it is reading OCSF slots the "
            "endpoint connectors never populate. This is the exact defect the item reproduced."
        )
    return failures


def _check_fields(root: Path) -> list[str]:
    """Each endpoint connector's own field names are recognised."""
    source = _read(root, RECORDER_PATH)
    tree = _module(source) if source else None
    if tree is None:
        return []
    failures: list[str] = []
    process_fields = set(_assigned_collection(tree, "PROCESS_FIELDS"))
    for field in REQUIRED_PROCESS_FIELDS:
        if field not in process_fields:
            failures.append(
                f"FIELDS: PROCESS_FIELDS does not include {field!r}. One of the four endpoint "
                f"connectors puts its executable there and will contribute nothing."
            )
    command_fields = set(_assigned_collection(tree, "COMMAND_LINE_FIELDS"))
    for field in REQUIRED_COMMAND_FIELDS:
        if field not in command_fields:
            failures.append(
                f"FIELDS: COMMAND_LINE_FIELDS does not include {field!r}. The command line is the only "
                f"place a disabled-permission-prompt flag appears."
            )
    return failures


def _check_clients(root: Path) -> list[str]:
    """Every MCP client the plan names is recognised by its config file."""
    source = _read(root, RECORDER_PATH)
    tree = _module(source) if source else None
    if tree is None:
        return []
    declared = set(_assigned_collection(tree, "MCP_CLIENT_CONFIGS"))
    missing = [client for client in REQUIRED_MCP_CLIENTS if client not in declared]
    if missing:
        return [
            f"CLIENTS: MCP_CLIENT_CONFIGS does not recognise {', '.join(missing)}. A configuration file is "
            f"the evidence that a server is wired in, which survives a reboot and a process listing that "
            f"missed the window."
        ]
    if not _assigned_collection(tree, "AI_IDE_EXTENSIONS"):
        return ["CLIENTS: AI_IDE_EXTENSIONS is empty, so no IDE extension can ever be inventoried."]
    return []


def _check_capabilities(root: Path) -> list[str]:
    """Every source declares what it sees AND what it cannot, both ways."""
    source = _read(root, RECORDER_PATH)
    tree = _module(source) if source else None
    if tree is None:
        return []
    failures: list[str] = []

    sources = set(_assigned_collection(tree, "DISCOVERY_SOURCES"))
    if not sources:
        return ["CAPABILITIES: DISCOVERY_SOURCES is absent, so there is nothing to describe."]

    table: dict[str, str] = {}
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else ([node.target] if isinstance(node, ast.AnnAssign) else [])
        if not any(isinstance(t, ast.Name) and t.id == "SOURCE_CAPABILITIES" for t in targets):
            continue
        # Narrowed explicitly: `tree.body` is `list[ast.stmt]`, and only the
        # two assignment forms carry a `.value`. Reading it off the statement
        # works for the nodes this loop reaches and is unchecked for the rest.
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        value = node.value
        if isinstance(value, ast.Dict):
            for key, declaration in zip(value.keys, value.values, strict=False):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and declaration is not None:
                    table[key.value] = ast.unparse(declaration)
    if not table:
        return ["CAPABILITIES: SOURCE_CAPABILITIES is absent. The plan asks, in words, to record what each source can and cannot see."]

    for missing in sorted(sources - set(table)):
        failures.append(f"CAPABILITIES: discovery source {missing!r} has no entry, so a reader cannot tell what it is blind to.")
    for extra in sorted(set(table) - sources):
        failures.append(f"CAPABILITIES: {extra!r} is described and is not a discovery source any row can carry.")

    for name, entry in sorted(table.items()):
        # The half that matters, and the half that is easy to omit.
        if "cannot_see" not in entry:
            failures.append(f"CAPABILITIES: {name!r} declares no cannot_see. No real source sees everything.")
        elif re.search(r"cannot_see\s*=\s*\(\s*\)", entry):
            failures.append(f"CAPABILITIES: {name!r} declares an empty cannot_see, which claims it is blind to nothing.")
        if "connectors" not in entry:
            failures.append(f"CAPABILITIES: {name!r} names no connector, so nothing says where its rows come from.")
    return failures


def _check_pack(root: Path) -> list[str]:
    """The osquery pack exists, is indexed, and selects what the recorder reads."""
    pack = _read(root, PACK_PATH)
    if not pack:
        return [
            f"PACK: {PACK_PATH} is absent. The plan requires an osquery pack for MCP client "
            f"configuration files and IDE extension directories, so a fleet already running osquery "
            f"gets this with no new agent."
        ]
    failures: list[str] = []
    for query in REQUIRED_PACK_QUERIES:
        if f"{query}:" not in pack:
            failures.append(f"PACK: {PACK_PATH} has no {query!r} query, so that evidence is never collected.")
    for column in REQUIRED_PACK_COLUMNS:
        if column not in pack:
            failures.append(
                f"PACK: {PACK_PATH} never selects {column!r}. The recorder classifies on it, so a pack "
                f"that stops selecting it keeps running and stops producing assets with nothing to say so."
            )
    # A pack nobody can find is a pack nobody assigns.
    if "aisoc-ai-estate" not in _read(root, PACK_README):
        failures.append(f"PACK: {PACK_README} does not list the pack in its curated table, so nobody discovers it.")
    return failures


def _check_doc(root: Path) -> list[str]:
    doc = _read(root, DOC_PATH)
    if not doc:
        return [f"DOC: {DOC_PATH} is absent. What each source can and cannot see has to be readable by an operator, not only by a test."]
    failures: list[str] = []
    if "cannot see" not in doc.lower():
        failures.append(f"DOC: {DOC_PATH} never says what a source cannot see, which is the half that makes an empty column readable.")
    for connector in ("fleetdm", "osctrl", "auditd", "windows_event"):
        if connector not in doc:
            failures.append(f"DOC: {DOC_PATH} does not mention {connector}, one of the four sources endpoint discovery reads.")
    # The honest limit. CrowdStrike, SentinelOne and Defender poll the
    # vendor's own *detections*, not raw process telemetry, so they cannot
    # supply a process start — and a reader who assumes otherwise concludes
    # their EDR is covering this when it is not.
    if "detections" not in doc.lower():
        failures.append(
            f"DOC: {DOC_PATH} does not record that the EDR connectors return vendor detections rather than "
            f"process telemetry. A reader would assume their EDR covers this."
        )
    return failures


RULES = (
    ("NAMESPACE", _check_namespace),
    ("FIELDS", _check_fields),
    ("CLIENTS", _check_clients),
    ("CAPABILITIES", _check_capabilities),
    ("PACK", _check_pack),
    ("DOC", _check_doc),
)


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []
    for _, rule in RULES:
        failures.extend(rule(root))
    return failures


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

INJECTIONS: tuple[tuple[str, Path, str, str], ...] = (
    # The original defect: read OCSF instead of the connector namespace.
    ("NAMESPACE", RECORDER_PATH, "fields = _connector_fields(ocsf)", "fields = dict(ocsf)"),
    ("FIELDS", RECORDER_PATH, '"process_name", "Image", "exe"', '"process_name", "Image"'),
    ("CLIENTS", RECORDER_PATH, '"Windsurf"', '"Windsurf_TYPO"'),
    ("CAPABILITIES", RECORDER_PATH, '"endpoint": SourceCapability(', '"endpoint_TYPO": SourceCapability('),
    ("PACK", PACK_PATH, "mcp_client_configurations:", "mcp_client_configurations_disabled:"),
    # Renamed, not suffixed: `windows_event_TYPO` still contains
    # `windows_event`, so a suffix injection would be caught by a gate doing
    # nothing at all.
    ("DOC", DOC_PATH, "windows_event", "wef-forwarding"),
)


def _materialise(dest: Path) -> None:
    for rel in READ_PATHS:
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / rel)


def _apply(root: Path, target: Path, old: str, new: str) -> bool:
    path = root / target
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return False
    path.write_text(text.replace(old, new), encoding="utf-8")
    return True


def _self_test() -> int:
    print(f"{Path(__file__).name} --self-test\n")
    results: list[tuple[str, bool]] = []

    clean = Path(tempfile.mkdtemp(prefix="ai-endpoint-clean-"))
    try:
        _materialise(clean)
        baseline = evaluate(clean)
        results.append(("the unmodified tree passes", not baseline))
        for line in baseline:
            print(f"        baseline: {line}")
    finally:
        shutil.rmtree(clean, ignore_errors=True)

    for rule_name, target, old, new in INJECTIONS:
        tmp = Path(tempfile.mkdtemp(prefix="ai-endpoint-"))
        try:
            _materialise(tmp)
            if not _apply(tmp, target, old, new):
                results.append((f"{rule_name}: injection applies", False))
                continue
            caught = any(line.startswith(f"{rule_name}:") for line in evaluate(tmp))
            results.append((f"{rule_name}: catches {old!r} -> {new!r}", caught))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    empty = Path(tempfile.mkdtemp(prefix="ai-endpoint-empty-"))
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

    if not (REPO_ROOT / "services" / "fusion").is_dir():
        print("check_ai_endpoint_discovery: no fusion service — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("Endpoint discovery of the AI estate (depth plan 6.2) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s) across {len(RULES)} rule(s).", file=sys.stderr)
        return 1

    print(
        f"OK — endpoint discovery reads the connector namespace, recognises "
        f"{len(REQUIRED_MCP_CLIENTS)} MCP clients, ships an osquery pack with "
        f"{len(REQUIRED_PACK_QUERIES)} queries, and records what each source cannot see."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

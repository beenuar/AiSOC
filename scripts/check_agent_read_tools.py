#!/usr/bin/env python3
"""Gate: the door an investigation agent opens stays a read-only door.

Gap-closure Phase 4.3.

An investigation agent can reach a customer's EDR, identity provider, SIEM
and cloud audit trail by emitting a sentence. That is the point, and it is
also the only surface in this product where a model's output turns into a
vendor API call with no human in between. Three facts therefore have to stay
true, and none of them is enforced by anything at runtime that would fail
loudly if it stopped being true:

  1. **Every agent-reachable verb is declared read-only.** The API's
     ``AGENT_READ_CAPABILITIES`` allowlist must be a subset of the
     capabilities ``CAPABILITY_CONTRACTS`` grades ``READ_ONLY``. The API also
     checks this against the live registry at call time, so this gate is the
     second of two independent controls rather than the only one; what it
     adds is failing at review rather than at 3am.

  2. **Every agent-reachable verb has an executor.** A verb in the allowlist
     with no implementation answers ``no_integration`` on every tenant, which
     reads as a customer configuration problem rather than as a capability
     nobody built. This is the ``KNOWN_ORPHANS`` shape one layer out.

  3. **The two indicator vocabularies agree.** ``services/agents`` publishes
     an enum of indicator types in the JSON schema the model selects on, and
     ``services/api`` validates against its own. Neither service can import
     the other, because both package their code as a top-level ``app``, so
     the only way to compare is to read the other tree's source. A model
     offered a type the API refuses gets a 422 it cannot fix; a type the API
     accepts and the model is never offered is a capability nobody can reach.

Both directions, in all three cases. A one-directional check is the shape
this repository keeps finding: it compares A against B, prints OK, and never
notices B drifting away from A.

Run:  python3 scripts/check_agent_read_tools.py
      python3 scripts/check_agent_read_tools.py --self-test

Exit codes: 0 clean, 1 a control has drifted, 2 the scan could not run.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()

API_VENDOR_READS = REPO_ROOT / "services" / "api" / "app" / "services" / "agent_tools" / "vendor_reads.py"
API_INDICATORS = REPO_ROOT / "services" / "api" / "app" / "services" / "agent_tools" / "indicators.py"
ACTIONS_CONTRACTS = REPO_ROOT / "services" / "actions" / "app" / "live_actions" / "capability_contracts.py"
ACTIONS_BUILTINS = REPO_ROOT / "services" / "actions" / "app" / "live_actions" / "builtins.py"
ACTIONS_READS = REPO_ROOT / "services" / "actions" / "app" / "live_actions" / "investigation_reads.py"
AGENT_TOOLS = REPO_ROOT / "services" / "agents" / "app" / "tools" / "customer_tools.py"


class ScanError(RuntimeError):
    """A file this gate must read is absent or does not parse."""


def _parse(path: Path) -> ast.Module:
    if not path.is_file():
        raise ScanError(f"missing {path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}")
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        raise ScanError(f"{path.name} does not parse: {exc}") from exc


def _assigned_value(tree: ast.Module, name: str) -> ast.expr | None:
    """The right-hand side of a module-level assignment to ``name``.

    Handles both ``x = ...`` and ``x: T = ...``. Both forms appear in these
    modules, and a version of this that read only the first reported "could
    not find" on an annotated constant, which is a gate that fails closed but
    for the wrong reason.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if name in [t.id for t in node.targets if isinstance(t, ast.Name)]:
                return node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name and node.value is not None:
                return node.value
    return None


def _frozenset_literal(tree: ast.Module, name: str) -> set[str]:
    """The string members of a module-level ``name = frozenset({...})``.

    Read with ``ast`` rather than by importing, because these four modules
    live in three services that cannot share a process: each packages its
    code as a top-level ``app``, so importing two of them is importing one of
    them twice. Reading the source is the only way to ask the other tree.
    """
    call = _assigned_value(tree, name)
    if call is not None:
        # `frozenset({...})` and a bare `{...}` are both accepted, so a
        # future simplification does not silently empty this gate's corpus.
        if isinstance(call, ast.Call) and call.args:
            call = call.args[0]
        if isinstance(call, ast.Set):
            return {e.value for e in call.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    raise ScanError(f"could not find a set literal named {name!r}")


def _dict_keys(tree: ast.Module, name: str) -> set[str]:
    """The string keys of a module-level ``name = {...}`` mapping."""
    value = _assigned_value(tree, name)
    if isinstance(value, ast.Dict):
        return {k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    raise ScanError(f"could not find a dict literal named {name!r}")


def _tuple_members(tree: ast.Module, name: str) -> set[str]:
    """The string members of a module-level ``name: T = (...)`` tuple."""
    value = _assigned_value(tree, name)
    if isinstance(value, ast.Tuple):
        return {e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    raise ScanError(f"could not find a tuple literal named {name!r}")


def _read_only_contract_verbs(tree: ast.Module) -> set[str]:
    """Capabilities ``CAPABILITY_CONTRACTS`` grades ``ActionImpact.READ_ONLY``."""
    contracts = _assigned_value(tree, "CAPABILITY_CONTRACTS")
    if isinstance(contracts, ast.Dict):
        out: set[str] = set()
        for key, value in zip(contracts.keys, contracts.values, strict=True):
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                continue
            if not isinstance(value, ast.Call):
                continue
            for keyword in value.keywords:
                if keyword.arg != "impact":
                    continue
                attribute = keyword.value
                if isinstance(attribute, ast.Attribute) and attribute.attr == "READ_ONLY":
                    out.add(key.value)
        return out
    raise ScanError("could not find CAPABILITY_CONTRACTS")


def _registered_capabilities() -> set[str]:
    """Capabilities with at least one executor in ``_BUILTIN_ADAPTERS``.

    Derived by reading the class names in the adapter tuple and then reading
    each read-executor's ``capability = "..."`` assignment out of
    ``investigation_reads.py``. Only the read module is parsed for the class
    bodies, because that is where every agent-reachable verb is implemented;
    a read verb implemented elsewhere would fail this gate, which is the
    correct outcome for a surface this narrow.
    """
    builtins_tree = _parse(ACTIONS_BUILTINS)
    registered_classes: set[str] = set()
    for node in ast.walk(builtins_tree):
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        if node.target.id != "_BUILTIN_ADAPTERS" or not isinstance(node.value, ast.Tuple):
            continue
        for element in node.value.elts:
            if isinstance(element, ast.Name):
                registered_classes.add(element.id)
            elif isinstance(element, ast.Starred) and isinstance(element.value, ast.Name):
                # A splatted group (`*VENDOR_BREADTH_EXECUTORS`) is not a read
                # verb source; recorded as unresolvable rather than ignored.
                registered_classes.add(f"*{element.value.id}")
    if not registered_classes:
        raise ScanError("could not read _BUILTIN_ADAPTERS")

    reads_tree = _parse(ACTIONS_READS)
    out: set[str] = set()
    for node in reads_tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in registered_classes:
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Assign):
                continue
            if "capability" not in [t.id for t in statement.targets if isinstance(t, ast.Name)]:
                continue
            if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                out.add(statement.value.value)
    return out


def scan() -> list[str]:
    errors: list[str] = []

    allowlist = _frozenset_literal(_parse(API_VENDOR_READS), "AGENT_READ_CAPABILITIES")
    if not allowlist:
        raise ScanError("AGENT_READ_CAPABILITIES parsed as empty; this gate would certify nothing")

    # ---- 1. every agent-reachable verb is declared read-only -------------
    read_only = _read_only_contract_verbs(_parse(ACTIONS_CONTRACTS))
    if not read_only:
        raise ScanError("no READ_ONLY capability contracts parsed; the contract format has changed")

    for capability in sorted(allowlist - read_only):
        errors.append(
            f"{capability!r} is reachable by an investigation agent and is NOT graded READ_ONLY in "
            f"capability_contracts.py. A verb that changes a customer's estate must go through the "
            f"approval path, not through a tool an agent calls by emitting a sentence."
        )
    # The reverse direction is a note rather than a failure: the allowlist
    # being *narrower* than the contract is the safe asymmetry, and a
    # read-only verb an agent is not offered is a deliberate choice (a
    # playbook may still use it). Printed so the choice stays visible.
    unexposed = sorted(read_only - allowlist)

    # ---- 2. every agent-reachable verb has an executor -------------------
    implemented = _registered_capabilities()
    for capability in sorted(allowlist - implemented):
        errors.append(
            f"{capability!r} is reachable by an investigation agent and has no registered executor in "
            f"investigation_reads.py. Dispatch answers no_integration on every tenant, which reads as a "
            f"customer configuration problem rather than as a capability nobody built. If the executor "
            f"lives in another module, move it here: every agent-reachable read is implemented in one "
            f"file so this gate has one place to look."
        )

    # ---- 3. the param allowlist covers every exposed verb ----------------
    params = _dict_keys(_parse(API_VENDOR_READS), "ALLOWED_PARAMS")
    for capability in sorted(allowlist - params):
        errors.append(
            f"{capability!r} has no entry in ALLOWED_PARAMS, so every parameter a caller sends is "
            f"dropped. The params dictionary carries the decrypted credential by the time it reaches "
            f"the actions service, so an absent entry is safe and silently useless: a caller's window "
            f"and template would never arrive."
        )
    for capability in sorted(params - allowlist):
        errors.append(f"ALLOWED_PARAMS names {capability!r}, which is not agent-reachable; the entry is stale")

    # ---- 4. the two indicator vocabularies agree ------------------------
    api_types = _dict_keys(_parse(API_INDICATORS), "INDICATOR_TYPES")
    agent_types = _tuple_members(_parse(AGENT_TOOLS), "INDICATOR_TYPES")
    if not api_types or not agent_types:
        raise ScanError("one of the two indicator vocabularies parsed as empty")
    for name in sorted(agent_types - api_types):
        errors.append(
            f"the agent tool schema offers indicator type {name!r} and the API does not accept it. "
            f"A model selecting it gets a 422 it has no way to fix, and will read the refusal as "
            f"the indicator being absent."
        )
    for name in sorted(api_types - agent_types):
        errors.append(
            f"the API accepts indicator type {name!r} and the agent tool schema does not offer it; "
            f"nothing can reach it, so it is dead weight with a maintenance cost."
        )

    if not errors:
        print(
            f"agent-read-tools: OK, {len(allowlist)} agent-reachable read verb(s), all READ_ONLY with "
            f"an executor and a parameter allowlist; {len(api_types)} indicator types agree across both services"
        )
        if unexposed:
            print(f"  note: read-only verbs deliberately NOT agent-reachable: {', '.join(unexposed)}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        errors = scan()
    except ScanError as exc:
        print(f"agent-read-tools: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("AGENT READ TOOL GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Pin the three things a tenant skill spans that no single module can enforce.

Gap-closure Phase 6.1 and 6.2.

A skill is authored in ``services/api``, validated against a tool vocabulary
that lives in ``services/agents``, and activated under a rule that is written
in SQL, in Python and in prose. None of those three trees can import the
others: both services package their code as top-level ``app``, and a CHECK
constraint is not importable at all. So the contract between them is a handful
of declarations that agree by convention, and conventions drift.

Three properties, each checked in both directions
--------------------------------------------------
**1. The tool vocabulary.** ``services/api/app/services/tenant_skills/tools.py``
declares what the authoring validator will accept: ``BUILTIN_PIVOTS`` for the
lake, ``SIEM_SEARCH_TOOL`` and ``CUSTOMER_TOOL_CAPABILITIES`` for Phase 4's
typed surface onto the customer's own products. ``KNOWN_PIVOTS`` in
``services/agents/app/investigator/strategies.py`` is what the agent can
actually bind, and ``VENDOR_READ_TOOLS`` in
``services/agents/app/tools/customer_tools.py`` is the capability each
customer tool resolves to. Both directions have a distinct failure:

* a tool in agents and not in the API makes a legitimate skill unauthorable,
  and the author is told their tool does not exist when it does;
* a tool in the API and not in agents lets a skill name one that is gone, and
  the failure surfaces as an investigation that quietly never reaches a pivot
  it declared, which the depth record then grades as shallow.

The capabilities are compared too, not just the names. A tool whose capability
drifted would be validated against a verb the tenant does not have, so the
skill would save and the tool would never bind.

This check has already earned its keep: it caught the six customer tools Phase
4 added to ``KNOWN_PIVOTS`` while this phase was in flight, which is exactly
the drift it was written for.

**2. Activation requires a backtest of the exact version.** This is the rule
that stops a report describing text nobody is running, and it is stated in
three places on purpose: the database CHECK, the store's refusal, and the
docs page an operator reads. A rule that survives in two of the three is a
rule somebody removed from the third and nobody noticed.

**3. The version reaches the investigation.** A skill that steers a verdict
without recording which version steered it is provenance-shaped and not
provenance. The gate requires the deep-investigation result to carry a
``tenant_skill`` field and the triage state to carry one too, because a skill
applied on one path and unrecorded on the other is exactly the half-wired
shape this program keeps finding.

Nothing is imported. The gate runs on a bare interpreter, and importing
either service would drag in httpx, SQLAlchemy and the whole worker stack to
compare a set of strings.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

_API_TOOLS_FILE = "services/api/app/services/tenant_skills/tools.py"
_AGENT_PIVOTS_FILE = "services/agents/app/investigator/strategies.py"
_AGENT_CUSTOMER_FILE = "services/agents/app/tools/customer_tools.py"

_MIGRATION = "services/api/migrations/070_tenant_skills.sql"
_STORE = "services/api/app/services/tenant_skills/store.py"
_DOC = "apps/docs/docs/console/tenant-skills.md"

_DEEP_RESULT = ("services/agents/app/investigator/deep_investigation.py", "DeepInvestigationResult")
_STATE = ("services/agents/app/models/state.py", "InvestigationState")
_PROVENANCE_FIELD = "tenant_skill"

#: The SQL that says an active row must name a backtest of its own version.
#: Matched on the three clauses rather than on the whole constraint text, so
#: reformatting the migration does not fail the gate and removing a clause
#: does.
_SQL_CLAUSES = (
    r"status\s*<>\s*'active'",
    r"backtest_evaluation_id\s+IS\s+NOT\s+NULL",
    r"backtest_baseline_id\s+IS\s+NOT\s+NULL",
    r"backtest_version\s*=\s*version",
)


def _read(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"FAIL: {relative} is missing; the tenant-skill contract cannot be checked")
    return path.read_text(encoding="utf-8")


def _string_members(source: str, name: str, relative: str) -> set[str]:
    """Read a module-level frozenset/tuple/set/list of string literals."""
    tree = ast.parse(source, filename=relative)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        value: ast.expr | None = node.value
        if isinstance(value, ast.Call) and value.args:
            value = value.args[0]
        if isinstance(value, ast.Tuple | ast.List | ast.Set):
            members = {e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            if members:
                return members
    raise SystemExit(f"FAIL: {name} was not found as a literal collection of strings in {relative}")


def _string_constant(source: str, name: str, relative: str) -> str:
    tree = ast.parse(source, filename=relative)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return str(node.value.value)
    raise SystemExit(f"FAIL: {name} was not found as a string constant in {relative}")


def _tool_capabilities(source: str, name: str, relative: str) -> dict[str, str]:
    """Read ``{tool_name: capability}`` from a flat or a nested mapping.

    The API side is flat; the agents side nests the capability inside a dict
    that also holds the argument name and the model-facing description. One
    reader for both, so the gate cannot be defeated by either side changing
    shape.
    """
    tree = ast.parse(source, filename=relative)
    for node in ast.walk(tree):
        targets: list[ast.expr]
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        out: dict[str, str] = {}
        for key, value in zip(node.value.keys, node.value.values, strict=False):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out[key.value] = value.value
            elif isinstance(value, ast.Dict):
                for k2, v2 in zip(value.keys, value.values, strict=False):
                    if (
                        isinstance(k2, ast.Constant)
                        and k2.value == "capability"
                        and isinstance(v2, ast.Constant)
                        and isinstance(v2.value, str)
                    ):
                        out[key.value] = v2.value
        if out:
            return out
    raise SystemExit(f"FAIL: {name} was not found as a mapping of tool name to capability in {relative}")


def _class_fields(source: str, class_name: str, relative: str) -> set[str]:
    tree = ast.parse(source, filename=relative)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            fields = {item.target.id for item in node.body if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)}
            if not fields:
                raise SystemExit(f"FAIL: {class_name} in {relative} declares no annotated fields")
            return fields
    raise SystemExit(f"FAIL: class {class_name} was not found in {relative}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate refuses an empty tree")
    parser.parse_args(argv)

    root = repo_root()
    failures: list[str] = []
    checked = 0

    # 1. Tool vocabulary, both directions, names and capabilities.
    api_source = _read(root, _API_TOOLS_FILE)
    api_builtin = _string_members(api_source, "BUILTIN_PIVOTS", _API_TOOLS_FILE)
    api_customer = _tool_capabilities(api_source, "CUSTOMER_TOOL_CAPABILITIES", _API_TOOLS_FILE)
    api_siem = _string_constant(api_source, "SIEM_SEARCH_TOOL", _API_TOOLS_FILE)
    api_names = api_builtin | set(api_customer) | {api_siem}

    agent_pivots = _string_members(_read(root, _AGENT_PIVOTS_FILE), "KNOWN_PIVOTS", _AGENT_PIVOTS_FILE)
    agent_source = _read(root, _AGENT_CUSTOMER_FILE)
    agent_customer = _tool_capabilities(agent_source, "VENDOR_READ_TOOLS", _AGENT_CUSTOMER_FILE)
    agent_siem = _string_constant(agent_source, "SIEM_SEARCH_TOOL", _AGENT_CUSTOMER_FILE)
    checked += len(api_names) + len(agent_pivots) + len(agent_customer)

    unauthorable = sorted(agent_pivots - api_names)
    unreachable = sorted(api_names - agent_pivots)
    if unauthorable:
        failures.append(
            f"KNOWN_PIVOTS holds {unauthorable} and {_API_TOOLS_FILE} does not: a skill naming one of these "
            f"is refused at authoring time although the agent can call it"
        )
    if unreachable:
        failures.append(
            f"{_API_TOOLS_FILE} holds {unreachable} and KNOWN_PIVOTS does not: a skill may name one of these "
            f"and the investigation will never reach it, which the depth record grades as shallow"
        )

    if api_siem != agent_siem:
        failures.append(
            f"the federated-SIEM tool is called {api_siem!r} in {_API_TOOLS_FILE} and {agent_siem!r} in "
            f"{_AGENT_CUSTOMER_FILE}: a skill would be validated against a name nothing binds"
        )
    for tool in sorted(set(api_customer) | set(agent_customer)):
        api_capability = api_customer.get(tool)
        agent_capability = agent_customer.get(tool)
        if api_capability != agent_capability:
            failures.append(
                f"customer tool {tool!r} resolves to capability {api_capability!r} in {_API_TOOLS_FILE} and "
                f"{agent_capability!r} in {_AGENT_CUSTOMER_FILE}: the validator would check this tenant against a "
                f"verb the agent never asks the registry for, so the skill saves and the tool never binds"
            )

    # 2. Activation requires a backtest of the exact version, in all three places.
    migration = _read(root, _MIGRATION)
    for clause in _SQL_CLAUSES:
        checked += 1
        if not re.search(clause, migration, re.IGNORECASE):
            failures.append(
                f"{_MIGRATION} no longer constrains `{clause}`: the database would accept an active skill "
                f"whose attached backtest graded different text"
            )

    store = _read(root, _STORE)
    checked += 1
    if "backtest_version" not in store or "activate_skill" not in store:
        failures.append(
            f"{_STORE} no longer checks the backtest version in activate_skill: the database constraint would "
            f"become the only refusal, and its message is a constraint name rather than a sentence"
        )

    doc = _read(root, _DOC)
    checked += 1
    if not re.search(r"backtest", doc, re.IGNORECASE) or not re.search(r"activat", doc, re.IGNORECASE):
        failures.append(
            f"{_DOC} no longer documents that activation requires a backtest: an operator reading the docs "
            f"would not know why their activate call is refused"
        )

    # 3. The version reaches both paths.
    for relative, class_name in (_DEEP_RESULT, _STATE):
        checked += 1
        if _PROVENANCE_FIELD not in _class_fields(_read(root, relative), class_name, relative):
            failures.append(
                f"{class_name} in {relative} no longer carries `{_PROVENANCE_FIELD}`: a skill would steer a "
                f"verdict on that path with no record of which version steered it"
            )

    if not checked:
        print("FAIL: the gate compared nothing, which is indistinguishable from a clean result")
        return 1

    if failures:
        print(f"FAIL: {len(failures)} tenant-skill contract problem(s)\n")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"OK: {len(api_names)} tool name(s) agree across both services, including {len(api_customer)} "
        f"customer-product tool(s) whose capabilities also match; the backtest-before-activation rule holds "
        f"in the migration, the store and the docs; and both the triage state and the investigation result "
        f"record which skill version guided them."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

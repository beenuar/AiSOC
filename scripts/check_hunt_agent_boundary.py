#!/usr/bin/env python3
"""The hunting agent must not be able to write a query.

Why this exists
---------------

A hunt is a question about a whole estate's history, and the hypothesis that
prompts one comes from an advisory, a ticket, or something a customer sent in.
All of those are attacker-influenceable, so a model relaying one into a query
language is one injected instruction away from an arbitrary read across every
row a tenant can see. A read at that scale exfiltrates telemetry and, on a
metered licence, costs money.

Phase 4 drew this boundary for the SIEM search and ``check_agent_read_tools.py``
keeps it. This is the same boundary for the hunting agent, and it is checked
the same way: **on the JSON schema the model is handed**, not on the validator
behind it. The schema is what actually constrains a model. A permissive schema
with a strict validator still lets the model spend a turn producing something
that gets rejected, and more importantly it means the only thing standing
between an injected instruction and a query is code somebody could relax
without noticing the schema already allowed it.

What it checks
--------------

``query-shaped-property``
    A property the model can populate whose name suggests it carries query
    text. The list is the one ``check_agent_read_tools.py`` uses, so the two
    agent surfaces refuse the same vocabulary.

``unconstrained-string``
    A property typed ``string`` with no ``enum`` where one is required. ``field``
    and ``operator`` are the two that decide what the compiler does, and an
    open string in either is a query language with extra steps.

``field-not-in-lake``
    A field offered to the model that the ClickHouse DDL does not create. This
    is the reachability rule the rest of this program keeps relearning: a plan
    over a column nothing records returns zero while looking like it worked.

``vocabulary-drift``
    The agents-side vocabulary and the API-side compiler disagree. The two
    services package their code as a top-level ``app`` and cannot import each
    other, so the sets are written twice and this reads both. A field the
    agent may propose and the compiler refuses is a turn wasted on every run;
    a field the compiler accepts and the agent never offers is dead surface.

``compiler-interpolates``
    The compiler builds a predicate with an f-string carrying the *value*
    rather than a placeholder. Read as source, because this is the one
    property no amount of vocabulary checking substitutes for.
"""

from __future__ import annotations

import ast
import re
import sys
import types
from dataclasses import dataclass
from pathlib import Path

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

_PLAN = Path("services/agents/app/hunt/plan.py")
_COMPILER = Path("services/api/app/services/retro_hunt/hunt_plan_sql.py")
_DDL = Path("services/api/clickhouse/001_init.sql")
_AGENT = Path("services/agents/app/hunt/agent.py")

REQUIRED = (_PLAN, _COMPILER, _DDL, _AGENT)

#: Property names that would mean the model is supplying query text. The same
#: vocabulary ``check_agent_read_tools.py`` refuses on the Phase 4 tools.
_QUERY_SHAPED = frozenset(
    {
        "query",
        "search",
        "spl",
        "kql",
        "esql",
        "sql",
        "free_text",
        "freetext",
        "filter",
        "where",
        "index",
        "expression",
        "statement",
        "raw",
    }
)

#: Properties that must be closed enums. These two decide what the compiler
#: emits; everything else is a bound value.
_MUST_BE_ENUM = ("field", "operator")


@dataclass
class Finding:
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"  [{self.kind}] {self.detail}"


def _load_plan_module(root: Path):  # noqa: ANN202
    """Load ``plan.py`` by path, leaving ``sys.modules`` as it found it.

    Registration is needed because ``@dataclass`` resolves annotations through
    ``sys.modules``; removal is needed because a synthetic name left behind
    has previously broken 21 unrelated tests in this repository.
    """
    import importlib.util  # noqa: PLC0415

    alias = "_aisoc_gate_hunt_plan"
    created: list[str] = []
    for name in ("app", "app.hunt"):
        if name not in sys.modules:
            module = types.ModuleType(name)
            module.__path__ = []  # type: ignore[attr-defined]
            sys.modules[name] = module
            created.append(name)
    spec = importlib.util.spec_from_file_location(alias, root / _PLAN)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_PLAN}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(alias, None)
        for name in created:
            sys.modules.pop(name, None)


def _ddl_columns(root: Path) -> set[str]:
    sql = (root / _DDL).read_text(encoding="utf-8")
    match = re.search(r"CREATE TABLE IF NOT EXISTS aisoc\.raw_events\s*\((.*?)\n\)", sql, re.DOTALL)
    if not match:
        return set()
    out: set[str] = set()
    for line in match.group(1).splitlines():
        stripped = line.strip().rstrip(",")
        if not stripped or stripped.startswith(("--", "INDEX", "PRIMARY", "CONSTRAINT")):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            out.add(parts[0])
    return out


def _compiler_sets(root: Path) -> tuple[set[str], set[str]]:
    """``(fields, operators)`` the API-side compiler accepts."""
    tree = ast.parse((root / _COMPILER).read_text(encoding="utf-8"))
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not names:
            continue
        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "frozenset" and value.args:
            value = value.args[0]
        if isinstance(value, ast.Set | ast.List | ast.Tuple):
            found[names[0]] = {e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return found.get("_FIELDS", set()), found.get("_OPERATORS", set())


def judge(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    plan = _load_plan_module(root)
    schema = plan.plan_json_schema()

    clause_schema = schema.get("properties", {}).get("clauses", {}).get("items", {})
    properties: dict = dict(schema.get("properties", {}))
    properties.update(clause_schema.get("properties", {}))

    for name in sorted(properties):
        if name.lower() in _QUERY_SHAPED:
            findings.append(
                Finding(
                    "query-shaped-property",
                    f"the plan schema offers a property named {name!r}; a model can put query text in it",
                )
            )

    for name in _MUST_BE_ENUM:
        spec = clause_schema.get("properties", {}).get(name)
        if spec is None:
            findings.append(Finding("unconstrained-string", f"the clause schema has no {name!r} property at all"))
            continue
        if not spec.get("enum"):
            findings.append(
                Finding(
                    "unconstrained-string",
                    f"{name!r} is not a closed enum in the schema the model is handed; "
                    "an open string here is a query language with extra steps",
                )
            )

    # Every property the model can populate must be a scalar. A nested object
    # is structure a model can smuggle meaning into.
    for name, spec in sorted(clause_schema.get("properties", {}).items()):
        if spec.get("type") not in {"string", "integer"}:
            findings.append(
                Finding(
                    "unconstrained-string", f"clause property {name!r} is typed {spec.get('type')!r}; only string and integer are allowed"
                )
            )

    ddl = _ddl_columns(root)
    if not ddl:
        return [Finding("unreadable", f"could not read the raw_events DDL from {_DDL}")]

    agent_fields = set(plan.HUNT_FIELDS)
    for name in sorted(agent_fields - ddl):
        findings.append(
            Finding(
                "field-not-in-lake",
                f"the agent may propose {name!r}, which the raw_events DDL does not create, "
                "so a plan using it returns zero while looking like it worked",
            )
        )

    compiler_fields, compiler_operators = _compiler_sets(root)
    if not compiler_fields or not compiler_operators:
        return [Finding("unreadable", f"could not read the accepted sets from {_COMPILER}")]

    for name in sorted(agent_fields - compiler_fields):
        findings.append(
            Finding("vocabulary-drift", f"the agent may propose field {name!r} and the compiler refuses it; every such plan wastes a turn")
        )
    for name in sorted(compiler_fields - agent_fields):
        findings.append(Finding("vocabulary-drift", f"the compiler accepts field {name!r} that the agent is never offered; dead surface"))

    agent_operators = set(plan.HUNT_OPERATORS)
    for name in sorted(agent_operators ^ compiler_operators):
        findings.append(Finding("vocabulary-drift", f"operator {name!r} is accepted on one side of the boundary and not the other"))

    # The one property no vocabulary check substitutes for.
    compiler_source = (root / _COMPILER).read_text(encoding="utf-8")
    for match in re.finditer(r'f"[^"]*\{value\}[^"]*"', compiler_source):
        findings.append(Finding("compiler-interpolates", f"the compiler formats a value into a statement: {match.group(0)[:80]}"))

    return findings


def _self_test() -> int:
    from gate_toolkit import self_test_main  # noqa: PLC0415

    root = repo_root()
    extra: list[tuple[str, bool]] = []

    clean = judge(root)
    extra.append(("the tree as committed has no findings", not clean))
    for finding in clean:
        print(f"        {finding}")

    plan = _load_plan_module(root)
    schema = plan.plan_json_schema()
    clause = schema["properties"]["clauses"]["items"]["properties"]

    extra.append(("the schema's field property is a closed enum", bool(clause["field"].get("enum"))))
    extra.append(("the schema's operator property is a closed enum", bool(clause["operator"].get("enum"))))
    extra.append(
        (
            "no property the model can populate is named like query text",
            not ({*schema["properties"], *clause} & _QUERY_SHAPED),
        )
    )

    # The validator refuses what the schema forbids, proven by trying.
    refused = 0
    # Annotated on the tuple rather than the loop variable so the empty-clause
    # case is inferred as the same list type as the others rather than as
    # list[Never], which no annotation on `bad` alone can reconcile.
    rejected: tuple[dict[str, list[dict[str, str]]], ...] = (
        {"clauses": [{"field": "raw_payload", "operator": "contains", "value": "x"}]},
        {"clauses": [{"field": "user_name", "operator": "regex", "value": ".*"}]},
        {"clauses": [{"field": "user_name", "operator": "eq", "value": "x"}] * (plan.MAX_CLAUSES + 1)},
        {"clauses": []},
    )
    for bad in rejected:
        try:
            plan.validate_plan(bad, hypothesis="probe")
        except plan.HuntPlanError:
            refused += 1
    extra.append(("the validator refuses an out-of-vocabulary field, operator, an over-long plan and an empty one", refused == 4))

    return self_test_main(Path(__file__).name, ["--check"], extra=extra)


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in args:
        return _self_test()

    root = repo_root()
    missing = [str(rel) for rel in REQUIRED if not (root / rel).exists()]
    if missing:
        print("check_hunt_agent_boundary: refusing to render a verdict — these files are missing:")
        for path in missing:
            print(f"  {path}")
        return 2

    findings = judge(root)
    if findings:
        print(f"check_hunt_agent_boundary: {len(findings)} finding(s)\n")
        for finding in findings:
            print(finding)
        print("\nA model that can name its own field or supply its own operator can compose a query,")
        print("and the hypothesis it was given is attacker-influenceable text.")
        return 1

    plan = _load_plan_module(root)
    print(
        f"check_hunt_agent_boundary: OK — the model chooses from {len(plan.HUNT_FIELDS)} recorded fields and "
        f"{len(plan.HUNT_OPERATORS)} operators, both closed enums in the schema it is handed, and every value it "
        f"supplies is a bound parameter."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""A dollar figure must arrive with the thing that says how it is known.

Why this exists
---------------
``CostTracker`` priced a call by looking its **model name** up in a table of
hosted list prices. The name it looked up was an ``aisoc-<role>`` alias, which
is not a model — it is a label the LiteLLM gateway resolves to one. No alias
is in the table, so every call fell through a ``(0.001, 0.002)`` default and
was booked at a price nobody charges for a model nobody named. A 903-token
completion on an operator's own hardware reported ``total_cost_usd=0.000999``,
and that figure reached the cost dashboard, the funnel, the per-run ledger and
the budget circuit breaker — which trips at ``AISOC_BUDGET_HARD_USD`` and
would eventually have degraded a working local install to deterministic-only
over money nobody spent.

Nothing in a diff shows that. The number was well-formed, plausibly small, and
wrong. What was missing was not a value but a *provenance*: no caller could ask
"measured, estimated, or unknown?", so every surface assumed the first.

What it checks, in both directions
----------------------------------
Every rule is a structural relationship between two name spaces, and both are
enumerated. The dominant defect shape in this repository is the check that
compares A against B and never B against A, so drift in the direction things
actually change slips through while the check prints OK.

  MONEY <-> COUNT   every money field in a response model has the count that
                    qualifies it, and every provenance count qualifies a money
                    field. A sum with no count cannot say "not measured"; a
                    count with no sum qualifies nothing
  WRITE <-> COLUMN  every provenance column the writer writes exists in the
                    migration, and every provenance column the migration adds
                    is written or read. A column nobody writes is a permanent
                    zero that reads as "not measured" forever
  NO-DEFAULT        no pricing table has a fallback rate, in either copy. The
                    default *was* the defect: it turned "unknown price" into a
                    confident number
  ALIAS-NEVER       an alias prefix can never become a pricing key, checked in
                    both the agents table and the API mirror
  HEADER-EXACT      the gateway cost headers read are the two that carry a
                    total, and none of the five that share their prefix but
                    carry a component, an adjustment, or a *percentage*
  PY <-> TS         the provenance fields on the wire exist on both sides. The
                    two packages cannot import one another, so they drift
  CONSOLE           a console surface that renders a currency amount from a
                    cost field consults a provenance count before doing so

Usage
-----
    python3 scripts/check_cost_provenance.py              # gate
    python3 scripts/check_cost_provenance.py --json
    python3 scripts/check_cost_provenance.py --self-test  # prove it bites

``--repo-root`` overrides the tree under inspection. The resolved root comes
from ``git rev-parse``, every file read and every count is printed before the
verdict, and a missing or empty input is a hard error rather than a quiet
zero: a gate that reports OK about a tree it never opened is worse than none.

Stdlib only. The lint job that runs this installs ruff and mypy and nothing
else, and a gate that needs a ``pip install`` to render a verdict can be
skipped.

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

TRACKER_REL = "services/agents/app/core/cost_telemetry.py"
GATEWAY_COST_REL = "services/agents/app/core/gateway_cost.py"
DASHBOARD_REL = "services/api/app/services/cost_dashboard.py"
INVESTIGATIONS_REL = "services/api/app/api/v1/endpoints/investigations.py"
MIGRATION_REL = "services/api/migrations/063_cost_provenance.sql"
API_TS_REL = "apps/web/src/lib/api.ts"

#: Console surfaces that render a cost to a human. Each must consult a
#: provenance count before printing a currency amount.
CONSOLE_RELS = (
    "apps/web/src/components/admin/CostDashboardView.tsx",
    "apps/web/src/components/dashboard/operations/AgentThroughputPanel.tsx",
    "apps/web/src/components/cases/InvestigationLedger.tsx",
)

#: A field name holding an amount of money.
MONEY_FIELD_RE = re.compile(r"^(?:total_|measured_|estimated_|recorded_|imputed_|savings_|avg_)?\w*?cost_usd$|^savings_usd$")

#: A field name holding the number of calls a money field was computed over.
#: `unpriced_call_count` is a provenance count with no money of its own — it
#: is the count of what could not be priced at all — so it is exempt from the
#: COUNT -> MONEY direction and named here rather than special-cased inline.
COUNT_FIELD_RE = re.compile(r"^(measured|estimated|unpriced)_call_count$")
COUNTLESS_PROVENANCE = frozenset({"unpriced_call_count"})

#: money field -> the count that qualifies it. Both directions are checked
#: against this map, so an added field must be paired here to pass.
MONEY_TO_COUNT = {
    "total_cost_usd": "measured_call_count",
    "measured_cost_usd": "measured_call_count",
    "estimated_cost_usd": "estimated_call_count",
}

#: Provenance columns. Written by the agents service, added by the migration.
PROVENANCE_COLUMNS = frozenset(
    {
        "measured_cost_usd",
        "measured_call_count",
        "estimated_cost_usd",
        "estimated_call_count",
        "unpriced_call_count",
        "resolved_model",
    }
)

#: The LiteLLM headers that carry a **total** cost. Only these may be read.
TOTAL_COST_HEADERS = frozenset({"x-litellm-response-cost", "x-litellm-response-cost-original"})

#: Headers that share the prefix and are NOT a total. `-margin-percent` is not
#: even denominated in money. A prefix match accepts all of these and produces
#: a plausible wrong number instead of an obvious absence, which is the harder
#: failure to notice.
DECOY_COST_HEADERS = frozenset(
    {
        "x-litellm-response-cost-input",
        "x-litellm-response-cost-output",
        "x-litellm-response-cost-discount-amount",
        "x-litellm-response-cost-margin-amount",
        "x-litellm-response-cost-margin-percent",
        "x-litellm-response-cost-tool-usage",
    }
)

#: Prefix of a logical gateway alias. Never a pricing key.
ALIAS_PREFIX = "aisoc-"

#: Pricing tables, by file, that must contain no alias and no default rate.
PRICING_TABLES = {TRACKER_REL: "_PRICING", DASHBOARD_REL: "_PUBLIC_PRICING"}


class GateError(RuntimeError):
    """The scan could not be performed — distinct from the scan finding nothing."""


@dataclass
class Finding:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.detail}"


@dataclass
class Corpus:
    """Everything the gate read, named, so a caller cannot lose which tree."""

    files_read: list[str] = field(default_factory=list)
    #: model name -> ({field name}, on_the_wire) for every class carrying money
    py_models: dict[str, tuple[set[str], bool]] = field(default_factory=dict)
    ts_interfaces: dict[str, set[str]] = field(default_factory=dict)
    written_columns: set[str] = field(default_factory=set)
    migration_columns: set[str] = field(default_factory=set)
    read_columns: set[str] = field(default_factory=set)
    pricing_keys: dict[str, set[str]] = field(default_factory=dict)
    pricing_defaults: dict[str, list[str]] = field(default_factory=dict)
    headers_read: set[str] = field(default_factory=set)
    console_guards: dict[str, bool] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        return {
            "files_read": len(self.files_read),
            "python_models": len(self.py_models),
            "typescript_interfaces": len(self.ts_interfaces),
            "columns_written": len(self.written_columns),
            "columns_in_migration": len(self.migration_columns),
            "pricing_tables": len(self.pricing_keys),
            "cost_headers_read": len(self.headers_read),
            "console_surfaces": len(self.console_guards),
        }


# --------------------------------------------------------------------------
# Parsing.
#
# Every parser below is AST- or structure-aware, never a bare regex over raw
# source, because each corpus contains text shaped exactly like what the gate
# looks for:
#
#   * ``gateway_cost.py``'s module docstring **enumerates all seven**
#     ``x-litellm-response-cost*`` headers in a table explaining why five are
#     refused. A line regex reads that as the code reading them, and credits
#     the gate's own documentation of a blind spot as the blind spot.
#   * ``cost_telemetry.py``'s docstring shows ``total_cost_usd=0.000999`` and
#     names ``(0.001, 0.002)`` while describing the defect it removed. A
#     regex for a default rate fires on the explanation of the default rate.
#   * ``api.ts`` carries doc comments naming ``measured_call_count`` above
#     fields, so a comment can satisfy a field requirement it does not meet.
#   * The migration's own ``COMMENT ON COLUMN`` statements repeat every
#     column name in prose.
#
# The self-test injects each of those shapes and requires the parser to
# decline to credit it.
# --------------------------------------------------------------------------


def _read(root: Path, rel: str, corpus: Corpus) -> str:
    path = root / rel
    if not path.is_file():
        raise GateError(f"missing input: {rel} (looked in {root})")
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise GateError(f"empty input: {rel}")
    corpus.files_read.append(rel)
    return text


def _parse_python(text: str, rel: str) -> ast.Module:
    try:
        return ast.parse(text)
    except SyntaxError as exc:
        raise GateError(f"{rel}: could not parse: {exc}") from exc


def parse_py_models(text: str, rel: str) -> dict[str, tuple[set[str], bool]]:
    """Class name -> (annotated field names, is-on-the-wire), for money classes.

    AST, so a field named only in a docstring or a comment is not a field.

    The second element is whether the class inherits ``BaseModel``, i.e.
    whether it is serialised to a client. Only those are reconciled against
    TypeScript: an internal dataclass like ``CostRow`` mirrors a database row
    and has no business appearing in ``api.ts``. Discriminating on the base
    class rather than on a name convention means a new response model is
    reconciled automatically and a new internal row is not falsely demanded.
    """
    tree = _parse_python(text, rel)
    out: dict[str, tuple[set[str], bool]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        fields = {stmt.target.id for stmt in node.body if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)}
        if not any(MONEY_FIELD_RE.match(f) for f in fields):
            continue
        bases = {b.id for b in node.bases if isinstance(b, ast.Name)} | {b.attr for b in node.bases if isinstance(b, ast.Attribute)}
        out[f"{rel}::{node.name}"] = (fields, "BaseModel" in bases)
    return out


def parse_ts_interfaces(text: str) -> dict[str, set[str]]:
    """Interface name -> field names, comments stripped.

    Block and line comments go first so a documented-but-absent field cannot
    satisfy a requirement, and neither can a commented-out one.
    """
    stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.MULTILINE)

    out: dict[str, set[str]] = {}
    for match in re.finditer(r"export\s+interface\s+(\w+)\s*(?:extends\s+\w+\s*)?\{", stripped):
        name = match.group(1)
        depth, i = 1, match.end()
        while i < len(stripped) and depth:
            if stripped[i] == "{":
                depth += 1
            elif stripped[i] == "}":
                depth -= 1
            i += 1
        body = stripped[match.end() : i - 1]
        fields = set(re.findall(r"^\s*(\w+)\??\s*:", body, flags=re.MULTILINE))
        if any(MONEY_FIELD_RE.match(f) for f in fields):
            out[name] = fields
    return out


def parse_sql_columns(text: str) -> set[str]:
    """Columns an ``ALTER TABLE ... ADD COLUMN`` actually adds.

    Driven off the ADD COLUMN clause rather than a name scan, so the
    ``COMMENT ON COLUMN`` statements — which repeat every column name in
    prose, and are the point of the file being readable — are not credited as
    adding anything. Line comments are stripped first.
    """
    without_comments = re.sub(r"^\s*--.*$", "", text, flags=re.MULTILINE)
    return {m.group(1) for m in re.finditer(r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", without_comments, re.IGNORECASE)}


def parse_written_columns(text: str, rel: str) -> set[str]:
    """Provenance columns named inside SQL string literals in Python code.

    Only string constants are considered, so a column named in a docstring is
    not a write... except that a docstring *is* a string constant. The
    discriminator is that a write names the column inside a statement that
    also contains INSERT, UPDATE or SELECT, which a prose docstring does not.
    """
    tree = _parse_python(text, rel)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        blob = node.value
        if not re.search(r"\b(INSERT|UPDATE|SELECT)\b", blob, re.IGNORECASE):
            continue
        for column in PROVENANCE_COLUMNS:
            if re.search(rf"\b{re.escape(column)}\b", blob):
                found.add(column)
    return found


def parse_pricing_table(text: str, rel: str, table_name: str) -> tuple[set[str], list[str]]:
    """(keys, default-rate sites) for a pricing dict, from the AST.

    A "default-rate site" is a ``.get(key, <2-tuple of numbers>)`` on the
    table, or a module constant whose value is a 2-tuple of numbers and whose
    name mentions default and price. Both are the shape that turns "unknown
    price" into a confident number. Found structurally, so the docstring that
    *describes* the removed ``(0.001, 0.002)`` default is not a finding.
    """
    tree = _parse_python(text, rel)
    keys: set[str] = set()
    defaults: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == table_name:
            if isinstance(node.value, ast.Dict):
                keys = {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == table_name:
                    keys = {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}

        # `.get(x, (a, b))` on the table — a default rate by any other name.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == table_name
            and len(node.args) == 2
        ):
            fallback = node.args[1]
            if _is_rate_tuple(fallback) or isinstance(fallback, ast.Name):
                defaults.append(f"{table_name}.get(..., {ast.unparse(fallback)})")

        # A module constant holding a rate pair, named like a default.
        if isinstance(node, ast.AnnAssign | ast.Assign):
            assigned = node.value
            if assigned is None or not _is_rate_tuple(assigned):
                continue
            names = _assigned_names(node)
            for name in names:
                if "DEFAULT" in name.upper() and ("PRIC" in name.upper() or "RATE" in name.upper()):
                    defaults.append(f"{name} = {ast.unparse(assigned)}")
    return keys, defaults


def _assigned_names(node: ast.AnnAssign | ast.Assign) -> list[str]:
    """Plain names this statement assigns to."""
    if isinstance(node, ast.AnnAssign):
        return [node.target.id] if isinstance(node.target, ast.Name) else []
    return [t.id for t in node.targets if isinstance(t, ast.Name)]


def _is_rate_tuple(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Tuple)
        and len(node.elts) == 2
        and all(isinstance(e, ast.Constant) and isinstance(e.value, int | float) for e in node.elts)
    )


def parse_headers_read(text: str, rel: str) -> set[str]:
    """Cost headers the extractor actually reads.

    Taken from the ``COST_HEADERS`` tuple's elements via the AST. The module
    docstring lists all seven headers in a table — five of them to explain why
    they are refused — so a line regex over this file credits the code with
    reading the very decoys the code exists to decline.
    """
    tree = _parse_python(text, rel)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        if "COST_HEADERS" not in _assigned_names(node):
            continue
        assigned = node.value
        if isinstance(assigned, ast.Tuple):
            return {e.value for e in assigned.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    raise GateError(f"{rel}: COST_HEADERS tuple not found — cannot tell which headers are read")


def parse_console_guard(text: str) -> bool:
    """Whether a console surface consults a provenance count.

    Comments stripped first: this file's own explanation of why the guard
    exists names the guard, and would otherwise satisfy the requirement it
    describes. A JSX/TS surface that formats currency from a cost field must
    reference a provenance count in live code.
    """
    stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.MULTILINE)
    renders_currency = bool(re.search(r"\$\{?[^}\n]*cost", stripped) or re.search(r"fmtUsd|formatUsd|fmtSpend", stripped))
    consults_count = bool(re.search(r"measured_call_count|measuredCalls|measuredCount|spendProvenance|fmtSpend", stripped))
    return (not renders_currency) or consults_count


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------


def collect(root: Path) -> Corpus:
    corpus = Corpus()

    tracker = _read(root, TRACKER_REL, corpus)
    gateway = _read(root, GATEWAY_COST_REL, corpus)
    dashboard = _read(root, DASHBOARD_REL, corpus)
    investigations = _read(root, INVESTIGATIONS_REL, corpus)
    migration = _read(root, MIGRATION_REL, corpus)
    api_ts = _read(root, API_TS_REL, corpus)

    for rel, text in ((DASHBOARD_REL, dashboard), (INVESTIGATIONS_REL, investigations)):
        corpus.py_models.update(parse_py_models(text, rel))
    corpus.ts_interfaces = parse_ts_interfaces(api_ts)

    corpus.migration_columns = parse_sql_columns(migration)
    corpus.written_columns = parse_written_columns(tracker, TRACKER_REL)
    corpus.read_columns = parse_written_columns(dashboard, DASHBOARD_REL) | parse_written_columns(investigations, INVESTIGATIONS_REL)

    for rel, table in PRICING_TABLES.items():
        text = tracker if rel == TRACKER_REL else dashboard
        keys, defaults = parse_pricing_table(text, rel, table)
        corpus.pricing_keys[rel] = keys
        corpus.pricing_defaults[rel] = defaults

    corpus.headers_read = parse_headers_read(gateway, GATEWAY_COST_REL)

    for rel in CONSOLE_RELS:
        corpus.console_guards[rel] = parse_console_guard(_read(root, rel, corpus))

    return corpus


# --------------------------------------------------------------------------
# Rules — every one enumerated in both directions
# --------------------------------------------------------------------------


def evaluate(corpus: Corpus) -> list[Finding]:
    findings: list[Finding] = []

    # MONEY -> COUNT, and COUNT -> MONEY. Applies to every money-carrying
    # class, internal rows included: a row that loses its count silently
    # re-enters the sums as measured.
    for model, (fields, _on_wire) in sorted(corpus.py_models.items()):
        for money, count in MONEY_TO_COUNT.items():
            if money in fields and count not in fields:
                findings.append(
                    Finding("MONEY-WITHOUT-COUNT", f"{model} carries `{money}` with no `{count}` — it cannot say 'not measured'")
                )
        for f in sorted(fields):
            if COUNT_FIELD_RE.match(f) and f not in COUNTLESS_PROVENANCE:
                qualified = [m for m, c in MONEY_TO_COUNT.items() if c == f]
                if not any(m in fields for m in qualified):
                    findings.append(Finding("COUNT-WITHOUT-MONEY", f"{model} carries `{f}` qualifying no money field"))

    # WRITE -> COLUMN, and COLUMN -> WRITE/READ.
    for column in sorted(corpus.written_columns - corpus.migration_columns):
        findings.append(Finding("WRITE-NO-COLUMN", f"`{column}` is written by the agents service and no migration adds it"))
    touched = corpus.written_columns | corpus.read_columns
    for column in sorted(corpus.migration_columns & PROVENANCE_COLUMNS - touched):
        findings.append(
            Finding("COLUMN-NO-WRITE", f"migration adds `{column}` and nothing writes or reads it — a permanent unmeasured zero")
        )

    # NO-DEFAULT, and ALIAS-NEVER, over both pricing tables.
    for rel, defaults in sorted(corpus.pricing_defaults.items()):
        for site in defaults:
            findings.append(Finding("DEFAULT-RATE", f"{rel}: `{site}` supplies a fallback price — an unknown model must impute nothing"))
    for rel, keys in sorted(corpus.pricing_keys.items()):
        if not keys:
            findings.append(Finding("EMPTY-PRICING", f"{rel}: pricing table parsed as empty — the parser or the table is wrong"))
        for key in sorted(k for k in keys if k.lower().startswith(ALIAS_PREFIX)):
            findings.append(Finding("ALIAS-PRICED", f"{rel}: `{key}` is a gateway alias and cannot carry a price"))

    # HEADER-EXACT, both directions.
    for header in sorted(corpus.headers_read - TOTAL_COST_HEADERS):
        kind = "a component/adjustment, not a total" if header in DECOY_COST_HEADERS else "not a known cost header"
        findings.append(Finding("HEADER-NOT-A-TOTAL", f"`{header}` is read as a cost and is {kind}"))
    for header in sorted(TOTAL_COST_HEADERS - corpus.headers_read):
        findings.append(Finding("HEADER-TOTAL-UNREAD", f"`{header}` carries a total and is not read — some gateway versions emit only it"))

    # PY <-> TS.
    # Only classes actually serialised to a client. An internal dataclass
    # mirrors a database row, not the wire, and demanding it appear in api.ts
    # would be the gate inventing a requirement rather than checking one.
    py_fields = {
        f for fields, on_wire in corpus.py_models.values() if on_wire for f in fields if MONEY_FIELD_RE.match(f) or COUNT_FIELD_RE.match(f)
    }
    ts_fields = {f for fields in corpus.ts_interfaces.values() for f in fields if MONEY_FIELD_RE.match(f) or COUNT_FIELD_RE.match(f)}
    if not corpus.ts_interfaces:
        findings.append(Finding("EMPTY-TS", f"{API_TS_REL}: no money-carrying interface parsed — the parser or the file is wrong"))
    for name in sorted(py_fields - ts_fields):
        findings.append(Finding("PY-NOT-IN-TS", f"`{name}` is on the wire from Python and absent from {API_TS_REL}"))
    for name in sorted(ts_fields - py_fields):
        findings.append(Finding("TS-NOT-IN-PY", f"`{name}` is declared in {API_TS_REL} and no Python model sends it"))

    # CONSOLE.
    for rel, guarded in sorted(corpus.console_guards.items()):
        if not guarded:
            findings.append(Finding("CONSOLE-UNGUARDED", f"{rel} renders a currency amount without consulting a provenance count"))

    return findings


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _self_test_cases() -> list[tuple[str, bool]]:
    """Injected defects and parser blind spots, each caught by its own code.

    Every corpus is built with a fresh constructor call rather than mutating a
    shared baseline. PR #829's self-test shallow-copied its nested corpora, so
    one case poisoned the baseline and every later case "caught" three codes it
    had inherited — a self-test that passes for the wrong reason is the gate's
    own defect one level up.
    """

    def baseline() -> Corpus:
        """A clean corpus, constructed fresh every call. No shared mutables."""
        c = Corpus()
        c.files_read = list(CONSOLE_RELS)
        c.py_models = {
            f"{DASHBOARD_REL}::CostHeadline": (
                {
                    "total_cost_usd",
                    "measured_call_count",
                    "estimated_cost_usd",
                    "estimated_call_count",
                    "unpriced_call_count",
                },
                True,
            )
        }
        c.ts_interfaces = {
            "CostHeadline": {
                "total_cost_usd",
                "measured_call_count",
                "estimated_cost_usd",
                "estimated_call_count",
                "unpriced_call_count",
            }
        }
        c.written_columns = set(PROVENANCE_COLUMNS)
        c.migration_columns = set(PROVENANCE_COLUMNS)
        c.read_columns = set(PROVENANCE_COLUMNS)
        c.pricing_keys = {TRACKER_REL: {"gpt-4o"}, DASHBOARD_REL: {"gpt-4o"}}
        c.pricing_defaults = {TRACKER_REL: [], DASHBOARD_REL: []}
        c.headers_read = set(TOTAL_COST_HEADERS)
        c.console_guards = dict.fromkeys(CONSOLE_RELS, True)
        return c

    cases: list[tuple[str, bool]] = []

    # The baseline must itself be clean, or every case below proves nothing.
    base_findings = evaluate(baseline())
    cases.append(("a clean corpus produces no findings (the baseline is not pre-poisoned)", not base_findings))

    def caught(description: str, mutate, code: str) -> None:
        c = baseline()
        mutate(c)
        codes = {f.code for f in evaluate(c)}
        cases.append((f"{description} -> {code}", code in codes))

    # --- injected defects, one per rule, both directions ------------------
    def drop_count(c: Corpus) -> None:
        c.py_models[f"{DASHBOARD_REL}::CostHeadline"][0].discard("measured_call_count")

    caught("a money field loses the count that qualifies it", drop_count, "MONEY-WITHOUT-COUNT")

    def orphan_count(c: Corpus) -> None:
        c.py_models[f"{DASHBOARD_REL}::CostHeadline"][0].discard("estimated_cost_usd")

    caught("a provenance count qualifies no money field", orphan_count, "COUNT-WITHOUT-MONEY")

    caught(
        "a column is written with no migration adding it",
        lambda c: c.migration_columns.discard("measured_cost_usd"),
        "WRITE-NO-COLUMN",
    )
    caught(
        "a migration adds a column nothing writes or reads",
        lambda c: (c.written_columns.discard("resolved_model"), c.read_columns.discard("resolved_model")),
        "COLUMN-NO-WRITE",
    )
    caught(
        "a pricing table regains a fallback rate",
        lambda c: c.pricing_defaults[TRACKER_REL].append("_DEFAULT_PRICE = (0.001, 0.002)"),
        "DEFAULT-RATE",
    )
    caught(
        "a gateway alias becomes a pricing key",
        lambda c: c.pricing_keys[DASHBOARD_REL].add("aisoc-triage"),
        "ALIAS-PRICED",
    )
    caught(
        "a component header is read as if it were a total",
        lambda c: c.headers_read.add("x-litellm-response-cost-margin-percent"),
        "HEADER-NOT-A-TOTAL",
    )
    caught(
        "a header that carries a total stops being read",
        lambda c: c.headers_read.discard("x-litellm-response-cost"),
        "HEADER-TOTAL-UNREAD",
    )
    caught(
        "a provenance field exists in Python and not TypeScript",
        lambda c: c.ts_interfaces["CostHeadline"].discard("unpriced_call_count"),
        "PY-NOT-IN-TS",
    )
    caught(
        "a provenance field exists in TypeScript and not Python",
        lambda c: c.ts_interfaces["CostHeadline"].add("recorded_cost_usd"),
        "TS-NOT-IN-PY",
    )
    caught(
        "a console surface prints currency with no provenance guard",
        lambda c: c.console_guards.__setitem__(CONSOLE_RELS[0], False),
        "CONSOLE-UNGUARDED",
    )
    caught("a pricing table parses as empty", lambda c: c.pricing_keys.__setitem__(TRACKER_REL, set()), "EMPTY-PRICING")
    caught("no TypeScript interface parses", lambda c: c.ts_interfaces.clear(), "EMPTY-TS")

    # --- parser blind spots: what the parser CREDITS, not what it flags ----
    # Each of these is text shaped exactly like the thing the gate looks for.
    # A line regex credits every one of them.

    docstring_headers = '''
"""Doc table explaining the decoys:

    x-litellm-response-cost-input               a component
    x-litellm-response-cost-margin-percent      a percentage, not money
"""
COST_HEADERS: tuple[str, ...] = ("x-litellm-response-cost", "x-litellm-response-cost-original")
'''
    cases.append(
        (
            "a docstring enumerating the five decoy headers is not credited as reading them",
            parse_headers_read(docstring_headers, "probe.py") == set(TOTAL_COST_HEADERS),
        )
    )

    described_default = '''
_PRICING: dict[str, tuple[float, float]] = {"gpt-4o": (0.005, 0.015)}
# The removed default was (0.001, 0.002) and it priced an alias.
def _estimate(model):
    """Previously fell through to _DEFAULT_PRICE = (0.001, 0.002); now returns None."""
    return _PRICING.get(model)
'''
    keys, defaults = parse_pricing_table(described_default, "probe.py", "_PRICING")
    cases.append(
        (
            "a docstring and comment describing the removed default rate are not findings",
            keys == {"gpt-4o"} and defaults == [],
        )
    )

    real_default = """
_PRICING: dict[str, tuple[float, float]] = {"gpt-4o": (0.005, 0.015)}
def _estimate(model):
    return _PRICING.get(model, (0.001, 0.002))
"""
    _, real_defaults = parse_pricing_table(real_default, "probe.py", "_PRICING")
    cases.append(("an inline `.get(k, (a, b))` default rate IS caught, not just a named constant", bool(real_defaults)))

    commented_ts = """
export interface CostHeadline {
  total_cost_usd: number;
  /** measured_call_count: number; — documented but absent */
  // estimated_call_count: number;
}
"""
    parsed_ts = parse_ts_interfaces(commented_ts)
    cases.append(
        (
            "a TS field named only in a comment or commented out is not credited as declared",
            parsed_ts.get("CostHeadline") == {"total_cost_usd"},
        )
    )

    comment_only_sql = """
-- ADD COLUMN IF NOT EXISTS measured_cost_usd DOUBLE PRECISION
ALTER TABLE t ADD COLUMN IF NOT EXISTS estimated_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0;
COMMENT ON COLUMN t.measured_call_count IS 'calls the sum covers';
"""
    cases.append(
        (
            "a commented-out ADD COLUMN and a COMMENT ON COLUMN are not credited as adding columns",
            parse_sql_columns(comment_only_sql) == {"estimated_cost_usd"},
        )
    )

    docstring_column = '''
def persist():
    """Writes measured_cost_usd and resolved_model to aisoc_run_costs."""
    conn.execute("UPDATE aisoc_run_costs SET estimated_cost_usd = $1")
'''
    cases.append(
        (
            "a docstring naming columns is not credited as writing them",
            parse_written_columns(docstring_column, "probe.py") == {"estimated_cost_usd"},
        )
    )

    comment_guard = """
// measured_call_count guards this, honest
export function Cell() { return <span>{fmtUsd(row.total_cost_usd)}</span>; }
"""
    cases.append(
        (
            "a console guard named only in a comment does not satisfy the guard requirement",
            parse_console_guard(comment_guard) is False,
        )
    )

    docstring_model = '''
class NotAModel:
    """Has total_cost_usd and measured_call_count in prose only."""
'''
    cases.append(
        (
            "a class naming money fields only in its docstring is not parsed as a model",
            parse_py_models(docstring_model, "probe.py") == {},
        )
    )

    wire_vs_internal = """
from pydantic import BaseModel

class OnTheWire(BaseModel):
    total_cost_usd: float
    measured_call_count: int

@dataclass(frozen=True)
class InternalRow:
    measured_cost_usd: float
    measured_call_count: int
"""
    parsed = parse_py_models(wire_vs_internal, "probe.py")
    cases.append(
        (
            "a BaseModel is on the wire and a dataclass is not, so TS reconciliation skips the row",
            parsed["probe.py::OnTheWire"][1] is True and parsed["probe.py::InternalRow"][1] is False,
        )
    )

    # ... and that the distinction actually changes the verdict, not just the
    # parse. An internal row whose fields are absent from TypeScript must not
    # be reported, while a wire model's must.
    internal_only = baseline()
    internal_only.py_models["probe::InternalRow"] = ({"measured_cost_usd", "measured_call_count"}, False)
    cases.append(
        (
            "an internal row's fields are not demanded of api.ts",
            "PY-NOT-IN-TS" not in {f.code for f in evaluate(internal_only)},
        )
    )

    return cases


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test_main(Path(__file__).name, extra=_self_test_cases())

    root = args.repo_root.resolve() if args.repo_root else repo_root()
    try:
        corpus = collect(root)
    except GateError as exc:
        print(f"check_cost_provenance: {exc}", file=sys.stderr)
        return 2

    findings = evaluate(corpus)

    if args.as_json:
        print(json.dumps({"root": str(root), "counts": corpus.counts(), "findings": [f.__dict__ for f in findings]}, indent=2))
        return 1 if findings else 0

    print(f"repository root: {root}")
    print("files read:")
    for rel in corpus.files_read:
        print(f"  {rel}")
    print("counts:")
    for key, value in corpus.counts().items():
        print(f"  {key}: {value}")
    print()

    if findings:
        print(f"{len(findings)} finding(s):")
        for finding in findings:
            print(f"  {finding}")
        return 1

    print("OK: every cost figure carries the provenance that says how it is known.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

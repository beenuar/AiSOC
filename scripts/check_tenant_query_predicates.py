#!/usr/bin/env python3
"""Fail the build when a query on a tenant-scoped table carries no tenant predicate.

``scripts/check_route_tenant_scope.py`` asks where the tenant *came from*. This
asks a different question, and the two do not overlap: once a route has a
tenant, does the query it runs actually filter on it?

Closing the parameter shape surfaced the worse variant. Eight routes matched on
an id and nothing else — ``select(Honeytoken).where(Honeytoken.id == token_id)``
— so naming another tenant's UUID read, revoked or deleted their row. The
parameter gate cannot see those: they take no tenant parameter, which is
precisely why they were broken. The addressing mode is irrelevant; the predicate
is the control.

It is the *only* control on most of this schema. Of the 81 tenant-scoped tables
in the migrations, 32 carry an RLS policy and 49 do not, and RLS only engages on
a session that ran ``SET LOCAL app.current_tenant_id`` (``TenantDBSession``). On
an ``aisoc_*`` table read through a plain ``DBSession``, a missing predicate is a
leak, not a defence-in-depth gap.

What counts as scoped
---------------------
Structural signals only, because a naming convention is exactly what drifts:

* a ``tenant_id`` predicate on the statement, however it got there — inline in
  the ``.where()`` chain, appended to a ``filters`` list, bound to a variable,
  added by a later ``q = q.where(...)``, carried in through a join, or applied
  by a helper that takes the statement and returns it filtered;
* a predicate binding the row to the **authenticated principal's own identity**
  (``PasskeyCredential.user_id == user.user_id``), which is strictly narrower
  than their tenant. Only an identity arriving through an auth dependency
  counts — a ``user_id`` the caller typed is not a credential.

Anything else is a finding, and must be on the ratchet with a reason.

Both directions
---------------
The dominant failure shape in this repository is the one-directional gate: it
compares A against B, never B against A, and prints OK while drift accumulates
in the direction things actually change. So:

* forward — an unscoped statement that is not on the ratchet fails;
* reverse — a **ratchet entry whose statement is now scoped, or gone, also
  fails**. That is what makes it shrink-only. An allowlist you can quietly
  outgrow is not a ratchet, and one that keeps passing after its justification
  lapsed is worse than none, because it reads like a decision somebody made.

``MAX_RATCHET`` is asserted against the table's length, so adding an entry means
raising a number in a diff rather than appending a line nobody reads.

Usage::

    python scripts/check_tenant_query_predicates.py            # gate
    python scripts/check_tenant_query_predicates.py --inventory
    python scripts/check_tenant_query_predicates.py --json
    python scripts/check_tenant_query_predicates.py --self-test

Exit codes: 0 clean, 1 violations, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _repo_root() -> Path:
    """Resolve the repository root from git, not from this file's location.

    A gate that derives its root from ``__file__`` will scan a stale copy of
    the tree and print a confident OK about a checkout it never opened.
    """
    env = os.environ.get("AISOC_REPO_ROOT")
    if env:
        return Path(env).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parent,
        )
        return Path(out.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path(__file__).resolve().parent.parent


REPO_ROOT = _repo_root()
SERVICES_DIR = REPO_ROOT / "services"

#: Never scanned. Written as path *segments* rather than substrings: a skip
#: spelled ``"node_modules"`` also swallows ``app/node_modules_helper.py``, and
#: one spelled as a prefix makes the gate's answer depend on whether anybody
#: has run an install.
SKIP_SEGMENTS = frozenset({"tests", "_vendor", "plans", "node_modules", ".venv", "migrations", "alembic"})
SKIP_FILE_PREFIXES = ("test_", "conftest")

#: SQLAlchemy statement constructors whose first argument names the entity.
STATEMENT_FUNCS = frozenset({"select", "update", "delete"})

#: Calls that attach a predicate to a statement.
PREDICATE_CALLS = frozenset({"where", "filter", "filter_by", "having", "join", "outerjoin", "join_from"})

#: Names that, appearing anywhere in a resolved predicate, mean the statement
#: is tenant-filtered.
TENANT_TOKENS = frozenset({"tenant_id", "tenant_ids", "tenant_uuid", "current_tenant_id"})

#: Annotations that establish an authenticated principal, so a predicate
#: comparing against one of that object's attributes is principal-derived
#: rather than caller-supplied. Mirrors AUTH_DEPENDENCY_NAMES in
#: check_route_tenant_scope.py; the two gates answer different questions about
#: the same vocabulary.
AUTH_ANNOTATIONS = frozenset(
    {
        "AuthUser",
        "CurrentUser",
        "ReadUser",
        "WriteUser",
        "AdminUser",
        "TenantPrincipal",
        "ScopedPrincipal",
        "PortfolioScope",
        "ActionPrincipal",
    }
)

#: How far to chase a predicate through local rebinding. Three hops covers
#: ``filters.append(...)`` → ``and_(*filters)`` → ``.where(...)`` with room to
#: spare; unbounded chasing would credit unrelated names.
_BINDING_DEPTH = 3

_SQL_VERB = re.compile(r"\b(SELECT|UPDATE|DELETE\s+FROM|INSERT\s+INTO)\b", re.IGNORECASE)
_SQL_TABLE = re.compile(r'\b(?:FROM|JOIN|UPDATE|INTO)\s+("?[\w.]+"?)', re.IGNORECASE)
_TENANT_IN_SQL = re.compile(r"\btenant_id\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Ratchet
# ---------------------------------------------------------------------------

#: Statements that reach a tenant-scoped table without a tenant predicate and
#: are nonetheless correct. Keyed ``path::function::entity``; the value is why.
#:
#: Every entry is re-verified on each run: if the statement it names has since
#: gained a predicate, or moved, or been deleted, the gate fails and the entry
#: must come out. That is the difference between a ratchet and an allowlist.
RATCHET: dict[str, str] = {
    # -- credential resolution: the lookup that *establishes* the tenant ------
    # These cannot filter on the caller's tenant because the caller has none
    # yet. The row they find is what assigns one. Scoping them on a tenant
    # would mean no login could ever resolve a user.
    "services/api/app/api/v1/endpoints/auth.py::login::User": "pre-auth credential lookup by email; this query is what resolves the tenant",
    "services/api/app/api/v1/endpoints/auth.py::refresh_token::User": (
        "refresh presents a signed token, not a tenant; the row it names assigns one"
    ),
    "services/api/app/api/v1/deps.py::get_current_user::User": "bearer-token subject lookup; runs before any tenant exists on the request",
    "services/api/app/api/v1/deps.py::_resolve_api_key::ApiKey": (
        "API-key hash lookup; the key row is the credential that carries the tenant"
    ),
    "services/api/app/api/v1/endpoints/graph_ws.py::_authenticate_ws::User": (
        "websocket ticket verification, same pre-auth shape as get_current_user"
    ),
    "services/api/app/api/v1/endpoints/passkeys.py::_consume_challenge::PasskeyChallenge": (
        "single-use WebAuthn challenge, matched on its own high-entropy value"
    ),
    "services/api/app/api/v1/endpoints/passkeys.py::passkey_authenticate_begin::User": (
        "pre-auth: resolves which user is signing in, by the email they typed"
    ),
    "services/api/app/api/v1/endpoints/passkeys.py::passkey_authenticate_begin::PasskeyCredential": (
        "pre-auth: lists the credentials registered for the resolved user"
    ),
    "services/api/app/api/v1/endpoints/passkeys.py::passkey_authenticate_finish::PasskeyCredential": (
        "pre-auth: matched on the WebAuthn credential id the authenticator signed"
    ),
    "services/api/app/api/v1/endpoints/passkeys.py::passkey_authenticate_finish::User": (
        "pre-auth: the owner of the verified credential, which is what assigns the tenant"
    ),
    "services/api/app/api/v1/endpoints/oauth.py::oauth_callback::OAuthState": (
        "matched on the 32-byte single-use state nonce, which is itself the credential"
    ),
    # -- deliberately cross-tenant surfaces ----------------------------------
    "services/api/app/api/v1/endpoints/tenants.py::create_user::User": (
        "platform-admin provisioning: creates users across tenants by design"
    ),
    "services/api/app/api/v1/endpoints/tenants.py::update_user::User": (
        "platform-admin user administration, authorised by the admin role not a tenant"
    ),
    "services/api/app/services/org_scope.py::resolve_portfolio_scope::OrganizationTenant": (
        "MSSP portfolio resolver: answers 'which tenants', so it cannot presuppose one"
    ),
    "services/api/app/services/org_scope.py::resolve_portfolio_scope::OrganizationMemberTenant": (
        "MSSP grant resolver, scoped on org_id + user_id, which is what bounds the portfolio"
    ),
    "services/api/app/api/v1/endpoints/replay.py::get_public_replay::PublishedReplay": (
        "a published replay is deliberately public; the slug is the capability"
    ),
    "services/api/app/api/v1/endpoints/replay.py::_unique_slug::PublishedReplay": (
        "slug-collision probe across all replays; a tenant-scoped check would mint duplicates"
    ),
    # -- no request, so no caller's tenant to filter on ----------------------
    "services/api/app/main.py::_demo_self_heal_bootstrap::PublishedReplay": (
        "startup bootstrap, not a request path; runs before any caller exists"
    ),
    "services/api/app/scripts/bootstrap_admin.py::bootstrap::User": "one-shot CLI bootstrap that creates the first tenant's first admin",
    "services/api/app/scripts/seed_demo.py::_ensure_user::User": "demo seeding CLI, addressed by a fixed deterministic id",
    "services/api/app/scripts/seed_demo.py::_seed_published_replay::PublishedReplay": (
        "demo seeding CLI for the canonical public replay slug"
    ),
    "services/api/app/workers/hunt_scheduler.py::run_once::SavedHunt": (
        "scheduler sweeps every tenant's due hunts, then executes each under its own tenant"
    ),
    "services/api/app/workers/oauth_refresh.py::_select_due_connectors::Connector": (
        "refresh worker sweeps all tenants' expiring OAuth grants; there is no caller"
    ),
    "services/api/app/workers/oauth_refresh.py::_refresh_one::Connector": (
        "writes back to the connector row the sweep above already selected, by primary key"
    ),
    "services/api/app/workers/oauth_refresh.py::_record_failure::Connector": "records the failure of that same swept row, by primary key",
    # -- the row is addressed by an opaque capability, and yields the tenant --
    "services/honeytokens/app/api/routes.py::webhook_trigger::Honeytoken": (
        "canary callback: the token id is the capability and the row supplies the tenant it belongs to"
    ),
    "services/osquery-tls/app/services/node_registry.py::get_node_by_key::OsqueryNode": (
        "node_key is the agent's enrolment credential; this lookup is what resolves its tenant"
    ),
    "services/osquery-tls/app/services/node_registry.py::mark_seen::OsqueryNode": (
        "heartbeat write to the node row the key above already resolved, by primary key"
    ),
    # -- scoped by a mechanism the AST cannot see, named so it can be re-checked
    "services/agents/app/investigator/ledger.py::complete_run::investigation_runs": (
        "connection runs _set_rls_context(conn, tenant_id) first and investigation_runs carries an RLS policy"
    ),
    "services/agents/app/investigator/ledger.py::persist_auto_triage::investigation_runs": (
        "same RLS-context connection as complete_run, on the same RLS-covered table"
    ),
    "services/api/app/services/retention.py::build_alert_purge_sql::alerts": (
        "returns SQL for the purge worker to run on a per-tenant RLS session; alerts carries an RLS policy"
    ),
    "services/api/app/workers/retention_purge.py::build_alert_count_sql::alerts": (
        "dry-run counterpart of build_alert_purge_sql, run on the same per-tenant RLS session"
    ),
    "services/api/app/api/v1/endpoints/investigations.py::_fetch_model_costs::aisoc_run_costs": (
        "deliberate: the agents service writes whatever tenant_id string the request carried, so the run_id (tenant-bound in "
        "investigation_runs and checked by _fetch_run) is the reliable key"
    ),
    "services/api/app/services/mssp_rule_resolver.py::resolve_effective_rules::DetectionRule": (
        "MSSP rule packs are cross-tenant by construction: a parent organisation's pack is resolved against its children, bounded by "
        "pack_id from the verified portfolio"
    ),
}

#: Raising this is a deliberate act with a diff attached. Appending to RATCHET
#: without raising it fails the gate, which is the whole point.
MAX_RATCHET = 34


# ---------------------------------------------------------------------------
# Inventory, derived from the tree
# ---------------------------------------------------------------------------


@dataclass
class Inventory:
    models: dict[str, str] = field(default_factory=dict)  # class name -> table
    tables: set[str] = field(default_factory=set)  # tables with a tenant_id column
    rls_tables: set[str] = field(default_factory=set)  # tables with an RLS policy


def _skipped(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if SKIP_SEGMENTS & set(rel.parts):
        return True
    return rel.name.startswith(SKIP_FILE_PREFIXES)


def _python_files(root: Path) -> list[Path]:
    base = root / "services"
    if not base.is_dir():
        return []
    return [p for p in sorted(base.rglob("*.py")) if not _skipped(p, root)]


def build_inventory(root: Path) -> Inventory:
    """Tenant-scoped models and tables, read out of the tree rather than listed.

    A hand-maintained list of "the tenant tables" is a naming convention with
    extra steps: the next migration adds a table and the gate never hears
    about it.
    """
    inv = Inventory()

    for py in _python_files(root):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            fields: set[str] = set()
            table: str | None = None
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    fields.add(stmt.target.id)
                elif isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        if not isinstance(tgt, ast.Name):
                            continue
                        fields.add(tgt.id)
                        if tgt.id == "__tablename__" and isinstance(stmt.value, ast.Constant):
                            table = str(stmt.value.value)
            # Only mapped classes. A Pydantic request model carrying a
            # `tenant_id` field is not a table, and counting it inflates the
            # inventory *and* teaches the raw-SQL matcher to treat the class
            # name as a table — a false positive waiting for any query that
            # happens to say `FROM Inventory`.
            if "tenant_id" in fields and table is not None:
                inv.models[node.name] = table

    for sql in sorted(root.glob("services/*/migrations/*.sql")):
        text = sql.read_text(encoding="utf-8", errors="ignore")
        bodies: dict[str, str] = {}
        for m in re.finditer(r'CREATE TABLE(?:\s+IF NOT EXISTS)?\s+([\w".]+)\s*\((.*?)\n\s*\);', text, re.S | re.I):
            name = m.group(1).strip('"').split(".")[-1]
            bodies[name] = bodies.get(name, "") + m.group(2)
        for m in re.finditer(r'ALTER TABLE\s+(?:IF EXISTS\s+)?([\w".]+)\s+ADD COLUMN(?:\s+IF NOT EXISTS)?\s+(\w+)', text, re.I):
            name = m.group(1).strip('"').split(".")[-1]
            bodies[name] = bodies.get(name, "") + " " + m.group(2)
        for name, body in bodies.items():
            if re.search(r"\btenant_id\b", body):
                inv.tables.add(name)
        for m in re.finditer(r'ALTER TABLE\s+(?:IF EXISTS\s+)?([\w".]+)\s+ENABLE ROW LEVEL SECURITY', text, re.I):
            inv.rls_tables.add(m.group(1).strip('"').split(".")[-1])

    inv.tables |= {t for t in inv.models.values() if t}
    return inv


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _names(node: ast.AST) -> set[str]:
    """Every identifier, attribute, keyword and short literal under ``node``."""
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            out.add(child.id)
        elif isinstance(child, ast.Attribute):
            out.add(child.attr)
        elif isinstance(child, ast.keyword) and child.arg:
            out.add(child.arg)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.add(child.value[:120])
    return out


def _local_bindings(fn: ast.AST) -> dict[str, set[str]]:
    """``name`` → every identifier ever assigned, appended or added to it.

    Deliberately flow-insensitive and union-ing: the question is only whether a
    tenant predicate *can* reach the statement, and a predicate appended on one
    branch still scopes the query on that branch.
    """
    binds: dict[str, set[str]] = {}

    def add(key: str, node: ast.AST) -> None:
        binds.setdefault(key, set()).update(_names(node))

    for stmt in ast.walk(fn):
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    add(tgt.id, stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            add(stmt.target.id, stmt.value)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            add(stmt.target.id, stmt.value)
        elif (
            isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute) and stmt.func.attr in {"append", "extend", "add", "update"}
        ):
            base = stmt.func.value
            if isinstance(base, ast.Name):
                for arg in stmt.args:
                    add(base.id, arg)
        elif isinstance(stmt, ast.For) and isinstance(stmt.target, ast.Name):
            add(stmt.target.id, stmt.iter)
    return binds


def _expand(seed: set[str], binds: dict[str, set[str]], depth: int = _BINDING_DEPTH) -> set[str]:
    seen = set(seed)
    frontier = set(seed)
    for _ in range(depth):
        nxt: set[str] = set()
        for name in frontier:
            for value in binds.get(name, ()):
                if value not in seen:
                    seen.add(value)
                    nxt.add(value)
        frontier = nxt
        if not frontier:
            break
    return seen


def _scoping_helpers(tree: ast.AST) -> set[str]:
    """Functions that take a statement and hand it back tenant-filtered.

    ``q = _scope(select(Alert), info, Alert)`` is scoped, and a scanner that
    only walks the ``.where()`` chain outward from ``select(...)`` reports it
    as wide open — the filter is applied one call frame away. Detected by what
    the helper *does* (returns a ``.where(...tenant_id...)`` built from one of
    its own parameters), not by what it is called.
    """
    helpers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = {a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]}
        if not params:
            continue
        for inner in ast.walk(node):
            if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)):
                continue
            if inner.func.attr not in PREDICATE_CALLS:
                continue
            base = inner.func.value
            # The filter must be applied to something derived from a parameter,
            # so a helper that merely mentions tenant_id does not qualify.
            if not (_names(base) & params):
                continue
            if _names(inner) & TENANT_TOKENS:
                helpers.add(node.name)
                break
    return helpers


def _tenant_validated_keys(fn: ast.AST, auth_names: set[str]) -> set[str]:
    """Keys this function already validated against the caller's tenant.

    ``investigations.py`` never puts a tenant on the child queries, and is
    right not to: it calls ``_fetch_run(db, run_id, current_user.tenant_id)``
    first, which 404s a run belonging to anybody else, and only then reads
    ``investigation_events`` by that verified ``run_id``. The row is addressed
    by a key the caller's tenant was checked against, which is the property —
    not the literal presence of a ``tenant_id`` column in the predicate.

    So: find calls that receive the principal's own tenant, and treat the
    other plain-name arguments of those calls as validated. The link is
    explicit — the statement only gets credit if its predicate names one of
    *those* keys.

    Known limit, stated rather than hidden: a guard that fails soft and lets
    execution continue cannot be told from one that raises. That is
    undecidable here, and it is why the ratchet exists. The real instance of
    it in this tree (``get_attack_path``'s relational fallback) is still
    caught, because the unscoped query lives in a different function.
    """
    validated: set[str] = set()
    if not auth_names:
        return validated
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        carries_tenant = False
        for expr in [*node.args, *[kw.value for kw in node.keywords]]:
            for sub in ast.walk(expr):
                if (
                    isinstance(sub, ast.Attribute)
                    and sub.attr in TENANT_TOKENS
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in auth_names
                ):
                    carries_tenant = True
        if not carries_tenant:
            continue
        for expr in [*node.args, *[kw.value for kw in node.keywords]]:
            if isinstance(expr, ast.Name):
                validated.add(expr.id)
    return validated


def _auth_bound_names(fn: ast.AST) -> set[str]:
    """Parameters annotated with an auth dependency, plus ``self``-ish aliases.

    A predicate comparing a column to ``user.user_id`` where ``user`` arrived
    through ``AuthUser`` is principal-derived and at least as narrow as the
    tenant. The same predicate against a ``user_id`` path parameter is not, and
    this is the only thing that tells them apart.
    """
    if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
        return set()
    bound: set[str] = set()
    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        if arg.annotation is not None and (_names(arg.annotation) & AUTH_ANNOTATIONS):
            bound.add(arg.arg)
    return bound


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    service: str
    path: str
    lineno: int
    function: str
    entity: str  # ORM class name, or table name for raw SQL
    table: str
    kind: str  # "orm" | "sql"
    rls: bool
    predicates: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.path}::{self.function}::{self.entity}"

    def location(self) -> str:
        return f"{self.path}:{self.lineno} {self.function}()"


def _enclosing_function(node: ast.AST, fn_of: dict[ast.AST, ast.AST]) -> ast.AST | None:
    return fn_of.get(node)


def _scan_orm(
    tree: ast.AST,
    inv: Inventory,
    *,
    service: str,
    rel: str,
    parents: dict[ast.AST, ast.AST],
    fn_of: dict[ast.AST, ast.AST],
) -> tuple[list[Finding], int]:
    helpers = _scoping_helpers(tree)
    findings: list[Finding] = []
    total = 0

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in STATEMENT_FUNCS):
            continue
        entities: set[str] = set()
        for arg in node.args:
            entities |= _names(arg) & inv.models.keys()
        if not entities:
            continue
        total += 1
        entity = sorted(entities)[0]

        predicates: set[str] = set()
        bound: str | None = None
        cursor: ast.AST = node
        wrapped_by_helper = False

        # Walk outward through `.where(...).order_by(...)` and through any
        # helper call the statement is handed to.
        while True:
            parent = parents.get(cursor)
            if isinstance(parent, ast.Attribute):
                grand = parents.get(parent)
                if isinstance(grand, ast.Call) and grand.func is parent:
                    if parent.attr in PREDICATE_CALLS:
                        for arg in grand.args:
                            predicates |= _names(arg)
                        for kw in grand.keywords:
                            if kw.arg:
                                predicates.add(kw.arg)
                    cursor = grand
                    continue
            if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id in helpers:
                wrapped_by_helper = True
                cursor = parent
                continue
            if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
                bound = parent.targets[0].id
            break

        fn = _enclosing_function(node, fn_of)
        fn_name = getattr(fn, "name", "<module>")
        binds = _local_bindings(fn) if fn is not None else {}

        if bound and fn is not None:
            for stmt in ast.walk(fn):
                if not (isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute)):
                    continue
                base = stmt.func.value
                if not (isinstance(base, ast.Name) and base.id == bound):
                    continue
                if stmt.func.attr in PREDICATE_CALLS:
                    for arg in stmt.args:
                        predicates |= _names(arg)
                    for kw in stmt.keywords:
                        if kw.arg:
                            predicates.add(kw.arg)
                elif stmt.func.attr in helpers:
                    wrapped_by_helper = True
            # `q = _scope(q, ...)` rebinding through a helper
            for stmt in ast.walk(fn):
                if (
                    isinstance(stmt, ast.Call)
                    and isinstance(stmt.func, ast.Name)
                    and stmt.func.id in helpers
                    and any(isinstance(a, ast.Name) and a.id == bound for a in stmt.args)
                ):
                    wrapped_by_helper = True

        if wrapped_by_helper:
            continue

        resolved = _expand(predicates, binds)
        if resolved & TENANT_TOKENS:
            continue
        # Principal-derived identity is narrower than the tenant. Matched
        # against the *direct* predicates rather than the expanded set: a
        # three-hop binding chase that happens to reach the name `user` is
        # not evidence that the query filters on the caller.
        auth_names = _auth_bound_names(fn) if fn is not None else set()
        if auth_names & predicates:
            continue
        # Addressed by a key this function already checked against the
        # caller's tenant.
        if fn is not None and (_tenant_validated_keys(fn, auth_names) & resolved):
            continue

        table = inv.models.get(entity, entity)
        findings.append(
            Finding(
                service=service,
                path=rel,
                lineno=node.lineno,
                function=fn_name,
                entity=entity,
                table=table,
                kind="orm",
                rls=table in inv.rls_tables,
                predicates=sorted(resolved)[:10],
            )
        )
    return findings, total


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """ids of string constants that are docstrings, so prose is not read as SQL.

    ``services/connectors/app/scheduler.py``'s module docstring describes the
    polling loop and mentions ``connectors``; read as SQL it looks like an
    unscoped query in a file the gate then reports with total confidence.
    """
    out: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", [])
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            out.add(id(body[0].value))
    return out


def _sql_text(node: ast.AST) -> str:
    """Flatten a literal, an f-string or a ``+`` chain into one blob."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_sql_text(v) if not isinstance(v, ast.FormattedValue) else " ? " for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _sql_text(node.left) + " " + _sql_text(node.right)
    return ""


def _scan_sql(
    tree: ast.AST,
    inv: Inventory,
    *,
    service: str,
    rel: str,
    parents: dict[ast.AST, ast.AST],
    fn_of: dict[ast.AST, ast.AST],
) -> tuple[list[Finding], int]:
    docstrings = _docstring_nodes(tree)
    findings: list[Finding] = []
    total = 0
    seen: set[tuple[int, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant | ast.JoinedStr):
            continue
        if id(node) in docstrings:
            continue
        # Only consider the outermost node of a concatenation chain.
        parent = parents.get(node)
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
            continue
        if isinstance(parent, ast.JoinedStr):
            continue
        blob = _sql_text(node)
        if len(blob) < 15 or not _SQL_VERB.search(blob):
            continue
        tables = {m.group(1).strip('"').split(".")[-1] for m in _SQL_TABLE.finditer(blob)}
        hit = tables & inv.tables
        if not hit:
            continue
        total += 1
        table = sorted(hit)[0]
        if (node.lineno, table) in seen:
            continue
        seen.add((node.lineno, table))

        fn = _enclosing_function(node, fn_of)
        fn_name = getattr(fn, "name", "<module>")

        if _TENANT_IN_SQL.search(blob):
            continue

        # The predicate may be concatenated in from a clause list, or bound
        # into the statement by a sibling expression, so resolve the whole
        # enclosing statement the way the ORM path does.
        stmt_node: ast.AST = node
        while stmt_node in parents and not isinstance(stmt_node, ast.stmt):
            stmt_node = parents[stmt_node]
        names = _names(stmt_node)
        binds = _local_bindings(fn) if fn is not None else {}
        resolved = _expand(names, binds)
        if any(_TENANT_IN_SQL.search(r) for r in resolved) or (resolved & TENANT_TOKENS):
            continue
        auth_names = _auth_bound_names(fn) if fn is not None else set()
        if auth_names & names:
            continue
        if fn is not None and (_tenant_validated_keys(fn, auth_names) & resolved):
            continue

        findings.append(
            Finding(
                service=service,
                path=rel,
                lineno=node.lineno,
                function=fn_name,
                entity=table,
                table=table,
                kind="sql",
                rls=table in inv.rls_tables,
                predicates=sorted(n for n in resolved if len(n) < 40)[:10],
            )
        )
    return findings, total


def scan(root: Path | None = None) -> tuple[list[Finding], Inventory, int, int]:
    base = root or REPO_ROOT
    inv = build_inventory(base)
    findings: list[Finding] = []
    files = 0
    statements = 0

    for py in _python_files(base):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"), filename=str(py))
        except SyntaxError:
            continue
        files += 1
        rel = py.relative_to(base).as_posix()
        service = rel.split("/")[1] if rel.startswith("services/") else "?"
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        fn_of: dict[ast.AST, ast.AST] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                for child in ast.walk(fn):
                    fn_of[child] = fn

        orm, n_orm = _scan_orm(tree, inv, service=service, rel=rel, parents=parents, fn_of=fn_of)
        sql, n_sql = _scan_sql(tree, inv, service=service, rel=rel, parents=parents, fn_of=fn_of)
        findings.extend(orm)
        findings.extend(sql)
        statements += n_orm + n_sql

    return findings, inv, files, statements


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def partition(findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    """Return (unratcheted findings, stale ratchet keys)."""
    seen_keys = {f.key for f in findings}
    unratcheted = [f for f in findings if f.key not in RATCHET]
    stale = sorted(k for k in RATCHET if k not in seen_keys)
    return unratcheted, stale


def _print_inventory(findings: list[Finding], inv: Inventory, files: int, statements: int) -> None:
    print(f"Tenant-predicate inventory — scanned {files} files under {SERVICES_DIR}")
    print(f"  tenant-scoped ORM models : {len(inv.models)}")
    print(f"  tenant-scoped tables     : {len(inv.tables)}")
    print(f"  of those, RLS-covered    : {len(inv.tables & inv.rls_tables)}  (the rest have query-layer scoping only)")
    print(f"  statements examined      : {statements}")
    print()
    services = sorted({f.service for f in findings})
    print(f"{'service':<16}{'findings':>10}{'ratcheted':>11}{'open':>7}{'no-RLS':>8}")
    print("-" * 52)
    for svc in services:
        rows = [f for f in findings if f.service == svc]
        ratch = sum(1 for f in rows if f.key in RATCHET)
        print(f"{svc:<16}{len(rows):>10}{ratch:>11}{len(rows) - ratch:>7}{sum(1 for f in rows if not f.rls):>8}")
    print("-" * 52)
    ratch = sum(1 for f in findings if f.key in RATCHET)
    print(f"{'TOTAL':<16}{len(findings):>10}{ratch:>11}{len(findings) - ratch:>7}{sum(1 for f in findings if not f.rls):>8}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_PROBE_MODEL = """
from sqlalchemy import Column, String
from app.db.base import Base

class Widget(Base):
    __tablename__ = "widgets"
    id = Column(String, primary_key=True)
    tenant_id = Column(String)
    owner_id = Column(String)
"""

_CLEAN = """
from sqlalchemy import select
from app.models.widget import Widget

async def get_widget(widget_id, user, db):
    return await db.execute(select(Widget).where(Widget.id == widget_id, Widget.tenant_id == user.tenant_id))
"""

_UNSCOPED = """
from sqlalchemy import select
from app.models.widget import Widget

async def get_widget(widget_id, user, db):
    return await db.execute(select(Widget).where(Widget.id == widget_id))
"""

_UNSCOPED_SQL = """
from sqlalchemy import text

async def get_widget(widget_id, db):
    return await db.execute(text("SELECT * FROM widgets WHERE id = :id").bindparams(id=widget_id))
"""

_SCOPED_VIA_LIST = """
from sqlalchemy import and_, select
from app.models.widget import Widget

async def list_widgets(user, db, kind=None):
    filters = [Widget.tenant_id == user.tenant_id]
    if kind:
        filters.append(Widget.kind == kind)
    return await db.execute(select(Widget).where(and_(*filters)))
"""

_SCOPED_VIA_HELPER = """
from sqlalchemy import select
from app.models.widget import Widget

def _scope(stmt, user, model):
    return stmt.where(model.tenant_id == user.tenant_id)

async def list_widgets(user, db):
    return await db.execute(_scope(select(Widget), user, Widget))
"""

_SCOPED_VIA_REBIND = """
from sqlalchemy import select
from app.models.widget import Widget

async def list_widgets(user, db, kind=None):
    q = select(Widget)
    q = q.where(Widget.tenant_id == user.tenant_id)
    if kind:
        q = q.where(Widget.kind == kind)
    return await db.execute(q)
"""

_SCOPED_VIA_PRINCIPAL = """
from typing import Annotated
from sqlalchemy import select
from app.api.v1.deps import AuthUser
from app.models.widget import Widget

async def my_widgets(user: AuthUser, db):
    return await db.execute(select(Widget).where(Widget.owner_id == user.user_id))
"""

_DOCSTRING_ONLY = '''
"""Widget helpers.

Historically this ran ``SELECT * FROM widgets WHERE id = ?`` before the ORM
landed. Prose, not a query.
"""

def helper():
    return 1
'''


def _write_probe(root: Path, sources: dict[str, str]) -> None:
    pkg = root / "services" / "probe" / "app"
    (pkg / "models").mkdir(parents=True, exist_ok=True)
    (pkg / "models" / "widget.py").write_text(_PROBE_MODEL, encoding="utf-8")
    for name, src in sources.items():
        (pkg / name).write_text(src, encoding="utf-8")


def _self_test() -> int:
    """Prove the gate fails on injected drift, both ways, and drops a stale entry."""
    cases: list[tuple[str, dict[str, str], int]] = [
        ("clean: by-id read carries a tenant predicate", {"r.py": _CLEAN}, 0),
        ("drift A: by-id ORM read with no tenant predicate", {"r.py": _UNSCOPED}, 1),
        ("drift B: by-id raw SQL with no tenant predicate", {"r.py": _UNSCOPED_SQL}, 1),
        ("control: predicate built in a filters list", {"r.py": _SCOPED_VIA_LIST}, 0),
        ("control: predicate applied by a wrapping helper", {"r.py": _SCOPED_VIA_HELPER}, 0),
        ("control: predicate added by a later q = q.where()", {"r.py": _SCOPED_VIA_REBIND}, 0),
        ("control: scoped on the authenticated principal's own id", {"r.py": _SCOPED_VIA_PRINCIPAL}, 0),
        ("control: SQL in a docstring is prose, not a query", {"r.py": _DOCSTRING_ONLY}, 0),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for i, (label, sources, want) in enumerate(cases):
            root = Path(tmp) / f"case{i}"
            _write_probe(root, sources)
            findings, _inv, files, _stmts = scan(root=root)
            got = len(findings)
            ok = got == want and files > 0
            if not ok:
                failures += 1
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {got} finding(s), want {want} (scanned {files} files)")

    failures += _self_test_stale_ratchet()
    failures += _self_test_ratchet_ceiling()

    if failures:
        print(f"\nself-test FAILED: {failures} case(s) did not behave as specified", file=sys.stderr)
        return 1
    print("\nself-test passed: drift detected in both directions, six controls clear, and a stale ratchet entry is dropped.")
    return 0


def _self_test_stale_ratchet() -> int:
    """Strip a live ratchet entry's justification and assert it stops protecting.

    The reverse direction. An entry keeps its exemption only while the
    statement it names is still unscoped; fix the code and the entry must come
    out, which is what makes the table shrink-only.
    """
    findings, _inv, _files, _stmts = scan()
    live = {f.key for f in findings} & RATCHET.keys()
    if not live:
        print("  [FAIL] stale ratchet: no live ratchet entry to exercise")
        return 1

    # Forward: every entry must correspond to a real unscoped statement.
    _unratcheted, stale = partition(findings)
    if stale:
        for key in stale:
            print(f"  [FAIL] stale ratchet entry (statement is now scoped, moved or deleted): {key}")
        return len(stale)

    # Reverse: remove one entry and assert the finding surfaces.
    victim = sorted(live)[0]
    saved = RATCHET.pop(victim)
    try:
        unratcheted, _ = partition(findings)
        if any(f.key == victim for f in unratcheted):
            print(f"  [PASS] stale ratchet: {victim} is reported the moment its entry is removed")
            return 0
        print(f"  [FAIL] stale ratchet: removing {victim} produced no finding")
        return 1
    finally:
        RATCHET[victim] = saved


def _self_test_ratchet_ceiling() -> int:
    if len(RATCHET) > MAX_RATCHET:
        print(f"  [FAIL] ratchet ceiling: {len(RATCHET)} entries exceeds MAX_RATCHET={MAX_RATCHET}")
        return 1
    print(f"  [PASS] ratchet ceiling: {len(RATCHET)}/{MAX_RATCHET} entries")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", action="store_true", help="print the per-service finding inventory")
    parser.add_argument("--json", action="store_true", help="emit every finding as JSON")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift both ways")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not SERVICES_DIR.is_dir():
        print(f"ERROR: no services/ directory under {REPO_ROOT} — refusing to report a result for a tree I did not open.", file=sys.stderr)
        return 2

    findings, inv, files, statements = scan()

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return 0

    if args.inventory:
        _print_inventory(findings, inv, files, statements)
        return 0

    unratcheted, stale = partition(findings)

    # Name what was scanned. A gate that prints OK without saying what it
    # opened cannot be told apart from one that opened nothing.
    print(
        f"check_tenant_query_predicates: scanned {files} files under {SERVICES_DIR}; "
        f"{statements} statements touch {len(inv.tables)} tenant-scoped tables "
        f"({len(inv.tables) - len(inv.tables & inv.rls_tables)} of them with no RLS policy)"
    )

    if len(RATCHET) > MAX_RATCHET:
        print(
            f"\nFAIL: the ratchet holds {len(RATCHET)} entries but MAX_RATCHET is {MAX_RATCHET}.",
            file=sys.stderr,
        )
        print("      It only shrinks. Fix the query rather than raising the ceiling.", file=sys.stderr)
        return 1

    if stale:
        print(f"\nFAIL: {len(stale)} ratchet entry/entries no longer describe an unscoped statement.", file=sys.stderr)
        print("      The code was fixed, moved or deleted. Remove the entry — a lapsed", file=sys.stderr)
        print("      justification that still passes reads like a decision somebody made.", file=sys.stderr)
        for key in stale:
            print(f"  - {key}", file=sys.stderr)

    if unratcheted:
        print(f"\nFAIL: {len(unratcheted)} statement(s) reach a tenant-scoped table with no tenant predicate.", file=sys.stderr)
        print("      How the row was addressed is irrelevant; naming another tenant's id reaches it.", file=sys.stderr)
        for f in unratcheted:
            rls = "" if f.rls else "  [no RLS — the predicate is the only control]"
            print(f"  - {f.location()} {f.kind} on {f.table}{rls}", file=sys.stderr)

    if stale or unratcheted:
        return 1

    print(
        f"OK: every statement on a tenant-scoped table filters on a tenant, "
        f"or is one of {len(RATCHET)} ratcheted exceptions that still holds."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

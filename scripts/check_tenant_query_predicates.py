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

It was the *only* control on most of this schema. Of 95 tenant-scoped tables,
31 carried an RLS policy and 64 did not; ``060_rls_coverage.sql`` plus a
revision in each of the four services that manage their own schema takes that
to every table bar ``users``, which is excluded so authentication can resolve a
principal before a tenant exists. Run ``--inventory`` for the live figures
rather than trusting these; they are a description, not a gate.

That does **not** demote the predicate, for two reasons worth stating where
somebody reading this file will see them:

* RLS engages only on a session that ran ``SET LOCAL app.current_tenant_id``.
  That is ``TenantDBSession`` in the API, ``_set_rls_context`` in the agents
  ledger / hunt store / LLM resolver, and the per-hunt rebind in the hunt
  scheduler. Every other connection — ingest, fusion, the workers — leaves it
  unset, and the policies then fail open by design.
* The role the services connect as used to be a superuser, and a superuser
  bypasses RLS even under FORCE ROW LEVEL SECURITY, so the second layer was
  not there at all. ``061_runtime_app_role.sql`` moved every deployment
  surface onto a DML-only role and ``scripts/check_runtime_db_role.py`` keeps
  it there, so that caveat is retired — but it applies again the moment an
  operator points ``DATABASE_URL`` at the owner, which is why the credit below
  is still counted separately rather than folded into the total.

So on most reads a missing predicate is still a leak rather than a
defence-in-depth gap, and this gate is still the control that matters.

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
  counts — a ``user_id`` the caller typed is not a credential;
* a key an **enforcing** guard already checked against the caller's tenant.
  "Enforcing" is the load-bearing word: a guard that logs and continues reads
  exactly like one that raises, so :func:`_guard_enforces` decides it
  structurally and refuses to guess when it cannot (see that docstring);
* an **RLS context bound on the connection**, on a table that actually carries
  a policy. Four ratchet entries described this mechanism instead of a defect.
  Re-checking them found the mechanism did not work: the agents service set
  ``app.tenant_id`` while every policy reads ``app.current_tenant_id``. The
  rule credits the fixed form and counts it separately in the output. Until
  061_runtime_app_role.sql that credit lapsed on every shipped deployment,
  because the connecting role bypassed RLS outright; it now holds by default
  and lapses only on a deployment that has pointed DATABASE_URL back at the
  owner — which ``scripts/check_runtime_db_role.py`` fails on.

Anything else is a finding, and must be on the ratchet with a reason.

Two arms, because a statement has no opinion about who calls it
---------------------------------------------------------------
The rule above asks whether a statement filters on a tenant. That is not
sufficient on its own, and GHSA-h4g5-39vv-pqfv is the proof: the connectors
scheduler's "every enabled instance, across every tenant" sweep is correctly
unscoped and correctly ratcheted — and a *request handler* was calling it,
picking one caller's row out of every tenant's by string-comparing an id, then
decrypting that row's vendor credential and spending it. Both halves read as
correct in isolation. Measured, with the Core-table rule below in place but
without this second arm, the gate reported OK on the vulnerable tree.

So the second arm asks: **which HTTP route handlers reach a statement that
carries no tenant predicate?** A sweep's exemption is earned by there being no
caller whose tenant it could have filtered on; a request handler has one, so
reaching it retires the justification. ``ROUTE_REACHABLE`` records the pairs
where a request legitimately may — pre-auth lookups, opaque-capability reads,
administrative surfaces that are cross-tenant by design, and handlers that
validated the key against the caller's tenant first — and it is a ratchet in
both directions like the other.

Two things it deliberately is not. It resolves a call through the importing
module rather than by bare name: a name-only pass invented five call paths
that do not exist, and a gate that fabricates findings gets switched off. And
it does not flag a *worker* calling the same sweep, because that caller is the
reason the exemption exists.

A third blind spot, found while measuring this and **not** closed here, is
recorded so it is not rediscovered as news: ``_TENANT_IN_SQL`` matches
``tenant_id`` anywhere in a raw statement, including the projection, so
``SELECT tenant_id, secret FROM t WHERE id = :id`` reads as scoped. The one
statement in this tree that relies on it (``scheduler.py``'s tenant
enumeration) is legitimately cross-tenant, so nothing is currently wrong —
but the rule is weaker than it looks.

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

#: The Postgres session variable the RLS policies read. A function that sets
#: it has scoped the whole connection, which no predicate in the SQL will show.
RLS_SESSION_VARIABLE = "app.current_tenant_id"

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
# Does a raw statement's `tenant_id` actually constrain the rows?
# ---------------------------------------------------------------------------
#
# `_TENANT_IN_SQL` answers "does this string contain the token", which is not
# the question. The blind spot was recorded in this module's own docstring and
# left open on the grounds that one statement relied on it and that statement
# was legitimately cross-tenant. That stopped being true: measured on `main`,
# 18 statements were credited by a token that constrains nothing, two of them
# `UPDATE … RETURNING id, tenant_id` worker sweeps that the ratchet is supposed
# to account for by name and did not, because the bare match short-circuited
# before the ratchet was ever consulted.
#
# The distinction is where the token sits, so the token's *clause* is what gets
# read. Occurrences are attributed to the clause keyword most recently opened
# before them, which handles subqueries and CTEs the way they actually nest:
# `WHERE id IN (SELECT … WHERE tenant_id = $1)` credits the inner predicate,
# and `UPDATE … WHERE <no tenant> RETURNING tenant_id` credits nothing.
#
# A real SQL parser was considered and rejected. `sqlglot` is in the tree and
# pinned exactly, but every gate here has to run on a bare interpreter before
# any `pip install` (see `scripts/gate_toolkit.py`), and a gate that acquires a
# dependency is a gate that gets skipped in the one environment that matters.
# The cost of that choice is recorded in `_UNCREDITED` below.

#: Comments are stripped before any clause is located. Two statements in this
#: tree carry a `--` note, and a token inside one constrains nothing while
#: reading exactly like a predicate to a positional scan.
_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

#: Clause keywords, **longest first**: `ON CONFLICT` must not be read as a join
#: `ON`, and `DELETE FROM` must not be read as a bare `FROM`. Python's `re`
#: alternation is first-match-wins rather than longest-match, so this ordering
#: is load-bearing and `test_on_conflict_is_not_read_as_a_join_on` pins it.
#: Ordered longest-first; the regex is built from this tuple rather than
#: written out separately, so the keyword set the matcher recognises and the
#: keyword set the two classification tables below are checked against cannot
#: be two different lists.
_CLAUSE_KEYWORDS: tuple[str, ...] = (
    "ON CONFLICT",
    "DO UPDATE SET",
    "DELETE FROM",
    "INSERT INTO",
    "GROUP BY",
    "ORDER BY",
    "LEFT JOIN",
    "RIGHT JOIN",
    "INNER JOIN",
    "OUTER JOIN",
    "CROSS JOIN",
    "SELECT",
    "FROM",
    "WHERE",
    "HAVING",
    "RETURNING",
    "VALUES",
    "USING",
    "UPDATE",
    "SET",
    "JOIN",
    "ON",
    "LIMIT",
    "OFFSET",
    "WITH",
)

_SQL_CLAUSE = re.compile(
    r"\b(" + "|".join(kw.replace(" ", r"\s+") for kw in _CLAUSE_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

#: Clauses in which `tenant_id` restricts which rows are read or written.
#:
#: `ON CONFLICT (tenant_id, …)` is here because the conflict target is what
#: selects the existing row an upsert updates — it is that statement's WHERE.
#: `INSERT INTO t (tenant_id, …)` is here for the write direction: the column
#: list plus a bound value is what stamps the new row with a tenant, and it is
#: the only form in which an INSERT can be scoped at all. 90 of the 108
#: statements this rule re-examines are that shape and every one is correct;
#: flagging them would have been 90 false positives, which is how a gate gets
#: switched off.
_CONSTRAINING_CLAUSES = frozenset({"WHERE", "ON", "USING", "HAVING", "ON CONFLICT", "INSERT INTO"})

#: Deliberately **not** credited, each for a stated reason:
#:
#: `SELECT` / `RETURNING`   a projection names a column on the way out; it says
#:                          nothing about which rows were chosen. This is the
#:                          defect being closed.
#: `ORDER BY` / `GROUP BY`  sorting and bucketing happen after the rows are
#:                          picked. A cross-tenant aggregate grouped by tenant
#:                          is still a cross-tenant read.
#: `VALUES`                 a bound value alone does not say which column it
#:                          lands in; the column list is what does.
#: `SET`                    on an UPDATE this *writes* the tenant column, which
#:                          constrains nothing about which rows are rewritten —
#:                          it is a tenant reassignment, the opposite of a
#:                          scope.
#:
#: Read by `_clause_classification_is_total`, not only by a human: a clause
#: added to `_SQL_CLAUSE` and classified into neither set would silently
#: default to "not credited", which is the safe direction but an unstated one.
#: The self-test asserts the two sets are disjoint and together cover every
#: alternative the regex can emit, so adding a keyword forces a decision.
_UNCREDITED = frozenset(
    {
        "SELECT",
        "RETURNING",
        "ORDER BY",
        "GROUP BY",
        "VALUES",
        "SET",
        "DO UPDATE SET",
        "FROM",
        "LIMIT",
        "OFFSET",
        "UPDATE",
        "DELETE FROM",
        "JOIN",
        "LEFT JOIN",
        "RIGHT JOIN",
        "INNER JOIN",
        "OUTER JOIN",
        "CROSS JOIN",
        "WITH",
    }
)


def _clause_classification_is_total() -> tuple[bool, str]:
    """Every clause `_SQL_CLAUSE` can emit is classified exactly once.

    A keyword the regex matches but neither set names falls through to "not
    constraining". That is the right default and the wrong way to arrive at
    it — nobody decided. Checked rather than trusted, because the regex and
    the two sets are three lists that have to agree and sit 60 lines apart.
    """
    emitted = set(_CLAUSE_KEYWORDS)
    both = _CONSTRAINING_CLAUSES & _UNCREDITED
    unclassified = emitted - _CONSTRAINING_CLAUSES - _UNCREDITED
    problems = []
    if both:
        problems.append(f"classified twice: {sorted(both)}")
    if unclassified:
        problems.append(f"matched by _SQL_CLAUSE but classified nowhere: {sorted(unclassified)}")
    return (not problems), "; ".join(problems) or f"{len(emitted)} clause keyword(s), each classified exactly once"


#: Known residuals, stated rather than silently carried. Neither is reachable
#: in this tree today and both are checked for by the self-test so that stays
#: visible:
#:
#: * a correlated subquery in a projection (`SELECT (SELECT … WHERE
#:   b.tenant_id = a.tenant_id) FROM a`) credits the outer statement off the
#:   inner predicate. The correlation makes the outer read per-tenant in
#:   practice, so this errs toward a credit rather than a false alarm.
#: * `INSERT INTO a (tenant_id, …) SELECT … FROM b` credits the stamped write
#:   while the *read* from `b` may be unscoped. One statement of this shape
#:   exists and it carries its own `WHERE tenant_id`.


#: A predicate *fragment* carries no clause keyword of its own — it is the
#: ``" AND tenant_id = :tid"`` that a caller concatenates onto a base query, or
#: an element of a ``filters`` list. The token is only credited there when it
#: is one side of a comparison, so ``", tenant_id"`` appended to a projection
#: stays uncredited. An optional ``::cast`` sits between the two in asyncpg
#: code (``tenant_id::uuid = $1``) and has to be stepped over.
_TENANT_COMPARED = re.compile(
    r"\btenant_id\b\s*(?:::\s*\w+\s*)?\s*(?:=|<>|!=|>=|<=|>|<|\bIN\b|\bIS\b|\bLIKE\b|\bBETWEEN\b|\bANY\b)"
    r"|(?:=|<>|!=|\bIN\b|\bANY\b)\s*\(?\s*\btenant_id\b",
    re.IGNORECASE,
)


def _tenant_predicate_in_sql(blob: str) -> bool:
    """Whether `tenant_id` appears somewhere that constrains the rows.

    Replaces a bare `tenant_id in the string` test. Returns False for a token
    that only ever appears in a projection, a `RETURNING` list, an `ORDER BY`,
    a `GROUP BY`, an UPDATE's `SET`, or a comment.

    Called on two kinds of string and has to answer for both: a whole
    statement, where the clause the token sits in decides; and a bare predicate
    fragment with no clause keyword at all, where being one side of a
    comparison decides.
    """
    text_only = _SQL_BLOCK_COMMENT.sub(" ", _SQL_LINE_COMMENT.sub(" ", blob))
    clauses = [(m.start(), re.sub(r"\s+", " ", m.group(1).upper())) for m in _SQL_CLAUSE.finditer(text_only)]
    for hit in _TENANT_IN_SQL.finditer(text_only):
        governing = ""
        for start, keyword in clauses:
            if start > hit.start():
                break
            governing = keyword
        if governing in _CONSTRAINING_CLAUSES:
            return True
        # No clause opened before the token: this is a fragment, not a
        # statement. Credit it only if the token is being compared against
        # something rather than merely listed.
        if not governing and _TENANT_COMPARED.search(text_only[max(0, hit.start() - 24) : hit.end() + 24]):
            return True
    return False


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
    # One entry where there were two. The bearer-token subject lookup was
    # inlined in `get_current_user` *and* copied into `_authenticate_ws`;
    # that copy skipped the session-revocation check and database RBAC
    # (GHSA-25fh-rxp8-67j8), so the two are now one function and this is
    # its one exemption.
    "services/api/app/api/v1/deps.py::resolve_jwt_principal::User": (
        "bearer-token subject lookup; runs before any tenant exists on the request"
    ),
    "services/api/app/api/v1/deps.py::_resolve_api_key::ApiKey": (
        "API-key hash lookup; the key row is the credential that carries the tenant"
    ),
    "services/api/app/services/scim/tokens.py::verify_token::ScimToken": (
        "SCIM bearer-token digest lookup; the token row is what assigns the tenant, "
        "and RFC 7643 defines no tenant attribute a caller could have supplied"
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
    "services/agents/app/playbook/pause.py::expire_due_returning::aisoc_playbook_pauses": (
        "the approval-expiry sweep: a per-tenant sweep would need a list of tenants to "
        "iterate, and a tenant missing from that list would have approvals that never "
        "expire, which is the silent hang the sweep exists to prevent"
    ),
    "services/agents/app/investigator/ledger.py::fail_stale_runs::investigation_runs": (
        "the stale-run reaper, the same shape as the approval and webhook sweeps below: a run is "
        "abandoned when the process that owned it is gone, so there is no caller and no tenant to "
        "filter by, and a per-tenant pass needs a list of tenants whose omissions are runs that "
        "render as 'running' forever. Admitted by the second arm of the policy in "
        "008_investigation_ledger.sql (`OR current_tenant_id() IS NULL`); the function says so, so a "
        "future policy that drops that arm turns this into a visible no-op rather than a silent one"
    ),
    "services/api/app/services/outbound_webhooks.py::due_deliveries::OutboundDelivery": (
        "the outbound-webhook retry sweep, the same shape as the approval and wait sweeps above: a "
        "per-tenant pass needs a list of tenants, and a tenant missing from it has events that are "
        "never sent while the dead-letter view reads empty. The row carries the tenant it belongs to "
        "and every read surface filters on it"
    ),
    "services/agents/app/playbook/pause.py::find_wait_by_token::aisoc_playbook_pauses": (
        "the resume token is the whole credential, so a caller presenting one has no tenant to filter "
        "by — the same shape as the SCIM-token and WebAuthn-challenge entries above. It is minted "
        "separately from the row id precisely so it cannot be guessed from anything an analyst can "
        "read, and `kind = 'wait'` is in the predicate so an approval can never be resumed this way"
    ),
    "services/agents/app/playbook/pause.py::due_waits::aisoc_playbook_pauses": (
        "the wait sweeper asks 'which waits are due', which cannot presuppose a tenant — the same "
        "discover-a-working-set shape as due_deliveries and report_scheduler.run_once below. It is "
        "read-only; `resolve` claims one row at a time under a tenant, and the two scoped reads "
        "beside it (find_waiting, resolve) do filter, so resuming another tenant's run takes two "
        "mistakes rather than one"
    ),
    "services/api/app/workers/report_scheduler.py::run_once::ReportTemplate": (
        "the report scheduler asks 'whose schedule is due', which cannot presuppose a tenant — the same "
        "reasoning recorded for hunt_scheduler.run_once and oauth_refresh._select_due_connectors, both of "
        "which discover a working set and then act per tenant"
    ),
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
    "services/api/app/services/retro_hunt/service.py::opted_in_tenants::RetroHuntSettings": (
        "answers 'which tenants opted in to retro-hunts', so it cannot presuppose one; the caller "
        "binds each tenant with set_config before any sweep or alert write, so every write after "
        "this read is RLS-enforced. Same shape and same reasoning as hunt_scheduler.run_once above"
    ),
    "services/api/app/workers/oauth_refresh.py::_select_due_connectors::Connector": (
        "refresh worker sweeps all tenants' expiring OAuth grants; there is no caller"
    ),
    "services/api/app/workers/oauth_refresh.py::_refresh_one::Connector": (
        "writes back to the connector row the sweep above already selected, by primary key"
    ),
    "services/api/app/workers/oauth_refresh.py::_record_failure::Connector": "records the failure of that same swept row, by primary key",
    "services/api/app/workers/approval_expiry.py::run_once::agent_approvals": (
        "counts pending approvals that carry no expires_at, across every tenant, for one operator log line. "
        "The sweep it sits beside is tenant-wide by nature and calls assert_cross_tenant_session first, so a "
        "tenant predicate here would report one tenant's gap as the whole estate's"
    ),
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
    # -- SQL fragments, assembled by a caller the gate scores separately -----
    # These two were on the ratchet as "run on a per-tenant RLS session". They
    # are not: ``_purge_alerts`` runs with row security *disabled* so it can
    # enumerate tenants, and appends ``AND tenant_id = :tenant_id`` itself. The
    # old reason named a mechanism the only caller deliberately avoids, which
    # is worse than no reason — it would have survived the caller dropping the
    # predicate. Re-checking every entry instead of trusting the two the RLS
    # rule was written for is what surfaced this.
    "services/api/app/services/retention.py::build_alert_purge_sql::alerts": (
        "returns a SQL string and never executes it; the sole caller (workers/retention_purge.py::_purge_alerts) "
        "appends AND tenant_id = :tenant_id, and that assembled statement is scored on its own"
    ),
    "services/api/app/workers/retention_purge.py::build_alert_count_sql::alerts": (
        "same fragment shape as build_alert_purge_sql: _purge_alerts concatenates the tenant predicate onto it before executing"
    ),
    "services/api/app/api/v1/endpoints/investigations.py::_fetch_model_costs::aisoc_run_costs": (
        "deliberate: the agents service writes whatever tenant_id string the request carried, so the run_id (tenant-bound in "
        "investigation_runs and checked by _fetch_run) is the reliable key"
    ),
    "services/api/app/services/mssp_rule_resolver.py::resolve_effective_rules::DetectionRule": (
        "MSSP rule packs are cross-tenant by construction: a parent organisation's pack is resolved against its children, bounded by "
        "pack_id from the verified portfolio"
    ),
    # -- users-administration surface (admin console): every statement is keyed
    # on a user id the caller already resolved through tenant-scoped queries
    # (the list/detail endpoints SELECT users WHERE tenant_id = :t and hand
    # _guard_last_admin/_end_sessions only ids that came out of that scoped
    # read; rbac.set_primary_role re-reads the target under the caller's
    # tenant before writing). Cross-tenant by the nature of a platform-admin
    # console; reachable only behind require_permission("roles:write").
    "services/api/app/api/v1/endpoints/admin_users.py::_end_sessions::User": (
        "write keyed on a user id from the tenant-scoped SELECT earlier in "
        "the same request; revoking another tenant's session requires "
        "guessing a UUID, not reaching it"
    ),
    "services/api/app/api/v1/endpoints/admin_users.py::_guard_last_admin::roles": (
        "count of admins holding this user's role rows; user_id comes from "
        "the tenant-scoped read, and the answer only ever denies the "
        "operation"
    ),
    "services/api/app/api/v1/endpoints/rbac.py::set_primary_role::User": (
        "mirrors the granted role name onto the user row, keyed on the "
        "user id validated against the caller's tenant at the top of this "
        "endpoint"
    ),
    "services/api/app/core/rbac_catalog.py::<module>::alerts": (
        "false-positive attribution: the flagged line is the PERMISSIONS "
        "vocabulary tuple, not SQL — the word 'alerts' appears only inside "
        "permission slugs ('alerts:read' …); the module's only executable "
        "SQL is seed_tenant_catalog's INSERT INTO permissions/roles/"
        "role_permissions/user_roles, each bound to :t"
    ),
    # ── the 2026-10-12 merge train (depth 5.4, 9.4, 4.3) ────────────────────
    "services/agents/app/playbook/pause.py::find_verification_by_token::aisoc_playbook_pauses": (
        "the signed answer link is the whole credential, exactly the find_wait_by_token shape above: "
        "the person clicking holds no AiSOC session, so there is no tenant to filter by. The HMAC "
        "covers (token, answer, stage) so a guessed token still answers nothing, and "
        "`kind = 'verification'` is in the predicate so an approval cannot be discharged this way"
    ),
    "services/agents/app/playbook/pause.py::due_verifications::aisoc_playbook_pauses": (
        "the verification sweeper asks 'which prompts passed their stage deadline', the same "
        "discover-a-working-set shape as due_waits beside it; escalation then acts on one row at a "
        "time with the tenant read off the row"
    ),
    "services/api/app/api/v1/endpoints/war_rooms.py::channel_decision::aisoc_case_war_rooms": (
        "the bot presents the shared service token and a war-room id; it holds no tenant and the "
        "request body deliberately has no tenant field to get wrong. The handler reads the row by "
        "id, binds set_rls_context to the row's own tenant before acting, and refuses without the "
        "token — the tenant comes from the row the bot named, never from the caller"
    ),
    "services/api/app/services/war_room.py::sync_war_room::aisoc_case_war_rooms": (
        "the sweep is a pure function of the case row: it reads the room by id handed to it by the "
        "worker's cross-tenant discovery below, and every post it writes is keyed to that room; the "
        "analyst-facing routes in endpoints/war_rooms.py all filter on the session tenant"
    ),
    "services/api/app/services/war_room.py::sync_war_room::aisoc_war_room_posts": (
        "the posted-keys read is scoped to one war_room_id — the room decides the tenant, and the "
        "unique constraint on (war_room_id, event_key) is what makes the sweep idempotent"
    ),
    "services/api/app/services/lake_query_runner.py::claim_statement::LakeQueryJob": (
        "the claim is one conditional UPDATE by job id where status = 'queued' — a worker claiming "
        "work enqueued by tenant-scoped routes, the same shape as approval_expiry.run_once. The "
        "routes that create and read jobs bind the tenant; the runner executes whichever replica won, "
        "and the policy's unbound-session arm is what admits its GUC-less session"
    ),
    "services/api/app/services/lake_query_runner.py::_record_progress::LakeQueryJob": (
        "progress lands on the claimed job by id; the claim above is what decided whose job it is"
    ),
    "services/api/app/services/lake_query_runner.py::_finish::LakeQueryJob": (
        "terminal state lands on the claimed job by id, guarded so a finished job is never revived; "
        "same claim-then-act shape as _record_progress"
    ),
    "services/api/app/services/lake_query_runner.py::list_stuck_jobs::LakeQueryJob": (
        "the stuck sweep asks 'which running jobs lost their runner', tenant-unbound by the same "
        "discover-a-working-set reasoning as due_deliveries; it only moves jobs to a terminal state"
    ),
    "services/api/app/workers/war_room_sync.py::<module>::aisoc_case_war_rooms": (
        "the sweep worker's 'which rooms are open' discovery, the same cross-tenant working-set "
        "shape as report_scheduler.run_once; sync_war_room then handles one room at a time"
    ),
    # ── services/connectors, visible to this gate for the first time ────────
    # These six are not new queries. They are the six statements the Core-table
    # blindness hid (see build_inventory), surfacing together the moment the
    # gate could see the table at all. Each was read before being recorded.
    "services/connectors/app/db/connector_repo.py::fetch_enabled_connectors::connectors_table": (
        "the connector scheduler's working set: 'which instances are enabled', across every tenant, "
        "which cannot presuppose a tenant — the same discover-a-working-set shape as "
        "hunt_scheduler.run_once and oauth_refresh._select_due_connectors above. A tenant missing "
        "from it is a customer whose connectors silently stop ingesting. Its only two callers are "
        "ConnectorScheduler.reload_jobs and _poll_one, neither reachable from a request; the "
        "docstring now says a request handler must not call it, and the route that did "
        "(GHSA-h4g5-39vv-pqfv) takes fetch_enabled_connector_for_tenant, which filters in SQL"
    ),
    "services/connectors/app/db/connector_repo.py::record_poll_success::connectors_table": (
        "writes the poll outcome back to the row the sweep above already selected, by primary key — "
        "the same shape and the same reasoning as oauth_refresh._refresh_one. Sole caller is "
        "ConnectorScheduler (scheduler.py:875) passing an id from its own enumeration; no request "
        "input reaches it"
    ),
    "services/connectors/app/db/connector_repo.py::record_poll_failure::connectors_table": (
        "the failure counterpart of record_poll_success, keyed on the same swept primary key; sole caller scheduler.py:1111"
    ),
    "services/connectors/app/db/connector_repo.py::record_checkpoint::connectors_table": (
        "persists the ingest cursor onto the swept row by primary key; sole caller "
        "ConnectorScheduler._record_checkpoint (scheduler.py:950), which is handed target.id from "
        "the poll it just completed"
    ),
    "services/connectors/app/db/connector_repo.py::record_backfill_run::connectors_table": (
        "stamps the backfill timestamp on the swept row by primary key; sole caller "
        "ConnectorScheduler._record_backfill_run (scheduler.py:902)"
    ),
    "services/connectors/app/db/connector_repo.py::record_schema_drift::connectors_table": (
        "records a confirmed drift on the swept row by primary key; sole caller scheduler.py:926, "
        "which compares the fingerprint of the poll it just performed"
    ),
    # ── raw SQL, visible to this gate for the first time ───────────────────
    # Not new queries, and not new debt. These seventeen statements are
    # unchanged on disk; they were credited by `_TENANT_IN_SQL` matching the
    # token anywhere in the string — a `RETURNING id, tenant_id`, a `SELECT
    # tenant_id, …` projection, an `ORDER BY tenant_id`. The clause-aware rule
    # (`_tenant_predicate_in_sql`) withdrew that credit, so each one arrives
    # here to be read on its merits for the first time. Every one was read.
    # None of them was given a predicate instead, because in every case a
    # tenant predicate would break the thing the statement exists to do.
    #
    # i. the lookup that *establishes* the tenant — same class as the
    #    pre-auth group at the top of this table, reached before a request
    #    has a tenant to filter on.
    "services/api/app/auth/sso_provisioning.py::resolve_connection::aisoc_sso_connections": (
        "pre-auth: resolves which SSO connection an assertion belongs to, by (provider, issuer). "
        "The row it finds is what assigns the tenant, so filtering on a tenant would mean no "
        "federated sign-in could ever resolve one"
    ),
    "services/api/app/auth/saml_metadata.py::resolve_saml_connection::aisoc_sso_connections": (
        "pre-auth: the SP-metadata and ACS entry points resolve a connection by issuer, or by none "
        "at all on the console link, before any principal exists. LIMIT 2 so an ambiguous "
        "configuration is detected rather than silently resolved to the first row"
    ),
    "services/api/app/api/v1/endpoints/mfa.py::_principal_for_enrolment::users": (
        "pre-auth second-factor enrolment: `:u` is the subject of a signed, purpose-checked "
        "sign-in challenge (`read_challenge(..., expect_purpose='enroll')`), not a caller-supplied "
        "id. The row it reads is what assigns the tenant the enrolment is then stamped with"
    ),
    "services/api/app/api/v1/endpoints/inbox_itsm.py::_fetch_token_and_connector::tenant_inbox_tokens": (
        "the inbound ITSM webhook carries an opaque inbox token and nothing else; this lookup is "
        "what turns that token into a tenant. Same shape as the SCIM bearer-token entry above"
    ),
    # ii. read cross-tenant *in order to* enforce the tenant check.
    "services/api/app/api/v1/endpoints/inbox_itsm.py::_fetch_token_and_connector::connectors": (
        "deliberately reads the connector row without a tenant predicate so the next statement can "
        "compare `connector_row.tenant_id != token_row.tenant_id`, log a cross-tenant attempt with "
        "both ids and refuse. Scoping the SELECT would collapse that into an indistinguishable "
        "404 and lose the signal the SOC is meant to see; nothing from the row is returned to the "
        "caller before the comparison"
    ),
    # iii. an identity predicate, which is strictly narrower than a tenant.
    "services/api/app/api/v1/endpoints/mfa.py::enrolment_row::aisoc_user_mfa": (
        "keyed on user_id, which every one of its eight callers passes as the authenticated "
        "principal's own (`current_user.user_id`, `principal.user_id`, or a user id already "
        "resolved from a verified challenge). A user id is narrower than a tenant id, which this "
        "gate credits on the ORM path; the raw-SQL path cannot see it because the predicate is "
        "bound in the caller, one function away"
    ),
    # iv. a worker's working set: "which tenants", which cannot presuppose one.
    #     The same discover-then-bind shape already recorded above for
    #     hunt_scheduler.run_once and oauth_refresh._select_due_connectors.
    "services/api/app/workers/autonomy_drift.py::<module>::aisoc_autonomy_grants": (
        "the drift sweep's enumeration — SELECT DISTINCT tenant_id across granted autonomy — which "
        "is the question 'which tenants hold a grant to re-check'. Each tenant is bound "
        "individually afterwards"
    ),
    "services/api/app/workers/retention_purge.py::_load_policies::retention_policies": (
        "loads every tenant's retention policy so the purge can run each one; a tenant missing from "
        "this read is a tenant whose data is never purged, which is the compliance failure the "
        "worker exists to prevent"
    ),
    "services/api/app/workers/phishing_report_intake.py::_mailbox_connectors::connectors": (
        "the intake worker's working set of enabled mailbox connectors across tenants; ordered by "
        "tenant so the fan-out is deterministic. Each connector is then polled under its own row's "
        "tenant"
    ),
    "services/api/app/workers/shadow_reconcile.py::<module>::aisoc_shadow_mode": (
        "COUNT(DISTINCT tenant_id) of tenants in shadow mode — a fleet-wide gauge for one log "
        "line. It returns a number, never a tenant's rows"
    ),
    "services/api/app/workers/approval_expiry.py::<module>::agent_approvals": (
        "expires every tenant's stale approvals in one statement, bounded by `expires_at < now()`. "
        "This is the UPDATE beside the no-deadline count already recorded above for "
        "approval_expiry.run_once, and it was the clearest instance of the defect this rule "
        "closes: it was credited by `RETURNING id, tenant_id`, a clause that constrains nothing"
    ),
    "services/fusion/app/services/sessions.py::<module>::sessions": (
        "SELECT DISTINCT tenant_id of sessions due for expiry — the enumeration that drives the "
        "sweep, which then closes each tenant's sessions under its own id"
    ),
    "services/fusion/app/services/alert_outbox.py::claim::fusion_alert_outbox": (
        "the outbox dispatcher claims due rows across every tenant under a lease; an outbox that "
        "drained only one tenant would stall delivery for all the others. The claim is bounded by "
        "`claimed_until` and `created_at`, and each claimed row carries the tenant it is delivered "
        "under. Credited until now by `RETURNING … tenant_id`"
    ),
    "services/fusion/app/services/alert_outbox.py::backlog::fusion_alert_outbox": (
        "the depth-and-age gauge behind the outbox's health signal, grouped by tenant precisely so "
        "one tenant's backlog is attributable. GROUP BY is not a filter: it buckets rows that were "
        "already read, which is why this rule does not credit it"
    ),
    "services/fusion/app/memory/provider.py::refresh::alerts": (
        "rebuilds the per-signature prior cache for every tenant in one pass, then partitions the "
        "rows by `tenant_id` in Python and hands each tenant only its own through "
        "`get_priors(tenant_id)`. The projected tenant_id is the partition key; a per-tenant query "
        "would be one round trip per tenant on a cadence"
    ),
    "services/connectors/app/scheduler.py::_promote_overdue_findings::connectors": (
        "SELECT DISTINCT tenant_id over enabled connectors — the scheduler's tenant enumeration, "
        "and the one statement this module's docstring already named as relying on the bare-token "
        "credit. It now holds a reason instead of a regex match"
    ),
    # v. a fragment, judged at its use sites rather than here.
    "services/api/app/services/alert_source_link.py::<module>::alert_source_links": (
        "`_SELECT` is a column list and a FROM, never executed as written: every one of its four "
        "callers interpolates it into an f-string that appends `WHERE tenant_id = :tenant_id`, and "
        "this gate judges each of those four call sites independently — a fifth caller that "
        "omitted the predicate would be flagged there. Entry is keyed on this table, so an "
        "unscoped statement on any other table in this module still fails"
    ),
    # -- escalations bridge: a deployment-level pager, not a tenant channel ----
    # The opt-in ack-clock bridge (profile `escalations`) sweeps every tenant's
    # unacknowledged cases to ONE operator-configured webhook by design: it is
    # the interim transport while the native outbound-webhook emitters (which
    # do per-tenant routing) have no production callers, and it retires when
    # they are wired. The deployment-wide read is the feature, documented in
    # the service README with the multi-tenant caveat. No route handler can
    # reach these — the service has no server at all, only a polling loop.
    "services/escalations/app/bridge.py::fetch_unacked::aisoc_cases": (
        "deployment-level escalation sweep across tenants to one operator webhook; "
        "per-tenant routing is the native outbound-webhook subsystem's job, which this bridges until wired"
    ),
    "services/escalations/app/bridge.py::pipeline_health::aisoc_dead_letters": (
        "deployment-wide health count (dead letters in 24h) for the daily digest; a per-tenant count would misstate pipeline health"
    ),
    "services/escalations/app/bridge.py::pipeline_health::investigation_runs": (
        "deployment-wide health count (failed investigations in 24h) for the daily digest, same reasoning as the dead-letter count"
    ),
}

#: Raising this is a deliberate act with a diff attached. Appending to RATCHET
#: without raising it fails the gate, which is the whole point.
#:
#: 60 -> 77 when `_tenant_predicate_in_sql` replaced the bare-token match.
#: This one needs its reasoning written down, because "raise the ceiling until
#: the scan passes" is the exact move this repository forbids, and from the
#: diff alone it looks identical.
#:
#: What it is not: seventeen new unscoped queries. Not one line of
#: `services/` changed in the commit that moved this number. Those seventeen
#: statements are byte-for-byte what they were, and every one was already
#: unscoped — the gate credited them because `tenant_id` appeared *somewhere*
#: in the SQL text, which for two of them was a `RETURNING` list and for
#: eleven was a `SELECT` projection or an `ORDER BY`.
#:
#: So 60 was never a debt balance. It was the balance a broken detector could
#: see, and the seventeen were debt the whole time, carried off the books. The
#: honest number is 77, and the number of genuinely new exemptions this change
#: introduces is zero.
#:
#: The alternative — leaving the ceiling at 60 — was rejected: it fails the
#: gate on every pull request for findings no author introduced and none can
#: fix, which is how a gate gets switched off. The other alternative, giving
#: the seventeen real predicates, was rejected per statement and for a reason
#: recorded per statement: four are pre-auth lookups that a tenant predicate
#: would make unable to resolve a tenant at all, nine are worker sweeps whose
#: whole job is "every tenant", one reads cross-tenant *in order to* enforce
#: the tenant check, one is keyed on an identity narrower than a tenant, and
#: one is a fragment judged at its four call sites instead.
#:
#: 32 -> 33 for the SCIM bearer-token lookup. It belongs to the first group
#: above, the lookups that *establish* a tenant rather than operate inside one:
#: a SCIM request carries no tenant and RFC 7643 defines no attribute that
#: could carry one, so the token row is the only thing that assigns it. The
#: other seven unscoped statements the SCIM surface introduced were given real
#: predicates instead of entries here.
#:
#: 33 -> 34 (gap-closure Phase 8.1): `retro_hunt.service.opted_in_tenants`.
#: A fan-out consumer's first question is "which tenants opted in", and that
#: question cannot presuppose a tenant — the same reasoning already recorded
#: for `org_scope.resolve_portfolio_scope`, `hunt_scheduler.run_once` and
#: `oauth_refresh._select_due_connectors`, all of which discover a working set
#: and then bind each tenant before touching it. The alternative was to issue
#: the identical query as raw SQL, which would have moved it out of this
#: gate's view without changing what it reads, and that is worse than an entry
#: with a reason beside it.
#:
#: 34 -> 35 (deferral 9b): `approval_expiry.run_once`'s no-deadline count. The
#: worker expires stale approvals across every tenant and asserts an unbound
#: session before it does, so the aggregate beside it is tenant-wide for the
#: same reason. The count feeds one log line and returns no tenant's rows. It
#: was moved out of module scope to earn this entry: keyed on `<module>` the
#: waiver would have matched any later unscoped query in the same file, which
#: is an allowlist wearing a ratchet's name.
# 35 before parity 5.2, which added the approval-expiry sweep. It is the
# one statement in that feature that is cross-tenant by construction: the
# two lookups beside it (find_waiting, resolve) take a tenant and filter
# on it, because resuming another tenant's playbook run should take two
# mistakes rather than one.
# 36 -> 39 (users-administration console): the three writes/counts keyed on
# a user id the caller resolved through a tenant-scoped read above; see the
# entries' reasons. Adding a cross-tenant console statement without scoping
# it still fails the reverse check when these become scoped.
# 40 -> 42 (depth 5.2): two sweepers. `due_deliveries` is the retry queue's
# "what is due" and `report_scheduler.run_once` is "whose schedule fired" —
# both are the discover-a-working-set shape already recorded three times
# above, and both act per tenant once they have the set.
# 42 -> 43 (depth 5.3): the `wait` step's two reads, one of each shape that
# is already recorded here. `find_wait_by_token` is a credential lookup —
# the resume token is the whole credential, minted separately from the row
# id precisely so it is not guessable from anything an analyst can read, and
# a caller presenting one has no tenant to filter by; it is the same shape
# as the SCIM token and WebAuthn challenge entries above. `due_waits` is a
# sweeper discovering its working set, read-only, with `resolve` claiming
# one row at a time under a tenant. The two scoped reads beside them
# (`find_waiting`, `resolve`) do take a tenant and filter on it, so resuming
# another tenant's run still takes two mistakes rather than one.
#
# Two entries added against a ceiling that rises by one, because 42 was a
# ceiling with a spare slot in it and the list held 41. The ceiling now
# equals the list, so the next unscoped statement has to be argued for
# rather than absorbed — which is what this number is for.
# 44 -> 50 (the 2026-10-12 merge train): seven entries for depth 5.4's signed
# answer link and verification sweeper, 9.4's war-room sweep, decision route
# and worker discovery — each the credential-lookup or discover-a-working-set
# shape already recorded above, verified in code before being recorded. Four
# more cover the lake job runner's ORM statements — keyed on the model class
# (LakeQueryJob), the way every ORM entry here is keyed, which is the detail
# the first attempt got wrong: keyed on the table name they matched nothing,
# so the same four entries read as stale and the four statements as unscoped
# in one run. The policy's unbound-session arm (fixed in the same train) is
# what admits the runner's GUC-less session at the database; this entry is
# what records the query-layer decision.
# 54 -> 60 (GHSA-h4g5-39vv-pqfv): the six `services/connectors` statements this
# gate could not previously see. They are not six new exemptions earned by
# argument — they are six statements that had been exempt by accident, because
# the table they query is a SQLAlchemy Core `Table` and entity detection only
# matched declarative class names. The count going up here is the gate getting
# *stricter*: the statement that had to be fixed rather than recorded,
# `fetch_enabled_connectors` called from a request handler, is absent from the
# list because the route now uses a sibling that filters in SQL.
MAX_RATCHET = 80


# ---------------------------------------------------------------------------
# Inventory, derived from the tree
# ---------------------------------------------------------------------------


@dataclass
class Inventory:
    models: dict[str, str] = field(default_factory=dict)  # class name -> table
    #: SQLAlchemy **Core** ``Table`` objects: the variable a statement names
    #: (``connectors_table``) -> the table it maps (``connectors``). Kept
    #: separate from ``models`` because the two are discovered differently and
    #: reporting which one matched is what makes a finding checkable.
    core_tables: dict[str, str] = field(default_factory=dict)
    tables: set[str] = field(default_factory=set)  # tables with a tenant_id column
    rls_tables: set[str] = field(default_factory=set)  # tables with an RLS policy

    def entities(self) -> set[str]:
        """Every name a statement can use to reach a tenant-scoped table."""
        return set(self.models) | set(self.core_tables)

    def table_for(self, entity: str) -> str:
        return self.models.get(entity) or self.core_tables.get(entity, entity)


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

        # SQLAlchemy **Core** tables, which the declarative scan above cannot
        # see because they are an assignment rather than a class.
        #
        # This was a hole wide enough to drive a cross-tenant credential read
        # through. `services/connectors` addresses the `connectors` table as
        # `connectors_table = Table("connectors", metadata, Column(...))` and
        # queries it as `select(connectors_table.c.id, ...)`. The entity match
        # below is against *names appearing inside the select()*, and that name
        # is `connectors_table` — which was in neither `models` nor `tables`,
        # so six statements in that file, including the unscoped read behind
        # GHSA-h4g5-39vv-pqfv, were skipped before any predicate was examined.
        # The gate printed OK over the whole service: not because it excluded
        # it, but because it could not see a single one of its queries.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            call = node.value
            if not (isinstance(target, ast.Name) and isinstance(call, ast.Call)):
                continue
            func = call.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name != "Table" or not call.args:
                continue
            first = call.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            # Only a table that declares a tenant column, matching the rule
            # the declarative branch applies. A Core table without one is not
            # tenant-scoped and nothing here should claim it is.
            declares_tenant = any(
                isinstance(arg, ast.Call)
                and (getattr(arg.func, "id", None) or getattr(arg.func, "attr", None)) == "Column"
                and arg.args
                and isinstance(arg.args[0], ast.Constant)
                and arg.args[0].value == "tenant_id"
                for arg in call.args
            )
            if declares_tenant:
                inv.core_tables[target.id] = first.value

    # Four services manage their own schema through alembic rather than this
    # chain of .sql files, so a glob that only saw the latter reported their
    # twelve tenant-scoped tables as unprotected however many policies they
    # carried. The regexes below are applied to the revision text unchanged —
    # which is why those revisions spell each ALTER TABLE out rather than
    # looping over a tuple of names.
    schema_files = [
        *root.glob("services/*/migrations/*.sql"),
        *root.glob("services/*/alembic/versions/*.py"),
        *root.glob("services/*/app/db/versions/*.py"),
    ]
    for sql in sorted(schema_files):
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
    inv.tables |= {t for t in inv.core_tables.values() if t}
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


def _module_functions(tree: ast.AST) -> dict[str, ast.AST]:
    """name → definition, for functions defined in this module."""
    return {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}


def _transfers_control(body: list[ast.stmt]) -> bool:
    """Does this block stop execution reaching what follows it?

    Approximate on purpose, and approximate in the safe direction: a block
    containing ``raise``/``return``/``continue``/``break`` anywhere counts as
    exiting. The alternative — full reachability analysis — buys nothing here,
    because the shape being told apart is a handler that *only* logs.
    """
    for node in body:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Raise | ast.Return | ast.Continue | ast.Break):
                return True
    return False


def _guard_enforces(fn: ast.AST, call: ast.Call, parents: dict[ast.AST, ast.AST], module_fns: dict[str, ast.AST]) -> bool:
    """Can execution reach the query when this guard did *not* find the row?

    This is the difference between a guard and a log line, and it is the one
    thing the old rule could not see. It credited any call that received the
    caller's tenant, so::

        case = await _load_case(db, case_id, user.tenant_id)
        if case is None:
            logger.warning("case %s not found", case_id)   # and carries on
        ...
        await db.execute(text("SELECT ... FROM aisoc_cases WHERE id = :cid"))

    read exactly like ``investigations.py``'s ``_fetch_run``, which 404s. The
    real instance of the fail-soft shape in this tree was caught only because
    its unscoped query sat in a different function; written inline it would
    have been credited.

    Three cases, in order, and the undecidable remainder is refused rather
    than guessed:

    1. The result is bound and tested. Then the answer is *visible*: if no
       branch testing it transfers control out, the guard demonstrably
       continues on failure and earns no credit. This is the decidable core.
    2. The result is not tested. Then the guard's contract must be to raise,
       which is answerable when the callee is defined in this module — the
       same "resolve it by what it wraps" move that found the aliased
       playbook-execute route. A callee whose body contains no ``raise``
       cannot be enforcing.
    3. The callee is not resolvable here (imported, a method, an attribute
       call). Undecidable, so **not credited** — the statement becomes a
       finding and needs a ratchet entry naming why. Refusing to guess is the
       narrowing; the previous rule guessed yes.
    """
    bound: str | None = None
    node: ast.AST = call
    while True:
        parent = parents.get(node)
        if parent is None:
            break
        if isinstance(parent, ast.Await):
            node = parent
            continue
        if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
            bound = parent.targets[0].id
        break

    if bound is not None:
        tests = [n for n in ast.walk(fn) if isinstance(n, ast.If) and bound in _names(n.test)]
        if tests:
            # Credited only if some branch that inspects the result leaves.
            return any(_transfers_control(t.body) or _transfers_control(t.orelse) for t in tests)

    func = call.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    callee = module_fns.get(name) if name else None
    if callee is None:
        return False
    return any(isinstance(n, ast.Raise) for n in ast.walk(callee))


def _tenant_validated_keys(
    fn: ast.AST,
    auth_names: set[str],
    parents: dict[ast.AST, ast.AST],
    module_fns: dict[str, ast.AST],
) -> set[str]:
    """Keys this function already validated against the caller's tenant.

    ``investigations.py`` never puts a tenant on the child queries, and is
    right not to: it calls ``_fetch_run(db, run_id, current_user.tenant_id)``
    first, which 404s a run belonging to anybody else, and only then reads
    ``investigation_events`` by that verified ``run_id``. The row is addressed
    by a key the caller's tenant was checked against, which is the property —
    not the literal presence of a ``tenant_id`` column in the predicate.

    So: find calls that receive the principal's own tenant, keep only those
    whose failure actually stops execution (see :func:`_guard_enforces`), and
    treat the other plain-name arguments of *those* calls as validated. The
    link is explicit — the statement only gets credit if its predicate names
    one of those keys.
    """
    validated: set[str] = set()
    if not auth_names:
        return validated

    # A guard is handed the session as well as the key, and for raw SQL the
    # statement's resolved name set contains the session too (`db.execute(...)`
    # is part of the expression). So `db` satisfied `keys & resolved` and every
    # raw statement in a function that called *any* tenant-carrying guard was
    # credited, whatever it was actually keyed on — a query on an unrelated id
    # sailed through. Found by probing what the rule credits rather than what
    # it flags.
    #
    # Excluded structurally by what the name is used *as*: a session is the
    # receiver of a call, a row key is not. Naming `db` / `session` / `conn`
    # would be the hand-written vocabulary this file exists to avoid.
    receivers = {
        node.func.value.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
    }

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
        if not _guard_enforces(fn, node, parents, module_fns):
            continue
        for expr in [*node.args, *[kw.value for kw in node.keywords]]:
            if isinstance(expr, ast.Name) and expr.id not in receivers:
                validated.add(expr.id)
    return validated


def _rls_context_setters(tree: ast.AST) -> set[str]:
    """Functions that bind a connection to one tenant via the Postgres GUC.

    Four statements in this tree are scoped by an RLS context set on the
    connection rather than by a predicate in the SQL — the agents ledger's
    ``complete_run`` and ``persist_auto_triage``, and the two retention purge
    SQL builders. They are correct, and the gate could not see it, so all four
    sat on the ratchet describing a mechanism instead of a defect.

    Detected by what the function *does* — executes a statement naming
    ``app.current_tenant_id`` and takes a tenant — not by being called
    ``_set_rls_context``. A hand-written vocabulary of helper names is the
    thing that made an aliased ``ExecuteUser`` read as anonymous.
    """
    setters: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = {a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]}
        if not any("tenant" in p for p in params):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and RLS_SESSION_VARIABLE in sub.value:
                setters.add(node.name)
                break
    return setters


def _binds_rls_context(fn: ast.AST | None, setters: set[str]) -> bool:
    """Does this function bind the connection to a tenant before querying?

    The call must carry something tenant-shaped: ``_set_rls_context(conn)``
    with no tenant is not a scope, and crediting it would turn the rule into
    "mentions a helper".
    """
    if fn is None or not setters:
        return False
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name not in setters:
            continue
        args = _names(ast.Tuple(elts=[*node.args, *[kw.value for kw in node.keywords]], ctx=ast.Load()))
        if any("tenant" in a for a in args):
            return True
    return False


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
    #: Scoped by an RLS context bound on the connection rather than by a
    #: predicate. Not a finding, but counted and reported, because the credit
    #: is conditional on the deployment connecting as a role that does not
    #: bypass RLS — see ``apps/docs/docs/operations/security.md``.
    via_rls_context: bool = False

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
) -> tuple[list[Finding], int, int]:
    helpers = _scoping_helpers(tree)
    module_fns = _module_functions(tree)
    setters = _rls_context_setters(tree)
    findings: list[Finding] = []
    total = 0
    rls_scoped = 0

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in STATEMENT_FUNCS):
            continue
        entities: set[str] = set()
        known = inv.entities()
        for arg in node.args:
            entities |= _names(arg) & known
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
        if fn is not None and (_tenant_validated_keys(fn, auth_names, parents, module_fns) & resolved):
            continue

        table = inv.table_for(entity)
        # Scoped by an RLS context on the connection. Only counts on a table
        # that actually carries a policy: setting the GUC against a table with
        # no policy scopes nothing at all.
        if table in inv.rls_tables and _binds_rls_context(fn, setters):
            rls_scoped += 1
            continue
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
    return findings, total, rls_scoped


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
) -> tuple[list[Finding], int, int]:
    docstrings = _docstring_nodes(tree)
    module_fns = _module_functions(tree)
    setters = _rls_context_setters(tree)
    findings: list[Finding] = []
    total = 0
    rls_scoped = 0
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

        if _tenant_predicate_in_sql(blob):
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
        # `_names` collects string *constants* as well as identifiers, so the
        # statement's own SQL comes back round in `resolved` and a bare token
        # test here silently re-grants the credit the clause rule above just
        # withheld. Measured: that defeated the clause rule on 14 of the 17
        # statements it had correctly demoted. Same rule, both places.
        if any(_tenant_predicate_in_sql(r) for r in resolved) or (resolved & TENANT_TOKENS):
            continue
        auth_names = _auth_bound_names(fn) if fn is not None else set()
        if auth_names & names:
            continue
        if fn is not None and (_tenant_validated_keys(fn, auth_names, parents, module_fns) & resolved):
            continue
        # Scoped by an RLS context on the connection rather than by anything
        # visible in the SQL. Only on a table that carries a policy.
        if table in inv.rls_tables and _binds_rls_context(fn, setters):
            rls_scoped += 1
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
    return findings, total, rls_scoped


# ---------------------------------------------------------------------------
# Route reachability
# ---------------------------------------------------------------------------
#
# Why a second arm exists at all
# ------------------------------
# The ratchet exempts a *statement*, and a statement has no opinion about who
# calls it. That is the gap GHSA-h4g5-39vv-pqfv went through, and it is worth
# stating exactly, because the obvious reading of the advisory is wrong:
# `services/connectors` was never excluded from this scan, and adding the
# Core-table rule above does not catch the vulnerability either. Measured: with
# that rule alone the gate reports OK on the vulnerable tree, because
# `fetch_enabled_connectors` is a legitimate cross-tenant sweep and is
# correctly ratcheted as one — while a *request handler* was calling it.
#
# "The scheduler legitimately iterates every tenant; a request handler does
# not" is the whole rule. A sweep's exemption is earned by there being no
# caller whose tenant it could have filtered on, so the exemption evaporates
# the moment an HTTP route reaches it — and nothing noticed, because both
# halves looked correct in isolation.
#
# Measured on `main`: 39 handler -> unscoped-statement pairs, every one of them
# a pre-auth credential lookup, a deliberately cross-tenant admin surface or an
# opaque-capability read that is *designed* to be called from a request. The
# vulnerable tree had 40. The fortieth is the finding.

#: Decorator attributes that mark an HTTP route handler.
ROUTE_DECORATOR_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

#: Handlers that may reach a cross-tenant statement, and why *a request* may.
#:
#: Distinct from ``RATCHET``, which says why the statement needs no predicate.
#: These two questions came apart in GHSA-h4g5-39vv-pqfv and the entry has to
#: answer the second one: not "why is this query unscoped" but "why is it
#: correct for an HTTP caller to reach it". Every pair below was read before it
#: was recorded, and they fall into four shapes that are all *designed* for a
#: request — unlike a sweep, whose exemption exists precisely because no
#: request reaches it.
#: Shorthands so a key fits a line. The gate compares whole keys, so these are
#: joined back into exactly the paths `scan_route_reachability` emits.
_EP = "services/api/app/api/v1/endpoints"
_SV = "services/api/app/services"
_AU = "services/api/app/auth"
_OSQ = "services/osquery-tls/app"

ROUTE_REACHABLE: dict[str, str] = {
    # -- pre-auth: the lookup that assigns the tenant ------------------------
    f"{_EP}/auth.py::login -> {_EP}/auth.py::login": ("sign-in by email: there is no tenant yet, and this query is what resolves one"),
    f"{_EP}/auth.py::refresh_token -> {_EP}/auth.py::refresh_token": (
        "refresh presents a signed token, not a tenant; the row it names assigns one"
    ),
    f"{_EP}/passkeys.py::passkey_authenticate_begin -> {_EP}/passkeys.py::passkey_authenticate_begin": (
        "pre-auth WebAuthn: resolves who is signing in from the email they typed"
    ),
    f"{_EP}/passkeys.py::passkey_authenticate_finish -> {_EP}/passkeys.py::passkey_authenticate_finish": (
        "pre-auth WebAuthn: the owner of the verified credential is what assigns the tenant"
    ),
    f"{_EP}/passkeys.py::passkey_authenticate_finish -> {_EP}/passkeys.py::_consume_challenge": (
        "single-use WebAuthn challenge matched on its own high-entropy value, before any session exists"
    ),
    f"{_EP}/passkeys.py::passkey_register_finish -> {_EP}/passkeys.py::_consume_challenge": (
        "the same single-use challenge, on the registration leg"
    ),
    f"{_EP}/mfa.py::webauthn_verify -> {_EP}/passkeys.py::_consume_challenge": (
        "the same single-use challenge, reused by the step-up verifier"
    ),
    f"{_EP}/oauth.py::oauth_callback -> {_EP}/oauth.py::oauth_callback": (
        "matched on the 32-byte single-use state nonce, which is itself the credential"
    ),
    # -- the row is addressed by an opaque capability and yields its own tenant
    "services/honeytokens/app/api/routes.py::webhook_trigger -> services/honeytokens/app/api/routes.py::webhook_trigger": (
        "canary callback: the token id is the capability and the row supplies its own tenant; "
        "the caller is whoever tripped the token and holds no session"
    ),
    f"{_OSQ}/api/v1/endpoints/config.py::get_config -> {_OSQ}/services/node_registry.py::mark_seen": (
        "node_key is the agent's enrolment credential; the heartbeat writes the row that key resolved"
    ),
    f"{_OSQ}/api/v1/endpoints/distributed_read.py::distributed_read -> {_OSQ}/services/node_registry.py::mark_seen": (
        "the same node_key heartbeat, on the distributed-read leg"
    ),
    f"{_OSQ}/api/v1/endpoints/distributed_write.py::distributed_write -> {_OSQ}/services/node_registry.py::mark_seen": (
        "the same node_key heartbeat, on the distributed-write leg"
    ),
    f"{_OSQ}/api/v1/endpoints/log.py::log -> {_OSQ}/services/node_registry.py::mark_seen": (
        "the same node_key heartbeat, on the log-submission leg"
    ),
    f"{_EP}/replay.py::get_public_replay -> {_EP}/replay.py::get_public_replay": (
        "a published replay is deliberately public; the slug is the capability"
    ),
    f"{_EP}/war_rooms.py::channel_decision -> {_EP}/war_rooms.py::channel_decision": (
        "the chat bot presents the shared service token and a war-room id, holds no tenant, and the "
        "handler binds the RLS context to the row's own tenant before acting"
    ),
    # -- cross-tenant by design, behind an administrative permission ---------
    f"{_EP}/tenants.py::create_user -> {_EP}/tenants.py::create_user": (
        "platform-admin provisioning: creates users across tenants by design"
    ),
    f"{_EP}/tenants.py::update_user -> {_EP}/tenants.py::update_user": (
        "platform-admin user administration, authorised by the admin role rather than a tenant"
    ),
    f"{_EP}/rbac.py::set_primary_role -> {_EP}/rbac.py::set_primary_role": (
        "mirrors the granted role onto a user id this endpoint already validated against the caller's tenant"
    ),
    f"{_EP}/usage.py::export_organization_month -> {_SV}/org_scope.py::resolve_portfolio_scope": (
        "the MSSP portfolio resolver answers 'which tenants may this operator see', so it cannot "
        "presuppose one; it is bounded by org_id + user_id"
    ),
    f"{_EP}/mssp.py::list_effective_rules_for_child -> {_SV}/mssp_rule_resolver.py::resolve_effective_rules": (
        "MSSP rule packs are cross-tenant by construction, bounded by a pack_id from the verified portfolio"
    ),
    f"{_EP}/mssp.py::count_effective_rules_for_child -> {_SV}/mssp_rule_resolver.py::resolve_effective_rules": (
        "the count beside the list above, same bound"
    ),
    f"{_EP}/detection_rules.py::hunt -> {_SV}/mssp_rule_resolver.py::resolve_effective_rules": (
        "resolves the effective rule set for the caller's own tenant through the same portfolio bound"
    ),
    f"{_EP}/replay.py::publish_replay -> {_EP}/replay.py::_unique_slug": (
        "slug-collision probe across all replays; a tenant-scoped check would mint duplicate public slugs"
    ),
    # -- the handler validated the key against the caller's tenant first -----
    f"{_EP}/war_rooms.py::sync -> {_SV}/war_room.py::sync_war_room": (
        "the handler loads the room WHERE id = :id AND tenant_id = :tenant_id, 404s on a miss and "
        "passes current_user.tenant_id in, so the sweep function is reached only with a room this "
        "request already proved it owns"
    ),
    f"{_EP}/investigations.py::get_run -> {_EP}/investigations.py::_fetch_model_costs": (
        "costs are keyed on a run_id that _fetch_run already checked against the caller's tenant"
    ),
    f"{_EP}/admin_users.py::delete_user -> {_EP}/admin_users.py::_end_sessions": (
        "keyed on a user id that came out of this module's tenant-scoped SELECT earlier in the request"
    ),
    f"{_EP}/admin_users.py::delete_user -> {_EP}/admin_users.py::_guard_last_admin": (
        "counts admins holding that already-validated user's roles, and only ever denies the operation"
    ),
    f"{_EP}/admin_users.py::patch_status -> {_EP}/admin_users.py::_end_sessions": "same validated user id, status leg",
    f"{_EP}/admin_users.py::patch_status -> {_EP}/admin_users.py::_guard_last_admin": "same last-admin guard, status leg",
    f"{_EP}/admin_users.py::add_role -> {_EP}/admin_users.py::_end_sessions": "same validated user id, role-grant leg",
    f"{_EP}/admin_users.py::remove_role -> {_EP}/admin_users.py::_end_sessions": "same validated user id, role-revoke leg",
    f"{_EP}/admin_users.py::remove_role -> {_EP}/admin_users.py::_guard_last_admin": "same last-admin guard, role-revoke leg",
    f"{_EP}/admin_users.py::set_roles -> {_EP}/admin_users.py::_end_sessions": "same validated user id, role-replace leg",
    f"{_EP}/admin_users.py::set_roles -> {_EP}/admin_users.py::_guard_last_admin": "same last-admin guard, role-replace leg",
    # -- pre-auth: the request has no tenant yet, which is why it is here ----
    # Twelve pairs that appeared together when `_tenant_predicate_in_sql`
    # withdrew the bare-token credit from the four statements behind them.
    # They are the first of this table's four shapes and the least ambiguous
    # one: a handler cannot filter on a tenant it has not been assigned, and
    # each of these statements is the thing that assigns it.
    f"{_AU}/oidc.py::oidc_callback -> {_AU}/sso_provisioning.py::resolve_connection": (
        "the OIDC callback arrives with an authorization code and an issuer, not a session; the "
        "connection row it resolves is what names the tenant the user is provisioned into"
    ),
    f"{_AU}/saml.py::saml_acs -> {_AU}/sso_provisioning.py::resolve_connection": (
        "the SAML assertion consumer service, same reasoning as the OIDC callback: unauthenticated "
        "by construction, and the resolved connection is what assigns the tenant"
    ),
    f"{_AU}/saml.py::saml_acs -> {_AU}/saml_metadata.py::resolve_saml_connection": (
        "the ACS resolves the connection a second time by the assertion's issuer in order to load "
        "the signing certificate it must verify against, before anything in the assertion is trusted"
    ),
    f"{_AU}/saml.py::saml_login -> {_AU}/saml_metadata.py::resolve_saml_connection": (
        "SP-initiated sign-in: the console link carries no issuer and no principal, so this is the "
        "lookup that decides which IdP to redirect to"
    ),
    f"{_AU}/saml.py::saml_logout -> {_AU}/saml_metadata.py::resolve_saml_connection": (
        "single logout is reached with the session already being torn down and must resolve the "
        "same connection to validate the LogoutRequest's signature"
    ),
    f"{_EP}/inbox_itsm.py::inbound_itsm_webhook -> {_EP}/inbox_itsm.py::_fetch_token_and_connector": (
        "the vendor's ITSM webhook authenticates with an opaque inbox token and nothing else. The "
        "helper is the tenant resolution step, and its second statement is deliberately "
        "cross-tenant so a token from one tenant aimed at another tenant's connector is detected "
        "and logged rather than silently 404'd"
    ),
    f"{_EP}/auth.py::login -> {_EP}/mfa.py::enrolment_row": (
        "sign-in asks whether the user it has just resolved holds a second factor, keyed on that "
        "user's own id. A tenant predicate would add nothing: user_id is the narrower key"
    ),
    f"{_EP}/mfa.py::mfa_status -> {_EP}/mfa.py::enrolment_row": "reads current_user.user_id's own enrolment",
    f"{_EP}/mfa.py::enroll_begin -> {_EP}/mfa.py::enrolment_row": "same, enrolment leg: principal.user_id only",
    f"{_EP}/mfa.py::enroll_confirm -> {_EP}/mfa.py::enrolment_row": "same, confirmation leg: principal.user_id only",
    f"{_EP}/mfa.py::verify -> {_EP}/mfa.py::enrolment_row": (
        "second-factor verification during sign-in, keyed on the user id carried by the signed sign-in challenge the caller presented"
    ),
    f"{_EP}/mfa.py::disable -> {_EP}/mfa.py::enrolment_row": "same, disable leg: current_user.user_id only",
}

#: Shrink-only, exactly like MAX_RATCHET. 34 is what `main` measured once the
#: fixed route stopped reaching the scheduler's sweep; the vulnerable tree
#: measured 35.
#: 34 -> 46 alongside MAX_RATCHET's 60 -> 77 and for the same reason: the
#: twelve pairs added were not reachable-by-a-request findings that appeared,
#: they are pairs that became *visible* when the four statements behind them
#: stopped being credited by a token in a projection. All twelve are pre-auth
#: routes, the shape whose exemption is strongest, and no handler changed.
MAX_ROUTE_REACHABLE = 46

#: How far to follow calls out of a handler. Four frames covers
#: handler -> service -> repository with room to spare.
_REACH_DEPTH = 4


@dataclass(frozen=True)
class ReachFinding:
    handler_path: str
    handler: str
    target_path: str
    target: str

    @property
    def key(self) -> str:
        return f"{self.handler_path}::{self.handler} -> {self.target_path}::{self.target}"


def _module_to_path(module: str, service: str) -> str | None:
    """``app.db.connector_repo`` in service ``connectors`` -> its file path.

    Resolution is by import rather than by bare name on purpose. A pass that
    matched any function of the same name anywhere in the service reported
    ``saml_login -> auth.login`` and ``identity_context_for_triage ->
    bootstrap_admin.bootstrap``: two name collisions, neither a call. A gate
    that invents findings gets switched off, which costs more than the gate
    was worth.
    """
    if not module.startswith("app"):
        return None
    return f"services/{service}/{module.replace('.', '/')}.py"


def _imported_names(tree: ast.AST, rel: str, service: str) -> dict[str, str]:
    """``local name -> defining module's path``, for ``from app.x import y``."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.level or not node.module:
            continue
        path = _module_to_path(node.module, service)
        if path is None:
            continue
        for alias in node.names:
            out[alias.asname or alias.name] = path
    return out


def scan_route_reachability(root: Path, findings: list[Finding]) -> list[ReachFinding]:
    """Handlers that reach a function owning a statement with no tenant predicate."""
    unscoped = {(f.path, f.function) for f in findings}
    if not unscoped:
        return []

    defined: set[tuple[str, str]] = set()
    called: dict[tuple[str, str], set[str]] = {}
    imports: dict[str, dict[str, str]] = {}
    handlers: list[tuple[str, str, str]] = []  # (path, name, service)

    for py in _python_files(root):
        rel = py.relative_to(root).as_posix()
        if not rel.startswith("services/"):
            continue
        service = rel.split("/")[1]
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        imports[rel] = _imported_names(tree, rel, service)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            defined.add((rel, node.name))
            names: set[str] = set()
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
                if name:
                    names.add(name)
            called[(rel, node.name)] = names
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute) and deco.func.attr in ROUTE_DECORATOR_METHODS:
                    handlers.append((rel, node.name, service))
                    break

    def resolve(name: str, from_path: str) -> tuple[str, str] | None:
        if (from_path, name) in defined:
            return (from_path, name)
        target = imports.get(from_path, {}).get(name)
        if target is not None and (target, name) in defined:
            return (target, name)
        return None

    out: list[ReachFinding] = []
    for path, handler, _service in handlers:
        seen: set[tuple[str, str]] = set()
        frontier = [(path, handler)]
        for _ in range(_REACH_DEPTH):
            nxt: list[tuple[str, str]] = []
            for node_key in frontier:
                if node_key in seen:
                    continue
                seen.add(node_key)
                if node_key in unscoped:
                    out.append(ReachFinding(path, handler, node_key[0], node_key[1]))
                for name in called.get(node_key, ()):
                    resolved = resolve(name, node_key[0])
                    if resolved is not None and resolved not in seen:
                        nxt.append(resolved)
            frontier = nxt
            if not frontier:
                break
    return sorted(set(out), key=lambda r: r.key)


@dataclass
class ScanResult:
    findings: list[Finding]
    inventory: Inventory
    files: int
    statements: int
    #: Statements credited because the connection carries an RLS context.
    #: Reported on every run rather than folded silently into "scoped": the
    #: credit holds only where the deployment connects as a role that does not
    #: bypass RLS. That was false of every shipped surface until
    #: 061_runtime_app_role.sql and is true of all of them now, which is a
    #: property of the deployment rather than of this tree — so it stays a
    #: separate number instead of being folded into "scoped".
    rls_scoped: int

    def __iter__(self):
        """Unpack as the 4-tuple the older call sites expect."""
        return iter((self.findings, self.inventory, self.files, self.statements))


def scan(root: Path | None = None) -> ScanResult:
    base = root or REPO_ROOT
    inv = build_inventory(base)
    findings: list[Finding] = []
    files = 0
    statements = 0
    rls_scoped = 0

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

        orm, n_orm, rls_orm = _scan_orm(tree, inv, service=service, rel=rel, parents=parents, fn_of=fn_of)
        sql, n_sql, rls_sql = _scan_sql(tree, inv, service=service, rel=rel, parents=parents, fn_of=fn_of)
        findings.extend(orm)
        findings.extend(sql)
        statements += n_orm + n_sql
        rls_scoped += rls_orm + rls_sql

    return ScanResult(findings, inv, files, statements, rls_scoped)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def partition(findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    """Return (unratcheted findings, stale ratchet keys)."""
    seen_keys = {f.key for f in findings}
    unratcheted = [f for f in findings if f.key not in RATCHET]
    stale = sorted(k for k in RATCHET if k not in seen_keys)
    return unratcheted, stale


def partition_reach(reach: list[ReachFinding]) -> tuple[list[ReachFinding], list[str]]:
    """Return (unallowed handler->statement pairs, stale allowlist keys).

    Both directions, for the same reason the statement ratchet runs both: an
    entry whose pair has gone — the handler stopped calling it, or the
    statement gained a predicate — is a justification that has lapsed, and one
    that keeps passing reads like a decision somebody made.
    """
    seen = {r.key for r in reach}
    unallowed = [r for r in reach if r.key not in ROUTE_REACHABLE]
    stale = sorted(k for k in ROUTE_REACHABLE if k not in seen)
    return unallowed, stale


def _print_inventory(findings: list[Finding], inv: Inventory, files: int, statements: int, rls_scoped: int = 0) -> None:
    print(f"Tenant-predicate inventory — scanned {files} files under {SERVICES_DIR}")
    print(f"  tenant-scoped ORM models : {len(inv.models)}")
    print(f"  tenant-scoped tables     : {len(inv.tables)}")
    print(f"  of those, RLS-covered    : {len(inv.tables & inv.rls_tables)}  (the rest have query-layer scoping only)")
    print(f"  statements examined      : {statements}")
    print(f"  scoped by RLS context    : {rls_scoped}  (holds where DATABASE_URL is the DML-only runtime role, which is now the default)")
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

# ── where `tenant_id` sits, one probe per clause the dialect offers ────────
#
# The rule this exercises is `_tenant_predicate_in_sql`. A sibling gate in this
# tree printed OK over four real violations because its detector knew two
# syntaxes out of five, so these are written per *clause* rather than per
# instance found on `main`: every clause a tenant column can legally appear in
# gets a probe, on whichever side of the rule it belongs.
#
# Must be FLAGGED — the token is there and constrains nothing.

_SQL_TENANT_IN_RETURNING = """
from sqlalchemy import text

async def expire(db):
    return await db.execute(text(
        "UPDATE widgets SET status = 'expired' WHERE expires_at < now() RETURNING id, tenant_id"
    ))
"""

_SQL_TENANT_IN_PROJECTION = """
from sqlalchemy import text

async def get_widget(widget_id, db):
    return await db.execute(text(
        "SELECT id, tenant_id, secret FROM widgets WHERE id = :id"
    ).bindparams(id=widget_id))
"""

_SQL_TENANT_IN_ORDER_BY = """
from sqlalchemy import text

async def all_widgets(db):
    return await db.execute(text("SELECT id, secret FROM widgets ORDER BY tenant_id"))
"""

_SQL_TENANT_IN_GROUP_BY = """
from sqlalchemy import text

async def depth(db):
    return await db.execute(text("SELECT count(*) FROM widgets GROUP BY tenant_id"))
"""

_SQL_TENANT_IN_COMMENT = """
from sqlalchemy import text

async def get_widget(widget_id, db):
    return await db.execute(text(
        "SELECT id FROM widgets -- callers must pass tenant_id\\n WHERE id = :id"
    ).bindparams(id=widget_id))
"""

_SQL_TENANT_IN_BLOCK_COMMENT = """
from sqlalchemy import text

async def get_widget(widget_id, db):
    return await db.execute(text(
        "SELECT id FROM widgets /* tenant_id is applied by RLS */ WHERE id = :id"
    ).bindparams(id=widget_id))
"""

_SQL_TENANT_IN_UPDATE_SET = """
from sqlalchemy import text

async def reassign(widget_id, new_tenant, db):
    return await db.execute(text(
        "UPDATE widgets SET tenant_id = :t WHERE id = :id"
    ).bindparams(t=new_tenant, id=widget_id))
"""

# Must PASS — the token constrains which rows are read or written.

_SQL_TENANT_IN_WHERE = """
from sqlalchemy import text

async def get_widget(widget_id, db):
    return await db.execute(text(
        "SELECT id, secret FROM widgets WHERE id = :id AND tenant_id = :t"
    ).bindparams(id=widget_id, t="x"))
"""

_SQL_TENANT_IN_JOIN_ON = """
from sqlalchemy import text

async def joined(db):
    return await db.execute(text(
        "SELECT w.id FROM widgets w JOIN gadgets g ON g.tenant_id = w.tenant_id WHERE w.id = :id"
    ).bindparams(id="x"))
"""

_SQL_TENANT_IN_USING = """
from sqlalchemy import text

async def joined(db):
    return await db.execute(text("SELECT w.id FROM widgets w JOIN gadgets USING (tenant_id)"))
"""

_SQL_TENANT_IN_HAVING = """
from sqlalchemy import text

async def noisy(db):
    return await db.execute(text(
        "SELECT count(*) FROM widgets GROUP BY kind HAVING tenant_id = :t"
    ).bindparams(t="x"))
"""

_SQL_TENANT_IN_INSERT_COLUMNS = """
from sqlalchemy import text

async def add(db):
    return await db.execute(text(
        "INSERT INTO widgets (id, tenant_id, secret) VALUES (:id, :t, :s) RETURNING id"
    ).bindparams(id="i", t="x", s="s"))
"""

_SQL_TENANT_IN_ON_CONFLICT = """
from sqlalchemy import text

async def upsert(db):
    return await db.execute(text(
        "INSERT INTO widgets (id, secret) VALUES (:id, :s) "
        "ON CONFLICT (tenant_id, id) DO UPDATE SET secret = EXCLUDED.secret"
    ).bindparams(id="i", s="s"))
"""

_SQL_TENANT_IN_SUBQUERY_WHERE = """
from sqlalchemy import text

async def claim(db):
    return await db.execute(text(
        "UPDATE widgets SET claimed = true WHERE id IN ("
        "  SELECT id FROM widgets WHERE tenant_id = :t LIMIT 10) RETURNING id"
    ).bindparams(t="x"))
"""

_SQL_TENANT_IN_CTE = """
from sqlalchemy import text

async def recent(db):
    return await db.execute(text(
        "WITH mine AS (SELECT id FROM widgets WHERE tenant_id = :t) "
        "SELECT id FROM mine"
    ).bindparams(t="x"))
"""

_SQL_TENANT_CAST_THEN_COMPARED = """
from sqlalchemy import text

async def get_widget(db):
    return await db.execute(text("SELECT id FROM widgets WHERE tenant_id::uuid = $1"))
"""

# The two ways a predicate arrives from outside the string the scanner reads.
# Both land on `_tenant_predicate_in_sql`, by different routes: the f-string
# flattens into one blob carrying its own WHERE, while the appended fragment
# has no clause keyword at all and is credited only because the token is one
# side of a comparison. The second is the branch a clause-position rule would
# otherwise get wrong, and it is how `alert_source_link.py`'s four call sites
# are written.
_SQL_TENANT_VIA_FSTRING = """
from sqlalchemy import text

_COLUMNS = "SELECT id, secret"

async def get_widget(widget_id, tenant, db):
    return await db.execute(
        text(f"{_COLUMNS} FROM widgets WHERE tenant_id = :t AND id = :id").bindparams(t=tenant, id=widget_id)
    )
"""

_SQL_TENANT_VIA_APPENDED_FRAGMENT = """
from sqlalchemy import text

async def get_widget(widget_id, tenant, db):
    sql = "SELECT id, secret FROM widgets WHERE id = :id"
    sql += " AND tenant_id = :t"
    return await db.execute(text(sql).bindparams(id=widget_id, t=tenant))
"""

#: The fragment branch must not become a blanket pass: a fragment that merely
#: *names* the column, as an appended projection would, still credits nothing.
_SQL_FRAGMENT_NAMES_BUT_DOES_NOT_COMPARE = """
from sqlalchemy import text

async def get_widget(widget_id, db):
    sql = "SELECT id FROM widgets WHERE id = :id"
    sql += " ORDER BY tenant_id"
    return await db.execute(text(sql).bindparams(id=widget_id))
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

_GUARD_THAT_RAISES = """
from typing import Annotated
from sqlalchemy import select
from app.api.v1.deps import AuthUser
from app.models.widget import Widget

async def _fetch_widget(db, widget_id, tenant_id):
    row = (await db.execute(select(Widget).where(Widget.id == widget_id, Widget.tenant_id == tenant_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404)
    return row

async def read_parts(widget_id, user: AuthUser, db):
    await _fetch_widget(db, widget_id, user.tenant_id)
    return await db.execute(select(Widget).where(Widget.id == widget_id))
"""

_GUARD_THAT_FAILS_SOFT = """
from typing import Annotated
from sqlalchemy import select
from app.api.v1.deps import AuthUser
from app.models.widget import Widget

async def _find_widget(db, widget_id, tenant_id):
    return (await db.execute(select(Widget).where(Widget.id == widget_id, Widget.tenant_id == tenant_id))).scalar_one_or_none()

async def read_parts(widget_id, user: AuthUser, db):
    owned = await _find_widget(db, widget_id, user.tenant_id)
    if owned is None:
        logger.warning("widget %s not found for this tenant", widget_id)
    return await db.execute(select(Widget).where(Widget.id == widget_id))
"""

_GUARD_TESTED_AND_RAISES = """
from typing import Annotated
from sqlalchemy import select
from app.api.v1.deps import AuthUser
from app.models.widget import Widget

async def _find_widget(db, widget_id, tenant_id):
    return (await db.execute(select(Widget).where(Widget.id == widget_id, Widget.tenant_id == tenant_id))).scalar_one_or_none()

async def read_parts(widget_id, user: AuthUser, db):
    owned = await _find_widget(db, widget_id, user.tenant_id)
    if owned is None:
        raise HTTPException(status_code=404)
    return await db.execute(select(Widget).where(Widget.id == widget_id))
"""

_GUARD_VALIDATES_A_DIFFERENT_KEY = """
from typing import Annotated
from sqlalchemy import select, text
from app.api.v1.deps import AuthUser
from app.models.widget import Widget

async def _fetch_widget(db, widget_id, tenant_id):
    row = (await db.execute(select(Widget).where(Widget.id == widget_id, Widget.tenant_id == tenant_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404)
    return row

async def read_unrelated(widget_id, other_id, user: AuthUser, db):
    await _fetch_widget(db, widget_id, user.tenant_id)
    return await db.execute(text("SELECT * FROM widgets WHERE owner_ref = :o").bindparams(o=other_id))
"""

_GUARD_NOT_RESOLVABLE = """
from typing import Annotated
from sqlalchemy import select
from app.api.v1.deps import AuthUser
from app.models.widget import Widget
from app.services.elsewhere import assert_owned

async def read_parts(widget_id, user: AuthUser, db):
    await assert_owned(db, widget_id, user.tenant_id)
    return await db.execute(select(Widget).where(Widget.id == widget_id))
"""

_RLS_CONTEXT_ON_COVERED_TABLE = """
async def _set_rls_context(conn, tenant_id):
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(tenant_id))

async def finish(conn_pool, widget_id, tenant_id):
    async with conn_pool.acquire() as conn:
        await _set_rls_context(conn, tenant_id)
        await conn.execute("UPDATE widgets SET status = 'done' WHERE id = $1", widget_id)
"""

_RLS_CONTEXT_ON_UNCOVERED_TABLE = """
async def _set_rls_context(conn, tenant_id):
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(tenant_id))

async def finish(conn_pool, gadget_id, tenant_id):
    async with conn_pool.acquire() as conn:
        await _set_rls_context(conn, tenant_id)
        await conn.execute("UPDATE gadgets SET status = 'done' WHERE id = $1", gadget_id)
"""

#: A migration giving ``widgets`` a policy but leaving ``gadgets`` without one,
#: so the RLS-context rule can be exercised on both sides of its condition.
_PROBE_MIGRATION = """
CREATE TABLE IF NOT EXISTS widgets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL
);
CREATE TABLE IF NOT EXISTS gadgets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL
);
ALTER TABLE widgets ENABLE ROW LEVEL SECURITY;
CREATE POLICY widgets_tenant ON widgets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
"""

#: SQLAlchemy **Core** tables, the shape that was invisible. The module declares
#: its own table rather than importing a declarative model, so nothing here
#: matches a class name — which is exactly the condition under which six
#: statements in `services/connectors` were skipped before any predicate was
#: looked at.
_CORE_TABLE_DECL = """
from sqlalchemy import Boolean, Column, MetaData, String, Table
from sqlalchemy.dialects.postgresql import UUID

metadata = MetaData()

widgets_table = Table(
    "widgets",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("is_enabled", Boolean, nullable=False),
    Column("name", String(255)),
)

gadgets_table = Table(
    "gadgets_no_tenant",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("name", String(255)),
)
"""

_CORE_UNSCOPED = """
from sqlalchemy import select
from app.core_tables import widgets_table

async def fetch(connection, widget_id):
    stmt = select(widgets_table.c.id, widgets_table.c.name).where(widgets_table.c.id == widget_id)
    return (await connection.execute(stmt)).first()
"""

_CORE_SCOPED = """
from sqlalchemy import select
from app.core_tables import widgets_table

async def fetch(connection, widget_id, tenant_id):
    stmt = select(widgets_table.c.id, widgets_table.c.name).where(
        widgets_table.c.id == widget_id,
        widgets_table.c.tenant_id == tenant_id,
    )
    return (await connection.execute(stmt)).first()
"""

_CORE_UPDATE_UNSCOPED = """
from sqlalchemy import update
from app.core_tables import widgets_table

async def touch(connection, widget_id):
    await connection.execute(update(widgets_table).where(widgets_table.c.id == widget_id).values(seen=True))
"""

#: A Core table that declares no tenant column is not tenant-scoped, and the
#: rule must not claim it is. Without this control the detector could be
#: "any Table(...)", which would report every lookup table in the tree.
_CORE_TABLE_WITHOUT_TENANT = """
from sqlalchemy import select
from app.core_tables import gadgets_table

async def fetch(connection, gadget_id):
    return (await connection.execute(select(gadgets_table.c.id).where(gadgets_table.c.id == gadget_id))).first()
"""

_DOCSTRING_ONLY = '''
"""Widget helpers.

Historically this ran ``SELECT * FROM widgets WHERE id = ?`` before the ORM
landed. Prose, not a query.
"""

def helper():
    return 1
'''


def _write_probe(root: Path, sources: dict[str, str], *, migration: str | None = None) -> None:
    pkg = root / "services" / "probe" / "app"
    (pkg / "models").mkdir(parents=True, exist_ok=True)
    (pkg / "models" / "widget.py").write_text(_PROBE_MODEL, encoding="utf-8")
    for name, src in sources.items():
        (pkg / name).write_text(src, encoding="utf-8")
    if migration is not None:
        mig = root / "services" / "probe" / "migrations"
        mig.mkdir(parents=True, exist_ok=True)
        (mig / "001_probe.sql").write_text(migration, encoding="utf-8")


def _self_test() -> int:
    """Prove the gate fails on injected drift, both ways, and drops a stale entry."""
    cases: list[tuple[str, dict[str, str], int, str | None]] = [
        ("clean: by-id read carries a tenant predicate", {"r.py": _CLEAN}, 0, None),
        ("drift A: by-id ORM read with no tenant predicate", {"r.py": _UNSCOPED}, 1, None),
        ("drift B: by-id raw SQL with no tenant predicate", {"r.py": _UNSCOPED_SQL}, 1, None),
        ("control: predicate built in a filters list", {"r.py": _SCOPED_VIA_LIST}, 0, None),
        ("control: predicate applied by a wrapping helper", {"r.py": _SCOPED_VIA_HELPER}, 0, None),
        ("control: predicate added by a later q = q.where()", {"r.py": _SCOPED_VIA_REBIND}, 0, None),
        ("control: scoped on the authenticated principal's own id", {"r.py": _SCOPED_VIA_PRINCIPAL}, 0, None),
        ("control: SQL in a docstring is prose, not a query", {"r.py": _DOCSTRING_ONLY}, 0, None),
        # The fail-soft distinction. All four look identical to the old rule.
        ("control: guard whose callee raises is enforcing", {"r.py": _GUARD_THAT_RAISES}, 0, None),
        ("control: guard tested with a raising handler is enforcing", {"r.py": _GUARD_TESTED_AND_RAISES}, 0, None),
        ("drift C: guard that logs and carries on is not a guard", {"r.py": _GUARD_THAT_FAILS_SOFT}, 1, None),
        ("drift D: guard defined elsewhere is undecidable, so not credited", {"r.py": _GUARD_NOT_RESOLVABLE}, 1, None),
        ("drift F: an enforcing guard on a different key credits nothing", {"r.py": _GUARD_VALIDATES_A_DIFFERENT_KEY}, 1, None),
        # The RLS-context rule, on both sides of its condition.
        ("control: RLS context bound on a table that has a policy", {"r.py": _RLS_CONTEXT_ON_COVERED_TABLE}, 0, _PROBE_MIGRATION),
        ("drift E: RLS context bound on a table with no policy", {"r.py": _RLS_CONTEXT_ON_UNCOVERED_TABLE}, 1, _PROBE_MIGRATION),
        # SQLAlchemy Core tables. The whole family was invisible, so each arm
        # is exercised: the read that was the vulnerability, the write shape
        # beside it, the scoped form that must stay clean, and a Core table
        # with no tenant column that must not be claimed at all.
        (
            "drift G: Core-table by-id read with no tenant predicate",
            {"core_tables.py": _CORE_TABLE_DECL, "r.py": _CORE_UNSCOPED},
            1,
            None,
        ),
        (
            "drift H: Core-table by-id update with no tenant predicate",
            {"core_tables.py": _CORE_TABLE_DECL, "r.py": _CORE_UPDATE_UNSCOPED},
            1,
            None,
        ),
        (
            "control: Core-table read carrying a tenant predicate",
            {"core_tables.py": _CORE_TABLE_DECL, "r.py": _CORE_SCOPED},
            0,
            None,
        ),
        (
            "control: a Core table declaring no tenant column is not tenant-scoped",
            {"core_tables.py": _CORE_TABLE_DECL, "r.py": _CORE_TABLE_WITHOUT_TENANT},
            0,
            None,
        ),
        # Clause position in raw SQL. Every clause a tenant column can legally
        # appear in, on the side of the rule it belongs to. The bare-token
        # match passed all seven of the first group.
        ("drift I: tenant_id only in a RETURNING list", {"r.py": _SQL_TENANT_IN_RETURNING}, 1, None),
        ("drift J: tenant_id only in a SELECT projection", {"r.py": _SQL_TENANT_IN_PROJECTION}, 1, None),
        ("drift K: tenant_id only in an ORDER BY", {"r.py": _SQL_TENANT_IN_ORDER_BY}, 1, None),
        ("drift L: tenant_id only in a GROUP BY", {"r.py": _SQL_TENANT_IN_GROUP_BY}, 1, None),
        ("drift M: tenant_id only in a -- line comment", {"r.py": _SQL_TENANT_IN_COMMENT}, 1, None),
        ("drift N: tenant_id only in a /* block comment */", {"r.py": _SQL_TENANT_IN_BLOCK_COMMENT}, 1, None),
        ("drift O: UPDATE SET tenant_id rewrites the column, it does not scope", {"r.py": _SQL_TENANT_IN_UPDATE_SET}, 1, None),
        ("control: tenant_id in a WHERE", {"r.py": _SQL_TENANT_IN_WHERE}, 0, None),
        ("control: tenant_id in a JOIN ... ON", {"r.py": _SQL_TENANT_IN_JOIN_ON}, 0, None),
        ("control: tenant_id in a USING (...)", {"r.py": _SQL_TENANT_IN_USING}, 0, None),
        ("control: tenant_id in a HAVING", {"r.py": _SQL_TENANT_IN_HAVING}, 0, None),
        ("control: INSERT column list stamps the written row", {"r.py": _SQL_TENANT_IN_INSERT_COLUMNS}, 0, None),
        ("control: ON CONFLICT target selects the upserted row", {"r.py": _SQL_TENANT_IN_ON_CONFLICT}, 0, None),
        ("control: predicate inside a subquery, RETURNING outside it", {"r.py": _SQL_TENANT_IN_SUBQUERY_WHERE}, 0, None),
        ("control: predicate inside a CTE", {"r.py": _SQL_TENANT_IN_CTE}, 0, None),
        ("control: tenant_id::uuid = $1 — a cast before the operator", {"r.py": _SQL_TENANT_CAST_THEN_COMPARED}, 0, None),
        ("control: predicate carried in by an f-string", {"r.py": _SQL_TENANT_VIA_FSTRING}, 0, None),
        ("control: predicate appended as a bare fragment", {"r.py": _SQL_TENANT_VIA_APPENDED_FRAGMENT}, 0, None),
        (
            "drift P: an appended fragment that names tenant_id without comparing it",
            {"r.py": _SQL_FRAGMENT_NAMES_BUT_DOES_NOT_COMPARE},
            1,
            None,
        ),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for i, (label, sources, want, migration) in enumerate(cases):
            root = Path(tmp) / f"case{i}"
            _write_probe(root, sources, migration=migration)
            findings, _inv, files, _stmts = scan(root=root)
            got = len(findings)
            ok = got == want and files > 0
            if not ok:
                failures += 1
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {got} finding(s), want {want} (scanned {files} files)")

    total_ok, total_detail = _clause_classification_is_total()
    failures += 0 if total_ok else 1
    print(f"  [{'PASS' if total_ok else 'FAIL'}] clause classification is total: {total_detail}")

    failures += _self_test_route_reachability()
    failures += _self_test_stale_ratchet()
    failures += _self_test_ratchet_ceiling()
    failures += _self_test_empty_corpus()

    if failures:
        print(f"\nself-test FAILED: {failures} case(s) did not behave as specified", file=sys.stderr)
        return 1
    # Counted rather than written down. The previous wording said "ten
    # controls" and was already wrong by the time anybody read it, which is
    # the same stale-figure-in-prose problem this gate exists to prevent.
    drifts = sum(1 for _label, _src, want, _mig in cases if want)
    controls = len(cases) - drifts
    print(
        f"\nself-test passed: {drifts} injected drifts detected and {controls} controls clear in the statement "
        f"scan, the route-reachability arm detects the advisory's shape without flagging the worker that "
        f"shape exists for, a stale ratchet entry is dropped, and each of the {len(_EMPTY_CORPUS_CASES)} ways "
        "the corpus can empty is refused."
    )
    return 0


#: ``(label, what to put in the scratch tree)``. Each leaves ``services/`` in
#: place and empties one of the three things the gate counts.
_EMPTY_CORPUS_CASES: tuple[tuple[str, dict[str, str], str | None], ...] = (
    ("no Python at all under services/", {}, None),
    ("Python but no tenant-scoped table anywhere", {"r.py": "VALUE = 1\n"}, None),
    (
        "a tenant-scoped table declared and no statement touching one",
        {"r.py": "VALUE = 1\n"},
        "CREATE TABLE IF NOT EXISTS widgets (\n    id UUID PRIMARY KEY,\n    tenant_id UUID NOT NULL\n);",
    ),
)


def _self_test_empty_corpus() -> int:
    """Each of the three ways this scan can end up with nothing must refuse.

    Not one case: the gate counts files, tables and statements, and any of
    them reaching zero means a different part of it stopped working. A single
    ``if not findings`` would have covered none of them — zero findings is
    what a clean tree looks like.

    The controls at the end are as important as the cases: an over-tight
    floor that fires on the real repository would be "fixed" by deleting it.
    """
    global REPO_ROOT, SERVICES_DIR  # noqa: PLW0603 - the scanned root is module state
    original_root, original_services = REPO_ROOT, SERVICES_DIR
    failures = 0
    for label, sources, migration in _EMPTY_CORPUS_CASES:
        with tempfile.TemporaryDirectory(prefix="predicates_empty_") as tmp:
            root = Path(tmp)
            (root / "services" / "probe" / "app").mkdir(parents=True)
            for name, src in sources.items():
                (root / "services" / "probe" / "app" / name).write_text(src, encoding="utf-8")
            if migration is not None:
                (root / "services" / "probe" / "migrations").mkdir(parents=True)
                (root / "services" / "probe" / "migrations" / "001.sql").write_text(migration, encoding="utf-8")
            REPO_ROOT, SERVICES_DIR = root, root / "services"
            try:
                status = main([])
            finally:
                REPO_ROOT, SERVICES_DIR = original_root, original_services
        if status != 0:
            print(f"  [PASS] empty corpus — {label}: exits {status} rather than reporting it clean")
        else:
            print(f"  [FAIL] empty corpus — {label}: reported OK having judged nothing")
            failures += 1
    return failures


#: A repository module with both shapes side by side, so the reachability rule
#: is exercised on both sides of its condition rather than only the failing one.
_REACH_REPO = """
from sqlalchemy import select
from app.core_tables import widgets_table

async def fetch_all_widgets(connection):
    stmt = select(widgets_table.c.id, widgets_table.c.name).where(widgets_table.c.is_enabled.is_(True))
    return (await connection.execute(stmt)).fetchall()

async def fetch_widget_for_tenant(connection, widget_id, tenant_id):
    stmt = select(widgets_table.c.id, widgets_table.c.name).where(
        widgets_table.c.id == widget_id,
        widgets_table.c.tenant_id == tenant_id,
    )
    return (await connection.execute(stmt)).first()
"""

#: The vulnerability's exact shape: a handler serving one caller out of a
#: cross-tenant working set.
_REACH_ROUTE_UNSCOPED = """
from fastapi import APIRouter
from app.repo import fetch_all_widgets

router = APIRouter()

@router.get("/widgets/{widget_id}")
async def read_widget(widget_id, connection):
    rows = await fetch_all_widgets(connection)
    return next((r for r in rows if str(r.id) == widget_id), None)
"""

#: The fixed shape, which must stay clean or the rule is unusable.
_REACH_ROUTE_SCOPED = """
from fastapi import APIRouter
from app.repo import fetch_widget_for_tenant

router = APIRouter()

@router.get("/widgets/{widget_id}")
async def read_widget(widget_id, connection, principal):
    return await fetch_widget_for_tenant(connection, widget_id, principal.tenant_id)
"""

#: A worker calling the same cross-tenant sweep. It must NOT be reported:
#: the sweep's exemption is exactly for callers like this one, and a rule that
#: flagged it would be telling every scheduler in the tree to scope a query
#: that cannot be scoped.
_REACH_WORKER = """
from app.repo import fetch_all_widgets

async def poll_everything(connection):
    for row in await fetch_all_widgets(connection):
        print(row)
"""


def _self_test_route_reachability() -> int:
    """Prove the second arm detects the advisory's shape, and only that shape.

    The statement ratchet alone cannot: measured against the vulnerable tree it
    reported OK, because the sweep was correctly ratcheted and the defect was
    *who called it*.
    """
    cases: tuple[tuple[str, dict[str, str], int], ...] = (
        (
            "drift I: a route handler serving one caller from a cross-tenant sweep",
            {"core_tables.py": _CORE_TABLE_DECL, "repo.py": _REACH_REPO, "routes.py": _REACH_ROUTE_UNSCOPED},
            1,
        ),
        (
            "control: a route handler calling the by-id-and-tenant sibling",
            {"core_tables.py": _CORE_TABLE_DECL, "repo.py": _REACH_REPO, "routes.py": _REACH_ROUTE_SCOPED},
            0,
        ),
        (
            "control: a worker calling the same sweep is what the exemption is for",
            {"core_tables.py": _CORE_TABLE_DECL, "repo.py": _REACH_REPO, "worker.py": _REACH_WORKER},
            0,
        ),
    )

    failures = 0
    with tempfile.TemporaryDirectory(prefix="predicates_reach_") as tmp:
        for i, (label, sources, want) in enumerate(cases):
            root = Path(tmp) / f"reach{i}"
            _write_probe(root, sources)
            result = scan(root=root)
            reach = scan_route_reachability(root, result.findings)
            got = len(reach)
            if got == want:
                print(f"  [PASS] {label}: {got} finding(s), want {want}")
            else:
                print(f"  [FAIL] {label}: {got} finding(s), want {want} — {[r.key for r in reach]}")
                failures += 1
    return failures


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
    failures = 0
    if len(RATCHET) > MAX_RATCHET:
        print(f"  [FAIL] ratchet ceiling: {len(RATCHET)} entries exceeds MAX_RATCHET={MAX_RATCHET}")
        failures += 1
    else:
        print(f"  [PASS] ratchet ceiling: {len(RATCHET)}/{MAX_RATCHET} entries")
    if len(ROUTE_REACHABLE) > MAX_ROUTE_REACHABLE:
        print(f"  [FAIL] route-reachability ceiling: {len(ROUTE_REACHABLE)} exceeds MAX_ROUTE_REACHABLE={MAX_ROUTE_REACHABLE}")
        failures += 1
    else:
        print(f"  [PASS] route-reachability ceiling: {len(ROUTE_REACHABLE)}/{MAX_ROUTE_REACHABLE} entries")
    return failures


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

    result = scan()
    findings, inv, files, statements = result.findings, result.inventory, result.files, result.statements

    # Name what was scanned, before any output mode. A gate that prints OK
    # without saying what it opened cannot be told apart from one that opened
    # nothing.
    print(
        f"check_tenant_query_predicates: scanned {files} files under {SERVICES_DIR}; "
        f"{statements} statements touch {len(inv.tables)} tenant-scoped tables "
        f"({len(inv.tables) - len(inv.tables & inv.rls_tables)} of them with no RLS policy)"
    )

    # And refuse when any of the three things it counts is zero. This gate did
    # not exit 0 over an empty tree before, but only because every ratchet
    # entry went stale at once and that check happens to run first — a true
    # statement about the wrong thing, and one that disappears the moment the
    # ratchet is emptied. The floor has to be the corpus.
    #
    # Three conditions rather than one, because they are three different
    # losses and rolling them together would let the interesting one hide
    # behind the obvious one. The middle is the dangerous case: the inventory
    # is derived from migration DDL and model classes, so a changed glob or a
    # renamed base class empties it silently while the walk still opens
    # hundreds of files and the gate still prints OK.
    #
    # Ahead of `--inventory` as well as the default, because CI runs the
    # inventory as its own step and the coverage figures it prints are quoted
    # elsewhere; all-zero and green is the worst of both.
    for count, detail in (
        (files, f"no Python file was read under {SERVICES_DIR} — the walk found nothing to scan"),
        (
            len(inv.tables),
            "no tenant-scoped table was discovered. The inventory comes from migration DDL and mapped "
            "models; zero of them means the schema globs or the model detection stopped matching, and "
            "every statement below would be judged against an empty set",
        ),
        (
            statements,
            f"{files} files were read and not one statement touched a tenant-scoped table. Found nothing "
            "and scanned nothing print the same word",
        ),
    ):
        if count == 0:
            print(f"\nFAIL: {detail}.", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return 0

    if args.inventory:
        _print_inventory(findings, inv, files, statements, result.rls_scoped)
        return 0

    unratcheted, stale = partition(findings)
    if result.rls_scoped:
        print(
            f"  {result.rls_scoped} statement(s) are scoped by an RLS context on the connection rather than by a "
            "predicate; that credit holds where DATABASE_URL is a role without SUPERUSER or BYPASSRLS, which "
            "every deployment surface now ships and scripts/check_runtime_db_role.py keeps true."
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

    # Second arm: who can *reach* a cross-tenant statement. A sweep's exemption
    # is earned by having no caller, so an HTTP route reaching one retires the
    # justification — which is the shape GHSA-h4g5-39vv-pqfv had, with both
    # halves looking correct in isolation.
    reach = scan_route_reachability(REPO_ROOT, findings)
    unallowed, stale_reach = partition_reach(reach)

    if len(ROUTE_REACHABLE) > MAX_ROUTE_REACHABLE:
        print(
            f"\nFAIL: {len(ROUTE_REACHABLE)} route-reachability entries exceeds MAX_ROUTE_REACHABLE={MAX_ROUTE_REACHABLE}.",
            file=sys.stderr,
        )
        print("      It only shrinks. Scope the query rather than raising the ceiling.", file=sys.stderr)
        return 1

    if stale_reach:
        print(f"\nFAIL: {len(stale_reach)} route-reachability entry/entries no longer describe a real call path.", file=sys.stderr)
        print("      Remove them — a lapsed justification that still passes reads like a decision.", file=sys.stderr)
        for key in stale_reach:
            print(f"  - {key}", file=sys.stderr)

    if unallowed:
        print(
            f"\nFAIL: {len(unallowed)} HTTP route handler(s) reach a statement that carries no tenant predicate.",
            file=sys.stderr,
        )
        print("      A cross-tenant sweep is exempt because nothing calls it with a tenant to filter on.", file=sys.stderr)
        print("      A request handler has one. Scope the read, or record why a request may reach it.", file=sys.stderr)
        for item in unallowed:
            print(f"  - {item.key}", file=sys.stderr)

    if stale or unratcheted or stale_reach or unallowed:
        return 1

    print(
        f"OK: every statement on a tenant-scoped table filters on a tenant, "
        f"or is one of {len(RATCHET)} ratcheted exceptions that still holds; "
        f"and every one of the {len(reach)} route->unscoped-statement paths is a recorded exception."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

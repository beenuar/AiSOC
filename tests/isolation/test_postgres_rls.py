"""Live-Postgres proof that the row-level security policies actually isolate.

Why this file exists
--------------------
Of 95 tenant-scoped tables, 31 carried an RLS policy and 64 did not, so on two
thirds of the schema the query predicate was the only thing between two
customers. ``services/api/migrations/060_rls_coverage.sql`` closes that. A
migration that adds 49 policies is worth exactly as much as the evidence that
they filter, so this is the evidence.

Shape of every assertion, borrowed from ``test_live_stores.py`` and
``services/api/tests/test_mssp_portfolio_isolation.py`` because it is what
makes such a test mean anything:

1. Seed a row for tenant A **and** a row for tenant B.
2. Assert an unscoped read sees both — a scoped read that returns nothing on an
   empty table passes for the wrong reason, and that is the failure mode this
   step exists to prevent.
3. Assert the tenant-A-scoped read returns A's row and never B's.

Read as the *non-superuser the policies are written for*
--------------------------------------------------------
A superuser, or any role with BYPASSRLS, ignores policies even under FORCE ROW
LEVEL SECURITY. ``docker-compose.yml`` and the CI service containers both run
every service as ``POSTGRES_USER=aisoc``, which the postgres image creates as a
superuser — so in the shipped configuration **every policy in this database is
bypassed**. ``test_superuser_bypasses_rls_which_is_why_the_probe_role_exists``
pins that as a measured fact rather than a caveat in a comment, so nobody reads
the green ticks below as "tenant isolation is on in production".

The rest of this suite therefore connects as a purpose-made role with neither
SUPERUSER nor BYPASSRLS. That is the configuration the policies are written
for, and the one ``apps/docs/docs/operations/security.md`` tells operators to
deploy.

Skips when no database answers, so a local ``pytest tests/isolation`` stays
green — but **cannot** skip where it is supposed to run. ``integration.yml``
sets ``POSTGRES_RLS_ISOLATION_REQUIRED=1`` and an unreachable database is then
a failure. A gate that quietly declines to run looks identical to one that
passed.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = REPO_ROOT / "services" / "api" / "migrations"

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("POSTGRES_RLS_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

#: Applied to every test. ``pytest.mark.asyncio`` is attached per-test instead
#: of module-wide, because two of the checks here are pure file reads and a
#: blanket asyncio mark on a synchronous function is an error in strict mode.
pytestmark = pytest.mark.skipif(
    "postgres" not in DSN and not REQUIRED,
    reason="needs a live Postgres with the migration chain applied (integration.yml)",
)

# Fixed ids so a failure names something greppable.
TENANT_A = uuid.UUID("0c000000-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("0c000000-0000-0000-0000-00000000000b")

#: A role with neither SUPERUSER nor BYPASSRLS. Created by the fixture rather
#: than reusing ``aisoc_app`` from 002_rls.sql, whose password is a literal
#: ``changeme`` that no deployment should keep and no test should depend on.
PROBE_ROLE = "aisoc_rls_probe"
PROBE_PASSWORD = "rls-probe-not-a-deployment-credential"

#: Excluded from RLS on purpose; see the header of 060_rls_coverage.sql.
#: ``users`` must resolve a principal before any tenant exists, and
#: platform-admin user administration is deliberately cross-tenant.
INTENTIONALLY_UNPROTECTED = frozenset({"users"})

#: API ORM models that declare a ``tenant_id`` but that no migration creates.
#: Named here rather than silently absent: a table nothing creates cannot carry
#: a policy, and the reason should be visible next to the exclusion.
ORM_MODELS_WITHOUT_A_TABLE = frozenset({"case_tasks", "case_timeline"})


def _asyncpg_dsn(url: str) -> str:
    """SQLAlchemy URL → bare DSN asyncpg accepts."""
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


#: Quoted literals inside a CHECK constraint, e.g.
#: ``CHECK (node_type = ANY (ARRAY['user'::text, 'host'::text]))``.
_CHECK_LITERAL = re.compile(r"'([^']+)'")


def _literal_for(
    data_type: str,
    udt: str,
    enum_labels: dict[str, list[str]],
    *,
    nonce: str,
    allowed: list[str] | None = None,
    max_len: int | None = None,
) -> str:
    """A syntactically valid value for a NOT NULL column with no default.

    Every table here has a different set of required columns, so the seeder
    derives them from ``information_schema`` instead of carrying 60
    hand-written INSERTs that go stale the first time a column is added.

    Three details earn their keep, each found by the seeder failing on a real
    table rather than by guessing:

    * ``nonce`` differs per seeded row. Several tables have a unique
      constraint that does *not* include ``tenant_id``, so A and B sharing a
      literal collides and the table silently drops out of the replay.
    * ``allowed`` carries the literals named in the column's CHECK constraint.
      ``identity_nodes.node_type`` and four others accept a fixed vocabulary.
    * ``max_len`` respects ``varchar(n)``; ``aisoc_attack_chains`` has a
      ``varchar(8)``.
    """
    if allowed:
        return f"'{allowed[0]}'"
    if data_type == "uuid":
        return f"'{uuid.uuid4()}'::uuid"
    if data_type in ("character varying", "text", "character"):
        value = f"p{nonce}"
        if max_len is not None:
            value = value[:max_len]
        return f"'{value}'"
    if data_type in ("integer", "bigint", "smallint"):
        return "1"
    if data_type in ("numeric", "double precision", "real"):
        return "1"
    if data_type == "boolean":
        return "false"
    if data_type in ("timestamp with time zone", "timestamp without time zone"):
        return "now()"
    if data_type == "date":
        return "current_date"
    if data_type == "jsonb":
        return "'{}'::jsonb"
    if data_type == "json":
        return "'{}'::json"
    if data_type == "inet":
        return "'198.51.100.1'::inet"
    if data_type == "ARRAY":
        # udt_name for an array is the element type prefixed with '_'.
        return f"'{{}}'::{udt.lstrip('_')}[]"
    if data_type == "USER-DEFINED":
        labels = enum_labels.get(udt) or []
        if labels:
            return f"'{labels[0]}'::{udt}"
    # Let Postgres decide; if it cannot, the seeder reports the column by name.
    return "DEFAULT"


async def _protected_tables(conn) -> list[str]:
    """Tenant-scoped tables in *this* database that carry an RLS policy."""
    rows = await conn.fetch(
        """
        SELECT c.relname AS t
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relkind = 'r'
           AND c.relrowsecurity
           AND EXISTS (
                 SELECT 1 FROM pg_attribute a
                  WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
         ORDER BY 1
        """
    )
    return [r["t"] for r in rows]


async def _check_vocabularies(conn, table: str) -> dict[str, list[str]]:
    """column → literals its CHECK constraint permits.

    Only single-column checks are used: a multi-column check tells us nothing
    about which value belongs to which column.
    """
    rows = await conn.fetch(
        """
        SELECT a.attname AS col, pg_get_constraintdef(c.oid) AS def
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
         WHERE c.contype = 'c'
           AND c.conrelid = to_regclass('public.' || quote_ident($1))
           AND array_length(c.conkey, 1) = 1
        """,
        table,
    )
    out: dict[str, list[str]] = {}
    for row in rows:
        literals = [m for m in _CHECK_LITERAL.findall(row["def"]) if not m.endswith("::text")]
        if literals:
            out.setdefault(row["col"], []).extend(literals)
    return out


async def _seed_row(conn, table: str, tenant: uuid.UUID, enum_labels: dict[str, list[str]], nonce: str) -> None:
    """Insert one row owned by ``tenant``, filling only what the schema demands."""
    cols = await conn.fetch(
        """
        SELECT column_name, data_type, udt_name, character_maximum_length
          FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1
           AND is_nullable = 'NO' AND column_default IS NULL
           AND column_name <> 'tenant_id'
         ORDER BY ordinal_position
        """,
        table,
    )
    vocab = await _check_vocabularies(conn, table)
    tenant_type = await conn.fetchval(
        """
        SELECT format_type(a.atttypid, a.atttypmod)
          FROM pg_attribute a
         WHERE a.attrelid = to_regclass('public.' || quote_ident($1))
           AND a.attname = 'tenant_id' AND NOT a.attisdropped
        """,
        table,
    )
    tenant_literal = f"'{tenant}'::uuid" if tenant_type == "uuid" else f"'{tenant}'"

    names = ["tenant_id"]
    values = [tenant_literal]
    for col in cols:
        literal = _literal_for(
            col["data_type"],
            col["udt_name"],
            enum_labels,
            nonce=nonce,
            allowed=vocab.get(col["column_name"]),
            max_len=col["character_maximum_length"],
        )
        if literal == "DEFAULT":
            continue
        names.append(f'"{col["column_name"]}"')
        values.append(literal)

    # Every literal above is generated here from the column's own type; none
    # of it comes from outside this process.
    await conn.execute(f'INSERT INTO public."{table}" ({", ".join(names)}) VALUES ({", ".join(values)})')  # noqa: S608


async def _make_probe_role() -> str:
    """A DSN for a role with neither SUPERUSER nor BYPASSRLS."""
    asyncpg = pytest.importorskip("asyncpg")
    if not DSN:
        pytest.skip("DATABASE_URL not set")
    admin_dsn = _asyncpg_dsn(DSN)
    try:
        admin = await asyncpg.connect(admin_dsn)
    except Exception as exc:  # noqa: BLE001
        if REQUIRED:
            pytest.fail(f"POSTGRES_RLS_ISOLATION_REQUIRED is set but no database answered at {admin_dsn!r}: {exc}")
        pytest.skip(f"no Postgres at {admin_dsn!r}: {exc}")
    try:
        await admin.execute(
            f"""
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{PROBE_ROLE}') THEN
                    CREATE ROLE {PROBE_ROLE} LOGIN PASSWORD '{PROBE_PASSWORD}';
                END IF;
            END $$;
            """
        )
        # NOSUPERUSER / NOBYPASSRLS are the whole point of this role.
        await admin.execute(f"ALTER ROLE {PROBE_ROLE} WITH LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{PROBE_PASSWORD}'")
        await admin.execute(f"GRANT USAGE ON SCHEMA public TO {PROBE_ROLE}")
        await admin.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {PROBE_ROLE}")
        await admin.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {PROBE_ROLE}")
    finally:
        await admin.close()

    return re.sub(r"//[^@]*@", f"//{PROBE_ROLE}:{PROBE_PASSWORD}@", _asyncpg_dsn(DSN), count=1)


#: Populated once by :func:`_seeded`. A module-scoped *async* fixture binds
#: itself to one event loop and pytest-asyncio gives each test a fresh one, so
#: the state is cached here instead.
_STATE: dict[str, object] = {}


async def _seeded() -> dict:
    """Seed one A row and one B row into every RLS-covered tenant table.

    Seeding runs as the owner with replication-role ``replica`` so foreign keys
    do not force a full object graph per table. The *reads* under test all run
    as the probe role, which is what the policies are written for.
    """
    if _STATE:
        return dict(_STATE)
    probe_dsn = await _make_probe_role()
    asyncpg = pytest.importorskip("asyncpg")
    admin = await asyncpg.connect(_asyncpg_dsn(DSN))
    enum_labels: dict[str, list[str]] = {}
    seeded_tables: list[str] = []
    unseedable: dict[str, str] = {}
    try:
        for row in await admin.fetch(
            "SELECT t.typname, e.enumlabel FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid ORDER BY e.enumsortorder"
        ):
            enum_labels.setdefault(row["typname"], []).append(row["enumlabel"])

        tables = await _protected_tables(admin)
        await admin.execute("SET session_replication_role = replica")
        # Clear any rows a previous run left behind. Without this the
        # "exactly 2 rows" assertions drift upward on every re-run and the
        # suite starts failing for a reason that has nothing to do with
        # isolation — which is how a test earns a reputation for flakiness.
        for table in tables:
            with contextlib.suppress(Exception):
                await admin.execute(
                    f'DELETE FROM public."{table}" WHERE tenant_id::text = ANY($1::text[])',  # noqa: S608
                    [str(TENANT_A), str(TENANT_B)],
                )
        for table in tables:
            try:
                async with admin.transaction():
                    await _seed_row(admin, table, TENANT_A, enum_labels, uuid.uuid4().hex[:6])
                    await _seed_row(admin, table, TENANT_B, enum_labels, uuid.uuid4().hex[:6])
            except Exception as exc:  # noqa: BLE001
                unseedable[table] = f"{type(exc).__name__}: {exc}"
                continue
            seeded_tables.append(table)
    finally:
        await admin.close()

    _STATE.update({"tables": tables, "seeded": seeded_tables, "unseedable": unseedable, "probe_dsn": probe_dsn})
    return dict(_STATE)


# ---------------------------------------------------------------------------
# The measured fact that makes every other result in this file conditional
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_superuser_bypasses_rls_which_is_why_the_probe_role_exists() -> None:
    """The role the services actually connect as ignores every policy here.

    Not a caveat in a docstring — a measurement. ``docker-compose.yml`` runs
    every service as ``POSTGRES_USER=aisoc``, and the postgres image creates
    that role as a superuser. If this test ever *fails* because the connecting
    role stopped bypassing RLS, that is good news and the deployment docs
        should say so.
    """
    await _seeded()
    asyncpg = pytest.importorskip("asyncpg")
    admin = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        is_super = await admin.fetchval("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        if not is_super:
            pytest.skip(f"connected as {DSN.split('//')[-1].split(':')[0]!r}, which does not bypass RLS — policies are live")
        async with admin.transaction():
            await admin.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(TENANT_A))
            both = await admin.fetchval("SELECT count(*) FROM alerts WHERE tenant_id IN ($1, $2)", TENANT_A, TENANT_B)
        assert both == 2, (
            f"expected the bypassing role to see both tenants' alerts, saw {both} — "
            "if this dropped to 1 the connection role changed and the docs are now understating the guarantee"
        )
    finally:
        await admin.close()


# ---------------------------------------------------------------------------
# The two-tenant replay, once per protected table
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_protected_table_is_seeded_for_both_tenants() -> None:
    """Non-vacuity, asserted once and loudly rather than per-table.

    A table the seeder could not populate would make its isolation assertion
    below trivially true, so the seeder's failures are a test result, not a
    log line.
    """
    seeded = await _seeded()
    assert seeded["tables"], "no RLS-covered tenant table found — the migration chain did not apply"
    assert not seeded["unseedable"], (
        "these RLS-covered tables could not be seeded, so their isolation assertions "
        f"would pass vacuously: {seeded['unseedable']}"
    )


@pytest.mark.asyncio
async def test_scoped_read_as_A_never_returns_B() -> None:
    """The property, table by table, as a non-bypassing role."""
    seeded = await _seeded()
    asyncpg = pytest.importorskip("asyncpg")
    probe = await asyncpg.connect(seeded["probe_dsn"])
    leaked: list[str] = []
    vacuous: list[str] = []
    checked = 0
    try:
        for table in seeded["seeded"]:
            # (2) Unscoped: both tenants' rows are really there.
            unscoped = await probe.fetchval(
                f'SELECT count(*) FROM public."{table}" WHERE tenant_id::text = ANY($1::text[])',  # noqa: S608
                [str(TENANT_A), str(TENANT_B)],
            )
            if unscoped != 2:
                vacuous.append(f"{table}: unscoped read saw {unscoped} of the 2 seeded rows")
                continue

            # (3) Scoped to A: A's row, never B's.
            async with probe.transaction():
                await probe.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(TENANT_A))
                seen_a = await probe.fetchval(
                    f'SELECT count(*) FROM public."{table}" WHERE tenant_id::text = $1',  # noqa: S608
                    str(TENANT_A),
                )
                seen_b = await probe.fetchval(
                    f'SELECT count(*) FROM public."{table}" WHERE tenant_id::text = $1',  # noqa: S608
                    str(TENANT_B),
                )
            if seen_b != 0:
                leaked.append(f"{table}: tenant B's row was visible to a session bound to tenant A")
            elif seen_a != 1:
                leaked.append(f"{table}: tenant A could not see its own row ({seen_a}), so the policy is over-tight")
            checked += 1
    finally:
        await probe.close()

    assert not vacuous, "seeded rows were not visible even unscoped, so the scoped assertions prove nothing: " + "; ".join(vacuous)
    assert not leaked, "; ".join(leaked)
    assert checked >= 40, f"only {checked} tables were replayed; the chain should protect far more"


@pytest.mark.asyncio
async def test_a_session_with_no_tenant_context_still_sees_everything() -> None:
    """Fail open on an unset context — the documented, deliberate semantic.

    Ingest, fusion, the hunt scheduler and the retention purge all operate
    across tenants on connections that never bind one. If this ever fails
    closed they stop processing silently, which is the failure mode that left
    ``tenant_sla_config`` returning zero rows for anybody who looked.
    """
    seeded = await _seeded()
    asyncpg = pytest.importorskip("asyncpg")
    probe = await asyncpg.connect(seeded["probe_dsn"])
    try:
        for table in seeded["seeded"][:20]:
            both = await probe.fetchval(
                f'SELECT count(*) FROM public."{table}" WHERE tenant_id::text = ANY($1::text[])',  # noqa: S608
                [str(TENANT_A), str(TENANT_B)],
            )
            assert both == 2, f"{table}: a worker connection with no tenant context saw {both} of 2 rows, not both"
    finally:
        await probe.close()


@pytest.mark.asyncio
async def test_no_policy_reads_a_session_variable_nothing_sets() -> None:
    """The bug class 060 repaired, kept repaired.

    Seven policies read ``app.tenant_id`` or ``app.current_tenant`` — names no
    code path sets — or called ``current_setting`` without ``missing_ok``, so
    they either returned zero rows forever or raised
    ``unrecognized configuration parameter``. Both are invisible while a
    superuser bypasses them.
    """
    asyncpg = pytest.importorskip("asyncpg")
    admin = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        rows = await admin.fetch("SELECT tablename, policyname, qual FROM pg_policies WHERE schemaname = 'public'")
    finally:
        await admin.close()

    wrong_variable: list[str] = []
    would_raise: list[str] = []
    for row in rows:
        qual = row["qual"] or ""
        for setting in re.findall(r"current_setting\(\s*'([^']+)'([^)]*)\)", qual):
            name, rest = setting
            if name != "app.current_tenant_id":
                wrong_variable.append(f"{row['tablename']}.{row['policyname']} reads {name!r}")
            elif "true" not in rest:
                would_raise.append(f"{row['tablename']}.{row['policyname']} omits missing_ok, so an unset context raises")

    assert not wrong_variable, (
        "a policy keyed on a session variable nothing sets returns zero rows forever: " + "; ".join(wrong_variable)
    )
    assert not would_raise, "; ".join(would_raise)


@pytest.mark.asyncio
async def test_every_tenant_table_is_protected_or_named() -> None:
    """Coverage, both directions.

    Forward: a tenant-scoped table with no policy fails unless it is one of the
    two documented exclusions. Reverse: an exclusion that no longer describes
    an unprotected table fails too, so the list cannot outlive its reason.
    """
    asyncpg = pytest.importorskip("asyncpg")
    admin = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        unprotected = {
            r["t"]
            for r in await admin.fetch(
                """
                SELECT c.relname AS t
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relrowsecurity
                   AND EXISTS (SELECT 1 FROM pg_attribute a
                                WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
                """
            )
        }
        unforced = {
            r["t"]
            for r in await admin.fetch(
                """
                SELECT c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity AND NOT c.relforcerowsecurity
                """
            )
        }
    finally:
        await admin.close()

    surprises = unprotected - INTENTIONALLY_UNPROTECTED
    assert not surprises, (
        f"tenant-scoped tables with no RLS policy: {sorted(surprises)}. "
        "Add one in a migration, or add the table to INTENTIONALLY_UNPROTECTED with the reason."
    )
    stale = INTENTIONALLY_UNPROTECTED - unprotected
    assert not stale, f"these are now protected, so the exclusion is stale and must come out: {sorted(stale)}"
    assert not unforced, (
        f"RLS is enabled but not FORCEd on {sorted(unforced)}, so the table owner — which is the "
        "application — walks straight past the policy"
    )


def test_orm_models_without_a_table_are_still_absent() -> None:
    """Two API models declare a tenant_id that no migration ever creates.

    Named rather than ignored. If a migration later creates one of these, this
    fails and the table needs a policy like every other.
    """
    sql = "\n".join(p.read_text(encoding="utf-8") for p in sorted(MIGRATIONS.glob("*.sql")))
    for table in sorted(ORM_MODELS_WITHOUT_A_TABLE):
        assert not re.search(rf'CREATE TABLE(?:\s+IF NOT EXISTS)?\s+"?{table}"?\b', sql, re.I), (
            f"{table} now has a migration, so it needs an RLS policy and must come out of ORM_MODELS_WITHOUT_A_TABLE"
        )


# ---------------------------------------------------------------------------
# The attack-path relational fallback, replayed for real
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attack_path_relational_fallback_refuses_another_tenants_case() -> None:
    """Tenant B names tenant A's case UUID and is refused.

    ``GET /graph/attack-path/{case_id}`` reads ``aisoc_cases`` by id when the
    Neo4j traversal fails — which, for a deployment that ships no graph
    database, is *always*. It gained a tenant predicate, but that fix was
    covered by the gate and by review only: the statement uses
    ``CAST(:cid AS UUID)``, which SQLite mangles, so the offline suites cannot
    execute it. This runs it against the database it is written for.
    """
    pytest.importorskip("asyncpg")
    pytest.importorskip("greenlet")
    sqlalchemy_asyncio = pytest.importorskip("sqlalchemy.ext.asyncio")

    api_root = REPO_ROOT / "services" / "api"
    if str(api_root) not in sys.path:
        sys.path.insert(0, str(api_root))
    from app.api.v1.endpoints.graph import _attack_path_from_relational  # noqa: PLC0415

    sa_url = DSN if DSN.startswith("postgresql+") else "postgresql+asyncpg://" + _asyncpg_dsn(DSN).split("://", 1)[1]
    engine = sqlalchemy_asyncio.create_async_engine(sa_url)
    case_a = uuid.uuid4()
    case_b = uuid.uuid4()
    try:
        from sqlalchemy import text  # noqa: PLC0415

        async with sqlalchemy_asyncio.async_sessionmaker(engine, expire_on_commit=False)() as db:
            await db.execute(text("SET session_replication_role = replica"))
            for case_id, tenant, title in ((case_a, TENANT_A, "A: ransomware"), (case_b, TENANT_B, "B: phishing")):
                # jsonb and uuid[] are cast from text rather than bound as
                # Python lists: asyncpg refuses a list for a jsonb parameter,
                # and the point of this test is the statement's own SQL.
                await db.execute(
                    text(
                        "INSERT INTO aisoc_cases (id, tenant_id, title, severity, status, mitre_techniques, alert_ids) "
                        "VALUES (CAST(:id AS UUID), CAST(:tid AS UUID), :title, 'high', 'investigating', "
                        "CAST(:tech AS JSONB), CAST(:alerts AS UUID[]))"
                    ).bindparams(
                        id=str(case_id),
                        tid=str(tenant),
                        title=title,
                        tech='["T1486"]',
                        alerts="{" + str(uuid.uuid4()) + "}",
                    )
                )
            await db.commit()

            # (2) Non-vacuity: A's case genuinely exists and is readable by A.
            own = await _attack_path_from_relational(db, str(case_a), TENANT_A)
            assert own is not None, "tenant A's own case was not found — every assertion below would be vacuous"
            assert own["nodes"], "tenant A's case produced no graph, so the read below proves nothing"

            # (3) The read that must be refused.
            leaked = await _attack_path_from_relational(db, str(case_a), TENANT_B)
            assert leaked is None, "tenant B reconstructed tenant A's attack path by naming its case UUID"

            crossed = await _attack_path_from_relational(db, str(case_b), TENANT_A)
            assert crossed is None, "tenant A reconstructed tenant B's attack path"
    finally:
        async with engine.begin() as conn:
            from sqlalchemy import text as _text  # noqa: PLC0415

            await conn.execute(_text("DELETE FROM aisoc_cases WHERE id = ANY(:ids)").bindparams(ids=[case_a, case_b]))
        await engine.dispose()


# ---------------------------------------------------------------------------
# The gate this suite backs, run as a meta-assertion
# ---------------------------------------------------------------------------


def test_predicate_gate_still_reports_no_violations() -> None:
    """RLS is the second layer, not a reason to relax the first one."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "check_tenant_query_predicates.py")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr

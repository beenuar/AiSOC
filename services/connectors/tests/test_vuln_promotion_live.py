"""The patch-window promotion statements, executed against real Postgres.

``tests/test_vuln_patch_windows.py`` pins these statements by asserting
substrings against the SQL strings, and its sibling reads the scheduler with
``inspect.getsource``. Neither executes anything, which is exactly why
``UPSERT_ALERT_SQL`` could carry ``:affected_hosts::jsonb`` and no test could
ever notice: the substring is present and correct, and the statement is the
thing that is broken.

SQLAlchemy *declares* bind parameters with one regex and *renders* them with
a stricter one, so for this statement the three ``::`` names are never
substituted and the literal text ``:affected_hosts::jsonb`` reaches the
driver, which answers ``syntax error at or near ":"``. The job runs every six
hours, each tenant's sweep is wrapped in ``except Exception:
logger.exception(...)``, and the comment above the schedule calls it *"the
ONLY path from asset_vulnerabilities back into the alert queue"* — so the
observable symptom of "no overdue-CVE alert has ever been created on any
deployment" is one log line.

The sibling control is the proof rather than a nicety.
``MARK_PROMOTED_SQL`` is the same shape, on the same connection, in the same
transaction, written with ``CAST(:tenant_id AS uuid)`` — if it succeeds while
the upsert raises, the fault is the ``::`` spelling and not the connection,
the parameters, the role or the schema.

    docker run -d --name aisoc-vuln-pg -p 55432:5432 \\
        -e POSTGRES_PASSWORD=aisoc_ci_secret -e POSTGRES_USER=aisoc \\
        -e POSTGRES_DB=aisoc postgres:16-alpine
    # ... apply services/api/migrations in full ...
    AISOC_TEST_POSTGRES=postgresql+asyncpg://aisoc:aisoc_ci_secret@127.0.0.1:55432/aisoc \\
        pytest tests/test_vuln_promotion_live.py

Run it under the **connectors service's own interpreter**. This service
resolves SQLAlchemy 2.1.6 and a system Python may give 2.0.x; the two declare
different parameter sets for the same statement, so the version that grades
the fix has to be the version the image installs.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import pytest
from app.vuln_promotion_sql import (
    MARK_OVERDUE_SQL,
    MARK_PROMOTED_SQL,
    PROMOTE_CANDIDATES_SQL,
    RESOLVE_REMEDIATED_SQL,
    UPSERT_ALERT_SQL,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip()
pytestmark = [
    pytest.mark.skipif(
        not DSN,
        reason="set AISOC_TEST_POSTGRES=postgresql+asyncpg://... (migrations applied) to run the promotion proof",
    ),
    pytest.mark.asyncio,
]


async def _seed(conn, tenant_id: uuid.UUID) -> None:
    """One tenant, one asset, one CVE whose patch window closed yesterday.

    Binds the tenant first. These tests run as the **runtime** role, not the
    owner: a superuser ignores every RLS policy in the schema even under
    FORCE ROW LEVEL SECURITY, so seeding as the owner is the exact workaround
    that has hidden policy defects in this repository before.
    """
    await conn.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )
    await conn.execute(
        text(
            """
            INSERT INTO tenants (id, name, slug)
            VALUES (CAST(:tid AS uuid), :name, :slug)
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"tid": str(tenant_id), "name": f"promo-{tenant_id.hex[:8]}", "slug": f"promo-{tenant_id.hex[:8]}"},
    )
    asset_id = uuid.uuid4()
    await conn.execute(
        text(
            """
            INSERT INTO assets (id, tenant_id, asset_type, name, criticality)
            VALUES (CAST(:aid AS uuid), CAST(:tid AS uuid), 'host', :name, 'high')
            """
        ),
        {"aid": str(asset_id), "tid": str(tenant_id), "name": f"web-{asset_id.hex[:6]}"},
    )
    await conn.execute(
        text(
            """
            INSERT INTO asset_vulnerabilities (
                tenant_id, asset_id, cve_id, title, severity, cvss_score,
                is_exploited, source, patch_due_date, patch_status
            ) VALUES (
                CAST(:tid AS uuid), CAST(:aid AS uuid), 'CVE-2026-0001',
                'Remote code execution', 'critical', 9.8, TRUE, 'qualys',
                (NOW() AT TIME ZONE 'UTC')::date - 1, 'tracked'
            )
            """
        ),
        {"tid": str(tenant_id), "aid": str(asset_id)},
    )


async def test_the_promotion_sweep_creates_an_alert() -> None:
    """The whole sweep, statement for statement, as the scheduler runs it."""
    engine = create_async_engine(DSN)
    tenant_id = uuid.uuid4()
    try:
        async with engine.begin() as conn:
            await _seed(conn, tenant_id)

        async with engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            await conn.execute(text(MARK_OVERDUE_SQL), {"tenant_id": tenant_id})
            await conn.execute(text(RESOLVE_REMEDIATED_SQL), {"tenant_id": tenant_id})
            candidates = (await conn.execute(text(PROMOTE_CANDIDATES_SQL), {"tenant_id": tenant_id})).fetchall()
            assert len(candidates) == 1, f"the candidate query found no overdue CVE: {candidates}"
            row = candidates[0]
            hosts = row.affected_hosts or []

            # The parameters the scheduler binds, verbatim.
            await conn.execute(
                text(UPSERT_ALERT_SQL),
                {
                    "tenant_id": tenant_id,
                    "title": f"{row.cve_id} overdue / urgent on {row.host_count} host(s)",
                    "description": "patch window closed; CVSS 9.8; actively exploited",
                    "severity": "critical",
                    "affected_hosts": json.dumps(hosts),
                    "tags": json.dumps(["patch-window", "vulnerability", str(row.cve_id).lower()]),
                    "idempotency_key": f"vuln-promo:{str(row.cve_id).lower()}",
                    "connector_id": None,
                    "raw_event": json.dumps({"cve": row.cve_id, "host_count": row.host_count}),
                },
            )

            # The sibling control. Same connection, same transaction, same
            # shape — written with CAST() rather than `::`. If this succeeds
            # while the upsert above raises, the fault is the spelling.
            await conn.execute(
                text(MARK_PROMOTED_SQL),
                {"tenant_id": tenant_id, "cve_id": str(row.cve_id).lower()},
            )

        async with engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            alert = (
                await conn.execute(
                    text(
                        """
                        SELECT title, severity, affected_hosts, tags, raw_event, status
                          FROM alerts
                         WHERE tenant_id = CAST(:tid AS uuid)
                           AND idempotency_key = :key
                        """
                    ),
                    {"tid": str(tenant_id), "key": "vuln-promo:cve-2026-0001"},
                )
            ).fetchone()
        assert alert is not None, "the only path from asset_vulnerabilities to alerts created no alert"
        assert alert.severity == "critical"
        hosts_json = alert.affected_hosts if isinstance(alert.affected_hosts, list) else json.loads(alert.affected_hosts)
        assert len(hosts_json) == 1, f"affected_hosts did not round-trip as jsonb: {alert.affected_hosts!r}"
        tags_json = alert.tags if isinstance(alert.tags, list) else json.loads(alert.tags)
        assert "patch-window" in tags_json
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            await conn.execute(text("DELETE FROM tenants WHERE id = CAST(:tid AS uuid)"), {"tid": str(tenant_id)})
        await engine.dispose()


async def test_the_cast_spelling_is_the_fault_not_the_connection() -> None:
    """The sibling control, run before the upsert so it is in the same report.

    ``MARK_PROMOTED_SQL`` is the same shape as ``UPSERT_ALERT_SQL`` — a
    tenant-scoped write, same module, same connection, same transaction — and
    is written ``CAST(:tenant_id AS uuid)``. It succeeding while the upsert
    raises is what rules out the connection, the parameters, the role and the
    schema and leaves only the ``::`` spelling.
    """
    engine = create_async_engine(DSN)
    tenant_id = uuid.uuid4()
    try:
        async with engine.begin() as conn:
            await _seed(conn, tenant_id)

        async with engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            control = await conn.execute(
                text(MARK_PROMOTED_SQL),
                {"tenant_id": tenant_id, "cve_id": "cve-2026-0001"},
            )
            assert control.rowcount == 1, "the CAST()-spelled sibling did not run — the fault is not the spelling"

            await conn.execute(
                text(UPSERT_ALERT_SQL),
                {
                    "tenant_id": tenant_id,
                    "title": "CVE-2026-0001 overdue",
                    "description": "d",
                    "severity": "critical",
                    "affected_hosts": json.dumps(["web-1"]),
                    "tags": json.dumps(["patch-window"]),
                    "idempotency_key": "vuln-promo:cve-2026-0001",
                    "connector_id": None,
                    "raw_event": json.dumps({"cve": "CVE-2026-0001"}),
                },
            )
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            await conn.execute(text("DELETE FROM tenants WHERE id = CAST(:tid AS uuid)"), {"tid": str(tenant_id)})
        await engine.dispose()


async def test_every_promotion_statement_renders_its_parameters() -> None:
    """No statement in this module may leave a `:name` in the rendered SQL.

    Asserted against the compiler rather than against the text, because the
    whole defect is that the declaring regex and the rendering regex disagree:
    the parameter is declared, the source reads correctly, and the literal
    `:affected_hosts::jsonb` is what the driver receives.
    """
    statements: dict[str, tuple[str, dict[str, Any]]] = {
        "MARK_OVERDUE_SQL": (MARK_OVERDUE_SQL, {"tenant_id": uuid.uuid4()}),
        "RESOLVE_REMEDIATED_SQL": (RESOLVE_REMEDIATED_SQL, {"tenant_id": uuid.uuid4()}),
        "PROMOTE_CANDIDATES_SQL": (PROMOTE_CANDIDATES_SQL, {"tenant_id": uuid.uuid4()}),
        "MARK_PROMOTED_SQL": (MARK_PROMOTED_SQL, {"tenant_id": uuid.uuid4(), "cve_id": "cve-2026-0001"}),
        "UPSERT_ALERT_SQL": (
            UPSERT_ALERT_SQL,
            {
                "tenant_id": uuid.uuid4(),
                "title": "t",
                "description": "d",
                "severity": "high",
                "affected_hosts": "[]",
                "tags": "[]",
                "idempotency_key": "k",
                "connector_id": None,
                "raw_event": "{}",
            },
        ),
    }
    engine = create_async_engine(DSN)
    try:
        dialect = engine.dialect
        for name, (sql, params) in statements.items():
            compiled = text(sql).bindparams(**params).compile(dialect=dialect)
            rendered = str(compiled)
            leftovers = [piece for piece in params if f":{piece}" in rendered]
            assert not leftovers, f"{name}: {leftovers} were never substituted — they reach the driver as literal text"
    finally:
        await engine.dispose()

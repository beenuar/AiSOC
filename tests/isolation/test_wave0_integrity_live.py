"""The Wave 0 no-writer defects, measured against real Postgres.

Each of these covers a mechanism that was complete, tested and
unreachable because the table or column it depended on had no writer.
Unit tests could not see any of them: the code was correct, and the data
it needed never arrived.

The suite is deliberately shaped around *reachability* rather than
behaviour. The question for each is "can this now happen at all", which
is the question the unit tests were silently answering yes to.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_WAVE0_DSN", "").strip(),
        reason="ISOLATION_WAVE0_DSN is not set; this suite needs a live Postgres",
    ),
]

TENANT = uuid.UUID("aaaa0000-0000-0000-0000-00000000aaaa")
OTHER_TENANT = uuid.UUID("bbbb0000-0000-0000-0000-00000000bbbb")


def _dsn() -> str:
    return os.environ["ISOLATION_WAVE0_DSN"]


def _pg_dsn() -> str:
    return _dsn().replace("postgresql+asyncpg://", "postgresql://")


async def _bind_tenant(connection, tenant) -> None:  # noqa: ANN001
    """Bind the session to a tenant, as every real request does.

    `aisoc_sso_connections` carries `WITH CHECK (tenant_id =
    current_tenant_id())`, so an unbound session cannot insert. This
    suite passed locally against a superuser — who bypasses RLS entirely
    — and failed in CI, where the job connects as the DML-only
    `aisoc_app` role. The local database was the more permissive test
    double, which is the same failure shape as an over-capable mock.
    """
    await connection.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant))


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def conn():
    asyncpg = pytest.importorskip("asyncpg")
    connection = await asyncpg.connect(_pg_dsn())
    try:
        for tenant in (TENANT, OTHER_TENANT):
            await connection.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                tenant,
                f"w0-{tenant.hex[:8]}",
                f"w0-{tenant.hex[:8]}",
            )
        yield connection
    finally:
        await connection.close()


class TestSsoConnectionsCanExist:
    """`aisoc_sso_connections` had no writer anywhere, so
    `resolve_connection` found nothing on every sign-in and both SAML and
    OIDC answered 403. The table was unreachable, not merely unused."""

    async def test_a_connection_can_be_written_and_resolved(self, conn) -> None:  # noqa: ANN001
        issuer = f"https://idp.example.com/{uuid.uuid4().hex[:8]}"
        await _bind_tenant(conn, TENANT)
        await conn.execute(
            "INSERT INTO aisoc_sso_connections "
            "(tenant_id, provider, issuer, display_name, enabled, group_role_mapping, default_role) "
            "VALUES ($1,'oidc',$2,'Example IdP',TRUE,$3::jsonb,'viewer')",
            TENANT,
            issuer,
            json.dumps({"soc-team": "soc_analyst"}),
        )

        row = await conn.fetchrow(
            "SELECT tenant_id, group_role_mapping, default_role, enabled "
            "  FROM aisoc_sso_connections WHERE provider='oidc' AND issuer=$1 AND enabled=TRUE",
            issuer,
        )
        assert row is not None, "the exact query sso_provisioning runs found nothing"
        assert row["tenant_id"] == TENANT
        assert json.loads(row["group_role_mapping"])["soc-team"] == "soc_analyst"

    async def test_two_tenants_cannot_claim_one_issuer(self, conn) -> None:  # noqa: ANN001
        """The unique index is the control that stops an assertion being
        ambiguous about which tenant it provisions into."""
        asyncpg = pytest.importorskip("asyncpg")
        issuer = f"https://idp.example.com/{uuid.uuid4().hex[:8]}"
        await _bind_tenant(conn, TENANT)
        await conn.execute(
            "INSERT INTO aisoc_sso_connections (tenant_id, provider, issuer) VALUES ($1,'saml',$2)",
            TENANT,
            issuer,
        )
        # The second tenant binds to itself, so the refusal below is the
        # unique index rather than RLS.
        await _bind_tenant(conn, OTHER_TENANT)
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                "INSERT INTO aisoc_sso_connections (tenant_id, provider, issuer) VALUES ($1,'saml',$2)",
                OTHER_TENANT,
                issuer,
            )
        await _bind_tenant(conn, TENANT)

    async def test_a_disabled_connection_does_not_resolve(self, conn) -> None:  # noqa: ANN001
        """So an administrator can stage one before turning it on."""
        issuer = f"https://idp.example.com/{uuid.uuid4().hex[:8]}"
        await conn.execute(
            "INSERT INTO aisoc_sso_connections (tenant_id, provider, issuer, enabled) VALUES ($1,'oidc',$2,FALSE)",
            TENANT,
            issuer,
        )
        row = await conn.fetchrow(
            "SELECT 1 FROM aisoc_sso_connections WHERE provider='oidc' AND issuer=$1 AND enabled=TRUE",
            issuer,
        )
        assert row is None


class TestProposalsCarryTheirOwnProof:
    """`/decide` refuses an approval without a `candidate_rule` verdict,
    and `/evaluate-rule` is the only writer of it — but fixtures were
    never stored, so an operator had nothing to send. The proposal could
    not prove itself and therefore could never be approved."""

    async def test_fixtures_round_trip(self, conn) -> None:  # noqa: ANN001
        proposal_id = uuid.uuid4()
        positives = [{"event_type": "process", "command_line": "powershell -enc AAA"}]
        negatives = [{"event_type": "process", "command_line": "notepad.exe"}]
        await conn.execute(
            "INSERT INTO detection_rule_proposals "
            "(id, tenant_id, name, rule_language, rule_body, category, positive_fixtures, negative_fixtures) "
            "VALUES ($1,$2,'enc powershell','sigma','detection: {}','endpoint',$3::jsonb,$4::jsonb)",
            proposal_id,
            TENANT,
            json.dumps(positives),
            json.dumps(negatives),
        )
        row = await conn.fetchrow(
            "SELECT positive_fixtures, negative_fixtures FROM detection_rule_proposals WHERE id=$1",
            proposal_id,
        )
        assert json.loads(row["positive_fixtures"]) == positives
        assert json.loads(row["negative_fixtures"]) == negatives

    async def test_the_default_is_an_empty_list_not_null(self, conn) -> None:  # noqa: ANN001
        """An existing proposal predates the column. `[]` means "claims
        nothing"; NULL would make every reader handle a third state."""
        proposal_id = uuid.uuid4()
        await conn.execute(
            "INSERT INTO detection_rule_proposals (id, tenant_id, name, rule_language, rule_body, category) "
            "VALUES ($1,$2,'legacy','sigma','detection: {}','endpoint')",
            proposal_id,
            TENANT,
        )
        row = await conn.fetchrow(
            "SELECT positive_fixtures, negative_fixtures FROM detection_rule_proposals WHERE id=$1",
            proposal_id,
        )
        assert json.loads(row["positive_fixtures"]) == []
        assert json.loads(row["negative_fixtures"]) == []


class TestMarketplaceInstallsSurviveARestart:
    """Install state was a process dict, so it was lost on restart and
    disagreed between replicas: install, refresh, told it is not
    installed, install again."""

    async def test_an_install_persists(self, conn) -> None:  # noqa: ANN001
        item = f"det-{uuid.uuid4().hex[:8]}"
        await conn.execute(
            "INSERT INTO marketplace_installs (tenant_id, item_id, item_type, version) VALUES ($1,$2,'detection','1.0.0')",
            TENANT,
            item,
        )
        assert await conn.fetchval("SELECT count(*) FROM marketplace_installs WHERE tenant_id=$1 AND item_id=$2", TENANT, item) == 1

    async def test_reinstalling_does_not_duplicate(self, conn) -> None:  # noqa: ANN001
        """`UNIQUE (tenant_id, item_id)` plus ON CONFLICT is what makes a
        double-click across two replicas safe, which the lock around a
        process dict stopped guaranteeing the moment there were two."""
        item = f"det-{uuid.uuid4().hex[:8]}"
        for version in ("1.0.0", "1.1.0"):
            await conn.execute(
                "INSERT INTO marketplace_installs (tenant_id, item_id, item_type, version) "
                "VALUES ($1,$2,'detection',$3) "
                "ON CONFLICT (tenant_id, item_id) DO UPDATE SET version = EXCLUDED.version",
                TENANT,
                item,
                version,
            )
        rows = await conn.fetch("SELECT version FROM marketplace_installs WHERE tenant_id=$1 AND item_id=$2", TENANT, item)
        assert len(rows) == 1
        assert rows[0]["version"] == "1.1.0"

    async def test_one_tenants_installs_are_not_anothers(self, conn) -> None:  # noqa: ANN001
        item = f"det-{uuid.uuid4().hex[:8]}"
        await conn.execute(
            "INSERT INTO marketplace_installs (tenant_id, item_id, item_type) VALUES ($1,$2,'detection')",
            TENANT,
            item,
        )
        assert (
            await conn.fetchval(
                "SELECT count(*) FROM marketplace_installs WHERE tenant_id=$1 AND item_id=$2",
                OTHER_TENANT,
                item,
            )
            == 0
        )


class TestSlaEventsHaveSomethingToAggregate:
    """`alert_sla_events` had one writer: a manual POST nothing calls. So
    `services/api/app/services/sla.py` computed MTTD, MTTR and MTTC over an empty table on
    every deployment — correct arithmetic with no data."""

    async def test_a_detected_acknowledged_pair_yields_an_mttd(self, conn) -> None:  # noqa: ANN001
        alert_id = uuid.uuid4()
        detected = datetime.now(UTC) - timedelta(hours=2)
        acknowledged = detected + timedelta(minutes=30)
        for event_type, at in (("detected", detected), ("acknowledged", acknowledged)):
            await conn.execute(
                "INSERT INTO alert_sla_events (tenant_id, alert_id, severity, event_type, occurred_at) VALUES ($1,$2,'high',$3,$4)",
                TENANT,
                alert_id,
                event_type,
                at,
            )

        minutes = await conn.fetchval(
            """
            SELECT EXTRACT(EPOCH FROM (ack.occurred_at - det.occurred_at)) / 60
              FROM alert_sla_events det
              JOIN alert_sla_events ack
                ON ack.alert_id = det.alert_id AND ack.event_type = 'acknowledged'
             WHERE det.alert_id = $1 AND det.event_type = 'detected'
            """,
            alert_id,
        )
        assert minutes == pytest.approx(30.0, abs=0.5)

    async def test_the_event_type_vocabulary_is_enforced(self, conn) -> None:  # noqa: ANN001
        """A typo'd verb would store and then never match an aggregation,
        which is the quiet-failure shape this wave exists to remove."""
        asyncpg = pytest.importorskip("asyncpg")
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO alert_sla_events (tenant_id, alert_id, severity, event_type) VALUES ($1,$2,'high','acknowleged')",
                TENANT,
                uuid.uuid4(),
            )

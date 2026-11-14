"""An investigation is given the alerts, not a restatement of their title.

The defect
----------
`AlertDetailView` sent the literal string `"Investigate alert: <title>"`.
`InvestigateRequest` carried only `alert_summary`. The case's `alert_ids` were
written at creation and read by nothing. So the forensic agent reasoned over
one line of text, while **auto-triage -- the same agent, the other entry
point -- correctly passed the whole `raw_event`**. Two callers into one
investigator, one of them starved.

The evidence was never missing and the receiver was never unprepared:
`InvestigationRequest` on the agents side has declared `raw_alert` since it
was written, and threads it all the way to the orchestrator. Nothing sent it.

Why the API assembles it rather than the browser
------------------------------------------------
Two reasons, and the second is the stronger one. The browser does not hold
raw events. And it should not be trusted with what reaches a model prompt
even if it did -- an attacker-influenced payload arriving at an LLM is the
surface `PromptInjectionGuard` exists for, and narrowing it to data the
server loaded itself is cheaper than guarding it.

Live Postgres, because the fix is a query. A fake session that answers any
SELECT cannot tell a query that loads the alerts from one that does not.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0f100000-0000-0000-0000-00000000000a")


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the investigation-payload proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _reset(session)
        try:
            yield session
        finally:
            await _reset(session)
    await engine.dispose()


async def _reset(session) -> None:
    await session.rollback()
    await session.execute(text("DELETE FROM aisoc_cases WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.execute(text("DELETE FROM alerts WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


async def _seed(session, *, alert_count: int = 1, with_case_link: bool = True) -> tuple[uuid.UUID, list[uuid.UUID]]:
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Payload Test', 'payload-test') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    alert_ids: list[uuid.UUID] = []
    for n in range(alert_count):
        aid = uuid.uuid4()
        alert_ids.append(aid)
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, description, severity, status,
                                    connector_type, external_id, mitre_techniques, entities,
                                    raw_event, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :de, 'high', 'new',
                        'crowdstrike', :ext, CAST(:mt AS jsonb), CAST(:en AS jsonb),
                        CAST(:raw AS jsonb), NOW(), NOW())
                """
            ),
            {
                "i": str(aid),
                "t": str(TENANT),
                "ti": f"Suspicious PowerShell {n}",
                "de": "Encoded command observed",
                "ext": f"VENDOR-{n}",
                "mt": '["T1059.001"]',
                "en": '{"host": "WIN-SRV-01"}',
                # The distinctive value the test looks for downstream. If this
                # string reaches the agent, the raw event reached the agent.
                "raw": f'{{"CommandLine": "powershell -enc SQBFAFgA", "Image": "C:\\\\\\\\pwsh.exe", "marker": "needle-{n}"}}',
            },
        )

    cid = uuid.uuid4()
    await session.execute(
        text(
            """
            INSERT INTO aisoc_cases (id, tenant_id, case_number, title, description, status,
                                     priority, severity, alert_ids)
            VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :num, 'Suspicious PowerShell wave',
                    'Three hosts in one hour', 'new', 'high', 'high', :aids)
            """
        ),
        {
            "i": str(cid),
            "t": str(TENANT),
            "num": f"CASE-{cid.hex[:8]}",
            # A list, not a `{...}` literal: asyncpg binds a Python sequence
            # to a uuid[] and rejects the text form outright.
            "aids": [str(a) for a in alert_ids] if with_case_link else [],
        },
    )
    await session.commit()
    return cid, alert_ids


@pytest.mark.asyncio
class TestTheAgentGetsTheRealEvent:
    async def test_the_raw_event_reaches_the_payload(self, db) -> None:
        """The reproduction. `needle-0` exists only inside the alert's
        `raw_event`; if it is in the payload, the real telemetry is."""
        from app.api.v1.endpoints.cases import _investigation_evidence

        cid, _ = await _seed(db, alert_count=1)

        _, raw_alert = await _investigation_evidence(db, cid, TENANT)

        assert raw_alert, "no evidence was assembled at all"
        blob = str(raw_alert)
        assert "needle-0" in blob, "the alert's raw_event did not reach the payload"
        assert "powershell -enc" in blob

    async def test_alert_metadata_travels_with_it(self, db) -> None:
        """The raw event alone loses what AiSOC added -- severity, the
        technique, the entity, which connector supplied it."""
        from app.api.v1.endpoints.cases import _investigation_evidence

        cid, _ = await _seed(db, alert_count=1)

        _, raw_alert = await _investigation_evidence(db, cid, TENANT)
        alert = raw_alert["alerts"][0]

        assert alert["severity"] == "high"
        assert alert["source"] == "crowdstrike"
        assert alert["vendor_id"] == "VENDOR-0"
        assert "T1059.001" in alert["mitre_techniques"]
        assert alert["entities"] == {"host": "WIN-SRV-01"}

    async def test_every_correlated_alert_is_included(self, db) -> None:
        from app.api.v1.endpoints.cases import _investigation_evidence

        cid, alert_ids = await _seed(db, alert_count=4)

        _, raw_alert = await _investigation_evidence(db, cid, TENANT)

        assert raw_alert["alerts_included"] == 4
        assert raw_alert["alert_count"] == len(alert_ids)
        assert raw_alert["truncated"] is False

    async def test_the_summary_describes_the_alerts_not_just_the_title(self, db) -> None:
        from app.api.v1.endpoints.cases import _investigation_evidence

        cid, _ = await _seed(db, alert_count=2)

        summary, _ = await _investigation_evidence(db, cid, TENANT)

        assert "Suspicious PowerShell wave" in summary
        assert "correlated alert" in summary
        assert "crowdstrike" in summary


@pytest.mark.asyncio
class TestItStaysHonestWhenThereIsNothing:
    async def test_a_case_with_no_alerts_sends_no_evidence(self, db) -> None:
        """`{}`, not a plausible-looking empty shape. A case opened by hand
        has no telemetry, and the groundedness gate reads this -- handing it
        a skeleton to score against is how a gate certifies anything."""
        from app.api.v1.endpoints.cases import _investigation_evidence

        cid, _ = await _seed(db, alert_count=0, with_case_link=False)

        summary, raw_alert = await _investigation_evidence(db, cid, TENANT)

        assert raw_alert == {}
        assert "Suspicious PowerShell wave" in summary

    async def test_another_tenants_case_yields_nothing(self, db) -> None:
        from app.api.v1.endpoints.cases import _investigation_evidence

        cid, _ = await _seed(db, alert_count=1)

        summary, raw_alert = await _investigation_evidence(db, cid, uuid.uuid4())

        assert raw_alert == {}
        assert summary == ""

    async def test_alerts_are_tenant_scoped(self, db) -> None:
        """The case is the caller's and the alert ids are attacker-suppliable
        in principle, so the alert query carries its own tenant predicate
        rather than trusting the case row."""
        import inspect

        from app.api.v1.endpoints import cases

        source = inspect.getsource(cases._investigation_evidence)
        alert_query = source[source.index("FROM alerts") :]

        assert "tenant_id = :tenant_id" in alert_query


class TestTheReceiverWasAlwaysReady:
    """The shape of this defect: nothing was missing except the call."""

    def test_the_agents_request_model_declares_raw_alert(self) -> None:
        from pathlib import Path

        router = Path(__file__).resolve().parents[3] / "services" / "agents" / "app" / "api" / "investigate.py"
        if not router.is_file():
            pytest.skip("services/agents is not present in this checkout")

        assert "raw_alert" in router.read_text(encoding="utf-8")

    def test_the_proxy_now_sends_it(self) -> None:
        import inspect

        from app.api.v1.endpoints import cases

        source = inspect.getsource(cases.case_investigate)

        assert '"raw_alert"' in source, "the proxy still forwards only a summary"

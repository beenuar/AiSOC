"""The citations land in the ledger, and an auditor can find them.

Depth 7.2 says the analysis is "cited in the ledger". That is a claim about
rows, so it is tested against rows. The ledger's immutability trigger, the
``(run_id, seq)`` unique constraint and the tenant foreign keys are all
properties of the real schema; a session double would answer whatever it was
asked and prove none of them.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.services.phishing.analysis import ArtefactResult, MessageAnalysis, cite_to_ledger
from app.services.phishing.headers import analyse_headers
from app.services.phishing.intake import ReportedMessage
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-00000000007b")
PHISH = "billing@phish.example.net"

HEADERS = {
    "from": f'"Billing Dept" <{PHISH}>',
    "to": "alice@example.com",
    "reply-to": "accounts@attacker.example.org",
    "authentication-results": "mx.example.com; spf=fail; dkim=none; dmarc=fail",
    "received": "from mx1.example.com by mail.example.com",
}


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
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at DATABASE_URL: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            text("""
                INSERT INTO tenants (id, name, slug)
                VALUES (:id, 'Depth 7.2 analysis', 'depth-72-analysis')
                ON CONFLICT (id) DO NOTHING
            """).bindparams(id=TENANT)
        )
        await session.commit()
        yield session
    await engine.dispose()


# There is deliberately no teardown that removes ledger rows. The first
# attempt at one failed with `investigation_events rows are immutable
# (attempted DELETE)`: the FK from events to runs is ON DELETE CASCADE, so
# deleting a run asks Postgres to delete its events, and migration 008's
# trigger refuses. That is the append-only control working exactly as
# designed, and writing a test fixture that defeats it would be the wrong
# fix. Every assertion below is scoped by the `run_id` its own call
# returned, so the rows accumulating between runs cannot affect it.


def _message() -> ReportedMessage:
    return ReportedMessage(
        intake_source="m365_graph",
        internet_message_id="<cited@phish.example.net>",
        sender=PHISH,
        subject="Invoice overdue",
        headers=HEADERS,
    )


def _analysis(*, analysed: int = 0, unanalysed: int = 0) -> MessageAnalysis:
    urls = [
        ArtefactResult(kind="url", value=f"https://a{i}.example.net", outcome="known", detail="clean", verdict="benign")
        for i in range(analysed)
    ]
    urls += [
        ArtefactResult(
            kind="url",
            value=f"https://b{i}.example.net",
            outcome="no_provider",
            detail="not analysed: no provider is configured. This is not a clean verdict.",
        )
        for i in range(unanalysed)
    ]
    return MessageAnalysis(headers=analyse_headers(HEADERS), urls=urls)


@pytest.mark.asyncio
async def test_one_run_and_one_event_per_component(db) -> None:
    submission_id = uuid.uuid4()
    run_id = await cite_to_ledger(db, tenant_id=TENANT, submission_id=submission_id, message=_message(), analysis=_analysis())
    await db.commit()

    assert run_id is not None
    run = (await db.execute(text("SELECT case_id, status FROM investigation_runs WHERE id = :i").bindparams(i=run_id))).fetchone()
    assert run.case_id == f"phishing-submission:{submission_id}"
    assert run.status == "completed"

    rows = (
        await db.execute(
            text("SELECT seq, kind, agent, summary, payload FROM investigation_events WHERE run_id = :i ORDER BY seq").bindparams(i=run_id)
        )
    ).fetchall()
    assert [r.seq for r in rows] == [1, 2, 3], "seq must be dense from one; the unique constraint makes a gap a write failure"
    assert {r.kind for r in rows} == {"evidence_cited"}
    assert {r.agent for r in rows} == {"aisoc-phishing-analysis"}
    assert [r.payload["component"] for r in rows] == ["headers", "urls", "attachments"]


@pytest.mark.asyncio
async def test_the_header_citation_records_what_was_not_evaluated(db) -> None:
    run_id = await cite_to_ledger(db, tenant_id=TENANT, submission_id=uuid.uuid4(), message=_message(), analysis=_analysis())
    await db.commit()
    payload = (
        (await db.execute(text("SELECT payload FROM investigation_events WHERE run_id = :i AND seq = 1").bindparams(i=run_id)))
        .fetchone()
        .payload
    )
    assert sorted(payload["failed"]) == ["dmarc", "spf"]
    assert payload["not_evaluated"] == ["dkim"]
    assert payload["hop_count"] == 1
    assert any(f["kind"] == "reply_to_redirect" for f in payload["findings"])


@pytest.mark.asyncio
async def test_an_unanalysed_url_is_cited_as_unanalysed(db) -> None:
    """The row an auditor reads must not be able to imply a clean result."""
    run_id = await cite_to_ledger(
        db, tenant_id=TENANT, submission_id=uuid.uuid4(), message=_message(), analysis=_analysis(analysed=1, unanalysed=2)
    )
    await db.commit()
    row = (
        await db.execute(text("SELECT summary, payload FROM investigation_events WHERE run_id = :i AND seq = 2").bindparams(i=run_id))
    ).fetchone()
    assert row.payload["analysed"] == 1
    assert row.payload["unanalysed"] == 2
    assert "not a clean verdict" in row.summary
    assert all("not a clean verdict" in item["detail"] for item in row.payload["items"] if item["outcome"] == "no_provider")


@pytest.mark.asyncio
async def test_the_citations_are_immutable_once_written(db) -> None:
    """Asserted against the real trigger, which a session double does not have."""
    run_id = await cite_to_ledger(db, tenant_id=TENANT, submission_id=uuid.uuid4(), message=_message(), analysis=_analysis())
    await db.commit()
    with pytest.raises(Exception, match="immutable"):
        await db.execute(text("UPDATE investigation_events SET summary = 'edited' WHERE run_id = :i").bindparams(i=run_id))
    await db.rollback()


@pytest.mark.asyncio
async def test_an_unwritable_ledger_returns_none_rather_than_raising(db) -> None:
    """An uncitable analysis is still an analysis, and the caller is told.

    A tenant id with no row violates the foreign key, which is the closest
    reachable analogue of a ledger that will not accept a write.
    """
    analysis = _analysis()
    run_id = await cite_to_ledger(db, tenant_id=uuid.uuid4(), submission_id=uuid.uuid4(), message=_message(), analysis=analysis)
    await db.rollback()
    assert run_id is None
    assert analysis.run_id is None


@pytest.mark.asyncio
async def test_the_submission_columns_migration_111_added_accept_the_analysis(db) -> None:
    """The second half of 'which code path writes this': the columns have a writer."""
    submission_id = uuid.uuid4()
    await db.execute(
        text("""
            INSERT INTO aisoc_phishing_submissions
                (id, tenant_id, artifact_kind, verdict, headers, auth_results, analysed_at,
                 artefacts_analysed, artefacts_unanalysed)
            VALUES (:id, :t, 'email', 'phishing', CAST(:h AS jsonb), CAST(:a AS jsonb), now(), 1, 2)
        """).bindparams(
            id=submission_id,
            t=TENANT,
            h='{"from": "x@example.net"}',
            a='{"spf": "fail", "dkim": "not_evaluated", "dmarc": "fail"}',
        )
    )
    await db.commit()
    row = (
        await db.execute(
            text(
                "SELECT auth_results, artefacts_analysed, artefacts_unanalysed, analysed_at FROM aisoc_phishing_submissions WHERE id = :i"
            ).bindparams(i=submission_id)
        )
    ).fetchone()
    assert row.auth_results["dkim"] == "not_evaluated"
    assert (row.artefacts_analysed, row.artefacts_unanalysed) == (1, 2)
    assert row.analysed_at is not None
    await db.execute(text("DELETE FROM aisoc_phishing_submissions WHERE id = :i").bindparams(i=submission_id))
    await db.commit()

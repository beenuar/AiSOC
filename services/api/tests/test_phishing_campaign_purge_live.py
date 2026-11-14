"""A 25-recipient campaign, against a real database, graded and previewed.

This is the gap-closure plan's own "Done when" turned into a test: *against a
mocked Graph API, a 25-recipient phishing campaign yields one purge proposal
that requires approval, executes once approved, verifies the messages are
gone, and can be reversed.*

Why it needs a real Postgres
-----------------------------
The two things under test are both properties of rows:
``ON CONFLICT (tenant_id, grouping_key)`` joining a second report to the first
report's campaign, and ``recipient_count`` being recomputed from the recipient
table rather than incremented. A fake session that answers whatever is asked
cannot show either — it is the shape that had a fake playbook store match
every event name while matching none of the 64 shipped playbooks. So this
skips without a database rather than passing without one.

The vendor half is mocked, deliberately and visibly
----------------------------------------------------
``dispatch_step`` is replaced with a recorder, so what is asserted is the
**fan-out**: one dispatch per mailbox, every one carrying the campaign's
recipient count so the dispatcher grades it at the campaign's tier rather
than as a one-recipient purge. The executor half — that the dispatch reaches
Graph, moves to recoverable items and reads the mailbox back — is asserted
against real HTTP in
``services/actions/tests/test_mailbox_remediation.py``, because the two
services cannot share an interpreter: both name their top-level package
``app``.

**No Microsoft 365 or Google Workspace tenant was exercised.** Every vendor
claim in this phase rests on the documented request shape and a respx mock.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest
import pytest_asyncio
from app.services.phishing import purge as phishing_purge
from app.services.phishing.campaigns import record_report
from app.services.phishing.intake import ReportedMessage
from app.services.phishing.purge import grade, propose_purge, restore_campaign
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-00000000007a")
SENDER = "billing@phish.example.net"
MESSAGE_ID = "<CAF.20261011.0700@mail.example.net>"
RECIPIENTS = tuple(f"user{i:02d}@example.com" for i in range(25))


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
        await _seed_tenant(session)
        await _reset(session)
        try:
            yield session
        finally:
            await _reset(session)
    await engine.dispose()


async def _seed_tenant(session) -> None:
    await session.execute(
        text("""
            INSERT INTO tenants (id, name, slug)
            VALUES (:id, 'Depth 7.1 phishing', 'depth-71-phishing')
            ON CONFLICT (id) DO NOTHING
        """).bindparams(id=TENANT)
    )
    await session.commit()


async def _reset(session) -> None:
    # Children first: the recipient rows cascade, but deleting explicitly
    # keeps the reset readable and independent of the FK's ON DELETE.
    await session.execute(text("DELETE FROM aisoc_phishing_campaign_recipients WHERE tenant_id = :t").bindparams(t=TENANT))
    await session.execute(text("DELETE FROM aisoc_phishing_campaigns WHERE tenant_id = :t").bindparams(t=TENANT))
    await session.execute(text("DELETE FROM aisoc_phishing_submissions WHERE tenant_id = :t").bindparams(t=TENANT))
    await session.commit()


def _message(*, recipients: tuple[str, ...] = RECIPIENTS, message_id: str = MESSAGE_ID, subject: str = "Invoice 10452 overdue"):
    return ReportedMessage(
        intake_source="m365_graph",
        internet_message_id=message_id,
        sender=SENDER,
        subject=subject,
        recipients=recipients,
        reported_by=recipients[0] if recipients else "",
    )


@dataclass
class _Dispatch:
    """What one call to ``dispatch_step`` was asked to do."""

    capability: str
    target: str
    params: dict[str, Any]
    dry_run: bool


@dataclass
class _Recorder:
    """Stands in for ``dispatch_step`` and records the fan-out.

    ``executed`` is set from ``dry_run`` so a preview can never be recorded
    as a purge — the recorder cannot be more permissive than the real
    dispatcher on the one property this test is about.
    """

    calls: list[_Dispatch] = field(default_factory=list)
    #: Mailboxes that do not hold the message, to exercise ``not_found``.
    missing: frozenset[str] = frozenset()

    async def __call__(self, db, **kwargs):
        from app.services.playbook_step_dispatch import StepDispatchReport

        call = _Dispatch(
            capability=kwargs["capability"],
            target=kwargs["target"],
            params=dict(kwargs.get("params") or {}),
            dry_run=bool(kwargs.get("dry_run", True)),
        )
        self.calls.append(call)
        if call.dry_run:
            return StepDispatchReport(
                capability=call.capability,
                status="simulated",
                executed=False,
                summary=f"would {call.capability} for {call.target}",
                vendor_id="m365",
            )
        if call.target in self.missing:
            return StepDispatchReport(
                capability=call.capability,
                status="failed",
                executed=False,
                summary="not found",
                detail="The message was not found in this mailbox, so nothing was purged.",
                vendor_id="m365",
            )
        return StepDispatchReport(
            capability=call.capability,
            status="executed",
            executed=True,
            summary=f"{call.capability} on {call.target}",
            vendor_id="m365",
            verification="verified",
            details={"restore_message_id": f"restored-{call.target}", "restore_folder_id": "inbox"},
        )


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(phishing_purge, "dispatch_step", rec)
    return rec


# ───────────────────────── grouping over real rows ───────────────────────


@pytest.mark.asyncio
async def test_two_reports_of_one_message_join_one_campaign(db) -> None:
    first = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:3]))
    second = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[2:6]))
    await db.commit()

    assert first is not None and second is not None
    assert first.id == second.id, "the same internet message id must not create two campaigns"
    assert second.created is False
    assert second.report_count == 2
    # Three plus four with one overlap: six mailboxes, not seven. An
    # incremented counter and a de-duplicating insert disagree here, and the
    # counter is what decides the approval tier.
    assert second.recipient_count == 6


@pytest.mark.asyncio
async def test_a_second_report_does_not_reset_a_purge_state_the_first_one_set(db, recorder) -> None:
    """The ON CONFLICT DO NOTHING claim, which a fake session cannot show."""
    campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:2]))
    await db.commit()
    assert campaign is not None
    await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=0.99, tier="L4", execute=True)

    await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:2]))
    await db.commit()

    states = (
        await db.execute(
            text("SELECT purge_state FROM aisoc_phishing_campaign_recipients WHERE campaign_id = :c").bindparams(c=campaign.id)
        )
    ).fetchall()
    assert {r.purge_state for r in states} == {"purged"}


@pytest.mark.asyncio
async def test_a_different_message_from_the_same_sender_is_a_different_campaign_when_ids_differ(db) -> None:
    """The message id outranks the sender, and that is the stronger claim."""
    a = await record_report(db, tenant_id=TENANT, message=_message(message_id="<a@example.net>"))
    b = await record_report(db, tenant_id=TENANT, message=_message(message_id="<b@example.net>"))
    await db.commit()
    assert a is not None and b is not None
    assert a.id != b.id
    assert a.grouping_basis == b.grouping_basis == "internet_message_id"


# ───────────────────────── the graded proposal ───────────────────────────


class TestTheProposalIsGradedOnceOnTheRecipientCount:
    @pytest.mark.asyncio
    async def test_twenty_five_recipients_require_a_human_at_any_tier_and_any_confidence(self, db, recorder) -> None:
        """The gap-closure 'Done when', literally."""
        campaign = await record_report(db, tenant_id=TENANT, message=_message())
        await db.commit()
        assert campaign is not None and campaign.recipient_count == 25

        for tier in ("L0", "L1", "L2", "L3", "L4"):
            outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier=tier)
            assert outcome is not None
            assert outcome.recipient_count == 25
            assert outcome.requested_impact == "severe"
            assert outcome.approval_requirement == "mandatory_human"

    @pytest.mark.asyncio
    async def test_a_four_recipient_campaign_is_graded_lower_than_a_twenty_five(self, db, recorder) -> None:
        """The negative control for the ladder: if it did not scale, these would match."""
        small = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:4]))
        await db.commit()
        assert small is not None
        outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=small.id, confidence=1.0, tier="L4")
        assert outcome is not None
        assert outcome.requested_impact == "moderate"
        assert outcome.approval_requirement == "analyst"

    def test_the_proposal_and_the_dispatcher_read_the_same_grading(self) -> None:
        """One function, so the approver and the executor cannot see different actions."""
        from app._vendor.action_contracts.capability_contracts import scaled_impact

        for count in (1, 4, 5, 24, 25, 500):
            impact, _requirement, _reason = grade(count, 1.0, "L4")
            assert impact == scaled_impact("purge_email", {"recipient_count": count}).value


# ───────────────────────── the fan-out ───────────────────────────────────


class TestOneDispatchPerMailbox:
    @pytest.mark.asyncio
    async def test_a_preview_dispatches_once_per_recipient_and_executes_nothing(self, db, recorder) -> None:
        campaign = await record_report(db, tenant_id=TENANT, message=_message())
        await db.commit()
        assert campaign is not None

        outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4")

        assert outcome is not None
        assert len(recorder.calls) == 25
        assert {c.target for c in recorder.calls} == set(RECIPIENTS)
        assert all(c.dry_run for c in recorder.calls)
        assert outcome.executed_count == 0
        assert {r.purge_state for r in outcome.recipients} == {"simulated"}

    @pytest.mark.asyncio
    async def test_every_dispatch_carries_the_campaigns_recipient_count(self, db, recorder) -> None:
        """Otherwise the dispatcher grades each mailbox as a one-recipient purge.

        That is the quiet way a SEVERE action becomes a MODERATE one: the
        proposal says mandatory_human, and each dispatch underneath it
        clears an analyst floor on its own.
        """
        campaign = await record_report(db, tenant_id=TENANT, message=_message())
        await db.commit()
        assert campaign is not None
        await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4")
        assert {c.params.get("recipient_count") for c in recorder.calls} == {25}

    @pytest.mark.asyncio
    async def test_a_preview_never_advances_the_campaign_past_proposed(self, db, recorder) -> None:
        campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:2]))
        await db.commit()
        assert campaign is not None
        outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4")
        assert outcome is not None and outcome.status == "purge_proposed"
        row = (await db.execute(text("SELECT status FROM aisoc_phishing_campaigns WHERE id = :i").bindparams(i=campaign.id))).fetchone()
        assert row.status == "purge_proposed"


class TestWhatCountsAsPurged:
    @pytest.mark.asyncio
    async def test_a_mailbox_without_the_message_is_not_found_not_purged(self, db, recorder) -> None:
        recorder.missing = frozenset(RECIPIENTS[:5])
        campaign = await record_report(db, tenant_id=TENANT, message=_message())
        await db.commit()
        assert campaign is not None

        outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4", execute=True)

        assert outcome is not None
        assert outcome.executed_count == 20
        states = {r.recipient: r.purge_state for r in outcome.recipients}
        assert all(states[m] == "not_found" for m in RECIPIENTS[:5])
        # Twenty of twenty-five is not a purge, and publishing it as one
        # teaches an analyst to trust a number that means nothing.
        assert outcome.status == "partially_purged"

    @pytest.mark.asyncio
    async def test_every_mailbox_purged_lands_on_purged(self, db, recorder) -> None:
        campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:3]))
        await db.commit()
        assert campaign is not None
        outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4", execute=True)
        assert outcome is not None
        assert outcome.status == "purged"
        assert outcome.executed_count == 3


# ───────────────────────── the reversal ──────────────────────────────────


class TestTheCampaignCanBeReversed:
    @pytest.mark.asyncio
    async def test_restore_runs_over_the_mailboxes_the_purge_executed_on(self, db, recorder) -> None:
        recorder.missing = frozenset(RECIPIENTS[:5])
        campaign = await record_report(db, tenant_id=TENANT, message=_message())
        await db.commit()
        assert campaign is not None
        await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4", execute=True)
        recorder.calls.clear()

        outcome = await restore_campaign(db, tenant_id=TENANT, campaign_id=campaign.id)

        assert outcome is not None
        # Twenty, not twenty-five: restoring a mailbox that never held the
        # message would report work that did not happen.
        assert len(recorder.calls) == 20
        assert all(c.capability == "restore_email" for c in recorder.calls)
        assert outcome.executed_count == 20
        assert outcome.status == "restored"

    @pytest.mark.asyncio
    async def test_the_restore_handles_the_purge_stored_reach_the_dispatch(self, db, recorder) -> None:
        """Microsoft's move gives the message a new id; without it the rollback guesses."""
        campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:2]))
        await db.commit()
        assert campaign is not None
        await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4", execute=True)
        recorder.calls.clear()
        await restore_campaign(db, tenant_id=TENANT, campaign_id=campaign.id)

        assert {c.params["restore_message_id"] for c in recorder.calls} == {f"restored-{m}" for m in RECIPIENTS[:2]}
        assert {c.params["restore_folder_id"] for c in recorder.calls} == {"inbox"}

    @pytest.mark.asyncio
    async def test_restoring_a_previewed_campaign_dispatches_nothing(self, db, recorder) -> None:
        campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:3]))
        await db.commit()
        assert campaign is not None
        await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4")
        recorder.calls.clear()
        outcome = await restore_campaign(db, tenant_id=TENANT, campaign_id=campaign.id)
        assert outcome is not None
        assert recorder.calls == []
        assert outcome.executed_count == 0


# ───────────────────────── honest empty states ───────────────────────────


@pytest.mark.asyncio
async def test_a_campaign_with_no_recipients_reports_so_rather_than_succeeding(db, recorder) -> None:
    """How somebody notices an intake adapter that stopped parsing a To header."""
    campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=()))
    await db.commit()
    assert campaign is not None and campaign.recipient_count == 0
    outcome = await propose_purge(db, tenant_id=TENANT, campaign_id=campaign.id, confidence=1.0, tier="L4", execute=True)
    assert outcome is not None
    assert outcome.recipient_count == 0
    assert outcome.executed_count == 0
    assert recorder.calls == []


@pytest.mark.asyncio
async def test_an_unknown_campaign_is_none_so_the_route_can_404(db, recorder) -> None:
    assert await propose_purge(db, tenant_id=TENANT, campaign_id=uuid.uuid4()) is None
    assert await restore_campaign(db, tenant_id=TENANT, campaign_id=uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_another_tenants_campaign_is_invisible(db, recorder) -> None:
    """Query-layer scoping, asserted rather than assumed from the RLS policy."""
    campaign = await record_report(db, tenant_id=TENANT, message=_message(recipients=RECIPIENTS[:2]))
    await db.commit()
    assert campaign is not None
    assert await propose_purge(db, tenant_id=uuid.uuid4(), campaign_id=campaign.id) is None

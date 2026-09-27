"""The promotion gate, end to end, against a real database.

Gap-closure Phase 2.3. This is the phase's "Done when", run rather than
reasoned about:

    on recorded data, a test tenant cannot enable auto-close for a class with
    20 shadow decisions, can once the thresholds are met, and is demoted when
    injected disagreements cross the drift threshold.

Why it lives here and not in a service suite
--------------------------------------------

The unit tests in ``services/actions`` prove the arithmetic and the unit tests
in ``services/api`` prove the statements are built correctly, and between them
they still would not catch the failure that matters most: an aggregate that
counts something slightly different from what the evaluator expects. The SQL
and the evaluator agree by convention, and a convention is what drifts. Only a
real Postgres executing the real statement over real rows closes that, so this
suite seeds decisions, runs the production aggregate over them and asks the
production gate what it thinks.

It is also the only place the audit trail can be checked properly. The hash
chain is computed on insert from the previous row for the same tenant, so a
mocked session cannot tell you whether a promotion, an override and a
demotion actually chain.

Skipping
--------

Skips when no Postgres answers, and refuses to skip when
``AUTONOMY_PROMOTION_LIVE_REQUIRED`` is set, following
``test_postgres_rls.py``. A suite that can silently skip where it is supposed
to run is a suite that reports green for a gate nobody executed.
"""

from __future__ import annotations

import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("AUTONOMY_PROMOTION_LIVE_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        "postgres" not in DSN and not REQUIRED,
        reason="no Postgres DATABASE_URL; set AUTONOMY_PROMOTION_LIVE_REQUIRED=1 to make this a failure",
    ),
]

#: Fixed so a failure is reproducible. Every decision below is written out
#: rather than generated from a distribution: "recorded data" means a reader
#: can count the rows that produced a verdict, and a random corpus that
#: happened to cross a threshold would be evidence about the seed.
CLASS = "identity"
RULE = "det-identity-004"
SOURCE = "okta"
MODEL = "ollama_chat/llama3.2:3b"

MALICIOUS = "true_positive"
FALSE_POSITIVE = "false_positive"
NEEDS_REVIEW = "needs_review"


def _sqlalchemy_url(url: str) -> str:
    """Whatever spelling the environment holds, as an asyncpg SQLAlchemy URL."""
    if url.startswith("postgresql+asyncpg://"):
        return url
    return re.sub(r"^postgres(ql)?://", "postgresql+asyncpg://", url)


#: A module-scoped *async* fixture binds itself to one event loop and
#: pytest-asyncio gives each test a fresh one, so the setup is an async context
#: manager entered inside each test instead. Same reason, and the same shape,
#: as ``test_postgres_rls.py``.
@asynccontextmanager
async def probe():
    """A tenant, an operator, shadow mode on for one class, and a bound session.

    Everything it creates it deletes, in foreign-key order, so a failing test
    does not poison the next one with rows the aggregate would count.
    """
    sqlalchemy_asyncio = pytest.importorskip("sqlalchemy.ext.asyncio")
    from sqlalchemy import text

    engine = sqlalchemy_asyncio.create_async_engine(_sqlalchemy_url(DSN), pool_pre_ping=True)
    maker = sqlalchemy_asyncio.async_sessionmaker(engine, expire_on_commit=False)
    session = maker()
    try:
        try:
            await session.execute(text("SELECT 1 FROM aisoc_autonomy_grants LIMIT 0"))
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            if REQUIRED:
                pytest.fail(f"migration 067 has not been applied: {exc}")
            pytest.skip(f"aisoc_autonomy_grants is absent: {exc}")

        tenant_id = uuid.uuid4()
        slug = f"promo-{tenant_id.hex[:10]}"
        await session.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug)"),
            {"id": tenant_id, "name": "Promotion gate probe", "slug": slug},
        )
        user_id = uuid.uuid4()
        await session.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active)
                VALUES (:id, :tenant_id, :email, :username, 'x', 'tenant_admin', TRUE)
                """
            ),
            {"id": user_id, "tenant_id": tenant_id, "email": f"{slug}@example.com", "username": slug},
        )
        await session.execute(
            text(
                """
                INSERT INTO aisoc_shadow_mode (tenant_id, alert_class, enabled, enabled_at)
                VALUES (:tenant_id, :alert_class, TRUE, now())
                """
            ),
            {"tenant_id": tenant_id, "alert_class": CLASS},
        )
        await session.commit()
        try:
            yield session, tenant_id, user_id
        finally:
            # The evidence and the grants, and nothing that the audit trail
            # hangs off. `audit_log` refuses a DELETE by trigger;
            # `audit_log.tenant_id` cascades from `tenants` and
            # `audit_log.actor_id` is `ON DELETE SET NULL` from `users`, so
            # removing either one reaches the trigger as a delete or an update
            # and is refused. Working around that here would mean
            # demonstrating the hole the trigger closes, so the probe leaves
            # the tenant and the operator behind. Each run uses a fresh tenant
            # UUID and every aggregate is tenant-scoped, so the residue cannot
            # reach another test. `test_the_audit_trail_cannot_be_deleted`
            # asserts the refusal rather than treating it as an inconvenience.
            for table in ("aisoc_autonomy_grants", "aisoc_shadow_decisions", "aisoc_shadow_mode"):
                await session.execute(text(f"DELETE FROM {table} WHERE tenant_id = :t"), {"t": tenant_id})
            await session.commit()
    finally:
        await session.close()
        await engine.dispose()


async def _record(
    session,
    tenant_id: uuid.UUID,
    *,
    count: int,
    verdict: str,
    disposition: str,
    resolved_at: datetime,
    spacing_seconds: int = 60,
) -> None:
    """Write ``count`` decisions that all said ``verdict`` and were closed ``disposition``.

    ``resolved_at`` advances, because the trailing drift slice is ordered by
    it. Rows written with one timestamp would make "the most recent 50" an
    arbitrary 50.
    """
    from sqlalchemy import text

    for index in range(count):
        await session.execute(
            text(
                """
                INSERT INTO aisoc_shadow_decisions
                    (tenant_id, alert_id, alert_class, rule_id, source, model, verdict,
                     confidence, decided_at, analyst_disposition, resolution_source, resolved_at)
                VALUES
                    (:tenant_id, :alert_id, :alert_class, :rule_id, :source, :model, :verdict,
                     0.91, :resolved_at, :disposition, 'aisoc', :resolved_at)
                """
            ),
            {
                "tenant_id": tenant_id,
                "alert_id": uuid.uuid4(),
                "alert_class": CLASS,
                "rule_id": RULE,
                "source": SOURCE,
                "model": MODEL,
                "verdict": verdict,
                "disposition": disposition,
                "resolved_at": resolved_at + timedelta(seconds=index * spacing_seconds),
            },
        )
    await session.commit()


async def _promote(session, tenant_id, user_id, **kwargs):
    from app.services.autonomy_grants import request_promotion

    return await request_promotion(
        session,
        tenant_id=tenant_id,
        actor_id=user_id,
        actor_email="probe@example.com",
        scope_kind="alert_class",
        scope_key=CLASS,
        capability="auto_close",
        **kwargs,
    )


async def _audit_actions(session, tenant_id) -> list[str]:
    from sqlalchemy import text

    rows = (
        (
            await session.execute(
                text("SELECT action FROM audit_log WHERE tenant_id = :t ORDER BY created_at, id"),
                {"t": tenant_id},
            )
        )
        .scalars()
        .all()
    )
    return [str(row) for row in rows]


class TestTheDoneWhen:
    async def test_twenty_decisions_cannot_enable_auto_close(self):
        """The first clause. Twenty perfect decisions are not a track record."""
        async with probe() as (session, tenant_id, user_id):
            base = datetime.now(UTC) - timedelta(days=5)
            await _record(session, tenant_id, count=12, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(session, tenant_id, count=8, verdict=MALICIOUS, disposition=MALICIOUS, resolved_at=base + timedelta(hours=1))

            transition = await _promote(session, tenant_id, user_id)

            assert transition.granted is False
            assert "insufficient_sample" in transition.refusal_values
            assert "insufficient_malicious" in transition.refusal_values
            # Every count that produced the refusal travels with it, so the
            # operator is told the distance rather than only the verdict.
            window = transition.evidence["window"]
            assert window["labelled"] == 20
            assert window["malicious_support"] == 8
            assert transition.evidence["thresholds"]["min_decisions"] == 100
            # A refusal is not a state change, so nothing was written.
            assert await _audit_actions(session, tenant_id) == []

    async def test_once_the_thresholds_are_met_it_is_granted(self):
        """The second clause, and the evidence snapshot that justifies it."""
        async with probe() as (session, tenant_id, user_id):
            base = datetime.now(UTC) - timedelta(days=10)
            # 150 decisions: 110 false positives agreed, 36 malicious of which 34
            # were caught, and 4 abstentions. Agreement 144/146 = 98.6%, recall
            # 34/36 = 94.4%, abstention 4/150 = 2.7%. Every floor cleared.
            await _record(session, tenant_id, count=110, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(
                session,
                tenant_id,
                count=34,
                verdict=MALICIOUS,
                disposition=MALICIOUS,
                resolved_at=base + timedelta(days=1),
            )
            await _record(
                session,
                tenant_id,
                count=2,
                verdict=FALSE_POSITIVE,
                disposition=MALICIOUS,
                resolved_at=base + timedelta(days=2),
            )
            await _record(
                session,
                tenant_id,
                count=4,
                verdict=NEEDS_REVIEW,
                disposition=FALSE_POSITIVE,
                resolved_at=base + timedelta(days=3),
            )

            transition = await _promote(session, tenant_id, user_id)

            assert transition.granted is True, transition.refusal_values
            assert transition.source == "earned"
            assert transition.refusals == ()

            window = transition.evidence["window"]
            assert window["labelled"] == 150
            assert window["answered"] == 146
            assert window["agreed"] == 144
            assert window["malicious_support"] == 36
            assert window["malicious_caught"] == 34
            assert window["agreement_rate"] == pytest.approx(144 / 146)
            assert window["malicious_recall"] == pytest.approx(34 / 36)

            # The snapshot has to still explain this in six months.
            evidence = transition.evidence
            assert evidence["thresholds"]["min_agreement"] == 0.95
            assert datetime.fromisoformat(evidence["window_start"]) < datetime.fromisoformat(evidence["window_end"])
            assert evidence["first_decision_id"] and evidence["last_decision_id"]
            assert evidence["models"] == [MODEL]
            assert evidence["resolution_sources"] == ["aisoc"]
            assert len(evidence["rules_digest"]) == 64

            assert await _audit_actions(session, tenant_id) == ["autonomy:granted"]

    async def test_injected_disagreements_demote_it(self):
        """The third clause: drift that the window average is still absorbing.

        The tenant is granted on a strong 30-day record, then 30 recent
        disagreements are injected. The *window* still passes comfortably:
        that is the whole point, and a gate reading only the window would
        leave this grant standing.
        """
        async with probe() as (session, tenant_id, user_id):
            from app.services.autonomy_grants import reconcile_grants
            from app.services.shadow_agreement import agreement_for

            base = datetime.now(UTC) - timedelta(days=20)
            await _record(session, tenant_id, count=200, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(
                session,
                tenant_id,
                count=40,
                verdict=MALICIOUS,
                disposition=MALICIOUS,
                resolved_at=base + timedelta(days=1),
            )
            granted = await _promote(session, tenant_id, user_id)
            assert granted.granted is True, granted.refusal_values

            # Nothing has changed yet, so a re-check leaves it alone.
            assert await reconcile_grants(session, tenant_id) == []

            # 30 recent disagreements. Against 240 earlier decisions the window
            # agreement is 240/270 = 88.9%, and the trailing 50 is 20/50 = 40%.
            await _record(
                session,
                tenant_id,
                count=30,
                verdict=FALSE_POSITIVE,
                disposition=MALICIOUS,
                resolved_at=datetime.now(UTC) - timedelta(minutes=30),
            )

            evidence = await agreement_for(session, tenant_id, scope_kind="alert_class", scope_key=CLASS)
            assert (evidence.recent.agreement_rate or 1.0) < 0.9, "the injected slice should be visibly bad"

            demotions = await reconcile_grants(session, tenant_id)

            assert len(demotions) == 1
            assert demotions[0].state == "demoted"
            assert "recent_drift" in demotions[0].refusal_values
            assert await _audit_actions(session, tenant_id) == ["autonomy:granted", "autonomy:demoted"]

    async def test_the_demoted_grant_no_longer_confers_anything(self):
        """A revoked capability must stop being readable as current.

        The dispatch path reads `state = 'granted'`, so a demoted row that
        still answered that query would be a capability nobody could see had
        been taken away.
        """
        async with probe() as (session, tenant_id, user_id):
            from app.services.autonomy_grants import reconcile_grants
            from sqlalchemy import text

            base = datetime.now(UTC) - timedelta(days=20)
            await _record(session, tenant_id, count=200, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(session, tenant_id, count=40, verdict=MALICIOUS, disposition=MALICIOUS, resolved_at=base + timedelta(days=1))
            await _promote(session, tenant_id, user_id)
            await _record(
                session,
                tenant_id,
                count=30,
                verdict=FALSE_POSITIVE,
                disposition=MALICIOUS,
                resolved_at=datetime.now(UTC) - timedelta(minutes=30),
            )
            await reconcile_grants(session, tenant_id)

            live = (
                await session.execute(
                    text(
                        """
                        SELECT count(*) FROM aisoc_autonomy_grants
                         WHERE tenant_id = :t AND state = 'granted' AND capability = 'auto_close'
                        """
                    ),
                    {"t": tenant_id},
                )
            ).scalar_one()
            assert live == 0


class TestAnOverrideIsVisiblyAnOverride:
    async def test_an_operator_can_grant_over_a_refusal(self):
        """The gate must be overridable, or it gets worked around silently."""
        async with probe() as (session, tenant_id, user_id):
            base = datetime.now(UTC) - timedelta(days=2)
            await _record(session, tenant_id, count=20, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)

            transition = await _promote(session, tenant_id, user_id, override=True, override_reason="Accepted for a two-week pilot")

            assert transition.granted is True
            assert transition.source == "operator_override"

    async def test_it_is_a_different_word_everywhere_it_lands(self):
        """Three places, because one of them alone would be reconstructable.

        The audit action, the grant row's source column, and the refusals
        carried in the snapshot. Six months later "was this earned" has to be
        answerable without inferring it from the numbers, which is exactly
        what somebody would have to do if the override were only a flag
        inside the evidence JSON.
        """
        async with probe() as (session, tenant_id, user_id):
            from sqlalchemy import text

            base = datetime.now(UTC) - timedelta(days=2)
            await _record(session, tenant_id, count=20, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _promote(session, tenant_id, user_id, override=True, override_reason="Pilot")

            assert await _audit_actions(session, tenant_id) == ["autonomy:overridden"]

            row = (
                (
                    await session.execute(
                        text(
                            """
                        SELECT source, override_reason, evidence
                        FROM aisoc_autonomy_grants WHERE tenant_id = :t
                        """
                        ),
                        {"t": tenant_id},
                    )
                )
                .mappings()
                .one()
            )
            assert row["source"] == "operator_override"
            assert row["override_reason"] == "Pilot"
            # The refusals that were overruled are in the snapshot, so the
            # override records what it waived rather than only that it happened.
            assert "insufficient_sample" in row["evidence"]["refusals"]

            changes = (
                await session.execute(
                    text("SELECT changes FROM audit_log WHERE tenant_id = :t ORDER BY created_at DESC LIMIT 1"),
                    {"t": tenant_id},
                )
            ).scalar_one()
            assert changes["source"] == "operator_override"
            assert "insufficient_sample" in changes["waived_refusals"]

    async def test_an_earned_grant_waives_nothing_and_says_so(self):
        """The empty list is the record that nothing had to be overruled."""
        async with probe() as (session, tenant_id, user_id):
            from sqlalchemy import text

            base = datetime.now(UTC) - timedelta(days=10)
            await _record(session, tenant_id, count=200, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(session, tenant_id, count=40, verdict=MALICIOUS, disposition=MALICIOUS, resolved_at=base + timedelta(days=1))
            await _promote(session, tenant_id, user_id)

            changes = (
                await session.execute(
                    text("SELECT changes FROM audit_log WHERE tenant_id = :t ORDER BY created_at DESC LIMIT 1"),
                    {"t": tenant_id},
                )
            ).scalar_one()
            assert changes["source"] == "earned"
            assert changes["waived_refusals"] == []

    async def test_an_override_is_demoted_on_the_same_floors(self):
        """An override is "I accept this today", not "stop measuring".

        Exempting overrides from demotion would make them permanent, which is
        the one thing that would turn the override back into the settings
        toggle this phase exists to replace.
        """
        async with probe() as (session, tenant_id, user_id):
            from app.services.autonomy_grants import reconcile_grants

            base = datetime.now(UTC) - timedelta(days=2)
            await _record(session, tenant_id, count=30, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _promote(session, tenant_id, user_id, override=True, override_reason="Pilot")

            await _record(
                session,
                tenant_id,
                count=40,
                verdict=FALSE_POSITIVE,
                disposition=MALICIOUS,
                resolved_at=datetime.now(UTC) - timedelta(minutes=10),
            )
            demotions = await reconcile_grants(session, tenant_id)

            assert len(demotions) == 1
            assert demotions[0].state == "demoted"


class TestTheAggregateAndTheEvaluatorAgree:
    async def test_an_abstention_is_excluded_from_agreement_by_the_real_sql(self):
        """The property the unit tests assert about the type, asserted about the query.

        This is the one that cannot be checked without a database: the type
        and the SQL agree by convention, and if the aggregate counted an
        abstention as a disagreement, every unit test would still pass while
        the live rate was wrong in the direction that refuses promotions.
        """
        async with probe() as (session, tenant_id, user_id):
            from app.services.shadow_agreement import agreement_for

            base = datetime.now(UTC) - timedelta(days=3)
            await _record(session, tenant_id, count=10, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(
                session,
                tenant_id,
                count=90,
                verdict=NEEDS_REVIEW,
                disposition=FALSE_POSITIVE,
                resolved_at=base + timedelta(hours=1),
            )

            evidence = await agreement_for(session, tenant_id, scope_kind="alert_class", scope_key=CLASS)

            assert evidence.window.labelled == 100
            assert evidence.window.answered == 10
            assert evidence.window.abstained == 90
            # Perfect over what it answered, and the abstention rate is what moved.
            assert evidence.window.agreement_rate == 1.0
            assert evidence.window.abstention_rate == pytest.approx(0.9)

    async def test_an_unlabeled_closure_is_resolved_but_not_graded(self):
        """An analyst who declined to classify must not become agreement."""
        async with probe() as (session, tenant_id, user_id):
            from app.services.shadow_agreement import agreement_for

            base = datetime.now(UTC) - timedelta(days=3)
            await _record(session, tenant_id, count=10, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(
                session,
                tenant_id,
                count=40,
                verdict=FALSE_POSITIVE,
                disposition="unlabeled",
                resolved_at=base + timedelta(hours=1),
            )

            evidence = await agreement_for(session, tenant_id, scope_kind="alert_class", scope_key=CLASS)

            assert evidence.window.resolved == 50
            assert evidence.window.labelled == 10
            assert evidence.window.unlabeled == 40
            assert evidence.window.agreement_rate == 1.0

    async def test_an_unresolved_decision_is_not_evidence_yet(self):
        """A verdict nobody has closed is neither agreement nor disagreement."""
        async with probe() as (session, tenant_id, user_id):
            from app.services.shadow_agreement import agreement_for
            from sqlalchemy import text

            for _ in range(25):
                await session.execute(
                    text(
                        """
                        INSERT INTO aisoc_shadow_decisions
                            (tenant_id, alert_id, alert_class, verdict, confidence, decided_at)
                        VALUES (:t, :a, :c, 'false_positive', 0.9, now())
                        """
                    ),
                    {"t": tenant_id, "a": uuid.uuid4(), "c": CLASS},
                )
            await session.commit()

            evidence = await agreement_for(session, tenant_id, scope_kind="alert_class", scope_key=CLASS)
            assert evidence.window.resolved == 0
            assert evidence.window.agreement_rate is None


class TestTheTransitionsAreInTheHashChainedLog:
    async def test_the_audit_trail_of_a_promotion_cannot_be_deleted(self):
        """The plan asks for the hash-chained log, so being append-only is the claim.

        A grant an operator can quietly remove the record of is a grant with
        no audit trail. The trigger refuses the DELETE, and this asserts the
        refusal rather than assuming it.
        """
        async with probe() as (session, tenant_id, user_id):
            from sqlalchemy import text

            base = datetime.now(UTC) - timedelta(days=2)
            await _record(session, tenant_id, count=20, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _promote(session, tenant_id, user_id, override=True, override_reason="Pilot")

            with pytest.raises(Exception, match="immutable"):
                await session.execute(text("DELETE FROM audit_log WHERE tenant_id = :t"), {"t": tenant_id})
            await session.rollback()

    async def test_promotion_and_demotion_chain_together(self):
        """Every transition joins one chain, in order, verifiable offline.

        `verify_chain` is the same pure function an external auditor would run
        over a CSV export, so what is checked here is what they would check.
        """
        async with probe() as (session, tenant_id, user_id):
            from app.services.audit_hash import verify_chain
            from app.services.autonomy_grants import reconcile_grants
            from sqlalchemy import text

            base = datetime.now(UTC) - timedelta(days=20)
            await _record(session, tenant_id, count=200, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
            await _record(session, tenant_id, count=40, verdict=MALICIOUS, disposition=MALICIOUS, resolved_at=base + timedelta(days=1))
            await _promote(session, tenant_id, user_id)
            await _record(
                session,
                tenant_id,
                count=30,
                verdict=FALSE_POSITIVE,
                disposition=MALICIOUS,
                resolved_at=datetime.now(UTC) - timedelta(minutes=30),
            )
            await reconcile_grants(session, tenant_id)

            rows = (
                (
                    await session.execute(
                        text(
                            """
                        SELECT id, tenant_id, actor_id, actor_email, actor_ip, action, resource,
                               resource_id, changes, metadata, created_at, prev_hash, entry_hash
                        FROM audit_log WHERE tenant_id = :t ORDER BY created_at, id
                        """
                        ),
                        {"t": tenant_id},
                    )
                )
                .mappings()
                .all()
            )

            assert [row["action"] for row in rows] == ["autonomy:granted", "autonomy:demoted"]
            valid, index, reason = verify_chain([dict(row) for row in rows])
            assert valid, f"chain broken at row {index}: {reason}"
            # The second row chains onto the first rather than starting a new one.
            assert rows[1]["prev_hash"] == rows[0]["entry_hash"]

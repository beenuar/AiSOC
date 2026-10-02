"""UEBA scoring and persistence, against a live Postgres.

Maturity: the evidence that takes **UEBA** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why a live database is the only way to test this
-------------------------------------------------
UEBA's 88 unit tests never open a connection. They are good tests of the
arithmetic — z-scores, composite weighting, peer comparison — and
structurally incapable of catching the defect that actually shipped:

`EntityBaseline` declared `peer_group_id`, migration `0001` never created
the column, and `score_event` raised on the first scoreable event. UEBA
could not write an anomaly on any deployment. Every unit test passed
throughout, because the ORM model and the test agreed with each other and
neither consulted the schema.

So this suite runs the migrations the service ships, then drives
`ScoringService.score_event` through a real session and reads the row back
out. A column the model declares and the migration omits fails here on the
first call.

The negative control
--------------------
`test_a_normal_event_produces_no_anomaly` is the half that makes the other
half mean something. A scorer that flagged everything would pass an
"anomalous event produces a row" assertion while being useless, and a
scorer that flagged nothing would pass a tenant-isolation assertion for
the wrong reason.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_UEBA_DSN", "").strip(),
        reason="ISOLATION_UEBA_DSN is not set; this suite needs live infrastructure",
    ),
]

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _dsn() -> str:
    value = os.environ.get("ISOLATION_UEBA_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_UEBA_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture
async def session():
    """A session against the schema the service's own migrations build.

    The tables come from `services/ueba/alembic/`, not from
    `Base.metadata.create_all`. That distinction is the entire point: the
    defect this suite exists for was a column present in the model and
    absent from the migration, and `create_all` would have papered over it
    by building the schema from the very model under test.
    """
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    dsn = _dsn()
    engine = create_async_engine(dsn, future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async with maker() as s:
        yield s
        # Scoped to the two test tenants so a shared database is not
        # emptied by a test run.
        for table in ("ueba_anomalies", "ueba_entity_baselines", "ueba_peer_groups"):
            await s.execute(
                sqlalchemy.text(f"DELETE FROM {table} WHERE tenant_id IN (:a, :b)"),
                {"a": str(TENANT_A), "b": str(TENANT_B)},
            )
        await s.commit()
    await engine.dispose()


def _scorer(session):  # noqa: ANN001, ANN202
    from app.services.scoring import ScoringService

    return ScoringService(session)


async def _train(scorer, tenant: uuid.UUID, entity: str, *, value: float, times: int = 40) -> None:
    """Give an entity a baseline by showing it ordinary behaviour.

    Real repetition rather than an inserted baseline row, so the training
    path is exercised too — a baseline writer that silently failed would
    otherwise look identical to one that worked.

    The values vary by a few percent on purpose. Feeding the identical
    number produces a baseline with **zero variance**, which the scorer
    correctly declines to score by deviation: its own log says so, naming
    automation and service accounts as the entities that converge there.
    A fixture that trained on a constant would be testing the
    unscoreable branch while claiming to test detection.
    """
    for index in range(times):
        # Deterministic jitter: a seeded random would make a failure hard
        # to reproduce from the test name alone.
        jitter = 1.0 + ((index % 7) - 3) * 0.04
        await scorer.score_event(
            tenant_id=tenant,
            entity_type="user",
            entity_id=entity,
            event_type="login",
            features={"bytes_out": value * jitter},
        )


class TestTheSchemaIsTheOneTheServiceShips:
    async def test_the_baseline_table_has_every_column_the_model_declares(self, session) -> None:  # noqa: ANN001
        """The exact defect: `peer_group_id` was in the model and not in
        migration 0001, so `score_event` raised on the first scoreable
        event and UEBA could not write an anomaly on any deployment."""
        import sqlalchemy
        from app.models.ueba import EntityBaseline

        result = await session.execute(
            sqlalchemy.text("SELECT column_name FROM information_schema.columns WHERE table_name = 'ueba_entity_baselines'")
        )
        actual = {row[0] for row in result}
        declared = {c.name for c in EntityBaseline.__table__.columns}

        missing = declared - actual
        assert not missing, (
            f"the model declares {sorted(missing)} and the migrations do not create "
            "them. Every query touching those columns raises, which is how UEBA "
            "shipped unable to write a single anomaly."
        )


class TestScoring:
    async def test_a_normal_event_produces_no_anomaly(self, session) -> None:  # noqa: ANN001
        """The negative control.

        Without it, 'an anomalous event produces a row' would pass for a
        scorer that flags everything.
        """
        scorer = _scorer(session)
        entity = f"alice-{uuid.uuid4().hex[:8]}"
        await _train(scorer, TENANT_A, entity, value=1000.0)

        anomaly = await scorer.score_event(
            tenant_id=TENANT_A,
            entity_type="user",
            entity_id=entity,
            event_type="login",
            features={"bytes_out": 1010.0},
        )
        assert anomaly is None, f"ordinary behaviour was scored anomalous ({anomaly!r}); a detector that flags everything detects nothing"

    async def test_an_outlier_produces_a_persisted_anomaly(self, session) -> None:  # noqa: ANN001
        """The positive half, read back out of the database rather than
        taken from the return value."""
        import sqlalchemy

        scorer = _scorer(session)
        entity = f"bob-{uuid.uuid4().hex[:8]}"
        await _train(scorer, TENANT_A, entity, value=1000.0)

        anomaly = await scorer.score_event(
            tenant_id=TENANT_A,
            entity_type="user",
            entity_id=entity,
            event_type="login",
            features={"bytes_out": 500_000.0},
        )
        assert anomaly is not None, "a 500x outlier against a trained baseline was not flagged"
        await session.commit()

        result = await session.execute(
            sqlalchemy.text("SELECT count(*) FROM ueba_anomalies WHERE tenant_id = :t AND entity_id = :e"),
            {"t": str(TENANT_A), "e": entity},
        )
        assert result.scalar() >= 1, (
            "score_event returned an anomaly that is not in the table; the return value and the persisted row are different claims"
        )


class TestTenantIsolation:
    async def test_one_tenants_baseline_does_not_train_another(self, session) -> None:  # noqa: ANN001
        """Two tenants, the same entity id, opposite normal behaviour.

        If baselines leaked, B's ordinary value would read as ordinary for
        A as well and the assertion below would fail.
        """
        scorer = _scorer(session)
        shared = f"svc-{uuid.uuid4().hex[:8]}"

        await _train(scorer, TENANT_A, shared, value=1000.0)
        await _train(scorer, TENANT_B, shared, value=500_000.0)

        # B's normal is A's outlier. A must still flag it.
        flagged = await scorer.score_event(
            tenant_id=TENANT_A,
            entity_type="user",
            entity_id=shared,
            event_type="login",
            features={"bytes_out": 500_000.0},
        )
        assert flagged is not None, (
            "tenant B's baseline trained tenant A: a value B does normally read as "
            "ordinary for A, which means the two estates share a model"
        )

    async def test_an_anomaly_is_written_against_its_own_tenant(self, session) -> None:  # noqa: ANN001
        import sqlalchemy

        scorer = _scorer(session)
        entity = f"carol-{uuid.uuid4().hex[:8]}"
        await _train(scorer, TENANT_A, entity, value=1000.0)
        await scorer.score_event(
            tenant_id=TENANT_A,
            entity_type="user",
            entity_id=entity,
            event_type="login",
            features={"bytes_out": 500_000.0},
        )
        await session.commit()

        leaked = await session.execute(
            sqlalchemy.text("SELECT count(*) FROM ueba_anomalies WHERE tenant_id = :t AND entity_id = :e"),
            {"t": str(TENANT_B), "e": entity},
        )
        assert leaked.scalar() == 0, "an anomaly scored for tenant A was written against tenant B"

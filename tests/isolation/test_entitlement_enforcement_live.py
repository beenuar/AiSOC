"""A configured limit refuses work only when a tenant opted in — live.

Depth 8.1, parity 4.5's second bullet.

Why this suite is live rather than offline
------------------------------------------
Every decision here reads rows: the opt-in table, the per-tenant
`tenants.limits` override, and a usage count over real rows. A double
answers whatever the test wrote into it, which is the shape that has
shipped defects in this repository repeatedly — a fake row answering for
columns a table does not have, a fake store matching whatever key it was
handed.

The counts are the specific risk. `measure_usage` binds the tenant as a
typed `UUID`; it used to bind `str(uuid)`, which only Postgres coerces,
so every quota count returned zero in any harness that was not Postgres
— and a quota reading zero is the direction nobody investigates.

`ENVIRONMENT=test`, never `development`, which is in
`AUTH_BYPASS_ENVIRONMENTS`.

The positive control
--------------------
`test_a_tenant_with_room_is_not_refused` and
`test_a_tenant_that_did_not_opt_in_is_not_refused` are not padding. A
guard stuck closed refuses everything and passes every "the limit is
enforced" assertion perfectly, which is exactly how a fail-closed control
shipped here withholding every grant on every deployment while its
negative tests were green. Half of this suite exists to catch that.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_ENTITLEMENTS_DSN", "").strip(),
        reason="ISOLATION_ENTITLEMENTS_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_ENTITLEMENTS_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_ENTITLEMENTS_DSN is not set")
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def sessionmaker_():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn())
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


async def _make_tenant(session, *, connectors: int, limit: object | None) -> uuid.UUID:
    """A tenant with *connectors* enabled connectors and an optional ceiling."""
    import json

    from sqlalchemy import text

    tenant_id = uuid.uuid4()
    tag = str(tenant_id)[:8]
    limits = {} if limit is None else {"connectors": limit}
    await session.execute(
        text("INSERT INTO tenants (id, name, slug, limits) VALUES (:id, :n, :s, CAST(:l AS jsonb))"),
        {"id": str(tenant_id), "n": f"ent-{tag}", "s": f"ent-{tag}", "l": json.dumps(limits)},
    )
    for n in range(connectors):
        await session.execute(
            text(
                "INSERT INTO connectors (id, tenant_id, name, connector_type, category, is_enabled) "
                "VALUES (:id, :t, :n, 'aws_cloudtrail', 'cloud', TRUE)"
            ),
            {"id": str(uuid.uuid4()), "t": str(tenant_id), "n": f"c{n}"},
        )
    await session.commit()
    return tenant_id


async def _opt_in(session, tenant_id: uuid.UUID, key: str) -> None:
    from sqlalchemy import text

    await session.execute(
        text("INSERT INTO aisoc_tenant_entitlement_enforcement (tenant_id, limit_key, enforce) VALUES (:t, :k, TRUE)"),
        {"t": str(tenant_id), "k": key},
    )
    await session.commit()


async def _drop(session, tenant_id: uuid.UUID) -> None:
    from sqlalchemy import text

    await session.execute(text("DELETE FROM connectors WHERE tenant_id = :t"), {"t": str(tenant_id)})
    await session.execute(text("DELETE FROM aisoc_tenant_entitlement_enforcement WHERE tenant_id = :t"), {"t": str(tenant_id)})
    await session.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": str(tenant_id)})
    await session.commit()


class TestTheCountIsReal:
    async def test_usage_is_measured_from_rows(self, sessionmaker_):
        """`measure_usage` used to bind the tenant as a string.

        Only Postgres coerces that against a `UUID` column, so every count
        returned zero on any other driver. Asserting a non-zero count
        against rows this test inserted — rather than against a second
        call to the thing being measured — is what catches it.
        """
        from app.services.entitlements import measure_usage

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=3, limit=None)
            try:
                usage = await measure_usage(session, tenant_id)
                assert usage["connectors"] == 3
            finally:
                await _drop(session, tenant_id)


class TestEnforcementIsOptIn:
    async def test_a_tenant_that_did_not_opt_in_is_not_refused(self, sessionmaker_):
        """The property that makes this safe to ship.

        `tenants.limits` has been a reporting input for as long as it has
        existed, so a ceiling already written there was never chosen as a
        hard cap. A tenant well over one, with no row in the opt-in table,
        must still be allowed through.
        """
        from app.services.entitlements import assert_within_limit

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=5, limit=1)
            try:
                await assert_within_limit(session, tenant_id, {"connectors": 1}, "connectors")
            finally:
                await _drop(session, tenant_id)

    async def test_an_opted_in_tenant_over_its_limit_is_refused(self, sessionmaker_):
        from app.services.entitlements import LimitExceeded, assert_within_limit

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=5, limit=2)
            await _opt_in(session, tenant_id, "connectors")
            try:
                with pytest.raises(LimitExceeded) as caught:
                    await assert_within_limit(session, tenant_id, {"connectors": 2}, "connectors")
                # The numbers, not a bare message: "quota exceeded" sends an
                # operator to a support channel, "5 of 2" sends them to the
                # setting.
                assert caught.value.used == 5
                assert caught.value.limit == 2
                assert caught.value.key == "connectors"
            finally:
                await _drop(session, tenant_id)


class TestThePositiveControls:
    """A guard stuck closed passes every negative assertion above."""

    async def test_a_tenant_with_room_is_not_refused(self, sessionmaker_):
        from app.services.entitlements import assert_within_limit

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=1, limit=10)
            await _opt_in(session, tenant_id, "connectors")
            try:
                await assert_within_limit(session, tenant_id, {"connectors": 10}, "connectors")
            finally:
                await _drop(session, tenant_id)

    async def test_an_opt_in_on_one_key_does_not_enforce_another(self, sessionmaker_):
        """Per key, not per tenant.

        Opting in to `connectors` must not start refusing seats. The two
        are stored in one table and a predicate that forgot `limit_key`
        would enforce every key the moment a tenant enabled one.
        """
        from app.services.entitlements import assert_within_limit

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=5, limit=1)
            await _opt_in(session, tenant_id, "connectors")
            try:
                # `seats` is over nothing here, but the point is that the
                # key is not in the enforced set at all.
                await assert_within_limit(session, tenant_id, {"seats": 0}, "seats")
            finally:
                await _drop(session, tenant_id)

    async def test_no_ceiling_configured_is_never_a_refusal(self, sessionmaker_):
        """AiSOC ships uncapped, and opting in must not invent a ceiling."""
        from app.services.entitlements import assert_within_limit

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=5, limit=None)
            await _opt_in(session, tenant_id, "connectors")
            try:
                await assert_within_limit(session, tenant_id, {}, "connectors")
                await assert_within_limit(session, tenant_id, {"connectors": "unlimited"}, "connectors")
            finally:
                await _drop(session, tenant_id)


class TestOneTenantsPolicyDoesNotReachAnother:
    async def test_enforcement_is_scoped_to_its_tenant(self, sessionmaker_):
        from app.services.entitlements import assert_within_limit, enforced_keys

        async with sessionmaker_() as session:
            strict = await _make_tenant(session, connectors=5, limit=1)
            relaxed = await _make_tenant(session, connectors=5, limit=1)
            await _opt_in(session, strict, "connectors")
            try:
                assert await enforced_keys(session, strict) == frozenset({"connectors"})
                assert await enforced_keys(session, relaxed) == frozenset()
                # The neighbour is over the same ceiling and still allowed.
                await assert_within_limit(session, relaxed, {"connectors": 1}, "connectors")
            finally:
                await _drop(session, strict)
                await _drop(session, relaxed)


class TestTheVocabularyIsChecked:
    async def test_an_unknown_limit_key_is_refused_by_the_database(self, sessionmaker_):
        """A typo stored here would match no key and enforce nothing.

        Checked in SQL as well as in the route, because the route is not
        the only thing that can write this table.
        """
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError, IntegrityError

        async with sessionmaker_() as session:
            tenant_id = await _make_tenant(session, connectors=0, limit=None)
            try:
                with pytest.raises((IntegrityError, DBAPIError)):
                    await session.execute(
                        text(
                            "INSERT INTO aisoc_tenant_entitlement_enforcement "
                            "(tenant_id, limit_key, enforce) VALUES (:t, 'connetcors', TRUE)"
                        ),
                        {"t": str(tenant_id)},
                    )
                    await session.commit()
                await session.rollback()
            finally:
                await _drop(session, tenant_id)

    async def test_the_check_constraint_and_the_python_vocabulary_agree(self, sessionmaker_):
        """Two places list the keys, so they are compared rather than trusted.

        The constraint cannot reference a table of keys -- there is not
        one -- so adding a key means editing both. This is the gate that
        makes forgetting one a failure rather than a silent half-enforced
        vocabulary.
        """
        import re

        from app.services.entitlements import LIMIT_KEYS_BY_NAME
        from sqlalchemy import text

        async with sessionmaker_() as session:
            definition = (
                await session.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        " WHERE conname = 'aisoc_tenant_entitlement_enforcement_key_known'"
                    )
                )
            ).scalar_one()
        in_sql = set(re.findall(r"'([a-z_]+)'", definition))
        assert in_sql == set(LIMIT_KEYS_BY_NAME), (
            f"the CHECK constraint allows {sorted(in_sql)} while LIMIT_KEYS defines "
            f"{sorted(LIMIT_KEYS_BY_NAME)}; a key in one and not the other is half enforced"
        )

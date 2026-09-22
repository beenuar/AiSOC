"""A tenant's chosen autonomy tier must actually govern their actions.

The console writes a per-tenant tier, per-action overrides and a HIGH-blast
whitelist to Postgres. The live-action dispatcher read none of it: autonomy came
from one deployment-wide `AISOC_MATURITY_TIER`, and the `whitelisted` flag that
gates L4 break-glass was left at its default so that path was unreachable.

These tests cover the resolution rules, with particular attention to the
fallback posture — an unreadable policy must not inherit a possibly more
permissive environment default.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.services import tenant_policy
from app.services.maturity import MaturityTier
from app.services.tenant_policy import TenantPolicy, resolve_tenant_policy

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    tenant_policy.clear_cache()
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    monkeypatch.delenv("DATABASE_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    yield
    tenant_policy.clear_cache()


# ── resolution ────────────────────────────────────────────────────────────


async def test_without_a_database_the_environment_default_applies(
    monkeypatch: pytest.MonkeyPatch,
):
    """Single-tenant installs keep their documented behaviour."""
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L2")
    policy = await resolve_tenant_policy(uuid4())
    assert policy.tier is MaturityTier.L2_CONTAIN
    assert policy.from_store is False
    assert policy.source == "environment"


async def test_stored_tier_wins_over_the_environment(monkeypatch: pytest.MonkeyPatch):
    """The regression: a tenant who picked L3 was governed by the env var."""
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L1")
    monkeypatch.setenv("DATABASE_DSN", "postgresql://stub/db")

    async def _load(tenant_id, dsn):  # noqa: ANN001, ANN202
        return TenantPolicy(tier=MaturityTier.L3_REMEDIATE, from_store=True, source="tenant_policy")

    monkeypatch.setattr(tenant_policy, "_load_from_store", _load)
    policy = await resolve_tenant_policy(uuid4())
    assert policy.tier is MaturityTier.L3_REMEDIATE
    assert policy.from_store is True


async def test_two_tenants_get_their_own_tiers(monkeypatch: pytest.MonkeyPatch):
    """One global tier is the multi-tenant bug this exists to fix."""
    monkeypatch.setenv("DATABASE_DSN", "postgresql://stub/db")
    tiers = {}

    async def _load(tenant_id, dsn):  # noqa: ANN001, ANN202
        return TenantPolicy(tier=tiers[tenant_id], from_store=True, source="tenant_policy")

    monkeypatch.setattr(tenant_policy, "_load_from_store", _load)
    cautious, bold = str(uuid4()), str(uuid4())
    tiers[cautious] = MaturityTier.L0_OBSERVE
    tiers[bold] = MaturityTier.L4_AUTOMATE

    assert (await resolve_tenant_policy(cautious)).tier is MaturityTier.L0_OBSERVE
    assert (await resolve_tenant_policy(bold)).tier is MaturityTier.L4_AUTOMATE


async def test_a_tenant_with_no_stored_row_gets_the_deployment_default(
    monkeypatch: pytest.MonkeyPatch,
):
    """Never configured is not the same fact as could not be read."""
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L2")
    monkeypatch.setenv("DATABASE_DSN", "postgresql://stub/db")

    async def _load(tenant_id, dsn):  # noqa: ANN001, ANN202
        return None

    monkeypatch.setattr(tenant_policy, "_load_from_store", _load)
    policy = await resolve_tenant_policy(uuid4())
    assert policy.tier is MaturityTier.L2_CONTAIN
    assert policy.from_store is False


async def test_unreadable_policy_falls_to_the_floor_not_the_env_default(
    monkeypatch: pytest.MonkeyPatch,
):
    """The safety-critical case.

    A database is configured, so a per-tenant policy exists, and the read
    failed. Inheriting `AISOC_MATURITY_TIER=L4` here would auto-execute
    high-blast actions the tenant may never have authorised.
    """
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
    monkeypatch.setenv("DATABASE_DSN", "postgresql://stub/db")

    async def _load(tenant_id, dsn):  # noqa: ANN001, ANN202
        raise ConnectionError("postgres unreachable")

    monkeypatch.setattr(tenant_policy, "_load_from_store", _load)
    policy = await resolve_tenant_policy(uuid4())
    assert policy.tier is tenant_policy.UNREADABLE_POLICY_FLOOR
    assert policy.tier is MaturityTier.L1_NOTIFY
    assert policy.source == "unreadable_policy_floor"


async def test_a_bad_tier_env_value_is_conservative(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_MATURITY_TIER", "TOTALLY_AUTONOMOUS")
    policy = await resolve_tenant_policy(None)
    assert policy.tier is MaturityTier.L1_NOTIFY


async def test_sqlalchemy_style_dsn_is_accepted(monkeypatch: pytest.MonkeyPatch):
    """Both DSN spellings are already present in deployed environments."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@h/db")
    assert tenant_policy._dsn() == "postgresql://u:p@h/db"


# ── whitelist ─────────────────────────────────────────────────────────────


def _wl(**kw):
    entry = {"action_type": "isolate_host", "constraints": {}, "expires_at": None}
    entry.update(kw)
    return TenantPolicy(tier=MaturityTier.L4_AUTOMATE, whitelist=[entry])


async def test_whitelist_matches_on_action_type():
    assert _wl().is_whitelisted("isolate_host", "WIN-DC01") is True
    assert _wl().is_whitelisted("disable_user", "alice") is False


async def test_expired_whitelist_entry_does_not_authorise():
    past = datetime.now(UTC) - timedelta(hours=1)
    assert _wl(expires_at=past).is_whitelisted("isolate_host", "WIN-DC01") is False


async def test_unexpired_whitelist_entry_authorises():
    future = datetime.now(UTC) + timedelta(hours=1)
    assert _wl(expires_at=future).is_whitelisted("isolate_host", "WIN-DC01") is True


async def test_target_constraint_is_enforced():
    scoped = _wl(constraints={"targets": ["LAB-01", "LAB-02"]})
    assert scoped.is_whitelisted("isolate_host", "LAB-01") is True
    assert scoped.is_whitelisted("isolate_host", "PROD-DC01") is False


async def test_no_whitelist_means_not_whitelisted():
    assert TenantPolicy(tier=MaturityTier.L4_AUTOMATE).is_whitelisted("isolate_host", "x") is False


# ── caching ───────────────────────────────────────────────────────────────


async def test_policy_is_cached_so_the_action_path_is_not_per_call_db_bound(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("DATABASE_DSN", "postgresql://stub/db")
    calls = 0

    async def _load(tenant_id, dsn):  # noqa: ANN001, ANN202
        nonlocal calls
        calls += 1
        return TenantPolicy(tier=MaturityTier.L2_CONTAIN, from_store=True)

    monkeypatch.setattr(tenant_policy, "_load_from_store", _load)
    tid = uuid4()
    await resolve_tenant_policy(tid)
    await resolve_tenant_policy(tid)
    await resolve_tenant_policy(tid)
    assert calls == 1


async def test_a_read_failure_is_not_cached(monkeypatch: pytest.MonkeyPatch):
    """A transient outage must not pin a tenant to the floor for the TTL."""
    monkeypatch.setenv("DATABASE_DSN", "postgresql://stub/db")
    state = {"fail": True}

    async def _load(tenant_id, dsn):  # noqa: ANN001, ANN202
        if state["fail"]:
            raise ConnectionError("down")
        return TenantPolicy(tier=MaturityTier.L3_REMEDIATE, from_store=True)

    monkeypatch.setattr(tenant_policy, "_load_from_store", _load)
    tid = uuid4()
    assert (await resolve_tenant_policy(tid)).tier is MaturityTier.L1_NOTIFY
    state["fail"] = False
    assert (await resolve_tenant_policy(tid)).tier is MaturityTier.L3_REMEDIATE

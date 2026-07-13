"""Phase C4 — fuse-time attack-chain auto-grouping tests.

Proves related alerts on a shared entity join one chain within the window,
that members are ordered by MITRE kill-chain stage (so "position" reflects the
intrusion stage, not arrival order), that a new entity starts a new chain, and
that everything is fail-soft.
"""

from __future__ import annotations

import json

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.attack_chain_grouper import AttackChainGrouper

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.fail = False

    async def get(self, key):  # noqa: ANN001
        if self.fail:
            raise RuntimeError("redis down")
        return self.store.get(key)

    async def set(self, key, value, ex=None):  # noqa: ANN001, ARG002
        if self.fail:
            raise RuntimeError("redis down")
        self.store[key] = value if isinstance(value, bytes) else str(value).encode()


def _alert(*, hostname=None, username=None, src_ip=None, tactics=None, title="t") -> RawAlert:
    return RawAlert(
        tenant_id=TENANT,
        source="test",
        title=title,
        severity=AlertSeverity.HIGH,
        hostname=hostname,
        username=username,
        src_ip=src_ip,
        mitre_tactics=tactics or [],
    )


async def test_first_alert_starts_new_chain():
    g = AttackChainGrouper(_FakeRedis())
    a = await g.assign(_alert(hostname="WIN-DC01", tactics=["initial-access"]))
    assert a is not None
    assert a.is_new_chain is True
    assert a.member_count == 1
    assert a.position == 1
    assert a.entity == "host:WIN-DC01"


async def test_second_alert_same_host_joins_chain():
    r = _FakeRedis()
    g = AttackChainGrouper(r)
    a1 = await g.assign(_alert(hostname="WIN-DC01", tactics=["initial-access"], title="phish"))
    a2 = await g.assign(_alert(hostname="WIN-DC01", tactics=["lateral-movement"], title="psexec"))
    assert a2.is_new_chain is False
    assert a2.chain_id == a1.chain_id
    assert a2.member_count == 2
    assert a1.member_count == 1


async def test_members_ordered_by_kill_chain_stage():
    r = _FakeRedis()
    g = AttackChainGrouper(r)
    # Arrive out of order: exfiltration first, then initial-access.
    await g.assign(_alert(hostname="H1", tactics=["exfiltration"], title="exfil"))
    early = await g.assign(_alert(hostname="H1", tactics=["initial-access"], title="access"))
    # The initial-access alert should rank position 1 (earliest stage) even
    # though it arrived second.
    assert early.position == 1
    assert early.stage == "initial-access"


async def test_cross_entity_link_via_shared_ip():
    r = _FakeRedis()
    g = AttackChainGrouper(r)
    a1 = await g.assign(_alert(hostname="H1", src_ip="10.0.0.9", tactics=["execution"]))
    # New host but same IP → joins the existing chain.
    a2 = await g.assign(_alert(hostname="H2", src_ip="10.0.0.9", tactics=["persistence"]))
    assert a2.chain_id == a1.chain_id


async def test_different_entity_starts_separate_chain():
    r = _FakeRedis()
    g = AttackChainGrouper(r)
    a1 = await g.assign(_alert(hostname="H1", tactics=["execution"]))
    a2 = await g.assign(_alert(hostname="H2", tactics=["execution"]))
    assert a1.chain_id != a2.chain_id


async def test_no_entity_returns_none():
    g = AttackChainGrouper(_FakeRedis())
    assert await g.assign(_alert(tactics=["impact"])) is None


async def test_failsoft_on_redis_error():
    r = _FakeRedis()
    r.fail = True
    g = AttackChainGrouper(r)
    assert await g.assign(_alert(hostname="H1")) is None


async def test_prior_alert_ids_populated():
    r = _FakeRedis()
    g = AttackChainGrouper(r)
    a1 = await g.assign(_alert(hostname="H1", tactics=["initial-access"]))
    a2 = await g.assign(_alert(hostname="H1", tactics=["discovery"]))
    # The second alert's prior_alert_ids is exactly the first alert's id.
    assert a2.prior_alert_ids == [_first_member_id(r, a1.chain_id)]
    assert len(a2.prior_alert_ids) == 1


def _first_member_id(redis: _FakeRedis, chain_id: str) -> str:
    raw = redis.store[f"chain:members:{chain_id}"]
    return json.loads(raw.decode())[0]["alert_id"]

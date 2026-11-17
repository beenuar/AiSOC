"""A user/ip/domain entity says where it was seen (#1950).

`root` with 40 points could be a brute force on one internet-facing box or
one failed login on each of ten servers — indistinguishable on a queue that
shows only value, score and count. Every contributing alert already names
its host; the engine now rolls those up per entity, bounded and evictable,
and the wire shape carries them so the list is triageable without opening
every entity.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.entity_risk import _MAX_HOSTS_PER_ENTITY, EntityRiskEngine

from tests.test_entity_risk import _TENANT, _FakeRedis


def _alert(*, username: str | None = "root", hostname: str | None = None, src_ip: str | None = None) -> RawAlert:
    return RawAlert(
        id=uuid4(),
        tenant_id=_TENANT,
        source="test",
        title="failed login",
        severity=AlertSeverity.MEDIUM,
        username=username,
        hostname=hostname,
        src_ip=src_ip,
    )


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> EntityRiskEngine:
    from app.core.config import settings

    monkeypatch.setattr(settings, "rba_enabled", True)
    return EntityRiskEngine(_FakeRedis())


@pytest.mark.asyncio
async def test_a_user_entity_accumulates_the_hosts_it_was_seen_on(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(hostname="web-01"))
    await engine.observe(_alert(hostname="web-01"))
    await engine.observe(_alert(hostname="db-02"))

    record = await engine.get(_TENANT, "user", "root")
    assert record is not None
    hosts = record.hosts_list()
    assert [(h["name"], h["alert_count"]) for h in hosts] == [("web-01", 2), ("db-02", 1)]
    assert all(h["last_seen"] for h in hosts), "a sighting without a time cannot be aged"
    assert record.to_dict()["hosts"] == hosts, "the wire shape must carry the rollup"


@pytest.mark.asyncio
async def test_a_hostless_alert_contributes_points_but_no_sighting(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(hostname=None))
    record = await engine.get(_TENANT, "user", "root")
    assert record is not None
    assert record.alert_count == 1
    assert record.hosts_list() == [], "no hostname on the alert means no invented sighting"


@pytest.mark.asyncio
async def test_a_host_entity_does_not_record_itself(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(username=None, hostname="web-01"))
    record = await engine.get(_TENANT, "host", "web-01")
    assert record is not None
    assert record.hosts_list() == [], "a host's host is itself; `web-01 — seen on web-01` is noise"


@pytest.mark.asyncio
async def test_contributors_carry_the_host_of_their_alert(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(hostname="app-03"))
    record = await engine.get(_TENANT, "user", "root")
    assert record is not None
    assert record.contributors and record.contributors[-1]["host"] == "app-03"

    await engine.observe(_alert(hostname=None))
    record = await engine.get(_TENANT, "user", "root")
    assert record is not None
    assert record.contributors, "the hostless alert must still contribute"
    assert "host" not in record.contributors[-1], "no host on the alert, no host key on the contribution"


@pytest.mark.asyncio
async def test_the_rollup_is_bounded_and_evicts_the_least_contributing_host(engine: EntityRiskEngine) -> None:
    # The keeper earns two contributions; the flood earns one each.
    await engine.observe(_alert(hostname="keeper"))
    await engine.observe(_alert(hostname="keeper"))
    for n in range(_MAX_HOSTS_PER_ENTITY + 3):
        await engine.observe(_alert(hostname=f"flood-{n:02d}"))

    record = await engine.get(_TENANT, "user", "root")
    assert record is not None
    hosts = record.hosts_list()
    assert len(hosts) == _MAX_HOSTS_PER_ENTITY, "one chatty entity must not grow its key without bound"
    assert hosts[0]["name"] == "keeper", "eviction must drop the least-contributing host, not the most"
    assert hosts[0]["alert_count"] == 2


@pytest.mark.asyncio
async def test_the_rollup_survives_a_save_load_round_trip(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(hostname="web-01", src_ip="203.0.113.7"))

    for entity_type, entity_value in (("user", "root"), ("src_ip", "203.0.113.7")):
        record = await engine.get(_TENANT, entity_type, entity_value)
        assert record is not None, f"{entity_type} record did not persist"
        assert [h["name"] for h in record.hosts_list()] == ["web-01"]

    queue = await engine.top_entities(_TENANT, limit=10)
    by_key = {(r.entity_type, r.entity_value): r for r in queue}
    assert [h["name"] for h in by_key[("user", "root")].to_dict()["hosts"]] == ["web-01"], (
        "the queue read is the surface #1950 is about; the rollup must reach it"
    )

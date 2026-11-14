"""The per-tenant first-seen store, and the line it refuses to cross.

Two rules read a `<attr>_seen_before` boolean and one reads `session_age_hours`;
nothing computed any of them. The assertions below are about behaviour under
the conditions that actually occur — a first sighting, a repeat, a different
tenant, and Redis being unavailable — rather than about the helper returning
a value.

The last of those is the one worth having: an outage must contribute **no
key**, because `False` means "this tenant has never seen this" and a novelty
rule told that about every event would fire on all of them.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from app.services.first_seen import AGE_FIELDS, SEEN_BEFORE_FIELDS, TRACKED_ATTRIBUTES, FirstSeenStore

_REPO = Path(__file__).resolve().parents[3]


class _FakeRedis:
    """`SET key value NX EX GET`, which is the one call the store makes."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None, get: bool = False) -> Any:
        previous = self.values.get(key)
        if not nx or previous is None:
            self.values[key] = value
        return previous if get else (None if (nx and previous is not None) else True)


class _NoRedis:
    async def set(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis is down")

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis is down")


@pytest.mark.asyncio
async def test_the_first_sighting_is_not_seen_before_and_the_second_is() -> None:
    store = FirstSeenStore(_FakeRedis())
    event = {"publisher_ip": "198.51.100.9"}

    first = await store.derived_fields("t-1", event, now=1000.0)
    assert first["publisher_ip_seen_before"] is False

    second = await store.derived_fields("t-1", event, now=1060.0)
    assert second["publisher_ip_seen_before"] is True


@pytest.mark.asyncio
async def test_tenants_do_not_share_sightings() -> None:
    store = FirstSeenStore(_FakeRedis())
    event = {"publisher_ip": "198.51.100.9"}
    await store.derived_fields("t-1", event, now=1000.0)
    other = await store.derived_fields("t-2", event, now=1060.0)
    assert other["publisher_ip_seen_before"] is False


@pytest.mark.asyncio
async def test_an_unreadable_store_contributes_no_key() -> None:
    """Not `False`. `False` would fire every novelty rule on every event."""
    store = FirstSeenStore(_NoRedis())
    assert await store.derived_fields("t-1", {"publisher_ip": "198.51.100.9"}, now=1000.0) == {}


@pytest.mark.asyncio
async def test_an_absent_subject_contributes_no_key() -> None:
    store = FirstSeenStore(_FakeRedis())
    assert await store.derived_fields("t-1", {"event_type": "publish"}, now=1000.0) == {}
    assert await store.derived_fields("t-1", {"publisher_ip": ""}, now=1000.0) == {}


@pytest.mark.asyncio
async def test_age_is_measured_from_the_first_sighting() -> None:
    store = FirstSeenStore(_FakeRedis())
    event = {"session_id": "sess-1"}
    assert (await store.derived_fields("t-1", event, now=1000.0))["session_age_hours"] == 0.0
    later = await store.derived_fields("t-1", event, now=1000.0 + 7200)
    assert later["session_age_hours"] == pytest.approx(2.0)


@pytest.mark.asyncio
async def test_a_tenantless_event_is_not_recorded() -> None:
    """Without a tenant the key would be shared, which is a cross-tenant read."""
    redis = _FakeRedis()
    store = FirstSeenStore(redis)
    assert await store.derived_fields("", {"publisher_ip": "198.51.100.9"}, now=1000.0) == {}
    assert redis.values == {}


@pytest.mark.asyncio
async def test_a_client_without_set_get_still_works() -> None:
    """Older clients reject `get=True` on SET; the fallback must still answer."""

    class _OldClient:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}

        async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> Any:
            if nx and key in self.values:
                return None
            self.values[key] = value
            return True

        async def get(self, key: str) -> Any:
            return self.values.get(key)

    store = FirstSeenStore(_OldClient())
    event = {"publisher_ip": "198.51.100.9"}
    assert (await store.derived_fields("t-1", event, now=1000.0))["publisher_ip_seen_before"] is False
    assert (await store.derived_fields("t-1", event, now=1060.0))["publisher_ip_seen_before"] is True


def test_the_reachability_gate_mirrors_this_module() -> None:
    """A new first-seen field must be added in both places or it is invisible."""
    spec = importlib.util.spec_from_file_location("cdf_first_seen", _REPO / "scripts" / "check_detection_fields.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    assert gate._FIRST_SEEN_DERIVED_FIELDS == frozenset(SEEN_BEFORE_FIELDS) | frozenset(AGE_FIELDS)


def test_the_tracked_attributes_the_plan_names_are_all_keyed() -> None:
    """The plan lists the attributes the store is keyed by; hold it to them."""
    for attribute in ("src_country", "src_asn", "client_family", "oauth_app", "event_name", "resource"):
        assert attribute in TRACKED_ATTRIBUTES


def test_an_age_of_a_thing_is_not_answered_from_a_first_sighting() -> None:
    """The refusal this module exists to make, pinned.

    `domain_age_days` wants a registration age from a registry. Answering it
    from "when this deployment first saw the domain" would make the rule fire
    on most of the internet, so no table here may grow that key.
    """
    forbidden = {"domain_age_days", "key_age_days", "publisher_account_age_days", "distribution_age_days", "old_factor_age_days"}
    assert not forbidden & (set(SEEN_BEFORE_FIELDS) | set(AGE_FIELDS))

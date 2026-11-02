"""A scheduled hunt runs on the lake when the tenant connected no SIEM.

Wave 2, Phase 5.2.

The gap, and why it reads as a working feature
-----------------------------------------------
Until this change every registered provider took credentials from a
connector the tenant had enabled, and `resolve_provider` ended with

    for provider in translatable:
        if connected_types.intersection(provider.connector_types):
            return provider
    raise UnsupportedTranslation(...)

`_execute_hunt` catches that exception and **returns 0**. So a tenant with
no connected SIEM — the default deployment, whose data lives in AiSOC's own
lake because AiSOC's own connectors put it there — got a hit count of zero
from every scheduled hunt, forever. Zero hits is not an error state: no case
opens, nothing is logged above INFO, and the hunt's `last_run_at` moves. It
is indistinguishable on every surface from "your hunt ran and found
nothing".

This is the same shape as the recorded defect in
`event_warehouse/credentials.py`, where every provider resolved its
credentials from settings fields that were never declared and "every
scheduled hunt on every deployment returned zero hits, and the scheduler
logged the skip at INFO". That one was fixed by giving providers the
tenant's connector credentials. This is the half that fix could not reach:
a tenant who has connected nothing for the credentials to come from.

The first test below is the reproduction. On the pre-change tree it fails
with `UnsupportedTranslation`, which the scheduler converts to 0.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from app.services.event_warehouse import UnsupportedTranslation, resolve_provider
from app.services.event_warehouse.lake import DEFAULT_LOOKBACK_HOURS, LakeProvider

#: What the deterministic translator stores in `translated_query`: three
#: dialect renderings plus the structured intents the lake compiler reads.
#: Every key is present for every question, which is why selection cannot be
#: driven by the translation alone.
_TRANSLATED = {
    "esql": "FROM logs | WHERE user == 'svc-backup'",
    "spl": "index=main user=svc-backup",
    "kql": "user: svc-backup",
    "intents": {"users": ["svc-backup"]},
    "explanation": "authentication by svc-backup",
}


def _hunt(translated: Any = None, *, tenant: uuid.UUID | None = None) -> Any:
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.tenant_id = tenant or uuid.uuid4()
    hunt.translated_query = _TRANSLATED if translated is None else translated
    del hunt.warehouse_provider
    return hunt


# ── selection ─────────────────────────────────────────────────────────────


def test_a_tenant_with_no_connected_siem_resolves_to_the_lake() -> None:
    """The reproduction. Pre-change this raises and the scheduler returns 0."""
    provider = resolve_provider(_hunt(), connected_types=set())
    assert provider.name == "lake", (
        "a tenant with no connected SIEM resolved to no provider at all, so every "
        "scheduled hunt returned a hit count of zero that is indistinguishable "
        "from 'your hunt found nothing'"
    )


def test_a_connected_siem_still_wins_over_the_lake() -> None:
    """The lake must not quietly take over from a warehouse a tenant bought.

    A tenant with a SIEM has years of history AiSOC never ingested. Answering
    from the lake instead would be a narrower answer to the same question,
    delivered without anybody choosing it.
    """
    assert resolve_provider(_hunt(), connected_types={"elastic"}).name == "elasticsearch"
    assert resolve_provider(_hunt(), connected_types={"splunk"}).name == "splunk"


def test_a_hunt_with_no_intents_does_not_fall_through_to_the_lake() -> None:
    """Selection still needs a translation this provider can read.

    Without this, the lake would absorb every unroutable hunt and report a
    confident zero for questions it never compiled — the failure the
    `connected_types` filter was added to stop, one layer further down.
    """
    no_intents = {k: v for k, v in _TRANSLATED.items() if k != "intents"}
    with pytest.raises(UnsupportedTranslation):
        resolve_provider(_hunt(no_intents), connected_types=set())


def test_an_untranslated_hunt_still_raises_rather_than_reaching_the_lake() -> None:
    with pytest.raises(UnsupportedTranslation):
        resolve_provider(_hunt({}), connected_types=set())


# ── execution ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_lake_provider_binds_the_tenant_and_counts_rows(monkeypatch) -> None:
    """The hunt is compiled, not interpolated, and scoped to its tenant."""
    tenant = uuid.uuid4()
    seen: dict[str, Any] = {}

    def _compile(intents, *, tenant_id, hours, limit):  # noqa: ANN001, ANN202
        seen["tenant_id"] = tenant_id
        seen["hours"] = hours
        seen["limit"] = limit
        seen["users"] = intents.users
        return SimpleNamespace(
            sql="SELECT 1 FROM aisoc.raw_events WHERE tenant_id = %(tenant_id)s",
            params={"tenant_id": tenant_id},
            unsupported_fields=[],
        )

    async def _execute(sql, *, params=None):  # noqa: ANN001, ANN202
        seen["sql"] = sql
        seen["params"] = params
        return SimpleNamespace(row_count=7, columns=[], rows=[], elapsed_ms=3)

    monkeypatch.setattr("app.services.lake_hunt.compile_hunt", _compile)
    monkeypatch.setattr("app.db.clickhouse.execute_lake_query", _execute)

    hits = await LakeProvider().run_hunt(_hunt(tenant=tenant), credentials=None, max_rows=250)

    assert hits == 7
    assert seen["tenant_id"] == str(tenant)
    assert seen["hours"] == DEFAULT_LOOKBACK_HOURS
    assert seen["limit"] == 250
    # The intents survived the JSONB round trip into something compile_hunt
    # can read by attribute, rather than failing on the first getattr.
    assert seen["users"] == ["svc-backup"]
    # Bound, never interpolated.
    assert "%(tenant_id)s" in seen["sql"]
    assert seen["params"]["tenant_id"] == str(tenant)


@pytest.mark.asyncio
async def test_an_absent_intent_reads_as_absent_rather_than_raising(monkeypatch) -> None:
    """`compile_hunt` treats a missing intent as not asked for.

    The attribute view must agree: raising on an unknown key would turn a
    hunt that simply did not mention hosts into a failed run.
    """
    captured: dict[str, Any] = {}

    def _compile(intents, *, tenant_id, hours, limit):  # noqa: ANN001, ANN202
        captured["hosts"] = intents.hosts
        captured["users"] = intents.users
        return SimpleNamespace(sql="SELECT 1", params={}, unsupported_fields=[])

    async def _execute(sql, *, params=None):  # noqa: ANN001, ANN202
        return SimpleNamespace(row_count=0)

    monkeypatch.setattr("app.services.lake_hunt.compile_hunt", _compile)
    monkeypatch.setattr("app.db.clickhouse.execute_lake_query", _execute)

    assert await LakeProvider().run_hunt(_hunt(), credentials=None) == 0
    assert captured["hosts"] is None
    assert captured["users"] == ["svc-backup"]


@pytest.mark.asyncio
async def test_a_hunt_that_does_not_compile_is_a_skip_not_a_failure(monkeypatch) -> None:
    """Same class as 'translated for a warehouse I do not speak'."""
    from app.services.lake_hunt import HuntCompileError

    def _compile(intents, **kwargs):  # noqa: ANN001, ANN003, ANN202
        raise HuntCompileError("no supported field in this hunt")

    monkeypatch.setattr("app.services.lake_hunt.compile_hunt", _compile)

    with pytest.raises(UnsupportedTranslation):
        await LakeProvider().run_hunt(_hunt(), credentials=None)


@pytest.mark.asyncio
async def test_an_unreachable_lake_is_an_error_never_a_zero(monkeypatch) -> None:
    """The distinction this whole item exists to preserve.

    "The lake is down" and "your hunt found nothing" must not render the
    same. The scheduler's caller skips the `last_run_at` bump on an error, so
    the hunt retries; a zero would move the clock and open no case.
    """
    from app.services.event_warehouse import HuntExecutionError

    def _compile(intents, **kwargs):  # noqa: ANN001, ANN003, ANN202
        return SimpleNamespace(sql="SELECT 1", params={}, unsupported_fields=[])

    async def _execute(sql, *, params=None):  # noqa: ANN001, ANN202
        raise ConnectionError("clickhouse unreachable")

    monkeypatch.setattr("app.services.lake_hunt.compile_hunt", _compile)
    monkeypatch.setattr("app.db.clickhouse.execute_lake_query", _execute)

    with pytest.raises(HuntExecutionError):
        await LakeProvider().run_hunt(_hunt(), credentials=None)


@pytest.mark.asyncio
async def test_dropped_conditions_are_reported_rather_than_swallowed(monkeypatch, caplog) -> None:
    """A hunt that ran with conditions missing found fewer hits than was asked.

    Publishing that count with no caveat is a false negative with a number
    on it, so the dropped fields are logged by name.
    """

    def _compile(intents, **kwargs):  # noqa: ANN001, ANN003, ANN202
        return SimpleNamespace(sql="SELECT 1", params={}, unsupported_fields=["process_name", "registry_key"])

    async def _execute(sql, *, params=None):  # noqa: ANN001, ANN202
        return SimpleNamespace(row_count=2)

    monkeypatch.setattr("app.services.lake_hunt.compile_hunt", _compile)
    monkeypatch.setattr("app.db.clickhouse.execute_lake_query", _execute)

    with caplog.at_level("INFO"):
        assert await LakeProvider().run_hunt(_hunt(), credentials=None) == 2

    assert "process_name" in caplog.text and "registry_key" in caplog.text


# ── the scheduler's own wiring ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_scheduler_does_not_ask_for_credentials_the_lake_has_no_use_for(monkeypatch) -> None:
    """Asking the resolver for an empty connector set raises HuntNotConfigured.

    The scheduler's handler turns that into a soft skip and a zero — which
    is precisely the silent zero this item removes, reintroduced one layer
    up. So the scheduler must not ask at all for a provider that declares no
    connector types.
    """
    from app.workers import hunt_scheduler

    asked: list[Any] = []

    async def _resolve_credentials(db, tenant_id, *, connector_types):  # noqa: ANN001, ANN202
        asked.append(connector_types)
        from app.services.event_warehouse import HuntNotConfigured

        raise HuntNotConfigured("no connector of that type")

    async def _connected(db, tenant_id, *, candidate_types):  # noqa: ANN001, ANN202
        return set()

    monkeypatch.setattr(hunt_scheduler, "resolve_tenant_warehouse", _resolve_credentials)
    monkeypatch.setattr(hunt_scheduler, "connected_warehouse_types", _connected)

    async def _run_hunt(self, hunt, *, credentials=None, max_rows=500):  # noqa: ANN001, ANN202
        assert credentials is None, "the lake was handed credentials it has no use for"
        return 4

    monkeypatch.setattr(LakeProvider, "run_hunt", _run_hunt)

    hits = await hunt_scheduler._execute_hunt(MagicMock(), _hunt())

    assert hits == 4
    assert asked == [], "the scheduler asked for credentials for a provider that declares no connector types"

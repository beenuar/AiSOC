"""Wave-2 items 2.2, 2.3 and 2.4 reach the production path.

All three modules were built, unit-tested and imported by nothing that
runs. `scripts/check_module_reachability.py` named them, and the reason it
is worth a test here as well is that reachability is a static property: it
proves `main.py` mentions the module, not that an event passing through the
worker ever reaches it. These drive the worker.

The three are deliberately asserted differently, because they integrate
differently. 2.2 and 2.4 publish derived fields that must land in the
namespace the corpus is matched against; 2.3 publishes findings the worker
must promote into alerts.
"""

from __future__ import annotations

import time
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.services.detection_engine import DetectionEngine
from app.services.weak_signals import WeakFinding, WeakSignal, build_alert
from app.workers.consumer import FusionWorker

TENANT = "11111111-1111-1111-1111-111111111111"


def _message(fields: dict[str, Any]) -> dict[str, Any]:
    return {"tenant_id": TENANT, "ocsf_event": {"tenant_uid": TENANT, **fields}}


class _Store:
    """A derived-field store, recording what it was asked about."""

    def __init__(self, published: dict[str, Any]) -> None:
        self.published = published
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def derived_fields(self, tenant: str, event: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tenant, event))
        return self.published


@pytest.mark.asyncio
async def test_each_store_reaches_the_namespace_on_its_own() -> None:
    """The guard used to require first-seen or baselines to be present.

    So a deployment with only the later stores configured skipped the whole
    enrichment pass and every rule reading their fields silently stopped
    firing. Each store is asserted alone, which is the case that was broken.
    """
    engine = DetectionEngine()
    for keyword, published in (
        ("long_horizon", {"lh_failed_network_breadth": 42}),
        ("api_behaviour", {"api_unknown_parameter": True}),
        ("first_seen", {"first_seen_asn_for_principal": True}),
        ("baselines", {"baseline_principal_volume_z": 4.0}),
    ):
        store = _Store(published)
        fields = await engine.context_fields(_message({"src_ip": "198.51.100.7"}), **{keyword: store})
        assert fields == published, f"{keyword} alone did not reach the namespace"
        assert store.calls and store.calls[0][0] == TENANT


@pytest.mark.asyncio
async def test_no_store_means_no_work() -> None:
    assert await DetectionEngine().context_fields(_message({"src_ip": "198.51.100.7"})) == {}


def test_an_ingest_stamped_ip_class_survives_into_the_namespace() -> None:
    """2.3's anonymizer-egress signal reads `ip_class`.

    On a live event the class is stamped at ingest and carried on the event
    itself, so what matters is that enrichment lets the event's own value
    stand rather than overwriting it.
    """
    engine = DetectionEngine()
    fields = engine.namespace(_message({"src_ip": "198.51.100.7", "ip_class": "tor_exit"}))
    assert fields["ip_class"] == "tor_exit"


def test_the_namespace_asks_for_ip_class_even_when_no_rule_does(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asserted on the request, because the dataset may have no answer.

    `_derived_wanted` is computed from the rules, so a corpus where no rule
    names `ip_class` would stop asking for it and a committed fixture --
    which carries a `src_ip` and no ingest stamp -- would classify
    differently from the live event it stands for.
    """
    engine = DetectionEngine()
    engine._derived_wanted = set()
    asked: list[set[str]] = []

    def _spy(event: dict[str, Any], requested: set[str] | None = None, **kwargs: Any) -> dict[str, Any]:
        asked.append(set(requested or ()))
        return event

    monkeypatch.setattr("app.services.detection_engine.enrich", _spy)
    engine.namespace(_message({"src_ip": "198.51.100.7"}))
    assert asked and "ip_class" in asked[0]


class _Aggregator:
    def __init__(self, findings: list[WeakFinding]) -> None:
        self._findings = findings
        self.seen: list[dict[str, Any]] = []

    async def observe(self, tenant: str, event: dict[str, Any], **_: Any) -> list[WeakFinding]:
        self.seen.append(event)
        return self._findings


def _finding() -> WeakFinding:
    at = time.time()
    return WeakFinding(
        subject="victim@example.com",
        subject_kind="principal",
        strength=1.4,
        severity="high",
        confidence=72,
        signals=[
            WeakSignal(kind="new_country", detail="XX", at=at),
            WeakSignal(kind="anonymizer_egress", detail="tor_exit", at=at + 1),
        ],
    )


@pytest.mark.asyncio
async def test_a_weak_finding_becomes_one_alert_through_the_worker() -> None:
    """The promotion the module could not do for itself.

    `observe()` returns findings and nothing called it, so no finding had
    ever become an alert on any deployment.
    """
    persisted: list[Any] = []
    worker = FusionWorker(
        engine=SimpleNamespace(process=AsyncMock()),  # type: ignore[arg-type]
        detector=DetectionEngine(),
        weak_signals=_Aggregator([_finding()]),
    )
    worker._fuse_and_persist = AsyncMock(side_effect=lambda alert, **_: persisted.append(alert))  # type: ignore[method-assign]

    message = _message({"src_ip": "198.51.100.7", "actor_email": "victim@example.com"})
    await worker._aggregate_weak_signals(message, {"first_seen_country_for_principal": True})

    assert len(persisted) == 1
    alert = persisted[0]
    assert alert.tenant_id == uuid.UUID(TENANT)
    assert alert.rule_id == "weak-signal-aggregation"
    # Every contributor named, not summarised: the claim is that no single
    # signal could fire, so a reader has to see which several did.
    assert "new_country" in alert.description
    assert "anonymizer_egress" in alert.description


@pytest.mark.asyncio
async def test_the_aggregator_sees_the_fields_the_corpus_saw() -> None:
    """It reads first-seen and baseline keys, so it must get the same ones.

    A second caller recomputing the namespace its own way is how two readers
    of one event come to disagree about it.
    """
    aggregator = _Aggregator([])
    worker = FusionWorker(
        engine=SimpleNamespace(process=AsyncMock()),  # type: ignore[arg-type]
        detector=DetectionEngine(),
        weak_signals=aggregator,
    )
    await worker._aggregate_weak_signals(
        _message({"src_ip": "198.51.100.7"}),
        {"first_seen_asn_for_principal": True, "baseline_principal_volume_z": 4.0},
    )
    assert aggregator.seen, "the aggregator was never called"
    seen = aggregator.seen[0]
    assert seen["first_seen_asn_for_principal"] is True
    assert seen["baseline_principal_volume_z"] == 4.0


@pytest.mark.asyncio
async def test_an_unreachable_aggregator_does_not_cost_the_event() -> None:
    """Advisory, like the AI-estate recorder.

    An optional enrichment that can raise out of the consume loop is an
    optional enrichment that can stall the pipeline.
    """
    failing = SimpleNamespace(observe=AsyncMock(side_effect=ConnectionError("redis is gone")))
    worker = FusionWorker(
        engine=SimpleNamespace(process=AsyncMock()),  # type: ignore[arg-type]
        detector=DetectionEngine(),
        weak_signals=failing,
    )
    await worker._aggregate_weak_signals(_message({"src_ip": "198.51.100.7"}), {})


@pytest.mark.asyncio
async def test_a_finding_without_a_tenant_is_refused() -> None:
    """An alert that cannot be scoped to a tenant must not be written."""
    assert build_alert({"ocsf_event": {}}, {}, _finding()) is None


@pytest.mark.parametrize("keyword", ["long_horizon", "api_behaviour", "weak_signals"])
def test_the_worker_accepts_each_store(keyword: str) -> None:
    """Pins the constructor keywords `main.py` passes.

    Renaming one would leave `main.py` raising on boot rather than silently
    dropping the store, but only if something asserts the names agree.
    """
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock()), **{keyword: object()})  # type: ignore[arg-type]
    assert getattr(worker, f"_{keyword}") is not None

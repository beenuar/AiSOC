"""The bundle must carry the five context dimensions, and say when it cannot.

``entity_neighborhoods`` answers "what is reachable" as an undifferentiated
node set. An investigation needs "what does it mean": which person holds the
account, what is exploitable on the host, which business application it
serves, who is accountable, which actor the indicators point at. Those five
have to survive into the prompt separately, because a model handed a node set
re-derives them badly or not at all.

The property these tests protect hardest is the partial flag. An unreachable
graph and an alert with genuinely no context produce identical empty bundles,
and an agent that cannot distinguish them will reason as though absence of
context were evidence of absence.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.context.bundle import (
    ContextBundle,
    ContextBundleBuilder,
    IncidentContextDimensions,
)

FULL_PAYLOAD: dict[str, Any] = {
    "identities": [
        {
            "account": "j.doe@example.com",
            "employee": "Jordan Doe",
            "title": "Staff Engineer",
            "department": "Platform",
            "manager": "Sam Rivera",
            "is_active": False,
        }
    ],
    "assets": [
        {
            "name": "build-07",
            "owner": "Jordan Doe",
            "vulnerabilities": [{"cve_id": "CVE-2026-1234", "known_exploited": True}],
        }
    ],
    "cloud": [{"provider": "aws", "account_id": "1234", "environment": "prod", "secret_count": 3}],
    "business": [
        {
            "name": "Payments API",
            "criticality": "tier-1",
            "data_classification": "pci",
            "owner": "Ada Chen",
            "internet_facing": True,
        }
    ],
    "threat": [
        {
            "ioc": "203.0.113.9",
            "ioc_type": "ip",
            "malware": "ExampleLoader",
            "actor": "Example Group",
            "attribution_confidence": 65,
            "techniques": ["T1078", "T1566"],
        }
    ],
    "narrative": ["- Identity: account j.doe@example.com, held by Jordan Doe"],
    "partial": False,
    "errors": [],
}


class FakeResponse:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeClient:
    """Stands in for httpx.AsyncClient; records the request it was given."""

    calls: list[tuple[str, dict[str, Any]]] = []

    def __init__(self, payload: Any = None, *, boom: Exception | None = None) -> None:
        self._payload = payload
        self._boom = boom

    def __call__(self, *args: Any, **kwargs: Any) -> FakeClient:
        return self

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        FakeClient.calls.append((url, kwargs))
        if self._boom is not None:
            raise self._boom
        return FakeResponse(self._payload)


@pytest.fixture(autouse=True)
def _reset_calls() -> None:
    FakeClient.calls = []


def _patch_client(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> None:
    import app.context.bundle as module

    monkeypatch.setattr(module.httpx, "AsyncClient", client)


class TestFetch:
    async def test_dimensions_land_in_the_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, FakeClient(FULL_PAYLOAD))
        builder = ContextBundleBuilder()
        result = await builder._fetch_incident_context("tenant-a", {"id": "alert-1"})

        assert result.dimensions_resolved == 5
        assert result.identities[0]["employee"] == "Jordan Doe"
        assert result.business[0]["criticality"] == "tier-1"
        assert result.threat[0]["actor"] == "Example Group"
        assert not result.partial

    async def test_the_tenant_is_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Scoping is enforced API-side; the caller must identify itself."""
        _patch_client(monkeypatch, FakeClient(FULL_PAYLOAD))
        await ContextBundleBuilder()._fetch_incident_context("tenant-a", {"id": "alert-1"})

        url, kwargs = FakeClient.calls[0]
        assert "alert-1" in url
        assert kwargs["headers"]["X-Tenant-ID"] == "tenant-a"

    @pytest.mark.parametrize("key", ["id", "alert_id", "external_id"])
    async def test_alert_id_is_read_from_any_of_the_three_shapes(self, monkeypatch: pytest.MonkeyPatch, key: str) -> None:
        """Fused alerts, API alerts and vendor findings spell it differently."""
        _patch_client(monkeypatch, FakeClient(FULL_PAYLOAD))
        await ContextBundleBuilder()._fetch_incident_context("t", {key: "alert-9"})
        assert "alert-9" in FakeClient.calls[0][0]

    async def test_no_alert_id_does_not_call_the_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, FakeClient(FULL_PAYLOAD))
        result = await ContextBundleBuilder()._fetch_incident_context("t", {})
        assert FakeClient.calls == []
        assert result.dimensions_resolved == 0


class TestPartial:
    async def test_partial_flag_survives_into_the_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {**FULL_PAYLOAD, "partial": True, "errors": ["threat (TimeoutError)"], "threat": []}
        _patch_client(monkeypatch, FakeClient(payload))
        result = await ContextBundleBuilder()._fetch_incident_context("t", {"id": "a"})

        assert result.partial
        assert result.errors == ["threat (TimeoutError)"]
        assert result.dimensions_resolved == 4, "the surviving dimensions were discarded"

    async def test_an_api_failure_does_not_poison_the_whole_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_safe wraps every fetcher; this asserts the wiring, not the helper."""
        _patch_client(monkeypatch, FakeClient(boom=RuntimeError("api down")))

        class State:
            incident_id = None
            tenant_id = "t"
            alert_summary = "suspicious login"
            raw_alert = {"id": "alert-1"}

        bundle = await ContextBundleBuilder().build(State())
        assert isinstance(bundle, ContextBundle)
        assert bundle.build_completed_at is not None
        assert bundle.incident_context.dimensions_resolved == 0


class TestHasAnyContext:
    def test_dimensions_alone_count_as_context(self) -> None:
        """Otherwise an alert whose only context is business criticality
        short-circuits to bare-alert reasoning and discards it."""
        bundle = ContextBundle(incident_id=__import__("uuid").uuid4())
        assert not bundle.has_any_context

        bundle.incident_context = IncidentContextDimensions(business=[{"name": "Payments API", "criticality": "tier-1"}])
        assert bundle.has_any_context

    def test_an_empty_dimensions_object_is_not_context(self) -> None:
        bundle = ContextBundle(incident_id=__import__("uuid").uuid4())
        bundle.incident_context = IncidentContextDimensions(partial=True, errors=["graph down"])
        assert not bundle.has_any_context, (
            "a failed lookup was counted as context; the agent would then " "take the bundle-aware path with nothing in it"
        )


def test_dimensions_resolved_counts_populated_slots_only() -> None:
    d = IncidentContextDimensions()
    assert d.dimensions_resolved == 0
    d.identities = [{"account": "a"}]
    d.assets = [{"id": "h"}]
    assert d.dimensions_resolved == 2
    assert d.has_content


class TestPromptRendering:
    """What reaches the model is the only thing that changes a verdict."""

    def _bundle(self, dimensions: IncidentContextDimensions) -> ContextBundle:
        bundle = ContextBundle(incident_id=__import__("uuid").uuid4())
        bundle.incident_context = dimensions
        return bundle

    def test_narrative_reaches_the_prompt(self) -> None:
        bundle = self._bundle(
            IncidentContextDimensions(
                business=[{"name": "Payments API"}],
                narrative=["- Business: Payments API, criticality tier-1, data pci"],
            )
        )
        text = "\n".join(bundle.prompt_context_lines())
        assert "Entity context" in text
        assert "criticality tier-1" in text

    def test_narrative_is_not_re_summarised(self) -> None:
        """Re-rendering here would drop the qualifiers that keep it honest."""
        line = "- Threat: ip 1.2.3.4, attributed to Example Group (attribution unconfirmed)"
        bundle = self._bundle(IncidentContextDimensions(threat=[{"ioc": "1.2.3.4"}], narrative=[line]))
        assert any(line in rendered for rendered in bundle.prompt_context_lines())

    def test_failed_lookup_is_stated_rather_than_omitted(self) -> None:
        """Silence reads to a model as 'no context exists', which is not what
        a timeout means."""
        bundle = self._bundle(IncidentContextDimensions(partial=True, errors=["identities (TimeoutError)"]))
        text = "\n".join(bundle.prompt_context_lines())
        assert "unavailable" in text
        assert "identities (TimeoutError)" in text
        assert "not as benign" in text

    def test_nothing_is_added_when_there_is_nothing_to_say(self) -> None:
        bundle = self._bundle(IncidentContextDimensions())
        assert "Entity context" not in "\n".join(bundle.prompt_context_lines())

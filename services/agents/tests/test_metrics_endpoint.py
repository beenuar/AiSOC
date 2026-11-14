"""The agents metrics endpoint: reachable, correct, and not open by default.

The auto-triage worker already counted everything worth counting into a
module dict that was read by exactly one log line at shutdown. Two of those
counters are the operator's early warning and neither could be scraped:
`dead_lettered` rising means alerts are being dropped rather than triaged,
and `deterministic` climbing while `llm` stays flat means the LLM path is
failing open to the fallback — which looks fine from outside, because alerts
still get verdicts.

The auth tests matter as much as the counter tests. An unauthenticated
metrics endpoint on the open internet is a slow leak of internal state, and
the mistake is made by omission.
"""

from __future__ import annotations

import pytest
from app.api.metrics import _TRIAGE, router
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestAuth:
    def test_open_in_development(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_ENV", "development")
        monkeypatch.delenv("METRICS_TOKEN", raising=False)
        assert client.get("/metrics").status_code == 200

    def test_refused_outside_development_when_no_token_is_set(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Refuse rather than expose internal counters anonymously."""
        monkeypatch.setenv("AISOC_ENV", "production")
        monkeypatch.delenv("METRICS_TOKEN", raising=False)
        response = client.get("/metrics")
        assert response.status_code == 401
        assert "METRICS_TOKEN" in response.json()["detail"]

    def test_refused_when_the_environment_is_unset(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unset environment must not be treated as development.

        This is the failure mode that ships an open endpoint: nobody sets
        AISOC_ENV in the container, and a permissive default makes that
        silently public.
        """
        monkeypatch.delenv("AISOC_ENV", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        monkeypatch.delenv("METRICS_TOKEN", raising=False)
        assert client.get("/metrics").status_code == 401

    def test_token_is_required_when_configured(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_ENV", "development")
        monkeypatch.setenv("METRICS_TOKEN", "s3cret")
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200

    def test_a_token_overrides_the_development_exemption(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configuring a token means it is enforced, dev or not."""
        monkeypatch.setenv("AISOC_ENV", "development")
        monkeypatch.setenv("METRICS_TOKEN", "s3cret")
        assert client.get("/metrics").status_code == 401


class TestCounters:
    @pytest.fixture(autouse=True)
    def _dev(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_ENV", "development")
        monkeypatch.delenv("METRICS_TOKEN", raising=False)
        # The counter is process-global and correctly refuses to go
        # backwards, so without this each test inherits the previous
        # test's totals and the assertions become order-dependent.
        # Clearing is what a process restart does.
        _TRIAGE.clear()

    def test_renders_prometheus_text_format(self, client: TestClient) -> None:
        response = client.get("/metrics")
        assert response.headers["content-type"].startswith("text/plain")
        assert "aisoc_agents_triage_total" in response.text

    def test_worker_counters_reach_the_scrape(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.workers import fused_alert_consumer

        monkeypatch.setattr(
            fused_alert_consumer,
            "_METRICS",
            {"triaged": 7, "dead_lettered": 2, "llm": 5, "deterministic": 2},
        )
        body = client.get("/metrics").text
        assert 'aisoc_agents_triage_total{result="triaged"} 7.0' in body
        assert 'aisoc_agents_triage_total{result="dead_lettered"} 2.0' in body

    def test_a_scrape_does_not_double_count(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """The worker owns the running total; this is a projection of it.

        Incrementing per scrape would multiply every counter by the scrape
        count, and the resulting graph would look like traffic.
        """
        from app.workers import fused_alert_consumer

        monkeypatch.setattr(fused_alert_consumer, "_METRICS", {"triaged": 3})
        client.get("/metrics")
        client.get("/metrics")
        body = client.get("/metrics").text
        assert 'aisoc_agents_triage_total{result="triaged"} 3.0' in body

    def test_counters_only_move_forward(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """A worker restart resets its dict; a Prometheus counter must not
        go backwards, because a decrease is read as a counter reset and
        produces a spike in every rate() over that window."""
        from app.workers import fused_alert_consumer

        monkeypatch.setattr(fused_alert_consumer, "_METRICS", {"errors": 9})
        client.get("/metrics")
        monkeypatch.setattr(fused_alert_consumer, "_METRICS", {"errors": 0})
        body = client.get("/metrics").text
        assert 'aisoc_agents_triage_total{result="errors"} 9.0' in body

    def test_a_missing_worker_is_an_empty_scrape_not_an_error(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """The worker needs Kafka and is often absent. Its absence means no
        triage activity, not a broken endpoint."""
        from app.workers import fused_alert_consumer

        def boom() -> dict[str, int]:
            raise RuntimeError("worker not started")

        monkeypatch.setattr(fused_alert_consumer.FusedAlertTriageWorker, "get_metrics", staticmethod(boom))
        assert client.get("/metrics").status_code == 200


def test_the_endpoint_is_mounted_unprefixed() -> None:
    """Prometheus scrapes /metrics, not /api/v1/metrics."""
    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert "/metrics" in paths


def test_a_private_registry_is_used() -> None:
    """The global default registry would raise on a second import, and
    carries collectors from anything else linked into the process."""
    from prometheus_client import REGISTRY

    assert _TRIAGE._name not in {  # noqa: SLF001
        getattr(c, "_name", None)
        for c in REGISTRY._collector_to_names  # noqa: SLF001
    }

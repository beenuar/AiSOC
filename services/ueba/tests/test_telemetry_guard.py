"""Tracing can no longer point at the service's own container (issue #1848).

The OTLP exporter was built inline in ``main.py`` against
``settings.otel_endpoint``, defaulting to ``http://localhost:4317`` — inside
a container that is this service itself, so every span export failed and the
batch processor retried a refused connection every few seconds. These pins
hold the replacement to its three properties: quiet by default, the compose
collector (never localhost) when enabled, and no resurrectable config field.
"""

from __future__ import annotations

import pytest
from app.core import telemetry
from app.core.config import settings


@pytest.fixture(autouse=True)
def _reset_latch(monkeypatch):
    monkeypatch.setattr(telemetry, "_STATE", {})
    monkeypatch.delenv("OTEL_EXPORTER", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    yield
    telemetry._STATE.clear()


def test_tracing_is_disabled_by_default():
    """No OTEL_EXPORTER means no exporter — one log line, never a retry loop.

    Deliberately diverging from api/agents (default otlp): this service emits
    spans continuously, so a dead default endpoint is hundreds of
    export-failure lines on a stand without the monitoring profile.
    """
    assert telemetry.exporter_name() == "none"
    assert telemetry.instrument_service_app(object(), settings.service_name) is False


def test_the_default_endpoint_is_the_compose_collector_not_localhost(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER", "otlp")
    endpoint = telemetry.otlp_endpoint()
    assert endpoint == "http://otel-collector:4317"
    assert "localhost" not in endpoint, (
        "inside a container localhost is this service itself; an exporter pointed there can never reach the collector"
    )


def test_an_operator_endpoint_is_honoured(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example:4317")
    assert telemetry.otlp_endpoint() == "http://collector.example:4317"


def test_an_unknown_exporter_disables_rather_than_guesses(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER", "zipkin")
    assert telemetry.instrument_service_app(object(), settings.service_name) is False


def test_the_localhost_config_field_is_gone():
    """``otel_endpoint`` must not come back: it was the defect, not a knob.

    The replacement reads ``OTEL_EXPORTER_OTLP_ENDPOINT`` — the OpenTelemetry
    convention the api and agents services already use.
    """
    assert not hasattr(settings, "otel_endpoint")

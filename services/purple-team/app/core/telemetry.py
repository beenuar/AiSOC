"""Guarded OpenTelemetry bootstrap (issue #1848).

The OTLP exporter used to be constructed inline in ``main.py``, pointed at
``settings.otel_endpoint`` with a default of ``http://localhost:4317``.
Inside a container ``localhost`` is the service itself, so tracing could
never reach the collector — which runs at ``otel-collector:4317``, behind
the compose ``monitoring`` profile — and the batch span processor retried a
refused connection every few seconds, hundreds of export-failure log lines
over a few hours on a stand with no collector. The code looked instrumented
while exporting nothing, which is worse than no tracing at all.

Vendored byte-identical into ``ueba``, ``honeytokens`` and ``purple-team``,
following the same convention as ``app/core/cors.py``; the canonical shape
is ``services/api/app/core/telemetry.py``.

Exporters, selected by ``OTEL_EXPORTER``:

- ``none``    → disabled. **The default here**, deliberately diverging from
  ``api``/``agents`` (whose default is ``otlp``): this service emits spans
  continuously, so with no collector a live exporter is a retry loop in the
  logs, while ``api``/``agents`` emit almost none and stay quiet. One log
  line says tracing is off and which variable turns it on.
- ``otlp``    → OTLP/gRPC to ``OTEL_EXPORTER_OTLP_ENDPOINT``, defaulting to
  ``http://otel-collector:4317`` — the compose service, never ``localhost``.
  Set this when running the ``monitoring`` profile.
- ``console`` → spans to stdout, for local development.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

#: The compose collector, reachable only with the `monitoring` profile up.
DEFAULT_OTLP_ENDPOINT = "http://otel-collector:4317"

#: Quiet by default — see the module docstring for why this differs from api.
DEFAULT_EXPORTER = "none"

#: Latch so instrument_service_app is idempotent. A dict rather than a
#: rebindable module global: the name is written from inside the function,
#: and CodeQL's cross-file analysis of three byte-identical copies (every
#: service packages as `app`) misreads rebinding writes as unused.
_STATE: dict[str, bool] = {}


def exporter_name() -> str:
    """The exporter this process should use, from ``OTEL_EXPORTER``."""
    return (os.getenv("OTEL_EXPORTER") or DEFAULT_EXPORTER).strip().lower()


def otlp_endpoint() -> str:
    """The collector endpoint, from ``OTEL_EXPORTER_OTLP_ENDPOINT``."""
    return (os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or DEFAULT_OTLP_ENDPOINT).strip()


def _build_exporter(name: str):
    if name == "console":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        return ConsoleSpanExporter()
    if name == "otlp":
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError:
            logger.warning("OTEL_EXPORTER=otlp but opentelemetry-exporter-otlp-proto-grpc is not installed; tracing disabled")
            return None
        return OTLPSpanExporter(endpoint=otlp_endpoint(), insecure=True)
    if name != "none":
        logger.warning("OTEL_EXPORTER=%r is not one of none|otlp|console; tracing disabled", name)
    return None


def instrument_service_app(app, service_name: str) -> bool:  # noqa: ANN001
    """Set up the tracer provider and FastAPI instrumentation. Idempotent.

    Returns whether tracing is live, so the caller's startup line can say
    so. Disabled — by configuration or by missing packages — costs exactly
    one log line, never a retry loop.

    Named differently from the api/agents ``instrument_app(app)`` on
    purpose: every service packages its code as ``app``, so a shared symbol
    name with a different arity reads as a wrong-arguments call to any
    whole-repository analysis (and to any human grepping across services).
    """
    if "enabled" in _STATE:
        return _STATE["enabled"]

    name = exporter_name()
    if name == "none":
        logger.info("OpenTelemetry tracing disabled (OTEL_EXPORTER unset; set OTEL_EXPORTER=otlp with the monitoring profile)")
        _STATE["enabled"] = False
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning("OpenTelemetry packages not installed; tracing disabled")
        _STATE["enabled"] = False
        return False

    exporter = _build_exporter(name)
    if exporter is None:
        _STATE["enabled"] = False
        return False

    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: service_name}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
    logger.info("OpenTelemetry tracing enabled exporter=%s endpoint=%s", name, otlp_endpoint() if name == "otlp" else "-")
    _STATE["enabled"] = True
    return True

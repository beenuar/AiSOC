"""
OpenTelemetry bootstrap for AiSOC Agents service.

Instruments:
  - FastAPI   (HTTP spans)
  - httpx     (outbound HTTP calls — enrichment, plugin invocations)
  - LangGraph agent nodes via manual spans (get_tracer)

Configuration (env vars):
  OTEL_EXPORTER              otlp | jaeger | console | none  (default: otlp)
  OTEL_SERVICE_NAME          aisoc-agents  (default)
  OTEL_EXPORTER_OTLP_ENDPOINT  http://otel-collector:4317  (default)
  ENVIRONMENT                development | staging | production

Usage:
  from app.core.telemetry import get_tracer, instrument_app

  tracer = get_tracer(__name__)
  with tracer.start_as_current_span("investigate.recon") as span:
      span.set_attribute("case.id", state.case_id)
      span.set_attribute("agent", "recon")
"""
from __future__ import annotations

import logging
import os

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

logger = logging.getLogger(__name__)

_TRACER_PROVIDER: TracerProvider | None = None


def _make_resource() -> Resource:
    return Resource.create(
        {
            SERVICE_NAME: os.getenv("OTEL_SERVICE_NAME", "aisoc-agents"),
            SERVICE_VERSION: os.getenv("AISOC_VERSION", "4.0.0"),
            "deployment.environment": os.getenv("ENVIRONMENT", "development"),
        }
    )


def _build_exporter(exporter_name: str):
    name = exporter_name.lower()

    if name == "console":
        return ConsoleSpanExporter()

    if name == "jaeger":
        try:
            from opentelemetry.exporter.jaeger.thrift import JaegerExporter  # type: ignore
            return JaegerExporter(
                agent_host_name=os.getenv("JAEGER_HOST", "jaeger"),
                agent_port=int(os.getenv("JAEGER_PORT", "6831")),
            )
        except ImportError:
            logger.warning("Jaeger exporter not installed; falling back to OTLP")
            name = "otlp"

    if name == "otlp":
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore
            endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
            return OTLPSpanExporter(endpoint=endpoint, insecure=True)
        except ImportError:
            logger.warning(
                "opentelemetry-exporter-otlp-proto-grpc not installed; "
                "set OTEL_EXPORTER=console for local dev"
            )
            return None

    return None


def setup_telemetry() -> TracerProvider:
    """Initialise the global TracerProvider. Idempotent."""
    global _TRACER_PROVIDER
    if _TRACER_PROVIDER is not None:
        return _TRACER_PROVIDER

    exporter_name = os.getenv("OTEL_EXPORTER", "otlp")
    provider = TracerProvider(resource=_make_resource())

    exporter = _build_exporter(exporter_name)
    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))
        logger.info("OpenTelemetry tracing enabled", extra={"exporter": exporter_name})

    trace.set_tracer_provider(provider)
    _TRACER_PROVIDER = provider
    return provider


def instrument_app(app) -> None:  # noqa: ANN001
    """Attach auto-instrumentation to a FastAPI app."""
    setup_telemetry()

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        pass

    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
        HTTPXClientInstrumentor().instrument()
    except ImportError:
        pass


def get_tracer(name: str = "aisoc-agents") -> trace.Tracer:
    """Return a named tracer, initialising telemetry if needed."""
    if _TRACER_PROVIDER is None:
        setup_telemetry()
    return trace.get_tracer(name)

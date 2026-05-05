"""
OpenTelemetry bootstrap for AiSOC API service.

Instruments:
  - FastAPI   (HTTP spans — method, route, status)
  - SQLAlchemy (DB query spans)
  - httpx     (outbound HTTP spans)
  - Manual    spans via get_tracer()

Exporters (selected by OTEL_EXPORTER env var):
  - "otlp"    → OTLP/gRPC to OTEL_EXPORTER_OTLP_ENDPOINT  (default)
  - "jaeger"  → Jaeger Thrift HTTP  (legacy)
  - "console" → stdout (local dev)
  - "none"    → no-op / disabled

Usage:
  from app.core.telemetry import get_tracer, instrument_app

  instrument_app(fastapi_app)          # called once in create_application()
  tracer = get_tracer(__name__)
  with tracer.start_as_current_span("my-op") as span:
      span.set_attribute("case.id", case_id)
"""

from __future__ import annotations

import logging
import os

from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

logger = logging.getLogger(__name__)

_TRACER_PROVIDER: TracerProvider | None = None


def _make_resource() -> Resource:
    return Resource.create(
        {
            SERVICE_NAME: os.getenv("OTEL_SERVICE_NAME", "aisoc-api"),
            SERVICE_VERSION: os.getenv("AISOC_VERSION", "4.0.0"),
            "deployment.environment": os.getenv("ENVIRONMENT", "development"),
        }
    )


def _build_exporter(exporter_name: str):
    """Return a span exporter for the given name."""
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
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,  # type: ignore
            )

            endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
            return OTLPSpanExporter(endpoint=endpoint, insecure=True)
        except ImportError:
            logger.warning("opentelemetry-exporter-otlp-proto-grpc not installed; install it or set OTEL_EXPORTER=console")
            return None

    # "none" or unknown → no exporter
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
    else:
        logger.info("OpenTelemetry tracing disabled (exporter=none or unavailable)")

    trace.set_tracer_provider(provider)
    _TRACER_PROVIDER = provider
    return provider


def instrument_app(app) -> None:  # noqa: ANN001
    """
    Attach auto-instrumentation to a FastAPI app.

    Must be called *after* the app is created but *before* it starts serving.
    """
    setup_telemetry()

    # FastAPI
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore

        FastAPIInstrumentor.instrument_app(app)
        logger.debug("FastAPI auto-instrumented")
    except ImportError:
        logger.warning("opentelemetry-instrumentation-fastapi not installed; skipping")

    # SQLAlchemy (engine-level spans)
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # type: ignore

        SQLAlchemyInstrumentor().instrument()
        logger.debug("SQLAlchemy auto-instrumented")
    except ImportError:
        logger.warning("opentelemetry-instrumentation-sqlalchemy not installed; skipping")

    # httpx (outbound HTTP calls — plugin invocations, enrichment calls, etc.)
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore

        HTTPXClientInstrumentor().instrument()
        logger.debug("httpx auto-instrumented")
    except ImportError:
        pass  # Optional — no warning needed


def get_tracer(name: str = "aisoc") -> trace.Tracer:
    """Return a named tracer, initialising telemetry if not yet done."""
    if _TRACER_PROVIDER is None:
        setup_telemetry()
    return trace.get_tracer(name)

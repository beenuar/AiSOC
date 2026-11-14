"""Streaming detection REST API (t6-streaming).

  GET   /streaming/rules         List active streaming rules.
  POST  /streaming/events        Push one event into the runtime.
  GET   /streaming/detections    Recent detections (newest first).
  GET   /streaming/stats         Runtime stats (ingest rate, drops, etc).

Why expose this over HTTP at all? In the current platform the
ingest path *is* the FastAPI process — the OCSF normaliser hands
events to whichever detection layer is configured. Exposing the
streaming layer over HTTP gives operators a way to dry-run the
windowed rules against synthetic events without booting a Kafka
broker.

When detection compute moves off-process to Flink/Bytewax, this
endpoint becomes a thin proxy to that engine; the on-disk rule
definitions stay in this repo.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.security.tenant import TenantContext, require_tenant
from app.streaming.registry import get_streaming_runtime


router = APIRouter(prefix="/streaming", tags=["streaming"])


class StreamingEventRequest(BaseModel):
    """One OCSF-ish event the streaming runtime will fan out to rules."""

    event_time: float = Field(gt=0)
    event_class: str = Field(min_length=1, max_length=64)
    outcome: str | None = Field(default=None, max_length=32)
    src_user: str | None = Field(default=None, max_length=200)
    src_host: str | None = Field(default=None, max_length=200)
    dst_host: str | None = Field(default=None, max_length=200)
    share: str | None = Field(default=None, max_length=200)
    rare_process: bool = False
    dst_external: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


def _serialize_detection(d) -> dict[str, Any]:  # noqa: ANN001 - dataclass at runtime
    return {
        "rule_id": d.rule_id,
        "tenant_id": d.tenant_id,
        "key": d.key,
        "event_time": d.event_time,
        "severity": d.severity,
        "description": d.description,
        "matching_event_count": d.matching_event_count,
        "sample_events": list(d.sample_events),
    }


@router.get("/rules")
def list_streaming_rules() -> dict[str, Any]:
    rt = get_streaming_runtime()
    return {
        "count": len(rt.rules),
        "rules": [
            {
                "rule_id": r.rule_id,
                "severity": r.severity,
                "description": r.description,
                "window_size_seconds": r.window.size_seconds,
                "window_slide_seconds": r.window.slide_seconds,
                "key_field": r.key_field,
                "kind": type(r).__name__,
            }
            for r in rt.rules
        ],
    }


@router.post("/events")
def post_streaming_event(
    body: StreamingEventRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Ingest a single event for the active tenant.

    Detections that fire as a result of the watermark advance
    triggered by this event are returned synchronously so a caller
    can correlate cause and effect during evaluation.
    """
    payload = body.model_dump(exclude_unset=False)
    payload.update(payload.pop("extra", {}))
    payload["tenant_id"] = ctx.active_tenant_id

    runtime = get_streaming_runtime()
    try:
        detections = runtime.ingest(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "ingested": 1,
        "detections": [_serialize_detection(d) for d in detections],
        "stats": _stats_payload(runtime),
    }


@router.get("/detections")
def list_recent_detections(
    limit: int = 50,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    runtime = get_streaming_runtime()
    detections = [
        d
        for d in reversed(runtime.recent_detections())
        if d.tenant_id == ctx.active_tenant_id
    ][:limit]
    return {
        "count": len(detections),
        "detections": [_serialize_detection(d) for d in detections],
    }


@router.get("/stats")
def streaming_stats(_: TenantContext = Depends(require_tenant)) -> dict[str, Any]:
    runtime = get_streaming_runtime()
    return _stats_payload(runtime)


def _stats_payload(runtime) -> dict[str, Any]:  # noqa: ANN001 - runtime is internal
    s = runtime.stats
    return {
        "events_ingested": s.events_ingested,
        "events_dropped_late": s.events_dropped_late,
        "detections_emitted": s.detections_emitted,
        "windows_evaluated": s.windows_evaluated,
    }

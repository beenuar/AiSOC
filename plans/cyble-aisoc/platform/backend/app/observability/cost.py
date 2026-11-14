"""Per-case observability + cost roll-ups (t4-observability).

Two surfaces:

1. ``case_observability(case_id, tenant_id)`` -> :class:`CaseObservability`:
   per-case roll-up of LLM token spend, agent latency, tool-call
   latency, and counts. Used by the case-file UI's "cost" panel and
   by the FinOps dashboard.

2. ``platform_observability(tenant_id, hours=24)`` ->
   :class:`PlatformObservability`: tenant-wide aggregate over a
   rolling window. Used by the dashboard view.

3. ``to_otel_payload(case_id, tenant_id)`` -> dict: OpenTelemetry-
   compatible trace export. Each :class:`AgentTrace` becomes one
   ``span`` with the agent / step / token counts mapped to span
   attributes. Each :class:`ToolCall` becomes a child span. The
   payload follows the OTel JSON spec so an operator can pipe it into
   any OTel collector without translation.

Design rules:

- Read-only and tenant-scoped. Every helper opens a single short DB
  scope, snapshots, and exits.
- Cheap enough to surface on the case file (sub-millisecond on the
  demo DB).
- Token spend uses an in-memory price table keyed on
  ``(provider, model)``. The table is intentionally conservative —
  customers can override it via ``AISOC_LLM_PRICE_OVERRIDES_JSON``
  when their procurement contract differs from the public list price.
"""
from __future__ import annotations

import os
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlmodel import select

from app.db import session_scope
from app.models.case import Case
from app.models.tool_call import ToolCall
from app.models.trace import AgentName, AgentTrace, TraceStep


# Per-1k-token price (USD) by (provider, model). The numbers are
# deliberately rounded to two decimals because the FinOps dashboard
# rounds to one cent anyway. When a model isn't in the table we fall
# back to the conservative default below so the dashboard never shows
# "$0.00" for a model whose pricing we just haven't curated yet.
_DEFAULT_PRICE_PER_1K_INPUT = 0.0030
_DEFAULT_PRICE_PER_1K_OUTPUT = 0.0150


_DEFAULT_PRICE_TABLE: dict[tuple[str, str], tuple[float, float]] = {
    # OpenAI
    ("openai", "gpt-4o"): (0.005, 0.015),
    ("openai", "gpt-4o-mini"): (0.00015, 0.0006),
    ("openai", "gpt-4.1"): (0.005, 0.015),
    ("openai", "gpt-4.1-mini"): (0.0008, 0.0024),
    # Anthropic
    ("anthropic", "claude-3-5-sonnet-20241022"): (0.003, 0.015),
    ("anthropic", "claude-3-5-haiku-20241022"): (0.00080, 0.0040),
    ("anthropic", "claude-3-opus-20240229"): (0.015, 0.075),
    # The deterministic mock provider is free.
    ("mock", "mock-deterministic"): (0.0, 0.0),
}


def _load_price_overrides() -> dict[tuple[str, str], tuple[float, float]]:
    """Optional JSON env override for per-tenant pricing contracts.

    Format: ``{"<provider>:<model>": {"input": 0.001, "output": 0.005}}``.
    """
    blob = os.environ.get("AISOC_LLM_PRICE_OVERRIDES_JSON")
    if not blob:
        return {}
    try:
        raw = json.loads(blob)
    except Exception:
        return {}
    out: dict[tuple[str, str], tuple[float, float]] = {}
    for key, value in raw.items():
        if ":" not in key or not isinstance(value, dict):
            continue
        provider, model = key.split(":", 1)
        out[(provider.strip(), model.strip())] = (
            float(value.get("input", _DEFAULT_PRICE_PER_1K_INPUT)),
            float(value.get("output", _DEFAULT_PRICE_PER_1K_OUTPUT)),
        )
    return out


def _price_for(provider: str, model: str) -> tuple[float, float]:
    overrides = _load_price_overrides()
    key = (provider, model)
    if key in overrides:
        return overrides[key]
    if key in _DEFAULT_PRICE_TABLE:
        return _DEFAULT_PRICE_TABLE[key]
    # Last resort: use the conservative default so the dashboard never
    # claims a brand-new unknown model is free.
    return _DEFAULT_PRICE_PER_1K_INPUT, _DEFAULT_PRICE_PER_1K_OUTPUT


# ─── DTOs ───────────────────────────────────────────────────────────


@dataclass
class AgentRollup:
    agent: str
    steps: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    cost_usd: float = 0.0


@dataclass
class ToolRollup:
    tool_name: str
    integration: str
    calls: int = 0
    failures: int = 0
    duration_ms: int = 0
    rollbacks: int = 0


@dataclass
class CaseObservability:
    case_id: int
    tenant_id: str
    tokens_in_total: int = 0
    tokens_out_total: int = 0
    cost_usd_total: float = 0.0
    agent_latency_ms_total: int = 0
    tool_duration_ms_total: int = 0
    trace_count: int = 0
    tool_call_count: int = 0
    rollback_count: int = 0
    by_agent: list[AgentRollup] = field(default_factory=list)
    by_tool: list[ToolRollup] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlatformObservability:
    tenant_id: str
    window_hours: int
    cases_observed: int = 0
    tokens_in_total: int = 0
    tokens_out_total: int = 0
    cost_usd_total: float = 0.0
    avg_cost_usd_per_case: float = 0.0
    avg_tokens_per_case: float = 0.0
    by_agent: list[AgentRollup] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Helpers ────────────────────────────────────────────────────────


def _coerce_step(step: Any) -> str:
    return step.value if isinstance(step, TraceStep) else str(step)


def _coerce_agent(agent: Any) -> str:
    return agent.value if isinstance(agent, AgentName) else str(agent)


def _trace_provider_model(trace: AgentTrace) -> tuple[str, str]:
    detail = trace.detail or {}
    provider = detail.get("provider") or detail.get("llm_provider") or "mock"
    model = detail.get("model") or detail.get("llm_model") or "mock-deterministic"
    return str(provider), str(model)


# ─── Per-case ──────────────────────────────────────────────────────


def _snapshot_traces(traces: list[AgentTrace]) -> list[dict[str, Any]]:
    """Snapshot ORM rows into plain dicts so callers can use them
    after the session closes."""
    return [
        {
            "agent": _coerce_agent(t.agent),
            "tokens_in": int(t.tokens_in or 0),
            "tokens_out": int(t.tokens_out or 0),
            "latency_ms": int(t.latency_ms or 0),
            "provider": _trace_provider_model(t)[0],
            "model": _trace_provider_model(t)[1],
        }
        for t in traces
    ]


def _snapshot_tool_calls(tool_calls: list[ToolCall]) -> list[dict[str, Any]]:
    return [
        {
            "tool_name": tc.tool_name,
            "integration": tc.integration,
            "success": bool(tc.success),
            "duration_ms": int(tc.duration_ms or 0),
            "rolled_back": tc.rolled_back_at is not None or tc.rollback_of_id is not None,
        }
        for tc in tool_calls
    ]


def case_observability(
    case_id: int, tenant_id: str
) -> Optional[CaseObservability]:
    """Aggregate observability for one case.

    Returns ``None`` when the case does not exist or is owned by a
    different tenant.
    """
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None or case.tenant_id != tenant_id:
            return None
        traces = list(
            session.exec(
                select(AgentTrace)
                .where(AgentTrace.case_id == case_id)
                .where(AgentTrace.tenant_id == tenant_id)
            ).all()
        )
        tool_calls = list(
            session.exec(
                select(ToolCall)
                .where(ToolCall.case_id == case_id)
                .where(ToolCall.tenant_id == tenant_id)
            ).all()
        )
        trace_snaps = _snapshot_traces(traces)
        tool_snaps = _snapshot_tool_calls(tool_calls)

    by_agent: dict[str, AgentRollup] = {}
    cost_total = 0.0
    for t in trace_snaps:
        agent = t["agent"]
        rollup = by_agent.setdefault(agent, AgentRollup(agent=agent))
        rollup.steps += 1
        rollup.tokens_in += t["tokens_in"]
        rollup.tokens_out += t["tokens_out"]
        rollup.latency_ms += t["latency_ms"]
        in_per_1k, out_per_1k = _price_for(t["provider"], t["model"])
        cost = (
            t["tokens_in"] * in_per_1k / 1000.0
            + t["tokens_out"] * out_per_1k / 1000.0
        )
        rollup.cost_usd += round(cost, 6)
        cost_total += cost

    by_tool: dict[str, ToolRollup] = {}
    rollback_count = 0
    for tc in tool_snaps:
        key = tc["tool_name"]
        rollup_tool = by_tool.setdefault(
            key,
            ToolRollup(tool_name=tc["tool_name"], integration=tc["integration"]),
        )
        rollup_tool.calls += 1
        if not tc["success"]:
            rollup_tool.failures += 1
        rollup_tool.duration_ms += tc["duration_ms"]
        if tc["rolled_back"]:
            rollup_tool.rollbacks += 1
            rollback_count += 1

    return CaseObservability(
        case_id=case_id,
        tenant_id=tenant_id,
        tokens_in_total=sum(r.tokens_in for r in by_agent.values()),
        tokens_out_total=sum(r.tokens_out for r in by_agent.values()),
        cost_usd_total=round(cost_total, 6),
        agent_latency_ms_total=sum(r.latency_ms for r in by_agent.values()),
        tool_duration_ms_total=sum(r.duration_ms for r in by_tool.values()),
        trace_count=len(trace_snaps),
        tool_call_count=len(tool_snaps),
        rollback_count=rollback_count,
        by_agent=list(by_agent.values()),
        by_tool=list(by_tool.values()),
    )


def platform_observability(
    tenant_id: str, *, window_hours: int = 24
) -> PlatformObservability:
    """Tenant-wide observability over the last ``window_hours``."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    with session_scope() as session:
        cases = list(
            session.exec(
                select(Case)
                .where(Case.tenant_id == tenant_id)
                .where(Case.created_at >= cutoff)
            ).all()
        )
        case_ids = [c.id for c in cases if c.id is not None]
        traces: list[AgentTrace] = []
        if case_ids:
            traces = list(
                session.exec(
                    select(AgentTrace)
                    .where(AgentTrace.tenant_id == tenant_id)
                    .where(AgentTrace.case_id.in_(case_ids))
                ).all()
            )
        cases_observed = len(cases)
        trace_snaps = _snapshot_traces(traces)

    by_agent: dict[str, AgentRollup] = {}
    cost_total = 0.0
    tokens_in_total = 0
    tokens_out_total = 0
    for t in trace_snaps:
        agent = t["agent"]
        rollup = by_agent.setdefault(agent, AgentRollup(agent=agent))
        rollup.steps += 1
        rollup.tokens_in += t["tokens_in"]
        rollup.tokens_out += t["tokens_out"]
        rollup.latency_ms += t["latency_ms"]
        in_per_1k, out_per_1k = _price_for(t["provider"], t["model"])
        cost = (
            t["tokens_in"] * in_per_1k / 1000.0
            + t["tokens_out"] * out_per_1k / 1000.0
        )
        rollup.cost_usd += round(cost, 6)
        cost_total += cost
        tokens_in_total += t["tokens_in"]
        tokens_out_total += t["tokens_out"]

    avg_cost = round(
        cost_total / cases_observed if cases_observed else 0.0, 6
    )
    avg_tokens = round(
        ((tokens_in_total + tokens_out_total) / cases_observed)
        if cases_observed
        else 0.0,
        2,
    )
    return PlatformObservability(
        tenant_id=tenant_id,
        window_hours=window_hours,
        cases_observed=cases_observed,
        tokens_in_total=tokens_in_total,
        tokens_out_total=tokens_out_total,
        cost_usd_total=round(cost_total, 6),
        avg_cost_usd_per_case=avg_cost,
        avg_tokens_per_case=avg_tokens,
        by_agent=list(by_agent.values()),
    )


# ─── OpenTelemetry export ───────────────────────────────────────────


def _trace_payload_to_span(
    *,
    payload: dict[str, Any],
    trace_id_hex: str,
    parent_span_id: str | None,
) -> dict[str, Any]:
    """Map one snapshotted trace dict to an OTel span dict."""
    start_ns = int(
        (
            payload.get("created_at") or datetime.now(timezone.utc)
        ).timestamp()
        * 1_000_000_000
    )
    duration_ns = int(payload.get("latency_ms", 0) * 1_000_000)
    span_id = format(
        int.from_bytes((str(payload.get("id")) + "agent").encode(), "big") % (2**64),
        "016x",
    )
    return {
        "name": f"{payload['agent']}.{payload['step']}",
        "traceId": trace_id_hex,
        "spanId": span_id,
        "parentSpanId": parent_span_id or "",
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": start_ns,
        "endTimeUnixNano": start_ns + duration_ns,
        "attributes": [
            {"key": "agent.name", "value": {"stringValue": payload["agent"]}},
            {"key": "agent.step", "value": {"stringValue": payload["step"]}},
            {"key": "case.id", "value": {"intValue": int(payload["case_id"])}},
            {
                "key": "case.tenant_id",
                "value": {"stringValue": str(payload["tenant_id"])},
            },
            {
                "key": "llm.tokens.in",
                "value": {"intValue": int(payload.get("tokens_in", 0))},
            },
            {
                "key": "llm.tokens.out",
                "value": {"intValue": int(payload.get("tokens_out", 0))},
            },
            {
                "key": "summary",
                "value": {"stringValue": payload.get("summary", "")},
            },
        ],
        "status": {"code": "STATUS_CODE_OK"},
    }


def _tool_payload_to_span(
    *,
    payload: dict[str, Any],
    trace_id_hex: str,
    parent_span_id: str | None,
) -> dict[str, Any]:
    start_ns = int(
        (
            payload.get("created_at") or datetime.now(timezone.utc)
        ).timestamp()
        * 1_000_000_000
    )
    duration_ns = int(payload.get("duration_ms", 0) * 1_000_000)
    span_id = format(
        int.from_bytes((str(payload.get("id")) + "tool").encode(), "big") % (2**64),
        "016x",
    )
    return {
        "name": payload["tool_name"],
        "traceId": trace_id_hex,
        "spanId": span_id,
        "parentSpanId": parent_span_id or "",
        "kind": "SPAN_KIND_CLIENT",
        "startTimeUnixNano": start_ns,
        "endTimeUnixNano": start_ns + duration_ns,
        "attributes": [
            {"key": "tool.name", "value": {"stringValue": payload["tool_name"]}},
            {
                "key": "tool.integration",
                "value": {"stringValue": payload["integration"]},
            },
            {
                "key": "tool.risk_class",
                "value": {"stringValue": payload["risk_class"]},
            },
            {
                "key": "tool.hitl_required",
                "value": {"boolValue": bool(payload.get("hitl_required", False))},
            },
            {"key": "case.id", "value": {"intValue": int(payload["case_id"])}},
        ],
        "status": {
            "code": "STATUS_CODE_OK"
            if payload.get("success", True)
            else "STATUS_CODE_ERROR"
        },
    }


def to_otel_payload(case_id: int, tenant_id: str) -> Optional[dict[str, Any]]:
    """OpenTelemetry-compatible JSON payload for a case.

    Builds a single root span for the case with each agent step and
    each tool call as a child span. The payload follows the OTel
    JSON spec (resourceSpans / scopeSpans / spans), so it can be
    POSTed straight to an OTel collector without translation.
    """
    case_meta: dict[str, Any] = {}
    trace_payloads: list[dict[str, Any]] = []
    tool_payloads: list[dict[str, Any]] = []
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None or case.tenant_id != tenant_id:
            return None
        traces = list(
            session.exec(
                select(AgentTrace)
                .where(AgentTrace.case_id == case_id)
                .where(AgentTrace.tenant_id == tenant_id)
                .order_by(AgentTrace.created_at.asc())
            ).all()
        )
        tool_calls = list(
            session.exec(
                select(ToolCall)
                .where(ToolCall.case_id == case_id)
                .where(ToolCall.tenant_id == tenant_id)
                .order_by(ToolCall.id.asc())
            ).all()
        )

        # Snapshot every field we'll need *before* the session closes so
        # we never hit DetachedInstanceError on access below.
        case_meta = {
            "id": case.id,
            "tenant_id": case.tenant_id,
            "severity": case.severity.value
            if hasattr(case.severity, "value")
            else str(case.severity),
            "verdict": case.verdict.value
            if hasattr(case.verdict, "value")
            else str(case.verdict),
            "created_at": case.created_at,
            "closed_at": case.closed_at,
            "updated_at": case.updated_at,
        }
        trace_payloads = [
            {
                "id": t.id,
                "case_id": t.case_id,
                "tenant_id": t.tenant_id,
                "agent": _coerce_agent(t.agent),
                "step": _coerce_step(t.step),
                "summary": t.summary or "",
                "tokens_in": int(t.tokens_in or 0),
                "tokens_out": int(t.tokens_out or 0),
                "latency_ms": int(t.latency_ms or 0),
                "created_at": t.created_at,
            }
            for t in traces
        ]
        tool_payloads = [
            {
                "id": tc.id,
                "case_id": tc.case_id,
                "tenant_id": tc.tenant_id,
                "tool_name": tc.tool_name,
                "integration": tc.integration,
                "risk_class": tc.risk_class.value
                if hasattr(tc.risk_class, "value")
                else str(tc.risk_class),
                "success": bool(tc.success),
                "duration_ms": int(tc.duration_ms or 0),
                "hitl_required": bool(tc.hitl_required),
                "created_at": tc.created_at,
            }
            for tc in tool_calls
        ]

    trace_id_hex = format(case_id, "032x")
    root_span_id = format(int(time.time()) % (2**64), "016x")
    case_start_ns = int(
        (case_meta.get("created_at") or datetime.now(timezone.utc)).timestamp()
        * 1_000_000_000
    )
    case_end_ns = int(
        (
            case_meta.get("closed_at")
            or case_meta.get("updated_at")
            or datetime.now(timezone.utc)
        ).timestamp()
        * 1_000_000_000
    )

    spans: list[dict[str, Any]] = [
        {
            "name": f"case.{case_id}",
            "traceId": trace_id_hex,
            "spanId": root_span_id,
            "kind": "SPAN_KIND_SERVER",
            "startTimeUnixNano": case_start_ns,
            "endTimeUnixNano": case_end_ns,
            "attributes": [
                {"key": "case.id", "value": {"intValue": case_id}},
                {
                    "key": "case.tenant_id",
                    "value": {"stringValue": str(tenant_id)},
                },
                {
                    "key": "case.severity",
                    "value": {"stringValue": case_meta.get("severity") or ""},
                },
                {
                    "key": "case.verdict",
                    "value": {"stringValue": case_meta.get("verdict") or ""},
                },
            ],
            "status": {"code": "STATUS_CODE_OK"},
        }
    ]
    for trace_payload in trace_payloads:
        spans.append(
            _trace_payload_to_span(
                payload=trace_payload,
                trace_id_hex=trace_id_hex,
                parent_span_id=root_span_id,
            )
        )
    for tool_payload in tool_payloads:
        spans.append(
            _tool_payload_to_span(
                payload=tool_payload,
                trace_id_hex=trace_id_hex,
                parent_span_id=root_span_id,
            )
        )

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {"stringValue": "cyble-aisoc"},
                        },
                        {
                            "key": "deployment.environment",
                            "value": {
                                "stringValue": os.environ.get(
                                    "AISOC_ENV", "demo"
                                )
                            },
                        },
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "app.observability", "version": "0.1.0"},
                        "spans": spans,
                    }
                ],
            }
        ]
    }

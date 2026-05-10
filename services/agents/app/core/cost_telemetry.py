"""Investigation cost telemetry.

Tracks token usage, model calls, latency, and estimated USD cost per run.
Persists aggregates to PostgreSQL (best-effort) and emits structlog events
that feed into the SOC metrics dashboard.

Usage::

    from app.core.cost_telemetry import CostTracker

    async with CostTracker(run_id="r1", tenant_id="t1") as tracker:
        result = await llm_call(...)
        tracker.record(
            model="gpt-4o",
            prompt_tokens=result.usage.prompt_tokens,
            completion_tokens=result.usage.completion_tokens,
            latency_ms=elapsed_ms,
        )
    # On __aexit__, aggregates are flushed to DB.
"""

from __future__ import annotations

import contextvars
import os
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Active-tracker context variable
# ---------------------------------------------------------------------------
# LangGraph threads the agent state through its nodes as a plain dict, so we
# cannot pass a CostTracker via the call signature without rewriting every
# agent. A contextvar lets each agent look up the tracker bound by its caller
# (the orchestrator) without changing the graph schema.

_current_tracker: contextvars.ContextVar[CostTracker | None] = contextvars.ContextVar(
    "aisoc_cost_tracker",
    default=None,
)


def current_cost_tracker() -> CostTracker | None:
    """Return the cost tracker bound to the current async context, if any."""
    return _current_tracker.get()


# ---------------------------------------------------------------------------
# Model pricing (USD per 1 k tokens, input / output)
# ---------------------------------------------------------------------------
_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-4": (0.03, 0.06),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "claude-3-5-sonnet-20241022": (0.003, 0.015),
    "claude-3-opus-20240229": (0.015, 0.075),
    "claude-3-haiku-20240307": (0.00025, 0.00125),
    "gemini-1.5-pro": (0.00125, 0.005),
    "gemini-1.5-flash": (0.000075, 0.0003),
}

_DEFAULT_PRICE = (0.001, 0.002)


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    in_price, out_price = _PRICING.get(model.lower(), _DEFAULT_PRICE)
    return (prompt_tokens / 1000) * in_price + (completion_tokens / 1000) * out_price


# ---------------------------------------------------------------------------
# Per-call record
# ---------------------------------------------------------------------------


@dataclass
class CallRecord:
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    cost_usd: float = 0.0
    tool: str | None = None
    step: str | None = None

    def __post_init__(self) -> None:
        self.cost_usd = _estimate_cost(self.model, self.prompt_tokens, self.completion_tokens)


# ---------------------------------------------------------------------------
# DB persistence
# ---------------------------------------------------------------------------

_POOL: Any = None


async def _get_pool() -> Any | None:
    global _POOL
    if _POOL is not None:
        return _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        return None
    try:
        import asyncpg  # type: ignore[import]

        pool = await asyncpg.create_pool(
            dsn.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://"),
            min_size=1,
            max_size=2,
        )
        async with pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS aisoc_run_costs (
                    run_id          TEXT NOT NULL,
                    tenant_id       TEXT NOT NULL,
                    model           TEXT,
                    total_prompt_tokens     INTEGER NOT NULL DEFAULT 0,
                    total_completion_tokens INTEGER NOT NULL DEFAULT 0,
                    total_cost_usd  DOUBLE PRECISION NOT NULL DEFAULT 0,
                    total_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
                    call_count      INTEGER NOT NULL DEFAULT 0,
                    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (run_id, tenant_id, model)
                );
                CREATE INDEX IF NOT EXISTS aisoc_run_costs_tenant_run
                    ON aisoc_run_costs (tenant_id, run_id);
                """
            )
        _POOL = pool
        return _POOL
    except Exception as exc:
        logger.debug("cost_telemetry.db_unavailable", error=str(exc))
        return None


async def _flush_to_db(
    run_id: str,
    tenant_id: str,
    records: list[CallRecord],
) -> None:
    if not records:
        return
    pool = await _get_pool()
    if pool is None:
        return

    # Aggregate by model
    by_model: dict[str, dict] = {}
    for r in records:
        m = by_model.setdefault(r.model, {"prompt": 0, "completion": 0, "cost": 0.0, "latency": 0.0, "calls": 0})
        m["prompt"] += r.prompt_tokens
        m["completion"] += r.completion_tokens
        m["cost"] += r.cost_usd
        m["latency"] += r.latency_ms
        m["calls"] += 1

    try:
        async with pool.acquire() as conn:
            for model, agg in by_model.items():
                await conn.execute(
                    """
                    INSERT INTO aisoc_run_costs
                        (run_id, tenant_id, model,
                         total_prompt_tokens, total_completion_tokens,
                         total_cost_usd, total_latency_ms, call_count)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (run_id, tenant_id, model) DO UPDATE
                        SET total_prompt_tokens     = aisoc_run_costs.total_prompt_tokens + EXCLUDED.total_prompt_tokens,
                            total_completion_tokens = aisoc_run_costs.total_completion_tokens + EXCLUDED.total_completion_tokens,
                            total_cost_usd          = aisoc_run_costs.total_cost_usd + EXCLUDED.total_cost_usd,
                            total_latency_ms        = aisoc_run_costs.total_latency_ms + EXCLUDED.total_latency_ms,
                            call_count              = aisoc_run_costs.call_count + EXCLUDED.call_count,
                            recorded_at             = now()
                    """,
                    run_id,
                    tenant_id,
                    model,
                    agg["prompt"],
                    agg["completion"],
                    agg["cost"],
                    agg["latency"],
                    agg["calls"],
                )
    except Exception as exc:
        logger.warning("cost_telemetry.flush_error", run_id=run_id, error=str(exc))


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------


@dataclass
class CostTracker:
    run_id: str
    tenant_id: str
    _records: list[CallRecord] = field(default_factory=list, init=False)
    _start: float = field(default_factory=time.monotonic, init=False)

    _token: Any = field(default=None, init=False, repr=False)

    async def __aenter__(self) -> CostTracker:
        # Bind into the current context so nested agents can find us.
        self._token = _current_tracker.set(self)
        return self

    async def __aexit__(self, *_: Any) -> None:
        try:
            await self.flush()
        finally:
            if self._token is not None:
                try:
                    _current_tracker.reset(self._token)
                except (LookupError, ValueError):
                    pass
                self._token = None

    def record(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        tool: str | None = None,
        step: str | None = None,
    ) -> CallRecord:
        rec = CallRecord(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            tool=tool,
            step=step,
        )
        self._records.append(rec)
        logger.info(
            "cost_telemetry.call",
            run_id=self.run_id,
            tenant_id=self.tenant_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=f"{rec.cost_usd:.6f}",
            latency_ms=f"{latency_ms:.1f}",
            tool=tool,
            step=step,
        )
        return rec

    @property
    def total_cost_usd(self) -> float:
        return sum(r.cost_usd for r in self._records)

    @property
    def total_tokens(self) -> int:
        return sum(r.prompt_tokens + r.completion_tokens for r in self._records)

    @property
    def total_latency_ms(self) -> float:
        return sum(r.latency_ms for r in self._records)

    def summary(self) -> dict:
        return {
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "total_cost_usd": self.total_cost_usd,
            "total_tokens": self.total_tokens,
            "total_latency_ms": self.total_latency_ms,
            "call_count": len(self._records),
            "models": list({r.model for r in self._records}),
        }

    async def flush(self) -> None:
        summary = self.summary()
        logger.info("cost_telemetry.run_summary", **summary)
        await _flush_to_db(self.run_id, self.tenant_id, self._records)


# ---------------------------------------------------------------------------
# Helpers for extracting token usage from LLM responses
# ---------------------------------------------------------------------------


def _extract_token_usage(response: Any) -> tuple[int, int]:
    """Best-effort extraction of (prompt_tokens, completion_tokens) from a
    LangChain / OpenAI / Anthropic response object.

    Newer LangChain releases expose ``response.usage_metadata`` with
    ``input_tokens`` / ``output_tokens``. Older paths populate
    ``response.response_metadata['token_usage']``. Some providers only give a
    ``total_tokens`` rollup; in that case we attribute everything to prompt.
    Returns ``(0, 0)`` when nothing is available so that recording never
    crashes the investigation.
    """
    if response is None:
        return 0, 0

    usage_meta = getattr(response, "usage_metadata", None)
    if isinstance(usage_meta, dict):
        prompt = int(usage_meta.get("input_tokens", 0) or 0)
        completion = int(usage_meta.get("output_tokens", 0) or 0)
        if prompt or completion:
            return prompt, completion
        total = int(usage_meta.get("total_tokens", 0) or 0)
        if total:
            return total, 0

    response_meta = getattr(response, "response_metadata", None)
    if isinstance(response_meta, dict):
        token_usage = response_meta.get("token_usage")
        if isinstance(token_usage, dict):
            prompt = int(token_usage.get("prompt_tokens", 0) or 0)
            completion = int(token_usage.get("completion_tokens", 0) or 0)
            if prompt or completion:
                return prompt, completion
            total = int(token_usage.get("total_tokens", 0) or 0)
            if total:
                return total, 0

    return 0, 0


def record_llm_call(
    response: Any,
    *,
    model: str,
    latency_ms: float,
    step: str | None = None,
    tool: str | None = None,
) -> CallRecord | None:
    """Record an LLM call against the currently active CostTracker, if any.

    No-op when no tracker is bound. Returns the ``CallRecord`` so callers can
    persist ``cost_usd`` into the audit log alongside the existing
    ``tokens_used`` field.
    """
    tracker = current_cost_tracker()
    if tracker is None:
        return None
    prompt_tokens, completion_tokens = _extract_token_usage(response)
    return tracker.record(
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=latency_ms,
        tool=tool,
        step=step,
    )

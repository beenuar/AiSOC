"""Investigation cost telemetry — what a run spent, and how that is known.

Tracks token usage, model calls, latency, and USD cost per run. Persists
aggregates to PostgreSQL (best-effort) and emits structlog events that feed
the cost dashboard and the SOC metrics dashboard.

Every dollar figure here carries its provenance
-----------------------------------------------
This module used to price a call by looking its **model name** up in a table
of hosted list prices. The name it looked up was an ``aisoc-<role>`` alias,
which is not a model — it is a label the LiteLLM gateway resolves to one. No
alias is in the table, so every call fell through to a ``(0.001, 0.002)``
default: a price nobody charges, for a model nobody named. A 903-token
completion on an operator's own hardware was reported as
``total_cost_usd=0.000999``, and that number reached the cost dashboard, the
per-run ledger, and the budget circuit breaker, which trips at
``AISOC_BUDGET_HARD_USD`` and would have degraded a working local deployment
to deterministic-only over money that was never spent.

A call is now booked under exactly one of three provenances, and the counts
travel with the sums everywhere:

``GATEWAY`` — measured
    The gateway reported the cost on the response headers. It resolved the
    alias, so it is the only party that knows what was actually called. This
    is real money (and is legitimately ``0.0`` for a local model, which is a
    *measured* zero, not an absent one).

``LIST_PRICE_ESTIMATE`` — estimated, and labelled as such on every surface
    No gateway figure, but the concrete model is one this table has a public
    list price for. Only ever keyed on a **concrete** model id — the alias, or
    the resolved model name the gateway supplied — never on an alias alone.

``UNPRICED`` — not measured
    Neither of the above. Reported as *not measured*, never as zero. Following
    the precedent set for MTTR (``services/api/app/api/v1/endpoints/metrics.py``),
    where a mean over zero rows was shipping as a confident ``0.0`` until the
    sample count travelled with it.

There is deliberately no "total cost" that mixes measured with estimated
money: a single number cannot be labelled two ways, and un-labelling an
estimate by adding it to a measurement is the defect one level up.

Usage::

    from app.core.cost_telemetry import CostTracker

    async with CostTracker(run_id="r1", tenant_id="t1") as tracker:
        result = await llm_call(...)
        tracker.record(
            model="aisoc-triage",
            prompt_tokens=..., completion_tokens=..., latency_ms=...,
            gateway_cost=extract_gateway_cost(result),   # None => not measured
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

from app.core.gateway_cost import GatewayCost, extract_gateway_cost, extract_resolved_model
from app.core.schema_bootstrap import ensure_table

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
# Cost provenance
# ---------------------------------------------------------------------------

#: The gateway reported what the call cost. Real money; ``0.0`` is a measured
#: zero (a local model), not a missing figure.
GATEWAY = "gateway"

#: Re-priced from a public list price for a concrete model. An approximation,
#: and labelled as one on every surface it reaches.
LIST_PRICE_ESTIMATE = "list_price_estimate"

#: Neither available. Reported as "not measured", never as zero.
UNPRICED = "unpriced"

COST_SOURCES = (GATEWAY, LIST_PRICE_ESTIMATE, UNPRICED)


# ---------------------------------------------------------------------------
# Public list pricing (USD per 1 k tokens, input / output)
#
# Keys are **concrete model ids**. There is deliberately no default entry: a
# model absent from this table has no known price, and inventing one is the
# defect this module was rewritten to remove. A gateway alias is never a key
# here and can never become one — see ``_estimate_cost``.
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

#: Shape of a logical task alias. An alias is resolved by the gateway and
#: carries no price of its own, so it is refused as a pricing key outright
#: rather than being allowed to miss the table and take a default.
_GATEWAY_ALIAS_PREFIX = "aisoc-"


def _price_key(model: str | None) -> str | None:
    """The table key for ``model``, or ``None`` if it cannot be priced.

    Providers are commonly prefixed at the gateway (``openai/gpt-4o-mini``,
    ``ollama/qwen2:1.5b``), so the provider segment is dropped before lookup —
    but only for a name that actually carries one, and never for an alias.
    """
    name = (model or "").strip().lower()
    if not name or name.startswith(_GATEWAY_ALIAS_PREFIX):
        return None
    if name in _PRICING:
        return name
    bare = name.rsplit("/", 1)[-1]
    return bare if bare in _PRICING else None


def _estimate_cost(model: str | None, prompt_tokens: int, completion_tokens: int) -> float | None:
    """List-price estimate for ``model``, or ``None`` when it has no known price.

    ``None`` is the whole point. The previous version returned a number
    unconditionally, so "we know this model's price" and "we guessed" were
    indistinguishable by the time the figure reached a dashboard.
    """
    key = _price_key(model)
    if key is None:
        return None
    in_price, out_price = _PRICING[key]
    return (max(prompt_tokens, 0) / 1000) * in_price + (max(completion_tokens, 0) / 1000) * out_price


# ---------------------------------------------------------------------------
# Per-call record
# ---------------------------------------------------------------------------


@dataclass
class CallRecord:
    """One LLM call, with what it cost and how that is known.

    ``cost_usd`` is ``None`` when ``cost_source`` is :data:`UNPRICED`. It is
    never silently zero: a caller that wants to add these up must decide what
    to do about the calls nobody can price.
    """

    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    cost_usd: float | None = None
    cost_source: str = UNPRICED
    #: What the gateway resolved ``model`` to, when it said. The alias asked
    #: for is not the model billed, and only this answers "billed for what".
    resolved_model: str | None = None
    #: Correlates with the gateway's own ``/spend/logs`` entry.
    call_id: str | None = None
    tool: str | None = None
    step: str | None = None
    gateway_cost: GatewayCost | None = None

    def __post_init__(self) -> None:
        gateway = self.gateway_cost
        if gateway is not None:
            self.cost_usd = gateway.cost_usd
            self.cost_source = GATEWAY
            self.resolved_model = self.resolved_model or gateway.resolved_model
            self.call_id = self.call_id or gateway.call_id
            return
        # No gateway figure. An estimate is allowed only against a concrete
        # model id — preferring what the gateway said it resolved to, since
        # that is the thing that would actually have been billed.
        estimate = _estimate_cost(self.resolved_model, self.prompt_tokens, self.completion_tokens)
        if estimate is None:
            estimate = _estimate_cost(self.model, self.prompt_tokens, self.completion_tokens)
        if estimate is None:
            self.cost_usd = None
            self.cost_source = UNPRICED
        else:
            self.cost_usd = estimate
            self.cost_source = LIST_PRICE_ESTIMATE

    @property
    def is_measured(self) -> bool:
        return self.cost_source == GATEWAY

    @property
    def is_estimated(self) -> bool:
        return self.cost_source == LIST_PRICE_ESTIMATE


@dataclass(frozen=True)
class CostSummary:
    """A run's spend and the provenance of it, as one value.

    Exists so callers pass the whole picture around rather than a bare float.
    A single ``cost_usd: float = 0.0`` parameter is what let an unmeasured run
    be persisted, traced and budgeted as a free one — the default was
    indistinguishable from a measurement of zero at every call site.
    """

    measured_usd: float | None = None
    measured_calls: int = 0
    estimated_usd: float | None = None
    estimated_calls: int = 0
    unpriced_calls: int = 0

    @classmethod
    def from_tracker(cls, tracker: CostTracker) -> CostSummary:
        return cls(
            measured_usd=tracker.measured_cost_usd,
            measured_calls=tracker.measured_call_count,
            estimated_usd=tracker.estimated_cost_usd,
            estimated_calls=tracker.estimated_call_count,
            unpriced_calls=tracker.unpriced_call_count,
        )


# ---------------------------------------------------------------------------
# DB persistence
# ---------------------------------------------------------------------------

_POOL: Any = None

#: Only used when the table is genuinely absent — normally it arrives with
#: ``services/api/migrations/020_soc_metrics_h2.sql``, which also gives it the
#: RLS policy this copy cannot.
_RUN_COSTS_DDL = """
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

#: Cost provenance, added by ``services/api/migrations/055_cost_provenance.sql``.
#: Applied here too because this writer has to run against a database whose
#: migrations it does not own, and a write that silently drops the provenance
#: columns would leave every new row indistinguishable from the pre-provenance
#: rows it exists to separate. Idempotent, and a no-op where 055 already ran.
_RUN_COSTS_PROVENANCE_DDL = """
ALTER TABLE aisoc_run_costs
    ADD COLUMN IF NOT EXISTS measured_cost_usd    DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS measured_call_count  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS estimated_cost_usd   DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS estimated_call_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unpriced_call_count  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS resolved_model       TEXT;
"""


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
            # Probe before creating: the runtime role holds DML only, and
            # `CREATE TABLE IF NOT EXISTS` checks the schema ACL before the
            # existence test, so it raises even when the table is there. See
            # app/core/schema_bootstrap.py.
            if not await ensure_table(conn, "aisoc_run_costs", _RUN_COSTS_DDL):
                await pool.close()
                return None
            try:
                await conn.execute(_RUN_COSTS_PROVENANCE_DDL)
            except Exception as exc:  # noqa: BLE001
                # The runtime role may hold DML only, in which case migration
                # 055 is the one that adds these. Loud enough to diagnose a
                # dashboard stuck on "not measured", quiet enough not to fail
                # the run: the token counts still land.
                logger.warning("cost_telemetry.provenance_columns_unavailable", error=str(exc))
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
        m = by_model.setdefault(
            r.model,
            {
                "prompt": 0,
                "completion": 0,
                "measured": 0.0,
                "measured_calls": 0,
                "estimated": 0.0,
                "estimated_calls": 0,
                "unpriced_calls": 0,
                "latency": 0.0,
                "calls": 0,
                "resolved": None,
            },
        )
        m["prompt"] += r.prompt_tokens
        m["completion"] += r.completion_tokens
        m["latency"] += r.latency_ms
        m["calls"] += 1
        if r.is_measured:
            m["measured"] += r.cost_usd or 0.0
            m["measured_calls"] += 1
        elif r.is_estimated:
            m["estimated"] += r.cost_usd or 0.0
            m["estimated_calls"] += 1
        else:
            m["unpriced_calls"] += 1
        if r.resolved_model and not m["resolved"]:
            m["resolved"] = r.resolved_model

    try:
        async with pool.acquire() as conn:
            for model, agg in by_model.items():
                await conn.execute(
                    # ``total_cost_usd`` carries **measured** cost only, and the
                    # provenance columns beside it say how much of the window
                    # that covers. It cannot also carry the estimate: a column
                    # named for money cannot be labelled two ways at once, and
                    # summing a guess into a measurement is how the guess stops
                    # looking like one.
                    """
                    INSERT INTO aisoc_run_costs
                        (run_id, tenant_id, model,
                         total_prompt_tokens, total_completion_tokens,
                         total_cost_usd, total_latency_ms, call_count,
                         measured_cost_usd, measured_call_count,
                         estimated_cost_usd, estimated_call_count,
                         unpriced_call_count, resolved_model)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    ON CONFLICT (run_id, tenant_id, model) DO UPDATE
                        SET total_prompt_tokens     = aisoc_run_costs.total_prompt_tokens + EXCLUDED.total_prompt_tokens,
                            total_completion_tokens = aisoc_run_costs.total_completion_tokens + EXCLUDED.total_completion_tokens,
                            total_cost_usd          = aisoc_run_costs.total_cost_usd + EXCLUDED.total_cost_usd,
                            total_latency_ms        = aisoc_run_costs.total_latency_ms + EXCLUDED.total_latency_ms,
                            call_count              = aisoc_run_costs.call_count + EXCLUDED.call_count,
                            measured_cost_usd       = aisoc_run_costs.measured_cost_usd + EXCLUDED.measured_cost_usd,
                            measured_call_count     = aisoc_run_costs.measured_call_count + EXCLUDED.measured_call_count,
                            estimated_cost_usd      = aisoc_run_costs.estimated_cost_usd + EXCLUDED.estimated_cost_usd,
                            estimated_call_count    = aisoc_run_costs.estimated_call_count + EXCLUDED.estimated_call_count,
                            unpriced_call_count     = aisoc_run_costs.unpriced_call_count + EXCLUDED.unpriced_call_count,
                            resolved_model          = COALESCE(EXCLUDED.resolved_model, aisoc_run_costs.resolved_model),
                            recorded_at             = now()
                    """,
                    run_id,
                    tenant_id,
                    model,
                    agg["prompt"],
                    agg["completion"],
                    agg["measured"],
                    agg["latency"],
                    agg["calls"],
                    agg["measured"],
                    agg["measured_calls"],
                    agg["estimated"],
                    agg["estimated_calls"],
                    agg["unpriced_calls"],
                    agg["resolved"],
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
        gateway_cost: GatewayCost | None = None,
        resolved_model: str | None = None,
    ) -> CallRecord:
        rec = CallRecord(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            tool=tool,
            step=step,
            gateway_cost=gateway_cost,
            resolved_model=resolved_model,
        )
        self._records.append(rec)
        logger.info(
            "cost_telemetry.call",
            run_id=self.run_id,
            tenant_id=self.tenant_id,
            model=model,
            resolved_model=rec.resolved_model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            # "not_measured" rather than "0.000000": the log line is read by a
            # human deciding whether a deployment is spending money, and the
            # two answers are not the same answer.
            cost_usd=("not_measured" if rec.cost_usd is None else f"{rec.cost_usd:.6f}"),
            cost_source=rec.cost_source,
            latency_ms=f"{latency_ms:.1f}",
            tool=tool,
            step=step,
        )
        return rec

    @property
    def measured_cost_usd(self) -> float | None:
        """Money the gateway said was spent, or ``None`` if nothing was measured.

        ``None`` and ``0.0`` are different facts: the first is "no call on this
        run reported a cost", the second is "every call that reported one
        reported zero", which is what a local model genuinely costs.
        """
        measured = [r.cost_usd or 0.0 for r in self._records if r.is_measured]
        return sum(measured) if measured else None

    @property
    def measured_call_count(self) -> int:
        return sum(1 for r in self._records if r.is_measured)

    @property
    def estimated_cost_usd(self) -> float | None:
        """List-price estimate for the calls nobody billed us for, or ``None``."""
        estimated = [r.cost_usd or 0.0 for r in self._records if r.is_estimated]
        return sum(estimated) if estimated else None

    @property
    def estimated_call_count(self) -> int:
        return sum(1 for r in self._records if r.is_estimated)

    @property
    def unpriced_call_count(self) -> int:
        return sum(1 for r in self._records if r.cost_source == UNPRICED)

    @property
    def total_tokens(self) -> int:
        return sum(r.prompt_tokens + r.completion_tokens for r in self._records)

    @property
    def total_latency_ms(self) -> float:
        return sum(r.latency_ms for r in self._records)

    def summary(self) -> dict:
        """The run's spend, with the provenance of every figure in it.

        There is no ``total_cost_usd`` key by design. It used to hold a number
        composed entirely of guesses against a default price, and a consumer
        reading a key by that name has no way to ask how it was arrived at.
        Anything that needs one dollar figure should use ``measured_cost_usd``
        and say "not measured" when ``measured_call_count`` is zero.
        """
        return {
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "measured_cost_usd": self.measured_cost_usd,
            "measured_call_count": self.measured_call_count,
            "estimated_cost_usd": self.estimated_cost_usd,
            "estimated_call_count": self.estimated_call_count,
            "unpriced_call_count": self.unpriced_call_count,
            "total_tokens": self.total_tokens,
            "total_latency_ms": self.total_latency_ms,
            "call_count": len(self._records),
            "models": list({r.model for r in self._records}),
            "resolved_models": sorted({r.resolved_model for r in self._records if r.resolved_model}),
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
    persist ``cost_usd`` and ``cost_source`` into the audit log alongside the
    existing ``tokens_used`` field.

    The cost is taken off the gateway's response headers when they are there.
    They are there when the client asked for them — see
    ``INCLUDE_HEADERS_PARAM`` in :mod:`app.core.gateway_cost` and the factory
    that sets it — and absent otherwise, in which case the call is booked as
    an estimate or as not measured rather than as zero.
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
        gateway_cost=extract_gateway_cost(response),
        resolved_model=extract_resolved_model(response),
    )

"""What the call actually cost, according to the thing that placed it.

The defect this replaces
------------------------
``CostTracker`` priced a call by looking its **model name** up in a table of
hosted list prices. The name it looked up was an ``aisoc-<role>`` alias, which
is not a model — it is a label the gateway resolves to one. No alias appears in
the price table, so every call fell through to a ``(0.001, 0.002)`` default and
was booked at a price nobody charges for a model nobody named.

On a local deployment that is not an approximation, it is an invention. A
903-token completion on the operator's own hardware was reported as
``total_cost_usd=0.000999``, and the same figure flowed into the cost
dashboard, the per-run ledger and the budget circuit breaker — which trips at
``AISOC_BUDGET_HARD_USD`` and would eventually degrade a working local
deployment to deterministic-only over money that was never spent.

Where the real number comes from
--------------------------------
The gateway resolved the alias, so the gateway is the only party that knows
what was actually called and what it cost. LiteLLM returns both on the
response headers. Measured against a real gateway (1.102.1) driving a local
Ollama model and a hosted model in the same config::

    alias           x-litellm-model-name    cost header
    aisoc-triage    ollama/qwen2:1.5b       x-litellm-response-cost-original: 0.0
    aisoc-summary   openai/gpt-4o-mini      x-litellm-response-cost:          1.35e-05

Same alias set, same request path: the local call is free and says so, the
hosted call carries the provider's real price. The alias alone distinguishes
neither.

``langchain_openai.ChatOpenAI`` only keeps response headers when built with
``include_response_headers=True``; without it ``response_metadata`` has no
``headers`` key at all and the cost is simply **not knowable from here** —
which is a third answer, distinct from zero and from an estimate.

Header selection is exact, never a prefix
-----------------------------------------
LiteLLM emits seven headers starting ``x-litellm-response-cost``:

    x-litellm-response-cost                     the total  (hosted call above)
    x-litellm-response-cost-original            the total before margin/discount
    x-litellm-response-cost-input               a component
    x-litellm-response-cost-output              a component
    x-litellm-response-cost-discount-amount     an adjustment
    x-litellm-response-cost-margin-amount       an adjustment
    x-litellm-response-cost-margin-percent      a *percentage*, not money

A prefix match would accept any of them, and ``-margin-percent`` is not even
denominated in dollars. Only the two totals are read, in a declared order, and
the self-test asserts a response carrying the five non-totals alone yields no
cost rather than a plausible-looking wrong one.

Stdlib only, and it never raises: a telemetry module that can throw would take
down the LLM call it is measuring.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: The only two headers that carry a total, most authoritative first.
#: ``x-litellm-response-cost`` is the billed figure; ``-original`` is the same
#: number before any margin or discount the gateway applies, and is the only
#: one some versions emit. Everything else sharing the prefix is a component,
#: an adjustment, or a percentage — see the module docstring.
COST_HEADERS: tuple[str, ...] = (
    "x-litellm-response-cost",
    "x-litellm-response-cost-original",
)

#: What the gateway resolved the requested alias to, e.g. ``ollama/qwen2:1.5b``.
#: Recording it is what makes a later estimate possible at all: an estimate
#: keyed on the alias is meaningless, one keyed on the resolved model is not.
RESOLVED_MODEL_HEADER = "x-litellm-model-name"

#: Correlates a recorded call with the gateway's own spend log, so an operator
#: reconciling the dashboard against ``/spend/logs`` has a join key.
CALL_ID_HEADER = "x-litellm-call-id"

#: Asking for the headers is what makes the cost knowable. Named here so the
#: factory that sets it and the gate that checks it cannot disagree.
INCLUDE_HEADERS_PARAM = "include_response_headers"


@dataclass(frozen=True)
class GatewayCost:
    """A cost the gateway reported, with what it was reported for."""

    cost_usd: float
    resolved_model: str | None = None
    call_id: str | None = None


def response_headers(response: Any) -> dict[str, str]:
    """Lower-cased response headers off a LangChain result, or ``{}``.

    ``{}`` means the headers were never captured, which is not the same as a
    gateway that reported no cost.
    """
    metadata = getattr(response, "response_metadata", None)
    if not isinstance(metadata, dict):
        return {}
    raw = metadata.get("headers")
    if raw is None:
        return {}
    try:
        items = raw.items()
    except AttributeError:
        return {}
    out: dict[str, str] = {}
    for key, value in items:
        try:
            out[str(key).strip().lower()] = str(value)
        except Exception:  # noqa: BLE001 — a malformed header is not a crash
            continue
    return out


def _as_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    # A negative cost is not a cost. Neither is NaN or an infinity, both of
    # which float() accepts and which would poison every sum downstream.
    if parsed != parsed or parsed in (float("inf"), float("-inf")) or parsed < 0:
        return None
    return parsed


def extract_gateway_cost(response: Any) -> GatewayCost | None:
    """The cost the gateway reported for ``response``, or ``None``.

    ``None`` means *not measurable here* — no gateway, or a client that did not
    keep the headers. Callers must not substitute zero for it.
    """
    headers = response_headers(response)
    if not headers:
        return None
    for name in COST_HEADERS:
        cost = _as_float(headers.get(name))
        if cost is not None:
            return GatewayCost(
                cost_usd=cost,
                resolved_model=(headers.get(RESOLVED_MODEL_HEADER) or "").strip() or None,
                call_id=(headers.get(CALL_ID_HEADER) or "").strip() or None,
            )
    return None


def extract_resolved_model(response: Any) -> str | None:
    """What the gateway resolved the requested alias to, if it said.

    Useful even when no cost header arrived: a recorded ``ollama/qwen2:1.5b``
    is why a later surface can say "local model, no spend" rather than guessing
    at an alias.
    """
    return (response_headers(response).get(RESOLVED_MODEL_HEADER) or "").strip() or None


__all__ = [
    "CALL_ID_HEADER",
    "COST_HEADERS",
    "GatewayCost",
    "INCLUDE_HEADERS_PARAM",
    "RESOLVED_MODEL_HEADER",
    "extract_gateway_cost",
    "extract_resolved_model",
    "response_headers",
]

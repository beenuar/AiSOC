"""Per-investigation token / USD / latency telemetry for the AiSOC eval harness.

This module is **stdlib-only** so it can run in CI / dev shells that don't
have the full agent dependency stack (pydantic, langgraph, langchain, ...).
``scripts/run_evals.py`` imports it lazily and folds its output into
``eval_report.json`` under the ``per_investigation`` key. The companion
``scripts/render_eval_charts.py`` renders the same numbers into SVG charts
that ship into ``apps/docs/docs/benchmark-charts/``.

What it computes
----------------
For each of the 200 synthetic incidents in
``services/agents/tests/eval_data/synthetic_incidents.json`` we compute, in a
**fully deterministic** way:

* ``prompt_tokens``     — system-prompt budget + ceil(len(description) / 4)
                          + ceil(sum(len(json.dumps(ev)) for ev in telemetry[:N])
                          / 4). The 4-chars-per-token rule is OpenAI's own
                          published heuristic for English text. The system
                          budget covers the agent's instructions + tool schema
                          (≈ 800 tokens at the time of writing).
* ``completion_tokens`` — base report budget scaled by severity, calibrated
                          against the substrate report-template shape.
                          Critical incidents get longer reports; medium ones
                          get shorter ones.
* ``latency_ms``        — measured wall-clock per incident across the
                          deterministic substrate path (description tokenize
                          + telemetry serialize). These are tiny (microseconds)
                          but the *distribution* across templates is the signal
                          we want — wet-eval (T5.5) replaces the absolute
                          numbers with real-LLM wall-clock.
* ``usd``               — applies ``RATE_CARD_2025_USD_PER_M`` to the token
                          counts. The rate card lives at the top of this file
                          and is clearly marked as illustrative public list
                          pricing — substitute the rate card for whatever
                          model your tenant actually runs.

Honesty
-------
These are **substrate / projected** numbers. The deterministic substrate
does not call an LLM. They are an *upper bound* on the budget the full
agent will consume on the same workload, and they let us gate cost
regressions in CI without paying for a wet eval on every PR. The wet-eval
numbers (real LLM calls, weekly job) land in T5.5; this telemetry is the
deterministic placeholder we use until then.

Every output object carries ``"mode": "deterministic_substrate"`` so
downstream consumers (docs, dashboards, CI gates) can clearly distinguish
substrate budgets from wet-eval ground truth.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, median
from typing import Any

# ---------------------------------------------------------------------------
# Rate card — illustrative public 2025-era list prices, USD per 1 M tokens.
# ---------------------------------------------------------------------------
# Substitute these with whatever your tenant actually pays. They mirror the
# pricing table in ``services/agents/app/core/cost_telemetry.py`` (which is
# expressed per 1 K tokens, i.e. divide-by-1000 of the numbers below) so the
# substrate gate and the runtime cost ledger agree on the same cost model.
#
# Source: vendor pricing pages snapshotted 2025-Q1. Marked "illustrative" in
# benchmark.md — do not treat these as authoritative for billing.
RATE_CARD_2025_USD_PER_M: dict[str, dict[str, float]] = {
    # OpenAI
    "gpt-4o":           {"input": 2.50,  "output": 10.00},
    "gpt-4o-mini":      {"input": 0.15,  "output": 0.60},
    "gpt-4-turbo":      {"input": 10.00, "output": 30.00},
    # Placeholder for the next-gen model name used in the v8 plan; pricing
    # mirrors gpt-4o until the public price for the real "gpt-5" lands.
    "gpt-5":            {"input": 5.00,  "output": 15.00},
    # Anthropic
    "claude-3.5-sonnet": {"input": 3.00,  "output": 15.00},
    "claude-3-haiku":    {"input": 0.25,  "output": 1.25},
    # Google
    "gemini-1.5-pro":    {"input": 1.25,  "output": 5.00},
    "gemini-1.5-flash":  {"input": 0.075, "output": 0.30},
}

# Models we report against by default. Picking a "headline" model lets the
# benchmark page show one number; the JSON report carries the full matrix so
# any tenant can re-render against their own cheaper / dearer choice.
DEFAULT_MODEL = "gpt-4o"

# ---------------------------------------------------------------------------
# Token-budget heuristics
# ---------------------------------------------------------------------------
# OpenAI published rule of thumb: 1 token ≈ 4 chars of English text. Good
# enough for an upper-bound CI gate; the wet-eval (T5.5) replaces this with
# tiktoken-counted real token usage.
_CHARS_PER_TOKEN = 4

# System-prompt budget. Covers the agent persona, tool descriptions, and the
# investigation rubric. Intentionally generous so the substrate budget sits
# above what the real agent burns — we'd rather flag a false-positive cost
# regression than miss a real one.
_SYSTEM_PROMPT_TOKENS = 800

# Number of telemetry events to include in the prompt budget per incident.
# The real agent does retrieval over the full corpus and trims; for the
# substrate budget we use the first N events from the inline ``telemetry``
# field which mirrors the typical "first-pass context bundle" shape.
_TELEMETRY_EVENTS_PER_PROMPT = 5

# Completion-budget anchor (tokens). Tuned against the report-template shape
# in ``services/agents/app/investigator/report_template.md`` — a typical
# substrate report at medium severity sits around this length.
_COMPLETION_BASE_TOKENS = 800

# Severity scaling for completion length. Higher-severity incidents get
# longer reports / response plans because the response section expands.
_SEVERITY_COMPLETION_FACTOR = {
    "info":     0.5,
    "low":      0.7,
    "medium":   1.0,
    "high":     1.4,
    "critical": 1.8,
}

# ---------------------------------------------------------------------------
# Default eval dataset path (relative to repo root).
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INCIDENTS_PATH = (
    _REPO_ROOT / "services" / "agents" / "tests" / "eval_data" / "synthetic_incidents.json"
)


# ---------------------------------------------------------------------------
# Token + cost math
# ---------------------------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Return the integer-token estimate for ``text`` using the 4-chars rule.

    Uses ``ceil`` so a non-empty string never round-trips to zero tokens.
    """
    if not text:
        return 0
    return math.ceil(len(text) / _CHARS_PER_TOKEN)


def cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    *,
    model: str = DEFAULT_MODEL,
    rate_card: dict[str, dict[str, float]] | None = None,
) -> float:
    """Apply ``rate_card`` to (prompt_tokens, completion_tokens) and return USD.

    Falls back to the gpt-4o entry if ``model`` isn't in the rate card.
    Result is non-negative; zero tokens → 0 USD.
    """
    rates = rate_card if rate_card is not None else RATE_CARD_2025_USD_PER_M
    entry = rates.get(model) or rates.get(DEFAULT_MODEL) or {"input": 2.5, "output": 10.0}
    return (
        (prompt_tokens / 1_000_000.0) * entry["input"]
        + (completion_tokens / 1_000_000.0) * entry["output"]
    )


# ---------------------------------------------------------------------------
# Per-incident telemetry record
# ---------------------------------------------------------------------------
@dataclass
class InvestigationTelemetry:
    incident_id: str
    template_id: str
    severity: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    usd: float

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def _telemetry_for_incident(
    incident: dict[str, Any],
    *,
    model: str,
    rate_card: dict[str, dict[str, float]] | None = None,
) -> InvestigationTelemetry:
    """Compute deterministic telemetry for a single incident.

    Latency is measured as the wall-clock cost of running the deterministic
    substrate work (description tokenize + telemetry serialize). Tiny in
    absolute terms but informative as a *distribution* — templates with more
    telemetry events take measurably longer.
    """
    desc = str(incident.get("description") or "")
    telemetry = incident.get("telemetry") or []

    t0 = time.perf_counter()
    desc_tokens = estimate_tokens(desc)
    serialized_telemetry_chars = 0
    for ev in telemetry[:_TELEMETRY_EVENTS_PER_PROMPT]:
        serialized_telemetry_chars += len(json.dumps(ev, sort_keys=True))
    telemetry_tokens = math.ceil(serialized_telemetry_chars / _CHARS_PER_TOKEN)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    prompt_tokens = _SYSTEM_PROMPT_TOKENS + desc_tokens + telemetry_tokens

    severity = str(incident.get("severity") or "medium").lower()
    factor = _SEVERITY_COMPLETION_FACTOR.get(severity, 1.0)
    completion_tokens = math.ceil(_COMPLETION_BASE_TOKENS * factor)

    usd = cost_usd(prompt_tokens, completion_tokens, model=model, rate_card=rate_card)

    return InvestigationTelemetry(
        incident_id=str(incident.get("id") or ""),
        template_id=str(incident.get("template_id") or ""),
        severity=severity,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=round(latency_ms, 4),
        usd=round(usd, 6),
    )


# ---------------------------------------------------------------------------
# Aggregate stats helpers
# ---------------------------------------------------------------------------
def _percentile(values: list[float], pct: float) -> float:
    """Return the ``pct``-th percentile of ``values`` using nearest-rank.

    ``values`` may be empty (returns 0.0). ``pct`` is in [0, 100].
    Nearest-rank avoids the interpolation surprises that bite small samples.
    """
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    if pct <= 0:
        return sorted_vals[0]
    if pct >= 100:
        return sorted_vals[-1]
    rank = max(1, math.ceil(pct / 100.0 * len(sorted_vals)))
    return sorted_vals[rank - 1]


def _summarise(values: list[float], decimals: int = 4) -> dict[str, float]:
    if not values:
        return {
            "count": 0,
            "min": 0.0, "max": 0.0,
            "mean": 0.0, "median": 0.0,
            "p50": 0.0, "p95": 0.0, "p99": 0.0,
        }
    return {
        "count": len(values),
        "min": round(min(values), decimals),
        "max": round(max(values), decimals),
        "mean": round(mean(values), decimals),
        "median": round(median(values), decimals),
        "p50": round(_percentile(values, 50), decimals),
        "p95": round(_percentile(values, 95), decimals),
        "p99": round(_percentile(values, 99), decimals),
    }


# ---------------------------------------------------------------------------
# Top-level: compute the ``per_investigation`` block for the eval report.
# ---------------------------------------------------------------------------
@dataclass
class PerInvestigationReport:
    mode: str
    model: str
    rate_card_per_m: dict[str, float]
    incidents: int
    templates: int
    aggregate: dict[str, Any]
    per_template: list[dict[str, Any]] = field(default_factory=list)
    incident_records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self, *, include_records: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "mode": self.mode,
            "model": self.model,
            "rate_card_per_m_tokens_usd": self.rate_card_per_m,
            "system_prompt_tokens": _SYSTEM_PROMPT_TOKENS,
            "completion_base_tokens": _COMPLETION_BASE_TOKENS,
            "chars_per_token": _CHARS_PER_TOKEN,
            "telemetry_events_per_prompt": _TELEMETRY_EVENTS_PER_PROMPT,
            "incidents": self.incidents,
            "templates": self.templates,
            "aggregate": self.aggregate,
            "per_template": self.per_template,
            "transparency_note": (
                "These numbers are computed against the deterministic "
                "substrate. They are an upper-bound projection of what the "
                "live agent will consume on the same workload using a "
                "4-chars/token estimator and an illustrative public 2025-era "
                "rate card. The wet-eval (T5.5) replaces them with real "
                "tiktoken counts and real LLM wall-clock."
            ),
        }
        if include_records:
            out["incident_records"] = self.incident_records
        return out


def compute_per_investigation_telemetry(
    incidents_path: Path | str = DEFAULT_INCIDENTS_PATH,
    *,
    model: str = DEFAULT_MODEL,
    rate_card: dict[str, dict[str, float]] | None = None,
    keep_records: bool = True,
) -> PerInvestigationReport:
    """Return a ``PerInvestigationReport`` for the 200-incident dataset.

    Set ``keep_records=False`` to drop the per-incident array from the report
    (useful when this is being piped into a small JSON budget, e.g. a CI
    summary block).
    """
    path = Path(incidents_path)
    incidents = json.loads(path.read_text()) if path.exists() else []

    rates = rate_card if rate_card is not None else RATE_CARD_2025_USD_PER_M
    entry = rates.get(model) or rates.get(DEFAULT_MODEL) or {"input": 2.5, "output": 10.0}

    records: list[InvestigationTelemetry] = [
        _telemetry_for_incident(inc, model=model, rate_card=rate_card)
        for inc in incidents
    ]

    prompt_tokens = [r.prompt_tokens for r in records]
    completion_tokens = [r.completion_tokens for r in records]
    total_tokens = [r.total_tokens for r in records]
    latencies = [r.latency_ms for r in records]
    usds = [r.usd for r in records]

    aggregate = {
        "tokens": {
            "prompt":     _summarise(prompt_tokens, decimals=2),
            "completion": _summarise(completion_tokens, decimals=2),
            "total":      _summarise(total_tokens, decimals=2),
        },
        "usd":     _summarise(usds, decimals=6),
        "latency_ms": _summarise(latencies, decimals=4),
    }

    by_template: dict[str, list[InvestigationTelemetry]] = {}
    for rec in records:
        by_template.setdefault(rec.template_id, []).append(rec)

    per_template: list[dict[str, Any]] = []
    for tpl_id in sorted(by_template):
        bucket = by_template[tpl_id]
        per_template.append({
            "template_id": tpl_id,
            "incidents": len(bucket),
            "tokens": {
                "prompt":     _summarise([r.prompt_tokens     for r in bucket], decimals=2),
                "completion": _summarise([r.completion_tokens for r in bucket], decimals=2),
                "total":      _summarise([r.total_tokens      for r in bucket], decimals=2),
            },
            "usd":        _summarise([r.usd        for r in bucket], decimals=6),
            "latency_ms": _summarise([r.latency_ms for r in bucket], decimals=4),
        })

    incident_records = (
        [
            {
                "incident_id": r.incident_id,
                "template_id": r.template_id,
                "severity": r.severity,
                "prompt_tokens": r.prompt_tokens,
                "completion_tokens": r.completion_tokens,
                "total_tokens": r.total_tokens,
                "latency_ms": r.latency_ms,
                "usd": r.usd,
            }
            for r in records
        ]
        if keep_records
        else []
    )

    return PerInvestigationReport(
        mode="deterministic_substrate",
        model=model,
        rate_card_per_m=entry,
        incidents=len(records),
        templates=len(by_template),
        aggregate=aggregate,
        per_template=per_template,
        incident_records=incident_records,
    )


# ---------------------------------------------------------------------------
# CLI for quick smoke / debug ("python scripts/eval_telemetry.py").
# ---------------------------------------------------------------------------
def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Per-investigation token/USD telemetry (deterministic substrate)."
    )
    parser.add_argument("--incidents", type=Path, default=DEFAULT_INCIDENTS_PATH)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write JSON to this path; if omitted, print to stdout.",
    )
    parser.add_argument(
        "--no-records",
        action="store_true",
        help="Omit per-incident records (smaller report).",
    )
    args = parser.parse_args()

    rep = compute_per_investigation_telemetry(
        args.incidents,
        model=args.model,
        keep_records=not args.no_records,
    )
    payload = json.dumps(rep.to_dict(include_records=not args.no_records), indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    else:
        print(payload)


if __name__ == "__main__":
    _cli()

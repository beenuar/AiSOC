"""Per-tenant cost governor: enforcement layer over cost telemetry.

Phase 1.5 of the world-class program. Anyone who can generate alerts can
generate LLM spend. `cost_telemetry.py` *tracks* spend into `aisoc_run_costs`
but nothing enforces against it. This module adds the enforcement the plan
requires:

- **Per-tenant token/USD budgets** with a soft cap (warn) and a hard cap.
- **Circuit breaker**: once a tenant crosses the hard cap in the rolling
  window, investigations drop to deterministic-only mode (no LLM) instead of
  billing unboundedly.
- **Per-alert token ceiling**: a single alert can never request more than
  `max_tokens_per_alert`.
- **Dedup / caching of identical investigations** keyed by an evidence hash,
  so a flood of identical alerts costs one investigation, not N.

The governor is pure and deterministic (injectable clock, in-memory store by
default) so the 10k-identical-alert DoS bound can be unit-tested offline with
no DB or LLM. Production wires a DB-backed spend window; the enforcement logic
is identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "BudgetConfig",
    "Decision",
    "GovernorDecision",
    "CostGovernor",
    "get_governor",
]


@dataclass(frozen=True)
class BudgetConfig:
    """Per-tenant budget policy. All caps apply to a rolling window."""

    soft_usd: float = 50.0
    hard_usd: float = 100.0
    max_tokens_per_alert: int = 20_000
    window_seconds: int = 24 * 3600
    cache_ttl_seconds: int = 3600

    @classmethod
    def from_env(cls) -> BudgetConfig:
        def _f(name: str, default: float) -> float:
            try:
                return float(os.environ.get(name, "").strip() or default)
            except ValueError:
                return default

        def _i(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, "").strip() or default)
            except ValueError:
                return default

        return cls(
            soft_usd=_f("AISOC_BUDGET_SOFT_USD", 50.0),
            hard_usd=_f("AISOC_BUDGET_HARD_USD", 100.0),
            max_tokens_per_alert=_i("AISOC_MAX_TOKENS_PER_ALERT", 20_000),
            window_seconds=_i("AISOC_BUDGET_WINDOW_SECONDS", 24 * 3600),
            cache_ttl_seconds=_i("AISOC_INVESTIGATION_CACHE_TTL", 3600),
        )


class Decision(str, Enum):
    ALLOW = "allow"  # run the full (LLM) investigation
    DEDUPLICATED = "deduplicated"  # identical investigation served from cache
    CIRCUIT_OPEN = "circuit_open"  # budget exhausted -> deterministic-only


@dataclass
class GovernorDecision:
    decision: Decision
    reason: str
    remaining_usd: float
    soft_breached: bool = False
    cached_verdict: dict[str, Any] | None = None

    @property
    def use_llm(self) -> bool:
        """Only a plain ALLOW may spend on the LLM."""
        return self.decision is Decision.ALLOW


@dataclass
class _SpendEvent:
    ts: float
    usd: float
    tokens: int


@dataclass
class _CacheEntry:
    verdict: dict[str, Any]
    expires_at: float


@dataclass
class CostGovernor:
    """Enforces per-tenant budgets, dedup, and the deterministic circuit breaker."""

    config: BudgetConfig = field(default_factory=BudgetConfig)
    now: Callable[[], float] = time.monotonic
    _spend: dict[str, deque[_SpendEvent]] = field(default_factory=dict, init=False)
    _cache: dict[tuple[str, str], _CacheEntry] = field(default_factory=dict, init=False)

    # -- fingerprinting --------------------------------------------------------

    @staticmethod
    def evidence_fingerprint(tenant_id: str, alert: Any) -> str:
        """Stable hash of the investigation-relevant evidence.

        Identical alerts (same tenant + same canonical evidence) collapse to
        the same fingerprint so repeats hit the cache. Volatile fields
        (timestamps, alert ids) are excluded by the caller passing a canonical
        subset; here we hash whatever we are given, deterministically.
        """
        try:
            canonical = json.dumps(alert, sort_keys=True, default=str)
        except (TypeError, ValueError):
            canonical = str(alert)
        digest = hashlib.sha256(f"{tenant_id}\x00{canonical}".encode()).hexdigest()
        return digest

    # -- window accounting -----------------------------------------------------

    def _prune(self, tenant_id: str) -> deque[_SpendEvent]:
        window_start = self.now() - self.config.window_seconds
        dq = self._spend.setdefault(tenant_id, deque())
        while dq and dq[0].ts < window_start:
            dq.popleft()
        return dq

    def spent_usd(self, tenant_id: str) -> float:
        return sum(e.usd for e in self._prune(tenant_id))

    def spent_tokens(self, tenant_id: str) -> int:
        return sum(e.tokens for e in self._prune(tenant_id))

    # -- enforcement -----------------------------------------------------------

    def cap_tokens(self, requested_tokens: int) -> int:
        """Clamp a per-alert token request to the ceiling."""
        return max(0, min(int(requested_tokens), self.config.max_tokens_per_alert))

    def check(self, tenant_id: str, fingerprint: str) -> GovernorDecision:
        """Decide how to handle an incoming investigation.

        Order: dedup cache -> circuit breaker -> allow. Dedup wins even when
        the circuit is open, because serving a cached verdict costs nothing.
        """
        now = self.now()

        cached = self._cache.get((tenant_id, fingerprint))
        if cached is not None and cached.expires_at > now:
            return GovernorDecision(
                decision=Decision.DEDUPLICATED,
                reason="identical investigation served from cache",
                remaining_usd=max(0.0, self.config.hard_usd - self.spent_usd(tenant_id)),
                soft_breached=self.spent_usd(tenant_id) >= self.config.soft_usd,
                cached_verdict=cached.verdict,
            )

        spent = self.spent_usd(tenant_id)
        remaining = max(0.0, self.config.hard_usd - spent)
        if spent >= self.config.hard_usd:
            return GovernorDecision(
                decision=Decision.CIRCUIT_OPEN,
                reason=f"tenant hard budget ${self.config.hard_usd:.2f} exhausted; deterministic-only",
                remaining_usd=0.0,
                soft_breached=True,
            )

        return GovernorDecision(
            decision=Decision.ALLOW,
            reason="within budget",
            remaining_usd=remaining,
            soft_breached=spent >= self.config.soft_usd,
        )

    def record_spend(self, tenant_id: str, usd: float, tokens: int) -> None:
        dq = self._prune(tenant_id)
        dq.append(_SpendEvent(ts=self.now(), usd=max(0.0, usd), tokens=max(0, tokens)))

    def record_verdict(
        self,
        tenant_id: str,
        fingerprint: str,
        verdict: dict[str, Any],
        *,
        usd: float,
        tokens: int,
    ) -> None:
        """Cache the verdict for dedup and account the spend it incurred."""
        self._cache[(tenant_id, fingerprint)] = _CacheEntry(
            verdict=verdict,
            expires_at=self.now() + self.config.cache_ttl_seconds,
        )
        self.record_spend(tenant_id, usd, tokens)

    def state(self, tenant_id: str) -> dict[str, Any]:
        spent = self.spent_usd(tenant_id)
        return {
            "tenant_id": tenant_id,
            "spent_usd": round(spent, 6),
            "soft_usd": self.config.soft_usd,
            "hard_usd": self.config.hard_usd,
            "soft_breached": spent >= self.config.soft_usd,
            "hard_breached": spent >= self.config.hard_usd,
            "spent_tokens": self.spent_tokens(tenant_id),
            "cached_entries": sum(1 for k in self._cache if k[0] == tenant_id),
        }


_GOVERNOR: CostGovernor | None = None


def get_governor() -> CostGovernor:
    """Process-wide governor singleton (config from env)."""
    global _GOVERNOR
    if _GOVERNOR is None:
        _GOVERNOR = CostGovernor(config=BudgetConfig.from_env())
    return _GOVERNOR

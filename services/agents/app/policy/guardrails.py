"""Per-action confidence guardrails with DB-backed tenant overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Default thresholds
# action_name -> minimum confidence (0.0–1.0) before autonomous execution.
# Actions not listed here require confidence >= 1.0 (i.e. always require review).
# ---------------------------------------------------------------------------
_DEFAULT_THRESHOLDS: dict[str, float] = {
    # Low-risk read actions — high autonomy
    "lookup_ip": 0.0,
    "lookup_domain": 0.0,
    "search_logs": 0.0,
    "enrich_alert": 0.0,
    "mitre_lookup": 0.0,
    "get_alert_context": 0.0,
    # Medium-risk actions — require reasonable confidence
    "add_alert_tag": 0.5,
    "close_alert": 0.6,
    "create_case": 0.5,
    "add_case_comment": 0.4,
    "assign_case": 0.6,
    # High-risk actions — require high confidence
    "quarantine_file": 0.85,
    "block_ip": 0.90,
    "isolate_host": 0.92,
    "disable_user_account": 0.90,
    "revoke_session": 0.80,
    "delete_object": 0.95,
    "firewall_rule_add": 0.88,
    "firewall_rule_remove": 0.90,
}

_POOL: Any = None  # asyncpg.Pool | None
_TENANT_OVERRIDES: dict[str, dict[str, float]] = {}  # tenant_id -> {action: threshold}


async def _load_overrides(tenant_id: str) -> dict[str, float]:
    """Load tenant-specific threshold overrides from the DB (best-effort)."""
    if tenant_id in _TENANT_OVERRIDES:
        return _TENANT_OVERRIDES[tenant_id]
    global _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        _TENANT_OVERRIDES[tenant_id] = {}
        return {}
    try:
        import asyncpg  # type: ignore[import]

        if _POOL is None:
            _POOL = await asyncpg.create_pool(
                dsn.replace("postgresql+asyncpg://", "postgresql://").replace(
                    "postgres+asyncpg://", "postgresql://"
                ),
                min_size=1,
                max_size=2,
            )
        async with _POOL.acquire() as conn:
            # Table created by the API service migration; may not exist in all envs
            rows = await conn.fetch(
                """
                SELECT action_name, min_confidence
                FROM aisoc_autonomy_thresholds
                WHERE tenant_id = $1
                """,
                tenant_id,
            )
            overrides = {r["action_name"]: float(r["min_confidence"]) for r in rows}
            _TENANT_OVERRIDES[tenant_id] = overrides
            return overrides
    except Exception as exc:
        logger.debug("policy.guardrails.overrides_unavailable", tenant_id=tenant_id, error=str(exc))
        _TENANT_OVERRIDES[tenant_id] = {}
        return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ActionResult:
    allowed: bool
    action: str
    confidence: float
    threshold: float
    reason: str = ""


@dataclass
class GuardrailPolicy:
    tenant_id: str
    thresholds: dict[str, float] = field(default_factory=dict)

    @classmethod
    async def load(cls, tenant_id: str) -> "GuardrailPolicy":
        overrides = await _load_overrides(tenant_id)
        merged = {**_DEFAULT_THRESHOLDS, **overrides}
        return cls(tenant_id=tenant_id, thresholds=merged)

    def evaluate(self, action: str, confidence: float) -> ActionResult:
        """Return an ActionResult indicating whether the action is allowed."""
        threshold = self.thresholds.get(action, 1.0)
        allowed = confidence >= threshold
        reason = (
            ""
            if allowed
            else (
                f"Confidence {confidence:.2f} is below threshold {threshold:.2f} "
                f"for action '{action}'. Human approval required."
            )
        )
        if not allowed:
            logger.info(
                "policy.guardrails.blocked",
                action=action,
                confidence=confidence,
                threshold=threshold,
                tenant_id=self.tenant_id,
            )
        return ActionResult(
            allowed=allowed,
            action=action,
            confidence=confidence,
            threshold=threshold,
            reason=reason,
        )

    def get_threshold(self, action: str) -> float:
        return self.thresholds.get(action, 1.0)

    def all_thresholds(self) -> dict[str, float]:
        return dict(self.thresholds)

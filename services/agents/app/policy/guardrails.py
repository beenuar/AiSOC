"""Per-action confidence guardrails with three-tier autonomy decisions.

For every action the agent can take we hold three confidence thresholds:

* ``auto``       — at or above this confidence, execute autonomously
* ``review``     — at or above this (but below ``auto``) → queue for analyst review
* ``escalation`` — at or above this (but below ``review``) → escalate to senior on-call
                  (anything below ``escalation`` is rejected outright)

Threshold resolution order (lowest to highest precedence):

1. Hard-coded defaults in this module (``_DEFAULT_THRESHOLDS``).
2. Site-wide YAML overrides at ``$AISOC_AUTONOMY_POLICY`` or
   ``services/agents/config/autonomy_policy.yaml``. Loaded once per process and
   cached. Useful for ops-managed deployments where every tenant gets the same
   policy.
3. Per-tenant DB overrides in the ``aisoc_autonomy_thresholds`` table. Managed
   from the admin UI. Wins over both defaults and YAML.

This three-layer model lets a security team commit policy to git, then allow
specific tenants to deviate without touching the file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------


class AutonomyDecision(str, Enum):
    """How the policy says the agent should handle a proposed action."""

    AUTO = "auto"
    REVIEW = "review"
    ESCALATE = "escalate"
    REJECT = "reject"


@dataclass(frozen=True)
class ActionThresholds:
    """Three confidence cutoffs for a single action.

    Invariant: ``escalation <= review <= auto`` and all are in ``[0.0, 1.0]``.
    """

    auto: float
    review: float
    escalation: float

    def decide(self, confidence: float) -> AutonomyDecision:
        if confidence >= self.auto:
            return AutonomyDecision.AUTO
        if confidence >= self.review:
            return AutonomyDecision.REVIEW
        if confidence >= self.escalation:
            return AutonomyDecision.ESCALATE
        return AutonomyDecision.REJECT

    def to_dict(self) -> dict[str, float]:
        return {"auto": self.auto, "review": self.review, "escalation": self.escalation}


def _make_thresholds(
    auto: float,
    review: float | None = None,
    escalation: float | None = None,
) -> ActionThresholds:
    """Build a normalised, monotonically-ordered :class:`ActionThresholds`.

    When the caller only supplies ``auto``, the other tiers fall back to
    sensible defaults: ``review = max(0, auto - 0.1)`` and
    ``escalation = max(0, review - 0.2)``. Out-of-range values are clamped.
    """
    a = max(0.0, min(1.0, float(auto)))
    r = float(review) if review is not None else max(0.0, a - 0.1)
    e = float(escalation) if escalation is not None else max(0.0, r - 0.2)
    r = max(0.0, min(a, r))
    e = max(0.0, min(r, e))
    return ActionThresholds(auto=a, review=r, escalation=e)


# ---------------------------------------------------------------------------
# Default thresholds — minimums shipped with AiSOC
# action_name -> (auto, review, escalation)
# Actions not listed here resolve to ``ActionThresholds(1.0, 1.0, 1.0)`` —
# i.e. always require an analyst.
# ---------------------------------------------------------------------------
_DEFAULT_THRESHOLDS: dict[str, ActionThresholds] = {
    # Read / enrichment — autonomous by default
    "lookup_ip": _make_thresholds(0.0, 0.0, 0.0),
    "lookup_domain": _make_thresholds(0.0, 0.0, 0.0),
    "search_logs": _make_thresholds(0.0, 0.0, 0.0),
    "enrich_alert": _make_thresholds(0.0, 0.0, 0.0),
    "mitre_lookup": _make_thresholds(0.0, 0.0, 0.0),
    "get_alert_context": _make_thresholds(0.0, 0.0, 0.0),
    # Case workflow — moderate autonomy, easy to roll back
    "add_alert_tag": _make_thresholds(0.50, 0.30, 0.10),
    "close_alert": _make_thresholds(0.60, 0.40, 0.20),
    "create_case": _make_thresholds(0.50, 0.30, 0.10),
    "add_case_comment": _make_thresholds(0.40, 0.20, 0.05),
    "assign_case": _make_thresholds(0.60, 0.40, 0.20),
    # Containment — high blast radius
    "quarantine_file": _make_thresholds(0.85, 0.65, 0.40),
    "block_ip": _make_thresholds(0.90, 0.70, 0.40),
    "isolate_host": _make_thresholds(0.92, 0.72, 0.45),
    "disable_user_account": _make_thresholds(0.90, 0.70, 0.40),
    "revoke_session": _make_thresholds(0.80, 0.60, 0.30),
    "delete_object": _make_thresholds(0.95, 0.80, 0.50),
    "firewall_rule_add": _make_thresholds(0.88, 0.68, 0.40),
    "firewall_rule_remove": _make_thresholds(0.90, 0.70, 0.40),
}

_REJECT_DEFAULT = ActionThresholds(auto=1.0, review=1.0, escalation=1.0)

# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------

_POOL: Any = None  # asyncpg.Pool | None
_TENANT_OVERRIDES: dict[str, dict[str, ActionThresholds]] = {}

# ``None`` means "not yet attempted"; an empty dict means "loaded but file
# absent or unreadable".
_YAML_THRESHOLDS: dict[str, ActionThresholds] | None = None


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def _yaml_policy_path() -> Path:
    override = os.environ.get("AISOC_AUTONOMY_POLICY", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parents[2] / "config" / "autonomy_policy.yaml"


def _coerce_threshold_value(action: str, value: Any) -> ActionThresholds | None:
    """Accept either a scalar (== ``auto`` only) or a ``{auto, review, escalation}`` dict."""
    if isinstance(value, int | float):
        try:
            return _make_thresholds(float(value))
        except (TypeError, ValueError):
            logger.warning("policy.guardrails.yaml_bad_value", action=action, value=repr(value))
            return None

    if isinstance(value, dict):
        try:
            auto = float(value.get("auto", value.get("auto_threshold", 1.0)))
        except (TypeError, ValueError):
            logger.warning("policy.guardrails.yaml_bad_auto", action=action, value=repr(value))
            return None
        review = value.get("review", value.get("analyst_review_threshold"))
        escalation = value.get("escalation", value.get("escalation_threshold"))
        try:
            r = float(review) if review is not None else None
            e = float(escalation) if escalation is not None else None
        except (TypeError, ValueError):
            logger.warning("policy.guardrails.yaml_bad_tier", action=action, review=review, escalation=escalation)
            return None
        thresholds = _make_thresholds(auto, r, e)
        if thresholds.review > thresholds.auto or thresholds.escalation > thresholds.review:
            logger.warning(
                "policy.guardrails.yaml_unordered",
                action=action,
                auto=thresholds.auto,
                review=thresholds.review,
                escalation=thresholds.escalation,
            )
        return thresholds

    logger.warning("policy.guardrails.yaml_bad_value", action=action, value=repr(value))
    return None


def _load_yaml_overrides() -> dict[str, ActionThresholds]:
    """Load and validate site-wide YAML thresholds.

    Schema::

        version: 1
        thresholds:
          isolate_host:
            auto: 0.92
            review: 0.72
            escalation: 0.45
          block_ip: 0.90        # scalar form == auto threshold only

    Unknown actions are accepted but logged so policy authors can spot typos.
    Values outside ``[0, 1]`` are clamped and logged rather than crashed on —
    a config typo should never disable the agent at boot.
    """
    global _YAML_THRESHOLDS
    if _YAML_THRESHOLDS is not None:
        return _YAML_THRESHOLDS

    path = _yaml_policy_path()
    if not path.is_file():
        _YAML_THRESHOLDS = {}
        return _YAML_THRESHOLDS

    try:
        import yaml  # type: ignore[import]
    except ImportError:
        logger.warning("policy.guardrails.yaml_disabled", reason="pyyaml not installed")
        _YAML_THRESHOLDS = {}
        return _YAML_THRESHOLDS

    try:
        with path.open("r", encoding="utf-8") as fp:
            doc = yaml.safe_load(fp) or {}
    except Exception as exc:
        logger.warning("policy.guardrails.yaml_parse_error", path=str(path), error=str(exc))
        _YAML_THRESHOLDS = {}
        return _YAML_THRESHOLDS

    raw = doc.get("thresholds") if isinstance(doc, dict) else None
    if not isinstance(raw, dict):
        logger.warning("policy.guardrails.yaml_invalid_shape", path=str(path))
        _YAML_THRESHOLDS = {}
        return _YAML_THRESHOLDS

    cleaned: dict[str, ActionThresholds] = {}
    for action, value in raw.items():
        if not isinstance(action, str):
            logger.warning("policy.guardrails.yaml_bad_key", key=repr(action))
            continue
        coerced = _coerce_threshold_value(action, value)
        if coerced is None:
            continue
        if action not in _DEFAULT_THRESHOLDS:
            logger.info("policy.guardrails.yaml_unknown_action", action=action)
        cleaned[action] = coerced

    _YAML_THRESHOLDS = cleaned
    logger.info("policy.guardrails.yaml_loaded", path=str(path), action_count=len(cleaned))
    return _YAML_THRESHOLDS


def reset_yaml_cache() -> None:
    """Clear the YAML cache. Used by tests and the admin reload endpoint."""
    global _YAML_THRESHOLDS
    _YAML_THRESHOLDS = None


def reset_tenant_cache(tenant_id: str | None = None) -> None:
    """Clear cached DB overrides. Pass ``None`` to clear every tenant."""
    if tenant_id is None:
        _TENANT_OVERRIDES.clear()
    else:
        _TENANT_OVERRIDES.pop(tenant_id, None)


# ---------------------------------------------------------------------------
# DB loader (best-effort)
# ---------------------------------------------------------------------------


async def _load_overrides(tenant_id: str) -> dict[str, ActionThresholds]:
    """Load tenant-specific threshold overrides from the DB (best-effort).

    Reads all three tiers (``min_confidence``, ``review_confidence``,
    ``escalation_confidence``) from ``aisoc_autonomy_thresholds``. The two
    derived columns are NULL on legacy rows; in that case
    :func:`_make_thresholds` derives the missing tiers from ``auto``.

    If the new columns don't exist (pre-021 schema) we gracefully fall back
    to the original single-column SELECT so older deployments keep working.
    """
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
                dsn.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://"),
                min_size=1,
                max_size=2,
            )
        async with _POOL.acquire() as conn:
            try:
                rows = await conn.fetch(
                    """
                    SELECT action_name,
                           min_confidence,
                           review_confidence,
                           escalation_confidence
                    FROM aisoc_autonomy_thresholds
                    WHERE tenant_id = $1
                    """,
                    tenant_id,
                )
            except Exception as schema_exc:
                # Pre-021 schema — fall back to the legacy single-column shape.
                logger.debug(
                    "policy.guardrails.overrides_legacy_schema",
                    tenant_id=tenant_id,
                    error=str(schema_exc),
                )
                rows = await conn.fetch(
                    """
                    SELECT action_name, min_confidence
                    FROM aisoc_autonomy_thresholds
                    WHERE tenant_id = $1
                    """,
                    tenant_id,
                )
            overrides: dict[str, ActionThresholds] = {}
            for r in rows:
                auto = float(r["min_confidence"])
                review_raw = r["review_confidence"] if "review_confidence" in r.keys() else None
                escalation_raw = r["escalation_confidence"] if "escalation_confidence" in r.keys() else None
                review = float(review_raw) if review_raw is not None else None
                escalation = float(escalation_raw) if escalation_raw is not None else None
                overrides[r["action_name"]] = _make_thresholds(auto, review, escalation)
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
    """Backward-compatible result for binary autonomy gating.

    ``allowed`` is true iff the policy decided :attr:`AutonomyDecision.AUTO`.
    Use :class:`DecisionResult` for the full three-tier outcome.
    """

    allowed: bool
    action: str
    confidence: float
    threshold: float
    reason: str = ""


@dataclass
class DecisionResult:
    """Three-tier autonomy decision with the cutoffs that produced it."""

    decision: AutonomyDecision
    action: str
    confidence: float
    thresholds: ActionThresholds
    reason: str = ""


@dataclass
class GuardrailPolicy:
    tenant_id: str
    thresholds: dict[str, ActionThresholds] = field(default_factory=dict)

    @classmethod
    async def load(cls, tenant_id: str) -> GuardrailPolicy:
        # Precedence (low → high): hard-coded defaults → YAML site policy →
        # DB tenant overrides. DB is loaded last so admin UI edits always win.
        yaml_thresholds = _load_yaml_overrides()
        db_overrides = await _load_overrides(tenant_id)
        merged: dict[str, ActionThresholds] = {
            **_DEFAULT_THRESHOLDS,
            **yaml_thresholds,
            **db_overrides,
        }
        return cls(tenant_id=tenant_id, thresholds=merged)

    @classmethod
    def load_sync(cls, tenant_id: str) -> GuardrailPolicy:
        """Synchronous loader — defaults + YAML only, no DB.

        Useful in CLI tools, tests, and any context where an event loop is not
        available.
        """
        yaml_thresholds = _load_yaml_overrides()
        merged: dict[str, ActionThresholds] = {**_DEFAULT_THRESHOLDS, **yaml_thresholds}
        return cls(tenant_id=tenant_id, thresholds=merged)

    # -- new three-tier API --------------------------------------------------

    def decide(self, action: str, confidence: float) -> DecisionResult:
        thresholds = self.thresholds.get(action, _REJECT_DEFAULT)
        decision = thresholds.decide(confidence)
        reason = ""
        if decision is AutonomyDecision.REVIEW:
            reason = f"Confidence {confidence:.2f} below auto threshold {thresholds.auto:.2f} for '{action}' — analyst review required."
        elif decision is AutonomyDecision.ESCALATE:
            reason = (
                f"Confidence {confidence:.2f} below review threshold {thresholds.review:.2f} for '{action}' — escalating to senior on-call."
            )
        elif decision is AutonomyDecision.REJECT:
            reason = f"Confidence {confidence:.2f} below escalation floor {thresholds.escalation:.2f} for '{action}' — refusing to act."
        if decision is not AutonomyDecision.AUTO:
            logger.info(
                "policy.guardrails.decision",
                action=action,
                decision=decision.value,
                confidence=confidence,
                auto=thresholds.auto,
                review=thresholds.review,
                escalation=thresholds.escalation,
                tenant_id=self.tenant_id,
            )
        return DecisionResult(
            decision=decision,
            action=action,
            confidence=confidence,
            thresholds=thresholds,
            reason=reason,
        )

    # -- backward-compat binary API -----------------------------------------

    def evaluate(self, action: str, confidence: float) -> ActionResult:
        """Return a binary :class:`ActionResult` (``allowed`` ⇔ ``AUTO``)."""
        decision = self.decide(action, confidence)
        thresholds = decision.thresholds
        allowed = decision.decision is AutonomyDecision.AUTO
        return ActionResult(
            allowed=allowed,
            action=action,
            confidence=confidence,
            threshold=thresholds.auto,
            reason=decision.reason,
        )

    def get_threshold(self, action: str) -> float:
        """Return the ``auto`` threshold for ``action`` (1.0 if unknown)."""
        return self.thresholds.get(action, _REJECT_DEFAULT).auto

    def get_thresholds(self, action: str) -> ActionThresholds:
        return self.thresholds.get(action, _REJECT_DEFAULT)

    def all_thresholds(self) -> dict[str, ActionThresholds]:
        return dict(self.thresholds)


def default_thresholds() -> dict[str, ActionThresholds]:
    """Return a copy of the hard-coded default thresholds."""
    return dict(_DEFAULT_THRESHOLDS)


def yaml_thresholds() -> dict[str, ActionThresholds]:
    """Return a copy of the currently-loaded YAML thresholds (loads if needed)."""
    return dict(_load_yaml_overrides())

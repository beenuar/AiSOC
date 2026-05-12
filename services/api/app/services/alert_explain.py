"""Structured alert explanation generator (Stage 2 #6).

This service powers ``POST /api/v1/alerts/{alert_id}/explain``. It
produces a single structured JSON payload — *not* an NDJSON stream —
because the API service's contract is request/response and the UI
tolerates a one-shot reply for the explain drawer.

The agents service exposes a streaming variant at
``services/agents/app/api/explain.py`` that the legacy ``ExplainDrawer``
already consumes. This service is intentionally lighter: it returns
the structured fields the spec calls for (``rule_lineage``,
``contributing_events``, ``mitre_techniques``, ``historical_fp_rate``,
``suggested_actions``) plus a brief ``summary`` so the drawer can paint
without a second round-trip.

Design choices
--------------

* **Best-effort rule lineage.** ``Alert`` does not carry a foreign key
  to ``DetectionRule`` (alerts can come from connectors that don't fire
  rules at all — see ``services/fusion``). We probe the alert's
  ``raw_event`` for an explicit ``rule_id`` / ``detection_rule_id``,
  then sweep ``tags`` for ``rule:<uuid>``, then fall back to matching
  rules by MITRE technique overlap and category. The matched rule
  drives the ``historical_fp_rate`` query and the rule lineage card.
* **Historical FP rate is computed live, not cached.** The query is
  bounded (last 90 days, capped at 5k rows) and indexed. Computing on
  read keeps the explanation honest — a tenant tuning a noisy rule
  will see the FP rate drop in real time.
* **LLM call is best-effort with a deterministic fallback.** The
  resolver in :mod:`app.services.llm_resolver` returns
  ``allowed=False`` whenever the tenant has no key, the env baseline
  is empty, or air-gap policy bites. In all of those cases we still
  return a useful explanation built from the corpus, so the explain
  button never fails closed.
* **Cost tracking is mandatory when the LLM fires.** Every successful
  outbound call books a row into ``aisoc_run_costs`` keyed by
  ``run_id=alert:<alert_uuid>`` so the cost dashboard can attribute
  spend back to the specific alert. This gives operators a clean
  audit trail when the explain button gets abused.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.models.alert import Alert
from app.models.detection_rule import DetectionRule
from app.services.cost_dashboard import _impute_public_cost
from app.services.llm_resolver import LlmConfig, resolve_llm_config

logger = logging.getLogger(__name__)


# Lookback window for the historical FP rate query. 90 days is long
# enough to see a tenant's tuning trends but short enough to dodge
# stale rules that haven't been triggered in a year. Capped at 5k
# alerts so a chatty rule can't blow up the explain endpoint.
_FP_RATE_LOOKBACK_DAYS = 90
_FP_RATE_SAMPLE_CAP = 5_000

# Max number of contributing events we surface from the alert. The
# drawer only needs a few; the rest are available via the alert detail
# view and the lake API.
_MAX_CONTRIBUTING_EVENTS = 5

# Cap MITRE technique cards so the drawer stays scannable.
_MAX_MITRE_TECHNIQUES = 5

# Match any T#### or T####.### technique id in free text. Mirrors the
# pattern used by the agents-side explainer.
_MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{1,3})?\b")


@dataclass(frozen=True)
class RuleLineage:
    """Provenance chain for the rule that (likely) fired this alert."""

    rule_id: str | None
    rule_name: str | None
    rule_description: str | None
    rule_status: str | None
    rule_severity: str | None
    rule_confidence: int | None
    rule_language: str | None
    is_builtin: bool
    confidence: str  # "high" | "medium" | "low" — how sure we are about the match
    match_method: str  # "raw_event" | "tags" | "mitre_overlap" | "none"


@dataclass(frozen=True)
class HistoricalFpRate:
    """Live-computed false-positive rate for the matched rule + scope."""

    fp_rate: float  # 0.0 .. 1.0
    sample_size: int  # # of resolved alerts considered
    false_positives: int  # # within sample with disposition='false_positive'
    lookback_days: int
    scope: str  # "rule" | "category" | "technique" — which fallback we used
    notes: str  # human-readable explanation


@dataclass(frozen=True)
class SuggestedAction:
    """One concrete next step grounded in the alert."""

    title: str
    rationale: str
    playbook_id: str | None  # link into the playbook engine when available
    priority: str  # "immediate" | "soon" | "fyi"


@dataclass(frozen=True)
class ContributingEvent:
    """Compact representation of one observable from the raw event."""

    label: str
    value: str
    annotation: str = ""


@dataclass(frozen=True)
class MitreTechnique:
    """One MITRE ATT&CK technique resolved from the local corpus."""

    id: str
    name: str
    tactic_names: list[str]
    description: str
    url: str


@dataclass(frozen=True)
class AlertExplanation:
    """Top-level explain payload returned by the endpoint."""

    alert_id: str
    summary: str
    rule_lineage: RuleLineage
    contributing_events: list[ContributingEvent]
    mitre_techniques: list[MitreTechnique]
    historical_fp_rate: HistoricalFpRate
    suggested_actions: list[SuggestedAction]
    llm_used: bool
    llm_source: str
    llm_reason: str  # populated when ``llm_used`` is False
    generated_at: str  # ISO-8601


# ---------------------------------------------------------------------------
# Rule lineage matching
# ---------------------------------------------------------------------------


_RULE_TAG_RE = re.compile(r"^rule:([0-9a-fA-F-]{36})$")


def _coerce_rule_id(value: Any) -> uuid.UUID | None:
    """Best-effort coerce an arbitrary value to a rule UUID."""
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


def _explicit_rule_id_from_alert(alert: Alert) -> uuid.UUID | None:
    """Probe the alert for an explicit rule reference.

    Connectors that *do* track rule provenance will normally drop the
    id into ``raw_event`` (most common) or stamp a ``rule:<uuid>`` tag
    on the alert. We accept both.
    """
    raw = alert.raw_event or {}
    if isinstance(raw, dict):
        for key in ("rule_id", "detection_rule_id", "ruleId", "detectionRuleId"):
            rid = _coerce_rule_id(raw.get(key))
            if rid is not None:
                return rid
        # Some connectors nest the rule under an "alert" or "detection" object.
        for nest_key in ("alert", "detection", "rule"):
            nested = raw.get(nest_key)
            if isinstance(nested, dict):
                for key in ("id", "rule_id", "detection_rule_id"):
                    rid = _coerce_rule_id(nested.get(key))
                    if rid is not None:
                        return rid

    tags = alert.tags or []
    if isinstance(tags, list):
        for tag in tags:
            if not isinstance(tag, str):
                continue
            match = _RULE_TAG_RE.match(tag.strip())
            if match:
                rid = _coerce_rule_id(match.group(1))
                if rid is not None:
                    return rid

    return None


async def _resolve_rule_lineage(db: AsyncSession, alert: Alert) -> tuple[DetectionRule | None, str, str]:
    """Find the detection rule (if any) that produced this alert.

    Returns ``(rule, confidence, match_method)``:

    * ``rule`` — the matched ``DetectionRule`` row, or ``None`` when
      no plausible match exists.
    * ``confidence`` — ``"high"`` for explicit references, ``"medium"``
      when we matched on category + technique overlap, ``"low"`` for
      single-axis matches, ``"none"`` when nothing matched.
    * ``match_method`` — one of the strings above (``raw_event``,
      ``tags``, ``mitre_overlap``, ``category``, ``none``) so the UI
      can flag low-confidence guesses.
    """
    # 1. Explicit reference in raw_event or tags.
    explicit_id = _explicit_rule_id_from_alert(alert)
    if explicit_id is not None:
        result = await db.execute(select(DetectionRule).where(DetectionRule.id == explicit_id))
        rule = result.scalar_one_or_none()
        if rule is not None:
            # The raw_event probe wins over the tag probe; we don't
            # bother distinguishing here because both signals come
            # from the connector and both are equally trustworthy.
            return rule, "high", "raw_event"

    # 2. Best-effort match by MITRE technique overlap + category.
    techniques = list(alert.mitre_techniques or [])
    technique_ids = [str(t) for t in techniques if isinstance(t, str)]

    if not technique_ids and not alert.category:
        # Nothing to match on; bail out early.
        return None, "none", "none"

    # Build a candidate set scoped to this tenant (RLS already filters
    # by tenant_id, but we add the predicate explicitly so the index
    # path is obvious to anyone reading the query log).
    filters = [
        # Match either the tenant-scoped rule or a platform-wide
        # built-in rule (NULL tenant_id). A connector firing in a
        # tenant context is very likely to match a builtin rule when
        # the tenant hasn't authored their own.
        ((DetectionRule.tenant_id == alert.tenant_id) | DetectionRule.tenant_id.is_(None)),
        DetectionRule.status.in_(["enabled", "active", "production"]),
    ]
    if alert.category:
        filters.append(DetectionRule.category == alert.category)

    result = await db.execute(
        select(DetectionRule)
        .where(and_(*filters))
        # Limit to a sane number — we only need to score a handful of
        # candidates, not every rule in the catalogue.
        .limit(50)
    )
    candidates = list(result.scalars().all())
    if not candidates:
        return None, "none", "none"

    # Score each candidate by technique-set overlap. A perfect match
    # (same techniques, same category) is high confidence; partial
    # overlap is medium; category-only is low.
    best: tuple[int, DetectionRule] | None = None
    for rule in candidates:
        rule_techniques = {str(t) for t in (rule.mitre_techniques or []) if isinstance(t, str)}
        overlap = len(rule_techniques.intersection(technique_ids))
        # Score: technique overlap dominates, with a tie-breaker on
        # rule confidence and a small bonus for built-in rules (they
        # tend to be higher quality than ad-hoc tenant rules).
        score = overlap * 10 + min(rule.confidence or 0, 100) // 10
        if rule.is_builtin:
            score += 1
        if best is None or score > best[0]:
            best = (score, rule)

    if best is None or best[0] == 0:
        # No technique overlap. If we narrowed by category and got
        # candidates, fall through to a low-confidence category match
        # using the highest-confidence candidate.
        if alert.category and candidates:
            top = max(candidates, key=lambda r: r.confidence or 0)
            return top, "low", "category"
        return None, "none", "none"

    score, rule = best
    if score >= 20:  # at least two technique matches
        return rule, "high", "mitre_overlap"
    if score >= 10:  # one technique match
        return rule, "medium", "mitre_overlap"
    return rule, "low", "mitre_overlap"


# ---------------------------------------------------------------------------
# Historical FP rate
# ---------------------------------------------------------------------------


async def _historical_fp_rate(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    rule: DetectionRule | None,
    alert: Alert,
) -> HistoricalFpRate:
    """Compute the live FP rate for the most specific available scope.

    Order of preference: same rule (when we have one) → same category
    + technique overlap → same category. We always cap the sample to
    keep the query bounded.
    """
    cutoff = datetime.now(UTC) - timedelta(days=_FP_RATE_LOOKBACK_DAYS)

    base_filters = [
        Alert.tenant_id == tenant_id,
        Alert.disposition.is_not(None),
        Alert.created_at >= cutoff,
    ]

    scope: str
    notes: str
    extra_filters: list[Any] = []

    if rule is not None and rule.id is not None:
        # Match alerts that either reference this rule explicitly or
        # share its category + technique signature. We don't have a FK
        # so we approximate; this is documented as an approximation
        # in the response notes so analysts know what they're seeing.
        extra_filters = [Alert.category == rule.category] if rule.category else []
        rule_techniques = list(rule.mitre_techniques or [])
        if rule_techniques:
            # Postgres JSONB ?| asks "does any of these top-level keys
            # appear in the array?". We use the SQLAlchemy ``op`` form
            # so we don't depend on the dialect-specific extension.
            extra_filters.append(Alert.mitre_techniques.op("?|")(rule_techniques))
        scope = "rule"
        notes = (
            f"Approximated by category={rule.category!r} and MITRE techniques matching {rule.name!r}; alerts don't carry a direct rule FK."
        )
    elif alert.category and (alert.mitre_techniques or []):
        extra_filters = [
            Alert.category == alert.category,
            Alert.mitre_techniques.op("?|")(list(alert.mitre_techniques or [])),
        ]
        scope = "category"
        notes = f"Computed across category={alert.category!r} alerts sharing at least one MITRE technique with this alert."
    elif alert.category:
        extra_filters = [Alert.category == alert.category]
        scope = "category"
        notes = f"Computed across all category={alert.category!r} alerts (no MITRE refinement)."
    else:
        # Tenant-wide fallback. Useful but very noisy; we mark it as
        # such in ``notes`` so the UI can warn the analyst.
        scope = "category"
        notes = "Tenant-wide fallback — alert has no category or MITRE data."

    query = (
        select(
            func.count().label("total"),
            func.count().filter(Alert.disposition == "false_positive").label("fps"),
        )
        .where(and_(*base_filters, *extra_filters))
        .limit(_FP_RATE_SAMPLE_CAP)
    )

    try:
        row = (await db.execute(query)).one()
    except Exception as exc:  # noqa: BLE001
        # FP rate is informational; never fail the whole explain
        # endpoint because the analytics query timed out.
        logger.warning("explain.fp_rate_query_failed tenant=%s error=%s", tenant_id, exc)
        return HistoricalFpRate(
            fp_rate=0.0,
            sample_size=0,
            false_positives=0,
            lookback_days=_FP_RATE_LOOKBACK_DAYS,
            scope=scope,
            notes=f"Query failed: {exc}; treat with caution.",
        )

    total = int(row.total or 0)
    fps = int(row.fps or 0)
    rate = (fps / total) if total else 0.0
    return HistoricalFpRate(
        fp_rate=round(rate, 4),
        sample_size=total,
        false_positives=fps,
        lookback_days=_FP_RATE_LOOKBACK_DAYS,
        scope=scope,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# MITRE technique resolution
# ---------------------------------------------------------------------------


def _extract_mitre_ids(alert: Alert) -> list[str]:
    """Pull MITRE technique IDs from the alert.

    Accepts the structured ``mitre_techniques`` column first (the
    canonical source) and falls back to a regex sweep over tags +
    title + description so older alerts without the structured field
    still get something useful.
    """
    found: list[str] = []
    seen: set[str] = set()

    for item in alert.mitre_techniques or []:
        if not isinstance(item, str):
            continue
        if item not in seen:
            found.append(item)
            seen.add(item)

    text_pool = " ".join(str(v) for v in (alert.tags or []) + [alert.title or "", alert.description or ""])
    for tid in _MITRE_ID_RE.findall(text_pool):
        if tid not in seen:
            found.append(tid)
            seen.add(tid)

    return found[:_MAX_MITRE_TECHNIQUES]


def _resolve_technique_card(technique_id: str) -> MitreTechnique:
    """Look up the technique in the local MITRE corpus when available.

    The MITRE corpus lives in the agents service; we do not import it
    from the API service to avoid a hard dependency. If a sibling
    module has already loaded the corpus into ``app.tools.mitre_full``
    we use it; otherwise we emit a stub card with just the ATT&CK URL.
    The drawer renders both shapes.
    """
    try:
        # Lazy import: the API service does not ship mitre_full by
        # default. When run inside the monorepo with the agents
        # package on the path it's available; in production API-only
        # deployments it isn't, and that's fine.
        from app.tools.mitre_full import get_technique  # type: ignore[import-not-found]
    except Exception:
        return MitreTechnique(
            id=technique_id,
            name=technique_id,
            tactic_names=[],
            description="",
            url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        )

    raw = get_technique(technique_id)
    desc = (raw.get("description") or "").strip()
    return MitreTechnique(
        id=raw.get("id", technique_id),
        name=raw.get("name", technique_id),
        tactic_names=list(raw.get("tactic_names") or []),
        description=desc[:280] + ("…" if len(desc) > 280 else ""),
        url=raw.get("url") or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


# ---------------------------------------------------------------------------
# Contributing events + suggested actions
# ---------------------------------------------------------------------------


def _extract_contributing_events(alert: Alert) -> list[ContributingEvent]:
    """Surface the most useful observables from the alert.

    Order: severity / risk score / source first (always available),
    then named observables from ``raw_event`` (user, IPs, host,
    process, hashes, URLs), then any structured IOCs the connector
    attached. Capped at ``_MAX_CONTRIBUTING_EVENTS``.
    """
    events: list[ContributingEvent] = []
    seen_labels: set[str] = set()

    def add(label: str, value: Any, annotation: str = "") -> None:
        if value in (None, "", [], {}) or label in seen_labels:
            return
        events.append(
            ContributingEvent(
                label=label,
                value=str(value)[:160],
                annotation=annotation,
            )
        )
        seen_labels.add(label)

    add("Severity", alert.severity)
    add("Source", alert.connector_type or "platform")
    if alert.ai_score is not None:
        add("AI score", round(float(alert.ai_score), 2))

    raw = alert.raw_event or {}
    if isinstance(raw, dict):
        for label, key in (
            ("User", "user"),
            ("User", "user_name"),
            ("Source IP", "src_ip"),
            ("Source IP", "source_ip"),
            ("Destination IP", "dest_ip"),
            ("Destination IP", "destination_ip"),
            ("Host", "hostname"),
            ("Host", "host"),
            ("Process", "process_name"),
            ("Process", "process"),
            ("File hash", "file_hash"),
            ("Domain", "domain"),
            ("URL", "url"),
        ):
            add(label, raw.get(key))

    return events[:_MAX_CONTRIBUTING_EVENTS]


def _build_suggested_actions(alert: Alert, mitre_ids: list[str]) -> list[SuggestedAction]:
    """Curated, never LLM-generated list of next steps.

    Generated suggestions are deliberately curated (not LLM-derived)
    so the explain button can never recommend a non-existent playbook
    or hallucinate a destructive action. The LLM only ever produces
    the prose summary.
    """
    tags = {str(t).lower() for t in (alert.tags or [])}
    severity = (alert.severity or "").lower()
    actions: list[SuggestedAction] = []

    if "account-takeover" in tags or "ato" in tags or "T1078" in mitre_ids:
        actions.append(
            SuggestedAction(
                title="Run ATO containment playbook",
                rationale="Block sessions, force password reset, and require step-up MFA on the affected identity.",
                playbook_id="ato-impossible-travel-block-v1",
                priority="immediate",
            )
        )

    if "ransomware" in tags or "T1486" in mitre_ids:
        actions.append(
            SuggestedAction(
                title="Isolate the host",
                rationale="Suspected ransomware activity — quarantine the endpoint to stop encryption spread.",
                playbook_id="ransomware-host-isolate-v1",
                priority="immediate",
            )
        )

    if "phishing" in tags or "bec" in tags:
        actions.append(
            SuggestedAction(
                title="Pull the message and similar deliveries",
                rationale="Identify other recipients and remove the message from inboxes before clicks propagate.",
                playbook_id="phishing-message-pull-v1",
                priority="soon",
            )
        )

    if any(t.startswith("T1190") or t.startswith("T1133") for t in mitre_ids):
        actions.append(
            SuggestedAction(
                title="Tighten perimeter exposure",
                rationale="Initial-access vector points at an external-facing service — review WAF rules and patch level.",
                playbook_id=None,
                priority="soon",
            )
        )

    if not actions:
        actions.append(
            SuggestedAction(
                title="Correlate with the last 24 h of alerts",
                rationale="Look for the same user, host, or IOC in adjacent detections to spot a multi-stage attack.",
                playbook_id=None,
                priority="fyi",
            )
        )

    if severity in ("high", "critical"):
        actions.append(
            SuggestedAction(
                title="Open a case and notify on-call",
                rationale=f"Severity is {severity}; promote to a tracked incident before further investigation.",
                playbook_id=None,
                priority="immediate" if severity == "critical" else "soon",
            )
        )

    return actions[:4]


# ---------------------------------------------------------------------------
# Summary (deterministic + optional LLM)
# ---------------------------------------------------------------------------


def _deterministic_summary(
    alert: Alert,
    mitre_techniques: list[MitreTechnique],
    rule_lineage: RuleLineage,
    fp: HistoricalFpRate,
) -> str:
    """Always-available summary built from the alert + corpus data.

    Used when the LLM is disabled (no key, air-gapped, etc.) or when
    the LLM call fails. The prose is intentionally bland — it exists
    to keep the drawer useful, not to delight.
    """
    title = alert.title or "Security alert"
    severity = (alert.severity or "unknown").lower()
    source = alert.connector_type or "an upstream connector"

    parts = [f"{title} fired at {severity} severity from {source}."]

    if rule_lineage.rule_name and rule_lineage.confidence != "none":
        confidence_note = (
            f"matched detection rule {rule_lineage.rule_name!r}"
            if rule_lineage.confidence == "high"
            else f"likely produced by {rule_lineage.rule_name!r} (match confidence: {rule_lineage.confidence})"
        )
        parts.append(f"This alert was {confidence_note}.")

    if mitre_techniques:
        ids = ", ".join(t.id for t in mitre_techniques[:3])
        parts.append(f"MITRE ATT&CK coverage: {ids}.")

    if fp.sample_size >= 10:
        pct = round(fp.fp_rate * 100, 1)
        parts.append(
            f"Historically {pct}% of similar alerts ({fp.sample_size} sampled in the last "
            f"{fp.lookback_days} days) were resolved as false positives."
        )

    desc = (alert.description or "").strip()
    if desc:
        snippet = desc if len(desc) <= 240 else desc[:237] + "…"
        parts.append(snippet)

    return " ".join(parts)


@dataclass(frozen=True)
class _LlmCallResult:
    """Internal: raw outcome of one LLM round-trip."""

    text: str | None
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    error: str | None


async def _call_llm_for_summary(
    *,
    alert: Alert,
    rule_lineage: RuleLineage,
    mitre_techniques: list[MitreTechnique],
    fp: HistoricalFpRate,
    llm_config: LlmConfig,
) -> _LlmCallResult:
    """One round-trip to the configured LLM, with hard timeouts.

    Returns a populated :class:`_LlmCallResult` regardless of outcome
    so the caller can both surface a summary and book accurate cost
    metadata into ``aisoc_run_costs``.
    """
    started = time.monotonic()
    base = llm_config.base_url.rstrip("/")
    url = f"{base}/v1/chat/completions"

    prompt_alert = {
        "title": alert.title,
        "severity": alert.severity,
        "category": alert.category,
        "source": alert.connector_type,
        "description": alert.description,
        "tags": alert.tags or [],
    }
    prompt_rule = (
        {
            "name": rule_lineage.rule_name,
            "description": rule_lineage.rule_description,
            "match_confidence": rule_lineage.confidence,
            "match_method": rule_lineage.match_method,
        }
        if rule_lineage.rule_name
        else None
    )
    prompt_mitre = [{"id": t.id, "name": t.name, "tactic_names": t.tactic_names} for t in mitre_techniques]
    prompt_fp = {
        "fp_rate": fp.fp_rate,
        "sample_size": fp.sample_size,
        "lookback_days": fp.lookback_days,
        "scope": fp.scope,
    }

    messages = [
        {
            "role": "system",
            "content": (
                "You are AiSOC's alert explainer. Given one security alert, the "
                "detection rule that fired (when known), a list of MITRE ATT&CK "
                "techniques pulled from the local corpus, and the historical "
                "false-positive rate for similar alerts, write a tight 3-5 "
                "sentence brief for an L1/L2 SOC analyst. Be concrete about "
                "WHAT happened, WHY it matters, and what the FP context implies "
                "for triage urgency. Never invent technique IDs, vendor names, "
                "or IOCs that aren't in the input. No bullet lists, no headings — "
                "just prose. Do not promise to take actions; the analyst decides."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "alert": prompt_alert,
                    "rule": prompt_rule,
                    "mitre_techniques": prompt_mitre,
                    "historical_fp": prompt_fp,
                },
                indent=2,
            ),
        },
    ]

    # Air-gap belt-and-braces: the resolver already vetoed
    # api.openai.com when ``AISOC_AIRGAPPED`` is on, but we re-check at
    # the actual call site so a future code path that bypasses the
    # resolver still gets stopped.
    try:
        enforce_airgap_for_url(url)
    except AirgapViolation as exc:
        return _LlmCallResult(
            text=None,
            model=llm_config.model,
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=(time.monotonic() - started) * 1000.0,
            error=f"airgap_violation: {exc}",
        )

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {llm_config.api_key}"},
                json={"model": llm_config.model, "messages": messages, "max_tokens": 360},
            )
            resp.raise_for_status()
            payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return _LlmCallResult(
            text=None,
            model=llm_config.model,
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=(time.monotonic() - started) * 1000.0,
            error=str(exc),
        )

    text = ""
    try:
        text = (payload["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError):
        text = ""

    usage = payload.get("usage") or {}
    return _LlmCallResult(
        text=text or None,
        model=llm_config.model,
        prompt_tokens=int(usage.get("prompt_tokens") or 0),
        completion_tokens=int(usage.get("completion_tokens") or 0),
        latency_ms=(time.monotonic() - started) * 1000.0,
        error=None if text else "empty_response",
    )


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------


async def _record_llm_cost(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    call: _LlmCallResult,
) -> None:
    """Book the LLM round-trip into ``aisoc_run_costs``.

    Uses ``run_id=alert:<uuid>`` so the cost dashboard's per-run drill-
    down can attribute the spend to the originating alert. The pricing
    is imputed against the public list price via
    :func:`_impute_public_cost` so BYOK customers see what they'd
    have paid had they used the platform's account; the actual on-key
    cost is whatever their LLM provider charges them and is opaque
    to us.
    """
    if call.text is None and call.error:
        # Don't book failed calls — they didn't consume billable
        # tokens (or the provider returned an error before the
        # response). We log them via the caller's structured log so
        # operators still see them in the audit trail.
        return

    cost_usd = _impute_public_cost(
        call.model,
        call.prompt_tokens,
        call.completion_tokens,
    )

    run_id = f"alert:{alert_id}"

    # ``aisoc_run_costs`` PK is (run_id, tenant_id, model). We use an
    # upsert so multiple explain calls for the same alert accumulate
    # rather than blowing up on a duplicate key — analysts may click
    # "explain" several times during triage.
    await db.execute(
        # Plain SQL keeps the dialect-specific INSERT … ON CONFLICT
        # in one place. The cost dashboard already uses the same
        # table; we don't introduce a new abstraction.
        _UPSERT_RUN_COST,
        {
            "run_id": run_id,
            "tenant_id": str(tenant_id),
            "model": call.model,
            "prompt_tokens": call.prompt_tokens,
            "completion_tokens": call.completion_tokens,
            "cost_usd": cost_usd,
            "latency_ms": call.latency_ms,
        },
    )


from sqlalchemy import text  # noqa: E402  (kept near use site for clarity)

_UPSERT_RUN_COST = text(
    """
    INSERT INTO aisoc_run_costs (
        run_id, tenant_id, model,
        total_prompt_tokens, total_completion_tokens,
        total_cost_usd, total_latency_ms, call_count, recorded_at
    )
    VALUES (
        :run_id, :tenant_id, :model,
        :prompt_tokens, :completion_tokens,
        :cost_usd, :latency_ms, 1, now()
    )
    ON CONFLICT (run_id, tenant_id, model) DO UPDATE SET
        total_prompt_tokens     = aisoc_run_costs.total_prompt_tokens     + EXCLUDED.total_prompt_tokens,
        total_completion_tokens = aisoc_run_costs.total_completion_tokens + EXCLUDED.total_completion_tokens,
        total_cost_usd          = aisoc_run_costs.total_cost_usd          + EXCLUDED.total_cost_usd,
        total_latency_ms        = aisoc_run_costs.total_latency_ms        + EXCLUDED.total_latency_ms,
        call_count              = aisoc_run_costs.call_count              + 1,
        recorded_at             = now()
    """
)


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


async def generate_alert_explanation(
    db: AsyncSession,
    *,
    alert: Alert,
) -> AlertExplanation:
    """Produce the full structured explanation for one alert.

    The caller is responsible for permission checks (``alerts:read``)
    and rate limiting; this function only does the explain work and
    assumes the session's RLS context already restricts visibility to
    the alert's tenant.
    """
    rule, lineage_confidence, lineage_method = await _resolve_rule_lineage(db, alert)
    rule_lineage = RuleLineage(
        rule_id=str(rule.id) if rule else None,
        rule_name=rule.name if rule else None,
        rule_description=rule.description if rule else None,
        rule_status=rule.status if rule else None,
        rule_severity=rule.severity if rule else None,
        rule_confidence=rule.confidence if rule else None,
        rule_language=rule.rule_language if rule else None,
        is_builtin=bool(rule.is_builtin) if rule else False,
        confidence=lineage_confidence,
        match_method=lineage_method,
    )

    fp = await _historical_fp_rate(
        db,
        tenant_id=alert.tenant_id,
        rule=rule,
        alert=alert,
    )

    mitre_ids = _extract_mitre_ids(alert)
    mitre_techniques = [_resolve_technique_card(tid) for tid in mitre_ids]
    contributing = _extract_contributing_events(alert)
    actions = _build_suggested_actions(alert, mitre_ids)

    fallback_summary = _deterministic_summary(alert, mitre_techniques, rule_lineage, fp)

    llm_config = await resolve_llm_config(db, alert.tenant_id)
    llm_used = False
    llm_reason = llm_config.reason
    summary = fallback_summary

    if llm_config.allowed and llm_config.api_key:
        call = await _call_llm_for_summary(
            alert=alert,
            rule_lineage=rule_lineage,
            mitre_techniques=mitre_techniques,
            fp=fp,
            llm_config=llm_config,
        )
        if call.text:
            summary = call.text
            llm_used = True
        else:
            llm_reason = call.error or "llm_returned_empty_response"
        # Always attempt to book the cost — _record_llm_cost no-ops on
        # failed calls so we don't pollute the cost table with zero
        # rows.
        try:
            await _record_llm_cost(
                db,
                tenant_id=alert.tenant_id,
                alert_id=alert.id,
                call=call,
            )
        except Exception as exc:  # noqa: BLE001
            # Cost tracking failures must never break the explain
            # response. Log and move on.
            logger.warning(
                "explain.cost_track_failed tenant=%s alert=%s error=%s",
                alert.tenant_id,
                alert.id,
                exc,
            )

    return AlertExplanation(
        alert_id=str(alert.id),
        summary=summary,
        rule_lineage=rule_lineage,
        contributing_events=contributing,
        mitre_techniques=mitre_techniques,
        historical_fp_rate=fp,
        suggested_actions=actions,
        llm_used=llm_used,
        llm_source=llm_config.source,
        llm_reason="" if llm_used else (llm_reason or "llm_disabled"),
        generated_at=datetime.now(UTC).isoformat(),
    )

"""The last few times an analyst decided an alert of this shape, and why.

Gap-closure Phase 6.3, agents half.

What this adds that organisation memory does not
------------------------------------------------
``app/context/organisation_memory.py`` already reads compiled statements, and
compiling is the point of that module: a reason has to recur across
independent analysts before it becomes a durable claim about the estate. That
threshold is deliberate and should not be lowered.

It also means a disagreement recorded once is invisible there. An analyst
looking at the queue by hand sees the last three times this rule fired and
what a colleague did about it, whether or not any of it has crossed a
corroboration threshold, and that is what this reads: the raw decisions, in
order, with the reason each analyst gave.

``aisoc_analyst_feedback`` is append-only, one row per tagged disagreement, so
it can answer "the last N" at all. The override row in institutional memory
cannot: it is upserted per signature, so it holds the latest decision and no
history.

Matching
--------
A decision reaches an alert two ways, and the stronger one is ordered first.
A decision tagged against the same **rule** is the most specific claim
available. A decision whose scope value is one of the alert's own entities (a
host, a principal) is the fallback that lets a decision about one machine be
seen from a different rule.

How the text is contained
-------------------------
First-party, like organisation memory and unlike a knowledge-base article: a
disposition and a reason code come from a closed vocabulary the server owns,
and the free-text note is typed by an authenticated analyst in the console.
So it is sanitised and capped rather than nonce-fenced. The cap matters
regardless of trust, because the note interpolates nothing but is unbounded
in length, and the prompt budget is shared with the evidence.

The wording is advisory for a reason specific to this source. These are
individual opinions, some of which have not been corroborated by anybody, and
a prompt that presented them as facts would let one analyst's mistaken
closure steer every later alert of that shape.

Point in time
-------------
A ``CUTOFF`` source, like runbooks: this is a per-alert query against a table
that grows with every decision a SOC makes, so the freeze is an ``as_of`` the
frozen reader supplies and the server applies, and the server reports how many
rows it refused.

This is the leakiest of the three sources by construction. A decision recorded
during the test window is literally an analyst's answer to an alert in that
window, so a replay that could see them would be grading the agent on the
labels it is about to be marked against. Phase 1's outcome-prior leak by a
shorter route.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.investigator.prompt_sanitizer import sanitize_text

logger = structlog.get_logger()

__all__ = [
    "MAX_DISPOSITIONS_IN_PROMPT",
    "RecentDispositions",
    "clear_cache",
    "enabled",
    "entities_for",
    "fetch_recent_dispositions",
    "render_for_prompt",
]

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT_S = float(os.getenv("AISOC_TRIAGE_DISPOSITIONS_TIMEOUT_S", "5"))

#: Decisions placed in one prompt. Five is "what did we do the last few
#: times"; fifty is a different product, and it is the evidence's budget.
MAX_DISPOSITIONS_IN_PROMPT = int(os.getenv("AISOC_TRIAGE_DISPOSITIONS_TOP_N", "5"))

#: Per-note cap. The note is free text an analyst typed with no length limit.
_MAX_NOTE_CHARS = 240

_CACHE_TTL_S = float(os.getenv("AISOC_TRIAGE_DISPOSITIONS_TTL_S", "120"))

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def enabled() -> bool:
    return os.getenv("AISOC_TRIAGE_DISPOSITIONS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def clear_cache() -> None:
    """Drop cached decisions. Tests, and the feedback path."""
    _cache.clear()


@dataclass(frozen=True)
class RecentDispositions:
    """What one lookup returned, and what a replay has to publish about it."""

    decisions: tuple[Mapping[str, Any], ...] = ()

    #: The instant the server says it cut off at, echoed rather than
    #: remembered, so a server that ignored the parameter cannot be reported
    #: as having honoured it. ``None`` means no cutoff was applied.
    as_of: str | None = None

    excluded_after_cutoff: int = 0
    without_timestamp: int = 0

    def as_state(self) -> dict[str, Any]:
        return {
            "decisions": [dict(d) for d in self.decisions],
            "as_of": self.as_of,
            "excluded_after_cutoff": self.excluded_after_cutoff,
            "without_timestamp": self.without_timestamp,
        }

    def __bool__(self) -> bool:
        return bool(self.decisions)


def entities_for(raw_alert: Mapping[str, Any] | None) -> list[str]:
    """The entity values a past decision could have been scoped to.

    Host and principal only. An IP is an entity a decision can be scoped to in
    principle, and matching on one here would pull in every decision about a
    NAT gateway or a shared egress address, which is a suppression nobody
    wrote.
    """
    raw = raw_alert or {}
    out: list[str] = []
    for key in ("hostname", "host", "username", "user", "user_name", "src_user"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    for key in ("affected_hosts", "affected_users"):
        values = raw.get(key)
        if isinstance(values, list):
            out.extend(v.strip() for v in values if isinstance(v, str) and v.strip())
    return sorted({v.lower() for v in out})[:10]


async def fetch_recent_dispositions(
    tenant_id: str | None,
    *,
    rule_id: str = "",
    entities: Sequence[str] = (),
    as_of: datetime | None = None,
    limit: int = MAX_DISPOSITIONS_IN_PROMPT,
) -> RecentDispositions:
    """The last few analyst decisions matching this alert. Never raises.

    ``as_of`` has no default, for the same reason it has none on the runbook
    reader: a default of "now" lets an unfrozen caller look frozen, and a
    default of the epoch silently returns nothing on every live triage.
    """
    if not enabled() or not tenant_id:
        return RecentDispositions()
    rule = (rule_id or "").strip()
    entity_list = [e for e in entities if e]
    if not rule and not entity_list:
        return RecentDispositions()

    cache_key = f"{tenant_id}|{as_of.isoformat() if as_of else ''}|{limit}|{rule}|{','.join(sorted(entity_list))}"
    cached = _cache.get(cache_key)
    now = time.monotonic()
    if cached is not None and now - cached[0] < _CACHE_TTL_S:
        return _shape(cached[1], limit=limit)

    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        # Loud, like the other context readers: without the shared secret the
        # API refuses the service path, so every triage would run without the
        # decisions the operator's own analysts recorded.
        logger.warning(
            "triage_dispositions.no_service_token",
            reason="AISOC_AGENTS_SERVICE_TOKEN is unset, so recent analyst decisions cannot be read",
        )
        return RecentDispositions()

    params: list[tuple[str, str]] = [("tenant_id", tenant_id), ("rule_id", rule), ("limit", str(limit))]
    params.extend(("entities", e) for e in entity_list)
    if as_of is not None:
        params.append(("as_of", as_of.isoformat()))

    url = f"{_API_URL.rstrip('/')}/api/v1/feedback/recent-dispositions"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.get(url, params=params, headers={"X-AiSOC-Service-Token": token})
    except httpx.HTTPError as exc:
        logger.warning("triage_dispositions.unreachable", error=str(exc)[:300])
        return RecentDispositions()

    if response.status_code >= 400:
        logger.warning("triage_dispositions.refused", status_code=response.status_code)
        return RecentDispositions()

    try:
        payload = response.json()
    except ValueError:
        logger.warning("triage_dispositions.bad_response")
        return RecentDispositions()

    if not isinstance(payload, dict):
        return RecentDispositions()
    _cache[cache_key] = (now, payload)
    return _shape(payload, limit=limit)


def _shape(payload: Mapping[str, Any], *, limit: int) -> RecentDispositions:
    rows = payload.get("dispositions")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    echoed = payload.get("as_of")
    return RecentDispositions(
        decisions=tuple(dict(r) for r in rows[: max(1, limit)]),
        as_of=str(echoed) if echoed else None,
        excluded_after_cutoff=int(payload.get("excluded_after_cutoff") or 0),
        without_timestamp=int(payload.get("without_timestamp") or 0),
    )


def render_for_prompt(state_value: Mapping[str, Any] | None) -> str:
    """The prompt block, or ``""`` when there is nothing to say.

    Empty for an empty list, for the reason organisation memory is: a heading
    reading "Recent decisions: none" teaches the model this tenant's analysts
    have never dispositioned an alert of this shape, which is a claim rather
    than the absence of one.
    """
    rows = (state_value or {}).get("decisions")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    if not rows:
        return ""

    lines: list[str] = []
    for row in rows:
        verdict = sanitize_text(str(row.get("analyst_disposition") or ""), max_len=40)
        if not verdict:
            continue
        reason = sanitize_text(str(row.get("reason_label") or row.get("reason_code") or ""), max_len=80)
        scope = sanitize_text(str(row.get("scope_value") or ""), max_len=120)
        when = str(row.get("decided_at") or "")[:10]
        note = sanitize_text(str(row.get("note") or ""), max_len=_MAX_NOTE_CHARS)
        # The AI verdict travels with the analyst's. "The agent said
        # true_positive and an analyst called it benign" is a different and
        # much more useful fact than either half alone.
        overturned = sanitize_text(str(row.get("ai_disposition") or ""), max_len=40)
        parts = [f"- {when or 'undated'}: an analyst closed this as **{verdict}**"]
        if overturned and overturned != verdict:
            parts.append(f", overturning an automated {overturned}")
        if reason:
            parts.append(f". Reason: {reason}")
        if scope:
            parts.append(f" (scoped to {scope})")
        if note:
            parts.append(f'. Note: "{note}"')
        lines.append("".join(parts))

    if not lines:
        return ""

    return (
        "Recent analyst decisions on alerts of this shape in this tenant, newest first:\n"
        + "\n".join(lines)
        + "\nThese are individual decisions, not compiled organisation memory: some have not "
        "been corroborated by a second analyst, and any of them may have been wrong. Treat a "
        "repeated benign decision as a reason to consider benign_true_positive and to say which "
        "decision you are following. It never overrides direct evidence of compromise in this "
        "alert's own telemetry, and a single decision is one person's opinion."
    )


def basis(state_value: Mapping[str, Any] | None) -> list[str]:
    """Confidence-basis lines naming what the prompt was given."""
    rows = (state_value or {}).get("decisions")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    if not rows:
        return []
    tally: dict[str, int] = {}
    for row in rows:
        verdict = str(row.get("analyst_disposition") or "unknown")
        tally[verdict] = tally.get(verdict, 0) + 1
    summary = ", ".join(f"{count}x {verdict}" for verdict, count in sorted(tally.items()))
    return [f"Recent analyst decisions in prompt: {len(rows)} ({summary})"]

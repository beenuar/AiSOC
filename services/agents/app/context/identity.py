"""Who is behind the account this alert names, where a connector provides it.

Gap-closure Phase 6.3, agents half.

A verdict about an account is a different verdict depending on whose account
it is. A contractor whose engagement ended last month authenticating from a
new country is not the same alert as a support engineer on rotation doing the
same thing, and triage has had no way to tell them apart.

The data is already there for any tenant that has imported a directory or a
CMDB: ``POST /graph/context/import`` writes ``Employee``, ``Department`` and
``Identity`` nodes, and ``incident_context.py`` already reads them for an
escalated alert. What did not exist was a version of the question triage can
ask, because that traversal starts at an ``Alert`` node and triage runs before
one exists. This reads by account name instead.

Nothing is inferred when the tenant has imported nothing. An empty result is
an empty block, not a statement that the principal is unknown.

The freeze here is weaker than the other two, and says so
---------------------------------------------------------
An ``Employee`` node carries ``updated_at``, set when the snapshot was
imported. That is an import stamp, not a business-effective date, and the
difference matters exactly where this source is most useful: a record imported
yesterday may describe somebody who left last year, and a record imported
before the split may have been updated in place since.

So the API refuses rows whose import stamp is provably after the cutoff,
because that much is establishable, and counts **every row it serves** as
untestable, because surviving an import-time cutoff is not evidence that the
fact predates the split. Both numbers reach the replay report.

That is the same treatment organisation-memory statements get, and for the
same reason: the existing precedent publishes ``statements_without_timestamp``
rather than claiming a freeze tighter than the data supports. A source whose
untestable count is always the whole set is not a reason to stop publishing
the count; it is the reason to publish it.

Containment
-----------
First-party. A display name, a title, a department and a manager come from the
tenant's own directory import, so this is sanitised and capped rather than
nonce-fenced, like organisation memory and unlike a knowledge-base article.
The cap is not ceremony: a display name is a free-text field in every
directory product, and the prompt budget is shared with the evidence.
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
    "MAX_IDENTITIES_IN_PROMPT",
    "IdentityContext",
    "accounts_for",
    "basis",
    "clear_cache",
    "enabled",
    "fetch_identity_context",
    "render_for_prompt",
]

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT_S = float(os.getenv("AISOC_TRIAGE_IDENTITY_TIMEOUT_S", "5"))

#: An alert names one or two principals in practice. A cap exists because a
#: correlated alert can name many and the prompt budget is the evidence's.
MAX_IDENTITIES_IN_PROMPT = int(os.getenv("AISOC_TRIAGE_IDENTITY_TOP_N", "5"))

_MAX_FIELD_CHARS = 120

_CACHE_TTL_S = float(os.getenv("AISOC_TRIAGE_IDENTITY_TTL_S", "300"))

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def enabled() -> bool:
    return os.getenv("AISOC_TRIAGE_IDENTITY_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def clear_cache() -> None:
    """Drop cached identity lookups. Tests, and the context-import path."""
    _cache.clear()


@dataclass(frozen=True)
class IdentityContext:
    """What one lookup returned, and what a replay has to publish about it."""

    identities: tuple[Mapping[str, Any], ...] = ()
    as_of: str | None = None
    excluded_after_cutoff: int = 0
    #: For this source, always the number served. See the module docstring.
    without_timestamp: int = 0

    def as_state(self) -> dict[str, Any]:
        return {
            "identities": [dict(i) for i in self.identities],
            "as_of": self.as_of,
            "excluded_after_cutoff": self.excluded_after_cutoff,
            "without_timestamp": self.without_timestamp,
        }

    def __bool__(self) -> bool:
        return bool(self.identities)


def accounts_for(raw_alert: Mapping[str, Any] | None) -> list[str]:
    """The account names this alert is about.

    Principals only. A hostname is resolved by the asset dimension, which is a
    different question with a different answer.
    """
    raw = raw_alert or {}
    out: list[str] = []
    for key in ("username", "user", "user_name", "src_user", "actor", "principal"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    values = raw.get("affected_users")
    if isinstance(values, list):
        out.extend(v.strip() for v in values if isinstance(v, str) and v.strip())
    return sorted({v.lower() for v in out})[:MAX_IDENTITIES_IN_PROMPT]


async def fetch_identity_context(
    tenant_id: str | None,
    *,
    accounts: Sequence[str],
    as_of: datetime | None = None,
    limit: int = MAX_IDENTITIES_IN_PROMPT,
) -> IdentityContext:
    """Directory context for these accounts. Never raises.

    ``as_of`` has no default, for the same reason the other two cutoff readers
    have none.
    """
    if not enabled() or not tenant_id:
        return IdentityContext()
    names = [a for a in accounts if a]
    if not names:
        return IdentityContext()

    cache_key = f"{tenant_id}|{as_of.isoformat() if as_of else ''}|{limit}|{','.join(sorted(names))}"
    cached = _cache.get(cache_key)
    now = time.monotonic()
    if cached is not None and now - cached[0] < _CACHE_TTL_S:
        return _shape(cached[1], limit=limit)

    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        logger.warning(
            "triage_identity.no_service_token",
            reason="AISOC_AGENTS_SERVICE_TOKEN is unset, so identity context cannot be read",
        )
        return IdentityContext()

    params: list[tuple[str, str]] = [("tenant_id", tenant_id), ("limit", str(limit))]
    params.extend(("accounts", a) for a in names)
    if as_of is not None:
        params.append(("as_of", as_of.isoformat()))

    url = f"{_API_URL.rstrip('/')}/api/v1/graph/identity-context"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.get(url, params=params, headers={"X-AiSOC-Service-Token": token})
    except httpx.HTTPError as exc:
        logger.warning("triage_identity.unreachable", error=str(exc)[:300])
        return IdentityContext()

    if response.status_code >= 400:
        logger.warning("triage_identity.refused", status_code=response.status_code)
        return IdentityContext()

    try:
        payload = response.json()
    except ValueError:
        logger.warning("triage_identity.bad_response")
        return IdentityContext()

    if not isinstance(payload, dict):
        return IdentityContext()
    _cache[cache_key] = (now, payload)
    return _shape(payload, limit=limit)


def _shape(payload: Mapping[str, Any], *, limit: int) -> IdentityContext:
    rows = payload.get("identities")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    echoed = payload.get("as_of")
    return IdentityContext(
        identities=tuple(dict(r) for r in rows[: max(1, limit)]),
        as_of=str(echoed) if echoed else None,
        excluded_after_cutoff=int(payload.get("excluded_after_cutoff") or 0),
        without_timestamp=int(payload.get("without_timestamp") or 0),
    )


def render_for_prompt(state_value: Mapping[str, Any] | None) -> str:
    """The prompt block, or ``""`` when the tenant has imported nothing.

    Empty for an empty list, for the reason the other renderers are: a heading
    saying the principal could not be identified is a claim, and it is one a
    model would reasonably treat as suspicious when the truth is that this
    tenant has no directory connector.
    """
    rows = (state_value or {}).get("identities")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    if not rows:
        return ""

    lines: list[str] = []
    for row in rows:
        account = sanitize_text(str(row.get("account") or ""), max_len=_MAX_FIELD_CHARS)
        if not account:
            continue
        bits: list[str] = []
        for key, label in (("employee", ""), ("title", "title"), ("department", "department"), ("manager", "manager")):
            value = sanitize_text(str(row.get(key) or ""), max_len=_MAX_FIELD_CHARS)
            if value:
                bits.append(value if not label else f"{label} {value}")
        # Employment status last and stated explicitly either way. "Still
        # employed" and "left the company" are the two facts this source
        # exists to supply, and leaving the negative implicit is how an
        # inactive account reads as an ordinary one.
        active = row.get("is_active")
        if active is False:
            end = sanitize_text(str(row.get("end_date") or ""), max_len=40)
            bits.append(f"NO LONGER ACTIVE in the directory{f' (ended {end})' if end else ''}")
        elif active is True:
            bits.append("active in the directory")
        employment = sanitize_text(str(row.get("employment_type") or ""), max_len=40)
        if employment:
            bits.append(employment)
        lines.append(f"- {account}: " + ", ".join(bits) if bits else f"- {account}: no directory record")

    if not lines:
        return ""

    return (
        "Directory context for the principals in this alert, from this tenant's own imported "
        "HR or identity data:\n" + "\n".join(lines) + "\nThis describes the account holder, not the activity. It is a reason to weigh the "
        "activity differently, never a verdict on its own: an inactive account authenticating is "
        "worth escalating, and a senior title is not evidence that anything was authorised. The "
        "record reflects the last directory import and may be out of date."
    )


def basis(state_value: Mapping[str, Any] | None) -> list[str]:
    """Confidence-basis lines naming what the prompt was given."""
    rows = (state_value or {}).get("identities")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    if not rows:
        return []
    inactive = sum(1 for r in rows if r.get("is_active") is False)
    line = f"Directory context in prompt: {len(rows)} principal(s)"
    if inactive:
        line += f", {inactive} no longer active in the directory"
    return [line]

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
from datetime import date, datetime
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


#: A departure this many days out or fewer counts as "departing". 30 days
#: because it is the common notice period and because the exfiltration
#: literature puts the elevated window in the final weeks; it is a default
#: rather than a constant, and the number is stated in the prompt so a
#: reader is never guessing which window produced the phrase.
DEPARTING_WITHIN_DAYS = 30

#: Bounded per principal: the prompt budget is shared with the evidence,
#: and a fleet user with forty enrolled devices must not crowd it out.
_MAX_DEVICES_PER_PRINCIPAL = 3


def _parse_date(value: Any) -> date | None:
    """An ISO-8601 calendar date, or None.

    Dates only. A last day is a calendar date in a jurisdiction and not an
    instant, so a value carrying a time is truncated rather than converted:
    treating it as UTC would move somebody's departure by a day for half
    the world.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def derive_employment_facts(row: Mapping[str, Any], *, today: date | None = None) -> dict[str, Any]:
    """Tenure, departure proximity and contractor status, from one row.

    Each is derived rather than stored, and each is absent rather than
    false when the underlying date is missing. A principal whose start date
    nobody imported is not a new joiner, and one with no end date is not
    "definitely staying" -- they are unknown, and the prompt says nothing
    instead of saying something reassuring.
    """
    now = today or date.today()  # noqa: DTZ011 - a calendar date, deliberately
    facts: dict[str, Any] = {}

    start = _parse_date(row.get("start_date"))
    if start is not None:
        facts["tenure_days"] = max(0, (now - start).days)

    end = _parse_date(row.get("end_date"))
    if end is not None:
        remaining = (end - now).days
        facts["days_until_departure"] = remaining
        # Both directions are facts, and the past one is the sharper of the
        # two: an account whose last day has passed and which is still
        # authenticating is the single highest-signal row this source holds.
        facts["departed"] = remaining < 0
        facts["departing_soon"] = 0 <= remaining <= DEPARTING_WITHIN_DAYS

    employment = str(row.get("employment_type") or "").strip().lower()
    if employment in {"contractor", "contingent", "temp", "temporary"}:
        facts["is_contractor"] = True
    elif employment in {"employee", "full-time", "part-time", "full time", "part time"}:
        facts["is_contractor"] = False
    # Anything else, including "unknown" and a value no mapping covers,
    # leaves the key absent. A contractor read as staff loses exactly the
    # signal this field exists for, and the reverse is a false accusation.

    return facts


def _render_device_line(device: Mapping[str, Any]) -> str | None:
    """One device, as a bounded phrase, or None when it says nothing."""
    hostname = sanitize_text(str(device.get("hostname") or ""), max_len=_MAX_FIELD_CHARS)
    compliance = str(device.get("compliance_state") or "").strip().lower()
    bits: list[str] = []
    if compliance == "noncompliant":
        bits.append("NOT COMPLIANT with this tenant's device policy")
    elif compliance == "in_grace_period":
        bits.append("in the policy grace period")
    elif compliance == "compliant":
        bits.append("compliant")
    elif compliance in {"", "unknown", "not_enrolled"}:
        # Said explicitly. An unmanaged or unevaluated device is a real
        # state and is not the same as a compliant one; leaving it out
        # would let the reader assume the quieter of the two.
        bits.append("compliance not evaluated by the MDM")

    encrypted = device.get("encrypted")
    if encrypted is False:
        bits.append("disk NOT encrypted")
    elif encrypted is True:
        bits.append("disk encrypted")
    # None is silent: "not reported" is not a finding.

    agent = sanitize_text(str(device.get("edr_agent_health") or ""), max_len=40).lower()
    if agent and agent not in {"secured", "cleared", "unknown"}:
        bits.append(f"threat-defence agent state {agent}")

    os_version = sanitize_text(str(device.get("os_version") or ""), max_len=40)
    os_name = sanitize_text(str(device.get("os_name") or ""), max_len=40)
    if os_name or os_version:
        bits.append(" ".join(part for part in (os_name, os_version) if part))

    if not bits:
        return None
    label = hostname or "an enrolled device"
    return f"{label}: " + ", ".join(bits)


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

        # Depth plan wave 2, item 1.3. Derived from the dates the row
        # already carries and stated with the window that produced each
        # phrase, so "departing soon" is never a number the reader has to
        # guess at. Absent when the date is absent: a principal whose start
        # date nobody imported is not a new joiner, and one with no end date
        # is not "definitely staying".
        facts = derive_employment_facts(row)
        if facts.get("departed"):
            bits.append("LAST DAY HAS PASSED and the account is still authenticating")
        elif facts.get("departing_soon"):
            bits.append(f"departing in {facts['days_until_departure']} day(s)")
        if facts.get("is_contractor"):
            bits.append("contractor, not an employee")
        tenure = facts.get("tenure_days")
        if isinstance(tenure, int) and tenure <= 30:
            bits.append(f"joined {tenure} day(s) ago")

        lines.append(f"- {account}: " + ", ".join(bits) if bits else f"- {account}: no directory record")

        # The device half, indented under its owner. Rendered only when the
        # MDM said something: a principal with no enrolled device gets no
        # line, because "no device found" on a tenant with no MDM connector
        # is a statement about our coverage and not about the principal.
        devices = row.get("devices")
        if isinstance(devices, list):
            for device in devices[:_MAX_DEVICES_PER_PRINCIPAL]:
                if not isinstance(device, Mapping):
                    continue
                rendered = _render_device_line(device)
                if rendered:
                    lines.append(f"  - device {rendered}")

    if not lines:
        return ""

    return (
        "Directory, HR and device context for the principals in this alert, from this tenant's own "
        "connected HR system, directory import or MDM:\n"
        + "\n".join(lines)
        + "\nThis describes the account holder, not the activity, and a device line describes the "
        "device rather than what was done on it. It is a reason to "
        "weigh the activity differently, never a verdict on its own: an account whose last day has "
        "passed authenticating is worth escalating, and a senior title is not evidence that "
        f'anything was authorised. "Departing" means a recorded last day within {DEPARTING_WITHIN_DAYS} days. The record '
        "reflects the last import or sync and may be out of date; a device with no line said "
        "nothing, which is not the same as a device that reported no problem."
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
    out = [line]

    # Each derived fact is cited separately rather than folded into the
    # count above, because the confidence basis is what a reviewer reads to
    # see which input moved a verdict, and "1 principal in prompt" does not
    # say that one of them left last week.
    derived = [derive_employment_facts(r) for r in rows]
    departed = sum(1 for f in derived if f.get("departed"))
    departing = sum(1 for f in derived if f.get("departing_soon"))
    contractors = sum(1 for f in derived if f.get("is_contractor"))
    if departed:
        out.append(f"HR context: {departed} principal(s) whose recorded last day has passed")
    if departing:
        out.append(f"HR context: {departing} principal(s) departing within {DEPARTING_WITHIN_DAYS} days")
    if contractors:
        out.append(f"HR context: {contractors} principal(s) recorded as contractors")

    devices = [d for r in rows for d in (r.get("devices") or []) if isinstance(d, Mapping)]
    if devices:
        noncompliant = sum(1 for d in devices if str(d.get("compliance_state") or "").lower() == "noncompliant")
        unencrypted = sum(1 for d in devices if d.get("encrypted") is False)
        detail = f"Device context in prompt: {len(devices)} enrolled device(s)"
        if noncompliant:
            detail += f", {noncompliant} not compliant"
        if unencrypted:
            detail += f", {unencrypted} with no disk encryption"
        out.append(detail)
    return out

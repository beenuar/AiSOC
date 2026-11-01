"""What the alert's actor could do, as of the alert — for the triage prompt.

Depth plan wave 2, Phase 1.1.

The sibling of :mod:`app.context.identity`, which answers *who* holds the
account. This one answers *what the account could do when it acted*, which is
the question that decides whether an unusual sign-in is a nuisance or an
incident.

Why this goes through ``/investigate/query``
--------------------------------------------
There is exactly one dispatch table for investigation primitives
(``investigation_tools.TOOLS``), and the console, the typed-pivot route and
the model's tool registry all read it. Adding a second route for triage would
let the console and the model be offered different tools, which is how a
capability ends up working on one surface and silently missing on another.

So this calls the same endpoint the registered tool calls, which is also what
makes the answer appear in the ledger: a tool call recorded against a run is
the auditable artefact, and a side-channel read would produce a prompt
sentence with no matching ``tool_call`` row — the shape the grounding check
already demotes a verdict for.

What it never does
------------------
It never turns an unanswerable question into silence. When no posture covers
the alert's time the block says so in words, because the alternative is a
model inferring from an absent section that the principal was ordinary.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

__all__ = [
    "PrivilegeContext",
    "basis",
    "enabled",
    "fetch_privilege_context",
    "render_for_prompt",
]

_API_URL = os.getenv("AISOC_API_URL", "http://api:8000")
TENANT_HEADER = "X-AiSOC-Tenant-ID"
_TIMEOUT_S = 8.0
_CACHE_TTL_S = 120.0
#: Hard cap on principals looked up per alert. An alert naming forty accounts
#: is a sweep, and forty round trips on the triage hot path would be the
#: thing that made triage slow rather than the thing that made it right.
MAX_PRINCIPALS = 3

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def enabled() -> bool:
    """On by default. It reads the platform's own Postgres, nothing external.

    The "off by default where it reaches out" rule governs calls that leave
    the deployment; this one does not, and a tenant that has collected no
    posture simply gets "unknown" everywhere at no cost.
    """
    return os.getenv("AISOC_TRIAGE_PRIVILEGE_CONTEXT", "1").strip().lower() not in {"0", "false", "no", "off"}


def clear_cache() -> None:
    _cache.clear()


@dataclass(frozen=True)
class PrivilegeContext:
    """One lookup's worth of privilege answers, with its gaps named."""

    principals: tuple[dict[str, Any], ...] = ()
    #: Principals asked about for which no posture version covered the event.
    #: Carried rather than dropped: "we could not answer" is the finding when
    #: a tenant has connected a provider and not collected its posture.
    unresolved: tuple[str, ...] = ()
    at: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    def as_state(self) -> dict[str, Any]:
        return {
            "principals": [dict(p) for p in self.principals],
            "unresolved": list(self.unresolved),
            "at": self.at,
            "notes": list(self.notes),
        }

    def __bool__(self) -> bool:
        return bool(self.principals or self.unresolved)


def _service_token() -> str:
    return (os.getenv("AISOC_API_SERVICE_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN") or "").strip()


async def fetch_privilege_context(
    tenant_id: str | None,
    *,
    principals: Sequence[str],
    at: datetime | None = None,
) -> PrivilegeContext:
    """Privilege for these principals as of ``at``. Never raises.

    ``at`` is the alert's event time and is not optional in spirit: passing
    ``None`` asks what the identity can do *now*, which is a different
    question from the one triage is answering.
    """
    if not enabled() or not tenant_id:
        return PrivilegeContext()
    names = [p.strip() for p in principals if p and p.strip()][:MAX_PRINCIPALS]
    if not names:
        return PrivilegeContext()

    token = _service_token()
    if not token:
        logger.warning(
            "triage_privilege.no_service_token",
            reason="AISOC_SERVICE_TOKEN is unset, so privilege context cannot be read",
        )
        return PrivilegeContext()

    at_iso = at.isoformat() if at is not None else ""
    resolved: list[dict[str, Any]] = []
    unresolved: list[str] = []
    notes: list[str] = []

    for name in names:
        cache_key = f"{tenant_id}|{at_iso}|{name.lower()}"
        cached = _cache.get(cache_key)
        now = time.monotonic()
        if cached is not None and now - cached[0] < _CACHE_TTL_S:
            payload = cached[1]
        else:
            payload = await _query(tenant_id, name, at_iso, token)
            if payload is None:
                # Transport failure. Deliberately not cached and deliberately
                # not recorded as "unresolved": the two mean different things
                # and conflating them would turn an API outage into a
                # permanent statement that a tenant has no posture.
                notes.append(f"the privilege lookup for {name} could not be completed")
                continue
            _cache[cache_key] = (now, payload)

        if payload.get("available") is False:
            unresolved.append(name)
            continue
        rows = payload.get("rows") or []
        if rows:
            resolved.append(dict(rows[0]))
        else:
            unresolved.append(name)

    return PrivilegeContext(
        principals=tuple(resolved),
        unresolved=tuple(unresolved),
        at=at_iso or None,
        notes=tuple(notes),
    )


async def _query(tenant_id: str, principal: str, at_iso: str, token: str) -> dict[str, Any] | None:
    args: dict[str, Any] = {"principal_id": principal}
    if at_iso:
        args["at"] = at_iso
    url = f"{_API_URL.rstrip('/')}/api/v1/graph/investigate/query"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.post(
                url,
                json={"tool": "identity_effective_permissions", "args": args},
                headers={"Authorization": f"Bearer {token}", TENANT_HEADER: tenant_id},
            )
    except httpx.HTTPError as exc:
        logger.warning("triage_privilege.unreachable", error=str(exc)[:300])
        return None
    if response.status_code >= 400:
        logger.warning("triage_privilege.refused", status_code=response.status_code)
        return None
    try:
        payload = response.json()
    except ValueError:
        logger.warning("triage_privilege.bad_response")
        return None
    return payload if isinstance(payload, dict) else None


def render_for_prompt(state_value: Mapping[str, Any] | None) -> str:
    """The prompt block, including the "we could not answer" case.

    Unlike the directory block one module over, this one is **not** empty
    when the answer is unknown. The difference is deliberate and is about
    which silence a model would misread. An absent directory block means the
    tenant has no directory connector, and saying so would be noise. An
    absent privilege block, on an alert about a cloud principal, reads as
    "nothing notable about this account's access" — which is a claim nobody
    made.
    """
    value = state_value or {}
    principals = value.get("principals")
    principals = [p for p in principals if isinstance(p, Mapping)] if isinstance(principals, list) else []
    unresolved = [str(u) for u in (value.get("unresolved") or []) if u]
    if not principals and not unresolved:
        return ""

    lines = ["## What the actor could do at the time of this alert", ""]
    for row in principals:
        tier = str(row.get("privilege_tier") or "unknown")
        tags = row.get("tags_set") or []
        name = str(row.get("principal_id") or "unknown principal")
        provider = str(row.get("provider") or "")
        tag_text = f"; tagged {', '.join(str(t) for t in tags)}" if tags else ""
        lines.append(f"- {name} ({provider}): privilege {tier}{tag_text}")
        if row.get("snapshot_was_partial"):
            lines.append("  - the posture snapshot was incomplete, so the real reach may be larger")
        if row.get("usage_measured") is False:
            lines.append(
                "  - which of these permissions were actually exercised was NOT measured on this "
                "deployment; do not treat them as unused"
            )
    for name in unresolved:
        lines.append(
            f"- {name}: privilege UNKNOWN — no posture snapshot covers this moment. "
            f"This is a gap in collection, not evidence that the account is unprivileged."
        )
    return "\n".join(lines)


def basis(state_value: Mapping[str, Any] | None) -> list[str]:
    """Confidence-basis lines naming what the prompt was given.

    Every line is a sentence an auditor can check against a ``tool_call``
    row, which is the point: a basis entry with no matching recorded call is
    the ungrounded shape the grounding check demotes a verdict for.
    """
    value = state_value or {}
    principals = value.get("principals")
    principals = [p for p in principals if isinstance(p, Mapping)] if isinstance(principals, list) else []
    unresolved = [str(u) for u in (value.get("unresolved") or []) if u]
    if not principals and not unresolved:
        return []

    out: list[str] = []
    for row in principals:
        tier = str(row.get("privilege_tier") or "unknown")
        tags = ", ".join(str(t) for t in (row.get("tags_set") or [])) or "no tags"
        at = str(value.get("at") or "the alert time")
        out.append(
            f"Effective permissions (identity_effective_permissions) for "
            f"{row.get('principal_id')}: privilege {tier} at {at}; {tags}"
        )
    if unresolved:
        out.append(
            f"Effective permissions: UNKNOWN for {', '.join(unresolved)} — no posture snapshot "
            f"covers the alert time, so privilege did not inform this verdict"
        )
    for note in value.get("notes") or []:
        out.append(f"Effective permissions: {note}")
    return out

"""What is already known to be wrong with the resource this alert touched.

Depth-2 item 8.1.

A verdict about a cloud resource is a different verdict depending on the state
that resource was already in. An anonymous read of an S3 bucket that a CNAPP
flagged as publicly readable three weeks ago is not the same alert as the same
read against a bucket that was private until this morning, and triage has had
no way to tell them apart: the CNAPP connectors modelled everything they
pulled as alerts, and `posture_findings` -- the table that models exactly this
-- had no writer at all.

Why this is not the graph
-------------------------
`incident_context.py` already resolves an alert into five dimensions,
including assets, and it is the right place for this on paper. It is also
100% Neo4j, which is a `full`-profile service, so on a CORE install every one
of those dimensions answers "graph unavailable". A posture finding that only
reaches a verdict on `full` would be a capability most deployments do not
have, described as one they do.

So this reads Postgres through an internal API route, which is CORE, and
follows `context/identity.py` exactly -- the one path of this shape proven
live. Same token resolution order, same never-raises contract, same cache,
same `basis()` for the ledger.

Absent is not clean
-------------------
The response carries `collected`, and this module keeps the distinction all
the way to the prompt. A tenant with no CNAPP connected has no findings, and
rendering that as "no findings on this resource" tells the model the estate
was checked. When nothing has collected, the block is empty -- the same
decision `identity.py` makes, and for the same reason: a heading that says a
resource is clean is a claim, and a model will reasonably treat it as
exculpatory.

Containment
-----------
A rule title and a resource name come from the customer's own CNAPP, which
reads them from their cloud estate, where a resource name is attacker-
influenced in every provider. Sanitised and capped like organisation memory,
and the finding's free text never carries an instruction the model is asked
to follow.
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
    "MAX_FINDINGS_IN_PROMPT",
    "CloudPostureContext",
    "basis",
    "clear_cache",
    "enabled",
    "fetch_cloud_posture_context",
    "render_for_prompt",
    "resources_for",
]

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT_S = float(os.getenv("AISOC_TRIAGE_POSTURE_TIMEOUT_S", "5"))

#: An alert names one or two resources in practice. The cap exists because a
#: correlated alert can name many and the prompt budget belongs to the
#: evidence.
MAX_FINDINGS_IN_PROMPT = int(os.getenv("AISOC_TRIAGE_POSTURE_TOP_N", "5"))

_MAX_FIELD_CHARS = 120
_CACHE_TTL_S = float(os.getenv("AISOC_TRIAGE_POSTURE_TTL_S", "300"))

_cache: dict[str, tuple[float, dict[str, Any]]] = {}

#: Reading this tenant's own already-collected store is on by default, like
#: the directory-context read beside it. The thing that is off by default is
#: the *collection* -- every CNAPP context read is opt-in per connector
#: instance, because that is the half that reaches out to somebody's API.
_ENABLED_VAR = "AISOC_TRIAGE_POSTURE_ENABLED"


def enabled() -> bool:
    return os.getenv(_ENABLED_VAR, "1").strip().lower() not in {"0", "false", "no", "off"}


def clear_cache() -> None:
    """Drop cached posture lookups. Tests, and the collector path."""
    _cache.clear()


@dataclass(frozen=True)
class CloudPostureContext:
    """What one lookup returned, and what a replay has to publish about it."""

    findings: tuple[Mapping[str, Any], ...] = ()
    #: False means no CNAPP has ever collected for this tenant. It is the
    #: difference between "the resource is clean" and "nobody has looked", and
    #: it is the whole reason this field travels instead of just a count.
    collected: bool = False
    matched_resources: int = 0
    as_of: str | None = None
    excluded_after_cutoff: int = 0
    #: Zero, and that is the honest number. Unlike directory context, whose
    #: only stamp is an import time, a posture finding carries the vendor's
    #: own `first_detected_at` — when the estate became wrong — so every
    #: served row is demonstrably point-in-time and none of them is
    #: untestable. Published anyway so the report's three keys per store mean
    #: the same thing for every store.
    without_timestamp: int = 0

    def as_state(self) -> dict[str, Any]:
        return {
            "findings": [dict(f) for f in self.findings],
            "collected": self.collected,
            "matched_resources": self.matched_resources,
            "as_of": self.as_of,
            "excluded_after_cutoff": self.excluded_after_cutoff,
        }

    def __bool__(self) -> bool:
        return bool(self.findings)


def resources_for(raw_alert: Mapping[str, Any] | None) -> list[str]:
    """Every name the alert gives for the thing it is about.

    Resources and hosts only. A principal is resolved by the directory
    context, which is a different question with a different answer.

    Lowercased because the stored keys are, and matching is an array overlap
    rather than a comparison the database can case-fold.
    """
    raw = raw_alert or {}
    out: list[str] = []
    for key in ("cloud_resource", "resource_id", "hostname", "host", "device_name", "asset_id"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    for key in ("affected_hosts", "affected_resources"):
        values = raw.get(key)
        if isinstance(values, list):
            out.extend(v.strip() for v in values if isinstance(v, str) and v.strip())
    return sorted({v.lower() for v in out})[: MAX_FINDINGS_IN_PROMPT * 2]


async def fetch_cloud_posture_context(
    tenant_id: str | None,
    *,
    resources: Sequence[str],
    as_of: datetime | None = None,
    limit: int = MAX_FINDINGS_IN_PROMPT,
) -> CloudPostureContext:
    """Open cloud-security findings on these resources. Never raises.

    ``as_of`` has no default, for the same reason the other cutoff readers
    have none: a caller that may pass one is a caller that may forget to, so
    the protocol method above this does not take it and the two
    implementations each bind it explicitly.

    The freeze here is stronger than directory context's and the difference is
    worth stating: a posture finding carries the vendor's own
    ``first_detected_at``, which is when the estate became wrong, not when
    AiSOC imported anything. Refusing rows first detected after the split is
    therefore a real point-in-time cut rather than a partial one.
    """
    if not enabled() or not tenant_id:
        return CloudPostureContext()
    names = [r for r in resources if r]
    if not names:
        return CloudPostureContext()

    cache_key = f"{tenant_id}|{as_of.isoformat() if as_of else ''}|{limit}|{','.join(sorted(names))}"
    cached = _cache.get(cache_key)
    now = time.monotonic()
    if cached is not None and now - cached[0] < _CACHE_TTL_S:
        return _shape(cached[1], limit=limit)

    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        logger.warning(
            "triage_posture.no_service_token",
            reason="AISOC_AGENTS_SERVICE_TOKEN is unset, so cloud posture context cannot be read",
        )
        return CloudPostureContext()

    params: list[tuple[str, str]] = [("tenant_id", tenant_id), ("limit", str(limit))]
    params.extend(("resources", r) for r in names)
    if as_of is not None:
        params.append(("as_of", as_of.isoformat()))

    url = f"{_API_URL.rstrip('/')}/api/v1/posture/resource-findings"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.get(url, params=params, headers={"X-AiSOC-Service-Token": token})
    except httpx.HTTPError as exc:
        logger.warning("triage_posture.unreachable", error=str(exc)[:300])
        return CloudPostureContext()

    if response.status_code >= 400:
        logger.warning("triage_posture.refused", status_code=response.status_code)
        return CloudPostureContext()

    try:
        payload = response.json()
    except ValueError:
        logger.warning("triage_posture.bad_response")
        return CloudPostureContext()

    if not isinstance(payload, dict):
        return CloudPostureContext()
    _cache[cache_key] = (now, payload)
    return _shape(payload, limit=limit)


def _shape(payload: Mapping[str, Any], *, limit: int) -> CloudPostureContext:
    rows = payload.get("findings")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    echoed = payload.get("as_of")
    return CloudPostureContext(
        findings=tuple(dict(r) for r in rows[: max(1, limit)]),
        collected=bool(payload.get("collected")),
        matched_resources=int(payload.get("matched_resources") or 0),
        as_of=str(echoed) if echoed else None,
        excluded_after_cutoff=int(payload.get("excluded_after_cutoff") or 0),
    )


def _one_line(value: Any, *, limit: int = _MAX_FIELD_CHARS) -> str:
    """Sanitise, then flatten to a single line.

    `sanitize_text` deliberately keeps single newlines — it collapses blank
    lines and strips control characters, which is right for a runbook body
    where paragraph structure is the content. Every field here is one cell of
    a one-line list item, so a surviving newline lets injected text start its
    own line and read as a new section of the prompt rather than as part of a
    resource name. Caught by
    `test_a_resource_name_cannot_smuggle_an_instruction_into_the_prompt`,
    which failed against the first version of this renderer.
    """
    cleaned = sanitize_text(str(value or ""), max_len=limit)
    return " ".join(cleaned.split())


_CLASS_WORDS = {
    "misconfiguration": "misconfiguration",
    "secret": "exposed secret",
    "runtime_detection": "runtime detection",
    "issue": "issue",
}


def render_for_prompt(state_value: Mapping[str, Any] | None) -> str:
    """The prompt block, or ``""`` when there is nothing honest to say.

    Empty for an empty list whether or not anything collected. "No findings on
    this resource" from a tenant with no CNAPP is false, and from a tenant
    with one it is an exculpatory claim about a resource the scanner may
    simply not cover. Either way it is not worth the tokens.
    """
    rows = (state_value or {}).get("findings")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    if not rows:
        return ""

    lines: list[str] = []
    for row in rows:
        title = _one_line(row.get("rule_title"))
        if not title:
            continue
        kind = _CLASS_WORDS.get(str(row.get("finding_class") or ""), "finding")
        severity = _one_line(row.get("severity") or "unknown", limit=20)
        resource = _one_line(row.get("resource_name") or row.get("matched_key"))
        source = _one_line(row.get("source") or "a cloud security tool", limit=40)
        seen = _one_line(row.get("first_detected_at"), limit=40)
        bit = f"- {resource or 'this resource'}: {severity} {kind} — {title} (reported by {source}"
        if seen:
            bit += f", first seen {seen}"
        lines.append(bit + ")")

    if not lines:
        return ""

    return (
        "Cloud security findings already open on the resources this alert names, from this "
        "tenant's own connected cloud-security tool:\n"
        + "\n".join(lines)
        + "\nThese describe the state the resource was already in, not the activity in this alert. "
        "A standing misconfiguration makes the activity easier, so it is a reason to weigh the "
        "activity differently; it is never evidence that the activity happened, and never evidence "
        "that it was authorised. A resource with no finding listed here may simply not be covered "
        "by the scanner."
    )


def basis(state_value: Mapping[str, Any] | None) -> list[str]:
    """Confidence-basis lines naming what the prompt was given.

    Says "has collected nothing" explicitly when that is the case. An absent
    line reads to a reviewer as "there was no posture context", which is true
    of both a clean estate and an unconnected one, and the ledger is exactly
    where that distinction has to survive.
    """
    state = state_value or {}
    rows = state.get("findings")
    rows = [r for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []
    if not rows:
        if state.get("collected"):
            return ["Cloud posture in prompt: none open on this alert's resources (a CNAPP has collected for this tenant)"]
        return []
    severities = [str(r.get("severity") or "") for r in rows]
    serious = sum(1 for s in severities if s in {"critical", "high"})
    line = f"Cloud posture in prompt: {len(rows)} open finding(s) on this alert's resources"
    if serious:
        line += f", {serious} critical or high"
    return [line]

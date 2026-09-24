"""Ask the API to write this run's verdict back to the source finding.

The worker does not dispatch the action itself. The API service holds the
credential vault, the tenant-scoped database session and the actions-service
token, and it is the single governed path a response action takes — a second
executor here would mean two places that can change a customer's SIEM, two
audit trails, and two copies of the credential handling, of which one would go
stale.

So this module is deliberately thin: one authenticated POST, a structured log
line, and no exceptions. Everything about *what* may be written — which
dispositions close a finding, which escalate, which are refused — is decided
downstream, because a policy mirrored in two services is a policy that
disagrees with itself eventually.

Governance
----------
``AISOC_SIEM_WRITEBACK_ENABLED`` (default **on**) turns the call off here as
well as downstream, so an operator can stop the traffic at either end.
``AISOC_SIEM_WRITEBACK_EXECUTE`` is read by the API, not here: a worker that
could decide to execute would be a second opinion on the one question the
operator is supposed to own.

Fail-soft is a hard requirement. The verdict is already durable by the time
this runs; a Splunk outage must not undo it, and an exception escaping here
would re-drive the whole triage through the retry path and eventually
dead-letter an alert that was triaged perfectly well.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT_S = float(os.getenv("AISOC_SIEM_WRITEBACK_TIMEOUT_S", "20"))

#: Verdicts worth sending. The API refuses everything else anyway; this avoids
#: an HTTP round trip per undecided alert, which on a noisy tenant is most of
#: them. It is never wider than the downstream set.
_WORTH_SENDING: frozenset[str] = frozenset(
    {
        "true_positive",
        "false_positive",
        "benign",
        "benign_true_positive",
        "escalate",
    }
)


def writeback_enabled() -> bool:
    return os.getenv("AISOC_SIEM_WRITEBACK_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _service_token() -> str:
    """Shared secret for the internal route. Empty means "do not call"."""
    return os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip()


async def write_back_disposition(
    *,
    tenant_id: str,
    alert_id: str,
    disposition: str,
    confidence: float | None = None,
    rationale: str = "",
) -> dict[str, Any] | None:
    """Post the verdict to the API's writeback route.

    Returns the API's report, or ``None`` when nothing was attempted. Never
    raises.

    The report is returned rather than reduced to a boolean because the two
    states a caller must not confuse — "written" and "would have been written"
    — are both successes at the HTTP layer and are distinguished only by the
    ``executed`` field.
    """
    if not writeback_enabled():
        return None
    if not alert_id or not tenant_id:
        return None
    if disposition not in _WORTH_SENDING:
        return None

    token = _service_token()
    if not token:
        # A loud skip, not a silent one. Without the shared secret the API
        # refuses the service path by design, so this would be a guaranteed
        # 401 on every triaged alert — an operator needs to see why the loop
        # is not closing rather than find an empty audit trail.
        logger.warning(
            "siem_writeback.no_service_token",
            alert_id=alert_id,
            reason="AISOC_AGENTS_SERVICE_TOKEN is unset, so the API's service path is closed",
        )
        return None

    url = f"{_API_URL.rstrip('/')}/api/v1/alerts/{alert_id}/source-writeback"
    payload: dict[str, Any] = {
        "disposition": disposition,
        "rationale": rationale[:4000],
        "tenant_id": tenant_id,
    }
    if confidence is not None:
        payload["confidence"] = max(0.0, min(1.0, float(confidence)))

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.post(url, json=payload, headers={"X-AiSOC-Service-Token": token})
    except httpx.HTTPError as exc:
        logger.warning("siem_writeback.unreachable", alert_id=alert_id, error=str(exc)[:300])
        return None

    if response.status_code >= 400:
        logger.warning(
            "siem_writeback.refused",
            alert_id=alert_id,
            status_code=response.status_code,
        )
        return None

    try:
        report = response.json()
    except ValueError:
        logger.warning("siem_writeback.bad_response", alert_id=alert_id)
        return None
    if not isinstance(report, dict):
        return None

    logger.info(
        "siem_writeback.reported",
        alert_id=alert_id,
        disposition=disposition,
        mode=report.get("mode"),
        # Echoed verbatim: if this is False the loop did NOT close, whatever
        # the HTTP status said.
        executed=bool(report.get("executed")),
        outcomes=len(report.get("outcomes") or []),
    )
    return report

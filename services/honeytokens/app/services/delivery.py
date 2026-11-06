"""Where a honeytoken trip goes, and what happens when it cannot get there.

GHSA-9q6p-m345-h3hj (F57, F58).

Two defects, one module
-----------------------
**F57 — a trip had nowhere to go.** `send_alert` posted to
``HONEYTOKEN_ALERT_WEBHOOK_URL``, which has no default, and returned ``False``
after an ``info`` log when it was unset. There is no receiver route anywhere
in the API, so on the shipped layout the single highest-confidence intrusion
signal this platform can produce reached nobody, and said so at a level
nothing watches.

The fix is a default destination rather than a new receiver: a trip is pushed
into the **ingest spine**, exactly the way a connector pushes a vendor
finding, so it becomes an alert through the path every other signal already
takes — dedup, fusion, correlation, auto-triage — instead of through a second
alert-creation path that would have to reimplement all of it. An operator who
has configured a webhook keeps getting the webhook; the ingest push is what
happens when they have not, which is the case the advisory is about.

**F58 — a trip lost to a transient outage was never retried.** Delivery was
attempted inline, once, and a failure set ``alert_sent = False`` on the
trigger row and was never looked at again. A receiver that was restarting
meant the signal was simply gone.

Delivery is now journalled **before the trip is acknowledged** and drained by
an awaited path, which is this repository's standing shape for exactly this
problem (`fusion_alert_outbox`, migration 121). The HTTP attempt happens
after the row is durable, so the worst case is a duplicate delivery rather
than a lost one — and the receiver can deduplicate on ``trigger_id``, which
every payload carries.

Permanent and transient are really distinguished
------------------------------------------------
A bare retry loop would be the wrong fix: it turns a misconfiguration into
churn and never tells the operator. So the classification is explicit, and
the three outcomes are acted on differently:

* **transient** — a timeout, a connection error, 408, 429 or any 5xx. The
  receiver may come back, so the row is left claimable with an exponential
  backoff and a bounded attempt ceiling.
* **permanent** — any other 4xx. A 401 means the token is wrong and a 404
  means the URL is wrong; retrying either for a day produces load and no
  alert. The row goes to ``dead`` with the reason recorded, which is a state
  an operator can query rather than a log line that scrolled away.
* **no destination** — neither a webhook nor an ingest URL resolves. Recorded
  as ``dead`` with that reason rather than retried, because nothing will
  change without an operator.

A row that exhausts its attempts also goes ``dead`` rather than being retried
forever. In every terminal case the reason is on the row.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import httpx

from app.core.config import settings
from app.security.tenant_scope import resolve_service_token

LOG = logging.getLogger(__name__)

#: The connector type the ingest normalizer keys its profile on. It must match
#: the entry in `services/ingest/internal/normalizer/normalizer.go`, or the
#: event falls through to the lenient fallback profile, is filed as category 4
#: Network Activity, and `should_promote()` never turns it into an alert — it
#: would be archived to the lake and silently never reach the queue, which is
#: the same invisible outcome this advisory is about, one layer down.
CONNECTOR_TYPE = "honeytoken"

#: Stable per-deployment identity for the pushes this service makes. A
#: honeytoken is not a polled connector instance, but the ingest contract
#: wants a connector id, and a fixed one keeps every trip attributable to the
#: same source rather than inventing a new identity per trip.
CONNECTOR_ID = uuid.UUID("00000000-0000-0000-0000-000000686f6e")

#: Attempts before a row is declared dead. Six attempts under the backoff
#: below spans roughly half an hour, which covers a receiver restart or a
#: rolling deploy without retrying a genuine misconfiguration indefinitely.
MAX_ATTEMPTS = 6

#: Seconds to wait before attempt N (1-indexed), capped.
_BACKOFF_SECONDS = (30, 60, 120, 300, 600, 900)


def backoff_seconds(attempts: int) -> int:
    """How long to wait before the next attempt, given attempts made so far."""
    if attempts < 1:
        return _BACKOFF_SECONDS[0]
    return _BACKOFF_SECONDS[min(attempts, len(_BACKOFF_SECONDS)) - 1]


class Disposition(str, Enum):
    """What the delivery attempt established."""

    DELIVERED = "delivered"
    #: The receiver may recover — keep the row and try again.
    RETRY = "retry"
    #: Nothing will change without an operator — stop, and say why.
    DEAD = "dead"


@dataclass(frozen=True)
class DeliveryResult:
    disposition: Disposition
    detail: str

    @property
    def delivered(self) -> bool:
        return self.disposition is Disposition.DELIVERED


def _sign_payload(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 hex digest for webhook payload verification."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def ingest_url() -> str:
    """The ingest service, same default and variable the connectors use."""
    return os.getenv("INGEST_SERVICE_URL", "http://ingest-worker:8080").strip().rstrip("/")


def trip_payload(
    *,
    honeytoken_id: uuid.UUID,
    tenant_id: uuid.UUID,
    token_type: str,
    token_name: str,
    trigger_id: uuid.UUID,
    source_ip: str | None,
    triggered_at: datetime,
) -> dict[str, Any]:
    """The canonical description of one trip.

    One shape for both destinations so a deployment that switches from the
    webhook to the spine does not silently start reporting different fields.
    """
    return {
        "event": "honeytoken.triggered",
        "honeytoken_id": str(honeytoken_id),
        "tenant_id": str(tenant_id),
        "token_type": token_type,
        "token_name": token_name,
        "trigger_id": str(trigger_id),
        "source_ip": source_ip,
        "triggered_at": triggered_at.isoformat(),
    }


def _classify_status(status_code: int) -> Disposition:
    """Whether re-sending this request could plausibly succeed.

    408 and 429 are 4xx that explicitly mean "try again"; every other 4xx is
    the sender's fault and will keep being the sender's fault.
    """
    if 200 <= status_code < 300:
        return Disposition.DELIVERED
    if status_code in (408, 429) or status_code >= 500:
        return Disposition.RETRY
    return Disposition.DEAD


async def _deliver_webhook(payload: dict[str, Any], *, client: httpx.AsyncClient) -> DeliveryResult:
    if not settings.alert_webhook_secret:
        # Pre-existing and deliberate: an unsigned alert cannot be told apart
        # from one a third party forged. Permanent, because no number of
        # retries produces a secret.
        return DeliveryResult(
            Disposition.DEAD,
            "alert_webhook_url is set but HONEYTOKEN_ALERT_WEBHOOK_SECRET is empty; refusing to send an unsigned alert",
        )

    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "X-AiSOC-Signature": f"sha256={_sign_payload(body, settings.alert_webhook_secret)}",
        "X-AiSOC-Event": "honeytoken.triggered",
    }
    resp = await client.post(settings.alert_webhook_url, content=body, headers=headers)
    disposition = _classify_status(resp.status_code)
    return DeliveryResult(disposition, f"webhook responded {resp.status_code}")


async def _deliver_ingest(payload: dict[str, Any], *, client: httpx.AsyncClient) -> DeliveryResult:
    """Push the trip down the spine, the way a connector pushes a finding."""
    base = ingest_url()
    if not base:
        return DeliveryResult(Disposition.DEAD, "no INGEST_SERVICE_URL and no alert_webhook_url; nowhere to deliver")

    token = resolve_service_token()
    if not token:
        # The ingest endpoint refuses an uncredentialed push with 401, and a
        # 401 from our own service reads to an operator as the receiver
        # rejecting us. Naming the missing variable is the whole value here.
        return DeliveryResult(
            Disposition.DEAD,
            "no AISOC_SERVICE_TOKEN (or AISOC_HONEYTOKENS_SERVICE_TOKEN) is set, so the ingest push would be refused 401",
        )

    headers = {
        "Content-Type": "application/json",
        "X-Tenant-ID": payload["tenant_id"],
        "Authorization": f"Bearer {token}",
    }
    envelope = {
        "connector_id": str(CONNECTOR_ID),
        "connector_type": CONNECTOR_TYPE,
        "source_format": "json",
        "events": [payload],
    }
    resp = await client.post(f"{base}/v1/ingest/batch", headers=headers, json=envelope)
    disposition = _classify_status(resp.status_code)
    return DeliveryResult(disposition, f"ingest responded {resp.status_code}")


async def deliver(payload: dict[str, Any], *, timeout: float = 10.0) -> DeliveryResult:
    """Deliver one trip to whichever destination this deployment has.

    The webhook wins when configured, so an existing deployment keeps the
    behaviour it has. The ingest spine is the default, which is what makes a
    trip produce an alert with no operator configuration at all.

    Never raises: every failure becomes a classified result, because the
    caller's job is to record the outcome rather than to decide what a
    `ReadTimeout` means.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if settings.alert_webhook_url:
                return await _deliver_webhook(payload, client=client)
            return await _deliver_ingest(payload, client=client)
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        # The receiver may be restarting. This is the case F58 is about.
        return DeliveryResult(Disposition.RETRY, f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 — a delivery must never take the request with it
        LOG.exception("honeytoken delivery raised")
        return DeliveryResult(Disposition.RETRY, f"{type(exc).__name__}: {exc}")


def now() -> datetime:
    return datetime.now(UTC)

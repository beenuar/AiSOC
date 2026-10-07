"""Tell somebody else's system that something happened here, provably.

AiSOC could be told things — ``POST /v1/inbox/{token}``, the ITSM webhook —
and could tell nobody anything. There was no outbound event webhook in the
tree at all, so a tenant who wanted an alert in their own system had to
poll.

The signature
-------------
``X-AiSOC-Signature: t=<unix>,v1=<hex>`` over ``"<t>.<raw body>"`` with
HMAC-SHA256 and the destination's shared secret. Deliberately the shape
Stripe, GitHub and Slack use, because the verifying code on the receiving
side is one the customer's team has written before — and a scheme nobody
recognises is a scheme nobody verifies.

Two properties the timestamp buys, and the reason each matters:

* it is **inside** the signed material, so an attacker cannot replay a
  captured body with a fresh timestamp;
* a receiver can bound how old a message it will accept, which is the only
  defence against a replay of a genuinely signed body.

Retries
-------
Exponential, capped, and bounded by an attempt count rather than a
deadline. A 5xx or a connection failure is transient and earns another
attempt; a 4xx other than 408/425/429 means the receiver understood and
refused, and asking again gets the same answer — so it is dead immediately
rather than after six identical refusals.

Dead letters are visible
------------------------
A delivery that exhausts its attempts becomes ``dead`` in the same table,
which ``GET /outbound-webhooks/dead-letters`` reads. A retry queue nobody
can see is indistinguishable from one that is empty, and the failure mode
of a silent one is a tenant who believes their SIEM has every alert.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.outbound_webhook import OutboundDelivery, OutboundWebhook
from app.security.credential_vault import CredentialVaultError, get_vault

logger = structlog.get_logger(__name__)

#: How many times a transient failure is retried before the delivery dies.
#: Six attempts over the ladder below spans a little under an hour, which
#: covers a receiver's deploy without holding a row for a day.
MAX_ATTEMPTS = 6

#: Backoff in seconds, indexed by attempt number. A list rather than a
#: formula so the ladder is readable and a test can assert it exactly.
_BACKOFF_SECONDS = (30, 120, 300, 900, 1800)

_TIMEOUT_SECONDS = 10.0
_SIGNATURE_HEADER = "X-AiSOC-Signature"
_EVENT_HEADER = "X-AiSOC-Event"
_DELIVERY_HEADER = "X-AiSOC-Delivery"

#: Statuses in the 4xx range that ask to be retried. Everything else there
#: means the receiver understood and refused.
_RETRYABLE_CLIENT_STATUSES = frozenset({408, 425, 429})


def sign(body: bytes, *, secret: str, timestamp: int | None = None) -> str:
    """The value of ``X-AiSOC-Signature`` for this body.

    The timestamp is signed with the body rather than beside it: a header a
    receiver reads but does not verify is a header an attacker can rewrite,
    which would turn the replay window into no window at all.
    """
    ts = int(timestamp if timestamp is not None else time.time())
    digest = hmac.new(secret.encode("utf-8"), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}"


def verify(body: bytes, header: str, *, secret: str, tolerance_seconds: int = 300, now: float | None = None) -> bool:
    """Whether ``header`` is this deployment's signature over ``body``.

    Shipped beside the signer, and exercised by the tests, because a signer
    with no verifier is a format nobody has ever checked round-trips — and
    the first person to find out would be a customer writing the other half
    against prose.
    """
    parts = dict(piece.split("=", 1) for piece in header.split(",") if "=" in piece)
    try:
        ts = int(parts.get("t", ""))
    except ValueError:
        return False
    supplied = parts.get("v1", "")
    if not supplied:
        return False
    if abs((now if now is not None else time.time()) - ts) > tolerance_seconds:
        return False
    expected = hmac.new(secret.encode("utf-8"), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def _secret_for(webhook: OutboundWebhook) -> str:
    if not webhook.secret:
        return ""
    try:
        return str(get_vault().decrypt_dict({"secret": webhook.secret}).get("secret") or "")
    except CredentialVaultError as exc:
        # Reported, never treated as "no secret". Sending unsigned because
        # a key would not decrypt is the shape where a receiver that checks
        # signatures starts rejecting everything and nobody knows why.
        raise ValueError(f"the signing secret for webhook {webhook.name!r} could not be decrypted: {exc}") from exc


def _next_attempt(attempts: int) -> datetime | None:
    """When to try again, or ``None`` once the ladder is exhausted."""
    if attempts >= MAX_ATTEMPTS:
        return None
    index = min(attempts - 1, len(_BACKOFF_SECONDS) - 1)
    return datetime.now(UTC) + timedelta(seconds=_BACKOFF_SECONDS[max(index, 0)])


async def enqueue_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    event_type: str,
    payload: dict[str, Any],
) -> list[OutboundDelivery]:
    """Queue one event for every enabled destination subscribed to it.

    Queued rather than sent inline. The caller is usually a request handler
    or a fusion worker, and holding either open for a receiver's timeout
    would make somebody else's availability ours.
    """
    rows = (
        (await db.execute(select(OutboundWebhook).where(OutboundWebhook.tenant_id == tenant_id).where(OutboundWebhook.enabled.is_(True))))
        .scalars()
        .all()
    )
    queued: list[OutboundDelivery] = []
    for webhook in rows:
        # An empty subscription list means every event: a destination
        # somebody created and subscribed to nothing is far more likely to
        # be "I want everything" than "I want silence".
        if webhook.event_types and event_type not in webhook.event_types:
            continue
        delivery = OutboundDelivery(
            tenant_id=tenant_id,
            webhook_id=webhook.id,
            event_type=event_type,
            payload=payload,
            status="pending",
            next_attempt_at=datetime.now(UTC),
        )
        db.add(delivery)
        queued.append(delivery)
    return queued


def _body(delivery: OutboundDelivery) -> bytes:
    """The exact bytes signed and sent, built once per delivery.

    ``sort_keys`` and a fixed separator so a retry produces byte-identical
    output — the signature covers the body, so a dict that serialised in a
    different order would be a differently-signed message claiming to be
    the same event.
    """
    envelope = {
        "id": str(delivery.id),
        "type": delivery.event_type,
        "created_at": delivery.created_at.isoformat() if delivery.created_at else datetime.now(UTC).isoformat(),
        "data": delivery.payload or {},
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


async def attempt_delivery(
    delivery: OutboundDelivery,
    webhook: OutboundWebhook,
    *,
    client: httpx.AsyncClient | None = None,
) -> OutboundDelivery:
    """One attempt. Mutates and returns the delivery; never raises."""
    delivery.attempts += 1
    try:
        secret = _secret_for(webhook)
    except ValueError as exc:
        delivery.status = "dead"
        delivery.next_attempt_at = None
        delivery.last_error = str(exc)[:500]
        return delivery

    body = _body(delivery)
    headers = {
        "Content-Type": "application/json",
        _EVENT_HEADER: delivery.event_type,
        _DELIVERY_HEADER: str(delivery.id),
    }
    if secret:
        headers[_SIGNATURE_HEADER] = sign(body, secret=secret)

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=_TIMEOUT_SECONDS)
    try:
        response = await client.post(webhook.url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        delivery.last_error = f"the receiver could not be reached: {exc}"[:500]
        delivery.next_attempt_at = _next_attempt(delivery.attempts)
        delivery.status = "pending" if delivery.next_attempt_at else "dead"
        return delivery
    finally:
        if owns_client:
            await client.aclose()

    delivery.last_status_code = response.status_code
    if 200 <= response.status_code < 300:
        delivery.status = "delivered"
        delivery.delivered_at = datetime.now(UTC)
        delivery.next_attempt_at = None
        delivery.last_error = ""
        return delivery

    delivery.last_error = f"HTTP {response.status_code}: {response.text[:200]}"
    retryable = response.status_code >= 500 or response.status_code in _RETRYABLE_CLIENT_STATUSES
    if not retryable:
        # Understood and refused. Six identical refusals would be six
        # identical answers, and the operator reading the dead-letter view
        # needs the first one, not the sixth.
        delivery.status = "dead"
        delivery.next_attempt_at = None
        return delivery

    delivery.next_attempt_at = _next_attempt(delivery.attempts)
    delivery.status = "pending" if delivery.next_attempt_at else "dead"
    return delivery


async def due_deliveries(db: AsyncSession, *, limit: int = 50) -> list[tuple[OutboundDelivery, OutboundWebhook]]:
    """Pending deliveries whose next attempt has come due, with their target.

    Cross-tenant by construction, the same shape as every other sweeper
    here: a per-tenant pass needs a list of tenants, and a tenant missing
    from it has events that are never sent and a queue that looks healthy.
    """
    rows = (
        (
            await db.execute(
                select(OutboundDelivery, OutboundWebhook)
                .join(OutboundWebhook, OutboundWebhook.id == OutboundDelivery.webhook_id)
                .where(OutboundDelivery.status == "pending")
                .where(OutboundDelivery.next_attempt_at.isnot(None))
                .where(OutboundDelivery.next_attempt_at <= datetime.now(UTC))
                .order_by(OutboundDelivery.next_attempt_at)
                .limit(limit)
            )
        )
        .tuples()
        .all()
    )
    return [(delivery, webhook) for delivery, webhook in rows]

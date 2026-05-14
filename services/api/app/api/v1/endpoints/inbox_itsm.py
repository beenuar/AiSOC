"""Inbound ITSM webhook receiver — Workstream 8 (bidirectional ITSM).

Public-facing counterpart to the *outbound* fan-out implemented in
``app.services.case_fanout``. The flow it closes is:

1. AiSOC case is created or its status changes →
2. ``case_fanout`` POSTs to ``services/connectors`` →
3. Connector creates / updates a Jira issue or ServiceNow incident →
4. Operator works the ticket *in their existing ITSM*, eventually
   transitioning it to "In Progress" / "Done" / "Resolved" / "Closed".
5. Their ITSM fires a webhook at THIS endpoint →
6. We resolve the inbound ticket back to its AiSOC case via
   ``case_external_refs`` and mirror the status onto ``aisoc_cases``.

This is what makes ITSM "the source of truth" — operators never have
to log into AiSOC to change a ticket status; the ITSM they already
live in keeps AiSOC in sync.

Why this lives in a separate module from ``inbox.py``
-----------------------------------------------------
``inbox.py`` is the *operator-facing* management API for tenant inbox
tokens (mint, list, rotate, revoke). Every route there requires an
authenticated user with ``connectors:read`` / ``connectors:write``
permission, because rotating a token is a privileged operation.

This module is the *public webhook receiver*. Authentication is via the
**inbox token in the URL path**, not via a session cookie or bearer.
The two have totally different threat models and audit footprints, so
they live in separate routers (sharing only the ``/inbox`` URL prefix
to keep operator mental models simple).

Auth model
----------
The URL is ``/api/v1/inbox/itsm/{tenant_token}/{connector_instance_id}``,
where:

* ``tenant_token`` is a row from ``tenant_inbox_tokens`` (template_id
  must be ``itsm-inbound``). Resolves to a ``tenant_id``.
* ``connector_instance_id`` is the UUID of a row in ``connectors`` —
  the specific Jira project / ServiceNow instance whose webhooks are
  hitting us. We cross-check that the connector's ``tenant_id`` matches
  the token's ``tenant_id`` so a leaked token from tenant A can't be
  paired with a connector from tenant B.

Optional second factor: if the operator set ``hmac_secret`` on the
inbox token, we verify ``X-AiSOC-Signature: sha256=<hex>`` against
``HMAC(secret, raw_body)`` and reject mismatches.

Idempotency
-----------
Vendor webhooks retry aggressively (Jira up to 5×, ServiceNow until
the destination 200s). Every code path here is structured so that
re-delivering the same payload is a no-op — we look up the case by
``(connector_instance_id, external_id)``, compare the inbound status
to the current AiSOC status, and only write when they actually differ.
A redelivered "Done" event after we've already closed the case bumps
``case_external_refs.last_synced_at`` and nothing else.

What we explicitly do NOT do
----------------------------
* We do not let the ITSM transition the AiSOC case into states that
  don't exist in our enum (``new``, ``triaged``, ``investigating``,
  ``contained``, ``resolved``, ``closed``). Anything we can't map
  cleanly is treated as "no status change" and the case stays put —
  but we still bump ``last_synced_at`` so the operator knows the
  webhook is alive.
* We do not delete cases when an ITSM ticket is deleted. That's
  destructive and irreversible; the operator must close the case
  through AiSOC's own UI.
* We do not honour assignment / priority changes. They're trivially
  reversible if we ever want them later, but for now ITSM is only the
  source of truth for *status*. Comments, custom fields, etc. are
  one-way (AiSOC → ITSM only).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text

from app.api.v1.deps import DBSession
from app.core.logging import safe_log_value

logger = logging.getLogger(__name__)

# Same prefix as ``inbox.py`` (operator-facing) so the public URL is
# /api/v1/inbox/itsm/.... The two modules share the prefix but not the
# auth / permission stack — see module docstring.
router = APIRouter(prefix="/inbox", tags=["inbox-itsm"])


# ---------------------------------------------------------------------------
# Status reverse maps. Inbound (vendor → AiSOC) is intentionally lossy and
# canonicalising — multiple vendor states collapse onto a single AiSOC state.
# We keep the maps narrow on purpose:
#
#   * Lower-case the vendor token before lookup, so "DONE", "Done", and
#     "done" all hit the same row.
#   * Anything we don't recognise returns None and the caller treats that
#     as "no status change" (still bump last_synced_at so operators see the
#     ping landed).
#
# These mirror the *forward* maps in
# ``services/connectors/app/connectors/jira_connector.py`` and
# ``services/connectors/app/connectors/servicenow.py`` — kept as a
# duplicate intentionally because:
#
#   * Forward maps are owned by the connectors microservice (Python AND
#     potentially Go ports later); inbound maps are owned by the API
#     service. Sharing a constant module across the network boundary
#     would couple deploy lifecycles unnecessarily.
#   * The directions are not symmetric (forward has finer granularity
#     than reverse), so keeping them separate makes each half readable.
# ---------------------------------------------------------------------------

_JIRA_INBOUND_STATUS: dict[str, str] = {
    # Standard Jira status names. We match against ``status.name`` from the
    # webhook payload, lower-cased.
    "to do": "triaged",
    "open": "triaged",
    "backlog": "triaged",
    "selected for development": "triaged",
    "in progress": "investigating",
    "in review": "investigating",
    "blocked": "contained",
    "on hold": "contained",
    "resolved": "resolved",
    "done": "resolved",
    "closed": "closed",
    "cancelled": "closed",
    "canceled": "closed",
    "won't fix": "closed",
    "wont fix": "closed",
    "won't do": "closed",
}


_SNOW_INBOUND_STATUS: dict[str, str] = {
    # ServiceNow ``state`` is numeric. Mapping from sys_choice list values
    # for the ``incident`` table:
    #   1 = New, 2 = In Progress, 3 = On Hold, 6 = Resolved, 7 = Closed,
    #   8 = Cancelled.
    "1": "triaged",
    "2": "investigating",
    "3": "contained",
    "6": "resolved",
    "7": "closed",
    "8": "closed",
}


# Connector types we accept inbound webhooks from. Anything else 422s — we
# don't want a misconfigured connector pointing the wrong vendor's webhook
# at this URL and silently dropping events.
_SUPPORTED_VENDORS: frozenset[str] = frozenset({"jira", "servicenow"})


# Inbox tokens used for ITSM inbound MUST carry this template_id. Operator
# UI mints tokens with this template specifically so an inbox token minted
# for, say, PagerDuty alert ingest can't accidentally be repurposed as an
# ITSM webhook receiver (which would be tenant-scoped but could trigger
# unwanted status changes on cases).
_ITSM_TEMPLATE_ID = "itsm-inbound"


# ---------------------------------------------------------------------------
# Lightweight wire schemas — we don't strictly validate the full vendor
# payload because Jira and ServiceNow both expose long-tail custom fields
# and rejecting unknown keys would brick operator workflows. We only pull
# the handful of fields we actually act on.
# ---------------------------------------------------------------------------


class InboundResult(BaseModel):
    """Response body for the inbound webhook."""

    case_id: uuid.UUID | None
    """AiSOC case the inbound event mapped to. ``None`` means the external
    ID wasn't found — the webhook is acknowledged with 200 anyway, because
    Jira/ServiceNow will retry forever on non-2xx and we don't want one
    stale ticket to block the queue."""

    case_number: str | None
    """Operator-friendly handle (e.g. ``CASE-1023``). None when ``case_id``
    is None or the underlying ``aisoc_cases`` row predates case_number."""

    external_id: str | None
    """The vendor handle we extracted from the payload (Jira issue key,
    ServiceNow sys_id). None means we couldn't find one — the payload is
    malformed and we logged the parse failure."""

    old_status: str | None
    """AiSOC status before this webhook. None when ``case_id`` is None."""

    new_status: str | None
    """AiSOC status after applying the inbound transition. Equal to
    ``old_status`` when the inbound vendor state didn't map to anything
    actionable, or when the case was already in the target state."""

    status_changed: bool
    """True iff we wrote a new status onto ``aisoc_cases``."""

    note: str | None = None
    """Human-readable explanation when nothing happened (unknown external_id,
    unmapped status, etc.). Useful in webhook delivery logs."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify_hmac(
    *,
    secret: str | None,
    raw_body: bytes,
    signature_header: str | None,
) -> None:
    """Reject the request if the inbox token has an HMAC secret and the
    inbound signature header doesn't match.

    Accepts both ``sha256=<hex>`` (GitHub-style) and bare ``<hex>`` because
    Jira and ServiceNow's webhook implementations differ. ``hmac.compare_digest``
    is constant-time.

    No-op when ``secret`` is None — the inbox token in the URL is the only
    authenticator in that case, which is the correct trust model when the
    vendor doesn't support HMAC signatures (older ServiceNow installs,
    bespoke webhook proxies, etc.).
    """
    if secret is None:
        return

    if signature_header is None or not signature_header.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="HMAC signature required for this inbox token",
        )

    sig = signature_header.strip()
    if sig.lower().startswith("sha256="):
        sig = sig.split("=", 1)[1].strip()

    expected = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(sig.lower(), expected.lower()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HMAC signature",
        )


def _parse_jira_payload(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    """Pull ``issue.key`` + ``issue.fields.status.name`` from a Jira webhook.

    Jira posts the full issue under ``issue`` for both ``jira:issue_created``
    and ``jira:issue_updated`` events. We only act on transitions, so we
    don't bother distinguishing the two — if there's a status to set, set it.

    Returns ``(external_id, status_name)``. Either or both may be None when
    the payload is malformed; the caller treats that as a no-op.
    """
    issue = payload.get("issue") or {}
    if not isinstance(issue, dict):
        return None, None

    key = issue.get("key")
    if not isinstance(key, str) or not key:
        return None, None

    fields = issue.get("fields") or {}
    if not isinstance(fields, dict):
        return key, None

    status_obj = fields.get("status") or {}
    if not isinstance(status_obj, dict):
        return key, None

    name = status_obj.get("name")
    if not isinstance(name, str):
        return key, None

    return key, name


def _parse_servicenow_payload(
    payload: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Pull ``sys_id`` + ``state`` from a ServiceNow business rule webhook.

    ServiceNow's webhook payloads are operator-configured via a business
    rule, but the canonical shape is a JSON object whose top-level keys
    are the column names of the ``incident`` table — same shape as the
    REST Table API GET response. We accept both that shape and a thin
    wrapper of ``{"current": {...}}`` (the form used when the operator
    forwards the BR's ``current`` GlideRecord directly).

    State is normalised to a string so the lookup against
    ``_SNOW_INBOUND_STATUS`` works for both ``"6"`` and ``6``.
    """
    record = payload.get("current") if "current" in payload else payload
    if not isinstance(record, dict):
        return None, None

    sys_id = record.get("sys_id")
    if not isinstance(sys_id, str) or not sys_id:
        # ServiceNow always populates sys_id; if it's missing the payload
        # is from a BR that didn't include it and we can't correlate.
        return None, None

    state = record.get("state")
    if state is None:
        return sys_id, None

    return sys_id, str(state)


def _map_inbound_status(vendor: str, raw_status: str | None) -> str | None:
    """Look up the AiSOC equivalent of a vendor status, or None.

    Returns None for both "vendor returned no status" and "we don't know
    how to map it" — they're the same outcome from the caller's point of
    view (don't change the AiSOC status).
    """
    if raw_status is None:
        return None
    if vendor == "jira":
        return _JIRA_INBOUND_STATUS.get(raw_status.strip().lower())
    if vendor == "servicenow":
        return _SNOW_INBOUND_STATUS.get(raw_status.strip())
    return None


async def _fetch_token_and_connector(
    db: Any,
    *,
    tenant_token: str,
    connector_instance_id: uuid.UUID,
) -> tuple[Any, Any]:
    """Resolve the inbox token and connector instance, verifying tenant match.

    Returns ``(inbox_token_row, connector_row)``. Raises 401/404 on missing
    or mismatched rows so the caller can stay focused on payload handling.

    The two lookups are deliberately separate queries (instead of a single
    JOIN) because:

    * They have different cache profiles — the token row is read on every
      webhook delivery, the connector row changes when the operator edits
      auth_config / the OAuth refresh worker runs.
    * 401 vs 404 carries different signal: a missing token is "this URL
      was revoked or never existed", a missing connector is "the operator
      detached this integration but forgot to update the vendor webhook".
      Distinguishing them helps webhook delivery debugging.
    """
    # 1. Resolve the token. We require revoked_at IS NULL — once an
    # operator rotates the token, the old one MUST stop accepting traffic.
    token_row = (
        await db.execute(
            text(
                """
                SELECT token, tenant_id, template_id, hmac_secret, revoked_at
                FROM tenant_inbox_tokens
                WHERE token = :token AND revoked_at IS NULL
                """
            ).bindparams(token=tenant_token)
        )
    ).fetchone()
    if token_row is None:
        # Don't echo the token in the error — even the trailing 8 chars
        # would help an attacker confirm a guess. The structlog event
        # carries the fingerprint for ops debugging.
        logger.info(
            "inbox_itsm.token_not_found",
            extra={"token_fingerprint": safe_log_value(f"...{tenant_token[-8:]}")},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked inbox token",
        )

    if token_row.template_id != _ITSM_TEMPLATE_ID:
        # An operator paired a vendor's ITSM webhook with an inbox token
        # minted for a different purpose (e.g. PagerDuty alert ingest).
        # We refuse to act on it — let the wizard mint a fresh ITSM token.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=("Inbox token is not valid for ITSM webhooks. Mint a token with template_id='itsm-inbound'."),
        )

    # 2. Resolve the connector. tenant_id check below prevents using a
    # token from one tenant against a connector from another.
    connector_row = (
        await db.execute(
            text(
                """
                SELECT id, tenant_id, connector_type, is_enabled
                FROM connectors
                WHERE id = :id
                """
            ).bindparams(id=connector_instance_id)
        )
    ).fetchone()
    if connector_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector instance not found",
        )

    if connector_row.tenant_id != token_row.tenant_id:
        # Cross-tenant attempt — log loudly so the SOC can investigate.
        logger.warning(
            "inbox_itsm.cross_tenant_attempt",
            extra={
                "token_tenant_id": safe_log_value(token_row.tenant_id),
                "connector_tenant_id": safe_log_value(connector_row.tenant_id),
                "connector_id": safe_log_value(connector_instance_id),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token and connector belong to different tenants",
        )

    if not connector_row.is_enabled:
        # A disabled connector should not be receiving traffic. Prefer 409
        # over 200 here so the vendor's webhook delivery dashboard surfaces
        # the issue instead of silently consuming the events.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connector instance is disabled",
        )

    if connector_row.connector_type not in _SUPPORTED_VENDORS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"connector_type '{connector_row.connector_type}' is not "
                "supported on the inbound ITSM webhook. "
                f"Supported: {', '.join(sorted(_SUPPORTED_VENDORS))}."
            ),
        )

    return token_row, connector_row


async def _apply_status_to_case(
    db: Any,
    *,
    case_row: Any,
    new_status: str,
    actor_label: str,
    external_id: str,
    vendor: str,
) -> None:
    """Mirror an inbound status onto ``aisoc_cases`` + write a system note.

    Three writes in one transaction (the caller commits):

    1. ``aisoc_cases``: status, updated_at, plus the timeline columns
       (``triaged_at`` / ``resolved_at`` / ``closed_at``) the appropriate
       transition implies. Mirrors the logic in
       ``cases.update_case`` so AiSOC's own audit math stays consistent.
    2. ``case_external_refs``: ``external_status`` + ``last_synced_at``.
       This is what makes the *next* outbound ``push_status_change`` a
       no-op — the connector compares ``external_status`` to the desired
       state and short-circuits when they already match.
    3. ``aisoc_case_comments``: a system note ("ServiceNow set state to
       Resolved → AiSOC case marked resolved") so the timeline view shows
       the inbound transition with its provenance.

    The caller has already verified ``new_status`` is in the allowed set,
    so we don't re-validate here.
    """
    now = datetime.now(UTC)

    # Map status → which timeline column to bump. We never *clear* a column
    # — once a case has been triaged, the timestamp stays even if it later
    # moves back to "new" (which the inbound flow can't actually do
    # anyway, but defending in depth is cheap). COALESCE keeps the first
    # transition's timestamp.
    triaged_at_set = (
        ", triaged_at = COALESCE(triaged_at, :now)" if new_status in {"triaged", "investigating", "contained", "resolved", "closed"} else ""
    )
    resolved_at_set = ", resolved_at = COALESCE(resolved_at, :now)" if new_status == "resolved" else ""
    closed_at_set = ", closed_at = COALESCE(closed_at, :now)" if new_status == "closed" else ""

    await db.execute(
        text(
            f"""
            UPDATE aisoc_cases
            SET status = :status,
                updated_at = :now
                {triaged_at_set}
                {resolved_at_set}
                {closed_at_set}
            WHERE id = :id
            """
        ).bindparams(status=new_status, now=now, id=case_row.id)
    )

    await db.execute(
        text(
            """
            UPDATE case_external_refs
            SET external_status = :ext_status,
                last_synced_at = :now,
                updated_at = :now
            WHERE case_id = :case_id AND external_id = :external_id
            """
        ).bindparams(
            ext_status=new_status,
            now=now,
            case_id=case_row.id,
            external_id=external_id,
        )
    )

    note_body = f"{vendor.title()} ticket {external_id} transitioned. AiSOC case marked '{new_status}' via inbound webhook."
    await db.execute(
        text(
            """
            INSERT INTO aisoc_case_comments
                (id, case_id, author, body, is_system, created_at)
            VALUES
                (:id, :case_id, :author, :body, TRUE, :now)
            """
        ).bindparams(
            id=uuid.uuid4(),
            case_id=case_row.id,
            author=actor_label,
            body=note_body,
            now=now,
        )
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/itsm/{tenant_token}/{connector_instance_id}",
    response_model=InboundResult,
    summary="Inbound ITSM webhook (Jira / ServiceNow → AiSOC case)",
)
async def inbound_itsm_webhook(
    tenant_token: str,
    connector_instance_id: uuid.UUID,
    request: Request,
    db: DBSession,
    x_aisoc_signature: str | None = Header(default=None, alias="X-AiSOC-Signature"),
) -> InboundResult:
    """Receive a Jira / ServiceNow webhook and mirror status onto AiSOC.

    Public-facing — the only authenticator is the ``tenant_token`` in the
    URL (and an optional ``X-AiSOC-Signature`` HMAC). Rate limiting and
    DDoS protection are expected to live at the edge (Cloudflare /
    upstream LB), not here — the vendor's source IPs are stable enough
    that the ops team can configure WAF rules.

    Always returns 200 (never 5xx) on the happy path, even when the
    payload doesn't map to anything actionable. Vendor webhook
    implementations retry forever on non-2xx, and a stale ticket pinging
    a long-deleted case shouldn't block the rest of the queue. We surface
    "nothing happened" via ``InboundResult.status_changed=False`` and a
    human-readable ``note``.
    """

    raw_body = await request.body()

    token_row, connector_row = await _fetch_token_and_connector(
        db,
        tenant_token=tenant_token,
        connector_instance_id=connector_instance_id,
    )

    _verify_hmac(
        secret=token_row.hmac_secret,
        raw_body=raw_body,
        signature_header=x_aisoc_signature,
    )

    # Parse JSON ourselves so we get the raw body for HMAC verification
    # *before* JSON parsing ever runs. ``request.json()`` would consume
    # the stream and we'd have nothing to verify against.
    try:
        import json

        payload = json.loads(raw_body or b"{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook body is not valid JSON: {exc.msg}",
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook body must be a JSON object",
        )

    vendor = connector_row.connector_type
    if vendor == "jira":
        external_id, raw_status = _parse_jira_payload(payload)
    elif vendor == "servicenow":
        external_id, raw_status = _parse_servicenow_payload(payload)
    else:
        # Already filtered in _fetch_token_and_connector but be defensive —
        # the tuple of supported vendors is the only place this list is
        # ever updated.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unsupported vendor: {vendor}",
        )

    if external_id is None:
        # Malformed payload — log the connector so ops can debug, but
        # 200 the vendor so they don't retry endlessly. We saw this in
        # the wild when ServiceNow business rules emit synthetic
        # "current=null" events on initial deploy.
        logger.info(
            "inbox_itsm.payload_missing_external_id",
            extra={
                "vendor": safe_log_value(vendor),
                "connector_id": safe_log_value(connector_instance_id),
                "tenant_id": safe_log_value(token_row.tenant_id),
            },
        )
        return InboundResult(
            case_id=None,
            case_number=None,
            external_id=None,
            old_status=None,
            new_status=None,
            status_changed=False,
            note=f"{vendor} payload missing required fields",
        )

    # Resolve external_id → AiSOC case via case_external_refs. The unique
    # constraint on (connector_instance_id, external_id) guarantees at
    # most one row.
    ref_row = (
        await db.execute(
            text(
                """
                SELECT r.id, r.case_id, r.external_status,
                       c.id AS aisoc_case_id, c.case_number, c.status
                FROM case_external_refs r
                JOIN aisoc_cases c ON c.id = r.case_id
                WHERE r.connector_instance_id = :connector_id
                  AND r.external_id = :external_id
                """
            ).bindparams(
                connector_id=connector_instance_id,
                external_id=external_id,
            )
        )
    ).fetchone()

    if ref_row is None:
        # ITSM ticket exists on the vendor side but we don't have it
        # linked to any AiSOC case. This is normal during onboarding
        # (operator imported pre-existing tickets) — bump nothing, log,
        # and 200 the vendor.
        logger.info(
            "inbox_itsm.unlinked_external_id",
            extra={
                "vendor": safe_log_value(vendor),
                "external_id": safe_log_value(external_id),
                "connector_id": safe_log_value(connector_instance_id),
                "tenant_id": safe_log_value(token_row.tenant_id),
            },
        )
        return InboundResult(
            case_id=None,
            case_number=None,
            external_id=external_id,
            old_status=None,
            new_status=None,
            status_changed=False,
            note=(f"No AiSOC case linked to {vendor} {external_id}. The ticket may pre-date the integration."),
        )

    # Update last_used_at on the inbox token regardless of whether the
    # status changed, so operators can see "this token is alive". Done
    # on every successful auth+resolve, not just on writes.
    now = datetime.now(UTC)
    await db.execute(text("UPDATE tenant_inbox_tokens SET last_used_at = :now WHERE token = :tok").bindparams(now=now, tok=tenant_token))

    new_status = _map_inbound_status(vendor, raw_status)
    if new_status is None:
        # Either the vendor sent no status field or we don't have a
        # mapping for it. Bump last_synced_at so the timeline shows the
        # ping landed but don't change the case.
        await db.execute(
            text(
                """
                UPDATE case_external_refs
                SET last_synced_at = :now, updated_at = :now
                WHERE id = :id
                """
            ).bindparams(now=now, id=ref_row.id)
        )
        await db.commit()
        return InboundResult(
            case_id=ref_row.aisoc_case_id,
            case_number=ref_row.case_number,
            external_id=external_id,
            old_status=ref_row.status,
            new_status=ref_row.status,
            status_changed=False,
            note=(f"{vendor} status '{raw_status}' has no AiSOC equivalent; last_synced_at bumped."),
        )

    if new_status == ref_row.status:
        # Idempotent redelivery — case is already in the target state.
        # Touch sync columns and return.
        await db.execute(
            text(
                """
                UPDATE case_external_refs
                SET external_status = :ext_status,
                    last_synced_at = :now,
                    updated_at = :now
                WHERE id = :id
                """
            ).bindparams(ext_status=new_status, now=now, id=ref_row.id)
        )
        await db.commit()
        return InboundResult(
            case_id=ref_row.aisoc_case_id,
            case_number=ref_row.case_number,
            external_id=external_id,
            old_status=ref_row.status,
            new_status=new_status,
            status_changed=False,
            note="Case already in target state; sync timestamps refreshed.",
        )

    # Real status change. The actor label leaks the connector_type only,
    # never the full URL or sys_id — that detail goes in the body of the
    # system comment.
    actor_label = f"itsm-webhook ({vendor})"
    try:
        await _apply_status_to_case(
            db,
            case_row=ref_row,
            new_status=new_status,
            actor_label=actor_label,
            external_id=external_id,
            vendor=vendor,
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.exception(
            "inbox_itsm.apply_failed",
            extra={
                "vendor": safe_log_value(vendor),
                "external_id": safe_log_value(external_id),
                "case_id": safe_log_value(ref_row.aisoc_case_id),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to apply inbound status: {exc}",
        ) from exc

    logger.info(
        "inbox_itsm.status_applied",
        extra={
            "vendor": safe_log_value(vendor),
            "external_id": safe_log_value(external_id),
            "case_id": safe_log_value(ref_row.aisoc_case_id),
            "old_status": safe_log_value(ref_row.status),
            "new_status": safe_log_value(new_status),
        },
    )
    return InboundResult(
        case_id=ref_row.aisoc_case_id,
        case_number=ref_row.case_number,
        external_id=external_id,
        old_status=ref_row.status,
        new_status=new_status,
        status_changed=True,
    )

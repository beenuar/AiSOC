"""Tenant inbox token management — Workstream 6 (universal capture).

For closed-proprietary tools that have neither a read API nor an OAuth
flow, AiSOC mints a per-tenant, rotatable inbox URL. The customer
points the vendor's existing webhook at that URL; ``services/ingest``
resolves the token to a tenant + vendor template and reuses the
existing OCSF normalizer + Kafka publisher.

This module exposes the **operator-facing** half of that machinery —
the management API the onboarding wizard calls when the user clicks the
"Push (any vendor)" card. It does *not* receive vendor webhook traffic;
that's the Go ``services/ingest`` service which reads ``tenant_inbox_tokens``
directly from Postgres.

Tenant scoping invariants:

* Every read query filters on
  ``TenantInboxToken.tenant_id == current_user.tenant_id``.
* The list of valid ``template_id`` values is loaded from the ingest
  service's template directory and validated server-side, so a malicious
  client cannot register a token pointing at a non-existent template
  (which would silently drop traffic on the floor).
* Tokens never round-trip in audit logs — only the trailing 8 chars
  (the "fingerprint") are emitted.
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import settings
from app.core.logging import safe_log_value
from app.db.rls import TenantDBSession
from app.models.inbox import TenantInboxToken

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/inbox", tags=["inbox"])

# Closed allowlist of template IDs the operator can reference. This must
# stay in lock-step with the YAML files at
# ``services/ingest/internal/normalizer/templates/*.yaml``. We treat it
# as a hard list (rather than reading the FS at request time) because:
#
# * Adding a template is a code/release event, not a runtime config
#   change — operators shouldn't pick a template name that isn't shipped.
# * The Go ingest service may be deployed independently; if a template
#   isn't shipped on the active version the URL silently drops events.
#   Validating at mint time turns that into a 400 instead of a black hole.
#
# Lower-cased and slugified to match the filename stem. Order is the
# UI's "preferred display order" so the wizard can iterate this list
# directly.
ALLOWED_TEMPLATE_IDS: tuple[str, ...] = (
    # P0 templates from the plan
    "generic-json",
    "pagerduty",
    "opsgenie",
    "microsoft-defender-email",
    "aws-sns",
    "aws-eventbridge",
    "github-security-advisory",
    "cloudflare-logpush",
    # Universal-capture sidecars
    "cef-syslog",
    "splunk-hec",
    "email-forwarded",
    # Bidirectional ITSM (Workstream 8) — inbound Jira / ServiceNow webhooks.
    # Tokens minted with this template terminate at
    # /api/v1/inbox/itsm/{tenant_token}/{connector_instance_id} on services/api
    # rather than the generic ingest path, because they need to resolve back
    # to a specific connector instance and mirror status onto aisoc_cases.
    "itsm-inbound",
)

# Same character set as connector_type — tightens HMAC body shape.
_LABEL_RE = re.compile(r"^[\w\-\. ]{1,255}$")


def _generate_inbox_token() -> str:
    """Return an opaque, URL-safe inbox token.

    32 bytes of entropy = ~256 bits, with the ``aitnb_`` prefix making
    it grep-able in logs / SIEMs and immediately distinguishable from
    other AiSOC token types (``aisoc_`` API keys, ``ait_`` per-connector
    push tokens).
    """
    return f"aitnb_{secrets.token_urlsafe(32)}"


def _fingerprint(token: str) -> str:
    """Return last 8 chars of a token, safe to log."""
    return f"...{token[-8:]}" if len(token) > 8 else "...<short>"


def _build_inbox_url(token: str, template_id: str | None = None) -> str:
    """Build the absolute inbox URL the customer pastes into the vendor.

    For most templates (PagerDuty, generic-json, syslog, etc.) the URL
    terminates at services/ingest, which resolves the token to a tenant
    + template_id and runs the OCSF normalizer.

    The exception is ``itsm-inbound`` (Workstream 8). Those URLs need to
    terminate at services/api because they:

    1. Need a database transaction to update aisoc_cases / case_external_refs.
    2. Need to look up case_fanout's earlier outbound projection to find
       the AiSOC case ID, which lives in the api-service-managed schema.
    3. Are pinned to a specific connector instance, so the URL carries a
       ``{connector_instance_id}`` placeholder that the operator fills in
       when they paste it into Jira/ServiceNow's webhook config.

    The placeholder ``<connector_instance_id>`` (UUID) is intentionally
    angle-bracketed so it's obvious in the wizard UI that the operator
    has to substitute it before saving the URL on the vendor side.
    """
    if template_id == "itsm-inbound":
        # Public URL of the API service (NOT the ingest service). Reuses
        # ``OAUTH_PUBLIC_BASE_URL`` because that's already the canonical
        # "where does the world reach my API" setting — adding a separate
        # ``API_PUBLIC_URL`` would duplicate the same value with different
        # names. Falls back to a relative path when unset, which is fine
        # for dev / docker-compose where the operator paste happens on the
        # same host the API is exposed from.
        api_base = (getattr(settings, "OAUTH_PUBLIC_BASE_URL", "") or "").rstrip("/")
        path = f"/api/v1/inbox/itsm/{token}/<connector_instance_id>"
        return f"{api_base}{path}" if api_base else path

    base = (getattr(settings, "INGEST_PUBLIC_URL", "") or "").rstrip("/")
    return f"{base}/v1/inbox/{token}" if base else f"/v1/inbox/{token}"


# ----------------------------------------------------------------- schemas


class InboxTokenCreate(BaseModel):
    """Request body for ``POST /api/v1/inbox/tokens``."""

    template_id: str = Field(
        ...,
        description=(
            "Vendor template stem from ``services/ingest/internal/normalizer/templates/*.yaml`` (e.g. ``pagerduty``, ``generic-json``)."
        ),
    )
    label: str | None = Field(
        default=None,
        description='Operator-facing label ("PagerDuty on-call").',
    )
    hmac_secret: str | None = Field(
        default=None,
        description=(
            "Optional HMAC-SHA256 secret for ``X-Signature`` verification. "
            "If provided, the ingest service rejects requests whose signature "
            "doesn't match. NULL means the URL token is the only authenticator."
        ),
        min_length=16,
        max_length=512,
    )


class InboxTokenResponse(BaseModel):
    """A single inbox token, including the *plaintext* token + URL.

    The token is returned in full **only** at mint time (when the wizard
    needs to show it to the operator). Subsequent list calls return the
    fingerprint instead, which is enough to identify the row but not
    enough to forge inbound traffic.
    """

    token: str
    inbox_url: str
    template_id: str
    label: str | None
    has_hmac_secret: bool
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class InboxTokenListItem(BaseModel):
    """List view: omits the plaintext token."""

    fingerprint: str
    template_id: str
    label: str | None
    has_hmac_secret: bool
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class InboxTemplateInfo(BaseModel):
    """Catalog entry for a vendor template the operator can pick."""

    template_id: str
    label: str
    description: str
    category: str


# Display metadata for each template. Same content the wizard renders;
# kept here (not in the YAML) because the YAML is parsed by the Go
# service and we don't want a cross-service schema dependency.
_TEMPLATE_CATALOG: dict[str, dict[str, str]] = {
    "generic-json": {
        "label": "Generic JSON",
        "description": ("Forward arbitrary JSON. Best effort field mapping; use a specific template below if your vendor is listed."),
        "category": "generic",
    },
    "pagerduty": {
        "label": "PagerDuty",
        "description": "PagerDuty Events API v2 / webhook payload.",
        "category": "alerting",
    },
    "opsgenie": {
        "label": "Opsgenie",
        "description": "Atlassian Opsgenie webhook payload.",
        "category": "alerting",
    },
    "microsoft-defender-email": {
        "label": "Microsoft Defender (email digest)",
        "description": "Forward Defender alert email digests via SES/Mailgun.",
        "category": "email",
    },
    "aws-sns": {
        "label": "AWS SNS",
        "description": "AWS SNS message subscription HTTPS endpoint.",
        "category": "cloud",
    },
    "aws-eventbridge": {
        "label": "AWS EventBridge",
        "description": "EventBridge API destination payload.",
        "category": "cloud",
    },
    "github-security-advisory": {
        "label": "GitHub Security Advisory",
        "description": "GitHub repo / org security advisory webhook.",
        "category": "vcs",
    },
    "cloudflare-logpush": {
        "label": "Cloudflare Logpush",
        "description": "Cloudflare Logpush HTTP destination payload.",
        "category": "network",
    },
    "cef-syslog": {
        "label": "Syslog / CEF",
        "description": "ArcSight Common Event Format over HTTPS.",
        "category": "siem",
    },
    "splunk-hec": {
        "label": "Splunk HEC-compatible",
        "description": (
            "Drop-in replacement for Splunk HTTP Event Collector. Re-target any tool already pointed at Splunk HEC by changing the URL."
        ),
        "category": "siem",
    },
    "email-forwarded": {
        "label": "Forwarded email",
        "description": ("Inbound webhook from Mailgun / SES routing rules. Useful for vendors that only deliver alerts via email."),
        "category": "email",
    },
    "itsm-inbound": {
        "label": "Inbound ITSM (Jira / ServiceNow)",
        "description": (
            "Receive status-change webhooks from Jira or ServiceNow. The URL "
            "must be paired with a specific connector instance — paste it "
            "into the vendor's webhook config alongside the connector ID. "
            "Tokens of this type terminate at services/api so we can mirror "
            "status onto aisoc_cases."
        ),
        "category": "itsm",
    },
}


# ----------------------------------------------------------------- helpers


def _to_response(row: TenantInboxToken, *, include_plaintext: bool) -> InboxTokenResponse:
    """Convert an ORM row to the wire response.

    ``include_plaintext`` is True only at mint time; everything else gets
    the fingerprint via ``_to_list_item``.
    """
    return InboxTokenResponse(
        token=row.token if include_plaintext else _fingerprint(row.token),
        inbox_url=_build_inbox_url(row.token, row.template_id),
        template_id=row.template_id,
        label=row.label,
        has_hmac_secret=row.hmac_secret is not None,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
    )


def _to_list_item(row: TenantInboxToken) -> InboxTokenListItem:
    return InboxTokenListItem(
        fingerprint=_fingerprint(row.token),
        template_id=row.template_id,
        label=row.label,
        has_hmac_secret=row.hmac_secret is not None,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
    )


# ----------------------------------------------------------------- endpoints


@router.get("/templates", response_model=list[InboxTemplateInfo])
async def list_templates(
    _user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
) -> list[InboxTemplateInfo]:
    """List the vendor templates the operator can mint inbox URLs for."""
    return [
        InboxTemplateInfo(
            template_id=tid,
            label=meta["label"],
            description=meta["description"],
            category=meta["category"],
        )
        for tid in ALLOWED_TEMPLATE_IDS
        for meta in (_TEMPLATE_CATALOG.get(tid),)
        if meta is not None
    ]


@router.get("/tokens", response_model=list[InboxTokenListItem])
async def list_tokens(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: TenantDBSession,
    include_revoked: bool = False,
) -> list[InboxTokenListItem]:
    """List the calling tenant's inbox tokens.

    By default revoked rows are filtered — operators rarely want to
    look at expired tokens, and showing them by default makes the
    "rotate token" flow noisy.
    """
    stmt = select(TenantInboxToken).where(TenantInboxToken.tenant_id == current_user.tenant_id)
    if not include_revoked:
        stmt = stmt.where(TenantInboxToken.revoked_at.is_(None))
    stmt = stmt.order_by(TenantInboxToken.created_at.desc())

    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [_to_list_item(row) for row in rows]


@router.post(
    "/tokens",
    response_model=InboxTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def mint_token(
    body: InboxTokenCreate,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: TenantDBSession,
) -> InboxTokenResponse:
    """Mint a new inbox token for the calling tenant.

    Returns the plaintext token + absolute URL exactly once. Subsequent
    list/get calls return only the fingerprint.
    """
    if body.template_id not in ALLOWED_TEMPLATE_IDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown template_id; valid: {', '.join(ALLOWED_TEMPLATE_IDS)}",
        )
    if body.label is not None and not _LABEL_RE.match(body.label):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="label may contain alphanumerics, dash, dot, underscore, space",
        )

    token = _generate_inbox_token()
    row = TenantInboxToken(
        token=token,
        tenant_id=current_user.tenant_id,
        template_id=body.template_id,
        label=body.label,
        hmac_secret=body.hmac_secret,
        created_at=datetime.now(UTC),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    logger.info(
        "tenant_inbox_token.minted",
        extra={
            "tenant_id": str(current_user.tenant_id),
            "template_id": safe_log_value(body.template_id),
            "token_fingerprint": _fingerprint(token),
            "has_hmac": body.hmac_secret is not None,
        },
    )
    return _to_response(row, include_plaintext=True)


@router.post("/tokens/{token_fingerprint}/rotate", response_model=InboxTokenResponse)
async def rotate_token(
    token_fingerprint: str,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: TenantDBSession,
) -> InboxTokenResponse:
    """Mint a new token with the same template/label/hmac, revoke the old.

    The wizard's "rotate" button calls this when a URL leaks. Old token
    is marked revoked so the ingest service rejects requests for it
    immediately; new plaintext token is returned for the operator to
    paste into the vendor's webhook config.

    We accept the fingerprint (not the full token) in the path so the
    plaintext token never appears in logs / proxy access logs.
    """
    # Fingerprint is the trailing 8 chars; LIKE-search for it under the
    # current tenant. Collisions across tenants are fine because we
    # filter by tenant_id; collisions within a tenant are vanishingly
    # unlikely (8 chars of base64 = ~48 bits) but if they ever happen
    # we 409 rather than guessing.
    suffix = token_fingerprint.lstrip(".")
    if len(suffix) < 4 or len(suffix) > 16:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid fingerprint",
        )

    result = await db.execute(
        select(TenantInboxToken).where(
            TenantInboxToken.tenant_id == current_user.tenant_id,
            TenantInboxToken.token.like(f"%{suffix}"),
            TenantInboxToken.revoked_at.is_(None),
        )
    )
    matches = result.scalars().all()
    if not matches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    if len(matches) > 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Fingerprint collision; rotate the specific token via API",
        )
    old = matches[0]

    new_token = _generate_inbox_token()
    new_row = TenantInboxToken(
        token=new_token,
        tenant_id=current_user.tenant_id,
        template_id=old.template_id,
        label=old.label,
        hmac_secret=old.hmac_secret,
        created_at=datetime.now(UTC),
    )
    db.add(new_row)

    await db.execute(update(TenantInboxToken).where(TenantInboxToken.token == old.token).values(revoked_at=datetime.now(UTC)))
    await db.commit()
    await db.refresh(new_row)

    logger.info(
        "tenant_inbox_token rotated",
        extra={
            "tenant_id": str(current_user.tenant_id),
            "template_id": old.template_id,
            "old_fingerprint": _fingerprint(old.token),
            "new_fingerprint": _fingerprint(new_token),
        },
    )
    return _to_response(new_row, include_plaintext=True)


@router.delete("/tokens/{token_fingerprint}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_token(
    token_fingerprint: str,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: TenantDBSession,
) -> None:
    """Permanently revoke an inbox token without minting a replacement.

    The ingest service rejects revoked tokens; we keep the row so the
    UI can still show "this token was revoked at X" in audit views.
    """
    suffix = token_fingerprint.lstrip(".")
    if len(suffix) < 4 or len(suffix) > 16:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid fingerprint",
        )

    result = await db.execute(
        select(TenantInboxToken).where(
            TenantInboxToken.tenant_id == current_user.tenant_id,
            TenantInboxToken.token.like(f"%{suffix}"),
            TenantInboxToken.revoked_at.is_(None),
        )
    )
    matches = result.scalars().all()
    if not matches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    if len(matches) > 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Fingerprint collision; revoke the specific token via API",
        )
    target = matches[0]

    await db.execute(update(TenantInboxToken).where(TenantInboxToken.token == target.token).values(revoked_at=datetime.now(UTC)))
    await db.commit()

    logger.info(
        "tenant_inbox_token revoked",
        extra={
            "tenant_id": str(current_user.tenant_id),
            "template_id": target.template_id,
            "token_fingerprint": _fingerprint(target.token),
        },
    )

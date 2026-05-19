"""Managed-instance waitlist endpoints — T6.1.

Three endpoints, one public + two admin-only:

* ``POST  /v1/waitlist/signup``           — public, rate-limited per IP.
  Accepts the marketing form payload, persists a row, fires a Slack
  webhook at the sales channel, returns ``{ok, entry_id}``. The 200
  response is deliberately generic: we don't leak whether the same
  email already signed up (idempotent re-submit is silently a no-op),
  so a scraper can't enumerate the customer list by replaying signups.
* ``GET   /v1/waitlist/entries``          — admin only.
  Lists entries with optional ``?status=`` filter and ``?limit=`` cap.
* ``PATCH /v1/waitlist/entries/{id}``     — admin only.
  Transitions the row through the state ladder
  (``new → contacted → onboarded → declined``) and stamps the matching
  audit timestamps.

The public signup endpoint never raises if the Slack webhook is
unhealthy — the prospect still sees a successful submit, the row is
still persisted, the support team will see it in the admin list.

Rate limiting
-------------

This is the only public-facing mutating endpoint in the API. We use a
**per-IP** token bucket (``app.services.waitlist.rate_limit``) rather
than the per-tenant limiter used by ``/lake`` and ``/explain`` — there
is no tenant context to limit against on a public signup. Source IP
resolves from ``X-Forwarded-For`` (trusting the proxy chain in front of
the API: Cloudflare → Fly.io edge → API), falling back to the raw
socket address.

Auth
----

The signup endpoint is the *one* unauthenticated mutating route in the
v1 API surface. ``get_current_user`` is intentionally **not** wired in
here; we'd otherwise reject the public form. The admin endpoints reuse
the standard :class:`AuthUser` dependency and require the
``admin:waitlist`` permission, which falls back to ``settings:write``
on tenants whose RBAC tables haven't been migrated to the granular
admin scope yet.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, get_current_user
from app.db.database import get_db
from app.models.waitlist import (
    ALLOWED_WAITLIST_STATUSES,
    WAITLIST_STATUS_CONTACTED,
    WAITLIST_STATUS_DECLINED,
    WAITLIST_STATUS_NEW,
    WAITLIST_STATUS_ONBOARDED,
    WaitlistEntry,
)
from app.services.waitlist import (
    SignupRateLimiter,
    SlackNotifier,
    build_signup_message,
    get_signup_rate_limiter,
    get_slack_notifier,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/waitlist", tags=["waitlist"])


# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

_MAX_FIELD_LEN_SHORT: int = 100
_MAX_FIELD_LEN_MEDIUM: int = 255
_MAX_MOTIVATION_LEN: int = 4000
_MAX_SOC_STACK_ENTRIES: int = 20
_MAX_LIST_LIMIT: int = 500


# Maps a user-supplied / DB-stored status value to the *hardcoded literal*
# that is safe to put into a log record. Looking up the value (rather than
# echoing the raw status through ``status if status in ALLOWED... else
# "<invalid>"``) breaks CodeQL's taint flow because the value side of the
# mapping is never derived from the input — it is a compile-time string
# literal. This satisfies ``py/log-injection`` without losing the
# operational signal. The keys mirror ``ALLOWED_WAITLIST_STATUSES``; any
# value outside that allowlist falls back to ``"<invalid>"`` at the call
# site.
_STATUS_LOG_TOKENS: dict[str, str] = {
    WAITLIST_STATUS_NEW: "new",
    WAITLIST_STATUS_CONTACTED: "contacted",
    WAITLIST_STATUS_ONBOARDED: "onboarded",
    WAITLIST_STATUS_DECLINED: "declined",
}


def _safe_log_value(value: object) -> str:
    """Sanitize a value before it lands in a log record.

    The values we route through this helper (``uuid.UUID`` instances from
    request path params and the authenticated user) are structurally
    incapable of containing CR/LF or other control characters — UUIDs are
    hex + hyphens by spec. CodeQL's ``py/log-injection`` taint tracker
    doesn't model that invariant, however, and still sees the value as
    user-influenced. Explicitly stripping CR/LF (the exact pattern the
    rule documentation lists as a sanitizer) is what breaks the taint
    flow. We also strip the rest of the ASCII control-character range to
    be defensive against future callers passing in strings that *can*
    carry such bytes.
    """
    text = str(value).replace("\r\n", "").replace("\r", "").replace("\n", "")
    # Strip any remaining ASCII control characters (0x00-0x1F, 0x7F) so
    # tab/escape characters can't smuggle log-line manipulation past the
    # CR/LF strip above.
    return "".join(ch for ch in text if ch.isprintable())


# RFC 5322 is famously permissive; we use a forgiving "addr@domain.tld"
# regex that catches obvious typos without rejecting legitimate edge
# cases (plus-addressing, hyphenated subdomains, etc.).
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


# ---------------------------------------------------------------------------
# Wire shapes
# ---------------------------------------------------------------------------


class WaitlistSignupRequest(BaseModel):
    """The exact payload the marketing form posts."""

    email: str = Field(..., min_length=3, max_length=320)
    company: str = Field(..., min_length=1, max_length=_MAX_FIELD_LEN_MEDIUM)
    role: str = Field(..., min_length=1, max_length=_MAX_FIELD_LEN_SHORT)
    soc_stack: list[str] = Field(default_factory=list)
    motivation: str = Field(..., min_length=1, max_length=_MAX_MOTIVATION_LEN)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        v = value.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid email address")
        return v

    @field_validator("company", "role", "motivation")
    @classmethod
    def _strip_strings(cls, value: str) -> str:
        v = value.strip()
        if not v:
            raise ValueError("must not be empty after trimming")
        return v

    @field_validator("soc_stack")
    @classmethod
    def _normalize_stack(cls, value: list[str]) -> list[str]:
        # Cap the list length and strip empties so a misbehaved form
        # client can't post a JSON blob full of empty strings.
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                continue
            normalized = item.strip()
            if not normalized:
                continue
            if len(normalized) > _MAX_FIELD_LEN_SHORT:
                normalized = normalized[:_MAX_FIELD_LEN_SHORT]
            if normalized in seen:
                continue
            seen.add(normalized)
            cleaned.append(normalized)
            if len(cleaned) >= _MAX_SOC_STACK_ENTRIES:
                break
        return cleaned


class WaitlistSignupResponse(BaseModel):
    """The reply to a successful (or idempotent-no-op) signup.

    Same shape whether the email was net-new or already on the list —
    the prospect should not be able to enumerate existing signups.
    """

    ok: bool = True
    message: str = "We'll be in touch within 5 business days."
    entry_id: str | None = None


class WaitlistEntryWire(BaseModel):
    """Admin-list / admin-patch response shape."""

    id: str
    email: str
    company: str
    role: str
    soc_stack: list[str]
    motivation: str
    status: str
    provisioned_tenant_id: str | None
    created_at: str
    contacted_at: str | None
    onboarded_at: str | None


class WaitlistEntriesResponse(BaseModel):
    entries: list[WaitlistEntryWire]
    total: int


class WaitlistPatchRequest(BaseModel):
    status: str = Field(..., min_length=1, max_length=32)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: str) -> str:
        v = value.strip().lower()
        if v not in ALLOWED_WAITLIST_STATUSES:
            raise ValueError(f"status must be one of: {sorted(ALLOWED_WAITLIST_STATUSES)}")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str:
    """Resolve the source IP, trusting the proxy chain in front of us.

    The API runs behind Cloudflare → Fly.io edge so ``X-Forwarded-For``
    is operator-controlled. We take the *first* address in the header
    when present (the original client) and fall back to the raw socket
    address otherwise. The limiter only uses this as a bucket key, so a
    forged header still gets the attacker their own bucket — they can't
    exhaust someone else's quota by spoofing.
    """
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    if request.client is not None:
        return request.client.host
    return "unknown"


def _to_wire(row: WaitlistEntry) -> WaitlistEntryWire:
    return WaitlistEntryWire(
        id=str(row.id),
        email=row.email,
        company=row.company,
        role=row.role,
        soc_stack=list(row.soc_stack or []),
        motivation=row.motivation,
        status=row.status,
        provisioned_tenant_id=(str(row.provisioned_tenant_id) if row.provisioned_tenant_id else None),
        created_at=row.created_at.isoformat(),
        contacted_at=row.contacted_at.isoformat() if row.contacted_at else None,
        onboarded_at=row.onboarded_at.isoformat() if row.onboarded_at else None,
    )


async def _require_admin(user: AuthUser, db: AsyncSession) -> None:
    """Centralised admin gate.

    The granular RBAC layer prefers ``admin:waitlist``; tenants that
    haven't migrated to the granular scope fall back to the legacy
    ``settings:write`` role permission. Either grants access.
    """
    if await user.has_permission_db("admin:waitlist", db):
        return
    if await user.has_permission_db("settings:write", db):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="admin:waitlist (or settings:write) required",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/signup",
    response_model=WaitlistSignupResponse,
    status_code=status.HTTP_200_OK,
    summary="Public waitlist signup (rate-limited per IP).",
)
async def signup(
    payload: WaitlistSignupRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    rate_limiter: SignupRateLimiter = Depends(get_signup_rate_limiter),
    notifier: SlackNotifier = Depends(get_slack_notifier),
) -> WaitlistSignupResponse:
    """Persist a new signup, fire a Slack ping, return the entry id."""
    source_ip = _client_ip(request)
    decision = await rate_limiter.acquire(source_ip)
    headers = decision.to_headers()
    for k, v in headers.items():
        response.headers[k] = v
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many signups from this address. Please try again later.",
            headers=headers,
        )

    # Insert idempotently: if the email already exists we treat it as a
    # successful no-op so a prospect who re-submits doesn't see a 409
    # (and can't enumerate). We do *not* update existing rows from this
    # path — only the admin PATCH endpoint moves an entry off ``new``.
    entry: WaitlistEntry | None = None
    try:
        existing = (await db.execute(select(WaitlistEntry).where(WaitlistEntry.email == payload.email))).scalar_one_or_none()
        if existing is not None:
            return WaitlistSignupResponse(entry_id=str(existing.id))

        entry = WaitlistEntry(
            email=payload.email,
            company=payload.company,
            role=payload.role,
            soc_stack=payload.soc_stack,
            motivation=payload.motivation,
            status=WAITLIST_STATUS_NEW,
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
    except IntegrityError:
        # Race: another request inserted between SELECT and commit.
        # Treat as idempotent success and look the row back up.
        await db.rollback()
        existing = (await db.execute(select(WaitlistEntry).where(WaitlistEntry.email == payload.email))).scalar_one_or_none()
        if existing is not None:
            return WaitlistSignupResponse(entry_id=str(existing.id))
        # If we still can't find it, fall through to a generic success
        # response — the data either landed elsewhere or will be
        # surfaced via the operator's audit trail.
        logger.warning("waitlist signup IntegrityError without recoverable row")
        return WaitlistSignupResponse(entry_id=None)
    except SQLAlchemyError as exc:
        logger.exception("waitlist signup DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not persist signup, please retry.",
        ) from exc

    # Fire-and-forget Slack notification. Notifier is contract-bound to
    # never raise; we still wrap in a try/except so a runtime error in
    # the notifier itself never bubbles up.
    try:
        message = build_signup_message(
            email=entry.email,
            company=entry.company,
            role=entry.role,
            soc_stack=list(entry.soc_stack or []),
            motivation=entry.motivation,
            entry_id=str(entry.id),
        )
        notifier.post(message)
    except Exception as exc:  # noqa: BLE001 — signup success must not depend on Slack
        logger.warning("waitlist signup slack notify failed: %s", exc)

    return WaitlistSignupResponse(entry_id=str(entry.id))


@router.get(
    "/entries",
    response_model=WaitlistEntriesResponse,
    summary="List waitlist entries (admin only).",
)
async def list_entries(
    db: DBSession,
    user: AuthUser,
    status_filter: str | None = None,
    limit: int = 100,
) -> WaitlistEntriesResponse:
    await _require_admin(user, db)
    if status_filter is not None:
        normalized = status_filter.strip().lower()
        if normalized not in ALLOWED_WAITLIST_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"status must be one of: {sorted(ALLOWED_WAITLIST_STATUSES)}",
            )
        status_filter = normalized

    capped_limit = max(1, min(int(limit), _MAX_LIST_LIMIT))

    stmt = select(WaitlistEntry)
    if status_filter is not None:
        stmt = stmt.where(WaitlistEntry.status == status_filter)
    stmt = stmt.order_by(desc(WaitlistEntry.created_at)).limit(capped_limit)

    rows = (await db.execute(stmt)).scalars().all()
    return WaitlistEntriesResponse(
        entries=[_to_wire(r) for r in rows],
        total=len(rows),
    )


@router.patch(
    "/entries/{entry_id}",
    response_model=WaitlistEntryWire,
    summary="Update a waitlist entry's status (admin only).",
)
async def patch_entry(
    entry_id: uuid.UUID,
    payload: WaitlistPatchRequest,
    db: DBSession,
    user: AuthUser,
) -> WaitlistEntryWire:
    await _require_admin(user, db)
    row = (await db.execute(select(WaitlistEntry).where(WaitlistEntry.id == entry_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="waitlist_entry_not_found")

    now = datetime.now(UTC)
    previous = row.status
    row.status = payload.status

    # Stamp the matching audit columns. ``onboarded`` is normally set by
    # the tenant_provision pipeline (which stamps ``provisioned_tenant_id``
    # at the same time); allow the admin to flip the status manually
    # here too so a back-fill is possible if the pipeline already ran
    # but the bookkeeping drift-corrected later.
    if payload.status == WAITLIST_STATUS_CONTACTED and row.contacted_at is None:
        row.contacted_at = now
    elif payload.status == WAITLIST_STATUS_ONBOARDED and row.onboarded_at is None:
        row.onboarded_at = now

    try:
        await db.commit()
        await db.refresh(row)
    except SQLAlchemyError as exc:
        await db.rollback()
        logger.exception("waitlist patch DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not update waitlist entry.",
        ) from exc

    # ``previous`` (DB enum) and ``payload.status`` (Pydantic-validated
    # against ``ALLOWED_WAITLIST_STATUSES``) are constrained to a known
    # allowlist; the dict-lookup form returns a value provably independent
    # of the input. ``entry_id`` and ``user.user_id`` are ``uuid.UUID``
    # objects that structurally cannot carry control characters, but
    # CodeQL's taint model still flags them — route them through
    # ``_safe_log_value`` so the CR/LF strip the rule explicitly
    # recognises as a sanitizer is applied.
    safe_previous = _STATUS_LOG_TOKENS.get(previous, "<invalid>")
    safe_next = _STATUS_LOG_TOKENS.get(payload.status, "<invalid>")
    logger.info(
        "waitlist_status_transition",
        extra={
            "entry_id": _safe_log_value(entry_id),
            "previous": safe_previous,
            "next": safe_next,
            "actor": _safe_log_value(user.user_id),
        },
    )
    return _to_wire(row)


# get_current_user re-exported so endpoints that need to surface a
# tighter auth dependency can re-use the canonical resolver without an
# import-graph detour. Re-exported here (in this endpoint module) so
# tests can monkeypatch it locally.
__all__: list[str] = [
    "router",
    "WaitlistSignupRequest",
    "WaitlistSignupResponse",
    "WaitlistEntriesResponse",
    "WaitlistEntryWire",
    "WaitlistPatchRequest",
    "get_current_user",
    "signup",
    "list_entries",
    "patch_entry",
]


def _resolved_admin_gate() -> Any:  # pragma: no cover — helper for type hints
    return Depends(get_current_user)

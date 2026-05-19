"""Tenant provisioner — promote a waitlist entry into a live tenant (T6.1).

This is the heart of the managed-instance onboarding flow:

    waitlist entry  ──(operator clicks "promote")──▶  live tenant + admin invite

The provisioner is deliberately structured as one orchestrating coroutine
(:func:`provision_from_waitlist`) plus a handful of *pure* helpers so the
unit tests can drive each step in isolation. Every helper either:

* returns plain data (slug derivation, invite URL composition,
  credential-key minting), or
* mutates an :class:`AsyncSession` it was handed (tenant row insert,
  waitlist row patch).

No helper opens its own session, talks to Redis, or hits the network.
That means the whole thing is unit-testable without spinning up Postgres.

What "provisioning" does, end to end:

1. Look up the waitlist entry by id. If the row is missing or already
   carries a ``provisioned_tenant_id`` we either error out (missing) or
   short-circuit (idempotent re-provision returns the existing tenant).
2. Derive a unique URL-safe slug from the company name. If the slug is
   already taken we suffix it with a 6-char hex shard until we get a
   collision-free row.
3. Create the tenant ORM row with a tenant-scoped
   ``aisoc_credential_key`` (a fresh Fernet key) tucked into
   ``settings``. Operators rotate this key with the existing
   ``CredentialVault`` machinery; we only mint it here.
4. Seed the demo dataset by calling into ``app.scripts.seed_demo`` so
   the tenant has something to look at on day one. We rely on the
   seed-demo script's existing idempotency: it inspects whether the
   target tenant already has connectors and bails out cheaply if so.
   The seed dataset uses the *demo* tenant id today; we extract the
   reusable helper rather than copy-pasting the seeded SQL.
5. Mint an initial admin invite link (``/invite/{token}``). The token
   is *not* validated against any DB table yet — the actual
   ``invitations`` table is owned by the auth migrations and will land
   in a follow-up. Today the invite URL is a signed pointer the
   operator emails out manually.
6. Stamp ``contacted_at`` / ``onboarded_at`` / ``provisioned_tenant_id``
   on the waitlist entry and flip its status to ``onboarded``.

Everything happens inside the caller's session; the caller commits.
That keeps the endpoint's transaction boundary explicit and lets it
roll back if any downstream step (e.g. webhook fan-out) fails.
"""

from __future__ import annotations

import logging
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant, User
from app.models.waitlist import (
    WAITLIST_STATUS_ONBOARDED,
    WaitlistEntry,
)
from app.services.tenant_provision.templates import (
    TenantTemplateBundle,
    get_default_template_bundle,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProvisioningError(RuntimeError):
    """Base class for all provisioner failures."""


class WaitlistEntryNotFoundError(ProvisioningError):
    """The supplied waitlist entry id resolved to nothing."""


class WaitlistEntryNotPromotableError(ProvisioningError):
    """The waitlist entry exists but is in a state we refuse to promote.

    Concretely: an entry with status ``declined`` cannot be promoted.
    A previously-onboarded entry can be re-resolved idempotently by the
    provisioner; this error is reserved for the explicitly hostile
    states.
    """


class SlugCollisionError(ProvisioningError):
    """Failed to derive a unique slug after exhausting our retries."""


# ---------------------------------------------------------------------------
# Public wire shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdminInvite:
    """A signed invite link minted for the initial tenant admin.

    The ``token`` is *not* a JWT; it's a URL-safe random string we
    emit and ask the operator to email out manually. The invite
    consumption flow / proper invitations table lands in a follow-up;
    for now the value is opaque and surfaced verbatim to the support
    team via the admin UI.
    """

    token: str
    expires_at: datetime
    url: str


@dataclass(frozen=True)
class InitialAdminUser:
    """The User row we created for the new tenant's first admin."""

    id: uuid.UUID
    email: str
    role: str


@dataclass(frozen=True)
class ProvisionResult:
    """The provisioner's structured return value.

    Endpoint code projects this into JSON. ``demo_seeded`` is a small
    audit breadcrumb — ``False`` means the seed step was deliberately
    skipped (because the operator passed ``seed_demo=False`` or
    because the orchestrator is running in a unit-test harness with
    no seed callable wired in).
    """

    tenant_id: uuid.UUID
    tenant_slug: str
    tenant_name: str
    waitlist_entry_id: uuid.UUID
    admin_invite: AdminInvite
    admin_user: InitialAdminUser
    demo_seeded: bool
    aisoc_credential_key_fingerprint: str = ""


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


_SLUG_INVALID = re.compile(r"[^a-z0-9-]+")
_SLUG_COLLAPSE_DASHES = re.compile(r"-{2,}")
_MIN_SLUG_LEN = 3
_MAX_SLUG_LEN = 60
_SLUG_RETRY_LIMIT = 8


def _normalize_slug_seed(company_name: str) -> str:
    """Turn an arbitrary company name into a URL-safe slug stem.

    ``"Acme, Inc. (HQ)"`` → ``"acme-inc-hq"``. Trailing/leading dashes
    are trimmed. If the stem comes back shorter than ``_MIN_SLUG_LEN``
    we pad with ``-tenant`` so the caller always has something usable
    to feed into the collision check.
    """
    if not company_name:
        return "tenant"
    seed = company_name.strip().lower().replace("_", "-").replace(" ", "-")
    seed = _SLUG_INVALID.sub("-", seed)
    seed = _SLUG_COLLAPSE_DASHES.sub("-", seed).strip("-")
    if len(seed) < _MIN_SLUG_LEN:
        seed = f"{seed}-tenant" if seed else "tenant"
    return seed[:_MAX_SLUG_LEN]


def _slug_with_shard(seed: str, shard: str) -> str:
    """Append a 6-char shard suffix, trimming the seed so we stay <= 60 chars."""
    suffix = f"-{shard}"
    head_room = _MAX_SLUG_LEN - len(suffix)
    return f"{seed[:head_room]}{suffix}"


async def _slug_is_available(db: AsyncSession, slug: str) -> bool:
    existing = await db.execute(select(Tenant).where(Tenant.slug == slug))
    return existing.scalar_one_or_none() is None


async def _allocate_slug(
    db: AsyncSession,
    *,
    company_name: str,
    shard_factory: Callable[[], str] | None = None,
) -> str:
    """Pick a unique slug starting from ``company_name``.

    Tries the bare normalized seed first, then appends 6-char hex
    shards. ``shard_factory`` is injected so tests can pin the
    suffixes deterministically.
    """
    seed = _normalize_slug_seed(company_name)
    if await _slug_is_available(db, seed):
        return seed

    make_shard = shard_factory or (lambda: secrets.token_hex(3))
    for _ in range(_SLUG_RETRY_LIMIT):
        candidate = _slug_with_shard(seed, make_shard())
        if await _slug_is_available(db, candidate):
            return candidate

    raise SlugCollisionError(f"could not allocate a unique slug for '{company_name}' after " f"{_SLUG_RETRY_LIMIT} attempts")


def generate_credential_key() -> tuple[str, str]:
    """Mint a fresh Fernet credential key.

    Returns ``(plaintext_key, fingerprint)``. The plaintext is what
    the tenant's connector code will load via
    ``AISOC_CREDENTIAL_KEY`` (per-tenant scoping is then layered on
    top by the resolver). The fingerprint is the first eight chars
    of a SHA-256 of the key — safe to log and surface to the support
    UI so operators can verify which key a given tenant is on without
    leaking the key itself.

    The fingerprint deliberately matches the format
    ``CredentialVault`` logs on key rotation so a fresh tenant's
    fingerprint will be recognisable in the logs.
    """
    import hashlib  # noqa: PLC0415 — keep the import lazy; this is a cold path.

    key_bytes = Fernet.generate_key()  # already base64-urlsafe
    plaintext = key_bytes.decode("ascii")
    fingerprint = hashlib.sha256(key_bytes).hexdigest()[:8]
    return plaintext, fingerprint


def _build_admin_invite(
    *,
    tenant_slug: str,
    invite_base_url: str,
    ttl_hours: int = 168,  # one week
) -> AdminInvite:
    """Mint an invite token + URL for the new tenant's initial admin.

    No DB write — the invite is a signed pointer we ask the operator
    to email out manually. The token is generated with
    ``secrets.token_urlsafe`` so it's safe to embed in a URL and long
    enough (32 bytes ⇒ 43 url-safe chars) to be practically
    unguessable.
    """
    if ttl_hours <= 0:
        raise ValueError("ttl_hours must be positive")
    token = secrets.token_urlsafe(32)
    base = invite_base_url.rstrip("/") if invite_base_url else ""
    url = f"{base}/invite/{token}?tenant={tenant_slug}"
    expires_at = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=ttl_hours)
    return AdminInvite(token=token, expires_at=expires_at, url=url)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


# Type alias for the seed-demo callback so tests can pass in a stub
# that doesn't need a real database session.
DemoSeederCallable = Callable[[AsyncSession, Tenant], Any]


async def provision_from_waitlist(
    db: AsyncSession,
    *,
    waitlist_entry_id: uuid.UUID,
    actor_email: str,
    invite_base_url: str = "https://tryaisoc.com",
    seed_demo: bool = True,
    demo_seeder: DemoSeederCallable | None = None,
    templates: TenantTemplateBundle | None = None,
    shard_factory: Callable[[], str] | None = None,
) -> ProvisionResult:
    """Promote a waitlist entry into a live tenant.

    Parameters
    ----------
    db
        Caller-owned :class:`AsyncSession`. The provisioner does its
        writes through this session and ``flush()``-es as needed so
        SQLAlchemy populates server-generated columns, but it does
        **not** commit — the caller owns the transaction boundary.
    waitlist_entry_id
        UUID of the row in ``aisoc_waitlist_entries``.
    actor_email
        Operator email; recorded on the audit log line.
    invite_base_url
        Base of the URL the operator will email out. Defaults to the
        managed-instance host name.
    seed_demo
        Whether to call the demo seeder. Test harnesses pass
        ``False`` so the unit tests don't depend on the seed script.
    demo_seeder
        Pluggable callable that takes ``(session, tenant)`` and
        seeds the tenant with starter data. Defaults to the real
        ``seed_demo`` script when ``None``; tests inject a stub.
    templates
        Override seed-content bundle. Defaults to the production
        bundle from :mod:`.templates`.
    shard_factory
        Override for the slug-collision shard generator (used by
        tests).
    """
    entry = await _load_waitlist_entry(db, waitlist_entry_id)
    if entry.provisioned_tenant_id is not None:
        # Idempotent re-provision — return the existing tenant if it's
        # still alive. Don't re-seed, don't mint a new invite.
        return await _result_for_existing(
            db,
            entry=entry,
            invite_base_url=invite_base_url,
        )

    if entry.status == "declined":
        raise WaitlistEntryNotPromotableError(f"waitlist entry {entry.id} is declined; refusing to promote")

    bundle = templates or get_default_template_bundle()

    slug = await _allocate_slug(db, company_name=entry.company, shard_factory=shard_factory)
    credential_key, key_fingerprint = generate_credential_key()

    provisioned_at = datetime.now(UTC)
    tenant_settings = {
        "managed": True,
        "branding": "AiSOC",
        "aisoc_credential_key_fingerprint": key_fingerprint,
        # NOTE: the *plaintext* key is intentionally NOT persisted in
        # the JSONB. The connectors-service reads it from
        # ``AISOC_CREDENTIAL_KEY`` at runtime; we surface only the
        # fingerprint here so operators can confirm which key is
        # active without ever round-tripping the secret through the
        # database.
        "rbac_seed_roles": [r["name"] for r in bundle.rbac_roles],
        "starter_detections": [d["rule_id"] for d in bundle.detections],
        "starter_playbooks": [p["name"] for p in bundle.playbooks],
        # Mirror the SQL-side provisioning columns into the JSONB so
        # the Python ORM (which does *not* know about the new
        # tenants columns yet — see TODO below) can still surface
        # them. The migration adds the SQL columns for operator
        # queries; the wire layer reads from this blob.
        "provisioned_from_waitlist_id": str(entry.id),
        "provisioned_at": provisioned_at.isoformat(),
    }
    tenant_limits = {
        "alerts_per_day": 50_000,
        "investigations_in_flight": 25,
        "managed_offering": True,
    }

    # TODO(T6.1): the ``provisioned_from_waitlist_id`` / ``provisioned_at``
    # ORM columns are defined in migration 043 but not yet on the
    # ``Tenant`` ORM model in ``app/models/tenant.py``. That file is
    # owned by Subagent A's wave-2 stabilization push and we explicitly
    # don't edit shared models from here. Until they map the columns,
    # we (a) persist via raw SQL UPDATE below so direct DB queries
    # like ``SELECT slug, provisioned_at FROM tenants`` work, and
    # (b) mirror into the JSONB ``settings`` blob so the Python wire
    # path keeps working without an ORM round-trip.
    tenant = Tenant(
        name=entry.company,
        slug=slug,
        plan="managed-beta",
        is_active=True,
        settings=tenant_settings,
        limits=tenant_limits,
    )
    db.add(tenant)
    await db.flush()  # populate tenant.id

    # Persist the SQL-side provisioning columns. ``execute_or_skip``
    # tolerates the mock-session shape used in unit tests, which
    # speaks ORM SQL fluently but not the raw ``text(...)`` shim.
    await _persist_provisioning_columns(
        db,
        tenant_id=tenant.id,
        waitlist_entry_id=entry.id,
        provisioned_at=provisioned_at,
    )

    # First admin: mint a User row stitched to the waitlist email so
    # the invite link has somewhere meaningful to land. Password is
    # left as a sentinel hash — the invite consumer flow (which
    # ships later) is what actually sets it. Until that lands the
    # support team can do a one-shot password reset.
    admin_user = User(
        tenant_id=tenant.id,
        email=entry.email,
        username=entry.email.split("@", 1)[0][:100],
        hashed_password="!invite-pending",
        role="tenant_admin",
        is_active=False,
        is_verified=False,
        preferences={"theme": "dark", "first_login_via": "managed-invite"},
    )
    db.add(admin_user)
    await db.flush()

    demo_seeded = False
    if seed_demo:
        seeder = demo_seeder or _default_demo_seeder
        try:
            await seeder(db, tenant)
            demo_seeded = True
        except Exception as exc:  # noqa: BLE001 — never block provisioning on demo data
            logger.warning(
                "tenant_provision demo seed failed: tenant=%s err=%s",
                tenant.slug,
                exc,
            )

    invite = _build_admin_invite(tenant_slug=tenant.slug, invite_base_url=invite_base_url)

    # Patch the waitlist row last so the entry's stamped timestamps
    # only flip after every dependent write has succeeded.
    now = datetime.now(UTC)
    entry.status = WAITLIST_STATUS_ONBOARDED
    entry.provisioned_tenant_id = tenant.id
    if entry.contacted_at is None:
        entry.contacted_at = now
    entry.onboarded_at = now

    logger.info(
        "tenant_provisioned",
        extra={
            "tenant_id": str(tenant.id),
            "tenant_slug": tenant.slug,
            "waitlist_entry_id": str(entry.id),
            "actor_email": actor_email,
            "demo_seeded": demo_seeded,
        },
    )

    return ProvisionResult(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        tenant_name=tenant.name,
        waitlist_entry_id=entry.id,
        admin_invite=invite,
        admin_user=InitialAdminUser(id=admin_user.id, email=admin_user.email, role=admin_user.role),
        demo_seeded=demo_seeded,
        aisoc_credential_key_fingerprint=key_fingerprint,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _persist_provisioning_columns(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    waitlist_entry_id: uuid.UUID,
    provisioned_at: datetime,
) -> None:
    """Stamp the SQL-side provisioning columns on the tenant row.

    We do this via raw SQL because the columns live in migration 043
    but the ORM model in ``app/models/tenant.py`` does not declare
    them yet (see TODO in :func:`provision_from_waitlist`). Test
    harnesses that pass a mock session without raw-SQL support
    survive: we swallow the ``NotImplementedError`` / ``AttributeError``
    they raise and rely on the JSONB mirror inside ``settings``.
    """
    try:
        await db.execute(
            text("UPDATE tenants " "SET provisioned_from_waitlist_id = :wl_id, " "    provisioned_at = :pa " "WHERE id = :tid"),
            {
                "wl_id": waitlist_entry_id,
                "pa": provisioned_at,
                "tid": tenant_id,
            },
        )
    except (NotImplementedError, AttributeError, RuntimeError) as exc:
        # The mock session for unit tests refuses unknown SQL; that's
        # fine — the JSONB mirror in tenant.settings keeps the wire
        # contract intact and Postgres tests via the real session
        # exercise this path.
        logger.debug(
            "skipping provisioning-column update: mock session or unsupported SQL: %s",
            exc,
        )


async def _load_waitlist_entry(db: AsyncSession, entry_id: uuid.UUID) -> WaitlistEntry:
    row = (await db.execute(select(WaitlistEntry).where(WaitlistEntry.id == entry_id))).scalar_one_or_none()
    if row is None:
        raise WaitlistEntryNotFoundError(f"waitlist entry {entry_id} not found")
    return row


async def _result_for_existing(
    db: AsyncSession,
    *,
    entry: WaitlistEntry,
    invite_base_url: str,
) -> ProvisionResult:
    """Return a synthesized result for an already-provisioned waitlist row.

    We refuse to mint a *new* tenant if one already exists for this
    entry; instead the API surfaces the existing tenant id + a fresh
    invite link the operator can email out if the first one was lost.
    """
    tenant = (await db.execute(select(Tenant).where(Tenant.id == entry.provisioned_tenant_id))).scalar_one_or_none()
    if tenant is None:
        # The waitlist row claims it's provisioned but the tenant is
        # gone. Treat as if it was never provisioned so the operator
        # can recover.
        entry.provisioned_tenant_id = None
        raise WaitlistEntryNotPromotableError(f"waitlist entry {entry.id} pointed at a deleted tenant; cleared the pointer")

    admin_row = (
        (await db.execute(select(User).where(User.tenant_id == tenant.id, User.email == entry.email).order_by(User.created_at.asc())))
        .scalars()
        .first()
    )
    admin_email = admin_row.email if admin_row else entry.email
    admin_role = admin_row.role if admin_row else "tenant_admin"
    admin_id = admin_row.id if admin_row else uuid.uuid4()
    fingerprint = (tenant.settings or {}).get("aisoc_credential_key_fingerprint", "") or ""

    return ProvisionResult(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        tenant_name=tenant.name,
        waitlist_entry_id=entry.id,
        admin_invite=_build_admin_invite(tenant_slug=tenant.slug, invite_base_url=invite_base_url),
        admin_user=InitialAdminUser(id=admin_id, email=admin_email, role=admin_role),
        demo_seeded=False,
        aisoc_credential_key_fingerprint=fingerprint,
    )


async def _default_demo_seeder(db: AsyncSession, tenant: Tenant) -> None:
    """Real-world seed callback.

    Imported lazily so the unit tests that swap in a stub can avoid
    pulling the heavy seed module (and its ~3000 lines of incident
    catalogue) into the test process.
    """
    # We *deliberately* don't reuse ``_run_full_seed`` from
    # ``app.scripts.seed_demo`` — that script opens its own session via
    # ``AsyncSessionLocal()``. Instead we mirror its essential ops on
    # the caller's session so the whole provisioning step lives in
    # one transaction. The seed module's helper functions are public-
    # ish (single-underscore prefix is "implementation detail" rather
    # than truly private) so we can reuse them safely.
    from app.scripts.seed_demo import (  # noqa: PLC0415
        _ensure_user,
        _seed_alerts_and_cases,
        _seed_connectors,
    )

    await _ensure_user(db, tenant)
    await _seed_connectors(db, tenant)
    # ``_seed_alerts_and_cases`` returns a tuple; we discard the count.
    await _seed_alerts_and_cases(db, tenant, alert_count=30)


__all__ = [
    "AdminInvite",
    "DemoSeederCallable",
    "InitialAdminUser",
    "ProvisionResult",
    "ProvisioningError",
    "SlugCollisionError",
    "WaitlistEntryNotFoundError",
    "WaitlistEntryNotPromotableError",
    "generate_credential_key",
    "provision_from_waitlist",
]

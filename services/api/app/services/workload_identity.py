"""Per-service credentials for service-to-service calls.

Depth plan item 8.2. ``workload_identities`` was created by migration 087
and read by nothing, so the only internal credential remained
``AISOC_SERVICE_TOKEN``: one string every internal caller presents.

What the shared token cannot do
-------------------------------
* **Attribution.** Every internal call is "a service". An audit trail that
  cannot say which service acted cannot answer the question an incident
  review asks first.
* **Scoping.** The ingest pipeline presents the same authority as the
  agents worker, so a leak anywhere is a leak everywhere.
* **Rotation.** Changing it means restarting every service at once, which
  is why nobody does it.

A workload identity fixes all three: the row names the service, carries
its own scope list, and holds a *previous* secret honoured until
``previous_expires_at`` so callers roll over on their own schedule.

What it deliberately does not change
------------------------------------
**The tenant still comes from a header, and is still mandatory.** A
workload credential identifies a service, not a tenant — the agents
container triages alerts for every tenant on the deployment. One shared
credential with no tenant is a cross-tenant read, so a caller that names
no tenant resolves to an empty scope and an empty scope refuses. That is
the same contract ``_resolve_service_principal`` already enforces for the
shared token, and this path reuses it rather than inventing a second one.

The secret is stored as a SHA-256 digest, never in the clear. It is high
entropy (192 bits from ``secrets.token_hex(24)``), so a digest is the
right primitive here and a password-stretching KDF would only add latency
to a credential checked on every internal request.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enterprise_iam import WorkloadIdentity

logger = logging.getLogger("aisoc.workload_identity")

#: Distinct from ``aisoc_`` so a workload secret is never mistaken for an
#: API key. It is a strict *extension* of the API-key prefix, which is the
#: trap: ``startswith("aisoc_")`` matches it too, so the authentication
#: path must test this one first. ``test_workload_identity.py`` pins that
#: ordering with an assertion rather than leaving it to a convention a
#: later edit can reorder away.
WORKLOAD_KEY_PREFIX = "aisoc_wl_"

#: How much of the secret is stored in the clear, for display and lookup.
#: ``aisoc_wl_`` plus seven hex characters.
_PREFIX_LENGTH = len(WORKLOAD_KEY_PREFIX) + 7

#: How long a superseded secret keeps working after a rotation. Long enough
#: for a rolling restart, short enough that a rotation prompted by a leak
#: actually ends the leak.
DEFAULT_ROTATION_GRACE = timedelta(hours=24)


def mint_workload_secret() -> tuple[str, str, str]:
    """``(secret, prefix, digest)`` for a new workload credential.

    The secret is returned once and never stored; only the digest and the
    prefix are persisted.
    """
    secret = f"{WORKLOAD_KEY_PREFIX}{secrets.token_hex(24)}"
    return secret, secret[:_PREFIX_LENGTH], hash_workload_secret(secret)


def hash_workload_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def is_workload_secret(token: str) -> bool:
    return token.startswith(WORKLOAD_KEY_PREFIX)


def _digest_matches(row: WorkloadIdentity, digest: str, *, now: datetime) -> bool:
    """Whether *digest* is this row's current secret, or its superseded one.

    Compared with :func:`hmac.compare_digest` rather than ``==``. Both
    values are already hashes, so a timing oracle leaks little, but this is
    a credential comparison and the cheap constant-time form is the one
    that does not have to be argued about.
    """
    if hmac.compare_digest(row.secret_hash, digest):
        return True
    if not row.previous_hash or not hmac.compare_digest(row.previous_hash, digest):
        return False
    # A superseded secret is only honoured inside its grace window, and a
    # row with no window is treated as expired rather than as unlimited:
    # "not set" must not be the most permissive state of a credential.
    expiry = row.previous_expires_at
    if expiry is None:
        return False
    return now < (expiry if expiry.tzinfo else expiry.replace(tzinfo=UTC))


async def authenticate_workload(db: AsyncSession, secret: str) -> WorkloadIdentity | None:
    """The identity this secret belongs to, or ``None``.

    ``None`` covers every refusal — unknown, revoked, expired, or a
    superseded secret past its grace window — because the caller turns all
    of them into the same 401. Distinguishing them in the response would
    tell an attacker which guesses were close.
    """
    if not is_workload_secret(secret):
        return None

    now = datetime.now(UTC)
    digest = hash_workload_secret(secret)
    rows = await db.execute(select(WorkloadIdentity).where(WorkloadIdentity.secret_prefix == secret[:_PREFIX_LENGTH]))

    for row in rows.scalars().all():
        if row.revoked_at is not None:
            continue
        if row.expires_at is not None:
            expiry = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
            if expiry <= now:
                continue
        if _digest_matches(row, digest, now=now):
            return row
    return None


async def touch(db: AsyncSession, identity_id: uuid.UUID) -> None:
    """Record that a credential was used, best effort.

    ``last_used_at`` is what tells an operator a credential they are about
    to revoke is actually dead. Failing the request because the write
    failed would turn a bookkeeping error into an outage, so this logs and
    returns.
    """
    try:
        row = await db.get(WorkloadIdentity, identity_id)
        if row is not None:
            row.last_used_at = datetime.now(UTC)
            await db.commit()
    except Exception as exc:  # noqa: BLE001 - bookkeeping must not deny a request
        await db.rollback()
        logger.warning("workload_identity.touch_failed: %s", str(exc).replace("\n", " ")[:200])


async def rotate(db: AsyncSession, row: WorkloadIdentity, *, grace: timedelta = DEFAULT_ROTATION_GRACE) -> str:
    """Issue a new secret, keeping the old one alive for *grace*.

    Returns the new secret, which is shown once. The caller commits.

    Rotation in place is the whole reason the ``previous_*`` columns exist:
    the only path before was create, update every caller, delete — which is
    downtime, so most deployments never rotated at all.
    """
    secret, prefix, digest = mint_workload_secret()
    row.previous_hash = row.secret_hash
    row.previous_expires_at = datetime.now(UTC) + grace
    row.secret_hash = digest
    row.secret_prefix = prefix
    return secret


def describe(row: WorkloadIdentity) -> dict[str, Any]:
    """The row as an API response. No secret material, ever."""
    return {
        "id": str(row.id),
        "service": row.service,
        "description": row.description,
        "scopes": list(row.scopes or []),
        "secret_prefix": row.secret_prefix,
        "rotation_pending_until": row.previous_expires_at.isoformat() if row.previous_expires_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }

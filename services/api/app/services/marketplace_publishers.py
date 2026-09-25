"""Publisher identity: who signed this, and may we say so.

``_get_registered_pub_key`` returned ``None`` unconditionally, with the
comment ``(stub — wire to DB)``. The consequence is worth stating exactly,
because it is not "signatures were weak": ``publish_plugin`` reads that
function, finds no key, and **skips verification entirely**, storing
``verified: False``. A submitted plugin could not be rejected for a bad
signature. The signing path existed end to end, was documented, had a CLI
command, and could never fail.

That matters most for what comes next. A marketplace that takes payment has
to be able to say which publisher a listing belongs to; paying people we
cannot identify for code we cannot attribute is not a feature gap, it is a
different product.

Three properties this module holds:

**A key is registered against a person, not a tenant.** Publishing is an
individual act and revocation has to be able to name one.

**Revocation is a timestamp, not a delete.** A signature made before
revocation stays explicable afterwards — "this was signed by a key we have
since revoked" is a different and more useful statement than "unknown key".

**Verification failing is different from no key being registered.** The first
is a rejection; the second is an unverified submission. Collapsing them is
how the stub above looked like a working control.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)


class PublisherKeyError(ValueError):
    """The supplied key is not a usable Ed25519 public key."""


@dataclass(frozen=True)
class RegisteredKey:
    id: uuid.UUID
    publisher_id: uuid.UUID
    public_key_pem: str
    fingerprint: str
    label: str


def parse_public_key(pem: str) -> tuple[Ed25519PublicKey, str]:
    """Validate a PEM Ed25519 public key and return it with its fingerprint.

    Rejecting a non-Ed25519 key here rather than at verification time means a
    publisher finds out while registering, not when their first release is
    silently unverifiable.
    """
    try:
        loaded = serialization.load_pem_public_key(pem.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — any parse failure is the same answer
        raise PublisherKeyError("not a valid PEM public key") from exc

    if not isinstance(loaded, Ed25519PublicKey):
        raise PublisherKeyError("only Ed25519 public keys are accepted")

    der = loaded.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return loaded, hashlib.sha256(der).hexdigest()


async def ensure_publisher(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    display_name: str,
    contact_email: str,
) -> uuid.UUID:
    """Return this user's publisher id, creating an unverified one if needed."""
    row = (
        await db.execute(
            text("SELECT id FROM marketplace_publishers WHERE tenant_id = :tenant_id AND user_id = :user_id"),
            {"tenant_id": str(tenant_id), "user_id": str(user_id)},
        )
    ).first()
    if row is not None:
        return uuid.UUID(str(row[0]))

    created = (
        await db.execute(
            text(
                "INSERT INTO marketplace_publishers "
                "(tenant_id, user_id, display_name, contact_email) "
                "VALUES (:tenant_id, :user_id, :display_name, :contact_email) "
                "RETURNING id"
            ),
            {
                "tenant_id": str(tenant_id),
                "user_id": str(user_id),
                "display_name": display_name[:200],
                "contact_email": contact_email[:320],
            },
        )
    ).first()
    await db.commit()
    return uuid.UUID(str(created[0]))


async def register_key(
    db: AsyncSession,
    *,
    publisher_id: uuid.UUID,
    public_key_pem: str,
    label: str = "",
) -> RegisteredKey:
    _, fingerprint = parse_public_key(public_key_pem)

    row = (
        await db.execute(
            text(
                "INSERT INTO marketplace_publisher_keys "
                "(publisher_id, public_key_pem, fingerprint, label) "
                "VALUES (:publisher_id, :pem, :fingerprint, :label) "
                "ON CONFLICT (fingerprint) DO UPDATE SET label = EXCLUDED.label "
                "RETURNING id, publisher_id, public_key_pem, fingerprint, label"
            ),
            {
                "publisher_id": str(publisher_id),
                "pem": public_key_pem,
                "fingerprint": fingerprint,
                "label": label[:120],
            },
        )
    ).first()
    await db.commit()
    return RegisteredKey(
        id=uuid.UUID(str(row[0])),
        publisher_id=uuid.UUID(str(row[1])),
        public_key_pem=str(row[2]),
        fingerprint=str(row[3]),
        label=str(row[4]),
    )


async def revoke_key(db: AsyncSession, *, publisher_id: uuid.UUID, fingerprint: str) -> bool:
    result = await db.execute(
        text(
            "UPDATE marketplace_publisher_keys SET revoked_at = now() "
            "WHERE publisher_id = :publisher_id AND fingerprint = :fingerprint "
            "AND revoked_at IS NULL"
        ),
        {"publisher_id": str(publisher_id), "fingerprint": fingerprint},
    )
    await db.commit()
    return bool(result.rowcount)


async def active_keys(db: AsyncSession, *, publisher_id: uuid.UUID) -> list[RegisteredKey]:
    rows = (
        await db.execute(
            text(
                "SELECT id, publisher_id, public_key_pem, fingerprint, label "
                "FROM marketplace_publisher_keys "
                "WHERE publisher_id = :publisher_id AND revoked_at IS NULL "
                "ORDER BY created_at"
            ),
            {"publisher_id": str(publisher_id)},
        )
    ).fetchall()
    return [
        RegisteredKey(
            id=uuid.UUID(str(r[0])),
            publisher_id=uuid.UUID(str(r[1])),
            public_key_pem=str(r[2]),
            fingerprint=str(r[3]),
            label=str(r[4]),
        )
        for r in rows
    ]


async def keys_for_user(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
) -> list[RegisteredKey]:
    """Every active key this user can sign with. Empty is a normal state."""
    rows = (
        await db.execute(
            text(
                "SELECT k.id, k.publisher_id, k.public_key_pem, k.fingerprint, k.label "
                "FROM marketplace_publisher_keys k "
                "JOIN marketplace_publishers p ON p.id = k.publisher_id "
                "WHERE p.tenant_id = :tenant_id AND p.user_id = :user_id "
                "AND k.revoked_at IS NULL ORDER BY k.created_at"
            ),
            {"tenant_id": str(tenant_id), "user_id": str(user_id)},
        )
    ).fetchall()
    return [
        RegisteredKey(
            id=uuid.UUID(str(r[0])),
            publisher_id=uuid.UUID(str(r[1])),
            public_key_pem=str(r[2]),
            fingerprint=str(r[3]),
            label=str(r[4]),
        )
        for r in rows
    ]


def verify_against(keys: list[RegisteredKey], payload: bytes, signature: bytes) -> str | None:
    """Return the fingerprint of the key that verified, or None.

    Tries every active key because a publisher rotating keys will have two
    valid ones for a while, and forcing them to re-sign everything during a
    rotation is how rotations get skipped.
    """
    for key in keys:
        try:
            public_key, _ = parse_public_key(key.public_key_pem)
            public_key.verify(signature, payload)
            return key.fingerprint
        except Exception:  # noqa: BLE001, S112 — a key that does not verify is the normal case here
            continue
    return None

"""Reconcile this service's string tenancy with the platform's UUID tenancy.

Two tenancy models met here and neither knew about the other.

The platform keys everything on a tenant UUID. This service stores
``tenant_id`` as a ``String(64)`` and enrols every node under the literal
``"default"`` unless the agent sends an ``X-AiSOC-Tenant`` header. Nothing
translated between them, so FIM events landed under the string ``"default"``
while the console asked for them under a UUID, and the FIM surface returned
nothing for every real tenant — a table that is empty because the write and
the read disagree, not because nothing happened.

The trap, which is why the obvious fix does not work: migration ``001`` seeds
the canonical tenant with slug ``default``, but the demo seed **renames that
slug to ``demo``**. So resolving the literal ``"default"`` by slug matches
nothing on any deployment that has been seeded, and matching by UUID never
worked because ``"default"`` is not one. Anything keyed on that literal
silently no-ops.

The fix is the one already established in
``services/agents/app/investigator/ledger.py::_resolve_tenant_id``: the
placeholder resolves to the canonical seed tenant by its **stable UUID**,
ignoring whatever its slug has been renamed to, and falls back to the sole
tenant in a single-tenant install. A genuinely unknown ref still resolves to
``None`` — the placeholder is not a wildcard, and "I could not tell which
tenant" must never become "all of them".

Skips are logged at ``warning`` with the ref, not at ``debug``. A silent skip
at debug level is how the original bug survived: the writes simply stopped and
the logs said nothing an operator would ever look at.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.osquery_tls.tenant")

#: The canonical seed tenant (migration 001). The demo seed renames its slug
#: from 'default' to 'demo'; this UUID is stable either way.
CANONICAL_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")

#: Refs that mean "the caller did not say" rather than naming a tenant.
PLACEHOLDER_TENANT_REFS = frozenset({"", "default", "none", "null"})


async def resolve_tenant_uuid(db: AsyncSession, tenant_ref: str | None) -> uuid.UUID | None:
    """Resolve a UUID string, slug, or name to the canonical tenant UUID.

    Returns ``None`` when the ref names no tenant this deployment knows, or
    when the placeholder is ambiguous (several tenants, none canonical).
    Callers must treat ``None`` as a refusal, never as "any tenant".

    This reads ``tenants``, which lives in the platform database this service
    shares (``DATABASE_URL`` points at the same ``aisoc`` database as the API).
    If that table is not reachable the answer is a refusal with a named
    reason, not a guess and not a 500 — an operator who pointed this service
    at a standalone database needs to be told that, and the alternative
    (falling back to the ``"default"`` string) is the bug this module exists
    to fix.
    """
    try:
        return await _resolve(db, tenant_ref)
    except SQLAlchemyError as exc:
        logger.warning(
            "osquery_tls.tenant_table_unreachable ref=%r error=%s — "
            "this service reads `tenants` from the shared platform database; "
            "check DATABASE_URL points at it",
            str(tenant_ref or "").replace("\r", "").replace("\n", " ")[:64],
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
        return None


async def _resolve(db: AsyncSession, tenant_ref: str | None) -> uuid.UUID | None:
    ref = (tenant_ref or "").strip()

    # 1. An explicit UUID is trusted as-is — but only if it names a real
    #    tenant. Accepting an arbitrary UUID would let an enrolling node
    #    invent a tenant that no row anywhere else shares.
    try:
        candidate = uuid.UUID(ref)
    except (ValueError, TypeError):
        candidate = None
    if candidate is not None:
        row = (await db.execute(text("SELECT id FROM tenants WHERE id = :tid"), {"tid": str(candidate)})).first()
        if row:
            return candidate
        logger.warning("osquery_tls.tenant_unknown_uuid ref=%s", str(candidate).replace("\r", "").replace("\n", " ")[:64])
        return None

    # 2. Exact slug / name match.
    row = (await db.execute(text("SELECT id FROM tenants WHERE slug = :ref OR name = :ref LIMIT 1"), {"ref": ref})).first()
    if row:
        return uuid.UUID(str(row[0]))

    # 3. Placeholder → the canonical seed tenant by stable UUID, else the sole
    #    tenant of a single-tenant install.
    if ref.lower() in PLACEHOLDER_TENANT_REFS:
        row = (await db.execute(text("SELECT id FROM tenants WHERE id = :tid"), {"tid": str(CANONICAL_TENANT_ID)})).first()
        if row:
            return CANONICAL_TENANT_ID
        rows = (await db.execute(text("SELECT id FROM tenants LIMIT 2"))).all()
        if len(rows) == 1:
            return uuid.UUID(str(rows[0][0]))
        logger.warning(
            "osquery_tls.tenant_placeholder_ambiguous ref=%r tenant_count=%d — refusing to guess",
            # `ref` arrives on the X-AiSOC-Tenant header, so it is sanitised
            # inline at the call site where CodeQL can see the property.
            str(ref).replace("\r", "").replace("\n", " ")[:64],
            len(rows),
        )
        return None

    logger.warning("osquery_tls.tenant_unknown_ref ref=%r", str(ref).replace("\r", "").replace("\n", " ")[:64])
    return None


async def resolve_tenant_key(db: AsyncSession, tenant_ref: str | None) -> str | None:
    """:func:`resolve_tenant_uuid` as the string this service stores.

    Node, FIM-event and pack-assignment rows key on ``String(64)``. Storing
    the canonical UUID's string form — rather than ``"default"`` — is what
    lets the console query this service with the same tenant identifier it
    uses everywhere else.
    """
    resolved = await resolve_tenant_uuid(db, tenant_ref)
    return str(resolved) if resolved is not None else None

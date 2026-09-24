"""Resolve warehouse credentials from the tenant's own connector instances.

Why this module exists
~~~~~~~~~~~~~~~~~~~~~~

Before it, every event-warehouse provider resolved its credentials from
process-wide settings: ``settings.ES_URL`` / ``ES_API_KEY`` for
Elasticsearch, ``SPLUNK_URL`` / ``SPLUNK_HMAC_TOKEN`` for Splunk,
``CHRONICLE_PROJECT_ID`` for Chronicle.

None of those names are declared fields on :class:`app.core.config.Settings`.
They were read through ``getattr(settings, "ES_URL", None)``, so the miss
produced no error and no warning — and because ``Settings`` is configured
with ``extra="ignore"``, an operator who read the resulting message and
exported ``ES_URL`` still got nothing: pydantic-settings discards an
undeclared variable and the same message repeats. Every scheduled hunt on
every deployment therefore returned zero hits, and the scheduler logged the
skip at INFO.

Meanwhile the platform already stores exactly these credentials, in the
place a user can actually reach: the ``connectors`` table, one row per
tenant per instance, secrets encrypted by :class:`CredentialVault`, written
by the connector wizard in the console. ``federated.py`` and
``case_fanout.py`` both resolve from there.

This module is the join. A hunt belongs to a tenant; the tenant connects a
SIEM through the UI; the hunt runs against that SIEM. No environment
variable, no operator, no redeploy.

Multi-tenancy consequence
~~~~~~~~~~~~~~~~~~~~~~~~~

Resolving from settings meant one global cluster for every tenant on the
deployment. A managed provider running twenty customers could not point
each one at their own SIEM even in principle. Resolving from the connector
row makes the warehouse per-tenant by construction, which is what the rest
of the platform already assumes.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault

from .base import HuntNotConfigured, WarehouseCredentials

logger = logging.getLogger(__name__)

__all__ = [
    "connected_warehouse_types",
    "resolve_tenant_warehouse",
]


def _select_enabled(tenant_id: uuid.UUID, connector_types: tuple[str, ...]):
    """Tenant-scoped, enabled-only query for the given connector types.

    Ordered by ``created_at`` then ``id`` so a tenant with two Elastic
    clusters gets a stable choice rather than whichever row the planner
    happened to return first. ``id`` breaks the tie because ``created_at``
    has second granularity in practice and two connectors added from the
    same wizard session can share it.
    """
    return (
        select(Connector)
        .where(
            Connector.tenant_id == tenant_id,
            Connector.is_enabled.is_(True),
            Connector.connector_type.in_(connector_types),
        )
        .order_by(Connector.created_at.asc(), Connector.id.asc())
    )


async def connected_warehouse_types(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    candidate_types: tuple[str, ...],
) -> set[str]:
    """Connector types among ``candidate_types`` this tenant has enabled.

    The provider registry uses this to pick a driver by what the tenant
    actually connected. Selecting by translation availability alone always
    chose Elasticsearch, because the translator emits ES|QL, SPL and KQL for
    every question — so a Splunk-only tenant was routed to a cluster they do
    not have.
    """
    if not candidate_types:
        return set()
    rows = (await db.execute(_select_enabled(tenant_id, candidate_types))).scalars().all()
    return {row.connector_type for row in rows}


async def resolve_tenant_warehouse(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    connector_types: tuple[str, ...],
    connector_id: uuid.UUID | None = None,
) -> WarehouseCredentials:
    """Return decrypted credentials for this tenant's warehouse instance.

    ``connector_id`` pins a specific instance (used when a caller names the
    cluster to run against); it is still filtered by ``tenant_id``, so
    naming another tenant's connector resolves to nothing rather than to
    their credentials.

    Raises :class:`HuntNotConfigured` when the tenant has connected no
    matching source, or when the stored secret cannot be decrypted. Both are
    soft-skip conditions for the scheduler, but they are distinguishable in
    the message so an operator can tell "nobody connected a SIEM" from "the
    vault key changed and the stored secret is unreadable" — the previous
    code could only ever say the former.
    """
    stmt = _select_enabled(tenant_id, connector_types)
    if connector_id is not None:
        stmt = stmt.where(Connector.id == connector_id)

    connector = (await db.execute(stmt)).scalars().first()
    if connector is None:
        pinned = f" (id={connector_id})" if connector_id else ""
        raise HuntNotConfigured(
            f"no enabled connector of type {sorted(connector_types)}{pinned} for this tenant — "
            "connect one from the console under Connectors"
        )

    try:
        auth = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        # Deliberately does not include the ciphertext or key id.
        logger.warning(
            "event_warehouse.credentials.decrypt_failed connector=%s type=%s",
            connector.id,
            connector.connector_type,
        )
        raise HuntNotConfigured(f"stored credentials for connector {connector.name!r} could not be decrypted: {exc}") from exc

    return WarehouseCredentials(
        connector_id=connector.id,
        connector_type=connector.connector_type,
        connector_name=connector.name,
        auth=auth if isinstance(auth, dict) else {},
        config=connector.connector_config or {},
    )

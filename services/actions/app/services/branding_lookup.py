"""What an operator's product is called, for the ChatOps prompt.

A **read path only**, deliberately. ``services/api`` owns the branding
schema, the write routes, the SVG sanitiser and the asset bytes; this reads
one column so the interactive approval prompt can say the operator's product
name instead of the platform's. Same split as the credential vault, where
``services/connectors`` ships a vendored ``decrypt_dict`` so the scheduler
can decrypt at poll time without owning the write path.

Only ``product_name``. The resolver in ``services/api`` returns colours, a
logo, support contacts and a footer; none of them has anywhere to go in a
Slack Block Kit payload or a Teams MessageCard, and resolving fields nobody
renders is how a second resolver starts drifting from the first.

Never raises. A branding lookup that failed would take down the approval
prompt it was decorating, and an approval that never reaches an analyst is a
worse outcome than one that reaches them under the platform's name.
"""

from __future__ import annotations

import os
from uuid import UUID

import structlog

logger = structlog.get_logger()

#: What an unbranded deployment calls itself. Mirrors ``DEFAULT_BRANDING``
#: in ``services/api/app/services/branding/resolver.py``.
DEFAULT_PRODUCT_NAME = "AiSOC"

# Resolves the owning organisation exactly as `owning_org_id` does, and in
# the same order: a managed customer is in `organization_tenants`, and the
# operator's own staff sign in to the organisation's `home_tenant_id`.
# Checking only the first leaves the operator's own prompts unbranded, which
# are the ones they see every day.
_QUERY = """
    SELECT product_name
    FROM aisoc_org_branding
    WHERE org_id = COALESCE(
        (SELECT org_id FROM organization_tenants WHERE tenant_id = $1),
        (SELECT id FROM organizations WHERE home_tenant_id = $1)
    )
"""


def _dsn() -> str | None:
    """An asyncpg-compatible DSN, or None when no database is configured.

    Accepts the SQLAlchemy spelling the API uses as well as the plain form,
    because both are already present in deployed environments. Copied from
    ``tenant_policy`` rather than imported so this module stays a leaf.
    """
    raw = (os.environ.get("DATABASE_DSN") or os.environ.get("DATABASE_URL") or "").strip()
    if not raw:
        return None
    return raw.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def product_name_for_tenant(tenant_id: str | UUID | None) -> str:
    """The product name to show this tenant, or the platform default.

    The default is returned for every "we could not tell" case -- no
    database, no tenant, no organisation, no branding row, an empty column,
    or a failed read -- because each of them means the same thing to the
    person reading the message: nobody has configured a name.
    """
    if tenant_id is None:
        return DEFAULT_PRODUCT_NAME
    dsn = _dsn()
    if not dsn:
        return DEFAULT_PRODUCT_NAME

    try:
        import asyncpg  # noqa: PLC0415 — optional at import time; only needed with a DSN

        conn = await asyncpg.connect(dsn, timeout=5.0)
        try:
            name = await conn.fetchval(_QUERY, UUID(str(tenant_id)))
        finally:
            await conn.close()
    except Exception as exc:  # noqa: BLE001 - see the module docstring
        logger.warning("branding_lookup.unavailable", error=str(exc)[:200])
        return DEFAULT_PRODUCT_NAME

    return (name or "").strip() or DEFAULT_PRODUCT_NAME

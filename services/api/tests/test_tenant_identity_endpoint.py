"""Unit tests for the tenant identity endpoint (Workstream 5 — SOC console parity).

The ``GET /api/v1/tenants/me/identity`` handler returns a minimal projection
of the current user's tenant (id, name, mssp_role, parent_tenant_id) without
requiring the ``settings:read`` permission. It is the data source for the
TopBar tenant switcher pill and role badge in the SOC console.

What we exercise here:

* Happy path: a known tenant row maps cleanly to ``TenantHeaderResponse``
  with every privileged field (``plan``, ``settings``, ``limits``) omitted.
* MSSP parent + child both round-trip — the ``mssp_role`` and
  ``parent_tenant_id`` fields make it through ``model_validate``.
* Missing tenant raises ``HTTPException`` 404 instead of leaking ``None``
  or a 500.
* The endpoint does not require ``settings:read`` (verified by *not*
  threading any permission stub — the test calls the function directly).

Like the other endpoint tests in this folder
(``test_llm_credentials_endpoint.py``, ``test_saved_views_endpoint.py``), we
avoid spinning up the full FastAPI app + Postgres. We stub the DB session
with a ``MagicMock`` and assert the contract the handler must keep.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.tenants import (
    TenantHeaderResponse,
    get_my_tenant_identity,
)
from app.models.tenant import Tenant
from fastapi import HTTPException


def _build_tenant(
    *,
    tenant_id: uuid.UUID | None = None,
    name: str = "Acme Corp",
    mssp_role: str | None = None,
    parent_tenant_id: uuid.UUID | None = None,
) -> Tenant:
    """Return a hydrated ``Tenant`` ORM instance (no DB session needed)."""

    tenant = Tenant()
    tenant.id = tenant_id or uuid.uuid4()
    tenant.name = name
    tenant.slug = "acme-corp"
    tenant.plan = "enterprise"
    tenant.is_active = True
    tenant.settings = {"super_secret": "should-not-leak"}
    tenant.limits = {"alerts_per_day": 100_000}
    tenant.mssp_role = mssp_role
    tenant.parent_tenant_id = parent_tenant_id
    tenant.created_at = datetime.now(UTC)
    tenant.updated_at = datetime.now(UTC)
    return tenant


def _build_user(tenant_id: uuid.UUID) -> SimpleNamespace:
    """Minimal CurrentUser stand-in. The endpoint only reads ``tenant_id``."""
    return SimpleNamespace(tenant_id=tenant_id, user_id=uuid.uuid4(), role="soc_analyst")


def _build_db(tenant: Tenant | None) -> MagicMock:
    """Build an AsyncMock-backed DB session whose query returns ``tenant``."""
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = tenant
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.mark.asyncio
async def test_identity_returns_minimal_projection() -> None:
    """Happy path: standalone tenant — only the four allow-listed fields make it out."""
    tid = uuid.uuid4()
    tenant = _build_tenant(tenant_id=tid, name="Acme Corp")
    user = _build_user(tenant_id=tid)
    db = _build_db(tenant)

    out = await get_my_tenant_identity(current_user=user, db=db)

    assert isinstance(out, TenantHeaderResponse)
    assert out.id == tid
    assert out.name == "Acme Corp"
    assert out.mssp_role is None
    assert out.parent_tenant_id is None

    # Privileged fields must NOT be exposed on this endpoint.
    payload = out.model_dump()
    for forbidden in ("plan", "settings", "limits", "slug", "is_active"):
        assert forbidden not in payload, f"{forbidden!r} leaked into TenantHeaderResponse"


@pytest.mark.asyncio
async def test_identity_returns_mssp_parent() -> None:
    """MSSP parent: ``mssp_role='parent'`` makes it through verbatim."""
    tid = uuid.uuid4()
    tenant = _build_tenant(tenant_id=tid, name="Acme MSSP", mssp_role="parent")
    user = _build_user(tenant_id=tid)
    db = _build_db(tenant)

    out = await get_my_tenant_identity(current_user=user, db=db)

    assert out.id == tid
    assert out.name == "Acme MSSP"
    assert out.mssp_role == "parent"
    assert out.parent_tenant_id is None


@pytest.mark.asyncio
async def test_identity_returns_mssp_child_with_parent_link() -> None:
    """MSSP child: parent linkage is preserved so the UI can render the breadcrumb."""
    parent_id = uuid.uuid4()
    tid = uuid.uuid4()
    tenant = _build_tenant(
        tenant_id=tid,
        name="Acme Subsidiary A",
        mssp_role="child",
        parent_tenant_id=parent_id,
    )
    user = _build_user(tenant_id=tid)
    db = _build_db(tenant)

    out = await get_my_tenant_identity(current_user=user, db=db)

    assert out.id == tid
    assert out.mssp_role == "child"
    assert out.parent_tenant_id == parent_id


@pytest.mark.asyncio
async def test_identity_raises_404_when_tenant_missing() -> None:
    """If the JWT references a tenant that no longer exists, we surface a clean 404."""
    user = _build_user(tenant_id=uuid.uuid4())
    db = _build_db(None)

    with pytest.raises(HTTPException) as excinfo:
        await get_my_tenant_identity(current_user=user, db=db)

    assert excinfo.value.status_code == 404
    assert "Tenant not found" in excinfo.value.detail

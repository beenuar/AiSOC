"""RBAC regression tests for the /threat-intel endpoints (Issue #13).

The threat-intel surface (IOCs, threat actors, intel feeds) is shared
across a tenant. In an MSSP / multi-tenant deployment, an analyst with
``viewer`` permissions must NOT be able to:

* create IOCs (a malicious analyst could poison detections by injecting
  false positives or whitelisting attacker infrastructure);
* delete IOCs/feeds (could blind detections by removing the IOCs that
  actually fire on the attacker traffic);
* create or modify threat-actor profiles (used by the attribution
  engine; bad data here surfaces in customer-visible briefings).

Before this fix the endpoints in
``app.api.v1.endpoints.threat_intel`` only required *authentication*
(``get_current_user``), not the ``threat_intel:write`` *permission*.
That meant any role that could log in (e.g. ``viewer``, ``soc_analyst``,
``api_service``) could create or delete IOCs.

These tests pin three things so the security gate cannot regress:

1. The static ``ROLE_PERMISSIONS`` map grants ``threat_intel:write``
   only to roles that should hold it (admin/tenant_admin/soc_lead/threat_hunter).
2. ``CurrentUser.require_permission`` raises HTTP 403 for under-privileged
   roles trying to perform write actions.
3. ``CurrentUser.require_permission`` permits the privileged roles.

We exercise (2) and (3) at the dependency layer, not by spinning up the
full FastAPI app, because the permission semantics are fully owned by
``app.api.v1.deps.CurrentUser`` and ``app.core.security.has_permission``.
That keeps the test hermetic (no DB, no app lifespan) while still
catching the real regression: removing the ``require_permission(...)``
``Depends`` from ``threat_intel.py``.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.core.security import ROLE_PERMISSIONS, has_permission
from fastapi import HTTPException

# ─── Static role-permission map (the source of truth) ────────────────────


WRITE_ROLES = ("admin", "platform_admin", "tenant_admin", "soc_lead", "threat_hunter")
READ_ONLY_ROLES = ("soc_analyst", "viewer", "api_service")


@pytest.mark.parametrize("role", WRITE_ROLES)
def test_write_roles_have_threat_intel_write(role: str) -> None:
    """Roles that own the threat-intel surface must hold :write.

    Removing :write from any of these roles would silently downgrade
    the role to read-only across the whole API, which is exactly the
    kind of change that would slip through code review.
    """
    assert has_permission(role, "threat_intel:write"), (
        f"Role {role!r} lost threat_intel:write — this is a permission "
        "regression. Either restore it in app.core.security.ROLE_PERMISSIONS "
        "or update WRITE_ROLES in this test."
    )


@pytest.mark.parametrize("role", READ_ONLY_ROLES)
def test_read_only_roles_lack_threat_intel_write(role: str) -> None:
    """Lower-privileged roles must NOT be able to mutate threat-intel.

    This is the core of the MSSP RBAC fix: a ``viewer`` or
    ``soc_analyst`` token must be rejected by the write endpoints even
    though it authenticates successfully.
    """
    assert not has_permission(role, "threat_intel:write"), (
        f"Role {role!r} unexpectedly has threat_intel:write. If this is "
        "intentional, update READ_ONLY_ROLES; otherwise this is the "
        "MSSP-RBAC vulnerability returning."
    )


@pytest.mark.parametrize("role", WRITE_ROLES + READ_ONLY_ROLES)
def test_all_known_roles_can_read_threat_intel(role: str) -> None:
    """Every legitimate role must keep :read.

    Read access is required for the alerts UI to display IOC enrichment
    inline. If we ever drop :read from a role we should know about it
    here, not from a 403 in the browser.
    """
    assert has_permission(
        role, "threat_intel:read"
    ), f"Role {role!r} lost threat_intel:read — this would break the alerts UI (IOC enrichment renders inline)."


def test_role_permissions_map_covers_every_role_under_test() -> None:
    """Sanity check: the test parameters track the real role list.

    If someone adds a new role to ROLE_PERMISSIONS but forgets to
    classify it as write or read-only here, this test fails loudly
    instead of silently leaving the new role unaudited.
    """
    real_roles = set(ROLE_PERMISSIONS) - {"admin", "platform_admin"}
    audited_roles = set(WRITE_ROLES + READ_ONLY_ROLES) - {"admin", "platform_admin"}
    missing = real_roles - audited_roles
    assert (
        not missing
    ), f"New role(s) {missing} added to ROLE_PERMISSIONS without RBAC test coverage. Add them to WRITE_ROLES or READ_ONLY_ROLES."


# ─── CurrentUser.require_permission integration ──────────────────────────


def _user(role: str, scopes: list[str] | None = None) -> CurrentUser:
    """Construct a CurrentUser without touching the DB or JWT plumbing."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role=role,
        email=f"{role}@example.test",
        scopes=scopes,
    )


@pytest.mark.parametrize("role", READ_ONLY_ROLES)
def test_require_permission_blocks_read_only_roles_from_write(role: str) -> None:
    """The dependency layer must 403 read-only roles trying to write.

    This mirrors what FastAPI does when ``Depends(require_permission(
    "threat_intel:write"))`` runs against a viewer token.
    """
    user = _user(role)
    with pytest.raises(HTTPException) as exc:
        user.require_permission("threat_intel:write")
    assert exc.value.status_code == 403
    assert "threat_intel:write" in exc.value.detail


@pytest.mark.parametrize("role", WRITE_ROLES)
def test_require_permission_allows_write_roles(role: str) -> None:
    """The dependency layer must allow privileged roles through.

    ``require_permission`` returns ``None`` on success; we assert it
    does not raise.
    """
    user = _user(role)
    user.require_permission("threat_intel:write")  # must not raise


@pytest.mark.parametrize("role", READ_ONLY_ROLES + WRITE_ROLES)
def test_require_permission_allows_read_for_all_legitimate_roles(role: str) -> None:
    user = _user(role)
    user.require_permission("threat_intel:read")  # must not raise


# ─── API-key scope path ──────────────────────────────────────────────────


def test_api_key_scoped_read_cannot_write() -> None:
    """A scoped API key with only :read must be 403'd on :write.

    API keys carry an explicit scope list (``CurrentUser.scopes``); the
    role field is ignored on that path. This test pins the contract that
    a key issued with ``threat_intel:read`` cannot escalate by being
    used against a write endpoint.
    """
    key = _user(role="api_service", scopes=["threat_intel:read"])
    with pytest.raises(HTTPException) as exc:
        key.require_permission("threat_intel:write")
    assert exc.value.status_code == 403
    assert "API key missing scope" in exc.value.detail


def test_api_key_scoped_write_can_write() -> None:
    key = _user(role="api_service", scopes=["threat_intel:write"])
    key.require_permission("threat_intel:write")  # must not raise


def test_api_key_wildcard_scope_can_write() -> None:
    """``"*"`` is the all-access scope used by platform-internal keys."""
    key = _user(role="api_service", scopes=["*"])
    key.require_permission("threat_intel:write")  # must not raise


def test_api_key_resource_wildcard_scope_can_write() -> None:
    """``threat_intel:*`` covers every action under the resource."""
    key = _user(role="api_service", scopes=["threat_intel:*"])
    key.require_permission("threat_intel:write")  # must not raise


# ─── Cross-tenant isolation guardrail (defense in depth) ─────────────────


def test_threat_intel_endpoint_module_uses_require_permission() -> None:
    """Source-level guardrail: imports must include the RBAC dependency.

    If a future refactor accidentally drops the ``require_permission``
    import from ``threat_intel.py`` (the failure mode that originally
    caused this issue), this test fails before any HTTP traffic does.
    """
    import inspect

    from app.api.v1.endpoints import threat_intel

    src = inspect.getsource(threat_intel)
    assert (
        "require_permission" in src
    ), "threat_intel.py no longer references require_permission — the MSSP RBAC gate has been removed. See Issue #13."
    assert 'require_permission("threat_intel:write")' in src, (
        "threat_intel.py no longer gates on threat_intel:write. "
        "Write endpoints (POST/DELETE on /iocs, /actors, /feeds) must "
        "stay behind that permission."
    )
    assert 'require_permission("threat_intel:read")' in src, (
        "threat_intel.py no longer gates on threat_intel:read. "
        "Even read endpoints should require the permission so a token "
        "that lacks it (e.g. a future limited role) is denied loudly."
    )

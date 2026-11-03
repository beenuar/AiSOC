"""The service principal may raise an approval, and may not answer one.

A playbook ``approval`` step needs the agents service to open an approval for a
human to decide. It reaches ``POST /api/v1/approvals`` on the shared service
token, whose permission set is a deliberately short read-only list — so the
route answered ``403 Permission denied: cases:write`` even once the token name
and the tenant header were right, and the run suspended against an approval that
did not exist.

The grant is ``approvals:write``, not ``cases:write``. That distinction is the
subject of this file, because the cheap fix — dropping ``cases:write`` into
``SERVICE_PRINCIPAL_PERMISSIONS`` — would have handed one credential that is
valid on every route for every tenant the whole case write surface, including
the comment authoring that GHSA-9mc5-hqgh-j6wf was about.

Two properties, and the second is the one that keeps the first honest:
nobody lost access (every role that held ``cases:write`` holds the new
permission), and the service still cannot *decide* an approval it raised.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.deps import SERVICE_PRINCIPAL_PERMISSIONS, CurrentUser
from app.core.security import ROLE_PERMISSIONS
from fastapi import HTTPException

APPROVAL_WRITE = "approvals:write"
CASES_WRITE = "cases:write"


def _service_principal() -> CurrentUser:
    """Built the way ``_resolve_service_principal`` builds it."""
    tenant = uuid.uuid4()
    return CurrentUser(
        user_id=uuid.uuid5(uuid.NAMESPACE_URL, f"aisoc:service:{tenant}"),
        tenant_id=tenant,
        role="api_service",
        email=f"service@{tenant}.internal",
        resolved_permissions=SERVICE_PRINCIPAL_PERMISSIONS,
    )


def test_the_service_principal_may_raise_an_approval() -> None:
    """The defect: this raised ``403 Permission denied``."""
    _service_principal().require_permission(APPROVAL_WRITE)


def test_the_service_principal_may_not_decide_an_approval() -> None:
    """Separation of duties, and the reason the grant is not ``cases:write``.

    ``POST /approvals/{id}/decide`` requires ``cases:write``. A credential that
    could raise *and* answer its own approval would make the pause decorative.
    """
    with pytest.raises(HTTPException) as refusal:
        _service_principal().require_permission(CASES_WRITE)
    assert refusal.value.status_code == 403


def test_the_service_principal_did_not_gain_the_case_write_surface() -> None:
    """The narrowness itself, asserted rather than described."""
    assert CASES_WRITE not in SERVICE_PRINCIPAL_PERMISSIONS
    assert "cases:delete" not in SERVICE_PRINCIPAL_PERMISSIONS
    assert APPROVAL_WRITE in SERVICE_PRINCIPAL_PERMISSIONS


def test_no_role_lost_the_ability_to_open_an_approval() -> None:
    """Narrowing a route's permission takes access away unless the new one is granted.

    Every role that could create an approval before — because it held
    ``cases:write`` — must still be able to.
    """
    regressed = [
        role for role, perms in ROLE_PERMISSIONS.items() if CASES_WRITE in perms and APPROVAL_WRITE not in perms and "*" not in perms
    ]
    assert regressed == [], f"these roles can no longer open an approval: {regressed}"


def test_the_wildcard_roles_are_unaffected() -> None:
    """Control: a role holding ``*`` needs no explicit grant, and must not read as regressed."""
    for role in ("platform_admin", "admin"):
        assert ROLE_PERMISSIONS[role] == ["*"]

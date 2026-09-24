"""The writeback route's two identities, and the one that must fail closed.

A route that can change state in a customer's SIEM needs a caller. Two are
allowed: a session with ``alerts:write``, and the agents worker holding a
shared service token.

The failure mode being guarded is the familiar one — an unset shared secret
compared against an absent header, both empty, both equal. That turns an
internal route into an unauthenticated one, and here it would let anyone close
findings in any tenant's SIEM. An unset token disables the service path
instead.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.endpoints.alert_writeback import _resolve_caller, service_token_valid
from fastapi import HTTPException


class _User:
    def __init__(self, tenant_id: uuid.UUID, *, allowed: bool = True) -> None:
        self.tenant_id = tenant_id
        self.email = "analyst@example.invalid"
        self._allowed = allowed

    def require_permission(self, permission: str) -> None:
        if not self._allowed:
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")


def test_unset_token_disables_the_service_path(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    assert service_token_valid(None) is False
    assert service_token_valid("") is False
    # The specific trap: both sides empty must not compare equal.
    assert service_token_valid("   ") is False


def test_empty_configured_token_never_matches_an_empty_header(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "   ")
    assert service_token_valid("") is False
    assert service_token_valid("   ") is False


def test_configured_token_matches_exactly(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "shared-secret-value")
    assert service_token_valid("shared-secret-value") is True
    assert service_token_valid("shared-secret-valu") is False
    assert service_token_valid("Shared-Secret-Value") is False


def test_unauthenticated_caller_is_refused(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    with pytest.raises(HTTPException) as exc:
        _resolve_caller(uuid.uuid4(), None, None)
    assert exc.value.status_code == 401


def test_service_caller_must_name_its_tenant(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "shared-secret-value")
    with pytest.raises(HTTPException) as exc:
        _resolve_caller(None, None, "shared-secret-value")
    assert exc.value.status_code == 400


def test_service_caller_with_a_tenant_is_admitted(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "shared-secret-value")
    tenant = uuid.uuid4()
    resolved, requested_by = _resolve_caller(tenant, None, "shared-secret-value")
    assert resolved == tenant
    assert requested_by == "aisoc-agents"


def test_a_session_tenant_wins_over_the_body(monkeypatch) -> None:
    """A user must not be able to write a disposition into another tenant."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "shared-secret-value")
    session_tenant = uuid.uuid4()
    other_tenant = uuid.uuid4()
    resolved, requested_by = _resolve_caller(other_tenant, _User(session_tenant), "shared-secret-value")
    assert resolved == session_tenant
    assert requested_by.startswith("user:")


def test_a_session_without_the_permission_is_refused() -> None:
    with pytest.raises(HTTPException) as exc:
        _resolve_caller(None, _User(uuid.uuid4(), allowed=False), None)
    assert exc.value.status_code == 403

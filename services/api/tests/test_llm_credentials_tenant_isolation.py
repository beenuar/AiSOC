"""Tenant-isolation tests for /api/v1/llm/credentials (Issue #159 / F013).

Sibling of ``test_threat_intel_tenant_isolation.py`` and
``test_alerts_tenant_isolation.py``: call the endpoint functions directly
with a mocked :class:`AsyncSession` and assert that every SQL statement
touching ``tenant_llm_credentials`` filters on ``tenant_id`` *and* binds
the caller's tenant id, and that writes always carry the caller's
tenant id (never allow caller-supplied ``tenant_id`` to override).

This endpoint is unusual in that ``tenant_id`` is the *primary key* of
``tenant_llm_credentials`` — there is one row per tenant. That makes
tenant isolation an even tighter contract: a cross-tenant read must
never resolve the other tenant's row even if no other rows exist, and a
PUT must never overwrite the other tenant's ciphertext.

The vault (``get_vault().encrypt(...)``) and the audit emitter
(``emit_audit(...)``) are dependencies we mock out so the test stays
focused on the SQL boundary — exhaustive vault / audit tests live
elsewhere.

The contract being protected
----------------------------
* GET resolves only the caller's row (returns ``None`` rather than
  leaking another tenant's record).
* PUT (upsert) issues a tenant-scoped SELECT, and any new row attached
  to the session carries the caller's ``tenant_id`` (never one taken
  from a payload or query string).
* DELETE issues a tenant-scoped SELECT + DELETE so a hostile or buggy
  caller cannot delete another tenant's credential.
* The audit row recorded for PUT / DELETE carries the caller's
  ``tenant_id``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1 import deps as deps_module
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import llm_credentials as llm_credentials_module
from app.api.v1.endpoints.llm_credentials import (
    LlmCredentialUpsert,
    delete_llm_credential,
    get_llm_credential,
    upsert_llm_credential,
)
from app.models.llm_credential import TenantLlmCredential
from pytest import MonkeyPatch

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    """Construct a CurrentUser without touching DB / JWT plumbing."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="tenant_admin",
        email="admin@example.com",
    )


def _credential(tenant_id: uuid.UUID, **overrides: Any) -> TenantLlmCredential:
    """Build a TenantLlmCredential ORM row in memory (no DB)."""
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "tenant_id": tenant_id,
        "provider": "openai",
        "base_url": None,
        "model": "gpt-4o-mini",
        "api_key_vault": "vault:v1:cGxhY2Vob2xkZXI=",
        "settings": {},
        "enabled": True,
        "created_at": now,
        "updated_at": now,
        "last_rotated_at": now,
    }
    defaults.update(overrides)
    row = TenantLlmCredential()
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock AsyncSession that captures SQL + binds and replays queued rows.

    Mirrors the helper used by the threat-intel + alerts isolation tests.
    """
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    db.added: list[Any] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:  # pragma: no cover — defensive: never crash the mock.
            params = {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        scalars = MagicMock()
        if isinstance(payload, list):
            scalars.all = MagicMock(return_value=payload)
            scalars.first = MagicMock(return_value=payload[0] if payload else None)
            result.scalar_one_or_none = MagicMock(return_value=payload[0] if payload else None)
        else:
            scalars.all = MagicMock(return_value=[payload] if payload else [])
            scalars.first = MagicMock(return_value=payload)
            result.scalar_one_or_none = MagicMock(return_value=payload)
        result.scalars = MagicMock(return_value=scalars)
        return result

    def _add(obj: Any) -> None:
        db.added.append(obj)

    db.execute = AsyncMock(side_effect=_execute)
    db.add = MagicMock(side_effect=_add)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _assert_tenant_scoped(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    """Every SQL statement against ``tenant_llm_credentials`` must bind caller's tenant_id."""
    assert executed, "expected at least one DB call"
    saw_credentials_query = False
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if "tenant_llm_credentials" not in normalized:
            continue
        saw_credentials_query = True
        assert "tenant_id" in normalized, f"tenant_id missing from SQL: {sql}"
        matching = [
            (name, value) for name, value in params.items() if (name == "tenant_id" or name.startswith("tenant_id_")) and value == tenant_id
        ]
        assert matching, (
            f"no bound tenant_id parameter matches caller's tenant in SQL: {sql}; " f"params={params}; expected_tenant={tenant_id}"
        )
    assert saw_credentials_query, "expected at least one query against tenant_llm_credentials"


# ────────────────────────────────────────────────────────────────────────────
# Shared monkey-patches: vault + audit are noise for isolation tests
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _stub_vault_and_audit(monkeypatch: MonkeyPatch) -> None:
    """Replace the vault + audit emitter with deterministic stubs.

    The vault stub returns a fixed ciphertext so we can assert the row
    attached to the session carries the encrypted value (rather than
    plaintext) without depending on the real CredentialVault config /
    env vars. The audit stub captures the kwargs it was called with so
    individual tests can assert ``tenant_id`` propagation.
    """

    fake_vault = MagicMock()
    fake_vault.encrypt = MagicMock(return_value="vault:v1:ZmFrZQ==")
    monkeypatch.setattr(llm_credentials_module, "get_vault", lambda: fake_vault)

    async def _fake_emit_audit(**kwargs: Any) -> None:
        # Record into module-level list so tests can inspect.
        _AUDIT_CAPTURE.append(kwargs)

    monkeypatch.setattr(llm_credentials_module, "emit_audit", _fake_emit_audit)
    _AUDIT_CAPTURE.clear()


_AUDIT_CAPTURE: list[dict[str, Any]] = []


# ────────────────────────────────────────────────────────────────────────────
# GET /llm/credentials
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_credential_scopes_by_tenant() -> None:
    """The SELECT for GET must bind current_user.tenant_id."""
    user = _user()
    db = _mk_db([_credential(user.tenant_id)])
    result = await get_llm_credential(current_user=user, db=db)
    assert result is not None
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_get_credential_returns_none_when_caller_has_no_row() -> None:
    """GET returns None (not 404) when no credential exists for the caller."""
    user = _user()
    db = _mk_db([None])
    result = await get_llm_credential(current_user=user, db=db)
    assert result is None
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_get_credential_does_not_leak_another_tenants_row() -> None:
    """If the DB only has tenant B's row, tenant A's GET must resolve None.

    We model this by having the mock return ``None`` for the caller's
    scoped query — what we're actually verifying is that the endpoint
    *issues the scoped query* (so a real DB would return None on its
    own), rather than blindly returning whatever ``scalar_one_or_none``
    surfaces.
    """
    tenant_a = _user()
    db = _mk_db([None])  # scoped query for tenant A finds nothing
    result = await get_llm_credential(current_user=tenant_a, db=db)
    assert result is None
    _assert_tenant_scoped(db.executed, tenant_a.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# PUT /llm/credentials (upsert)
# ────────────────────────────────────────────────────────────────────────────


def _request_stub() -> Any:
    """A minimal Request stand-in for emit_audit (we've stubbed it anyway)."""
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.headers = {}
    return req


@pytest.mark.asyncio
async def test_upsert_credential_scopes_existing_lookup_by_tenant() -> None:
    """The initial SELECT-for-existing must bind current_user.tenant_id."""
    user = _user()
    # ``None`` -> no existing row, so the upsert branch creates a new row.
    db = _mk_db([None])
    payload = LlmCredentialUpsert(provider="openai", api_key="sk-secret-test")
    result = await upsert_llm_credential(payload=payload, request=_request_stub(), current_user=user, db=db)
    assert result.provider == "openai"
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_upsert_credential_create_attaches_caller_tenant() -> None:
    """The newly-created row attached to the session must carry caller's tenant_id."""
    user = _user()
    db = _mk_db([None])
    payload = LlmCredentialUpsert(provider="openai", api_key="sk-secret-test")
    await upsert_llm_credential(payload=payload, request=_request_stub(), current_user=user, db=db)
    assert len(db.added) == 1, "exactly one new row should have been attached"
    new_row = db.added[0]
    assert isinstance(new_row, TenantLlmCredential)
    assert new_row.tenant_id == user.tenant_id, "new TenantLlmCredential row must carry caller's tenant_id, not a payload-supplied one"
    # Confirm we stored the ciphertext from the vault, not the plaintext.
    assert new_row.api_key_vault == "vault:v1:ZmFrZQ=="
    assert new_row.api_key_vault != "sk-secret-test"


@pytest.mark.asyncio
async def test_upsert_credential_update_preserves_caller_tenant() -> None:
    """Updating an existing row must never mutate ``tenant_id`` to anything else."""
    user = _user()
    existing = _credential(user.tenant_id, provider="anthropic")
    db = _mk_db([existing])  # SELECT returns caller's existing row.
    payload = LlmCredentialUpsert(provider="openai", api_key="sk-rotation-test")
    await upsert_llm_credential(payload=payload, request=_request_stub(), current_user=user, db=db)
    # The endpoint mutates the existing row in place; tenant_id must not move.
    assert existing.tenant_id == user.tenant_id, "update path must not rebind tenant_id"
    # And it should not have added a brand-new row.
    assert db.added == [], "update path must not insert a duplicate"
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_upsert_credential_audit_carries_caller_tenant() -> None:
    """The audit row emitted on PUT must use current_user.tenant_id."""
    user = _user()
    db = _mk_db([None])
    payload = LlmCredentialUpsert(provider="openai", api_key="sk-secret-test")
    await upsert_llm_credential(payload=payload, request=_request_stub(), current_user=user, db=db)
    assert _AUDIT_CAPTURE, "expected emit_audit to be called on PUT"
    last = _AUDIT_CAPTURE[-1]
    assert last["tenant_id"] == user.tenant_id
    assert last["actor_id"] == user.user_id
    assert last["action"] == "settings.llm.upsert"


# ────────────────────────────────────────────────────────────────────────────
# DELETE /llm/credentials
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_credential_scopes_select_and_delete_by_tenant() -> None:
    """Both the existence SELECT and the DELETE statement must bind tenant_id."""
    user = _user()
    db = _mk_db([_credential(user.tenant_id)])
    await delete_llm_credential(request=_request_stub(), current_user=user, db=db)
    # Two statements: SELECT + DELETE, both tenant-scoped.
    assert len(db.executed) == 2, f"expected SELECT + DELETE, got {len(db.executed)}: {db.executed}"
    _assert_tenant_scoped(db.executed, user.tenant_id)

    # Belt-and-braces: confirm the second statement is a DELETE.
    delete_sql, _ = db.executed[1]
    normalized = re.sub(r"\s+", " ", delete_sql).lower()
    assert normalized.startswith(
        "delete from tenant_llm_credentials"
    ), f"second statement must be a DELETE FROM tenant_llm_credentials: {delete_sql}"


@pytest.mark.asyncio
async def test_delete_credential_idempotent_when_row_missing() -> None:
    """DELETE is a no-op when no row exists; still scoped by tenant_id, still does not audit."""
    user = _user()
    db = _mk_db([None])  # SELECT finds nothing
    result = await delete_llm_credential(request=_request_stub(), current_user=user, db=db)
    assert result is None
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # No audit row for a missing-row DELETE — by design.
    assert _AUDIT_CAPTURE == []


@pytest.mark.asyncio
async def test_delete_credential_audit_carries_caller_tenant() -> None:
    """The audit row emitted on a real DELETE must use current_user.tenant_id."""
    user = _user()
    existing = _credential(user.tenant_id)
    db = _mk_db([existing])
    await delete_llm_credential(request=_request_stub(), current_user=user, db=db)
    assert _AUDIT_CAPTURE, "expected emit_audit to be called for a real DELETE"
    last = _AUDIT_CAPTURE[-1]
    assert last["tenant_id"] == user.tenant_id
    assert last["actor_id"] == user.user_id
    assert last["action"] == "settings.llm.delete"


# Defensive: keep ``deps_module`` import live so static checkers don't drop it
# if we later need to inject ``require_permission`` overrides here.
assert deps_module is not None

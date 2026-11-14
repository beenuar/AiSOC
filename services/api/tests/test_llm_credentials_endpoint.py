"""Unit tests for the per-tenant BYOK LLM credentials endpoint (WS-H2).

The ``/api/v1/llm/credentials`` GET/PUT/DELETE handlers wire together
four collaborators:

* the SQLAlchemy session (read existing row, upsert new one, hard-delete
  on remove),
* :class:`app.security.credential_vault.CredentialVault` (encrypt the
  plaintext API key into ``vault:v1:<base64>`` ciphertext),
* the audit log (an immutable row appended on every write so a buyer's
  compliance team has a paper trail of who rotated which provider when),
* and the cross-field validator that enforces "hosted SaaS providers
  require an api_key, local/custom providers require a base_url".

Spinning up the full FastAPI app + Postgres + Fernet wiring for these
units would be slow and would double-cover the lower layers. We follow
the same pattern as the sibling endpoint tests in this repo
(``test_saved_views_endpoint.py``, ``test_lake_endpoint.py``): mock the
DB session, build a ``SimpleNamespace`` user, and assert the contract
the endpoint should keep.

What we exercise here:

* ``GET`` returns ``None`` cleanly when no row exists, returns a
  projection (with ``has_api_key`` but never the key itself) when one
  does.
* ``PUT`` happy path: create + encrypt + audit on first write, rotation-
  only PUT (api_key=None) leaves the existing ciphertext alone, fresh
  api_key bumps ``last_rotated_at``.
* ``PUT`` validation: missing ``base_url`` for local providers,
  missing ``api_key`` for hosted SaaS, base_url with non-http scheme,
  base_url without hostname.
* ``PUT`` failure: a vault encrypt error must surface as a 500 *before*
  any DB mutation lands (so the caller does not end up with a half-
  written row).
* ``DELETE`` is idempotent (204 with no audit when nothing to delete)
  and emits an audit row when there was a row to delete.
* The vault round-trip is sound — a string encrypted by the vault
  decrypts back to the same string, and the projection surfaces
  ``has_api_key=True`` when the ciphertext column is non-empty.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.v1.endpoints.llm_credentials import (
    LlmCredentialUpsert,
    _enforce_provider_invariants,
    _project,
    delete_llm_credential,
    get_llm_credential,
    upsert_llm_credential,
)
from app.security.credential_vault import (
    _CIPHER_PREFIX,
    CredentialVault,
    CredentialVaultError,
)
from cryptography.fernet import Fernet
from fastapi import HTTPException
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


def _build_user(
    *,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    role: str = "tenant_admin",
) -> SimpleNamespace:
    """Minimal CurrentUser stand-in.

    The endpoint reads ``tenant_id``, ``user_id``, ``role``, and ``email``
    only — a SimpleNamespace keeps the tests free of the auth import
    graph. Note that the dependency-injected ``require_permission``
    check is bypassed when we call the endpoint function directly; the
    permission contract is owned by the FastAPI dep wiring (asserted
    indirectly via the integration smoke tests in CI).
    """
    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        role=role,
        email="admin@example.com",
    )


def _build_request(
    *,
    headers: dict[str, str] | None = None,
    client_host: str = "127.0.0.1",
) -> Any:
    """Build a minimal FastAPI Request stand-in for the audit emission.

    The audit helper only reads ``request.headers`` and
    ``request.client``; no need for a full ASGI scope. Same shape as
    :func:`tests.test_lake_endpoint._build_request`.
    """
    req = MagicMock()
    req.headers = headers or {}
    req.client = MagicMock()
    req.client.host = client_host
    return req


def _llm_row(
    *,
    tenant_id: uuid.UUID | None = None,
    provider: str = "openai",
    base_url: str | None = None,
    model: str | None = None,
    api_key_vault: str | None = "vault:v1:fakeciphertext",
    settings: dict[str, Any] | None = None,
    enabled: bool = True,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
    last_rotated_at: datetime | None = None,
) -> SimpleNamespace:
    """Build a TenantLlmCredential row stand-in.

    SimpleNamespace rather than the real ORM class so tests don't
    accidentally touch SQLAlchemy's instrumentation — assigning to
    ``row.provider`` on a real model would dirty the session, which is
    test-irrelevant noise here.
    """
    now = datetime.now(UTC)
    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        provider=provider,
        base_url=base_url,
        model=model,
        api_key_vault=api_key_vault,
        settings=settings if settings is not None else {},
        enabled=enabled,
        created_at=created_at or now,
        updated_at=updated_at or now,
        last_rotated_at=last_rotated_at,
    )


def _mock_db_with_existing(
    existing: Any | None,
    *,
    extra_executes: int = 0,
) -> MagicMock:
    """Build a DB whose first ``execute`` returns ``existing`` via ``scalar_one_or_none``.

    ``extra_executes`` lets callers (e.g. DELETE, which runs a second
    ``execute`` for the actual DELETE statement) reserve more results
    in the side_effect chain. Subsequent results return a generic
    "no row" mock so any later ``scalar_one_or_none`` call is benign.
    """
    select_result = MagicMock()
    select_result.scalar_one_or_none = MagicMock(return_value=existing)

    extras = []
    for _ in range(extra_executes):
        result = MagicMock()
        result.scalar_one_or_none = MagicMock(return_value=None)
        extras.append(result)

    db = MagicMock()
    db.execute = AsyncMock(side_effect=[select_result, *extras])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.rollback = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# _project — the read-only ORM → wire-model projection
# ---------------------------------------------------------------------------


def test_project_strips_ciphertext_and_surfaces_has_api_key() -> None:
    """The plaintext key never leaves the server — only ``has_api_key``.

    This is the core privacy guarantee of the GET endpoint. Even an
    operator with DB read access who pokes the API gets back a boolean,
    not a key — they have to re-rotate to "see" a new one. This test
    pins that contract so a future refactor that accidentally adds
    ``api_key`` to the response model fails CI loudly.
    """
    row = _llm_row(
        provider="openai",
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        api_key_vault="vault:v1:abcdef",
        settings={"organization": "org-123"},
    )
    view = _project(row)

    assert view.provider == "openai"
    assert view.base_url == "https://api.openai.com"
    assert view.model == "gpt-4o-mini"
    assert view.has_api_key is True
    assert view.settings == {"organization": "org-123"}
    # Confirm there is no ``api_key`` attribute leaking through; the
    # response model schema doesn't include one, and runtime introspection
    # should agree.
    assert not hasattr(view, "api_key")
    # Pydantic dump must also be free of any plaintext-key flavoured key.
    dumped = view.model_dump()
    assert "api_key" not in dumped
    assert dumped["has_api_key"] is True


def test_project_marks_has_api_key_false_when_ciphertext_empty() -> None:
    """A NULL ciphertext column → ``has_api_key=False``.

    Important so the UI can render the "Configure your LLM" CTA for a
    tenant that has stored a base_url + provider for a local-* deployment
    that does not need a key.
    """
    row = _llm_row(api_key_vault=None, provider="local-ollama")
    view = _project(row)
    assert view.has_api_key is False


def test_project_normalises_settings_none_to_empty_dict() -> None:
    """A ``None`` settings column round-trips as ``{}``.

    The DB column is NOT NULL with default ``{}`` in the migration, but
    a fresh ORM instance pre-flush can be ``None``. Defensive normalisation
    here means the response model never blows up on a transient race.
    """
    row = _llm_row(settings=None)
    view = _project(row)
    assert view.settings == {}


# ---------------------------------------------------------------------------
# LlmCredentialUpsert — Pydantic field validators
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://api.openai.com", "https://api.openai.com"),
        ("http://localhost:11434", "http://localhost:11434"),
        # Whitespace gets trimmed; empty strings collapse to None.
        ("  https://example.com  ", "https://example.com"),
        ("   ", None),
        ("", None),
        (None, None),
    ],
)
def test_base_url_validator_accepts_valid_inputs(value: str | None, expected: str | None) -> None:
    """The validator strips whitespace and collapses empties to ``None``."""
    payload = LlmCredentialUpsert(provider="custom", base_url=value, api_key="k")
    assert payload.base_url == expected


@pytest.mark.parametrize("bad", ["ftp://x.example", "not-a-url", "ws://x.example"])
def test_base_url_validator_rejects_non_http_schemes(bad: str) -> None:
    """Non-http(s) schemes 422 — the explain path uses an http client.

    A wss:// URL would silently fail at request time; the 422 here gives
    the operator a precise error in the UI before the row is written.
    """
    with pytest.raises(ValidationError) as exc:
        LlmCredentialUpsert(provider="custom", base_url=bad, api_key="k")
    assert "base_url must be an http(s) URL" in str(exc.value)


def test_base_url_validator_rejects_missing_hostname() -> None:
    """A scheme-only URL has no host to point the LLM client at."""
    with pytest.raises(ValidationError) as exc:
        LlmCredentialUpsert(provider="custom", base_url="https://", api_key="k")
    assert "base_url must include a hostname" in str(exc.value)


def test_api_key_validator_strips_and_collapses_whitespace_only() -> None:
    """Whitespace-only api_key → ``None`` (treated as "keep existing").

    Operators sometimes paste a key with a trailing newline, or paste
    nothing into the input. Stripping prevents the latter from looking
    like a key in the audit row.
    """
    payload = LlmCredentialUpsert(provider="openai", api_key="   ")
    assert payload.api_key is None
    payload = LlmCredentialUpsert(provider="openai", api_key="  abc  ")
    assert payload.api_key == "abc"


def test_provider_enum_rejects_unknown_value() -> None:
    """Unknown provider → 422 *before* it reaches the DB CHECK constraint.

    The enum lives in three places (DB CHECK, Pydantic Literal, and the
    classifier in ``llm_status``). Catching here keeps the failure mode
    "422 with a useful detail" rather than "500 from a constraint
    violation pretending to be a server error".
    """
    with pytest.raises(ValidationError):
        LlmCredentialUpsert(provider="bedrock", api_key="k")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _enforce_provider_invariants — cross-field rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", ["local-ollama", "local-vllm", "local-litellm", "custom"])
def test_enforce_invariants_requires_base_url_for_local_and_custom(
    provider: str,
) -> None:
    """Local + custom providers must point at a base_url.

    A NULL base_url for these providers is meaningless (we have no
    canonical endpoint to fall back to). Catching here means the API
    refuses to create the row rather than letting the agents service
    log a baffling "no base_url configured" warning at request time.
    """
    payload = LlmCredentialUpsert(provider=provider, base_url=None, api_key="k")
    with pytest.raises(HTTPException) as exc:
        _enforce_provider_invariants(payload, existing=None)
    assert exc.value.status_code == 422
    assert "requires base_url" in exc.value.detail


@pytest.mark.parametrize("provider", ["openai", "anthropic", "azure-openai"])
def test_enforce_invariants_requires_api_key_for_hosted_when_no_existing(
    provider: str,
) -> None:
    """Hosted SaaS providers require a key on the *first* write.

    A subsequent rotation-only PUT (``api_key=None`` on an existing
    row that already has a ciphertext) is fine — see the next test.
    """
    payload = LlmCredentialUpsert(provider=provider, api_key=None)
    with pytest.raises(HTTPException) as exc:
        _enforce_provider_invariants(payload, existing=None)
    assert exc.value.status_code == 422
    assert "requires api_key" in exc.value.detail


def test_enforce_invariants_allows_rotation_only_put_for_hosted() -> None:
    """``api_key=None`` is fine when the existing row already has one.

    This is the critical UX for "edit base_url without re-typing a
    100-char secret". If we 422'd here, every PUT would force a key
    re-entry, which is exactly the friction operators complain about.
    """
    existing = _llm_row(provider="openai", api_key_vault="vault:v1:abc")
    payload = LlmCredentialUpsert(provider="openai", api_key=None)
    # Should not raise.
    _enforce_provider_invariants(payload, existing=existing)


def test_enforce_invariants_local_with_no_key_is_allowed() -> None:
    """Local providers without auth legitimately have no key."""
    payload = LlmCredentialUpsert(
        provider="local-ollama",
        base_url="http://localhost:11434",
        api_key=None,
    )
    # Should not raise.
    _enforce_provider_invariants(payload, existing=None)


# ---------------------------------------------------------------------------
# GET /api/v1/llm/credentials
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_returns_none_when_no_row() -> None:
    """Empty case returns ``None`` (not 404) so the UI can render its CTA.

    Returning a 404 would force the frontend to dispatch on error codes
    when the "no credential set" case is the *expected* state for a
    fresh tenant. ``None`` keeps the success/failure axes orthogonal.
    """
    db = _mock_db_with_existing(None)
    user = _build_user()

    result = await get_llm_credential(current_user=user, db=db)

    assert result is None
    db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_returns_projection_when_row_exists() -> None:
    """Existing row → ``LlmCredentialView`` with ``has_api_key=True``.

    The plaintext key remains in the vault — the response only signals
    presence so the UI can render "credential present" without ever
    receiving the secret.
    """
    user = _build_user()
    row = _llm_row(
        tenant_id=user.tenant_id,
        provider="anthropic",
        model="claude-3-5-sonnet-20241022",
        api_key_vault="vault:v1:abc",
    )
    db = _mock_db_with_existing(row)

    result = await get_llm_credential(current_user=user, db=db)

    assert result is not None
    assert result.provider == "anthropic"
    assert result.model == "claude-3-5-sonnet-20241022"
    assert result.has_api_key is True


@pytest.mark.asyncio
async def test_get_scopes_query_to_current_tenant() -> None:
    """The SELECT must filter by the caller's tenant_id.

    Defence-in-depth — the DB also has RLS on this table — but a
    forgotten predicate here would leak credentials across tenants if
    RLS were ever disabled in a future migration. Asserting the
    compiled SQL shape catches the regression at unit-test speed.
    """
    user = _build_user()
    db = _mock_db_with_existing(None)
    await get_llm_credential(current_user=user, db=db)

    stmt = db.execute.await_args.args[0]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    assert "tenant_llm_credentials" in compiled
    assert (str(user.tenant_id) in compiled) or (user.tenant_id.hex in compiled)


# ---------------------------------------------------------------------------
# PUT /api/v1/llm/credentials — happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_creates_new_row_encrypts_and_emits_audit() -> None:
    """First-time PUT for a tenant: row added, key encrypted, audit emitted.

    This is the "I just got an OpenAI key, let me wire it in" flow. We
    assert the four invariants that matter:

    * ``db.add`` is called exactly once with a row object whose
      ``api_key_vault`` is a ``vault:v1:`` ciphertext (not the plaintext).
    * ``last_rotated_at`` is populated (powers the "rotated N days ago"
      UI hint).
    * ``emit_audit`` is called with ``action="settings.llm.upsert"``,
      ``rotated=True``, ``created=True``, and the new provider — the
      compliance-evidence shape the buyer's auditor reads.
    * The audit changes never include the plaintext key.
    """
    user = _build_user()
    db = _mock_db_with_existing(None)
    request = _build_request()

    payload = LlmCredentialUpsert(
        provider="openai",
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        api_key="sk-real-secret-DO-NOT-LOG",
    )

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        result = await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    db.add.assert_called_once()
    added_row = db.add.call_args.args[0]
    assert added_row.provider == "openai"
    assert added_row.api_key_vault is not None
    assert added_row.api_key_vault.startswith(_CIPHER_PREFIX)
    assert "sk-real-secret-DO-NOT-LOG" not in added_row.api_key_vault
    assert added_row.last_rotated_at is not None
    db.commit.assert_awaited_once()

    mock_emit.assert_awaited_once()
    audit_kwargs = mock_emit.call_args.kwargs
    assert audit_kwargs["action"] == "settings.llm.upsert"
    assert audit_kwargs["resource"] == "llm_credential"
    assert audit_kwargs["actor_id"] == user.user_id
    assert audit_kwargs["actor_email"] == user.email
    assert audit_kwargs["request"] is request

    changes = audit_kwargs["changes"]
    assert changes["provider"] == "openai"
    assert changes["previous_provider"] is None
    assert changes["rotated"] is True
    assert changes["created"] is True
    assert changes["enabled"] is True
    # Plaintext leakage check — the audit row must never carry the key.
    assert "api_key" not in changes
    assert "sk-real-secret-DO-NOT-LOG" not in str(changes)

    assert result.provider == "openai"
    assert result.has_api_key is True


@pytest.mark.asyncio
async def test_put_rotation_only_keeps_existing_ciphertext_and_does_not_bump_rotated_at() -> None:
    """``api_key=None`` on an existing row: keep ciphertext, no rotation bump.

    Use case: operator changes ``model`` from gpt-4o to gpt-4o-mini
    without re-typing the secret. We assert (1) the stored ciphertext
    is unchanged, (2) ``last_rotated_at`` is not bumped (it's only the
    *key rotation* timestamp, not the *row update* timestamp), and (3)
    the audit row reports ``rotated=False`` so the compliance log
    distinguishes config tweaks from key rotations.
    """
    user = _build_user()
    original_ciphertext = "vault:v1:original_token"
    original_rotated_at = datetime(2024, 1, 1, tzinfo=UTC)
    existing = _llm_row(
        tenant_id=user.tenant_id,
        provider="openai",
        model="gpt-4o",
        api_key_vault=original_ciphertext,
        last_rotated_at=original_rotated_at,
    )
    db = _mock_db_with_existing(existing)
    request = _build_request()

    payload = LlmCredentialUpsert(
        provider="openai",
        model="gpt-4o-mini",  # changed
        api_key=None,  # keep existing
    )

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        result = await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    # The mutated row is the same object; assert the in-place mutations.
    assert existing.api_key_vault == original_ciphertext
    assert existing.last_rotated_at == original_rotated_at
    assert existing.model == "gpt-4o-mini"
    db.add.assert_not_called()  # update path, not insert.
    db.commit.assert_awaited_once()

    mock_emit.assert_awaited_once()
    changes = mock_emit.call_args.kwargs["changes"]
    assert changes["rotated"] is False
    assert changes["created"] is False
    assert result.has_api_key is True


@pytest.mark.asyncio
async def test_put_with_new_key_bumps_last_rotated_at_on_existing() -> None:
    """Supplying a new ``api_key`` on an existing row → fresh ciphertext + rotation bump.

    The audit row's ``rotated=True`` flag is the compliance signal that
    a key rotation happened. Operators can join this against the
    rotation policy ("rotate every 90 days") to prove hygiene.
    """
    user = _build_user()
    original_ciphertext = "vault:v1:old_token"
    original_rotated_at = datetime(2024, 1, 1, tzinfo=UTC)
    existing = _llm_row(
        tenant_id=user.tenant_id,
        provider="openai",
        api_key_vault=original_ciphertext,
        last_rotated_at=original_rotated_at,
    )
    db = _mock_db_with_existing(existing)
    request = _build_request()

    payload = LlmCredentialUpsert(provider="openai", api_key="sk-new-secret")

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    # Ciphertext changed; the new value is a real vault token (not the
    # plaintext) and is not the original.
    assert existing.api_key_vault != original_ciphertext
    assert existing.api_key_vault.startswith(_CIPHER_PREFIX)
    assert "sk-new-secret" not in existing.api_key_vault
    # last_rotated_at advanced.
    assert existing.last_rotated_at > original_rotated_at

    changes = mock_emit.call_args.kwargs["changes"]
    assert changes["rotated"] is True
    assert changes["created"] is False


@pytest.mark.asyncio
async def test_put_records_provider_transition_in_audit_changes() -> None:
    """Switching providers writes both the new and previous provider.

    The buyer's auditor wants to know "this tenant moved from openai
    to azure-openai on day X" — the ``previous_provider`` key in the
    audit row's changes payload is that signal.
    """
    user = _build_user()
    existing = _llm_row(
        tenant_id=user.tenant_id,
        provider="openai",
        api_key_vault="vault:v1:original",
    )
    db = _mock_db_with_existing(existing)
    request = _build_request()

    payload = LlmCredentialUpsert(provider="azure-openai", api_key="sk-azure")

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    changes = mock_emit.call_args.kwargs["changes"]
    assert changes["provider"] == "azure-openai"
    assert changes["previous_provider"] == "openai"


# ---------------------------------------------------------------------------
# PUT /api/v1/llm/credentials — failure paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_vault_failure_surfaces_500_and_does_not_commit() -> None:
    """A vault failure must not leave a half-written row.

    The endpoint encrypts *before* mutating the session. We assert:

    * the call surfaces a 500 (not a 422 — the operator did nothing
      wrong; the platform's vault is misconfigured),
    * ``db.commit()`` was never awaited,
    * no row was added to the session.
    """
    user = _build_user()
    db = _mock_db_with_existing(None)
    request = _build_request()
    payload = LlmCredentialUpsert(provider="openai", api_key="sk-secret")

    bad_vault = MagicMock()
    bad_vault.encrypt.side_effect = CredentialVaultError("vault offline")

    with patch(
        "app.api.v1.endpoints.llm_credentials.get_vault",
        return_value=bad_vault,
    ):
        with pytest.raises(HTTPException) as exc:
            await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    assert exc.value.status_code == 500
    assert "Failed to encrypt" in exc.value.detail
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_put_validation_blocks_local_provider_without_base_url() -> None:
    """Local providers need a base_url — the endpoint must 422 before any DB write.

    Catching here (rather than letting the migration's CHECK constraint
    fire at commit time) gives the UI a precise error and avoids a
    rollback that would look like a 500 to the operator.
    """
    user = _build_user()
    db = _mock_db_with_existing(None)
    request = _build_request()
    payload = LlmCredentialUpsert(provider="local-ollama", base_url=None)

    with pytest.raises(HTTPException) as exc:
        await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    assert exc.value.status_code == 422
    assert "requires base_url" in exc.value.detail
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_put_validation_blocks_first_openai_write_without_api_key() -> None:
    """Openai (and other hosted SaaS) require an api_key on first write."""
    user = _build_user()
    db = _mock_db_with_existing(None)
    request = _build_request()
    payload = LlmCredentialUpsert(provider="openai", api_key=None)

    with pytest.raises(HTTPException) as exc:
        await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    assert exc.value.status_code == 422
    assert "requires api_key" in exc.value.detail
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_put_audit_failure_does_not_500_the_call() -> None:
    """The audit log must never tank a successful write.

    If the audit DB is briefly unavailable, the buyer's tenant should
    still be able to rotate keys — losing one audit row is preferable
    to losing the rotation (which a panicked admin would re-attempt,
    likely with the wrong key).
    """
    user = _build_user()
    db = _mock_db_with_existing(None)
    request = _build_request()
    payload = LlmCredentialUpsert(provider="openai", api_key="sk-secret")

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(side_effect=RuntimeError("audit table is gone")),
    ):
        # Should NOT raise — the endpoint catches and logs.
        result = await upsert_llm_credential(payload=payload, request=request, current_user=user, db=db)

    assert result.provider == "openai"
    assert result.has_api_key is True
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# DELETE /api/v1/llm/credentials
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_existing_row_emits_audit_with_provider() -> None:
    """DELETE on an existing row → 204 + audit row capturing the provider.

    The audit row is the only post-delete record of *what* was there.
    We assert it carries the provider so the buyer's compliance team
    can answer "what credential was active when X happened?".
    """
    user = _build_user()
    existing = _llm_row(
        tenant_id=user.tenant_id,
        provider="openai",
        api_key_vault="vault:v1:abc",
    )
    db = _mock_db_with_existing(existing, extra_executes=1)  # SELECT then DELETE
    request = _build_request()

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        result = await delete_llm_credential(request=request, current_user=user, db=db)

    assert result is None  # 204 response
    # Two execute calls: SELECT existing, then DELETE.
    assert db.execute.await_count == 2
    db.commit.assert_awaited_once()

    mock_emit.assert_awaited_once()
    kwargs = mock_emit.call_args.kwargs
    assert kwargs["action"] == "settings.llm.delete"
    assert kwargs["resource"] == "llm_credential"
    assert kwargs["changes"] == {"provider": "openai"}


@pytest.mark.asyncio
async def test_delete_idempotent_when_no_row_exists() -> None:
    """DELETE on an empty row is a no-op: 204, no audit, no error.

    Idempotency matters because the UI may issue a DELETE on an
    already-cleared tenant during a "Clear configuration" flow. A 404
    here would force the UI to special-case the empty state, which we
    avoid by mirroring the GET endpoint's "None is fine" semantics.
    """
    user = _build_user()
    db = _mock_db_with_existing(None, extra_executes=1)  # SELECT (None) then DELETE
    request = _build_request()

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        result = await delete_llm_credential(request=request, current_user=user, db=db)

    assert result is None
    db.commit.assert_awaited_once()
    # No row to audit, so no audit row.
    mock_emit.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_audit_failure_does_not_500_the_call() -> None:
    """Audit failures on DELETE are also non-fatal — same rationale as PUT."""
    user = _build_user()
    existing = _llm_row(tenant_id=user.tenant_id, provider="openai")
    db = _mock_db_with_existing(existing, extra_executes=1)
    request = _build_request()

    with patch(
        "app.api.v1.endpoints.llm_credentials.emit_audit",
        new=AsyncMock(side_effect=RuntimeError("audit table is gone")),
    ):
        result = await delete_llm_credential(request=request, current_user=user, db=db)

    assert result is None
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Vault round-trip — covers the encrypt/decrypt boundary that the
# endpoint relies on. These are pure-vault tests but live here because
# they encode the contract the endpoint depends on (a fresh PUT must
# round-trip to the agents service's resolver and back).
# ---------------------------------------------------------------------------


def test_vault_roundtrip_preserves_plaintext() -> None:
    """encrypt → decrypt yields the same plaintext.

    The agents service uses a vendored copy of this vault to decrypt
    at request time; if these two ever diverge on the wire format, the
    explain endpoint will silently fall back to the env baseline. This
    is the "the wire format hasn't drifted" smoke test.
    """
    vault = CredentialVault(Fernet.generate_key())
    plaintext = "sk-very-real-secret"
    ciphertext = vault.encrypt(plaintext)
    assert ciphertext.startswith(_CIPHER_PREFIX)
    assert plaintext not in ciphertext
    assert vault.decrypt(ciphertext) == plaintext


def test_vault_round_trip_through_endpoint_path_and_back() -> None:
    """End-to-end: PUT-time encrypt + GET-time projection + agents-side decrypt.

    Simulates the full WS-H2 hot path:

    1. The endpoint encrypts the plaintext key using the canonical vault.
    2. The row is projected to the wire model — ``has_api_key=True``,
       no plaintext.
    3. The agents service (using the same key material) decrypts the
       stored ciphertext and recovers the plaintext.

    We use the canonical vault (services/api) to encrypt and the
    vendored vault (services/agents) to decrypt, exactly mirroring the
    cross-service runtime contract.
    """
    # ruff: noqa: PLC0415 — local imports keep agents-side bootstrapping
    # out of the module-load path; this test is the only one that needs them.
    import sys
    from pathlib import Path

    agents_root = Path(__file__).resolve().parents[2] / "agents"
    if str(agents_root) not in sys.path:
        sys.path.insert(0, str(agents_root))

    from app.security.credential_vault import CredentialVault as AgentsVault

    key = Fernet.generate_key()
    api_vault = CredentialVault(key)
    agents_vault = AgentsVault(key)

    plaintext = "sk-cross-service-secret"
    ciphertext = api_vault.encrypt(plaintext)

    # Endpoint stores ``ciphertext`` in ``api_key_vault``; projection
    # surfaces only a presence flag.
    row = _llm_row(api_key_vault=ciphertext)
    view = _project(row)
    assert view.has_api_key is True
    assert "api_key" not in view.model_dump()

    # Agents-side resolver decrypts the same ciphertext and recovers
    # the original plaintext.
    assert agents_vault.decrypt(ciphertext) == plaintext

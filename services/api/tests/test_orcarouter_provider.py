"""OrcaRouter Cyber Inference — provider, PKCE connect and catalog contract.

The tests are grouped by the surface they hold:

* registration — the provider ids exist in the same three places migration 038
  documented, and neither entry accepts a credential-less write;
* origins — authentication answers on ``www.orcarouter.ai`` and inference on
  ``api.orcarouter.ai/v1``, with a shared self-hosted base and explicit
  overrides, and neither origin is derived from the other;
* PKCE — a fresh verifier/state per attempt, an S256 challenge with no padding,
  an out-of-band authorize URL, single-use state, and an exchange that carries
  the verifier in the body to ``/api/v1/auth/keys``;
* catalog — capability filtering from metadata, a bounded request, a verified
  fallback that is never mixed into a live answer;
* credential lifecycle — a rejected durable key marks the exact generation for
  reauthentication, and a late failure cannot touch a newer credential.

Every credential here is a fake. Nothing in this file talks to OrcaRouter; the
one live check lives in ``test_orcarouter_live.py`` and skips without a key.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from app.api.v1.endpoints import llm_credentials as creds
from app.api.v1.endpoints import llm_orcarouter as connect_api
from app.models.orcarouter_connect import OrcaRouterConnectState
from app.services import orcarouter
from app.services.llm_credential_probe import ProbeResult

FAKE_KEY = "sk-orca-test-not-a-real-key"
FAKE_CODE = "code-test-123"


def _user(tenant_id: uuid.UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=uuid.uuid4(),
        email="operator@example.test",
        api_key_prefix=None,
    )


def _db_with(*results: MagicMock) -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()  # Session.add is synchronous.
    db.execute.side_effect = list(results)
    return db


def _row(
    *,
    provider: str = orcarouter.API_KEY_PROVIDER,
    base_url: str | None = "https://api.orcarouter.ai/v1",
    model: str | None = "orcarouter/auto",
    key_vault: str | None = "vault:v1:fake",
    settings: dict | None = None,
) -> SimpleNamespace:
    now = datetime.now(UTC)
    return SimpleNamespace(
        tenant_id=uuid.uuid4(),
        provider=provider,
        base_url=base_url,
        model=model,
        api_key_vault=key_vault,
        settings=settings or {"credential_generation": "gen-1"},
        enabled=True,
        created_at=now,
        updated_at=now,
        last_rotated_at=now,
    )


# --------------------------------------------------------------- registration


def test_both_provider_ids_are_registered_and_need_a_key() -> None:
    assert orcarouter.API_KEY_PROVIDER in creds.LlmProvider.__args__
    assert orcarouter.OAUTH_PROVIDER in creds.LlmProvider.__args__
    assert orcarouter.API_KEY_PROVIDER in creds._PROVIDERS_REQUIRING_KEY
    assert orcarouter.OAUTH_PROVIDER in creds._PROVIDERS_REQUIRING_KEY
    # The endpoint is fixed for both; a tenant does not have to supply it.
    assert orcarouter.API_KEY_PROVIDER not in creds._PROVIDERS_REQUIRING_BASE_URL
    assert orcarouter.OAUTH_PROVIDER not in creds._PROVIDERS_REQUIRING_BASE_URL


def test_orcarouter_write_without_a_key_is_refused() -> None:
    payload = creds.LlmCredentialUpsert(provider=orcarouter.API_KEY_PROVIDER)
    with pytest.raises(creds.HTTPException) as excinfo:
        creds._enforce_provider_invariants(payload, existing=None)
    assert excinfo.value.status_code == 422
    assert "requires api_key" in excinfo.value.detail


def test_orcarouter_write_rejects_a_foreign_key_prefix() -> None:
    payload = creds.LlmCredentialUpsert(provider=orcarouter.OAUTH_PROVIDER, api_key="sk-openai-looking")
    with pytest.raises(creds.HTTPException) as excinfo:
        creds._enforce_provider_invariants(payload, existing=None)
    assert excinfo.value.status_code == 422
    assert "sk-orca-" in excinfo.value.detail


def test_orcarouter_write_fills_the_fixed_endpoint_and_default_model() -> None:
    base, model = creds._orcarouter_defaults(orcarouter.API_KEY_PROVIDER, None, None)
    assert base == "https://api.orcarouter.ai/v1"
    assert model == "orcarouter/auto"
    # An operator override still wins.
    assert creds._orcarouter_defaults(orcarouter.API_KEY_PROVIDER, "https://orca.internal/v1", "orcarouter/fusion") == (
        "https://orca.internal/v1",
        "orcarouter/fusion",
    )
    # Untouched for every other provider.
    assert creds._orcarouter_defaults("openai", None, None) == (None, None)


def test_projection_reports_needs_reauth_without_the_key() -> None:
    row = _row(settings={"credential_generation": "gen-2", "needs_reauth": True})
    view = creds._project(row)
    assert view.needs_reauth is True
    assert view.has_api_key is True
    assert "api_key" not in view.model_dump()


# --------------------------------------------------------------- origins


def test_default_origins_are_the_documented_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ORCAROUTER_AUTH_BASE_URL", "ORCAROUTER_API_BASE_URL", "ORCA_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    assert orcarouter.auth_base() == "https://www.orcarouter.ai"
    assert orcarouter.api_base() == "https://api.orcarouter.ai/v1"
    assert orcarouter.exchange_url() == "https://www.orcarouter.ai/api/v1/auth/keys"
    # The relay path is not the auth path: /v1/auth/keys is a 404.
    assert httpx.URL(orcarouter.exchange_url()).path == "/api/v1/auth/keys"


def test_shared_self_hosted_base_serves_both_without_hostname_surgery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORCAROUTER_AUTH_BASE_URL", raising=False)
    monkeypatch.delenv("ORCAROUTER_API_BASE_URL", raising=False)
    monkeypatch.setenv("ORCA_BASE_URL", "https://orca.example.internal")
    assert orcarouter.auth_base() == "https://orca.example.internal"
    assert orcarouter.api_base() == "https://orca.example.internal/v1"


def test_shared_base_that_already_names_a_version_is_not_doubled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCA_BASE_URL", "https://orca.example.internal/v1")
    assert orcarouter.api_base() == "https://orca.example.internal/v1"


def test_explicit_overrides_win_and_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCA_BASE_URL", "https://shared.example.internal")
    monkeypatch.setenv("ORCAROUTER_AUTH_BASE_URL", "https://auth.example.internal")
    monkeypatch.setenv("ORCAROUTER_API_BASE_URL", "https://relay.example.internal/v1")
    assert orcarouter.auth_base() == "https://auth.example.internal"
    assert orcarouter.api_base() == "https://relay.example.internal/v1"


def test_api_override_never_moves_the_auth_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ORCAROUTER_AUTH_BASE_URL", "ORCA_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ORCAROUTER_API_BASE_URL", "https://relay.example.internal/v1")
    assert orcarouter.auth_base() == "https://www.orcarouter.ai"


def test_plain_http_is_only_allowed_for_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCAROUTER_AUTH_BASE_URL", "http://127.0.0.1:8080")
    assert orcarouter.auth_base() == "http://127.0.0.1:8080"
    monkeypatch.setenv("ORCAROUTER_AUTH_BASE_URL", "http://orca.example.internal")
    with pytest.raises(orcarouter.OrcaRouterError) as excinfo:
        orcarouter.auth_base()
    assert excinfo.value.code == "config"


# --------------------------------------------------------------- PKCE


def test_pkce_attempt_is_fresh_and_challenge_is_s256_without_padding() -> None:
    first = orcarouter.new_pkce_attempt()
    second = orcarouter.new_pkce_attempt()
    assert first.verifier != second.verifier
    assert first.state != second.state
    expected = hashlib.sha256(first.verifier.encode("ascii")).digest()
    import base64

    assert first.challenge == base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
    assert "=" not in first.challenge


def test_authorize_url_is_out_of_band_on_the_auth_origin() -> None:
    attempt = orcarouter.new_pkce_attempt()
    url = orcarouter.build_authorize_url(attempt.challenge, attempt.state)
    parsed = httpx.URL(url)
    assert f"{parsed.scheme}://{parsed.host}" == "https://www.orcarouter.ai"
    assert parsed.path == "/auth"
    assert parsed.params["callback_url"] == "oob"
    assert parsed.params["code_challenge_method"] == "S256"
    assert parsed.params["code_challenge"] == attempt.challenge
    assert parsed.params["state"] == attempt.state
    # The verifier never rides in a URL.
    assert attempt.verifier not in url


def test_state_comparison_is_constant_time_and_strict() -> None:
    assert orcarouter.states_match("abc", "abc") is True
    assert orcarouter.states_match("abc", "abd") is False
    assert orcarouter.states_match("", "") is True


async def test_exchange_posts_the_verifier_to_the_auth_origin_only() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"key": FAKE_KEY, "user_id": "42", "scope": "api"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await orcarouter.exchange_code(FAKE_CODE, "verifier-value", client=client)
    await client.aclose()

    assert seen["url"] == "https://www.orcarouter.ai/api/v1/auth/keys"
    body = json.loads(str(seen["body"]))
    assert body == {"code": FAKE_CODE, "code_verifier": "verifier-value", "code_challenge_method": "S256"}
    assert result.key == FAKE_KEY
    assert result.scope == "api"


@pytest.mark.parametrize(
    ("status", "code"),
    [(400, "protocol"), (403, "denied"), (429, "rate_limit"), (500, "network")],
)
async def test_exchange_maps_refusals_to_actionable_codes(status: int, code: str) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(status, json={"error": "x"})))
    with pytest.raises(orcarouter.OrcaRouterError) as excinfo:
        await orcarouter.exchange_code(FAKE_CODE, "verifier-value", client=client)
    await client.aclose()
    assert excinfo.value.code == code
    assert "verifier-value" not in str(excinfo.value)
    assert FAKE_CODE not in str(excinfo.value)


async def test_exchange_rejects_a_scope_downgrade() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"key": FAKE_KEY, "scope": "connector"}))
    )
    with pytest.raises(orcarouter.OrcaRouterError) as excinfo:
        await orcarouter.exchange_code(FAKE_CODE, "verifier", client=client)
    await client.aclose()
    assert excinfo.value.code == "scope"
    assert "connector" in excinfo.value.message


async def test_exchange_without_a_key_is_a_protocol_error_not_an_echo() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"scope": "api"})))
    with pytest.raises(orcarouter.OrcaRouterError) as excinfo:
        await orcarouter.exchange_code(FAKE_CODE, "verifier", client=client)
    await client.aclose()
    assert excinfo.value.code == "protocol"
    assert "did not contain an API key" in excinfo.value.message


# --------------------------------------------------------------- catalog


def _catalog_row(model_id: str, **overrides) -> dict:
    row = {
        "id": model_id,
        "object": "model",
        "name": model_id,
        "supported_endpoint_types": ["openai"],
        "architecture": {"input_modalities": ["text"]},
    }
    row.update(overrides)
    return row


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        (_catalog_row("text/only"), True),
        (_catalog_row("image/in", architecture={"input_modalities": ["text", "image"]}), True),
        (_catalog_row("img-gen", supported_endpoint_types=["image-generation"]), False),
        (_catalog_row("video", supported_endpoint_types=["openai-video"]), False),
        (_catalog_row("rerank", supported_endpoint_types=["jina-rerank"]), False),
        (_catalog_row("embed", supported_endpoint_types=["embeddings"]), False),
        (_catalog_row("image-only-in", architecture={"input_modalities": ["image"]}), False),
        (_catalog_row("anthropic", supported_endpoint_types=["anthropic"]), True),
        (_catalog_row("gemini", supported_endpoint_types=["gemini"]), True),
        (_catalog_row("responses", supported_endpoint_types=["openai-response"]), True),
    ],
)
def test_chat_capability_comes_from_declared_metadata(row: dict, expected: bool) -> None:
    parsed = orcarouter.parse_model(row)
    assert parsed is not None
    assert orcarouter.is_chat_capable(parsed) is expected


def test_undeclared_modalities_fail_closed_only_for_multimodal() -> None:
    # No architecture block at all: the endpoint type decides, and nothing is
    # inferred about modalities.
    parsed = orcarouter.parse_model({"id": "x/unknown", "supported_endpoint_types": ["openai"]})
    assert parsed is not None
    assert parsed.input_modalities == []
    assert orcarouter.is_chat_capable(parsed) is True


def test_recommended_models_are_their_own_list_in_vendor_order() -> None:
    ids = [entry["id"] for entry in orcarouter.recommended_models()]
    assert ids == ["orcarouter/auto", "orcacyber-ultra-1.0", "orcacyber-zero-1.5", "orcarouter/fusion"]
    # A caller mutating its copy must not change the constant the next request sees.
    copy = orcarouter.recommended_models()
    copy[0]["id"] = "mutated"
    assert orcarouter.recommended_models()[0]["id"] == "orcarouter/auto"


async def test_catalog_filters_and_deduplicates() -> None:
    rows = [
        _catalog_row("a/one"),
        _catalog_row("a/one"),
        _catalog_row("b/imagegen", supported_endpoint_types=["image-generation"]),
        _catalog_row("c/two", architecture={"input_modalities": ["text", "image"]}),
    ]
    parsed = [m for m in (orcarouter.parse_model(r) for r in rows) if m]
    kept = [m.id for m in orcarouter.filter_chat(parsed)]
    assert kept == ["a/one", "c/two"]


async def test_live_catalog_is_authoritative_and_unmixed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["capability"] == "chat"
        assert request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
        return httpx.Response(
            200,
            json={"data": [_catalog_row("live/one"), _catalog_row("img/x", supported_endpoint_types=["image-generation"])]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    catalog = await orcarouter.fetch_catalog(FAKE_KEY, client=client)
    await client.aclose()
    assert catalog.source == "live"
    assert catalog.degraded is False
    assert [m.id for m in catalog.models] == ["live/one"]
    # Not one seed entry leaks into a live answer.
    seed_ids = {s["id"] for s in orcarouter.VERIFIED_CHAT_SEED}
    assert not seed_ids & {m.id for m in catalog.models}


async def test_failed_catalog_returns_the_verified_seed_and_says_so() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    catalog = await orcarouter.fetch_catalog(FAKE_KEY, client=client)
    await client.aclose()
    assert catalog.source == "fallback"
    assert catalog.degraded is True
    assert catalog.detail
    ids = {m.id for m in catalog.models}
    assert {"openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash", "deepseek/deepseek-v4-pro", "orcarouter/auto"} <= ids
    gpt = next(m for m in catalog.models if m.id == "openai/gpt-5.5")
    assert gpt.reasoning_efforts == ["low", "medium", "high", "xhigh"]


async def test_catalog_without_a_compatible_model_falls_back() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"data": [_catalog_row("img", supported_endpoint_types=["image-generation"])]})
        )
    )
    catalog = await orcarouter.fetch_catalog(FAKE_KEY, client=client)
    await client.aclose()
    assert catalog.source == "fallback"
    assert catalog.degraded is True


async def test_catalog_oversize_response_is_refused() -> None:
    huge = {"data": [_catalog_row(f"m/{i}") for i in range(10)]}
    body = json.dumps(huge).encode()
    padded = body + b" " * (orcarouter.CATALOG_MAX_BYTES + 10)
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=padded)))
    catalog = await orcarouter.fetch_catalog(FAKE_KEY, client=client)
    await client.aclose()
    assert catalog.source == "fallback"


# --------------------------------------------------------------- connect endpoints


async def test_connect_start_keeps_the_verifier_server_side() -> None:
    db = AsyncMock()
    db.add = MagicMock()
    response = await connect_api.start_orcarouter_connect(current_user=_user(), db=db)
    row = db.add.call_args.args[0]
    assert isinstance(row, OrcaRouterConnectState)
    assert row.code_verifier
    assert row.code_verifier not in response.authorize_url
    assert response.state in response.authorize_url
    assert "callback_url=oob" in response.authorize_url
    assert "code_challenge_method=S256" in response.authorize_url
    assert response.provider == orcarouter.OAUTH_PROVIDER


async def test_connect_finish_exchanges_and_stores_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    pending = OrcaRouterConnectState(
        state="state-value-1234567890",
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        code_verifier="stored-verifier",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    pending_res = MagicMock()
    pending_res.scalar_one_or_none.return_value = pending
    no_row = MagicMock()
    no_row.scalar_one_or_none.return_value = None
    db = _db_with(pending_res, MagicMock(), no_row)

    captured: dict[str, str] = {}

    async def fake_exchange(code: str, verifier: str):
        captured["code"] = code
        captured["verifier"] = verifier
        return orcarouter.ExchangeResult(key=FAKE_KEY, scope="api", user_id="7")

    class FakeVault:
        def encrypt(self, value: str) -> str:
            captured["stored"] = value
            return "vault:v1:ciphertext"

    monkeypatch.setattr(connect_api.orcarouter, "exchange_code", fake_exchange)
    monkeypatch.setattr(connect_api, "get_vault", lambda: FakeVault())
    monkeypatch.setattr(connect_api, "emit_audit", AsyncMock())

    view = await connect_api.finish_orcarouter_connect(
        payload=connect_api.ConnectFinishRequest(state=pending.state, code="  code-value  "),
        request=MagicMock(),
        current_user=user,
        db=db,
    )

    assert captured == {"code": "code-value", "verifier": "stored-verifier", "stored": FAKE_KEY}
    assert view.provider == orcarouter.OAUTH_PROVIDER
    assert view.base_url == "https://api.orcarouter.ai/v1"
    assert view.model == "orcarouter/auto"
    assert view.has_api_key is True
    # The key is never in the projection a browser receives.
    assert FAKE_KEY not in json.dumps(view.model_dump(), default=str)


async def test_connecting_over_another_provider_does_not_keep_its_model_id() -> None:
    """A model id belongs to the provider that advertised it."""
    row = _row(provider="openai", base_url="https://api.openai.com/v1", model="gpt-4o")
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db = _db_with(res)

    class FakeVault:
        def encrypt(self, value: str) -> str:
            return "vault:v1:ciphertext"

    import app.api.v1.endpoints.llm_orcarouter as connect_module

    original = connect_module.get_vault
    connect_module.get_vault = lambda: FakeVault()
    try:
        persisted = await connect_api._persist_key(
            db,
            tenant_id=row.tenant_id,
            key=FAKE_KEY,
            base_url=orcarouter.api_base(),
            method="pkce-oob",
        )
    finally:
        connect_module.get_vault = original

    assert persisted.provider == orcarouter.OAUTH_PROVIDER
    assert persisted.model == "orcarouter/auto"
    # Connecting is not saving: a disabled override stays disabled.
    assert persisted.enabled is True


async def test_connect_finish_refuses_an_unknown_or_reused_state() -> None:
    none_res = MagicMock()
    none_res.scalar_one_or_none.return_value = None
    db = _db_with(none_res)
    with pytest.raises(connect_api.HTTPException) as excinfo:
        await connect_api.finish_orcarouter_connect(
            payload=connect_api.ConnectFinishRequest(state="x" * 20, code="code"),
            request=MagicMock(),
            current_user=_user(),
            db=db,
        )
    assert excinfo.value.status_code == 400
    assert "again" in excinfo.value.detail


async def test_connect_finish_refuses_an_expired_attempt() -> None:
    pending = OrcaRouterConnectState(
        state="state-value-1234567890",
        tenant_id=uuid.uuid4(),
        user_id=None,
        code_verifier="v",
        created_at=datetime.now(UTC) - timedelta(minutes=20),
        expires_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    res = MagicMock()
    res.scalar_one_or_none.return_value = pending
    db = _db_with(res, MagicMock())
    with pytest.raises(connect_api.HTTPException) as excinfo:
        await connect_api.finish_orcarouter_connect(
            payload=connect_api.ConnectFinishRequest(state=pending.state, code="code"),
            request=MagicMock(),
            current_user=_user(tenant_id=pending.tenant_id),
            db=db,
        )
    assert "expired" in excinfo.value.detail


async def test_model_discovery_requires_a_key() -> None:
    none_res = MagicMock()
    none_res.scalar_one_or_none.return_value = None
    db = _db_with(none_res)
    with pytest.raises(connect_api.HTTPException) as excinfo:
        await connect_api.list_orcarouter_models(
            payload=connect_api.ModelDiscoveryRequest(),
            current_user=_user(),
            db=db,
        )
    assert excinfo.value.status_code == 409


async def test_model_discovery_rejects_a_malformed_supplied_key() -> None:
    db = AsyncMock()
    db.add = MagicMock()
    with pytest.raises(connect_api.HTTPException) as excinfo:
        await connect_api.list_orcarouter_models(
            payload=connect_api.ModelDiscoveryRequest(api_key="not-an-orca-key"),
            current_user=_user(),
            db=db,
        )
    assert excinfo.value.status_code == 422


async def test_model_discovery_uses_the_stored_key_without_returning_it(monkeypatch: pytest.MonkeyPatch) -> None:
    row = _row()
    stored_res = MagicMock()
    stored_res.scalar_one_or_none.return_value = row
    db = _db_with(stored_res)

    class FakeVault:
        def decrypt(self, token: str) -> str:
            return FAKE_KEY

    seen: dict[str, str] = {}

    async def fake_catalog(key: str, *, capability: str = "chat"):
        seen["key"] = key
        seen["capability"] = capability
        return orcarouter.Catalog(models=[orcarouter.ModelEntry(id="live/one", name="live/one")], source="live")

    monkeypatch.setattr(connect_api, "get_vault", lambda: FakeVault())
    monkeypatch.setattr(connect_api.orcarouter, "fetch_catalog", fake_catalog)

    view = await connect_api.list_orcarouter_models(
        payload=connect_api.ModelDiscoveryRequest(),
        current_user=_user(),
        db=db,
    )
    assert seen == {"key": FAKE_KEY, "capability": "chat"}
    assert view.source == "live"
    assert [m["id"] for m in view.data] == ["live/one"]
    # Recommendations are stated separately and never inflate the live answer.
    assert [m["id"] for m in view.recommended][:2] == ["orcarouter/auto", "orcacyber-ultra-1.0"]
    assert view.default_model == "orcarouter/auto"
    assert FAKE_KEY not in json.dumps(view.model_dump())


# --------------------------------------------------------------- reauth lifecycle


async def test_a_rejected_key_marks_only_its_own_generation() -> None:
    row = _row(settings={"credential_generation": "gen-1"})
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db = _db_with(res)

    marked = await creds._mark_needs_reauth(db, tenant_id=row.tenant_id, generation="gen-1")
    assert marked is True
    assert row.settings["needs_reauth"] is True
    assert row.settings["needs_reauth_generation"] == "gen-1"


async def test_a_late_failure_cannot_mark_a_newer_credential() -> None:
    row = _row(settings={"credential_generation": "gen-2"})
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db = _db_with(res)

    marked = await creds._mark_needs_reauth(db, tenant_id=row.tenant_id, generation="gen-1")
    assert marked is False
    assert row.settings.get("needs_reauth") is None


async def test_a_successful_call_clears_the_flag_for_that_generation() -> None:
    row = _row(settings={"credential_generation": "gen-1", "needs_reauth": True})
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db = _db_with(res)

    cleared = await creds._clear_needs_reauth(db, tenant_id=row.tenant_id, generation="gen-1")
    assert cleared is True
    assert row.settings["needs_reauth"] is False
    assert "needs_reauth_generation" not in row.settings


async def test_a_late_success_cannot_clear_a_newer_credentials_flag() -> None:
    row = _row(settings={"credential_generation": "gen-2", "needs_reauth": True})
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db = _db_with(res)

    cleared = await creds._clear_needs_reauth(db, tenant_id=row.tenant_id, generation="gen-1")
    assert cleared is False
    assert row.settings["needs_reauth"] is True


def test_probe_result_carries_the_status_and_the_default_model() -> None:
    result = ProbeResult(outcome="refused", detail="x", status_code=401)
    assert result.status_code == 401
    from app.services.llm_credential_probe import _DEFAULT_BASE, _FALLBACK_MODEL

    assert _DEFAULT_BASE[orcarouter.API_KEY_PROVIDER] == "https://api.orcarouter.ai/v1"
    assert _FALLBACK_MODEL[orcarouter.OAUTH_PROVIDER] == "orcarouter/auto"

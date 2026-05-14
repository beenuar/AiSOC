"""Unit tests for ``services/agents/app/security/llm_resolver`` (WS-H2).

The resolver is the read path the explain endpoint uses to answer
"for *this* tenant, what LLM config (if any) should we use right
now?". The tests below cover every branch documented in the module
docstring:

* env-only baseline (no tenant ref, or tenant ref ``"default"``)
* tenant override fully replacing env (``source="tenant"``)
* partial tenant override layered over env (``source="mixed"``)
* corrupt / undecryptable tenant ciphertext degrading to env baseline
* vault not configured (``AISOC_CREDENTIAL_KEY`` unset) degrading to env baseline
* air-gap policy blocking ``api.openai.com`` even with a valid key
* air-gap policy *allowing* a private LiteLLM gateway
* ledger import / pool failure degrading to env baseline
* ``_classify_source`` matrix (tenant / environment / mixed / none)
* round-trip vault decrypt of a token produced by the API-side vault

The DB layer is mocked via a fake ``asyncpg.Pool`` so we never need a
running Postgres for these tests; the explain hot path's real DB
contract is covered separately by the API-side credential tests.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

# ----- import path setup ---------------------------------------------------

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))


# ----- helpers --------------------------------------------------------------


def _import_resolver():
    """Import the resolver fresh so per-test env tweaks take effect.

    The resolver itself reads env vars on every call (``_env_baseline``,
    ``_airgap_blocks``), so re-import is *not* required for those — but
    the vendored vault caches a singleton, so we always reset that
    cache before each test (see the autouse fixture below).
    """
    from app.security import llm_resolver  # noqa: PLC0415

    return llm_resolver


def _reset_vault() -> None:
    from app.security import credential_vault  # noqa: PLC0415

    credential_vault.reset_vault_for_tests()


def _set_vault_key(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """Configure ``AISOC_CREDENTIAL_KEY`` with a fresh Fernet key.

    Returns the key bytes so a test can also instantiate a vault
    directly and produce a ciphertext to seed into a mocked DB row.
    """
    key = Fernet.generate_key()
    monkeypatch.setenv("AISOC_CREDENTIAL_KEY", key.decode("ascii"))
    monkeypatch.delenv("AISOC_CREDENTIAL_KEY_ROTATION_FROM", raising=False)
    _reset_vault()
    return key


def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every env var the resolver consumes so tests start clean."""
    for var in (
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "LLM_API_KEY",
        "LLM_BASE_URL",
        "LLM_MODEL",
        "AISOC_LLM_MODEL",
        "AISOC_AIRGAPPED",
    ):
        monkeypatch.delenv(var, raising=False)


# ----- autouse fixture ------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset vault singleton and strip LLM env vars before each test.

    Many of the helpers under test consult module-level / process-level
    state (``_vault_singleton``, ``os.environ``). Without this fixture
    one test's vault key would leak into the next test.
    """
    _clear_llm_env(monkeypatch)
    _reset_vault()
    yield
    _reset_vault()


# ===========================================================================
# _env_baseline
# ===========================================================================


class TestEnvBaseline:
    """Verify the resolver speaks the same env-var dialect as the API
    service's status endpoint (``services/api/.../llm_status.py``).
    """

    def test_empty_env_returns_blank_triple(self) -> None:
        resolver = _import_resolver()
        base, model, key = resolver._env_baseline()
        assert base == ""
        assert model == ""
        assert key is None

    def test_openai_style_env_is_picked_up(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-1")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com")
        monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")

        resolver = _import_resolver()
        base, model, key = resolver._env_baseline()
        assert base == "https://api.openai.com"
        assert model == "gpt-4o-mini"
        assert key == "sk-env-1"

    def test_llm_style_env_is_picked_up_when_openai_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LLM_API_KEY", "private-llm-key")
        monkeypatch.setenv("LLM_BASE_URL", "http://llm.internal:4000/v1")
        monkeypatch.setenv("LLM_MODEL", "llama3.1-8b")

        resolver = _import_resolver()
        base, model, key = resolver._env_baseline()
        assert base == "http://llm.internal:4000/v1"
        assert model == "llama3.1-8b"
        assert key == "private-llm-key"

    def test_openai_takes_precedence_over_llm_aliases(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-from-openai")
        monkeypatch.setenv("LLM_API_KEY", "should-be-ignored")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com")
        monkeypatch.setenv("LLM_BASE_URL", "http://nope")
        monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")
        monkeypatch.setenv("LLM_MODEL", "should-be-ignored")

        resolver = _import_resolver()
        base, model, key = resolver._env_baseline()
        assert base == "https://api.openai.com"
        assert model == "gpt-4o-mini"
        assert key == "sk-from-openai"

    def test_aisoc_llm_model_legacy_env_supported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_LLM_MODEL", "claude-3.5-sonnet")
        resolver = _import_resolver()
        _, model, _ = resolver._env_baseline()
        assert model == "claude-3.5-sonnet"


# ===========================================================================
# _airgap_blocks
# ===========================================================================


class TestAirgapBlocks:
    """Air-gap policy must mirror the legacy ``_llm_allowed`` helper."""

    def test_airgap_off_never_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # AISOC_AIRGAPPED unset → never block, regardless of host.
        resolver = _import_resolver()
        for url in ("", "https://api.openai.com", "http://litellm.internal"):
            blocked, _ = resolver._airgap_blocks(url)
            assert blocked is False, f"airgap=off blocked {url!r}"

    @pytest.mark.parametrize("flag", ["1", "true", "yes"])
    def test_airgap_blocks_empty_base_url(self, flag: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_AIRGAPPED", flag)
        resolver = _import_resolver()
        blocked, reason = resolver._airgap_blocks("")
        assert blocked is True
        assert "would default to api.openai.com" in reason

    def test_airgap_blocks_openai_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_AIRGAPPED", "true")
        resolver = _import_resolver()
        blocked, reason = resolver._airgap_blocks("https://api.openai.com/v1")
        assert blocked is True
        # Match the full literal reason from ``_airgap_blocks`` rather than a
        # bare hostname substring (avoids CodeQL's
        # ``py/incomplete-url-substring-sanitization`` heuristic, which fires on
        # any ``"api.openai.com" in <str>`` check even in test assertions).
        assert reason == "AISOC_AIRGAPPED is on and base_url points at api.openai.com."

    def test_airgap_allows_private_litellm_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_AIRGAPPED", "true")
        resolver = _import_resolver()
        blocked, _ = resolver._airgap_blocks("http://litellm.internal:4000/v1")
        assert blocked is False


# ===========================================================================
# _classify_source
# ===========================================================================


class TestClassifySource:
    """The source label must match what tenant_llm_status reports."""

    def test_none_when_neither_side_contributes(self) -> None:
        resolver = _import_resolver()
        result = resolver._classify_source(
            env_base_url="",
            env_model="",
            env_key=None,
            tenant_contributed_base_url=False,
            tenant_contributed_model=False,
            tenant_contributed_key=False,
        )
        assert result == "none"

    def test_environment_when_only_env_set(self) -> None:
        resolver = _import_resolver()
        result = resolver._classify_source(
            env_base_url="",
            env_model="",
            env_key="sk-env",
            tenant_contributed_base_url=False,
            tenant_contributed_model=False,
            tenant_contributed_key=False,
        )
        assert result == "environment"

    def test_tenant_when_tenant_replaces_everything(self) -> None:
        # Tenant supplied all three fields and env is blank.
        resolver = _import_resolver()
        result = resolver._classify_source(
            env_base_url="",
            env_model="",
            env_key=None,
            tenant_contributed_base_url=True,
            tenant_contributed_model=True,
            tenant_contributed_key=True,
        )
        assert result == "tenant"

    def test_mixed_when_tenant_supplies_key_but_env_supplies_model(self) -> None:
        # Common operator scenario: env defines model, tenant brings key.
        resolver = _import_resolver()
        result = resolver._classify_source(
            env_base_url="",
            env_model="gpt-4o-mini",
            env_key=None,
            tenant_contributed_base_url=False,
            tenant_contributed_model=False,
            tenant_contributed_key=True,
        )
        assert result == "mixed"


# ===========================================================================
# _decrypt_vault_token
# ===========================================================================


class TestDecryptVaultToken:
    """Decryption is best-effort and must never raise."""

    def test_returns_none_when_vault_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No AISOC_CREDENTIAL_KEY set → vault.get_vault() returns None.
        monkeypatch.delenv("AISOC_CREDENTIAL_KEY", raising=False)
        _reset_vault()

        resolver = _import_resolver()
        result = resolver._decrypt_vault_token("vault:v1:something", "tenant-a")
        assert result is None

    def test_round_trip_with_configured_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_vault_key(monkeypatch)
        from app.security.credential_vault import get_vault  # noqa: PLC0415

        vault = get_vault()
        assert vault is not None
        ciphertext = vault.encrypt("sk-tenant-secret")
        assert ciphertext.startswith("vault:v1:")

        resolver = _import_resolver()
        result = resolver._decrypt_vault_token(ciphertext, "tenant-a")
        assert result == "sk-tenant-secret"

    def test_returns_none_on_corrupt_ciphertext(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Configure a vault with one key, then hand it a token encrypted
        # under a completely different key — must degrade gracefully.
        _set_vault_key(monkeypatch)

        wrong_key_vault_key = Fernet.generate_key()
        wrong_fernet = Fernet(wrong_key_vault_key)
        bogus_token = "vault:v1:" + wrong_fernet.encrypt(b"sk-other").decode("ascii")

        resolver = _import_resolver()
        result = resolver._decrypt_vault_token(bogus_token, "tenant-a")
        assert result is None


# ===========================================================================
# resolve_llm_config — no DB lookup paths
# ===========================================================================


class TestResolveNoTenant:
    """Sanity-check the early-exit branches that skip the DB entirely."""

    @pytest.mark.asyncio
    async def test_none_tenant_ref_uses_env_baseline_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm.internal:4000")
        monkeypatch.setenv("OPENAI_MODEL", "llama3.1-8b")

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config(None)

        assert cfg.allowed is True
        assert cfg.api_key == "sk-env"
        assert cfg.base_url == "http://litellm.internal:4000"
        assert cfg.model == "llama3.1-8b"
        assert cfg.source == "environment"
        assert cfg.reason == ""

    @pytest.mark.asyncio
    async def test_default_tenant_ref_skips_db(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm.internal:4000")

        # If we reached the DB lookup, importing app.investigator.ledger
        # would explode in this slim test env. The fact that we don't
        # patch it and the test still passes proves the early-exit.
        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("default")
        assert cfg.allowed is True
        assert cfg.source == "environment"

    @pytest.mark.asyncio
    async def test_no_key_anywhere_returns_disallowed_with_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No env key, no tenant ref → allowed=False with deterministic
        # fallback base_url / model so callers can still log.
        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config(None)

        assert cfg.allowed is False
        assert cfg.api_key is None
        assert cfg.base_url == "https://api.openai.com"
        assert cfg.model == "gpt-4o-mini"
        assert "no api key" in cfg.reason.lower()

    @pytest.mark.asyncio
    async def test_airgap_blocks_default_openai_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com")
        monkeypatch.setenv("AISOC_AIRGAPPED", "true")

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config(None)
        assert cfg.allowed is False
        # See note in ``test_airgap_blocks_openai_host``: assert against the full
        # literal reason to avoid CodeQL's
        # ``py/incomplete-url-substring-sanitization`` false positive.
        assert cfg.reason == "AISOC_AIRGAPPED is on and base_url points at api.openai.com."

    @pytest.mark.asyncio
    async def test_airgap_allows_private_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm.internal:4000/v1")
        monkeypatch.setenv("AISOC_AIRGAPPED", "true")

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config(None)
        assert cfg.allowed is True
        assert cfg.source == "environment"


# ===========================================================================
# resolve_llm_config — DB lookup paths
# ===========================================================================


def _make_pool_with_row(row: dict[str, Any] | None) -> MagicMock:
    """Build a fake ``asyncpg.Pool`` whose connection returns ``row``.

    The resolver calls (in order):
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_uuid(conn, tenant_ref)
            await _set_rls_context(conn, tenant_id)
            row = await conn.fetchrow(...)

    Where ``_resolve_tenant_uuid`` itself either parses the ref as a
    UUID (no DB hop) or calls ``conn.fetchrow`` once to look up the
    slug. We arrange for the first ``fetchrow`` call to satisfy the
    UUID-from-slug lookup and the second to return the credential row.
    """
    conn = MagicMock()
    # First fetchrow → tenant id lookup (only used for non-UUID refs).
    # Second fetchrow → tenant_llm_credentials row.
    tenant_id_row = {"id": uuid.uuid4()}
    conn.fetchrow = AsyncMock(side_effect=[tenant_id_row, row])
    conn.execute = AsyncMock()

    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


def _stub_ledger(monkeypatch: pytest.MonkeyPatch, pool: MagicMock | None) -> None:
    """Inject a fake ``app.investigator.ledger`` into ``sys.modules``.

    The real package eagerly imports LangGraph in ``__init__``, so the
    test harness substitutes a hollow package + a stub ``ledger``
    submodule whose ``get_pool`` returns the supplied fake pool.
    """
    pkg_name = "app.investigator"
    ledger_name = "app.investigator.ledger"

    if pkg_name not in sys.modules:
        pkg = ModuleType(pkg_name)
        pkg.__path__ = [str(_AGENTS_ROOT / "app" / "investigator")]
        monkeypatch.setitem(sys.modules, pkg_name, pkg)

    ledger = ModuleType(ledger_name)
    if pool is None:

        async def _raise():
            raise RuntimeError("DATABASE_URL not set")

        ledger.get_pool = _raise  # type: ignore[attr-defined]
    else:
        ledger.get_pool = AsyncMock(return_value=pool)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, ledger_name, ledger)

    # If another test (e.g. ``test_audit_helpers``) previously loaded the
    # real ``app.investigator`` package, its ``__init__`` ran
    # ``from .orchestrator import …``, which transitively executed
    # ``from . import ledger`` and bound the *real* ledger module as the
    # ``ledger`` attribute on the package object. Python's
    # ``from app.investigator import ledger as _ledger`` resolves that
    # attribute first and only falls back to ``sys.modules`` when the
    # attribute is missing — so swapping ``sys.modules`` is not enough.
    # Force the attribute to our stub so the resolver consumes it.
    pkg_obj = sys.modules[pkg_name]
    monkeypatch.setattr(pkg_obj, "ledger", ledger, raising=False)


class TestResolveWithTenant:
    @pytest.mark.asyncio
    async def test_tenant_row_with_full_override_yields_source_tenant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_vault_key(monkeypatch)
        from app.security.credential_vault import get_vault  # noqa: PLC0415

        vault = get_vault()
        assert vault is not None
        ciphertext = vault.encrypt("sk-tenant")

        row = {
            "provider": "openai_compatible",
            "base_url": "http://tenant-llm.example/v1",
            "model": "tenant-model-7b",
            "api_key_vault": ciphertext,
            "settings": {},
            "enabled": True,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")

        assert cfg.allowed is True
        assert cfg.api_key == "sk-tenant"
        assert cfg.base_url == "http://tenant-llm.example/v1"
        assert cfg.model == "tenant-model-7b"
        assert cfg.source == "tenant"
        assert cfg.reason == ""

    @pytest.mark.asyncio
    async def test_tenant_supplies_only_key_layered_over_env_is_mixed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Operator scenario: env sets base_url + model, tenant BYOKs
        # only the key. Source should be "mixed".
        monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm.internal:4000")
        monkeypatch.setenv("OPENAI_MODEL", "llama3.1-8b")
        # Note: no OPENAI_API_KEY.

        _set_vault_key(monkeypatch)
        from app.security.credential_vault import get_vault  # noqa: PLC0415

        vault = get_vault()
        assert vault is not None
        ciphertext = vault.encrypt("sk-tenant-byok")

        row = {
            "provider": "openai_compatible",
            "base_url": None,
            "model": None,
            "api_key_vault": ciphertext,
            "settings": {},
            "enabled": True,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")

        assert cfg.allowed is True
        assert cfg.api_key == "sk-tenant-byok"
        # Tenant did not contribute base_url/model — env values must win.
        assert cfg.base_url == "http://litellm.internal:4000"
        assert cfg.model == "llama3.1-8b"
        assert cfg.source == "mixed"

    @pytest.mark.asyncio
    async def test_disabled_tenant_row_is_treated_as_no_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # ``enabled=false`` lets operators pause BYOK without deletion.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-fallback")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm.internal:4000")

        _set_vault_key(monkeypatch)
        from app.security.credential_vault import get_vault  # noqa: PLC0415

        vault = get_vault()
        assert vault is not None
        row = {
            "provider": "openai_compatible",
            "base_url": "http://disabled.example",
            "model": "disabled-model",
            "api_key_vault": vault.encrypt("sk-disabled"),
            "settings": {},
            "enabled": False,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")

        # Tenant override ignored; env wins.
        assert cfg.allowed is True
        assert cfg.api_key == "sk-env-fallback"
        assert cfg.base_url == "http://litellm.internal:4000"
        assert cfg.source == "environment"

    @pytest.mark.asyncio
    async def test_corrupt_ciphertext_falls_back_to_env_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # If the tenant's stored ciphertext can't be decrypted with the
        # current vault key (mid-rotation, mistyped secret, etc.), the
        # resolver must fall back to the env key — *not* fail open and
        # *not* error out the explain request.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-fallback")
        _set_vault_key(monkeypatch)

        # Build a ciphertext under a *different* key, simulating drift.
        wrong_key = Fernet.generate_key()
        wrong_fernet = Fernet(wrong_key)
        bogus_token = "vault:v1:" + wrong_fernet.encrypt(b"sk-tenant").decode("ascii")

        row = {
            "provider": "openai_compatible",
            "base_url": "http://tenant-llm.example/v1",
            "model": "tenant-model",
            "api_key_vault": bogus_token,
            "settings": {},
            "enabled": True,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")

        # Tenant base_url + model still apply (they decrypt fine), but
        # the api_key fell back to the env value, so source is "mixed".
        assert cfg.allowed is True
        assert cfg.api_key == "sk-env-fallback"
        assert cfg.base_url == "http://tenant-llm.example/v1"
        assert cfg.model == "tenant-model"
        assert cfg.source == "mixed"

    @pytest.mark.asyncio
    async def test_vault_disabled_falls_back_to_env_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # AISOC_CREDENTIAL_KEY missing → vault.get_vault() returns None.
        # Resolver must still surface tenant base_url/model and use env key.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-fallback")
        monkeypatch.delenv("AISOC_CREDENTIAL_KEY", raising=False)
        _reset_vault()

        row = {
            "provider": "openai_compatible",
            "base_url": "http://tenant-llm.example/v1",
            "model": "tenant-model",
            # Some token — does not need to be valid because the vault
            # can't even attempt decryption without a key.
            "api_key_vault": "vault:v1:opaque",
            "settings": {},
            "enabled": True,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")

        assert cfg.allowed is True
        assert cfg.api_key == "sk-env-fallback"
        assert cfg.base_url == "http://tenant-llm.example/v1"
        assert cfg.source == "mixed"

    @pytest.mark.asyncio
    async def test_no_tenant_row_uses_env_baseline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm.internal:4000")

        pool = _make_pool_with_row(None)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")
        assert cfg.allowed is True
        assert cfg.api_key == "sk-env"
        assert cfg.source == "environment"

    @pytest.mark.asyncio
    async def test_ledger_unavailable_falls_back_to_env_baseline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate the "agents box can't reach the platform DB right now"
        # path. Resolver must never raise on this; it just degrades.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        _stub_ledger(monkeypatch, pool=None)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")
        assert cfg.allowed is True
        assert cfg.api_key == "sk-env"
        assert cfg.source == "environment"

    @pytest.mark.asyncio
    async def test_db_query_failure_falls_back_to_env_baseline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # ``conn.fetchrow`` blows up mid-query (e.g. transient outage,
        # connection cap exceeded). Must not propagate.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")

        conn = MagicMock()
        conn.fetchrow = AsyncMock(side_effect=RuntimeError("connection lost"))
        conn.execute = AsyncMock()

        acquire_cm = MagicMock()
        acquire_cm.__aenter__ = AsyncMock(return_value=conn)
        acquire_cm.__aexit__ = AsyncMock(return_value=None)
        pool = MagicMock()
        pool.acquire = MagicMock(return_value=acquire_cm)

        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")
        assert cfg.allowed is True
        assert cfg.source == "environment"


# ===========================================================================
# Integration: airgap interaction with tenant override
# ===========================================================================


class TestAirgapWithTenantOverride:
    @pytest.mark.asyncio
    async def test_airgap_allows_tenant_private_gateway(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The whole point of BYOK in air-gapped deployments: tenant
        # points at their internal LLM, AISOC_AIRGAPPED=true does *not*
        # block them.
        monkeypatch.setenv("AISOC_AIRGAPPED", "true")
        _set_vault_key(monkeypatch)
        from app.security.credential_vault import get_vault  # noqa: PLC0415

        vault = get_vault()
        assert vault is not None
        ciphertext = vault.encrypt("sk-tenant")

        row = {
            "provider": "openai_compatible",
            "base_url": "http://tenant-llm.internal:4000/v1",
            "model": "internal-model",
            "api_key_vault": ciphertext,
            "settings": {},
            "enabled": True,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")
        assert cfg.allowed is True
        assert cfg.api_key == "sk-tenant"
        assert cfg.base_url == "http://tenant-llm.internal:4000/v1"

    @pytest.mark.asyncio
    async def test_airgap_blocks_tenant_byok_to_openai(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Even with a valid tenant BYOK row, if it points at OpenAI and
        # AISOC_AIRGAPPED=true, we must refuse the live call.
        monkeypatch.setenv("AISOC_AIRGAPPED", "true")
        _set_vault_key(monkeypatch)
        from app.security.credential_vault import get_vault  # noqa: PLC0415

        vault = get_vault()
        assert vault is not None
        ciphertext = vault.encrypt("sk-tenant")

        row = {
            "provider": "openai",
            "base_url": "https://api.openai.com",
            "model": "gpt-4o-mini",
            "api_key_vault": ciphertext,
            "settings": {},
            "enabled": True,
        }
        pool = _make_pool_with_row(row)
        _stub_ledger(monkeypatch, pool)

        resolver = _import_resolver()
        cfg = await resolver.resolve_llm_config("tenant-a")
        assert cfg.allowed is False
        # See note in ``test_airgap_blocks_openai_host``: assert against the full
        # literal reason to avoid CodeQL's
        # ``py/incomplete-url-substring-sanitization`` false positive.
        assert cfg.reason == "AISOC_AIRGAPPED is on and base_url points at api.openai.com."

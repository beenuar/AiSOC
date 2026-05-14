"""Unit tests for ``app.core.cors`` — the shared FastAPI CORS helper.

The four behaviours we lock down here are:

* **Env priority** — ``AISOC_CORS_ORIGINS`` beats ``CORS_ORIGINS``.
* **Whitespace + empty entries** — operators copy/paste lists from Helm or
  the .env console and we must not turn ``"a, ,b"`` into a three-element
  allow-list that includes the empty string.
* **Default fallback** — when no env vars are set, we hand back the
  service-supplied default (or :data:`DEFAULT_CORS_ORIGINS` as a last
  resort), so vendored copies of the helper work even when shipped without
  any environment variables.
* **Production wildcard guard** — combining ``"*"`` with
  ``allow_credentials=True`` raises :class:`CORSConfigurationError` in
  production and downgrades credentials elsewhere instead of silently
  configuring a known-bad pattern.

These guarantees come from CORS spec § 6.1.3 ("If the credentials flag is
true, then the value of `Access-Control-Allow-Origin` must not be `*`") —
the bug we're guarding against is a deploy where someone leaves a wildcard
allow-list in place on the API gateway. The helper is the only thing that
keeps that from going out unnoticed, so it gets explicit unit tests rather
than relying on integration coverage.
"""

from __future__ import annotations

import pytest
from app.core.cors import (
    DEFAULT_ALLOW_HEADERS,
    DEFAULT_ALLOW_METHODS,
    DEFAULT_CORS_ORIGINS,
    CORSConfigurationError,
    build_cors_kwargs,
    resolve_cors_origins,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# All env vars the helper reads. Cleared in each test so we don't pick up
# whatever the developer happens to have exported.
_CORS_ENV_VARS = (
    "AISOC_CORS_ORIGINS",
    "CORS_ORIGINS",
    "AISOC_ENV",
    "ENVIRONMENT",
    "APP_ENV",
)


@pytest.fixture(autouse=True)
def _clean_cors_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip CORS-related env so each test starts from a known-empty slate."""
    for name in _CORS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# resolve_cors_origins
# ---------------------------------------------------------------------------


class TestResolveCorsOrigins:
    """Cover env priority + parsing edge cases."""

    def test_aisoc_cors_origins_wins_over_legacy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The deploy is mid-migration: both env vars are set. The canonical
        # name must win so we don't silently honour a stale alias.
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "https://new.example.com")
        monkeypatch.setenv("CORS_ORIGINS", "https://legacy.example.com")

        assert resolve_cors_origins() == ["https://new.example.com"]

    def test_legacy_cors_origins_used_when_canonical_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CORS_ORIGINS", "https://legacy.example.com")

        assert resolve_cors_origins() == ["https://legacy.example.com"]

    def test_empty_env_var_falls_through_to_next(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Helm sometimes sets the variable to an empty string when the
        # operator doesn't configure CORS. Treat empty as "not set".
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "")
        monkeypatch.setenv("CORS_ORIGINS", "https://legacy.example.com")

        assert resolve_cors_origins() == ["https://legacy.example.com"]

    def test_whitespace_and_blank_entries_are_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "AISOC_CORS_ORIGINS",
            "  https://a.example.com , ,https://b.example.com,  ",
        )

        assert resolve_cors_origins() == [
            "https://a.example.com",
            "https://b.example.com",
        ]

    def test_default_fallback_when_unset(self) -> None:
        assert resolve_cors_origins() == list(DEFAULT_CORS_ORIGINS)

    def test_service_supplied_default_overrides_module_default(self) -> None:
        custom = ["https://service.local"]

        assert resolve_cors_origins(default=custom) == custom


# ---------------------------------------------------------------------------
# build_cors_kwargs — non-production / safe paths
# ---------------------------------------------------------------------------


class TestBuildCorsKwargsSafePaths:
    """The happy-path cases that production deploys should hit."""

    def test_returns_methods_and_headers_compatible_with_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "https://app.example.com")

        kwargs = build_cors_kwargs(service_name="api", allow_credentials=True)

        assert kwargs["allow_origins"] == ["https://app.example.com"]
        assert kwargs["allow_credentials"] is True
        # We must enumerate methods/headers when credentials=True; browsers
        # reject "*" in that combination.
        assert kwargs["allow_methods"] == list(DEFAULT_ALLOW_METHODS)
        assert kwargs["allow_headers"] == list(DEFAULT_ALLOW_HEADERS)
        assert "*" not in kwargs["allow_methods"]
        assert "*" not in kwargs["allow_headers"]

    def test_no_credentials_uses_wildcard_methods_headers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # For services like /enrich + /ueba we don't carry cookies, so the
        # spec allows "*" — and it keeps the surface forward-compatible.
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "https://app.example.com")

        kwargs = build_cors_kwargs(service_name="ueba", allow_credentials=False)

        assert kwargs["allow_credentials"] is False
        assert kwargs["allow_methods"] == ["*"]
        assert kwargs["allow_headers"] == ["*"]

    def test_caller_overrides_methods_and_headers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "https://app.example.com")

        kwargs = build_cors_kwargs(
            service_name="connectors",
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "X-Tenant-ID"],
            expose_headers=["X-Request-ID"],
        )

        assert kwargs["allow_methods"] == ["GET", "POST"]
        assert kwargs["allow_headers"] == ["Authorization", "X-Tenant-ID"]
        assert kwargs["expose_headers"] == ["X-Request-ID"]

    def test_expose_headers_omitted_when_not_provided(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "https://app.example.com")

        kwargs = build_cors_kwargs(service_name="api", allow_credentials=True)

        # Starlette's CORSMiddleware defaults expose_headers=() when missing;
        # we mirror that by leaving the key out entirely, so we don't fight
        # the framework over an empty list.
        assert "expose_headers" not in kwargs


# ---------------------------------------------------------------------------
# build_cors_kwargs — wildcard + credentials production guard
# ---------------------------------------------------------------------------


class TestBuildCorsKwargsProductionGuard:
    """The reason this helper exists at all: catching unsafe deploys."""

    @pytest.mark.parametrize(
        "env_var,env_value",
        [
            ("AISOC_ENV", "production"),
            ("AISOC_ENV", "prod"),
            ("AISOC_ENV", "PRODUCTION"),  # case-insensitive
            ("ENVIRONMENT", "production"),
            ("APP_ENV", "prod"),
        ],
    )
    def test_wildcard_plus_credentials_raises_in_production(
        self,
        monkeypatch: pytest.MonkeyPatch,
        env_var: str,
        env_value: str,
    ) -> None:
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "*")
        monkeypatch.setenv(env_var, env_value)

        with pytest.raises(CORSConfigurationError) as excinfo:
            build_cors_kwargs(service_name="api", allow_credentials=True)

        # Error message should name the service and point at the fix —
        # operators need to know what to set, not just what's wrong.
        assert "api" in str(excinfo.value)
        assert "AISOC_CORS_ORIGINS" in str(excinfo.value)

    def test_wildcard_plus_credentials_downgrades_outside_production(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # No env var set → not production. Dev shouldn't fail to start just
        # because someone exported CORS_ORIGINS=* in their shell.
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "*")

        with caplog.at_level("WARNING", logger="app.core.cors"):
            kwargs = build_cors_kwargs(service_name="api", allow_credentials=True)

        assert kwargs["allow_origins"] == ["*"]
        # The whole point of the guard: credentials get silently disabled so
        # the spec-incompatible combination never goes out.
        assert kwargs["allow_credentials"] is False
        assert any("wildcard" in record.message.lower() and "api" in record.message for record in caplog.records)

    def test_wildcard_without_credentials_is_allowed_everywhere(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Public, unauthenticated surfaces (honeytoken pixels, /healthz on
        # public probes) can legitimately ship a wildcard. We must not
        # break those.
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "*")
        monkeypatch.setenv("AISOC_ENV", "production")

        kwargs = build_cors_kwargs(service_name="honeytokens", allow_credentials=False)

        assert kwargs["allow_origins"] == ["*"]
        assert kwargs["allow_credentials"] is False

    def test_explicit_list_unaffected_by_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_CORS_ORIGINS", "https://app.example.com")
        monkeypatch.setenv("AISOC_ENV", "production")

        kwargs = build_cors_kwargs(service_name="api", allow_credentials=True)

        # An explicit allow-list is the safe path — no warnings, no
        # downgrades, credentials stay enabled.
        assert kwargs["allow_origins"] == ["https://app.example.com"]
        assert kwargs["allow_credentials"] is True

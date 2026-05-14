"""Tests for the canonical "dev mode" detection helpers (Batch 11 — H-8 + P2-A3).

Background
----------
Before unification, several modules each rolled their own check for
"is this a development environment?":

* ``services/api/app/api/v1/dev_auth.py`` used ``ENV in {"dev", "development", "local"}``
* ``services/api/app/core/logging.py`` used ``ENV == "development"``
* ``services/api/app/main.py`` used ``ENVIRONMENT in {"development", "dev"}``
* ``services/api/app/security/credential_vault.py`` had its own helper

Each list was slightly different, so the same boot could be "dev" for
one check and "prod" for another. This file pins the unified behavior
so future refactors cannot regress it.

The canonical helpers live in ``app.core.config``:

* :data:`DEV_ENVIRONMENTS` — most subsystems (incl. ``"test"``)
* :data:`AUTH_BYPASS_ENVIRONMENTS` — dev-auth shim (excludes ``"test"``)
* :func:`is_dev_env(value)` — pure predicate over a string
* :func:`is_auth_bypass_env(value)` — pure predicate over a string
* :func:`current_env_from_os` — reads ``$ENV`` / ``$ENVIRONMENT`` at call time
* :func:`is_dev_mode_runtime` — convenience combiner of the two above
* :meth:`Settings.is_dev` / :meth:`Settings.is_production` — settings-level predicates
* :meth:`Settings._reconcile_env_aliases` — model-validator that mirrors
  ``ENV`` ↔ ``ENVIRONMENT`` so an operator who sets only one isn't
  silently treated as production by code that reads the other.
"""

from __future__ import annotations

import warnings

import pytest
from app.core.config import (
    AUTH_BYPASS_ENVIRONMENTS,
    DEV_ENVIRONMENTS,
    Settings,
    current_env_from_os,
    is_auth_bypass_env,
    is_dev_env,
    is_dev_mode_runtime,
)

# ─── Helpers ─────────────────────────────────────────────────────────────


def _make_settings(**overrides) -> Settings:
    """Construct a Settings instance without reading the host .env file."""
    base: dict = {
        "ENVIRONMENT": "production",
        "ENV": "production",
        "SECRET_KEY": "a" * 64,
        "METRICS_TOKEN": "long-random-token",
        "PLUGIN_TRUST_MODE": "strict",
        "AISOC_CREDENTIAL_KEY": "Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


# ─── DEV_ENVIRONMENTS / AUTH_BYPASS_ENVIRONMENTS invariants ──────────────


def test_dev_environments_contains_canonical_set():
    """The dev set MUST contain these five names (audit-pinned)."""
    assert {"development", "dev", "local", "demo", "test"} <= DEV_ENVIRONMENTS


def test_auth_bypass_environments_excludes_test():
    """``"test"`` must NOT permit the auth bypass.

    Otherwise any test suite that forgets to seed an Authorization
    header is silently handed admin-on-the-demo-tenant, masking real
    auth regressions.
    """
    assert "test" in DEV_ENVIRONMENTS
    assert "test" not in AUTH_BYPASS_ENVIRONMENTS


def test_auth_bypass_environments_is_strict_subset_of_dev():
    """Auth-bypass ⊊ dev. Anything that bypasses auth is by definition dev."""
    assert AUTH_BYPASS_ENVIRONMENTS < DEV_ENVIRONMENTS


def test_dev_and_auth_bypass_sets_are_frozensets():
    """Both must be frozensets so a downstream caller cannot mutate them."""
    assert isinstance(DEV_ENVIRONMENTS, frozenset)
    assert isinstance(AUTH_BYPASS_ENVIRONMENTS, frozenset)


# ─── is_dev_env() ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    ["development", "dev", "local", "demo", "test"],
)
def test_is_dev_env_true_for_canonical_names(value):
    assert is_dev_env(value) is True


@pytest.mark.parametrize(
    "value",
    ["production", "prod", "staging", "stage", "preprod", "uat", "qa"],
)
def test_is_dev_env_false_for_non_dev(value):
    assert is_dev_env(value) is False


@pytest.mark.parametrize(
    "value",
    [None, "", "   "],
)
def test_is_dev_env_false_for_empty_or_none(value):
    # Empty/missing must NOT be silently treated as dev — otherwise
    # an operator forgetting to set the env var gets the dev rails
    # (auth bypass, ephemeral creds, etc.) in production.
    assert is_dev_env(value) is False


@pytest.mark.parametrize(
    "value, expected",
    [
        ("DEVELOPMENT", True),
        ("Production", False),
        ("  dev  ", True),
        ("\tlocal\n", True),
        ("  PROD  ", False),
    ],
)
def test_is_dev_env_normalizes_case_and_whitespace(value, expected):
    assert is_dev_env(value) is expected


def test_is_dev_env_unknown_string_is_false():
    """A typo / unknown environment name fails closed (treated as prod)."""
    assert is_dev_env("developement") is False  # common typo
    assert is_dev_env("dev1") is False
    assert is_dev_env("development2") is False


# ─── is_auth_bypass_env() ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    ["development", "dev", "local", "demo"],
)
def test_is_auth_bypass_env_true_for_bypass_names(value):
    assert is_auth_bypass_env(value) is True


def test_is_auth_bypass_env_false_for_test():
    """Pinned in is own test: ``test`` must NOT enable the auth bypass."""
    assert is_auth_bypass_env("test") is False


@pytest.mark.parametrize(
    "value",
    ["production", "prod", "staging", None, "", "qa"],
)
def test_is_auth_bypass_env_false_for_non_dev(value):
    assert is_auth_bypass_env(value) is False


def test_is_auth_bypass_env_normalizes_case():
    assert is_auth_bypass_env("DEV") is True
    assert is_auth_bypass_env("  Demo  ") is True


# ─── current_env_from_os() ───────────────────────────────────────────────


def test_current_env_from_os_prefers_env_over_environment(monkeypatch):
    """``ENV`` wins when both are set (matches Settings ordering)."""
    monkeypatch.setenv("ENV", "dev")
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert current_env_from_os() == "dev"


def test_current_env_from_os_falls_back_to_environment(monkeypatch):
    """When ``ENV`` is unset, ``ENVIRONMENT`` is used."""
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert current_env_from_os() == "production"


def test_current_env_from_os_returns_empty_when_neither_set(monkeypatch):
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert current_env_from_os() == ""


def test_current_env_from_os_normalizes_case_and_whitespace(monkeypatch):
    monkeypatch.setenv("ENV", "  DEVELOPMENT  ")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert current_env_from_os() == "development"


def test_current_env_from_os_reads_live_environment(monkeypatch):
    """No caching — a mid-test setenv is reflected immediately."""
    monkeypatch.setenv("ENV", "dev")
    assert current_env_from_os() == "dev"
    monkeypatch.setenv("ENV", "production")
    assert current_env_from_os() == "production"


# ─── is_dev_mode_runtime() ───────────────────────────────────────────────


def test_is_dev_mode_runtime_true_for_dev_envs(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert is_dev_mode_runtime() is True


def test_is_dev_mode_runtime_true_for_test_env(monkeypatch):
    monkeypatch.setenv("ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert is_dev_mode_runtime() is True


def test_is_dev_mode_runtime_false_for_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert is_dev_mode_runtime() is False


def test_is_dev_mode_runtime_false_when_unset(monkeypatch):
    """Missing env fails closed → not dev (i.e. treat as production)."""
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert is_dev_mode_runtime() is False


# ─── Settings.is_dev / Settings.is_production ────────────────────────────


@pytest.mark.parametrize(
    "env_name",
    ["development", "dev", "local", "demo", "test"],
)
def test_settings_is_dev_true_for_dev_envs(env_name):
    s = _make_settings(ENVIRONMENT=env_name, ENV=env_name)
    assert s.is_dev is True
    assert s.is_production is False


@pytest.mark.parametrize(
    "env_name",
    ["production", "prod", "staging", "qa"],
)
def test_settings_is_dev_false_for_non_dev_envs(env_name):
    s = _make_settings(ENVIRONMENT=env_name, ENV=env_name)
    assert s.is_dev is False
    assert s.is_production is True


def test_settings_is_dev_is_property_not_method():
    """Catch the easy regression of calling it as ``settings.is_dev()``."""
    s = _make_settings(ENVIRONMENT="development", ENV="development")
    assert isinstance(s.is_dev, bool)
    assert isinstance(s.is_production, bool)


# ─── _reconcile_env_aliases model validator ──────────────────────────────


def test_reconcile_mirrors_environment_to_env_when_only_environment_set():
    """Operator sets ENVIRONMENT=production only; ENV is the class default.

    Validator must mirror ENVIRONMENT→ENV so a module that reads
    ``settings.ENV`` doesn't silently see ``"development"``.
    """
    s = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        # leave ENV at its class default
        SECRET_KEY="a" * 64,
        METRICS_TOKEN="long-random-token",
        AISOC_CREDENTIAL_KEY="Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
    )
    assert s.ENVIRONMENT == "production"
    assert s.ENV == "production"


def test_reconcile_mirrors_env_to_environment_when_only_env_set():
    """Reverse direction — operator sets only ENV."""
    s = Settings(
        _env_file=None,
        ENV="production",
        # leave ENVIRONMENT at its class default
        SECRET_KEY="a" * 64,
        METRICS_TOKEN="long-random-token",
        AISOC_CREDENTIAL_KEY="Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
    )
    assert s.ENV == "production"
    assert s.ENVIRONMENT == "production"


def test_reconcile_both_set_and_agree_no_warning():
    """No warning when both are set to the same value."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        s = _make_settings(ENV="production", ENVIRONMENT="production")
        assert s.ENV == "production"
        assert s.ENVIRONMENT == "production"
        # No reconciliation warning should have fired.
        assert not any("disagree" in str(w.message) for w in caught), [str(w.message) for w in caught]


def test_reconcile_disagreement_prefers_environment_and_warns():
    """When ENV and ENVIRONMENT both have non-default values and disagree,
    ENVIRONMENT wins (newer alias) and a RuntimeWarning surfaces so
    operators see it in boot logs.

    The validator only treats both as "explicitly set" when neither
    equals the class default ``"development"`` — so we use two distinct
    non-default values here.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        s = _make_settings(ENV="staging", ENVIRONMENT="production")
        # ENVIRONMENT preference → mirrored into ENV
        assert s.ENVIRONMENT == "production"
        assert s.ENV == "production"
        msgs = [str(w.message) for w in caught if issubclass(w.category, RuntimeWarning)]
        assert any("disagree" in m for m in msgs), msgs


def test_reconcile_default_env_with_explicit_environment_no_warning():
    """``ENV`` defaulting to ``"development"`` while ``ENVIRONMENT`` is
    set explicitly is NOT a disagreement — it's the common mirror case.

    The validator must silently mirror ``ENVIRONMENT`` into ``ENV``
    without a noisy warning.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        s = Settings(
            _env_file=None,
            ENVIRONMENT="production",
            # ENV omitted → stays at class default "development"
            SECRET_KEY="a" * 64,
            METRICS_TOKEN="long-random-token",
            AISOC_CREDENTIAL_KEY="Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
        )
        assert s.ENV == "production"
        assert s.ENVIRONMENT == "production"
        # No "disagree" warning — operator only set one of them.
        msgs = [str(w.message) for w in caught]
        assert not any("disagree" in m for m in msgs), msgs


def test_reconcile_both_default_stays_development():
    """Neither set explicitly → both stay at the class default."""
    s = Settings(
        _env_file=None,
        SECRET_KEY="a" * 64,
        AISOC_CREDENTIAL_KEY="Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
    )
    assert s.ENV == "development"
    assert s.ENVIRONMENT == "development"
    assert s.is_dev is True


# ─── Integration: dev_auth.is_dev_mode honors env changes ────────────────


def test_dev_auth_is_dev_mode_reads_live_env(monkeypatch):
    """``dev_auth.is_dev_mode()`` must reflect a mid-test env change.

    Catches the regression of caching the result with ``@lru_cache`` —
    we deliberately do NOT cache so monkeypatching works.
    """
    from app.api.v1 import dev_auth

    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert dev_auth.is_dev_mode() is True

    monkeypatch.setenv("ENV", "production")
    assert dev_auth.is_dev_mode() is False


def test_dev_auth_is_dev_mode_excludes_test(monkeypatch):
    """``ENV=test`` must NOT trip the auth bypass even though it IS a dev env."""
    from app.api.v1 import dev_auth

    monkeypatch.setenv("ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert dev_auth.is_dev_mode() is False


def test_dev_auth_is_dev_mode_honors_environment_fallback(monkeypatch):
    """Operator sets only ENVIRONMENT — dev_auth still picks it up."""
    from app.api.v1 import dev_auth

    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert dev_auth.is_dev_mode() is True

    monkeypatch.setenv("ENVIRONMENT", "production")
    assert dev_auth.is_dev_mode() is False

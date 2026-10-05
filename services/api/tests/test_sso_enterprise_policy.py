"""SSO enterprise-policy suite: role vocabulary, provisioning gates, flags.

These tests lock the security properties of the SSO wave, not its shape:
least-privilege defaults, fail-closed gates, auditable role changes, and the
feature flag that keeps the whole surface shut until verified.
"""

from __future__ import annotations

import pytest

# ── role vocabulary ──────────────────────────────────────────────────────────


def test_infosec_role_exists_and_is_least_privilege_analyst() -> None:
    from app.core.security import ROLE_PERMISSIONS

    infosec = set(ROLE_PERMISSIONS["infosec"])
    # The spec floor: analyst work is fully available.
    assert {
        "alerts:read",
        "alerts:write",
        "cases:read",
        "cases:write",
        "threat_intel:read",
        "threat_intel:write",
        "rules:write",
        "playbooks:execute",
        "lake:query",
        "reports:read",
    } <= infosec
    # The ceiling: no user, role, settings, credential, audit or admin door.
    forbidden = {
        "users:write",
        "users:delete",
        "roles:write",
        "roles:delete",
        "settings:write",
        "api_keys:manage",
        "platform_admin",
        "alert_source_raw:read",
        "audit:delete",
        "connectors:write",
    }
    assert not (infosec & forbidden)


def test_viewer_stays_the_floor_after_the_wave() -> None:
    from app.core.security import ROLE_PERMISSIONS

    viewer = set(ROLE_PERMISSIONS["viewer"])
    assert "alerts:write" not in viewer
    assert "users:write" not in viewer
    assert "roles:write" not in viewer


def test_infosec_is_grantable_and_admin_never_is() -> None:
    from app.core import role_grants

    assert "infosec" in role_grants.GRANTABLE_ROLES
    assert "infosec" not in role_grants.never_grantable()
    # Wildcard roles stay out of band no matter who asks — including the
    # SSO group-mapping path, which draws from this same vocabulary.
    assert "admin" in role_grants.never_grantable()
    assert "platform_admin" in role_grants.never_grantable()


# ── group → role mapping ─────────────────────────────────────────────────────


def test_infosec_group_maps_above_viewer_and_below_analyst() -> None:
    from app.auth.sso_provisioning import map_groups_to_role

    mapping = {"AiSOC.Viewer": "viewer", "AiSOC.InfoSec": "infosec"}
    assert map_groups_to_role(["AiSOC.InfoSec"], mapping) == "infosec"
    # highest wins regardless of order
    assert map_groups_to_role(["AiSOC.Viewer", "AiSOC.InfoSec"], mapping) == "infosec"
    assert map_groups_to_role(["AiSOC.InfoSec", "AiSOC.Viewer"], mapping) == "infosec"


def test_admin_group_mapping_is_refused_not_applied() -> None:
    from app.auth.sso_provisioning import map_groups_to_role

    # Even if an operator wires `admin` into the mapping (the endpoint
    # rejects it upstream; this is the second door), provisioning itself
    # falls back rather than conferring it.
    assert map_groups_to_role(["admins"], {"admins": "admin"}) == "viewer"


def test_default_role_is_viewer() -> None:
    from app.auth.sso_provisioning import DEFAULT_ROLE

    assert DEFAULT_ROLE == "viewer"


# ── domain allowlist ─────────────────────────────────────────────────────────


def test_domain_allowlist_fails_closed() -> None:
    from app.auth.sso_provisioning import _domain_allowed, _parse_domain_allowlist

    allowed = _parse_domain_allowlist("Example.COM, partner.io")
    assert _domain_allowed("a@example.com", allowed)
    assert _domain_allowed("a@PARTNER.IO", allowed)
    assert not _domain_allowed("a@evil.com", allowed)
    assert not _domain_allowed("nope", allowed)


def test_sso_feature_flag_defaults_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.auth.oidc import _sso_feature_enabled

    monkeypatch.delenv("SSO_ENABLED", raising=False)
    assert not _sso_feature_enabled()
    monkeypatch.setenv("SSO_ENABLED", "false")
    assert not _sso_feature_enabled()
    monkeypatch.setenv("SSO_ENABLED", "true")
    assert _sso_feature_enabled()


def test_status_endpoint_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from app.api.v1.endpoints import auth as auth_ep

    monkeypatch.delenv("SSO_ENABLED", raising=False)
    monkeypatch.delenv("SSO_LOCAL_ADMIN_ONLY", raising=False)
    monkeypatch.delenv("SSO_LOGIN_LABEL", raising=False)
    out = asyncio.run(auth_ep.sso_status())
    assert out["sso_enabled"] is False  # hidden by default
    assert out["local_login_enabled"] is True  # break-glass stays open

    monkeypatch.setenv("SSO_ENABLED", "true")
    monkeypatch.setenv("SSO_LOGIN_LABEL", "Sign in with Acme")
    out = asyncio.run(auth_ep.sso_status())
    assert out["sso_enabled"] is True
    assert out["login_label"] == "Sign in with Acme"
    assert out["local_login_enabled"] is True  # until the operator closes it

    monkeypatch.setenv("SSO_LOCAL_ADMIN_ONLY", "true")
    out = asyncio.run(auth_ep.sso_status())
    assert out["local_login_enabled"] is False

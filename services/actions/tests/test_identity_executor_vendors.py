"""
Phase 3.4 vendor-dispatch tests for identity executors.

We stub the per-vendor client factories so we can verify the
executor picks the right vendor in priority order (Okta → Entra
→ GWS → simulation) without hitting any external API.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.executors import identity
from app.executors.identity import (
    DisableUserExecutor,
    ForceMFAExecutor,
    ResetPasswordExecutor,
    SuspendSessionExecutor,
)
from app.models.action import ActionRequest, ActionStatus, ActionType


def _request(action_type: ActionType, **params: object) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=action_type,
        target="alice@corp.com",
        parameters=dict(params),
    )


class _OkClient:
    """A stub IdP client whose methods all return success dicts.

    Every IdP method shape is slightly different (Okta uses
    `disable_user`, Entra uses `disable_user`, GWS uses
    `suspend_user`), so we accept anything.
    """

    def __init__(self, label: str) -> None:
        self._label = label

    async def disable_user(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "disable_user", "success": True}

    async def suspend_user(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "suspend_user", "success": True}

    async def clear_sessions(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "clear_sessions"}

    async def revoke_sessions(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "revoke_sessions", "success": True}

    async def reset_password(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "reset_password", "success": True}

    async def require_mfa(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "require_mfa", "success": True}

    async def enforce_2sv(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "enforce_2sv", "success": True}

    async def force_mfa_enrollment(self, *_args: object, **_kw: object) -> dict:
        return {"vendor": self._label, "verb": "force_mfa_enrollment", "success": True}


# --------------------------- Disable user ---------------------------


@pytest.mark.asyncio
async def test_disable_user_prefers_okta_when_all_three_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: _OkClient("okta"))
    monkeypatch.setattr(identity, "_entra_client", lambda params: _OkClient("entra"))
    monkeypatch.setattr(identity, "_gws_client", lambda params: _OkClient("gws"))

    result = await DisableUserExecutor().execute(_request(ActionType.DISABLE_USER))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "okta"
    assert result.rollback_data["vendor"] == "okta"


@pytest.mark.asyncio
async def test_disable_user_uses_entra_when_okta_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: _OkClient("entra"))
    monkeypatch.setattr(identity, "_gws_client", lambda params: _OkClient("gws"))

    result = await DisableUserExecutor().execute(_request(ActionType.DISABLE_USER))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "entra"
    assert result.rollback_data["vendor"] == "entra"


@pytest.mark.asyncio
async def test_disable_user_uses_gws_when_only_gws_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: None)
    monkeypatch.setattr(identity, "_gws_client", lambda params: _OkClient("gws"))

    result = await DisableUserExecutor().execute(_request(ActionType.DISABLE_USER))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "gws"
    # GWS verb is suspend_user, not disable_user — confirm we did
    # call the right method shape.
    assert result.output["verb"] == "suspend_user"
    assert result.rollback_data["vendor"] == "gws"


@pytest.mark.asyncio
async def test_disable_user_falls_through_to_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: None)
    monkeypatch.setattr(identity, "_gws_client", lambda params: None)

    result = await DisableUserExecutor().execute(_request(ActionType.DISABLE_USER))
    assert result.status == ActionStatus.COMPLETED
    assert "Simulation mode" in result.output["note"]
    # Sim path must list all three credential bundles.
    assert "okta_domain" in result.output["note"]
    assert "azure_tenant_id" in result.output["note"]
    assert "gws_service_account_key" in result.output["note"]


# --------------------------- Suspend session ---------------------------


@pytest.mark.asyncio
async def test_suspend_session_uses_entra_revoke_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: _OkClient("entra"))
    monkeypatch.setattr(identity, "_gws_client", lambda params: None)

    result = await SuspendSessionExecutor().execute(_request(ActionType.SUSPEND_SESSION))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "entra"
    assert result.output["verb"] == "revoke_sessions"


@pytest.mark.asyncio
async def test_suspend_session_uses_gws_signout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: None)
    monkeypatch.setattr(identity, "_gws_client", lambda params: _OkClient("gws"))

    result = await SuspendSessionExecutor().execute(_request(ActionType.SUSPEND_SESSION))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "gws"
    assert result.output["verb"] == "revoke_sessions"


# --------------------------- Reset password ---------------------------


@pytest.mark.asyncio
async def test_reset_password_uses_entra_when_okta_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: _OkClient("entra"))
    monkeypatch.setattr(identity, "_gws_client", lambda params: None)

    result = await ResetPasswordExecutor().execute(_request(ActionType.RESET_PASSWORD))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "entra"
    # Critical security invariant: the temp password is never in
    # the executor's output dict.
    assert "password" not in result.output
    assert "temp_password" not in result.output


@pytest.mark.asyncio
async def test_reset_password_uses_gws_when_only_gws_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: None)
    monkeypatch.setattr(identity, "_gws_client", lambda params: _OkClient("gws"))

    result = await ResetPasswordExecutor().execute(_request(ActionType.RESET_PASSWORD))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "gws"
    assert "password" not in result.output


# --------------------------- Force MFA ---------------------------


@pytest.mark.asyncio
async def test_force_mfa_uses_entra_require_mfa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: _OkClient("entra"))
    monkeypatch.setattr(identity, "_gws_client", lambda params: None)

    result = await ForceMFAExecutor().execute(_request(ActionType.FORCE_MFA))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "entra"
    assert result.output["verb"] == "require_mfa"


@pytest.mark.asyncio
async def test_force_mfa_uses_gws_enforce_2sv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity, "_okta_client", lambda params: None)
    monkeypatch.setattr(identity, "_entra_client", lambda params: None)
    monkeypatch.setattr(identity, "_gws_client", lambda params: _OkClient("gws"))

    result = await ForceMFAExecutor().execute(_request(ActionType.FORCE_MFA))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["vendor"] == "gws"
    assert result.output["verb"] == "enforce_2sv"

"""Identity executors must call their IdP clients with the signatures they have.

The companion to ``test_siem_client_signatures.py``, for the same defect and
the same reason: simulation mode never constructs a vendor client, so a wrong
keyword argument is invisible in every test that supplies no credentials and
raises ``TypeError`` on the first live call.

This one shipped. ``ResetPasswordExecutor`` documents ``parameters.send_email``
as "used only for the Okta path" and passed ``send_email=`` to
``OktaClient.reset_password(self, login_or_id)``, which did not accept it. The
executor's ``except Exception`` turned the ``TypeError`` into a FAILED
``ActionResult``, so the verb did not crash — it simply could never succeed
against Okta, and the failure looked like an Okta problem.

``test_identity_executor_vendors.py`` covers the same executors and could not
catch it, because its stub client is ``async def reset_password(self, *_args,
**_kw)``. A fake that accepts anything proves the dispatch order and nothing
about the call. ``create_autospec(..., spec_set=True)`` enforces the real
signature and fails exactly where the live client would.
"""

from __future__ import annotations

from unittest.mock import create_autospec
from uuid import uuid4

import pytest
from app.clients.azure_entra_client import AzureEntraClient
from app.clients.google_workspace_client import GoogleWorkspaceClient
from app.clients.okta_client import OktaClient
from app.executors import identity
from app.executors.identity import (
    DisableUserExecutor,
    ForceMFAExecutor,
    ResetPasswordExecutor,
    SuspendSessionExecutor,
)
from app.models.action import ActionRequest, ActionStatus, ActionType

_FACTORIES = ("_okta_client", "_entra_client", "_gws_client")


def _autospec(cls: type):
    """An autospec whose methods reject arguments the real client rejects."""
    return create_autospec(cls, spec_set=True, instance=True)


def _request(action_type: ActionType, **parameters: object) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=action_type,
        target="alice@corp.com",
        parameters=dict(parameters),
        rationale="signature conformance test",
    )


def _only(monkeypatch: pytest.MonkeyPatch, factory: str, client: object) -> None:
    """Wire one vendor in and the other two out, so dispatch is unambiguous."""
    for attr in _FACTORIES:
        monkeypatch.setattr(identity, attr, (lambda params: client) if attr == factory else (lambda params: None))


@pytest.mark.asyncio
async def test_okta_reset_password_matches_the_client_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fails on the pre-fix client: `send_email=` was not a parameter of it."""
    client = _autospec(OktaClient)
    client.reset_password.return_value = {"success": True}
    _only(monkeypatch, "_okta_client", client)

    result = await ResetPasswordExecutor().execute(_request(ActionType.RESET_PASSWORD, send_email=False))

    assert result.status is ActionStatus.COMPLETED, result.error
    assert client.reset_password.call_args.kwargs["send_email"] is False


@pytest.mark.asyncio
async def test_okta_reset_password_defaults_to_sending_the_email(monkeypatch: pytest.MonkeyPatch) -> None:
    """The documented default — a reset the user is never told about is not one."""
    client = _autospec(OktaClient)
    client.reset_password.return_value = {"success": True}
    _only(monkeypatch, "_okta_client", client)

    result = await ResetPasswordExecutor().execute(_request(ActionType.RESET_PASSWORD))

    assert result.status is ActionStatus.COMPLETED, result.error
    assert client.reset_password.call_args.kwargs["send_email"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("executor_cls", "action_type", "factory", "client_cls", "method"),
    [
        (DisableUserExecutor, ActionType.DISABLE_USER, "_okta_client", OktaClient, "disable_user"),
        (DisableUserExecutor, ActionType.DISABLE_USER, "_entra_client", AzureEntraClient, "disable_user"),
        (DisableUserExecutor, ActionType.DISABLE_USER, "_gws_client", GoogleWorkspaceClient, "suspend_user"),
        (ResetPasswordExecutor, ActionType.RESET_PASSWORD, "_entra_client", AzureEntraClient, "reset_password"),
        (ResetPasswordExecutor, ActionType.RESET_PASSWORD, "_gws_client", GoogleWorkspaceClient, "reset_password"),
        (SuspendSessionExecutor, ActionType.SUSPEND_SESSION, "_entra_client", AzureEntraClient, "revoke_sessions"),
        (SuspendSessionExecutor, ActionType.SUSPEND_SESSION, "_gws_client", GoogleWorkspaceClient, "revoke_sessions"),
        (ForceMFAExecutor, ActionType.FORCE_MFA, "_okta_client", OktaClient, "force_mfa_enrollment"),
        (ForceMFAExecutor, ActionType.FORCE_MFA, "_entra_client", AzureEntraClient, "require_mfa"),
    ],
)
async def test_every_identity_arm_matches_its_client_signature(
    monkeypatch: pytest.MonkeyPatch,
    executor_cls: type,
    action_type: ActionType,
    factory: str,
    client_cls: type,
    method: str,
) -> None:
    """Every remaining executor/vendor pair, under a spec that can reject."""
    client = _autospec(client_cls)
    getattr(client, method).return_value = {"success": True}
    _only(monkeypatch, factory, client)

    result = await executor_cls().execute(_request(action_type))

    assert result.status is ActionStatus.COMPLETED, result.error
    getattr(client, method).assert_called_once()


@pytest.mark.asyncio
async def test_okta_suspend_session_calls_both_halves_under_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Okta session arm is two calls, and both have to match."""
    client = _autospec(OktaClient)
    client.clear_sessions.return_value = {"success": True}
    client.suspend_user.return_value = {"success": True}
    _only(monkeypatch, "_okta_client", client)

    result = await SuspendSessionExecutor().execute(_request(ActionType.SUSPEND_SESSION))

    assert result.status is ActionStatus.COMPLETED, result.error
    client.clear_sessions.assert_called_once()
    client.suspend_user.assert_called_once()

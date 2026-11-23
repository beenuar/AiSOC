"""``POST /actions/{action_id}/undo``: the user-facing door to a reversal.

This layer decides two things and no more — which connector holds the
credentials for the vendor the action executed against, and where a reversal
that needs a human goes to wait — exactly the split the playbook-step
dispatch draws. Whether the undo may run belongs to ``services/actions``,
which grades the reverse capability's contract.

The load-bearing assertions:

* credentials come from the tenant's stored integration through the vault,
  never from the request — the request body cannot even carry them, because
  unknown fields are refused;
* an undo the grading queues lands in the approvals inbox, and the decide
  path re-drives it with the deciding identity bound as the approver;
* every outcome is audited with who asked, which action, and what the
  reversal answered.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import action_undo as endpoint_module
from app.api.v1.endpoints import approvals as approvals_module
from app.models.responder import AgentApproval
from app.services import action_undo as service_module
from app.services import actions_client
from fastapi import Request
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.asyncio

TENANT = uuid.uuid4()
ACTION_ID = str(uuid.uuid4())


def _user(**overrides: Any) -> CurrentUser:
    base: dict[str, Any] = {
        "user_id": uuid.uuid4(),
        "tenant_id": TENANT,
        "role": "analyst",
        "email": "rory@example.com",
        "resolved_permissions": frozenset({"actions:execute", "actions:execute:medium", "cases:write"}),
    }
    base.update(overrides)
    return CurrentUser(**base)


def _stored_record(**overrides: Any) -> dict[str, Any]:
    record = {
        "id": ACTION_ID,
        "tenant_id": str(TENANT),
        "status": "completed",
        "action_type": "sync_detection_rule",
        "target": "AiSOC - brute force by user",
        "output": {"vendor": "splunk", "rule_name": "AiSOC - brute force by user"},
        "rollback_data": {"vendor": "splunk", "name": "AiSOC - brute force by user", "prior": {"search": "index=main"}},
        "parameters": {},
    }
    record.update(overrides)
    return record


class _Connector:
    connector_type = "splunk"
    name = "splunk"
    auth_config = {"token": "vault:v1:ciphertext"}
    connector_config = {"base_url": "https://splunk.example:8089"}
    allowed_capabilities = None


class _Vault:
    def decrypt_dict(self, blob: dict) -> dict:
        return {"token": "decrypted-from-vault"}


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    record: dict[str, Any] | None = None,
    connector: Any = _Connector(),
    upstream: dict[str, Any] | Exception | None = None,
) -> list[dict[str, Any]]:
    """Stand in for the actions service, the tenant database and the vault."""
    sent: list[dict[str, Any]] = []

    async def _get_action(**kwargs: Any) -> dict[str, Any]:
        if record is None:
            raise actions_client.ActionsServiceError("Action not found", status_code=404, upstream_detail="Action not found")
        return record

    async def _undo_action(**kwargs: Any) -> dict[str, Any]:
        sent.append(kwargs)
        if isinstance(upstream, Exception):
            raise upstream
        return upstream or {
            "action_id": kwargs["action_id"],
            "status": "rolled_back",
            "reversed": True,
            "vendor_id": "splunk",
            "rolled_back_at": "2026-11-22T00:00:00+00:00",
            "rolled_back_by": "rory@example.com",
        }

    async def _pick(db: Any, *, tenant_id: Any, capability: str, implementers: list[str], pinned: str) -> Any:
        return connector

    monkeypatch.setattr(actions_client, "get_action", _get_action, raising=False)
    monkeypatch.setattr(actions_client, "undo_action", _undo_action, raising=False)
    monkeypatch.setattr(service_module, "_pick_connector", _pick)
    monkeypatch.setattr(service_module, "get_vault", _Vault)
    return sent


class _AuditSpy:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[dict[str, Any]] = []

        async def _emit(**kwargs: Any) -> None:
            self.calls.append(kwargs)

        monkeypatch.setattr(endpoint_module, "emit_audit", _emit)


async def _call_route(
    monkeypatch: pytest.MonkeyPatch,
    *,
    user: CurrentUser | None = None,
    body: endpoint_module.ActionUndoRequest | None = None,
) -> dict[str, Any]:
    return await endpoint_module.undo_action(
        action_id=uuid.UUID(ACTION_ID),
        body=body,
        user=user or _user(),
        # Stand-ins: the seams underneath (connector pick, vault, actions
        # client, audit) are monkeypatched, so nothing reads past the type.
        db=cast(AsyncSession, SimpleNamespace()),
        request=cast(Request, None),
    )


class TestCredentialsComeFromTheStoredIntegration:
    async def test_the_vault_not_the_request_supplies_the_credentials(self, monkeypatch: pytest.MonkeyPatch):
        """The request body carries nothing credential-shaped; what reaches
        the actions service is the vault's decrypted connector config plus
        the connector's operational settings."""
        sent = _wire(monkeypatch, record=_stored_record())
        _AuditSpy(monkeypatch)

        report = await _call_route(monkeypatch)

        assert report["status"] == "rolled_back"
        assert len(sent) == 1
        auth_config = sent[0]["auth_config"]
        assert auth_config["token"] == "decrypted-from-vault"
        assert auth_config["base_url"] == "https://splunk.example:8089"
        assert sent[0]["tenant_id"] == str(TENANT)

    async def test_a_credential_bearing_body_is_refused(self):
        """Unknown fields are refused outright, so there is no way to smuggle
        a credential or a destination through this route."""
        with pytest.raises(ValidationError):
            endpoint_module.ActionUndoRequest(splunk_token="tok-1")
        with pytest.raises(ValidationError):
            endpoint_module.ActionUndoRequest(auth_config={"token": "tok-1"})

    async def test_a_tenant_without_the_connector_is_told_so(self, monkeypatch: pytest.MonkeyPatch):
        _wire(monkeypatch, record=_stored_record(), connector=None)
        _AuditSpy(monkeypatch)

        with pytest.raises(Exception) as excinfo:
            await _call_route(monkeypatch)

        assert getattr(excinfo.value, "status_code", None) == 422
        assert "splunk" in str(getattr(excinfo.value, "detail", ""))


class TestApprovalFlow:
    async def test_a_queued_undo_lands_in_the_approvals_inbox(self, monkeypatch: pytest.MonkeyPatch):
        _wire(
            monkeypatch,
            record=_stored_record(),
            upstream={
                "action_id": ACTION_ID,
                "status": "pending_approval",
                "reversed": False,
                "requirement": "analyst",
                "reason": "The action's contract requires analyst approval even at 95% confidence.",
                "vendor_id": "splunk",
            },
        )
        _AuditSpy(monkeypatch)
        created: list[dict[str, Any]] = []

        async def _create(db: Any, user: Any, **kwargs: Any) -> Any:
            created.append(kwargs)
            return SimpleNamespace(id=uuid.UUID("99999999-9999-9999-9999-999999999999"))

        monkeypatch.setattr(endpoint_module, "create_undo_approval", _create)

        report = await _call_route(monkeypatch)

        assert report["status"] == "pending_approval"
        assert report["reversed"] is False
        assert report["approval_id"] == "99999999-9999-9999-9999-999999999999"
        assert len(created) == 1
        assert created[0]["undo_of"] == ACTION_ID
        assert created[0]["action_type"] == "sync_detection_rule"

    async def test_the_decide_path_re_drives_the_undo_with_the_deciding_identity(self, monkeypatch: pytest.MonkeyPatch):
        """Approving the queued undo carries the decision through with the
        decider bound as approver and the stamped requester kept separate —
        the same identity split the forward decide path sends."""
        driven: list[dict[str, Any]] = []

        async def _drive(db: Any, **kwargs: Any) -> Any:
            driven.append(kwargs)
            return SimpleNamespace(
                status="rolled_back",
                reversed_=True,
                vendor_id="splunk",
                error="",
                as_dict=lambda: {"status": "rolled_back"},
            )

        monkeypatch.setattr(service_module, "drive_undo", _drive)

        requester_stamp = {"user_id": str(uuid.uuid4()), "tenant_id": str(TENANT), "permissions": ["actions:execute:medium"]}
        row = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            run_id=None,
            summary="undo it",
            title="Undo sync_detection_rule",
            requested_by="user:rory@example.com",
            action={
                "kind": "action_undo",
                "undo_of": ACTION_ID,
                "action_type": "sync_detection_rule",
                "target": "AiSOC - brute force by user",
                "confidence": 0.95,
                approvals_module._REQUESTER_KEY: requester_stamp,
            },
        )
        decider = _user(email="dana@example.com")

        dispatch = await approvals_module._dispatch_decision(
            cast(AgentApproval, row), decider, approve=True, db=cast(AsyncSession, SimpleNamespace())
        )

        assert dispatch["state"] == approvals_module._DISPATCH_EXECUTED
        assert len(driven) == 1
        assert driven[0]["action_id"] == ACTION_ID
        assert driven[0]["approver"]["user_id"] == str(decider.user_id)
        assert driven[0]["requester"] == requester_stamp
        assert driven[0]["confidence"] == 0.95

    async def test_a_denied_undo_executes_nothing(self, monkeypatch: pytest.MonkeyPatch):
        async def _drive(db: Any, **kwargs: Any) -> Any:  # pragma: no cover - must not be called
            raise AssertionError("a denial must not reach the actions service")

        monkeypatch.setattr(service_module, "drive_undo", _drive)
        row = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            run_id=None,
            summary="undo it",
            title="Undo sync_detection_rule",
            requested_by="user:rory@example.com",
            action={"kind": "action_undo", "undo_of": ACTION_ID},
        )

        dispatch = await approvals_module._dispatch_decision(
            cast(AgentApproval, row), _user(), approve=False, db=cast(AsyncSession, SimpleNamespace())
        )

        assert dispatch["state"] == approvals_module._DISPATCH_DECLINED

    async def test_a_failed_redriven_undo_is_reported_failed(self, monkeypatch: pytest.MonkeyPatch):
        async def _drive(db: Any, **kwargs: Any) -> Any:
            return SimpleNamespace(
                status="undo_failed",
                reversed_=False,
                vendor_id="splunk",
                error="the vendor refused the delete",
                as_dict=lambda: {"status": "undo_failed"},
            )

        monkeypatch.setattr(service_module, "drive_undo", _drive)
        row = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            run_id=None,
            summary="undo it",
            title="Undo sync_detection_rule",
            requested_by="user:rory@example.com",
            action={"kind": "action_undo", "undo_of": ACTION_ID},
        )

        dispatch = await approvals_module._dispatch_decision(
            cast(AgentApproval, row), _user(), approve=True, db=cast(AsyncSession, SimpleNamespace())
        )

        assert dispatch["state"] == approvals_module._DISPATCH_FAILED
        assert "refused" in dispatch["detail"]


class TestHonestReporting:
    async def test_a_vendor_refusal_reaches_the_caller_as_a_failed_undo(self, monkeypatch: pytest.MonkeyPatch):
        _wire(
            monkeypatch,
            record=_stored_record(),
            upstream={
                "action_id": ACTION_ID,
                "status": "undo_failed",
                "reversed": False,
                "vendor_id": "splunk",
                "error": "the executor reported the reversal did not run (vendor refusal or missing reversal state)",
            },
        )
        _AuditSpy(monkeypatch)

        report = await _call_route(monkeypatch)

        assert report["status"] == "undo_failed"
        assert report["reversed"] is False
        assert "did not run" in report["error"]

    async def test_upstream_state_refusals_keep_their_reason(self, monkeypatch: pytest.MonkeyPatch):
        _wire(
            monkeypatch,
            record=_stored_record(),
            upstream=actions_client.ActionsServiceError(
                "409",
                status_code=409,
                upstream_detail="this action was already rolled back at 2026-11-21 by dana; there is nothing left to undo",
            ),
        )
        _AuditSpy(monkeypatch)

        with pytest.raises(Exception) as excinfo:
            await _call_route(monkeypatch)

        assert getattr(excinfo.value, "status_code", None) == 409
        assert "already rolled back" in str(getattr(excinfo.value, "detail", ""))

    async def test_the_outcome_is_audited(self, monkeypatch: pytest.MonkeyPatch):
        _wire(monkeypatch, record=_stored_record())
        audit = _AuditSpy(monkeypatch)
        user = _user()

        await _call_route(monkeypatch, user=user)

        assert len(audit.calls) == 1
        entry = audit.calls[0]
        assert entry["action"] == "actions:undo"
        assert entry["resource"] == "action"
        assert entry["resource_id"] == ACTION_ID
        assert entry["actor_id"] == user.user_id
        changes = entry["changes"]
        assert changes["status"] == "rolled_back"
        assert changes["reversed"] is True
        assert changes["vendor_id"] == "splunk"

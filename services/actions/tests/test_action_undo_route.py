"""``POST /actions/{action_id}/rollback``: the route that makes reversals real.

Every executor's ``rollback()`` was reachable only from tests: no route and no
worker invoked one, so the ``reverse_capability`` the contracts advertise and
the ``rollback_data`` captured on every destructive verb fed a reversal the
product could not dispatch. These tests drive the new route end to end against
the same mock Splunk management API the forward vendor-arm tests use, through
the real ``SplunkSyncDetectionRule`` adapter — the vendor fake is what shows
the prior definition coming back.

What is pinned here, in order of importance:

* the reversal is **governed**: an undo whose reverse capability requires
  analyst approval does not run until a distinct approver is bound, exactly
  as forward dispatch queues the forward verb;
* credentials reach the executor from the request's ``auth_config`` (resolved
  server-side by the API from the tenant's stored integration) and never from
  the stored record — the seeded records carry none;
* the state guard is one conditional UPDATE: an action that never executed or
  was already rolled back is refused with the reason, and a vendor refusal is
  a FAILED undo, never a success.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from app.api import router as router_module
from app.live_actions import register_builtin_executors, registry
from app.live_actions.builtins import SplunkSyncDetectionRule
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.models.action import ActionPrincipal, ActionStatus
from app.security.authz import require_service_auth
from app.services import action_store
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_sync_detection_rule_vendor_arms import SPL, _FakeSplunk, _wire_splunk

TENANT = "11111111-1111-1111-1111-111111111111"
TENANT_UUID = UUID(TENANT)
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"

RULE_NAME = "AiSOC - brute force by user"
PRIOR_SPL = "index=main | stats count"

#: Connector-schema credentials, the shape the API resolves out of the vault.
#: The route translates them into the executor's vendor-prefixed params, which
#: is the same boundary translation forward dispatch performs.
SPLUNK_AUTH_CONFIG = {"base_url": "https://splunk.example:8089", "token": "tok-1"}

REQUESTER = ActionPrincipal(
    user_id="rory@example.com",
    permissions=["actions:execute:medium"],
    tenant_id=TENANT_UUID,
)
APPROVER = ActionPrincipal(
    user_id="dana@example.com",
    permissions=["actions:execute:medium"],
    tenant_id=TENANT_UUID,
)


@pytest.fixture(autouse=True)
def _clean_store():
    action_store.clear()
    yield
    action_store.clear()


@pytest.fixture(autouse=True)
def _registered_builtins():
    """The live registry is populated at app startup; these tests build a bare
    FastAPI app, so register the builtin adapters the way ``main`` does."""
    register_builtin_executors(overwrite=True)


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router_module.router, prefix="/api/v1")
    app.dependency_overrides[require_service_auth] = lambda: None
    return TestClient(app)


def _splunk_request(**overrides: Any) -> LiveActionRequest:
    params = {
        "splunk_url": "https://splunk.example:8089",
        "splunk_token": "tok-1",
        "query": SPL,
        "schedule": "*/10 * * * *",
        "severity": "high",
    }
    params.update(overrides.pop("params", {}))
    return LiveActionRequest(
        capability="sync_detection_rule",
        vendor_id="splunk",
        tenant_id=uuid4(),
        target=RULE_NAME,
        params=params,
        requested_by="test@aisoc.internal",
        **overrides,
    )


def _seed_completed(result: LiveActionResult, *, action_type: str = "sync_detection_rule", target: str = RULE_NAME) -> str:
    """Persist the record the classic door would have written for ``result``.

    ``parameters`` is deliberately empty: the undo's credentials must come
    from the request (where the API puts the tenant's stored integration),
    and a test that seeded them into the record could not tell the two
    sources apart.
    """
    details = dict(result.details)
    rollback_data = details.pop("rollback_data", {})
    record = {
        "id": str(result.request_id),
        "tenant_id": TENANT,
        "status": ActionStatus.COMPLETED,
        "action_type": action_type,
        "target": target,
        "incident_id": str(uuid4()),
        "parameters": {},
        "output": details,
        "rollback_data": rollback_data,
        "requested_by_user_id": REQUESTER.user_id,
    }
    asyncio.run(action_store.save(record))
    return record["id"]


def _execute_forward(splunk: _FakeSplunk) -> str:
    """Run the real Splunk arm against the fake vendor and persist the record."""
    result = asyncio.run(SplunkSyncDetectionRule().execute(_splunk_request()))
    assert result.status == LiveActionStatus.SUCCEEDED
    assert splunk.searches[RULE_NAME]["search"].strip() == SPL
    return _seed_completed(result)


def _record(action_id: str, tenant: str = TENANT) -> dict[str, Any]:
    record = asyncio.run(action_store.get(action_id, tenant_id=tenant))
    assert record is not None, f"no record stored for {action_id}"
    return record


def _status_of(record: dict[str, Any]) -> str:
    return str(getattr(record["status"], "value", record["status"]))


def _undo(client: TestClient, action_id: str, *, tenant: str = TENANT, **body: Any):
    payload: dict[str, Any] = {
        "auth_config": SPLUNK_AUTH_CONFIG,
        "principal": REQUESTER.model_dump(mode="json"),
        "requested_by": "user:rory@example.com",
    }
    payload.update(body)
    return client.post(
        f"/api/v1/actions/{action_id}/rollback",
        json=payload,
        headers={"X-Tenant-ID": tenant},
    )


@pytest.fixture()
def splunk(monkeypatch: pytest.MonkeyPatch) -> _FakeSplunk:
    fake = _FakeSplunk()
    fake.searches[RULE_NAME] = {
        "search": PRIOR_SPL,
        "cron_schedule": "*/30 * * * *",
        "alert.severity": "medium",
    }
    _wire_splunk(monkeypatch, fake)
    return fake


class TestApprovalGoverned:
    """The reverse capability's contract grades the undo before anything runs."""

    def test_an_analyst_tier_reversal_waits_for_an_approver(self, client: TestClient, splunk: _FakeSplunk):
        """sync_detection_rule's reverse is itself, declared analyst — the
        undo must queue, the vendor must not be touched, and the record must
        stay exactly as it was."""
        action_id = _execute_forward(splunk)
        writes_before = len(splunk.requests)

        response = _undo(client, action_id)

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "pending_approval"
        assert body["reversed"] is False
        assert body["requirement"] == "analyst"
        assert splunk.requests[writes_before:] == [], "a queued undo must not touch the vendor"
        assert _status_of(_record(action_id)) == "completed"

    def test_a_bound_approver_releases_the_reversal(self, client: TestClient, splunk: _FakeSplunk):
        """The headline: executed forward through the real Splunk arm, undone
        through the route, and the mock vendor shows the prior definition —
        SPL and schedule both — restored."""
        action_id = _execute_forward(splunk)

        response = _undo(
            client,
            action_id,
            approver=APPROVER.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )

        assert response.status_code == 200, response.json()
        body = response.json()
        assert body["status"] == "rolled_back"
        assert body["reversed"] is True
        assert splunk.searches[RULE_NAME]["search"].strip() == PRIOR_SPL
        assert splunk.searches[RULE_NAME]["cron_schedule"] == "*/30 * * * *"

        record = _record(action_id)
        assert _status_of(record) == "rolled_back"
        assert record["rolled_back_by"] == APPROVER.user_id
        assert record["rolled_back_at"]
        provenance = record["rollback"]
        assert provenance["state"] == "reversed"
        assert provenance["requested_by"] == "user:rory@example.com"
        assert provenance["approved_by"] == APPROVER.user_id
        assert provenance["vendor_id"] == "splunk"

    def test_the_requester_cannot_approve_their_own_undo(self, client: TestClient, splunk: _FakeSplunk):
        action_id = _execute_forward(splunk)

        response = _undo(
            client,
            action_id,
            approver=REQUESTER.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )

        assert response.status_code == 403
        assert "duties" in response.json()["detail"].lower()
        assert splunk.searches[RULE_NAME]["search"].strip() == SPL, "the refusal must come before the vendor"

    def test_an_approver_without_the_permission_is_refused(self, client: TestClient, splunk: _FakeSplunk):
        action_id = _execute_forward(splunk)
        weak = ActionPrincipal(user_id="intern@example.com", permissions=["actions:read"], tenant_id=TENANT_UUID)

        response = _undo(
            client,
            action_id,
            approver=weak.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )

        assert response.status_code == 403
        assert splunk.searches[RULE_NAME]["search"].strip() == SPL

    def test_an_automatic_tier_reversal_runs_without_an_approver(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """block_sender's reverse (unblock_sender) is low-impact and declared
        automatic: at a tier that permits it, with confidence above the floor,
        the undo runs with no approver bound — the same auto-allowed shape
        forward dispatch grades through the same matrix."""
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L3")

        calls: list[tuple[LiveActionResult, dict[str, Any] | None]] = []

        class _CapturingAdapter:
            vendor_id = "m365"
            capability = "block_sender"

            async def rollback(self, result: LiveActionResult, params: dict[str, Any] | None = None) -> bool:
                calls.append((result, params))
                return True

        monkeypatch.setitem(registry._REGISTRY, ("m365", "block_sender"), (_CapturingAdapter(), "builtin"))

        action_id = _seed_completed(
            LiveActionResult(
                request_id=uuid4(),
                status=LiveActionStatus.SUCCEEDED,
                capability="block_sender",
                vendor_id="m365",
                summary="blocked",
                details={"rollback_data": {"vendor": "m365", "sender": "spoof@example.net"}},
            ),
            action_type="block_sender",
            target="spoof@example.net",
        )

        response = _undo(
            client,
            action_id,
            auth_config={"tenant_id": "t", "client_id": "c", "client_secret": "s"},
            confidence=0.95,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "rolled_back"
        assert body["reversed"] is True
        assert len(calls) == 1
        result, _params = calls[0]
        assert result.details["rollback_data"]["sender"] == "spoof@example.net"
        assert _record(action_id)["rolled_back_by"] == REQUESTER.user_id


class TestStateGuards:
    def test_an_action_that_never_executed_is_refused(self, client: TestClient, splunk: _FakeSplunk):
        action_id = str(uuid4())
        asyncio.run(
            action_store.save(
                {
                    "id": action_id,
                    "tenant_id": TENANT,
                    "status": ActionStatus.AWAITING_APPROVAL,
                    "action_type": "sync_detection_rule",
                    "target": RULE_NAME,
                    "incident_id": str(uuid4()),
                    "parameters": {},
                }
            )
        )

        response = _undo(client, action_id, approver=APPROVER.model_dump(mode="json"))

        assert response.status_code == 409
        assert "awaiting_approval" in response.json()["detail"]

    def test_an_already_rolled_back_action_is_refused_with_the_reason(self, client: TestClient, splunk: _FakeSplunk):
        action_id = _execute_forward(splunk)
        first = _undo(
            client,
            action_id,
            approver=APPROVER.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )
        assert first.json()["status"] == "rolled_back"

        second = _undo(
            client,
            action_id,
            approver=APPROVER.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )

        assert second.status_code == 409
        assert "already" in second.json()["detail"].lower()

    def test_a_record_that_captured_nothing_is_refused(self, client: TestClient, splunk: _FakeSplunk):
        """A simulation-mode forward action stores an empty rollback_data;
        there is no state to restore and the route must say so rather than
        guess a vendor."""
        action_id = _seed_completed(
            LiveActionResult(
                request_id=uuid4(),
                status=LiveActionStatus.SUCCEEDED,
                capability="sync_detection_rule",
                vendor_id="splunk",
                summary="simulated",
                details={},
            )
        )

        response = _undo(client, action_id, approver=APPROVER.model_dump(mode="json"))

        assert response.status_code == 422
        assert "captured" in response.json()["detail"].lower()

    def test_a_tenant_cannot_undo_another_tenants_action(self, client: TestClient, splunk: _FakeSplunk):
        action_id = _execute_forward(splunk)

        response = _undo(client, action_id, tenant=OTHER_TENANT, approver=APPROVER.model_dump(mode="json"))

        assert response.status_code == 404

    def test_a_caller_naming_no_tenant_is_refused(self, client: TestClient, splunk: _FakeSplunk):
        action_id = _execute_forward(splunk)

        response = client.post(
            f"/api/v1/actions/{action_id}/rollback",
            json={"auth_config": SPLUNK_AUTH_CONFIG},
        )

        assert response.status_code == 400

    def test_a_verb_whose_reversal_cannot_take_credentials_is_refused_up_front(self, client: TestClient, splunk: _FakeSplunk):
        """isolate_host's legacy rollback takes no params, so per-call
        credentials cannot reach it; the route refuses before grading rather
        than queueing an approval for an undo that can never run."""
        action_id = _seed_completed(
            LiveActionResult(
                request_id=uuid4(),
                status=LiveActionStatus.SUCCEEDED,
                capability="isolate_host",
                vendor_id="crowdstrike",
                summary="contained",
                details={"rollback_data": {"vendor": "crowdstrike", "device_id": "dev-1"}},
            ),
            action_type="isolate_host",
            target="WKSTN-01",
        )

        response = _undo(client, action_id, approver=APPROVER.model_dump(mode="json"))

        assert response.status_code == 422
        assert "credential" in response.json()["detail"].lower()


class TestHonestOutcomes:
    def test_a_vendor_refusal_is_a_failed_undo_never_a_success(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """The action created the rule (no prior), so the reversal is a
        delete; the vendor refuses it. The executor returns False and the
        record must say the undo failed while the action stays in force."""
        fake = _FakeSplunk(refuse_delete=True)
        _wire_splunk(monkeypatch, fake)
        action_id = _execute_forward(fake)

        response = _undo(
            client,
            action_id,
            approver=APPROVER.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "undo_failed"
        assert body["reversed"] is False
        assert RULE_NAME in fake.searches, "the rule is still there; saying otherwise would be the lie this route exists to remove"

        record = _record(action_id)
        assert _status_of(record) == "completed", "a failed undo leaves the action in force and retryable"
        assert record["rollback"]["state"] == "failed"
        assert record.get("rolled_back_at") is None

    def test_the_undo_outcome_is_audited_on_the_record(self, client: TestClient, splunk: _FakeSplunk):
        """Who asked, who approved, which action, which vendor, what the
        executor answered — readable off the record afterwards."""
        action_id = _execute_forward(splunk)
        before = datetime.now(UTC).isoformat()

        _undo(
            client,
            action_id,
            approver=APPROVER.model_dump(mode="json"),
            requester=REQUESTER.model_dump(mode="json"),
        )

        record = _record(action_id)
        provenance = record["rollback"]
        assert provenance["approved_by"] == APPROVER.user_id
        assert provenance["requested_by"] == "user:rory@example.com"
        assert provenance["vendor_id"] == "splunk"
        assert provenance["state"] == "reversed"
        assert provenance["requirement"] == "analyst"
        assert record["rolled_back_at"] >= before

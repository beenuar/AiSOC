"""An approval must authorize somebody (T3.6).

Before this, the Slack and Teams bots verified who clicked, recorded them in
an audit event, and called ``approve_action(action_id)`` with no body. The
actions service ran :func:`authorize_approver` on ``None``, so the
permission-tier check and separation of duties were both skipped — the human
existed only in a log line. An approval path that does not authorize is worse
than no approval path, because it reads as a control.

Every test here fails against that behaviour.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from app.api import router as router_module
from app.core.config import get_settings
from app.models.action import ActionPrincipal, ActionStatus, ActionType, ChatOpsApprover
from app.security import chatops_identity
from fastapi import HTTPException

APPROVER_MAP = {
    "slack": {
        "U_LEAD": {
            "user_id": "dana@example.com",
            "permissions": ["actions:execute:high"],
            "roles": ["soc-lead"],
        },
        "U_JUNIOR": {
            "user_id": "sam@example.com",
            "permissions": ["actions:execute:low"],
        },
        "U_REQUESTER": {
            "user_id": "rory@example.com",
            "permissions": ["actions:execute:high"],
        },
    },
    "teams": {"29:abc": {"user_id": "kit@example.com", "permissions": ["actions:execute:high"]}},
    "email": {"dana@example.com": {"user_id": "dana@example.com", "permissions": ["actions:execute:high"]}},
}


@pytest.fixture(autouse=True)
def _approver_map(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_CHATOPS_APPROVERS", json.dumps(APPROVER_MAP))
    get_settings.cache_clear()
    chatops_identity.reset_cache()
    yield
    get_settings.cache_clear()
    chatops_identity.reset_cache()


def _pending(action_type: ActionType = ActionType.ISOLATE_HOST, *, requested_by: str | None = None) -> dict:
    return {
        "id": str(uuid4()),
        "incident_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "action_type": action_type.value,
        "target": "host-1",
        "rationale": "test",
        "status": ActionStatus.AWAITING_APPROVAL,
        "requested_by_user_id": requested_by,
    }


# ── the identity resolver ──────────────────────────────────────────────────


def test_a_mapped_slack_user_resolves_with_real_permissions() -> None:
    principal = chatops_identity.resolve_approver("slack", "U_LEAD")
    assert principal is not None
    assert principal.user_id == "dana@example.com"
    assert principal.permissions == ["actions:execute:high"]


def test_an_unmapped_user_resolves_to_nothing_rather_than_an_empty_principal() -> None:
    """Returning a permission-less principal would pass the identity check and
    then fail the tier check for a reason an operator cannot tell apart from a
    misconfigured tier."""
    assert chatops_identity.resolve_approver("slack", "U_NOBODY") is None


def test_an_unknown_platform_is_refused_not_trusted() -> None:
    assert chatops_identity.resolve_approver("carrier-pigeon", "U_LEAD") is None


def test_platform_matching_is_case_insensitive_but_user_ids_are_not() -> None:
    """Slack ids are case-sensitive opaque handles; the platform key is not."""
    assert chatops_identity.resolve_approver("SLACK", "U_LEAD") is not None
    assert chatops_identity.resolve_approver("slack", "u_lead") is None


def test_a_malformed_map_is_loud_rather_than_silently_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_CHATOPS_APPROVERS", "{not json")
    get_settings.cache_clear()
    chatops_identity.reset_cache()
    with pytest.raises(chatops_identity.ChatOpsIdentityError, match="not valid JSON"):
        chatops_identity.resolve_approver("slack", "U_LEAD")


def test_an_unset_map_means_nobody_can_approve(monkeypatch: pytest.MonkeyPatch) -> None:
    """The correct default for a control that was previously absent."""
    monkeypatch.setenv("AISOC_CHATOPS_APPROVERS", "")
    get_settings.cache_clear()
    chatops_identity.reset_cache()
    assert chatops_identity.resolve_approver("slack", "U_LEAD") is None


# ── binding on the approve path ────────────────────────────────────────────


def test_an_approval_with_no_identity_is_refused() -> None:
    """The regression. This used to return the record and execute."""
    record = _pending()
    with pytest.raises(HTTPException) as exc:
        router_module._bind_approver(record, record["id"], None, None, require=True)
    assert exc.value.status_code == 403
    assert "approver identity is required" in exc.value.detail


def test_an_unmapped_chatops_user_cannot_approve() -> None:
    record = _pending()
    assertion = ChatOpsApprover(platform="slack", platform_user_id="U_NOBODY")
    with pytest.raises(HTTPException) as exc:
        router_module._bind_approver(record, record["id"], None, assertion, require=True)
    assert exc.value.status_code == 403
    assert "not mapped" in exc.value.detail


def test_a_mapped_chatops_user_with_the_tier_can_approve() -> None:
    record = _pending()
    assertion = ChatOpsApprover(platform="slack", platform_user_id="U_LEAD")
    bound = router_module._bind_approver(record, record["id"], None, assertion, require=True)
    assert bound is not None and bound.user_id == "dana@example.com"


def test_a_mapped_user_below_the_required_tier_cannot_approve() -> None:
    """isolate_host is a high-blast action; actions:execute:low must not reach it."""
    record = _pending(ActionType.ISOLATE_HOST)
    assertion = ChatOpsApprover(platform="slack", platform_user_id="U_JUNIOR")
    with pytest.raises(HTTPException) as exc:
        router_module._bind_approver(record, record["id"], None, assertion, require=True)
    assert exc.value.status_code == 403
    assert "lacks" in exc.value.detail


def test_separation_of_duties_applies_to_a_chatops_approval() -> None:
    """The requester cannot approve their own action, even over Slack.

    This was entirely unreachable before: with no approver bound there was no
    identity to compare against the requester.
    """
    record = _pending(requested_by="rory@example.com")
    assertion = ChatOpsApprover(platform="slack", platform_user_id="U_REQUESTER")
    with pytest.raises(HTTPException) as exc:
        router_module._bind_approver(record, record["id"], None, assertion, require=True)
    assert exc.value.status_code == 403
    assert "separation of duties" in exc.value.detail


def test_a_direct_principal_still_works_and_takes_precedence() -> None:
    """The console path supplies a full principal from its authenticated user."""
    record = _pending()
    principal = ActionPrincipal(user_id="console@example.com", permissions=["actions:*"])
    assertion = ChatOpsApprover(platform="slack", platform_user_id="U_NOBODY")
    bound = router_module._bind_approver(record, record["id"], principal, assertion, require=True)
    assert bound is not None and bound.user_id == "console@example.com"


def test_a_teams_identity_resolves_against_the_teams_half_of_the_map() -> None:
    """A Teams user id must not resolve because a Slack id happens to match.

    The Teams bot imports the Slack bot's client when it is on the image, so
    the platform has to travel with the identity rather than being a constant
    in the client.
    """
    record = _pending()
    bound = router_module._bind_approver(
        record,
        record["id"],
        None,
        ChatOpsApprover(platform="teams", platform_user_id="29:abc"),
        require=True,
    )
    assert bound is not None and bound.user_id == "kit@example.com"

    with pytest.raises(HTTPException):
        router_module._bind_approver(
            record,
            record["id"],
            None,
            ChatOpsApprover(platform="teams", platform_user_id="U_LEAD"),
            require=True,
        )


# ── the reject path is deliberately asymmetric ─────────────────────────────


def test_a_rejection_without_identity_is_allowed_but_records_none() -> None:
    """A timeout-driven rejection has no human by definition.

    Requiring one would leave an expired request stuck in awaiting_approval
    forever, and a rejection causes no vendor effect.
    """
    record = _pending()
    assert router_module._bind_approver(record, record["id"], None, None, require=False) is None


def test_a_rejection_with_identity_still_authorizes_it() -> None:
    """Identity is optional on reject, but not unchecked when present —
    otherwise "who declined to contain this host" has an unverified answer."""
    record = _pending(requested_by="rory@example.com")
    with pytest.raises(HTTPException) as exc:
        router_module._bind_approver(
            record,
            record["id"],
            None,
            ChatOpsApprover(platform="slack", platform_user_id="U_REQUESTER"),
            require=False,
        )
    assert exc.value.status_code == 403


def test_the_requirement_can_be_disabled_for_a_legacy_deployment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_ACTIONS_REQUIRE_APPROVER", "false")
    monkeypatch.setenv("AISOC_ACTIONS_REQUIRE_PRINCIPAL", "false")
    get_settings.cache_clear()
    record = _pending()
    assert router_module._bind_approver(record, record["id"], None, None, require=True) is None

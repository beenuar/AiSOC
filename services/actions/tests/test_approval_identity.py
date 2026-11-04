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

#: The tenant every approver below is scoped to, and the one `_pending`
#: actions belong to.
#:
#: Every entry in this map used to omit `tenant_id`, mirroring the example in
#: `chatops_identity`'s own docstring -- and that is precisely the shape that
#: skipped the tenant comparison in `authorize_approver` *and* left the record
#: read unscoped (GHSA-fm3f-p5jv-6hcg, F06). So the whole of this suite was
#: exercising the ungoverned path while asserting that approvals are
#: authorized. `TestATenantlessApproverIsRefused` at the bottom is the case
#: that was missing.
TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"

APPROVER_MAP = {
    "slack": {
        "U_LEAD": {
            "user_id": "dana@example.com",
            "permissions": ["actions:execute:high"],
            "roles": ["soc-lead"],
            "tenant_id": TENANT,
        },
        "U_JUNIOR": {
            "user_id": "sam@example.com",
            "permissions": ["actions:execute:low"],
            "tenant_id": TENANT,
        },
        "U_REQUESTER": {
            "user_id": "rory@example.com",
            "permissions": ["actions:execute:high"],
            "tenant_id": TENANT,
        },
        # Deliberately tenantless, for the refusal case. This is the entry
        # shape the documented example used to show.
        "U_UNSCOPED": {
            "user_id": "nolan@example.com",
            "permissions": ["actions:execute:high"],
        },
    },
    "teams": {"29:abc": {"user_id": "kit@example.com", "permissions": ["actions:execute:high"], "tenant_id": TENANT}},
    "email": {
        "dana@example.com": {
            "user_id": "dana@example.com",
            "permissions": ["actions:execute:high"],
            "tenant_id": TENANT,
        }
    },
}


@pytest.fixture(autouse=True)
def _approver_map(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_CHATOPS_APPROVERS", json.dumps(APPROVER_MAP))
    get_settings.cache_clear()
    chatops_identity.reset_cache()
    yield
    get_settings.cache_clear()
    chatops_identity.reset_cache()


def _pending(
    action_type: ActionType = ActionType.ISOLATE_HOST,
    *,
    requested_by: str | None = None,
    tenant_id: str = TENANT,
) -> dict:
    return {
        "id": str(uuid4()),
        "incident_id": str(uuid4()),
        "tenant_id": tenant_id,
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


def test_a_direct_principal_still_works() -> None:
    """The console path supplies a full principal from its authenticated user."""
    record = _pending()
    principal = ActionPrincipal(user_id="console@example.com", permissions=["actions:*"], tenant_id=TENANT)
    bound = router_module._bind_approver(record, record["id"], principal, None, require=True)
    assert bound is not None and bound.user_id == "console@example.com"


def test_two_identities_for_one_decision_are_refused() -> None:
    """Was `..._and_takes_precedence`, which pinned the defect as intended.

    The old assertion was that a body `approver` wins over a ChatOps
    assertion. Read as a security property that is: the *more forgeable* of
    two identities silently overrides the one resolved through the operator's
    approver map, and the map is never consulted
    (GHSA-fm3f-p5jv-6hcg, F01). Measured against the real service, a body
    principal the map had never heard of, declaring `permissions: ["*"]`, was
    recorded as `approved_by_user_id` alongside a valid Slack assertion.

    A caller presenting two identities for one decision is ambiguous whichever
    one is correct. Refused rather than resolved by precedence, because a
    precedence rule is something a future caller can be built around.
    """
    record = _pending()
    principal = ActionPrincipal(user_id="console@example.com", permissions=["actions:*"], tenant_id=TENANT)
    assertion = ChatOpsApprover(platform="slack", platform_user_id="U_LEAD")
    with pytest.raises(HTTPException) as exc:
        router_module._bind_approver(record, record["id"], principal, assertion, require=True)
    assert exc.value.status_code == 400
    assert "not both" in exc.value.detail


class TestATenantlessApproverIsRefused:
    """GHSA-fm3f-p5jv-6hcg, F06.

    `authorize_approver` guarded its whole tenant comparison behind
    `approver.tenant_id is not None`, so an approver carrying no tenant
    skipped it -- and `_tenant_of` returns None for the same principal, which
    leaves the record *read* unscoped too. One identity could approve any
    tenant's containment.

    Not hypothetical configuration: the Teams entry in `chatops_identity`'s
    documented example omits `tenant_id`, and every entry in this file's own
    approver map did until this change.
    """

    def test_an_approver_with_no_tenant_cannot_approve_a_tenanted_action(self) -> None:
        record = _pending()
        assertion = ChatOpsApprover(platform="slack", platform_user_id="U_UNSCOPED")
        with pytest.raises(HTTPException) as exc:
            router_module._bind_approver(record, record["id"], None, assertion, require=True)
        assert exc.value.status_code == 403
        assert "carries no tenant" in exc.value.detail
        # The refusal names the configuration to fix. An operator seeing a
        # bare 403 has several controls to choose between.
        assert "AISOC_CHATOPS_APPROVERS" in exc.value.detail

    def test_a_tenant_scoped_approver_is_still_accepted(self) -> None:
        """Positive control.

        A tenant check that refused everybody would satisfy the test above and
        make every ChatOps approval impossible -- the fail-closed shape this
        repository has shipped before and whose negative test passed
        perfectly.
        """
        record = _pending()
        assertion = ChatOpsApprover(platform="slack", platform_user_id="U_LEAD")
        bound = router_module._bind_approver(record, record["id"], None, assertion, require=True)
        assert bound is not None and bound.user_id == "dana@example.com"

    def test_an_approver_scoped_to_another_tenant_is_still_refused(self) -> None:
        """The arm that did work, kept working."""
        record = _pending(tenant_id=OTHER_TENANT)
        assertion = ChatOpsApprover(platform="slack", platform_user_id="U_LEAD")
        with pytest.raises(HTTPException) as exc:
            router_module._bind_approver(record, record["id"], None, assertion, require=True)
        assert exc.value.status_code == 403
        assert "does not match" in exc.value.detail

    def test_an_action_with_no_tenant_does_not_require_one_of_the_approver(self) -> None:
        """Second positive control.

        The refusal is about an approver who cannot be compared to a tenant
        the *action* names. An action carrying no tenant has nothing to
        compare, and reading that as "refuse" would be the fail-closed
        mistake in its other direction.
        """
        record = _pending()
        record["tenant_id"] = ""
        assertion = ChatOpsApprover(platform="slack", platform_user_id="U_UNSCOPED")
        bound = router_module._bind_approver(record, record["id"], None, assertion, require=True)
        assert bound is not None and bound.user_id == "nolan@example.com"


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

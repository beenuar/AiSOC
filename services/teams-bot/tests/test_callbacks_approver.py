"""A Teams approval must carry the identity the HMAC already proved (T3.6).

`handle_card_action` verified the inbound signature, recorded `approver_id` in
an audit event, and then called `approve_action(action_id)` with nothing else.
The actions service therefore authorized nobody: the permission-tier check and
separation of duties were both skipped, and the clicking user existed only in
the audit trail.

The platform has to travel with the identity rather than being a constant in
the client, because `build_actions_client` prefers the Slack bot's client when
it is present on the image — stamping "slack" onto a Teams user would resolve
against the wrong half of the approver map.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from app.callbacks import _chatops_approver, handle_card_action
from app.services.hmac_signer import sign_card_data

SECRET = "teams-test-secret"


class _FakeActionsClient:
    def __init__(self) -> None:
        self.approve_calls: list[tuple[str, dict[str, Any] | None]] = []
        self.reject_calls: list[tuple[str, dict[str, Any] | None]] = []

    @staticmethod
    def chatops_approver(platform: str, platform_user_id: str | None) -> dict[str, Any] | None:
        if not platform_user_id:
            return None
        return {"chatops_approver": {"platform": platform, "platform_user_id": platform_user_id}}

    async def approve_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        self.approve_calls.append((action_id, approver))
        return {"id": action_id, "status": "approved"}

    async def reject_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        self.reject_calls.append((action_id, approver))
        return {"id": action_id, "status": "rejected"}


class _ClientWithoutHelper:
    """A double that predates `chatops_approver`, as a test stub might."""

    def __init__(self) -> None:
        self.approve_calls: list[tuple[str, dict[str, Any] | None]] = []

    async def approve_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        self.approve_calls.append((action_id, approver))
        return {"id": action_id, "status": "approved"}

    async def reject_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"id": action_id, "status": "rejected"}


def _signed(verb: str, action_id: str = "act-1", case_id: str = "case-1") -> dict[str, Any]:
    """Mint the signed `data` payload a real Adaptive Card button carries.

    The verb is the wire value (`approve` / `reject` / `need_info`), which
    `handle_card_action` maps to a decision label.
    """
    return sign_card_data(
        verb=verb,
        action_id=action_id,
        case_id=case_id,
        issued_at=int(time.time()),
        secret=SECRET,
    )


# ── the payload builder ────────────────────────────────────────────────────


def test_the_platform_is_teams_not_the_client_default() -> None:
    built = _chatops_approver(_FakeActionsClient(), "29:1abc")
    assert built == {"chatops_approver": {"platform": "teams", "platform_user_id": "29:1abc"}}


def test_a_client_without_the_helper_still_sends_the_identity() -> None:
    """Silently omitting it is what made approvals authorize nobody, so the
    fallback builds the payload rather than dropping it."""
    built = _chatops_approver(_ClientWithoutHelper(), "29:1abc")
    assert built is not None
    assert built["chatops_approver"]["platform"] == "teams"


def test_no_approver_id_means_no_payload() -> None:
    assert _chatops_approver(_FakeActionsClient(), None) is None
    assert _chatops_approver(_FakeActionsClient(), "") is None


# ── end to end through the callback ────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_approval_forwards_the_verified_identity() -> None:
    client = _FakeActionsClient()
    result = await handle_card_action(
        payload=_signed("approve"),
        approver_id="29:1abc",
        secret=SECRET,
        max_age_seconds=300,
        actions_client=client,
    )
    assert result["ok"] is True
    assert client.approve_calls == [("act-1", {"chatops_approver": {"platform": "teams", "platform_user_id": "29:1abc"}})]


@pytest.mark.asyncio
async def test_a_rejection_forwards_it_too() -> None:
    """Identity is optional on reject but still recorded, so "who declined to
    contain this host" has a checked answer."""
    client = _FakeActionsClient()
    await handle_card_action(
        payload=_signed("reject"),
        approver_id="29:1abc",
        secret=SECRET,
        max_age_seconds=300,
        actions_client=client,
    )
    assert client.reject_calls[0][1]["chatops_approver"]["platform_user_id"] == "29:1abc"


@pytest.mark.asyncio
async def test_a_tampered_payload_never_reaches_the_actions_service() -> None:
    payload = _signed("approve")
    payload["action_id"] = "act-somebody-elses"
    client = _FakeActionsClient()

    result = await handle_card_action(
        payload=payload,
        approver_id="29:1abc",
        secret=SECRET,
        max_age_seconds=300,
        actions_client=client,
    )

    assert result["ok"] is False
    assert client.approve_calls == []
    assert client.reject_calls == []


@pytest.mark.asyncio
async def test_need_info_is_non_terminal_and_calls_nothing() -> None:
    client = _FakeActionsClient()
    result = await handle_card_action(
        payload=_signed("need_info"),
        approver_id="29:1abc",
        secret=SECRET,
        max_age_seconds=300,
        actions_client=client,
    )
    assert result["decision"] == "need_info"
    assert client.approve_calls == []
    assert client.reject_calls == []

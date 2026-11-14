"""Opening a war room: legal names, an existing channel, a bad invite.

Depth plan 9.4.

Asserted by name below:

* a case title becomes a channel name Slack will actually accept — the four
  rules it enforces are encoded rather than discovered at runtime;
* `name_taken` resolves to the existing channel rather than failing, because
  re-opening a war room for a case that already has one should find it;
* an invite that fails does **not** undo a channel that now exists, and the
  reply names who was not added, so the console can say "the room is open,
  these were not added" instead of "something went wrong";
* a failed header message is a degraded room, not a failed open;
* the internal token is required, and an unset token refuses rather than
  opening the route to anything that can reach the pod.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.war_room import channel_name_for, router, slack_reason
from fastapi import FastAPI
from fastapi.testclient import TestClient

TOKEN = "internal-token-for-the-war-room-tests"


class FakeSlackError(Exception):
    """Stands in for the SDK's error type, which this service need not import."""


class FakeClient:
    def __init__(
        self,
        *,
        create_raises: str | None = None,
        invite_fails: set[str] | None = None,
        post_raises: bool = False,
        existing: list[dict[str, Any]] | None = None,
    ) -> None:
        self.create_raises = create_raises
        self.invite_fails = invite_fails or set()
        self.post_raises = post_raises
        self.existing = existing or []
        self.created: list[str] = []
        self.invited: list[str] = []
        self.messages: list[dict[str, Any]] = []

    async def conversations_create(self, name: str, is_private: bool = False) -> dict[str, Any]:
        if self.create_raises:
            raise FakeSlackError(self.create_raises)
        self.created.append(name)
        return {"channel": {"id": "C0WARROOM1", "name": name}}

    async def conversations_list(self, **_kwargs: Any) -> dict[str, Any]:
        return {"channels": self.existing, "response_metadata": {"next_cursor": ""}}

    async def conversations_invite(self, channel: str, users: str) -> dict[str, Any]:
        if users in self.invite_fails:
            raise FakeSlackError(self.invite_fails_reason(users))
        self.invited.append(users)
        return {"ok": True}

    def invite_fails_reason(self, user: str) -> str:
        return "already_in_channel" if user.startswith("UALREADY") else "user_not_found"

    async def chat_postMessage(self, **kwargs: Any) -> dict[str, Any]:  # noqa: N802 - Slack's own name
        if self.post_raises:
            raise FakeSlackError("channel_not_found")
        self.messages.append(kwargs)
        return {"ok": True}


class FakeBolt:
    def __init__(self, client: FakeClient) -> None:
        self.client = client


def make_client(fake: FakeClient | None, monkeypatch) -> TestClient:
    from app.core import config as config_module

    monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
    config_module.get_settings.cache_clear()

    app = FastAPI()
    app.include_router(router)
    if fake is not None:
        app.state.bolt_app = FakeBolt(fake)
    return TestClient(app)


def _open(client: TestClient, token: str | None = TOKEN, **body: Any):
    headers = {"X-AiSOC-Internal-Token": token} if token else {}
    payload = {
        "case_id": "11111111-1111-1111-1111-111111111111",
        "case_number": "CASE-2026-0431",
        "title": "File server encrypted overnight!!",
        "severity": "critical",
        "status": "investigating",
        "invite": [],
    }
    payload.update(body)
    return client.post("/internal/war-room", json=payload, headers=headers)


class TestChannelName:
    """Slack's four rules, encoded rather than discovered at runtime."""

    def test_a_case_title_becomes_a_name_slack_accepts(self) -> None:
        name = channel_name_for("CASE-2026-0431", "File server encrypted overnight!!")
        assert name == "aisoc-case-2026-0431-file-server-encrypted-overnight"
        assert name == name.lower()
        assert " " not in name and "." not in name
        assert len(name) <= 80

    def test_a_very_long_title_is_truncated_without_a_trailing_hyphen(self) -> None:
        name = channel_name_for("CASE-1", "x" * 200)
        assert len(name) <= 80
        assert not name.endswith("-")

    def test_the_case_number_leads_so_it_survives_truncation(self) -> None:
        """It is what an analyst searches for; a long title is not."""
        name = channel_name_for("CASE-2026-0431", "y" * 200)
        assert name.startswith("aisoc-case-2026-0431")


class TestErrorText:
    """The vendor's own words go to the log; the reason code goes to the caller."""

    def test_a_known_code_is_returned(self) -> None:
        assert slack_reason(Exception("The request to the Slack API failed: name_taken")) == "name_taken"
        assert slack_reason(FakeSlackError("restricted_action")) == "restricted_action"

    def test_an_unknown_code_is_a_fixed_string_not_a_passthrough(self) -> None:
        # Slack adds error codes and this list will go stale. "refused"
        # plus a log line is the right failure for that; a passthrough
        # would reopen the hole the day a new code appears.
        assert slack_reason(Exception("some_brand_new_code_2027")) == "refused"
        assert slack_reason(Exception("!!! 500 !!!")) == "refused"

    def test_the_result_is_always_a_literal_from_the_closed_set(self) -> None:
        from app.war_room import _SLACK_REASONS, _UNKNOWN_REASON

        for message in ("a" * 5000, "xoxb-leaked-token", "", "NAME_TAKEN"):
            assert slack_reason(Exception(message)) in _SLACK_REASONS | {_UNKNOWN_REASON}

    def test_a_create_failure_does_not_return_the_api_response(self, monkeypatch) -> None:
        secret = "xoxb-this-would-be-a-leaked-token"
        fake = FakeClient(create_raises=f"restricted_action: full response with {secret}")
        client = make_client(fake, monkeypatch)
        res = _open(client)
        assert res.status_code == 502
        detail = res.json()["detail"]
        assert "restricted_action" in detail
        # The whole API response is what `str(exc)` carries, and returning
        # it is both more than the caller can act on and an
        # information-exposure finding.
        assert secret not in detail


class TestOpen:
    def test_it_creates_invites_and_posts_a_header(self, monkeypatch) -> None:
        fake = FakeClient()
        client = make_client(fake, monkeypatch)
        res = _open(client, invite=["U111", "U222"])
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["channel_id"] == "C0WARROOM1"
        assert body["invited"] == ["U111", "U222"]
        assert body["not_invited"] == []
        assert fake.created == ["aisoc-case-2026-0431-file-server-encrypted-overnight"]
        assert "CASE-2026-0431" in fake.messages[0]["text"]

    def test_name_taken_resolves_to_the_existing_channel(self, monkeypatch) -> None:
        name = "aisoc-case-2026-0431-file-server-encrypted-overnight"
        fake = FakeClient(create_raises="name_taken", existing=[{"id": "C0EXISTING", "name": name}])
        client = make_client(fake, monkeypatch)
        res = _open(client)
        assert res.status_code == 201, res.text
        # Re-opening finds the room rather than failing. The alternative is a
        # console button that works once per case and errors forever after.
        assert res.json()["channel_id"] == "C0EXISTING"

    def test_name_taken_with_no_matching_channel_is_a_readable_failure(self, monkeypatch) -> None:
        fake = FakeClient(create_raises="name_taken", existing=[])
        client = make_client(fake, monkeypatch)
        res = _open(client)
        assert res.status_code == 502
        assert "archived or private" in res.json()["detail"]

    def test_a_bad_invite_does_not_undo_a_channel_that_exists(self, monkeypatch) -> None:
        fake = FakeClient(invite_fails={"UGONE"})
        client = make_client(fake, monkeypatch)
        res = _open(client, invite=["U111", "UGONE"])
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["channel_id"] == "C0WARROOM1"
        assert body["invited"] == ["U111"]
        # Named, so the console can say which people were not added rather
        # than reporting a generic failure for a room that is open.
        assert [row["user"] for row in body["not_invited"]] == ["UGONE"]
        # A reason code, not the API response: this list is rendered in the
        # console, and `str(exc)` from the Slack SDK carries everything the
        # API said.
        assert body["not_invited"][0]["reason"] == "user_not_found"

    def test_someone_already_in_the_channel_counts_as_invited(self, monkeypatch) -> None:
        fake = FakeClient(invite_fails={"UALREADY1"})
        client = make_client(fake, monkeypatch)
        res = _open(client, invite=["UALREADY1"])
        assert res.json()["invited"] == ["UALREADY1"]
        assert res.json()["not_invited"] == []

    def test_a_failed_header_is_a_degraded_room_not_a_failed_open(self, monkeypatch) -> None:
        fake = FakeClient(post_raises=True)
        client = make_client(fake, monkeypatch)
        res = _open(client)
        assert res.status_code == 201
        assert res.json()["channel_id"] == "C0WARROOM1"

    def test_a_create_failure_that_is_not_name_taken_fails_loudly(self, monkeypatch) -> None:
        fake = FakeClient(create_raises="restricted_action")
        client = make_client(fake, monkeypatch)
        res = _open(client)
        # The analyst pressed a button. A 202 "we'll try" here would be the
        # toast-only control the console is not allowed to ship.
        assert res.status_code == 502
        assert "restricted_action" in res.json()["detail"]

    def test_no_slack_client_is_503_not_a_quiet_success(self, monkeypatch) -> None:
        client = make_client(None, monkeypatch)
        res = _open(client)
        assert res.status_code == 503
        assert "SLACK_BOT_TOKEN" in res.json()["detail"]


class TestAuthorization:
    def test_the_internal_token_is_required(self, monkeypatch) -> None:
        client = make_client(FakeClient(), monkeypatch)
        assert _open(client, token=None).status_code == 401
        assert _open(client, token="wrong").status_code == 401

    def test_an_unset_token_refuses_rather_than_opening_the_route(self, monkeypatch) -> None:
        from app.core import config as config_module

        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "")
        config_module.get_settings.cache_clear()
        app = FastAPI()
        app.include_router(router)
        app.state.bolt_app = FakeBolt(FakeClient())
        with TestClient(app) as client:
            res = client.post(
                "/internal/war-room",
                json={"case_id": "x"},
                headers={"X-AiSOC-Internal-Token": ""},
            )
        # A route that creates channels in somebody's workspace must not be
        # open to whatever can reach the pod.
        assert res.status_code == 401


class TestPost:
    def test_it_says_one_thing(self, monkeypatch) -> None:
        fake = FakeClient()
        client = make_client(fake, monkeypatch)
        res = client.post(
            "/internal/war-room/post",
            json={"channel_id": "C0WARROOM1", "text": "*Status* is now `resolved`."},
            headers={"X-AiSOC-Internal-Token": TOKEN},
        )
        assert res.status_code == 202
        assert fake.messages[-1]["channel"] == "C0WARROOM1"

    def test_a_vendor_refusal_is_a_status_the_caller_can_act_on(self, monkeypatch) -> None:
        fake = FakeClient(post_raises=True)
        client = make_client(fake, monkeypatch)
        res = client.post(
            "/internal/war-room/post",
            json={"channel_id": "C0GONE", "text": "anything"},
            headers={"X-AiSOC-Internal-Token": TOKEN},
        )
        assert res.status_code == 502
        # The API records this verbatim as the room's `last_error`, and an
        # operator reading "channel_not_found" knows it was archived.
        assert "channel_not_found" in res.json()["detail"]


@pytest.mark.parametrize("token", ["", None])
def test_post_also_requires_the_token(monkeypatch, token: str | None) -> None:
    client = make_client(FakeClient(), monkeypatch)
    headers = {"X-AiSOC-Internal-Token": token} if token is not None else {}
    res = client.post("/internal/war-room/post", json={"channel_id": "C", "text": "t"}, headers=headers)
    assert res.status_code == 401

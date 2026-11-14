"""Teams war rooms: a named refusal when Graph is not configured.

Depth plan 9.4.

The honest state for a stock install is "this cannot work yet, and here is
exactly what is missing". Asserted below:

* the refusal is a 501 that **names the missing settings**, not a generic
  error and not a silent fallback to the incoming webhook — one shared
  channel for every case would put the next incident's traffic in the last
  one's thread;
* a display name Teams will accept, with the forbidden characters removed;
* the internal token is required on both routes.
"""

from __future__ import annotations

import pytest
from app.war_room import channel_name_for, graph_config, require_channel_id, router
from fastapi import FastAPI
from fastapi.testclient import TestClient

TOKEN = "internal-token-for-the-teams-war-room-tests"

GRAPH_VARS = ("MS_GRAPH_TENANT_ID", "MS_GRAPH_CLIENT_ID", "MS_GRAPH_CLIENT_SECRET", "MS_TEAMS_TEAM_ID")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
    for name in GRAPH_VARS:
        monkeypatch.delenv(name, raising=False)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _open(client, token=TOKEN):
    headers = {"X-AiSOC-Internal-Token": token} if token else {}
    return client.post(
        "/internal/war-room",
        json={"case_id": "11111111-1111-1111-1111-111111111111", "case_number": "CASE-1", "title": "Intrusion"},
        headers=headers,
    )


def test_an_unconfigured_deployment_refuses_and_names_what_is_missing(client) -> None:
    res = _open(client)
    assert res.status_code == 501
    detail = res.json()["detail"]
    # Every one of the four, by name. "Not configured" alone sends an
    # operator to the documentation to guess.
    for name in GRAPH_VARS:
        assert name in detail
    # And it says why there is no fallback.
    assert "last one's thread" in detail


def test_it_does_not_quietly_succeed_through_the_webhook(client) -> None:
    res = _open(client)
    assert res.status_code != 201
    assert "channel_id" not in res.json()


def test_the_post_route_refuses_the_same_way(client) -> None:
    res = client.post(
        "/internal/war-room/post",
        json={"channel_id": "19:abc", "text": "anything"},
        headers={"X-AiSOC-Internal-Token": TOKEN},
    )
    assert res.status_code == 501
    assert "Microsoft Graph is not configured" in res.json()["detail"]


def test_graph_config_reports_every_missing_name(monkeypatch) -> None:
    for name in GRAPH_VARS:
        monkeypatch.delenv(name, raising=False)
    assert graph_config() == list(GRAPH_VARS)
    monkeypatch.setenv("MS_GRAPH_TENANT_ID", "t")
    assert graph_config() == list(GRAPH_VARS[1:])


def test_graph_config_returns_the_four_values_when_all_are_present(monkeypatch) -> None:
    for name in GRAPH_VARS:
        monkeypatch.setenv(name, f"value-for-{name}")
    config = graph_config()
    assert isinstance(config, tuple)
    assert len(config) == 4


@pytest.mark.parametrize(
    ("number", "title", "forbidden"),
    [("CASE-1", "Exfil via <share>?", "<"), ("CASE-2", 'A "quoted" lure', '"'), ("CASE-3", "a/b\\c", "/")],
)
def test_the_channel_name_drops_characters_teams_forbids(number: str, title: str, forbidden: str) -> None:
    name = channel_name_for(number, title)
    assert forbidden not in name
    assert len(name) <= 50
    assert number in name


def test_the_internal_token_is_required(client) -> None:
    assert _open(client, token=None).status_code == 401
    assert _open(client, token="wrong").status_code == 401


class TestChannelIdShape:
    """`channel_id` arrives over HTTP and ends up in a Graph URL path."""

    def test_a_real_graph_channel_id_passes(self) -> None:
        good = "19:AbCd_12-34=xyzAbCd12@thread.tacv2"
        assert require_channel_id(good) == good

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "19:short@thread.tacv2",
            "../../../v1.0/users",
            "19:abcdefgh@thread.evil",
            "https://attacker.example/19:abcdefgh@thread.tacv2",
        ],
    )
    def test_anything_else_is_refused_rather_than_escaped(self, bad: str) -> None:
        # Refused, not escaped: an escaped value that reaches Graph and
        # matches nothing reports a clean failure for a request that never
        # ran, which on a forensic surface is the worst possible answer.
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            require_channel_id(bad)
        assert exc.value.status_code == 422

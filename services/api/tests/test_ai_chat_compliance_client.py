"""The compliance client against vendor-shaped payloads through a mock server.

Depth plan wave 2, Phase 7.1. Follows
`services/connectors/tests/connectors/test_live_vendor_smoke.py`: a mock
server returning the vendor's own documented response bodies, driven through
the client's real httpx path.

`httpx.MockTransport` rather than `respx`, because `respx` is not in the API
service's locked dependency set and a test that needs a package CI does not
install is a test CI cannot run. MockTransport replaces only the network leg:
request construction, parameter encoding, `raise_for_status` and JSON
decoding are all production code.

Every payload below is the vendor's published example, field for field, from
the reference pages named in the client's module docstring.
"""

from __future__ import annotations

import httpx
import pytest
from app.services.ai_chat_compliance.client import (
    ADMIN_KEY_PREFIX,
    COMPLIANCE_KEY_PREFIX,
    AiChatComplianceClient,
    ComplianceKeyTypeError,
)

pytestmark = pytest.mark.asyncio

FULL_KEY = COMPLIANCE_KEY_PREFIX + "abc123"
ADMIN_KEY = ADMIN_KEY_PREFIX + "abc123"
ORG = "91012d09-e48b-438e-a489-1bebfd8fa6f9"

_ACTIVITIES = {
    "data": [
        {
            "id": "activity_01DeFgHjKmNpQrStUvWxYzAb",
            "created_at": "2026-04-10T08:09:10Z",
            "organization_id": "org_01Wv6QeBcDfGhJkLmNpQrSt8",
            "organization_uuid": ORG,
            "actor": {
                "type": "user_actor",
                "email_address": "user@example.com",
                "user_id": "user_01TuVwXyZaBcDeFgH2JkLmN4",
                "ip_address": "192.0.2.34",
                "user_agent": "Mozilla/5.0...",
            },
            "type": "claude_chat_created",
            "claude_chat_id": "claude_chat_01CdEfGhJkMnPqRsTuVwXyZa",
            "claude_project_id": "claude_proj_01KGp4eZNug9ri4kE35RSppq",
        }
    ],
    "has_more": False,
    "next_page": None,
}

_CHATS = {
    "data": [
        {
            "id": "claude_chat_01H5CWunD7RpVJ5bHa8RCkja",
            "name": "Product Requirements Discussion",
            "created_at": "2026-04-10T08:09:10Z",
            "updated_at": "2026-04-10T09:10:11Z",
            "deleted_at": None,
            "model": "claude-opus-5-5",
            "organization_uuid": ORG,
            "project_id": "claude_proj_01KGp4eZNug9ri4kE35RSppq",
            "user": {"id": "user_01WxYzAbCdEfGhJkMnPqRsTu", "email_address": "user@example.com"},
        }
    ],
    "has_more": False,
    "next_page": None,
}


def _transport(routes: list[tuple[str, list[dict]]], record: list[httpx.Request] | None = None) -> httpx.MockTransport:
    """Answer by the first path fragment that matches, in order.

    An unmatched request raises rather than returning an empty body: a mock
    that answers anything cannot notice a wrong endpoint, which is the most
    useful thing this kind of test catches.
    """
    queues = {frag: list(bodies) for frag, bodies in routes}

    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        for frag, bodies in queues.items():
            if frag in str(request.url):
                return httpx.Response(200, json=bodies.pop(0) if len(bodies) > 1 else bodies[0])
        raise AssertionError(f"no mock route for {request.url}")

    return httpx.MockTransport(handler)


def _client(key: str, routes: list[tuple[str, list[dict]]], record: list[httpx.Request] | None = None):
    return AiChatComplianceClient(key, transport=_transport(routes, record))


async def test_activity_feed_is_read():
    rows, cursor = await _client(FULL_KEY, [("/compliance/activities", [_ACTIVITIES])]).list_activities()

    assert len(rows) == 1
    assert rows[0]["type"] == "claude_chat_created"
    assert rows[0]["actor"]["email_address"] == "user@example.com"
    assert cursor is None


async def test_the_activity_feed_accepts_an_admin_key():
    """Both key types carry this scope, so there must be no refusal here.

    Refusing an admin key for the one endpoint it *can* reach would make
    the cheaper key useless and send operators to mint the privileged one
    they do not need.
    """
    rows, _ = await _client(ADMIN_KEY, [("/compliance/activities", [_ACTIVITIES])]).list_activities()
    assert len(rows) == 1


async def test_pagination_follows_next_page_and_stops():
    page_one = {"data": [{"uuid": "a", "name": "one"}], "has_more": True, "next_page": "tok-2"}
    page_two = {"data": [{"uuid": "b", "name": "two"}], "has_more": False, "next_page": None}
    seen: list[httpx.Request] = []
    rows = await _client(FULL_KEY, [("/compliance/organizations", [page_one, page_two])], seen).list_organizations()

    assert [r["uuid"] for r in rows] == ["a", "b"]
    assert len(seen) == 2
    # The token is passed back unchanged, which the vendor requires.
    assert dict(httpx.URL(str(seen[-1].url)).params)["page"] == "tok-2"


async def test_the_request_carries_the_vendor_required_headers():
    """A missing `anthropic-version` is a 400 the mock would never show.

    Asserting on the request as well as on the parsed result is what stops
    a mock being more forgiving than the vendor.
    """
    seen: list[httpx.Request] = []
    await _client(FULL_KEY, [("/compliance/activities", [_ACTIVITIES])], seen).list_activities()

    assert seen[0].headers["x-api-key"] == FULL_KEY
    assert seen[0].headers["anthropic-version"] == "2023-06-01"


async def test_users_are_read_for_one_organization():
    body = {"data": [{"id": "user_01", "email_address": "alice@example.com", "role": "admin"}], "has_more": False}
    rows = await _client(FULL_KEY, [(f"/organizations/{ORG}/users", [body])]).list_users(ORG)
    assert rows[0]["role"] == "admin"


async def test_chat_listing_returns_references_with_no_content():
    refs = await _client(FULL_KEY, [("/compliance/apps/chats", [_CHATS])]).list_chats()

    assert len(refs) == 1
    ref = refs[0]
    assert ref.external_id == "claude_chat_01H5CWunD7RpVJ5bHa8RCkja"
    assert ref.actor_email == "user@example.com"
    assert ref.project_external_id == "claude_proj_01KGp4eZNug9ri4kE35RSppq"
    # The conversation's own title is content the tenant did not ask us to
    # keep, and it is routinely a summary of the conversation.
    assert not hasattr(ref, "name")


async def test_classifying_a_chat_returns_labels_and_never_the_text():
    """The boundary that makes the content table safe to persist.

    The messages exist inside this call and nowhere else: the method
    returns a `Classification`, so no caller can reach the conversation
    even by accident.
    """
    messages = {
        "data": [
            {"id": "m1", "text": "can you review this deploy script"},
            {
                "id": "m2",
                "content": [
                    {"type": "text", "text": "sure, paste it"},
                    {"type": "text", "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
                ],
            },
        ],
        "has_more": False,
    }
    result = await _client(FULL_KEY, [("/messages", [messages])]).classify_chat("claude_chat_01")

    assert result.labels == ("secrets",)
    assert result.secret_kinds == ("aws_access_key",)
    assert result.messages_examined == 2
    assert result.messages_matched == 1
    assert result.snippet is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in result.snippet


async def test_a_content_block_list_is_read_not_just_a_plain_text_field():
    """The negative twin of the message flattener.

    The vendor sends either shape. A reader that handled only `text` would
    classify a corpus of block-form messages as entirely clean — the quiet
    direction of wrong, and one no error surfaces.
    """
    messages = {"data": [{"id": "m1", "content": [{"type": "text", "text": "SSN 123-45-6789"}]}], "has_more": False}
    result = await _client(FULL_KEY, [("/messages", [messages])]).classify_chat("claude_chat_01")
    assert result.labels == ("regulated",)


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.list_organizations(),
        lambda c: c.list_users(ORG),
        lambda c: c.list_roles(ORG),
        lambda c: c.list_chats(),
        lambda c: c.classify_chat("claude_chat_01"),
    ],
)
async def test_an_admin_key_is_refused_before_the_request_for_everything_else(call):
    """Refused by type, not by 403.

    The vendor answers these five 403 for an admin key. Letting the request
    go and surfacing the 403 would tell an operator their key is wrong when
    the key is fine and the *type* is not, which is a different fix. The
    empty route list is the proof: any HTTP call at all would raise
    "no mock route".
    """
    client = AiChatComplianceClient(ADMIN_KEY, transport=_transport([]))
    with pytest.raises(ComplianceKeyTypeError, match="Compliance Access Key"):
        await call(client)


async def test_no_method_returns_message_text():
    """A structural assertion, not a behavioural one.

    If a future method hands a caller the message list, the rest of this
    feature's minimisation argument stops holding. Asserting on the public
    surface is the only way that shows up in review.
    """
    public = {name for name in dir(AiChatComplianceClient) if not name.startswith("_")}
    assert public == {
        "classify_chat",
        "list_activities",
        "list_chats",
        "list_organizations",
        "list_roles",
        "list_users",
        "reaches_content",
    }

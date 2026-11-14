"""A custom endpoint's chat models can populate the selector, and nothing else can.

What this closes
----------------
The ``custom`` BYOK provider points a tenant at any OpenAI-compatible endpoint,
and the model was a hand-typed id. ``POST /api/v1/llm/credentials/models`` asks
``GET {base}/models`` and returns the chat-capable entries.

Three things are pinned here, and each has a way to look right while being
wrong:

* **The filter.** An aggregating endpoint lists image, video, audio and
  embedding models beside its chat models, and its ``/models`` rows say so only
  through optional fields. A filter that passed everything would still produce
  a populated dropdown; the fixtures below assert the exact surviving set.
* **The bounds.** The URL and the body are both tenant-controlled. Each bound is
  driven past its limit through the real ``httpx`` client and streaming read --
  only the bytes on the wire are swapped, via ``httpx.MockTransport``.
* **The key.** The stored key goes only to the stored base URL. A form that
  changed the base URL and left the key blank must not send the saved key to
  the new host.
"""

from __future__ import annotations

import asyncio
import functools
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import llm_credentials as llm_credentials_module
from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.security.credential_vault import get_vault
from app.services import llm_model_discovery as discovery_mod
from app.services.llm_model_discovery import (
    DISCOVERY_MAX_BYTES,
    DISCOVERY_MAX_MODELS,
    discover_chat_models,
    filter_chat_models,
    models_url_for_base,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

#: A private literal: permitted by ``allow_private=True`` and needs no DNS.
PRIVATE_BASE = "http://10.20.30.40:8000/v1"


@pytest.fixture(autouse=True)
def _airgap_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patched where it is read, at call time -- see test_llm_credential_probe.
    from app.core import airgap as airgap_mod

    monkeypatch.setattr(airgap_mod.settings, "AISOC_AIRGAPPED", False, raising=False)


def _ids(rows: list[Any]) -> set[str]:
    return {m.id for m in filter_chat_models(rows).models}


# --------------------------------------------------------------- fixtures

#: Shaped like an aggregating gateway: one row per (model, endpoint) pair, the
#: endpoint named in ``type``, and several model families in one list. Every
#: name is invented.
MIXED_GATEWAY_ROWS: list[dict[str, Any]] = [
    {"id": "acme/chat-large", "type": "vendor-a/chat-completions"},
    {"id": "acme/chat-large", "type": "vendor-a/responses"},
    {"id": "acme/chat-small", "type": "vendor-a/chat-completions"},
    # Served over a second chat protocol too; offered once.
    {"id": "globex/reasoner-2", "type": "vendor-b/messages"},
    {"id": "globex/reasoner-2", "type": "vendor-a/chat-completions"},
    # A chat row whose id contains a non-text word: the declared type wins.
    {"id": "acme/voice-audio-preview", "type": "vendor-a/chat-completions"},
    # Only reachable through an asynchronous, non-chat route.
    {"id": "acme/deep-thinker-pro", "type": "vendor-a/responses/submit"},
    {"id": "initech/decider-1", "type": "internal/decisions"},
    {"id": "acme/pixel-3", "type": "vendor-a/image-generations"},
    {"id": "acme/pixel-3-edit", "type": "vendor-a/image-editing"},
    {"id": "umbrella/clipmaker", "type": "internal/video-generations/submit"},
    {"id": "acme/vector-small", "type": "vendor-a/embeddings"},
    {"id": "hooli/narrator", "type": "internal/text-to-speech"},
    {"id": "hooli/scribe", "type": "internal/speech-to-text/submit"},
    {"id": "hooli/composer", "type": "internal/audio-generations/submit"},
    {"id": "initech/page-reader", "type": "internal/optical-character-recognition"},
    # A multi-purpose router listed under every route it accepts.
    {"id": "globex/router", "type": "vendor-a/image-generations"},
    {"id": "globex/router", "type": "vendor-a/chat-completions"},
]

MIXED_GATEWAY_CHAT = {"acme/chat-large", "acme/chat-small", "globex/reasoner-2", "acme/voice-audio-preview", "globex/router"}


class TestTheFilter:
    def test_a_mixed_gateway_list_keeps_exactly_its_chat_models(self) -> None:
        result = filter_chat_models(MIXED_GATEWAY_ROWS)

        assert {m.id for m in result.models} == MIXED_GATEWAY_CHAT
        assert result.listed == 15
        assert result.excluded == 10
        assert [m.id for m in result.models] == sorted(MIXED_GATEWAY_CHAT), "offered once each, in a stable order"

    def test_a_plain_openai_shaped_list_is_judged_by_the_id(self) -> None:
        """A self-hosted server declares nothing. Its rows are chat models
        unless the id names a non-text family, as a whole word."""
        rows = [
            {"id": i, "object": "model", "owned_by": "local"}
            for i in (
                "example-chat-7b",
                "example-instruct-70b:q4",
                "example-embed-large",
                "text-embedding-small",
                "example-tts-1",
                "example-whisper-small",
                "example-image-xl",
                "example-rerank-base",
                "imagery-analyst-13b",
            )
        ]

        assert _ids(rows) == {"example-chat-7b", "example-instruct-70b:q4", "imagery-analyst-13b"}

    def test_declared_modalities_are_honoured(self) -> None:
        rows = [
            {"id": "a/text", "architecture": {"modality": "text->text"}},
            {"id": "a/vision", "architecture": {"modality": "text+image->text"}},
            {"id": "a/painter", "architecture": {"modality": "text->image"}},
            {"id": "a/listener", "architecture": {"input_modalities": ["audio"], "output_modalities": ["text"]}},
            {"id": "a/both", "architecture": {"input_modalities": ["text"], "output_modalities": ["text", "image"]}},
            {"id": "a/split", "modalities": {"input": ["text"], "output": ["audio"]}},
            {"id": "a/top", "input_modalities": ["text"], "output_modalities": ["text"]},
        ]

        assert _ids(rows) == {"a/text", "a/vision", "a/both", "a/top"}

    def test_declared_capabilities_are_honoured(self) -> None:
        rows = [
            {"id": "a/one", "capabilities": {"completion_chat": True, "vision": False}},
            {"id": "a/two", "capabilities": {"completion_chat": False}},
            {"id": "a/three", "capabilities": ["chat", "tools"]},
            {"id": "a/four-embed", "capabilities": {"function_calling": True}},
        ]

        # a/four-embed declares nothing about chat, so its id decides.
        assert _ids(rows) == {"a/one", "a/three"}

    def test_a_declared_negative_beats_a_declared_positive(self) -> None:
        """Wrongly hidden can still be typed; wrongly offered fails at triage."""
        rows = [{"id": "a/x", "type": "chat", "architecture": {"modality": "text->image"}}]

        assert _ids(rows) == set()

    def test_a_label_that_never_says_chat_is_not_a_classifier(self) -> None:
        """Some endpoints use ``type`` for "base" vs "fine-tuned". Reading
        that as "not chat" would empty the list."""
        rows = [
            {"id": "a/base-model", "type": "base"},
            {"id": "a/tuned", "type": "fine-tuned"},
            {"id": "a/embed-v1", "type": "base"},
        ]

        assert _ids(rows) == {"a/base-model", "a/tuned"}

    def test_rows_without_a_usable_id_are_skipped(self) -> None:
        rows: list[Any] = ["a-string", None, {"id": ""}, {"id": 7}, {"name": "x"}, {"id": "ok/model"}]

        result = filter_chat_models(rows)

        assert [m.id for m in result.models] == ["ok/model"]
        assert result.listed == 1

    def test_nothing_chat_capable_says_so_and_points_at_the_typed_id(self) -> None:
        result = filter_chat_models([{"id": "a/embed", "type": "embeddings"}])

        assert result.outcome == "ok"
        assert result.models == []
        assert "type the model id" in result.detail.lower()


class TestTheUrl:
    @pytest.mark.parametrize(
        ("base", "expected"),
        [
            ("https://gw.example.com/v1", "https://gw.example.com/v1/models"),
            ("https://gw.example.com/v1/", "https://gw.example.com/v1/models"),
            ("https://gw.example.com", "https://gw.example.com/v1/models"),
            ("https://gw.example.com/v1/chat/completions", "https://gw.example.com/v1/models"),
        ],
    )
    def test_models_is_listed_beside_the_completions_url_triage_calls(self, base: str, expected: str) -> None:
        assert models_url_for_base(base) == expected


# --------------------------------------------------------------- the call


class _Recorder:
    """A ``MockTransport`` handler that records what reached the wire."""

    def __init__(self, response: httpx.Response | None = None, *, delay: float = 0.0) -> None:
        self.response = response or httpx.Response(200, json={"object": "list", "data": MIXED_GATEWAY_ROWS})
        self.delay = delay
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.response

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


class TestTheCall:
    @pytest.mark.asyncio
    async def test_it_asks_models_with_the_key_and_returns_only_chat(self) -> None:
        wire = _Recorder()

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k-123", transport=wire.transport)

        assert result.outcome == "ok", result.detail
        assert {m.id for m in result.models} == MIXED_GATEWAY_CHAT
        [request] = wire.requests
        assert request.method == "GET"
        assert str(request.url) == f"{PRIVATE_BASE}/models"
        assert request.headers["authorization"] == "Bearer k-123"

    @pytest.mark.asyncio
    async def test_no_key_means_no_authorization_header(self) -> None:
        wire = _Recorder()

        await discover_chat_models(base_url=PRIVATE_BASE, api_key=None, transport=wire.transport)

        assert "authorization" not in wire.requests[0].headers

    @pytest.mark.parametrize(
        ("status_code", "needle"),
        [(401, "rejected the key"), (403, "rejected the key"), (404, "type the model id"), (500, "http 500")],
    )
    @pytest.mark.asyncio
    async def test_each_refusal_is_a_reported_state(self, status_code: int, needle: str) -> None:
        wire = _Recorder(httpx.Response(status_code, text="nope"))

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert result.outcome == "refused"
        assert needle in result.detail.lower()
        assert result.models == []

    @pytest.mark.asyncio
    async def test_a_redirect_is_reported_not_followed(self) -> None:
        """Following it would dial a host the SSRF guard never saw."""
        wire = _Recorder(httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert result.outcome == "refused"
        assert len(wire.requests) == 1

    @pytest.mark.parametrize("body", [b"<html>not json</html>", b'{"models": []}', b'"a string"'])
    @pytest.mark.asyncio
    async def test_a_body_that_is_not_a_model_list_is_refused(self, body: bytes) -> None:
        wire = _Recorder(httpx.Response(200, content=body))

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert result.outcome == "refused"
        assert result.models == []


class TestTheBounds:
    @pytest.mark.asyncio
    async def test_a_body_over_the_byte_cap_is_not_read(self) -> None:
        rows = [{"id": f"m/{i:07d}", "type": "chat", "pad": "x" * 200} for i in range(DISCOVERY_MAX_BYTES // 200 + 10)]
        wire = _Recorder(httpx.Response(200, content=json.dumps({"data": rows}).encode()))

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert result.outcome == "refused"
        assert "larger than" in result.detail
        assert result.models == []

    @pytest.mark.asyncio
    async def test_the_selector_is_capped_and_says_so(self) -> None:
        rows = [{"id": f"m/{i:04d}", "type": "chat"} for i in range(DISCOVERY_MAX_MODELS + 25)]
        rows += [{"id": f"img/{i:04d}", "type": "image"} for i in range(50)]
        wire = _Recorder(httpx.Response(200, json={"data": rows}))

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert result.outcome == "ok"
        assert len(result.models) == DISCOVERY_MAX_MODELS
        assert result.truncated is True
        assert result.listed == DISCOVERY_MAX_MODELS + 75

    @pytest.mark.asyncio
    async def test_the_raw_row_count_does_not_cut_chat_models(self) -> None:
        """Non-chat rows ahead of the chat ones must not use up the selector's
        budget: capping raw rows at the selector size would drop these."""
        rows = [{"id": f"img/{i:04d}", "type": "image"} for i in range(DISCOVERY_MAX_MODELS + 100)]
        rows += [{"id": "acme/chat-late", "type": "chat"}]
        wire = _Recorder(httpx.Response(200, json={"data": rows}))

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert [m.id for m in result.models] == ["acme/chat-late"]
        assert result.truncated is False

    @pytest.mark.asyncio
    async def test_the_deadline_covers_the_whole_exchange(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(discovery_mod, "DISCOVERY_TIMEOUT_SECONDS", 0.2)
        wire = _Recorder(delay=2.0)

        result = await discover_chat_models(base_url=PRIVATE_BASE, api_key="k", transport=wire.transport)

        assert result.outcome == "unreachable"
        assert "did not return" in result.detail


class TestTheGuards:
    @pytest.mark.parametrize(
        "base",
        ["http://169.254.169.254/v1", "http://127.0.0.1:8000/v1", "http://[::1]:8000/v1"],
    )
    @pytest.mark.asyncio
    async def test_metadata_and_loopback_are_refused_before_anything_is_dialled(self, base: str) -> None:
        wire = _Recorder()

        result = await discover_chat_models(base_url=base, api_key="k", transport=wire.transport)

        assert result.outcome == "refused"
        assert "refused" in result.detail.lower()
        assert wire.requests == []

    @pytest.mark.asyncio
    async def test_air_gap_reports_unverified_and_dials_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core import airgap as airgap_mod

        monkeypatch.setattr(airgap_mod.settings, "AISOC_AIRGAPPED", True, raising=False)
        wire = _Recorder()

        result = await discover_chat_models(base_url="https://gw.example.com/v1", api_key="k", transport=wire.transport)

        assert result.outcome == "unverified"
        assert wire.requests == []


# --------------------------------------------------------------- the route


class _Session:
    """Answers the endpoint's one SELECT with a fixed row."""

    def __init__(self, row: Any) -> None:
        self.row = row

    async def execute(self, *_: Any, **__: Any) -> Any:
        return SimpleNamespace(scalar_one_or_none=lambda: self.row)


def _stored(provider: str = "custom", base_url: str = PRIVATE_BASE, key: str | None = "stored-key") -> SimpleNamespace:
    now = datetime.now(UTC)
    return SimpleNamespace(
        tenant_id=uuid.uuid4(),
        provider=provider,
        base_url=base_url,
        model=None,
        api_key_vault=get_vault().encrypt(key) if key else None,
        settings={},
        enabled=True,
        created_at=now,
        updated_at=now,
        last_rotated_at=now,
    )


@pytest.fixture
def route(monkeypatch: pytest.MonkeyPatch):
    """The real router, the real permission dependency and the real discovery
    function; only the database row and the bytes on the wire are supplied."""
    wire = _Recorder()
    monkeypatch.setattr(
        llm_credentials_module,
        "discover_chat_models",
        functools.partial(discover_chat_models, transport=wire.transport),
    )
    app = FastAPI()
    app.include_router(llm_credentials_module.router, prefix="/api/v1")
    state: dict[str, Any] = {"row": None, "scopes": None}
    app.dependency_overrides[get_db] = lambda: _Session(state["row"])
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="tenant_admin",
        email="admin@example.com",
        scopes=state["scopes"],
    )
    return TestClient(app), wire, state


class TestTheRoute:
    def test_it_is_published_where_the_console_asks_for_it(self) -> None:
        from pathlib import Path

        from app.main import app

        client = (Path(__file__).resolve().parents[3] / "apps" / "web" / "src" / "lib" / "api.ts").read_text(encoding="utf-8")

        assert "/api/v1/llm/credentials/models" in app.openapi()["paths"]
        assert "/api/v1/llm/credentials/models" in client

    def test_an_unsaved_form_lists_with_the_typed_key(self, route: Any) -> None:
        client, wire, _ = route

        response = client.post("/api/v1/llm/credentials/models", json={"base_url": PRIVATE_BASE, "api_key": "typed-key"})

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["outcome"] == "ok"
        assert {m["id"] for m in body["models"]} == MIXED_GATEWAY_CHAT
        assert (body["listed"], body["excluded"]) == (15, 10)
        assert wire.requests[0].headers["authorization"] == "Bearer typed-key"

    def test_a_saved_credential_lists_with_the_stored_key(self, route: Any) -> None:
        client, wire, state = route
        state["row"] = _stored()

        response = client.post("/api/v1/llm/credentials/models", json={})

        assert response.status_code == 200, response.text
        assert str(wire.requests[0].url) == f"{PRIVATE_BASE}/models"
        assert wire.requests[0].headers["authorization"] == "Bearer stored-key"

    def test_the_stored_key_is_not_sent_to_a_different_base_url(self, route: Any) -> None:
        """The form changed the base URL and left the key blank. Sending the
        saved key there would hand it to a host it was never configured for."""
        client, wire, state = route
        state["row"] = _stored()

        response = client.post("/api/v1/llm/credentials/models", json={"base_url": "http://10.99.99.99:9000/v1"})

        assert response.status_code == 200, response.text
        assert str(wire.requests[0].url) == "http://10.99.99.99:9000/v1/models"
        assert "authorization" not in wire.requests[0].headers

    def test_another_providers_key_is_never_used(self, route: Any) -> None:
        client, wire, state = route
        state["row"] = _stored(provider="local-litellm")

        response = client.post("/api/v1/llm/credentials/models", json={"base_url": PRIVATE_BASE})

        assert response.status_code == 200, response.text
        assert "authorization" not in wire.requests[0].headers

    def test_no_base_url_anywhere_is_a_422(self, route: Any) -> None:
        client, wire, _ = route

        response = client.post("/api/v1/llm/credentials/models", json={})

        assert response.status_code == 422
        assert wire.requests == []

    def test_a_non_http_base_url_is_a_422(self, route: Any) -> None:
        client, wire, _ = route

        response = client.post("/api/v1/llm/credentials/models", json={"base_url": "file:///etc/passwd"})

        assert response.status_code == 422
        assert wire.requests == []

    def test_a_read_scoped_key_cannot_make_the_server_dial_out(self, route: Any) -> None:
        """`settings:write`, like `/test`: the route dials an operator-supplied
        URL with private addresses permitted."""
        client, wire, state = route
        state["scopes"] = ["settings:read"]

        response = client.post("/api/v1/llm/credentials/models", json={"base_url": PRIVATE_BASE})

        assert response.status_code == 403
        assert wire.requests == []

    def test_a_write_scoped_key_is_not_refused(self, route: Any) -> None:
        """The negative control for the refusal above."""
        client, _, state = route
        state["scopes"] = ["settings:write"]

        response = client.post("/api/v1/llm/credentials/models", json={"base_url": PRIVATE_BASE})

        assert response.status_code == 200, response.text

"""Integration tests for the NL → playbook drafter HTTP endpoint (T3.7).

Mounts the playbooks router on a throw-away FastAPI app and exercises
``POST /api/v1/playbooks/draft-from-nl`` with the substrate path
(``allow_llm=False``) so the tests stay hermetic.

Covers the explicit contract guarantees promised to the React Flow
editor:

* 200 on a valid prompt with a payload shape exactly matching
  :meth:`DraftResult.to_dict`.
* 400 on empty / whitespace-only prompt — UX must show the field error.
* 400 on prompt > 4000 chars — DoS / context-flooding guard.
* ``enabled`` MUST come back ``false`` no matter the input.
* The route SHOULD appear BEFORE the catch-all ``/{playbook_id}`` route
  — otherwise the substring ``draft-from-nl`` is interpreted as a
  playbook id (regression guard).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.api.playbooks import router as playbooks_router  # noqa: E402

# ---------------------------------------------------------------------------
# Test app fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(playbooks_router)
    return TestClient(app)


def _post(client: TestClient, body: dict[str, Any]) -> Any:
    return client.post("/api/v1/playbooks/draft-from-nl", json=body)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_draft_from_nl_happy_path(client: TestClient) -> None:
    resp = _post(
        client,
        {
            "prompt": ("When a high-severity alert fires, isolate the host " "and notify the SOC."),
            "allow_llm": False,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert set(payload.keys()) == {
        "playbook",
        "rationale",
        "used_llm",
        "schema_validated",
    }
    assert payload["used_llm"] is False
    assert payload["schema_validated"] is True

    pb = payload["playbook"]
    types = [s["type"] for s in pb["steps"]]
    assert "isolate_host" in types
    assert "notify" in types
    assert pb["enabled"] is False, "drafts MUST come back disabled"
    assert pb["trigger"]["on"] == "alert"
    assert pb["trigger"].get("severity") == ["high"]


def test_draft_returns_nl_drafted_tag(client: TestClient) -> None:
    resp = _post(client, {"prompt": "Notify the SOC", "allow_llm": False})
    assert resp.status_code == 200
    pb = resp.json()["playbook"]
    assert "nl-drafted" in pb["tags"]


def test_draft_default_allow_llm_is_true(client: TestClient) -> None:
    # Without ``allow_llm`` the server defaults to True, but with no
    # LLM configured the drafter must still fall back to substrate
    # successfully (used_llm reflects the actual path taken).
    resp = _post(client, {"prompt": "Enrich the entity"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["used_llm"] in (True, False)
    # Either way the playbook must be valid.
    assert body["playbook"]["enabled"] is False


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", "\n\t  \n"])
def test_empty_prompt_returns_400(client: TestClient, bad: str) -> None:
    resp = _post(client, {"prompt": bad, "allow_llm": False})
    assert resp.status_code == 400
    assert "prompt" in resp.text.lower()


def test_oversize_prompt_returns_400(client: TestClient) -> None:
    huge = "a" * 4001
    resp = _post(client, {"prompt": huge, "allow_llm": False})
    assert resp.status_code == 400
    assert "too long" in resp.text.lower()


def test_missing_prompt_returns_422(client: TestClient) -> None:
    # Pydantic — required field missing.
    resp = client.post("/api/v1/playbooks/draft-from-nl", json={})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Routing regression — the new route MUST NOT be shadowed by /{playbook_id}
# ---------------------------------------------------------------------------


def test_route_not_shadowed_by_id_param() -> None:
    """The ``draft-from-nl`` route must be declared BEFORE the catch-all
    ``/{playbook_id}`` route on the same router; otherwise FastAPI
    would route ``POST /api/v1/playbooks/draft-from-nl`` as a request
    for a playbook whose id is ``draft-from-nl``."""

    # Walk the router's exposed routes and check ordering.
    paths_in_order = [getattr(r, "path", None) for r in playbooks_router.routes if getattr(r, "path", None)]
    try:
        nl_idx = paths_in_order.index("/api/v1/playbooks/draft-from-nl")
    except ValueError as exc:
        raise AssertionError("draft-from-nl route not registered on the playbooks router") from exc

    # Any route containing ``{playbook_id}`` must appear AFTER nl_idx.
    for i, p in enumerate(paths_in_order):
        if p and "{playbook_id}" in p:
            assert i > nl_idx, (
                f"route {p!r} (idx {i}) comes BEFORE draft-from-nl (idx {nl_idx}); " f"it would shadow the NL drafter endpoint."
            )

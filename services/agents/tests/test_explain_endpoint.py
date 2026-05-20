# ruff: noqa: I001
"""Integration tests for ``POST /api/v1/explain`` (WS-D1).

We mount *only* the explain router into a fresh FastAPI app so the test
suite does not pull in the heavyweight ``services/agents/app/main.py``
lifespan (LangGraph, model loaders, MITRE corpus prefetch, etc.). The
LLM is forced off via ``AISOC_AIRGAPPED=true`` and a missing
``OPENAI_API_KEY`` so every stream is deterministic.

Each test resets the module-level explain-limiter singleton via
:func:`_reset_explain_limiter` so env-var-driven config changes take
effect for the next request.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ----- import path setup ---------------------------------------------------

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

# Force the LLM off *before* importing app.api.explain so its module-level
# default ladder is consistent with what the tests assume.
os.environ.pop("OPENAI_API_KEY", None)
os.environ["AISOC_AIRGAPPED"] = "true"

from app.api.explain import (  # noqa: E402
    _frame,
    _reset_explain_limiter,
    router as explain_router,
)

# ----- shared fixtures ------------------------------------------------------


SAMPLE_ALERT: dict[str, Any] = {
    "id": "ALERT-TEST-0001",
    "title": "Impossible travel — login from Frankfurt then Tokyo within 8 minutes",
    "severity": "high",
    "source": "okta",
    "description": (
        "User authenticated successfully from two geographically impossible locations within an 8-minute window. Likely account takeover."
    ),
    "tags": ["account-takeover", "ato", "identity"],
    "mitreAttack": [{"techniqueId": "T1078"}],
    "iocs": [
        {"type": "ip", "value": "203.0.113.42"},
        {"type": "ip", "value": "198.51.100.7"},
    ],
    "rawEvent": {
        "user_name": "alice.tan",
        "src_ip": "203.0.113.42",
        "hostname": "okta-prod",
    },
}


def _build_app() -> FastAPI:
    """Construct a fresh FastAPI app with only the explain router mounted."""
    _reset_explain_limiter()
    app = FastAPI()
    app.include_router(explain_router)
    return app


def _parse_ndjson(body: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


@pytest.fixture(autouse=True)
def _isolate_limiter_state() -> Any:
    """Reset the explain limiter singleton before and after every test.

    Env vars are restored automatically by ``monkeypatch``; the singleton
    is process-wide and outlives the env scope, so we drop it explicitly.
    """
    _reset_explain_limiter()
    yield
    _reset_explain_limiter()


# ---------------------------------------------------------------------------
# Happy path — full stream contract
# ---------------------------------------------------------------------------


def test_explain_streams_grounded_ndjson(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the full WS-D1 frame contract on a representative ATO alert.

    Asserts:
      * HTTP 200 + ``application/x-ndjson`` content-type
      * ``X-RateLimit-*`` headers present and consistent with config
      * Section ordering: summary → ocsf → mitre → evidence → next
      * Last frame is ``done`` and echoes the alert id
      * Okta-sourced alert maps to OCSF Authentication (class_uid=3002)
      * MITRE T1078 emitted with a valid attack.mitre.org URL
      * ATO-tagged alert recommends ``ato-impossible-travel-block-v1``
      * Evidence frame surfaces the user from ``rawEvent``
    """
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "120")
    monkeypatch.setenv("AISOC_EXPLAIN_BURST", "60")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")

    client = TestClient(_build_app())
    response = client.post(
        "/api/v1/explain",
        json={
            "alert": SAMPLE_ALERT,
            "alert_id": SAMPLE_ALERT["id"],
            "tenant_id": "tenant-a",
        },
    )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert int(response.headers["X-RateLimit-Limit"]) == 60
    # First request consumes one token.
    assert int(response.headers["X-RateLimit-Remaining"]) == 59
    assert "Retry-After" not in response.headers

    frames = _parse_ndjson(response.text)
    assert frames, "expected at least one NDJSON frame"

    last = frames[-1]
    assert last["kind"] == "done", f"expected 'done' last, got {last}"
    assert last["alert_id"] == "ALERT-TEST-0001"

    # Section ordering — explicit and stable so the frontend can rely on it.
    section_ids = [f["id"] for f in frames if f["kind"] == "section"]
    assert section_ids == ["summary", "ocsf", "mitre", "evidence", "next"], f"unexpected section order: {section_ids}"

    # OCSF mapping: Okta source → Authentication (class_uid 3002).
    ocsf = next((f for f in frames if f["kind"] == "ocsf"), None)
    assert ocsf is not None, "no ocsf frame emitted"
    assert ocsf["class_uid"] == 3002

    # MITRE: T1078 with valid attack.mitre.org URL.
    mitre = [f for f in frames if f["kind"] == "mitre"]
    assert any(m["id"] == "T1078" for m in mitre), f"expected T1078, got {[m['id'] for m in mitre]}"
    for m in mitre:
        assert m["url"].startswith("https://attack.mitre.org/techniques/")

    # ATO tag pulls in the impossible-travel-block playbook.
    next_steps = [f for f in frames if f["kind"] == "next_step"]
    assert any(s["playbook_id"] == "ato-impossible-travel-block-v1" for s in next_steps)

    # Evidence surfaces the offending user from rawEvent.
    evidence = [f for f in frames if f["kind"] == "evidence"]
    assert any(
        "alice.tan" in e["value"] for e in evidence
    ), f"evidence missing user from rawEvent: {[(e['label'], e['value']) for e in evidence]}"


def test_explain_uses_default_tenant_when_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitting ``tenant_id`` must still produce a valid stream.

    The body model defaults ``tenant_id`` to ``"default"`` which the
    rate-limit-key resolver explicitly treats as "no tenant — fall back
    to client IP", so the call must not 500 on a missing field.
    """
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "120")
    monkeypatch.setenv("AISOC_EXPLAIN_BURST", "60")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")

    client = TestClient(_build_app())
    response = client.post(
        "/api/v1/explain",
        json={"alert": SAMPLE_ALERT, "alert_id": SAMPLE_ALERT["id"]},
    )
    assert response.status_code == 200, response.text
    frames = _parse_ndjson(response.text)
    assert frames[-1]["kind"] == "done"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_explain_throttles_with_429_and_ndjson_error_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant exceeds bucket → second call returns 429 + structured error.

    Capacity=1 with a tiny refill rate guarantees the second call within
    the same test is denied. The 429 body must be a single NDJSON
    ``error`` frame so SSE/EventSource clients that ignore HTTP status
    still see a structured failure.
    """
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "1")
    monkeypatch.setenv("AISOC_EXPLAIN_BURST", "1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")

    client = TestClient(_build_app())
    body = {
        "alert": SAMPLE_ALERT,
        "alert_id": SAMPLE_ALERT["id"],
        "tenant_id": "tenant-a",
    }

    first = client.post("/api/v1/explain", json=body)
    assert first.status_code == 200, first.text

    second = client.post("/api/v1/explain", json=body)
    assert second.status_code == 429, second.text
    assert second.headers["content-type"].startswith("application/x-ndjson")
    assert int(second.headers["X-RateLimit-Limit"]) == 1
    assert int(second.headers["X-RateLimit-Remaining"]) == 0
    # Retry-After must be a non-negative integer ≥ 1 (rounded up).
    retry = int(second.headers["Retry-After"])
    assert retry >= 1

    frames = _parse_ndjson(second.text)
    assert len(frames) == 1, f"429 body must be a single NDJSON error frame, got {len(frames)}"
    assert frames[0]["kind"] == "error"
    assert "rate_limited" in frames[0]["error"]


def test_explain_buckets_are_per_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """Draining tenant-a's bucket must not throttle tenant-b."""
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "1")
    monkeypatch.setenv("AISOC_EXPLAIN_BURST", "1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")

    client = TestClient(_build_app())

    drain = client.post(
        "/api/v1/explain",
        json={"alert": SAMPLE_ALERT, "tenant_id": "tenant-a"},
    )
    assert drain.status_code == 200
    deny = client.post(
        "/api/v1/explain",
        json={"alert": SAMPLE_ALERT, "tenant_id": "tenant-a"},
    )
    assert deny.status_code == 429

    # tenant-b is fresh — its bucket has not been touched.
    fresh = client.post(
        "/api/v1/explain",
        json={"alert": SAMPLE_ALERT, "tenant_id": "tenant-b"},
    )
    assert fresh.status_code == 200, fresh.text


def test_explain_limiter_disabled_when_rpm_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``AISOC_EXPLAIN_RPM=0`` is the documented opt-out for self-hosters."""
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "0")
    monkeypatch.setenv("AISOC_EXPLAIN_BURST", "0")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")

    client = TestClient(_build_app())
    response = client.post(
        "/api/v1/explain",
        json={"alert": SAMPLE_ALERT, "tenant_id": "tenant-a"},
    )
    assert response.status_code == 200
    assert "X-RateLimit-Limit" not in response.headers
    assert "X-RateLimit-Remaining" not in response.headers
    assert "Retry-After" not in response.headers


def test_explain_limiter_handles_invalid_env_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Garbage env values must fall back to defaults, not crash startup."""
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "not-a-number")
    monkeypatch.setenv("AISOC_EXPLAIN_BURST", "also-bad")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")

    client = TestClient(_build_app())
    response = client.post(
        "/api/v1/explain",
        json={"alert": SAMPLE_ALERT, "tenant_id": "tenant-a"},
    )
    assert response.status_code == 200, response.text
    # Defaults kick in → headers are present and the limit > 0.
    assert int(response.headers["X-RateLimit-Limit"]) > 0


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------


def test_frame_emits_newline_terminated_json() -> None:
    """``_frame`` must produce one NDJSON record terminated with ``\\n``."""
    out = _frame({"kind": "delta", "section": "summary", "text": "hello "})
    assert isinstance(out, bytes)
    assert out.endswith(b"\n")
    parsed = json.loads(out.decode().strip())
    assert parsed == {"kind": "delta", "section": "summary", "text": "hello "}


def test_frame_handles_unicode() -> None:
    """Frames must serialise non-ASCII chars without surrogate errors."""
    out = _frame({"kind": "delta", "section": "summary", "text": "naïve résumé "})
    parsed = json.loads(out.decode().strip())
    assert parsed["text"] == "naïve résumé "

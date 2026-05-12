"""
HTTP-level tests for the live-action router (Stage 2 #8).

These tests pin down the REST contract that the agent loop, the
playbook editor, and the frontend all build against:

* ``GET /api/v1/live-actions`` returns a stable discovery shape with
  ``executors``, ``vendors``, and ``capabilities`` keys.
* The two filter query params (``vendor_id``, ``capability``) compose.
* ``POST /api/v1/live-actions/dispatch`` returns 200 even on executor
  failure — failures live inside ``result.status`` so callers can build
  retry / fallback logic without parsing HTTP error bodies.
* ``POST /api/v1/live-actions/dry-run`` always reports ``mode=dry_run``
  regardless of what the request body said, so the "Preview" button on
  the frontend cannot accidentally fire a live action.

We mount the FastAPI app once per test via TestClient and reset the
registry inside each test so the discovery surface is fully predictable
— without that reset the FastAPI startup hook from a previous test
could leak the full set of 19 builtin adapters into our assertions.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from app.live_actions import (
    LiveActionExecutor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
    register_executor,
    reset_for_tests,
)
from app.main import app
from fastapi.testclient import TestClient


class _StubIsolateHost(LiveActionExecutor):
    vendor_id = "stubvendor"
    capability = "isolate_host"
    description = "Stub isolate-host executor used by router tests."
    requires_credentials = False

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        # Mirror what a real executor does: honour dry_run by returning
        # SIMULATED so the router can tag mode=dry_run consistently.
        status = LiveActionStatus.SIMULATED if request.dry_run else LiveActionStatus.SUCCEEDED
        return LiveActionResult(
            request_id=request.request_id,
            status=status,
            capability=self.capability,
            vendor_id=self.vendor_id,
            summary=f"stub isolate {request.target}",
            details={"echo_target": request.target},
        )


class _StubBlockIP(LiveActionExecutor):
    vendor_id = "stubfirewall"
    capability = "block_ip"
    description = "Stub block-ip executor."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=self.capability,
            vendor_id=self.vendor_id,
            summary=f"blocked {request.target}",
        )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Yield a TestClient with a clean registry seeded with two stubs.

    We deliberately *don't* let the startup hook run with the full set
    of 19 builtin adapters — discovery assertions become brittle when
    the universe shifts under them. The router code path is identical
    regardless of how many executors are registered, so two stubs are
    enough to cover the contract.
    """
    reset_for_tests()
    register_executor(_StubIsolateHost(), source="builtin")
    register_executor(_StubBlockIP(), source="builtin")
    with TestClient(app) as c:
        # The startup hook re-registered the real builtins on top of our
        # stubs. Wipe again and re-seed so the assertions below see only
        # what we expect.
        reset_for_tests()
        register_executor(_StubIsolateHost(), source="builtin")
        register_executor(_StubBlockIP(), source="builtin")
        yield c
    reset_for_tests()


def test_discovery_returns_all_registered_executors(client: TestClient) -> None:
    response = client.get("/api/v1/live-actions")

    assert response.status_code == 200
    body = response.json()
    assert {"executors", "vendors", "capabilities"} <= body.keys()
    assert len(body["executors"]) == 2

    # Vendors and capabilities are sort-uniqued projections.
    assert body["vendors"] == ["stubfirewall", "stubvendor"]
    assert body["capabilities"] == ["block_ip", "isolate_host"]


def test_discovery_filter_by_capability(client: TestClient) -> None:
    response = client.get("/api/v1/live-actions", params={"capability": "isolate_host"})
    assert response.status_code == 200
    body = response.json()
    assert len(body["executors"]) == 1
    assert body["executors"][0]["vendor_id"] == "stubvendor"
    assert body["vendors"] == ["stubvendor"]


def test_discovery_filter_by_vendor(client: TestClient) -> None:
    response = client.get("/api/v1/live-actions", params={"vendor_id": "stubfirewall"})
    assert response.status_code == 200
    body = response.json()
    assert len(body["executors"]) == 1
    assert body["executors"][0]["capability"] == "block_ip"


def test_discovery_filters_compose(client: TestClient) -> None:
    """Combined filters narrow to the intersection."""
    response = client.get(
        "/api/v1/live-actions",
        params={"vendor_id": "stubvendor", "capability": "block_ip"},
    )
    assert response.status_code == 200
    body = response.json()
    # stubvendor only implements isolate_host, so the combined filter is empty.
    assert body["executors"] == []
    assert body["vendors"] == []
    assert body["capabilities"] == []


def test_by_capability_endpoint(client: TestClient) -> None:
    response = client.get("/api/v1/live-actions/by-capability/isolate_host")
    assert response.status_code == 200
    assert response.json() == ["stubvendor"]


def test_by_capability_returns_empty_list_for_unknown(client: TestClient) -> None:
    """No 404 — empty list is the contract so the planner doesn't special-case."""
    response = client.get("/api/v1/live-actions/by-capability/nonexistent_cap")
    assert response.status_code == 200
    assert response.json() == []


def test_by_vendor_endpoint(client: TestClient) -> None:
    response = client.get("/api/v1/live-actions/by-vendor/stubvendor")
    assert response.status_code == 200
    assert response.json() == ["isolate_host"]


def test_dispatch_succeeds_and_reports_live_mode(client: TestClient) -> None:
    response = client.post(
        "/api/v1/live-actions/dispatch",
        json={
            "capability": "isolate_host",
            "vendor_id": "stubvendor",
            "target": "host-77",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "live"
    assert body["result"]["status"] == "succeeded"
    assert body["result"]["vendor_id"] == "stubvendor"
    assert body["result"]["capability"] == "isolate_host"
    assert body["result"]["details"]["echo_target"] == "host-77"


def test_dispatch_with_dry_run_flag_reports_dry_run_mode(client: TestClient) -> None:
    response = client.post(
        "/api/v1/live-actions/dispatch",
        json={
            "capability": "isolate_host",
            "vendor_id": "stubvendor",
            "target": "host-77",
            "dry_run": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "dry_run"
    assert body["result"]["status"] == "simulated"


def test_dispatch_unknown_pair_returns_200_with_failed_result(client: TestClient) -> None:
    """Unknown (vendor, capability) is a planning error, not a transport error.

    The agent loop gets ``status=failed`` inside the response body so it
    can pick another vendor without parsing HTTP error shapes.
    """
    response = client.post(
        "/api/v1/live-actions/dispatch",
        json={
            "capability": "isolate_host",
            "vendor_id": "ghost_vendor",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["status"] == "failed"
    assert body["result"]["error"] == "executor_not_found"
    # The summary echoes the missing vendor so the agent can log a
    # human-readable reason without parsing the structured error code.
    assert "ghost_vendor" in body["result"]["summary"]


def test_dry_run_endpoint_forces_dry_run_even_when_body_says_false(
    client: TestClient,
) -> None:
    """The /dry-run endpoint is the safety rail: client cannot opt out."""
    response = client.post(
        "/api/v1/live-actions/dry-run",
        json={
            "capability": "isolate_host",
            "vendor_id": "stubvendor",
            "target": "host-77",
            "dry_run": False,  # client lying — server must override.
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "dry_run"
    # The stub returns SIMULATED whenever request.dry_run is True, which
    # proves the override propagated all the way through.
    assert body["result"]["status"] == "simulated"


def test_dispatch_validates_request_body(client: TestClient) -> None:
    """Pydantic still enforces required fields — empty body should 422."""
    response = client.post("/api/v1/live-actions/dispatch", json={})
    assert response.status_code == 422

"""Authoring and running a response playbook needs more than a login.

GHSA-8cpf-mchw-jpf2, F15. The playbooks router authenticated every caller and
resolved their tenant, and then asked nothing else. So a `viewer` -- the role
that exists precisely to look without touching -- could create a playbook
whose steps dispatch containment, and run it.

Measured against the real router over ASGI before the fix, with a real HS256
console token minted exactly as `services/api` mints one:

    anonymous create                                  401
    viewer POST /api/v1/playbooks   (isolate_host)    201
    viewer POST /api/v1/playbooks/{id}/run            202

The 401 is what makes the other two a finding rather than a broken harness:
authentication worked, and authorization was simply not asked for. The API
gates the same step dispatch on `actions:execute`
(`endpoints/playbook_steps.py:70`), so the two halves of one capability
disagreed about who may use it.

Why a role and not a permission
--------------------------------
`TenantPrincipal` carried tenants and nothing else, so this service had no way
to tell a viewer from an administrator. It now carries the `role` claim from
the verified token -- from the signature, never from a request field -- and
the router maps roles to the two playbook verbs.

That mapping is a *mirror* of `ROLE_PERMISSIONS` in
`services/api/app/core/security.py`, not an import: this service builds with
its own directory as its Docker context and cannot import the API's package.
A mirror that can silently disagree with its original is the second
permission model this repository refuses, so
`test_the_role_table_matches_the_api` reads that file and fails if either
side moves alone.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import pathlib
import time
import uuid

import pytest
from app.api.playbooks import _MAY_AUTHOR, _MAY_RUN
from app.api.playbooks import router as playbooks_router
from fastapi import FastAPI
from fastapi.testclient import TestClient

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
API_SECURITY = REPO_ROOT / "services" / "api" / "app" / "core" / "security.py"

SECRET = "agents-playbook-authz-test-secret-at-least-32-chars"
TENANT = str(uuid.uuid4())


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(role: str) -> str:
    """A first-party access token, built the way `create_access_token` builds one."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload = _b64(
        json.dumps(
            {
                "sub": str(uuid.uuid4()),
                "tenant_id": TENANT,
                "email": f"{role}@example.com",
                "role": role,
                "type": "access",
                "iat": now,
                "exp": now + 3600,
            },
            separators=(",", ":"),
        ).encode()
    )
    sig = hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


def _playbook() -> dict:
    return {
        "id": f"pb-{uuid.uuid4().hex[:8]}",
        "name": "Contain the host",
        "description": "a playbook whose only step changes the estate",
        "trigger": {"event": "alert.created"},
        "steps": [{"id": "s1", "name": "Isolate", "type": "isolate_host", "params": {"host": "finance-ws-01"}}],
        "enabled": True,
    }


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_CONSOLE_JWT_SECRET", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "production")
    app = FastAPI()
    app.include_router(playbooks_router)
    return TestClient(app)


def _as(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(role)}"}


# ── the control that stops every refusal below passing for the wrong reason ──


def test_an_anonymous_caller_is_still_refused(client: TestClient) -> None:
    anonymous = client.post("/api/v1/playbooks", json=_playbook())
    assert anonymous.status_code in (401, 403), anonymous.text


# ── a viewer may look ─────────────────────────────────────────────────────────


def test_a_viewer_cannot_author_a_playbook(client: TestClient) -> None:
    response = client.post("/api/v1/playbooks", headers=_as("viewer"), json=_playbook())
    assert response.status_code == 403, f"a viewer authored a playbook that dispatches containment: {response.status_code} {response.text}"
    assert "playbooks:write" in response.json()["detail"]


def test_a_viewer_cannot_run_a_playbook(client: TestClient) -> None:
    created = client.post("/api/v1/playbooks", headers=_as("tenant_admin"), json=_playbook())
    assert created.status_code == 201, created.text
    response = client.post(
        f"/api/v1/playbooks/{created.json()['id']}/run",
        headers=_as("viewer"),
        json={"context": {}, "dry_run": False},
    )
    assert response.status_code == 403, f"a viewer ran a playbook that dispatches containment: {response.status_code} {response.text}"
    assert "playbooks:execute" in response.json()["detail"]


def test_a_viewer_cannot_update_or_delete_one(client: TestClient) -> None:
    created = client.post("/api/v1/playbooks", headers=_as("tenant_admin"), json=_playbook())
    pb_id = created.json()["id"]
    updated = client.put(f"/api/v1/playbooks/{pb_id}", headers=_as("viewer"), json={"enabled": False})
    assert updated.status_code == 403, updated.text
    deleted = client.delete(f"/api/v1/playbooks/{pb_id}", headers=_as("viewer"))
    assert deleted.status_code == 403, deleted.text


def test_a_viewer_can_still_list_them(client: TestClient) -> None:
    """Positive control, and the reason the role exists.

    A gate that refused a viewer everything would satisfy every test above and
    make the read-only role useless -- which is pressure to hand people a
    wider one.
    """
    listed = client.get("/api/v1/playbooks", headers=_as("viewer"))
    assert listed.status_code == 200, listed.text


# ── the roles that may ────────────────────────────────────────────────────────


def test_a_tenant_admin_can_author_and_run(client: TestClient) -> None:
    """Positive control.

    A check that refused everybody would pass every negative test here and
    make the playbook surface unusable -- the fail-closed shape this
    repository has shipped before, where a control withheld every grant on
    every deployment and passed its negative test perfectly.
    """
    created = client.post("/api/v1/playbooks", headers=_as("tenant_admin"), json=_playbook())
    assert created.status_code == 201, created.text
    run = client.post(
        f"/api/v1/playbooks/{created.json()['id']}/run",
        headers=_as("tenant_admin"),
        json={"context": {}, "dry_run": True},
    )
    assert run.status_code == 202, run.text


@pytest.mark.parametrize("role", ["soc_lead", "soc_analyst"])
def test_an_analyst_may_run_but_not_author(client: TestClient, role: str) -> None:
    """The split the API already makes, now made here too.

    `soc_lead` and `soc_analyst` hold `playbooks:execute` and not
    `playbooks:write`, so they run the pack an administrator wrote and do not
    write their own.
    """
    created = client.post("/api/v1/playbooks", headers=_as("tenant_admin"), json=_playbook())
    pb_id = created.json()["id"]
    created = client.post("/api/v1/playbooks", headers=_as(role), json=_playbook())
    assert created.status_code == 403, created.text
    run = client.post(f"/api/v1/playbooks/{pb_id}/run", headers=_as(role), json={"context": {}, "dry_run": True})
    assert run.status_code == 202, run.text


# ── the mirror must not drift ────────────────────────────────────────────────


def _api_role_permissions() -> dict[str, set[str]]:
    """Parse `ROLE_PERMISSIONS` out of the API's source.

    Parsed rather than imported: both services name their top-level package
    `app`, so importing one inside the other's test process shadows it. Read
    by its own header rather than by position, because a table read by column
    index is how `project_stats.py` came to publish "0 rows" against a real
    278.
    """
    tree = ast.parse(API_SECURITY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "ROLE_PERMISSIONS" and node.value is not None:
                # `literal_eval` on the real literal, rather than a line-wise
                # scan. The first version of this was a regex over lines and
                # it silently missed every single-line entry -- including
                # `"platform_admin": ["*"]`, the one that grants everything --
                # so the pin reported a mismatch that was its own parser.
                return {role: set(perms) for role, perms in ast.literal_eval(node.value).items()}
    raise AssertionError("ROLE_PERMISSIONS is no longer a module-level literal in services/api")


def _holders(permissions: dict[str, set[str]], permission: str) -> set[str]:
    return {role for role, perms in permissions.items() if permission in perms or "*" in perms}


def test_the_role_table_matches_the_api() -> None:
    """One permission model, mirrored in two places that must agree.

    If a role gains or loses `playbooks:write` or `playbooks:execute` in the
    API and this table does not move, the console and this service disagree
    about who may run a response playbook -- which is the disagreement the
    whole finding was.
    """
    permissions = _api_role_permissions()
    assert permissions, "ROLE_PERMISSIONS could not be parsed; the pin is not measuring anything"

    assert _holders(permissions, "playbooks:write") == set(_MAY_AUTHOR), (
        "the roles holding playbooks:write in services/api no longer match _MAY_AUTHOR here"
    )
    assert _holders(permissions, "playbooks:execute") == set(_MAY_RUN), (
        "the roles holding playbooks:execute in services/api no longer match _MAY_RUN here"
    )


def test_viewer_holds_neither_in_the_api() -> None:
    """The premise of this whole suite, taken from the API rather than assumed."""
    permissions = _api_role_permissions()
    assert "viewer" in permissions, "the API no longer defines a viewer role"
    assert "playbooks:write" not in permissions["viewer"]
    assert "playbooks:execute" not in permissions["viewer"]

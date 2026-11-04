"""A playbook runs for the tenant in the credential, never the one in the body.

What was wrong (GHSA-27wx-pcv5-pr7q)
------------------------------------
``services/agents/app/api/playbooks.py`` declares its auth at the router:
``dependencies=[Depends(require_console_or_service_auth)]``. That resolves a
``TenantPrincipal`` on every request and then hands it nowhere, because no
handler declared it as a parameter. So the service knew who was asking and
never asked.

Every route underneath was unscoped in consequence, and in two distinct ways:

* **Execution took its tenant from the request body.** ``run_playbook`` passed
  ``body.context`` to the engine verbatim, and ``engine.py`` reads
  ``context.get("tenant_id")`` when it resolves ``${NAME}`` integration
  references, creates approvals and dispatches actions. Naming another
  tenant there made the platform resolve *their* vault-decrypted integration
  values — bearer headers, webhook URLs, routing keys — and write them into a
  run record the caller then read back.
* **The two stores have no tenant at all.** ``PlaybookStore`` is a
  process-global singleton keyed by playbook id and ``Playbook`` carried no
  owner field; ``_runs`` is a module-level dict. So list/get/update/delete
  reached every tenant's playbooks, and the run routes reached every tenant's
  runs.

The durable shape is the one this repository keeps finding: a router-level
``Depends`` *authenticates* and binds nothing, which reads more convincingly
as gated than an unguarded route does. The same pairing produced
GHSA-h4g5-39vv-pqfv on the connectors ``resource-config`` route.

What this asserts
-----------------
The tenant is taken from the principal and the body's copy is **deleted**
rather than validated — a caller cannot name a tenant at all, so there is no
value left to compare and get wrong. Both stores are then keyed by that
tenant, so a foreign row is not found rather than found and filtered.

Non-ownership answers **404, not 403**: a 403 on a real id and a 404 on an
invented one lets a caller enumerate which playbook and run ids exist across
every tenant, so the two answers are required to be byte-identical.

The positive controls are as load-bearing as the refusals. A route that
refuses everything passes every negative assertion while being broken, and
"stuck closed" reads as working caution — so each tenant must still run its
own playbook, and the shipped pack library must stay readable by everyone.

Why this is a unit test rather than a live one
----------------------------------------------
Nothing on this path touches a database: the playbook store is a JSON file,
the run store is a dict, and the credential is a JWT the guard verifies in
process. So the whole finding is reachable with the **real** ASGI app, the
**real** router guard and **real** signed tokens, with nothing overridden —
which means it runs on every pull request rather than only where containers
are available. ``tests/isolation/`` would gate it behind a DSN it does not
need.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

SECRET = "playbook-tenant-binding-secret-at-least-32-chars"
SERVICE_TOKEN = "playbook-tenant-binding-service-token"

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def console_token(tenant: uuid.UUID, *, role: str = "tenant_admin") -> str:
    """A verified console session for one tenant.

    `tenant_admin` rather than `soc_analyst`: this suite is about *which
    tenant* a caller may reach, and it authors playbooks to set that up.
    Authoring now needs `playbooks:write`, which an analyst does not hold
    (GHSA-8cpf-mchw-jpf2, F15) -- so an analyst here would make every case
    fail on authorization before it reached the tenant question.
    """
    """A console access token, signed the way ``services/api`` signs one.

    Minted here rather than by importing the API, because both services name
    their top-level package ``app`` and importing one shadows the other. The
    construction is byte-compatible with ``create_access_token`` and the
    *verifier* on the path is the real one, which is the half that matters:
    ``require_console_or_service_auth`` -> ``verify_console_token``.
    """
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {
        "sub": f"user-{tenant}",
        "tenant_id": str(tenant),
        "role": role,
        "type": "access",
        "exp": int(time.time()) + 600,
    }
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def auth(tenant: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {console_token(tenant)}"}


def service_auth(tenant: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {SERVICE_TOKEN}", "X-AiSOC-Tenant-ID": str(tenant)}


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Production posture, and the credential material both auth shapes need.

    ``ENVIRONMENT=test`` deliberately: ``development`` is in
    ``AUTH_BYPASS_ENVIRONMENTS`` and would resolve a demo principal inside the
    one suite whose whole subject is that the tenant comes from the credential.
    ``test`` is excluded from that set for exactly this reason.

    The store directory is redirected at a tmp path so a created playbook is
    never written into the repository's own ``data/playbooks``.
    """
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("PLAYBOOK_STORE_DIR", str(tmp_path / "playbooks"))
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    monkeypatch.delenv("AISOC_DEV_AUTH_BYPASS", raising=False)
    monkeypatch.delenv("AISOC_PLAYBOOK_HTTP_EXECUTE", raising=False)
    yield


@pytest.fixture()
def client(_env: None) -> Iterator[TestClient]:
    """The real playbooks router, with the real guard and nothing overridden."""
    from app.api import playbooks as playbooks_api
    from app.playbook.store import PlaybookStore

    # Both stores are process-global singletons, so a run or a playbook left
    # by a previous test would be visible to this one. Pinning assertions to
    # ids the test itself creates is the other half of that; this is the half
    # that keeps a listing assertion meaningful.
    PlaybookStore._instance = None
    playbooks_api._runs.clear()

    app = FastAPI()
    app.include_router(playbooks_api.router)
    with TestClient(app) as test_client:
        yield test_client

    PlaybookStore._instance = None
    playbooks_api._runs.clear()


def create_playbook(client: TestClient, tenant: uuid.UUID, name: str, steps: list[dict[str, Any]] | None = None) -> str:
    response = client.post(
        "/api/v1/playbooks",
        json={"name": name, "steps": steps or []},
        headers=auth(tenant),
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def run_playbook(
    client: TestClient,
    tenant: uuid.UUID,
    playbook_id: str,
    context: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    return client.post(
        f"/api/v1/playbooks/{playbook_id}/run",
        json={"context": context or {}, "dry_run": False},
        headers=headers if headers is not None else auth(tenant),
    )


# ---------------------------------------------------------------------------
# The reported finding
# ---------------------------------------------------------------------------


def test_a_run_executes_as_the_credentials_tenant_not_the_body(client: TestClient) -> None:
    """The reported defect, at its root: ``{"context": {"tenant_id": <victim>}}``.

    Asserted on the run's own recorded context, which is what the engine reads
    when it resolves integration references, creates approvals and dispatches
    actions — so this is the value the whole finding turns on.
    """
    playbook_id = create_playbook(client, TENANT_A, "poc")

    accepted = run_playbook(client, TENANT_A, playbook_id, {"tenant_id": str(TENANT_B)})
    assert accepted.status_code == 202, accepted.text
    run_id = accepted.json()["run_id"]

    record = client.get(f"/api/v1/playbooks/runs/{run_id}", headers=auth(TENANT_A))
    assert record.status_code == 200, record.text
    executed_as = record.json()["context"]["tenant_id"]

    assert executed_as == str(TENANT_A), f"a tenant-A caller named tenant B in the body and the run executed as {executed_as}"


def test_the_engine_resolves_integration_references_for_the_credentials_tenant(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The disclosure sink the reporter demonstrated.

    ``engine._handle_http`` calls ``references.resolve(tenant_id=...)``, which
    asks the API for that tenant's vault-decrypted integration values. The
    question this answers is *which tenant was asked for*, recorded at the real
    call site — a resolver that returns whatever it is asked for cannot be
    asked it, so the recorder returns nothing and only the argument is read.
    """
    from app.playbook import references

    asked: list[str] = []

    async def _record(*, tenant_id: str, names: list[str]) -> dict[str, Any]:
        asked.append(tenant_id)
        return {}

    monkeypatch.setattr(references, "resolve", _record)

    playbook_id = create_playbook(
        client,
        TENANT_A,
        "poc-http",
        steps=[{"name": "leak", "type": "http", "params": {"url": "${POC_LEAK}", "method": "GET"}}],
    )
    accepted = run_playbook(client, TENANT_A, playbook_id, {"tenant_id": str(TENANT_B)})
    assert accepted.status_code == 202, accepted.text

    assert asked, "the http step never resolved a reference, so this test proves nothing"
    assert asked == [str(TENANT_A)], f"the engine resolved another tenant's integration references: asked for {asked}"


def test_a_tenant_cannot_read_another_tenants_run(client: TestClient) -> None:
    """``_runs`` is a deployment-global dict and ``get_run`` filtered on nothing.

    This is how the resolved integration data reached the attacker: the run
    record carries the resolved URL, and any run was readable by anyone.
    """
    playbook_id = create_playbook(client, TENANT_B, "victim")
    accepted = run_playbook(client, TENANT_B, playbook_id)
    assert accepted.status_code == 202, accepted.text
    victim_run = accepted.json()["run_id"]

    response = client.get(f"/api/v1/playbooks/runs/{victim_run}", headers=auth(TENANT_A))

    assert response.status_code == 404, f"tenant A read tenant B's run record: {response.status_code} {response.text[:300]}"


def test_a_foreign_run_is_indistinguishable_from_one_that_does_not_exist(client: TestClient) -> None:
    """404 rather than 403, so the route stops being an existence oracle."""
    playbook_id = create_playbook(client, TENANT_B, "victim")
    victim_run = run_playbook(client, TENANT_B, playbook_id).json()["run_id"]

    foreign = client.get(f"/api/v1/playbooks/runs/{victim_run}", headers=auth(TENANT_A))
    absent = client.get(f"/api/v1/playbooks/runs/{uuid.uuid4()}", headers=auth(TENANT_A))

    assert foreign.status_code == absent.status_code == 404
    assert foreign.json() == absent.json(), f"a foreign run is distinguishable from an absent one: {foreign.json()} vs {absent.json()}"


def test_run_listing_shows_only_the_callers_own_runs(client: TestClient) -> None:
    """Strictly worse than reading one run by id: this needs no id at all."""
    a_playbook = create_playbook(client, TENANT_A, "mine")
    b_playbook = create_playbook(client, TENANT_B, "theirs")
    a_run = run_playbook(client, TENANT_A, a_playbook).json()["run_id"]
    b_run = run_playbook(client, TENANT_B, b_playbook).json()["run_id"]

    listed = client.get("/api/v1/playbooks/runs", headers=auth(TENANT_A))
    assert listed.status_code == 200, listed.text
    ids = {row["run_id"] for row in listed.json()}

    assert a_run in ids, "tenant A lost sight of its own run"
    assert b_run not in ids, "tenant A enumerated tenant B's runs with no id at all"


# ---------------------------------------------------------------------------
# The stores themselves — unreported, and a write surface as well as a read
# ---------------------------------------------------------------------------


def test_playbook_listing_shows_only_the_callers_own_playbooks(client: TestClient) -> None:
    a_playbook = create_playbook(client, TENANT_A, "mine")
    b_playbook = create_playbook(client, TENANT_B, "theirs")

    listed = client.get("/api/v1/playbooks", headers=auth(TENANT_A))
    assert listed.status_code == 200, listed.text
    ids = {row["id"] for row in listed.json()}

    assert a_playbook in ids, "tenant A lost sight of its own playbook"
    assert b_playbook not in ids, "tenant A listed tenant B's playbooks"


def test_a_tenant_cannot_read_another_tenants_playbook(client: TestClient) -> None:
    b_playbook = create_playbook(client, TENANT_B, "theirs")

    response = client.get(f"/api/v1/playbooks/{b_playbook}", headers=auth(TENANT_A))

    assert response.status_code == 404, f"tenant A read tenant B's playbook: {response.text[:300]}"


def test_a_tenant_cannot_rewrite_another_tenants_playbook(client: TestClient) -> None:
    """A write, not a read: the steps are where a playbook's automation lives.

    Editing another tenant's steps points their automation wherever the
    attacker likes, which the advisory's confidentiality framing does not
    cover.
    """
    b_playbook = create_playbook(client, TENANT_B, "theirs")

    response = client.put(
        f"/api/v1/playbooks/{b_playbook}",
        json={"name": "rewritten-by-tenant-a"},
        headers=auth(TENANT_A),
    )
    assert response.status_code == 404, f"tenant A rewrote tenant B's playbook: {response.text[:300]}"

    unchanged = client.get(f"/api/v1/playbooks/{b_playbook}", headers=auth(TENANT_B))
    assert unchanged.status_code == 200, unchanged.text
    assert unchanged.json()["name"] == "theirs", "tenant B's playbook was modified by tenant A"


def test_a_tenant_cannot_delete_another_tenants_playbook(client: TestClient) -> None:
    b_playbook = create_playbook(client, TENANT_B, "theirs")

    response = client.delete(f"/api/v1/playbooks/{b_playbook}", headers=auth(TENANT_A))
    assert response.status_code == 404, f"tenant A deleted tenant B's playbook: {response.text[:300]}"

    survivor = client.get(f"/api/v1/playbooks/{b_playbook}", headers=auth(TENANT_B))
    assert survivor.status_code == 200, "tenant B's playbook was destroyed by tenant A"


def test_a_tenant_cannot_run_another_tenants_playbook(client: TestClient) -> None:
    """Running someone else's playbook executes *their* automation on demand."""
    b_playbook = create_playbook(client, TENANT_B, "theirs")

    response = run_playbook(client, TENANT_A, b_playbook)

    assert response.status_code == 404, f"tenant A ran tenant B's playbook: {response.text[:300]}"


def test_a_service_token_cannot_name_one_tenant_and_run_as_another(client: TestClient) -> None:
    """The declared tenant must bound the run, not merely accompany it."""
    playbook_id = create_playbook(client, TENANT_A, "svc", steps=[])

    accepted = run_playbook(
        client,
        TENANT_A,
        playbook_id,
        {"tenant_id": str(TENANT_B)},
        headers=service_auth(TENANT_A),
    )
    assert accepted.status_code == 202, accepted.text
    run_id = accepted.json()["run_id"]

    record = client.get(f"/api/v1/playbooks/runs/{run_id}", headers=service_auth(TENANT_A))
    assert record.status_code == 200, record.text
    assert record.json()["context"]["tenant_id"] == str(TENANT_A)


# ---------------------------------------------------------------------------
# Positive controls — the route must still work, or "fixed" means "broken"
# ---------------------------------------------------------------------------


def test_each_tenant_still_runs_its_own_playbook(client: TestClient) -> None:
    """Stuck-closed reads as working caution, so this is the half that catches it."""
    for tenant in (TENANT_A, TENANT_B):
        playbook_id = create_playbook(client, tenant, f"own-{tenant}")

        accepted = run_playbook(client, tenant, playbook_id)
        assert accepted.status_code == 202, f"tenant {tenant} lost the ability to run its own playbook: {accepted.text[:300]}"

        record = client.get(f"/api/v1/playbooks/runs/{accepted.json()['run_id']}", headers=auth(tenant))
        assert record.status_code == 200, record.text
        assert record.json()["context"]["tenant_id"] == str(tenant)


def test_the_shipped_pack_library_stays_readable_by_every_tenant(client: TestClient) -> None:
    """Pack playbooks are shared content, like detection rules, and must not be scoped away.

    Scoping every row to its creator would make the 62 shipped packs invisible
    to everyone, which is a different outage wearing the same fix.
    """
    from app.playbook.store import PlaybookStore

    builtin = [pb for pb in PlaybookStore.default().list(tenant_id=str(TENANT_A)) if pb.tenant_id is None]
    if not builtin:
        pytest.skip("no pack playbooks are present in this checkout")

    for tenant in (TENANT_A, TENANT_B):
        listed = client.get("/api/v1/playbooks", headers=auth(tenant))
        assert listed.status_code == 200, listed.text
        ids = {row["id"] for row in listed.json()}
        assert builtin[0].id in ids, f"tenant {tenant} lost the shipped pack library"

        fetched = client.get(f"/api/v1/playbooks/{builtin[0].id}", headers=auth(tenant))
        assert fetched.status_code == 200, f"tenant {tenant} cannot read a shipped pack playbook"


def test_an_unauthenticated_caller_is_refused_before_any_lookup(client: TestClient) -> None:
    """The router-level guard still applies; this pins it from the route's side."""
    playbook_id = create_playbook(client, TENANT_A, "guarded")

    assert client.get("/api/v1/playbooks").status_code == 401
    assert client.get("/api/v1/playbooks/runs").status_code == 401
    assert client.post(f"/api/v1/playbooks/{playbook_id}/run", json={"context": {}}).status_code == 401

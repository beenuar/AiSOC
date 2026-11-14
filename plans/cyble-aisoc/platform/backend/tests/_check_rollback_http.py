"""HTTP-surface smoke test for the rollback REST API.

The service-layer test (``tests/_check_rollback.py``) covers eligibility,
audit pairing, and re-rollback rejection at the Python level. This file
covers the **HTTP boundary**: are the tenant guard, status-code mapping,
and request/response contracts on ``app.api.rollback_routes`` actually
wired the way they need to be?

Concretely we verify, against a real FastAPI ``TestClient`` and a real
HS256 JWT minted with the configured secret:

  1.  An ``anon`` request (no Authorization, no dev-anon override) is
      rejected with **401** — we never leak the rollback queue.
  2.  A tenant token for ``tenant-a`` can list ``/rollback/eligible`` and
      sees its own forward EDR isolate row.
  3.  A tenant token for ``tenant-b`` calling the same list endpoint sees
      **zero rows** for tenant-a — tenant scoping is enforced at the API.
  4.  ``GET /rollback/{id}/eligibility`` against another tenant's row
      returns **403**, not 404 with a leaky 'eligible: false' body.
  5.  ``POST /rollback/{id}`` from the rightful tenant returns **200**,
      the response contains ``rollback_of_id`` and ``reverse_tool``, and
      the forward row's ``rolled_back_at`` is stamped.
  6.  A second ``POST /rollback/{id}`` returns **409** with
      ``{code: "INELIGIBLE", reason: "...already rolled back..."}`` —
      idempotent guard, no silent re-execution.
  7.  ``POST /rollback/{id}`` from a *different* tenant for the same row
      returns **403** (and notably *not* 409, so we don't disclose
      existence to the wrong tenant).
  8.  ``POST /rollback/9_999_999`` (nonexistent id) returns **404**.

We run with ``AISOC_DEV_ALLOW_ANON_TENANT=false`` so the 401 path is real;
without that the dev fallback would mint a default-tenant context for
unauthenticated requests and case (1) would mis-pass.

Usage:

    cd platform/backend
    python -m tests._check_rollback_http
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Ephemeral DB, autonomous mode (no HITL gate on forwards), strict auth
# (no anon fallback). All three MUST be set before `app.config.settings`
# is constructed — i.e. before any `app.*` import below.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-rollback-http-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "rollback-http.db")
os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "false"
# Stable secret so a token minted here verifies against the same settings
# the API uses. Don't rely on whatever the dev default is.
os.environ["AISOC_JWT_SECRET_KEY"] = "rollback-http-test-secret-do-not-use-in-prod"
os.environ.setdefault("AISOC_ENV", "development")

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.agents.responder import ResponderAgent
from app.db import engine, init_db
from app.main import app
from app.models.case import Case, Severity
from app.models.tool_call import ToolCall
from app.security.jwt import issue_tenant_token
# Importing the tool modules triggers registration so the rollback
# service can resolve `edr.isolate_host` → `edr.release_host`.
from app.tools import edr as _edr  # noqa: F401
from app.tools import email_tool as _email  # noqa: F401
from app.tools import idp as _idp  # noqa: F401
from fastapi.testclient import TestClient
from sqlmodel import Session, select


TENANT_A = "tenant-a"
TENANT_B = "tenant-b"


def _mint(tenant_id: str, subject: str = "analyst@cyble.test") -> str:
    return issue_tenant_token(
        tenant_id=tenant_id,
        subject=subject,
        roles=["analyst"],
    )


def _auth_headers(tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_mint(tenant_id)}"}


async def _seed_forward_action(tenant_id: str) -> tuple[int, int]:
    """Create a case and a successful WRITE-REVERSIBLE forward call.

    Returns ``(case_id, tool_call_id)`` so the HTTP-level checks have a
    real row to operate on without going through the orchestrator.
    """
    with Session(engine) as db:
        case = Case(
            tenant_id=tenant_id,
            title=f"rollback-http test for {tenant_id}",
            severity=Severity.HIGH,
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        assert case.id is not None
        case_id = case.id

        responder = ResponderAgent(db=db, case_id=case_id, tenant_id=tenant_id)
        await responder.call_tool(
            "edr.isolate_host",
            {"host": f"host-of-{tenant_id}", "reason": "smoke"},
            rationale="seed forward action for HTTP smoke",
        )
        tc = db.exec(
            select(ToolCall)
            .where(ToolCall.case_id == case_id)
            .where(ToolCall.tool_name == "edr.isolate_host")
            .order_by(ToolCall.id.desc())  # type: ignore[attr-defined]
        ).first()
        assert tc is not None and tc.id is not None
        return case_id, tc.id


def _check_unauth_returns_401(client: TestClient) -> None:
    """No auth header → 401, never a default-tenant fallthrough."""
    r = client.get("/rollback/eligible")
    assert r.status_code == 401, (r.status_code, r.text)
    # WWW-Authenticate hint is part of the contract for browser clients.
    assert "www-authenticate" in {k.lower() for k in r.headers.keys()}
    print("OK  unauth GET /rollback/eligible → 401 with WWW-Authenticate")


def _check_list_is_tenant_scoped(
    client: TestClient, tc_id_a: int, case_id_a: int
) -> None:
    """Tenant-A sees its own forward row; Tenant-B sees zero of A's rows."""
    # Tenant-A: should see its own row.
    r_a = client.get(
        "/rollback/eligible",
        params={"include_ineligible": "false"},
        headers=_auth_headers(TENANT_A),
    )
    assert r_a.status_code == 200, (r_a.status_code, r_a.text)
    rows_a = r_a.json()
    ids_a = {row["id"] for row in rows_a}
    assert tc_id_a in ids_a, (tc_id_a, ids_a)
    matching = next(row for row in rows_a if row["id"] == tc_id_a)
    assert matching["tenant_id"] == TENANT_A
    assert matching["case_id"] == case_id_a
    assert matching["tool_name"] == "edr.isolate_host"
    assert matching["eligible"] is True
    assert matching["reverse_tool"] == "edr.release_host"
    # Reverse-params preview must mirror the forward host so the operator
    # confirmation modal shows the right value.
    assert matching["reverse_params_preview"].get("host") == f"host-of-{TENANT_A}"
    # We deliberately omit ``result`` from the list payload (PII-ish);
    # confirm the route honors that contract.
    assert "result" not in matching, "list view must not expose tool result blob"
    print(
        "OK  tenant-A GET /rollback/eligible shows own forward row "
        f"(id={tc_id_a}) with reverse_params_preview"
    )

    # Tenant-B: must NOT see any tenant-A rows.
    r_b = client.get(
        "/rollback/eligible",
        params={"include_ineligible": "true"},
        headers=_auth_headers(TENANT_B),
    )
    assert r_b.status_code == 200, (r_b.status_code, r_b.text)
    rows_b = r_b.json()
    assert all(row["tenant_id"] == TENANT_B for row in rows_b), (
        f"tenant-B list leaked rows from {set(r['tenant_id'] for r in rows_b)}"
    )
    assert tc_id_a not in {row["id"] for row in rows_b}, (
        f"tenant-A row {tc_id_a} leaked into tenant-B list"
    )
    print("OK  tenant-B GET /rollback/eligible cannot see tenant-A rows")


def _check_eligibility_cross_tenant_403(
    client: TestClient, tc_id_a: int
) -> None:
    """Reading another tenant's eligibility verdict → 403."""
    r = client.get(
        f"/rollback/{tc_id_a}/eligibility",
        headers=_auth_headers(TENANT_B),
    )
    assert r.status_code == 403, (r.status_code, r.text)
    print(
        f"OK  tenant-B GET /rollback/{tc_id_a}/eligibility → 403 "
        "(no cross-tenant existence disclosure)"
    )


def _check_post_rollback_happy_path(
    client: TestClient, tc_id_a: int
) -> None:
    """Tenant-A POSTs the rollback → 200 + paired audit row."""
    r = client.post(
        f"/rollback/{tc_id_a}",
        headers=_auth_headers(TENANT_A),
        json={
            "actor": "user:alice@cyble.com",
            "rationale": "false positive on isolate",
        },
    )
    assert r.status_code == 200, (r.status_code, r.text)
    body = r.json()
    assert body["rollback_of_id"] == tc_id_a, body
    assert body["reverse_tool"] == "edr.release_host", body
    assert body["result"].get("isolated") is False, body["result"]
    assert body.get("rolled_back_at"), body
    assert "user:alice@cyble.com" in (body.get("rolled_back_by") or ""), body
    print(f"OK  tenant-A POST /rollback/{tc_id_a} → 200 with paired reverse result")

    # Forward row should now carry the audit stamps in the DB itself.
    with Session(engine) as db:
        forward = db.get(ToolCall, tc_id_a)
        assert forward is not None
        assert forward.rolled_back_at is not None
        assert forward.rolled_back_by and "user:alice@cyble.com" in forward.rolled_back_by

        reverse = db.exec(
            select(ToolCall).where(ToolCall.rollback_of_id == tc_id_a)
        ).first()
        assert reverse is not None
        assert reverse.tenant_id == TENANT_A
        assert reverse.tool_name == "edr.release_host"
    print("OK  DB-level audit pair persisted from HTTP path")


def _check_repeat_rollback_returns_409(
    client: TestClient, tc_id_a: int
) -> None:
    """Second rollback of the same forward row → 409 INELIGIBLE."""
    r = client.post(
        f"/rollback/{tc_id_a}",
        headers=_auth_headers(TENANT_A),
        json={"actor": "user:alice@cyble.com", "rationale": "retry"},
    )
    assert r.status_code == 409, (r.status_code, r.text)
    detail = r.json().get("detail") or {}
    # FastAPI may surface the detail dict directly or under .detail; handle both.
    if isinstance(detail, dict):
        assert detail.get("code") == "INELIGIBLE", detail
        assert "already rolled back" in detail.get("reason", ""), detail
    else:
        assert "already rolled back" in str(detail)
    print(
        f"OK  repeat POST /rollback/{tc_id_a} → 409 INELIGIBLE "
        "(idempotent guard intact)"
    )


def _check_cross_tenant_post_403(
    client: TestClient, tc_id_a: int
) -> None:
    """Tenant-B trying to undo tenant-A's action → 403, not 409.

    The distinction matters: 409 would tell tenant-B that some row with
    that id exists in another tenant. 403 is the correct existence-
    preserving response.
    """
    # Make a *fresh* forward row for tenant-A that has NOT been rolled
    # back yet, so any cross-tenant 409 leak would be unambiguous (vs the
    # already-rolled-back row above where a 409 would be the same answer
    # tenant-A would see).
    async def _seed():
        return await _seed_forward_action(TENANT_A)

    _case_id, fresh_tc_id = asyncio.run(_seed())

    r = client.post(
        f"/rollback/{fresh_tc_id}",
        headers=_auth_headers(TENANT_B),
        json={"actor": "user:mallory@evil.test", "rationale": "should fail"},
    )
    assert r.status_code == 403, (r.status_code, r.text)
    print(
        f"OK  tenant-B POST /rollback/{fresh_tc_id} → 403 "
        "(no cross-tenant undo, no 409 existence leak)"
    )

    # And confirm the forward row was NOT mutated by that rejected call.
    with Session(engine) as db:
        forward = db.get(ToolCall, fresh_tc_id)
        assert forward is not None
        assert forward.rolled_back_at is None, (
            "forward row should not have been touched by cross-tenant POST"
        )
        reverse = db.exec(
            select(ToolCall).where(ToolCall.rollback_of_id == fresh_tc_id)
        ).first()
        assert reverse is None, "no reverse row should have been created"
    print("OK  rejected cross-tenant POST left no side-effects in DB")


def _check_missing_id_returns_404(client: TestClient) -> None:
    """Nonexistent tool_call_id → 404, not 500."""
    r = client.post(
        "/rollback/999999999",
        headers=_auth_headers(TENANT_A),
        json={"actor": "user:alice@cyble.com"},
    )
    assert r.status_code == 404, (r.status_code, r.text)
    print("OK  POST /rollback/<unknown-id> → 404")


def main() -> None:
    init_db()
    # Seed one forward action under tenant-A; the rest of the checks key
    # off this id.
    case_id_a, tc_id_a = asyncio.run(_seed_forward_action(TENANT_A))
    print(f"seeded tenant-A forward edr.isolate_host as tool_call={tc_id_a}")

    with TestClient(app) as client:
        _check_unauth_returns_401(client)
        _check_list_is_tenant_scoped(client, tc_id_a, case_id_a)
        _check_eligibility_cross_tenant_403(client, tc_id_a)
        _check_post_rollback_happy_path(client, tc_id_a)
        _check_repeat_rollback_returns_409(client, tc_id_a)
        _check_cross_tenant_post_403(client, tc_id_a)
        _check_missing_id_returns_404(client)

    print("\nALL ROLLBACK HTTP CHECKS PASSED")


if __name__ == "__main__":
    main()

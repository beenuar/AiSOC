"""Smoke test for tenant enforcement across REST endpoints.

Validates:
1. The default-tenant anonymous bootstrap still works (dev mode).
2. Listing `/cases` honors `viewable_tenant_ids()` (single-tenant token
   sees only its rows; admin token sees all three demo tenants).
3. Single-row reads (`/cases/{id}`) raise 403 when the caller can't
   view the row's tenant.
4. The `/alerts` ingestion path stamps `tenant_id` from the caller's
   context onto both `Alert` and `Case`.
5. MSSP parent tenants can pivot into allowed child tenants via
   `X-AISOC-Tenant` and are blocked from pivoting elsewhere.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Boot in dev mode so we don't have to mint a token for every assertion;
# we mint tokens explicitly when testing the secured paths.
os.environ.setdefault("AISOC_DEV_ALLOW_ANON_TENANT", "true")
os.environ.setdefault("AISOC_SEED_ON_STARTUP", "true")
os.environ.setdefault("AISOC_LLM_PROVIDER", "mock")
# The smoke test exercises REST/tenancy plumbing; the agent loop only matters
# insofar as ingestion stamps tenant_id correctly. Run the mesh in
# `autonomous` mode so the Responder's destructive tool calls don't stall on
# the 15-minute HITL SLA, and shrink the SLA itself as a belt-and-braces
# guard against any HITL request that still fires.
os.environ.setdefault("AISOC_AUTONOMY_LEVEL", "autonomous")
os.environ.setdefault("AISOC_HITL_SLA_SECONDS", "2")

# Make `app` importable when running this script directly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collections import Counter

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.security.jwt import encode_token


def _token(
    tenant_id: str,
    *,
    subject: str = "test-user",
    roles: tuple[str, ...] = ("analyst",),
    is_mssp: bool = False,
    mssp_parent_tid: str | None = None,
    allowed_tenants: tuple[str, ...] = (),
) -> str:
    """Mint a JWT for testing. Mirrors the production token shape."""
    payload: dict = {
        "sub": subject,
        "tid": tenant_id,
        "roles": list(roles),
    }
    if is_mssp:
        payload["mssp"] = True
        if mssp_parent_tid:
            payload["mssp_parent_tid"] = mssp_parent_tid
        if allowed_tenants:
            payload["allowed_tenants"] = list(allowed_tenants)
    return encode_token(payload)


def main() -> int:
    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        marker = "OK" if ok else "FAIL"
        print(f"  [{marker}] {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(label)

    print("== Smoke: tenant enforcement ==")
    # Use TestClient as a context manager so the FastAPI `lifespan` hook fires
    # and `init_db() + seed_if_empty()` actually run before the first request.
    with TestClient(app) as client:
        _run_checks(client, check)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


def _run_checks(client, check) -> None:
    # ── 1. Anon dev-mode lists default tenant only ───────────────────────
    print("\n[1] Anonymous dev-mode /cases")
    r = client.get("/cases?limit=100")
    check("anon /cases returns 200", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        rows = r.json()
        tenants_seen = Counter(row["tenant_id"] for row in rows)
        check(
            "anon /cases only sees default tenant",
            set(tenants_seen) == {settings.default_tenant},
            f"saw={dict(tenants_seen)}",
        )

    # ── 2. Single-tenant JWT only sees own rows ──────────────────────────
    print("\n[2] Single-tenant JWT (demo-tenant-acme)")
    acme_token = _token("demo-tenant-acme")
    r = client.get(
        "/cases?limit=100",
        headers={"Authorization": f"Bearer {acme_token}"},
    )
    check("acme /cases returns 200", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        rows = r.json()
        tenants_seen = Counter(row["tenant_id"] for row in rows)
        check(
            "acme /cases isolated to demo-tenant-acme",
            set(tenants_seen) == {"demo-tenant-acme"},
            f"saw={dict(tenants_seen)}",
        )

    # ── 3. Cross-tenant single-row read is forbidden ─────────────────────
    print("\n[3] Cross-tenant single-row read")
    # Find a case belonging to demo-tenant-globex from the admin view first.
    admin_token = _token(
        settings.default_tenant,
        subject="platform-admin",
        roles=("admin",),
    )
    r = client.get(
        "/cases?limit=100",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    check("admin /cases returns 200", r.status_code == 200, f"status={r.status_code}")
    globex_case_id: int | None = None
    if r.status_code == 200:
        rows = r.json()
        admin_tenants_seen = Counter(row["tenant_id"] for row in rows)
        check(
            "admin /cases spans all demo tenants",
            len(admin_tenants_seen) >= 3,
            f"saw={dict(admin_tenants_seen)}",
        )
        for row in rows:
            if row["tenant_id"] == "demo-tenant-globex":
                globex_case_id = row["id"]
                break

    if globex_case_id is not None:
        # Acme caller asking for a globex case → 403.
        r = client.get(
            f"/cases/{globex_case_id}",
            headers={"Authorization": f"Bearer {acme_token}"},
        )
        check(
            "acme cannot read globex case",
            r.status_code == 403,
            f"status={r.status_code}",
        )
        # Admin can.
        r = client.get(
            f"/cases/{globex_case_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        check(
            "admin can read globex case",
            r.status_code == 200,
            f"status={r.status_code}",
        )
    else:
        check("found a globex case to probe", False, "no globex cases in seed")

    # ── 4. /alerts ingestion stamps tenant_id ────────────────────────────
    print("\n[4] /alerts ingestion stamps caller's tenant_id")
    r = client.post(
        "/alerts",
        headers={"Authorization": f"Bearer {acme_token}"},
        json={
            "external_id": "smoke-001",
            "source": "smoke-test",
            "title": "smoke: suspicious login from acme",
            "description": "smoke-test ingestion",
            "severity": "medium",
            "mitre_techniques": ["T1078"],
        },
    )
    check("acme ingestion accepted", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        body = r.json()
        check(
            "ingestion echoes tenant_id=demo-tenant-acme",
            body.get("tenant_id") == "demo-tenant-acme",
            f"body={body}",
        )
        case_id = body.get("case_id")
        # Globex caller must NOT be able to read this case.
        globex_token = _token("demo-tenant-globex")
        r2 = client.get(
            f"/cases/{case_id}",
            headers={"Authorization": f"Bearer {globex_token}"},
        )
        check(
            "globex cannot read acme's freshly-ingested case",
            r2.status_code == 403,
            f"status={r2.status_code}",
        )

    # ── 5. MSSP pivot semantics ──────────────────────────────────────────
    print("\n[5] MSSP pivot")
    mssp_parent = settings.demo_mssp_tenant
    mssp_children = list(settings.demo_mssp_children)
    if not mssp_children:
        check("MSSP fixture configured", False, "no demo_mssp_children")
    else:
        child_ok = mssp_children[0]
        # The MSSP analyst's "home" tenant is the MSSP itself; the parent
        # claim is the same MSSP. Children listed in `allowed_tenants` are
        # the pivot targets.
        mssp_token = _token(
            mssp_parent,
            subject="mssp-analyst",
            is_mssp=True,
            mssp_parent_tid=mssp_parent,
            allowed_tenants=tuple(mssp_children),
        )
        # Pivot into allowed child should succeed.
        r = client.get(
            "/cases?limit=100",
            headers={
                "Authorization": f"Bearer {mssp_token}",
                "X-AISOC-Tenant": child_ok,
            },
        )
        check(
            f"MSSP pivot into allowed child {child_ok} returns 200",
            r.status_code == 200,
            f"status={r.status_code}",
        )
        # Pivot into a tenant outside the allowed list → 403.
        # Pick a tenant we know is not in the MSSP child list.
        candidates = [
            "demo-tenant-acme",
            "demo-tenant-globex",
            settings.default_tenant,
        ]
        stranger = next(
            (t for t in candidates if t not in mssp_children and t != mssp_parent),
            None,
        )
        if stranger is None:
            check("MSSP stranger pivot test setup", False, "no stranger tenant found")
        else:
            r = client.get(
                "/cases?limit=100",
                headers={
                    "Authorization": f"Bearer {mssp_token}",
                    "X-AISOC-Tenant": stranger,
                },
            )
            check(
                f"MSSP pivot to non-allowed {stranger} → 403",
                r.status_code == 403,
                f"status={r.status_code}",
            )

    # ── 6. Bogus token → 401 ─────────────────────────────────────────────
    print("\n[6] Bogus token")
    r = client.get(
        "/cases?limit=100",
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    check("bogus bearer → 401", r.status_code == 401, f"status={r.status_code}")


if __name__ == "__main__":
    raise SystemExit(main())

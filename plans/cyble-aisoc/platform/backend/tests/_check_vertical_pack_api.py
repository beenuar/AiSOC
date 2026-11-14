"""Smoke check for the vertical pack REST API (t3d-api).

End-to-end test that drives ``platform/backend/app/api/vertical_pack_routes.py``
through :class:`fastapi.testclient.TestClient` so we cover the
real wiring — auth dependency, route registration, response shaping,
and service-layer side effects — not just isolated unit logic.

Coverage:

1. **Catalog** — ``GET /detections/packs`` and ``GET /detections/packs/{pack}``
   return the on-disk catalog. Includes the routing-order regression:
   the literal paths ``/assignments``, ``/calibrations`` and
   ``/effective`` MUST resolve before the greedy ``/{pack}`` parameter
   defined at the bottom of the routes file.

2. **Assignments** — idempotent ``POST`` and ``DELETE`` semantics on
   ``(tenant_id, pack)``. ``assigned_by`` reflects the caller's JWT
   subject, not a static value.

3. **Calibrations** — upsert/get/list/delete with severity override
   and disable. ``GET`` returns 404 before any override exists; that
   404 is a UX signal, not an error.

4. **Effective engine introspection** — confirms that mutations through
   the API are immediately reflected by ``GET /detections/packs/effective``.
   This is the cache-invalidation contract.

5. **Tenant isolation** — tenant A's assignments and calibrations
   do NOT leak into tenant B's effective view.

6. **Auth** — bogus token gives 401; anonymous dev mode binds the
   caller to ``default_tenant``.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_vertical_pack_api.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB BEFORE importing app code.

    The seed routine in app.main builds demo cases against whatever DB
    is configured. We disable seeding here because this test only
    needs the catalog reconciliation step — anything else would
    spam the DB with unrelated rows and slow the smoke test.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-vp-api-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ.setdefault("AISOC_DEV_ALLOW_ANON_TENANT", "true")
    # Keep the autonomous agent mesh quiet so ingestion side effects
    # don't race with the test's TestClient assertions.
    os.environ.setdefault("AISOC_AUTONOMY_LEVEL", "autonomous")
    os.environ.setdefault("AISOC_HITL_SLA_SECONDS", "2")
    return db_path


DB_PATH = _bootstrap_env()
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.security.jwt import encode_token  # noqa: E402


# Test tenants are deliberately namespaced so they don't collide with
# anything the demo seed might create.
TENANT_ALPHA = "tenant-vpapi-alpha"
TENANT_BETA = "tenant-vpapi-beta"


def _token(tenant_id: str, *, subject: str = "vpapi-analyst") -> str:
    """Mint an HS256 JWT for the given tenant. Mirrors prod token shape."""
    return encode_token(
        {
            "sub": subject,
            "tid": tenant_id,
            "roles": ["analyst"],
        }
    )


def _auth(tenant_id: str, *, subject: str = "vpapi-analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(tenant_id, subject=subject)}"}


def main() -> int:
    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        marker = "OK" if ok else "FAIL"
        print(f"  [{marker}] {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(label)

    print(f"== Smoke: vertical pack REST API (DB={DB_PATH}) ==")

    # Context manager so the FastAPI ``lifespan`` hook runs init_db()
    # and the registry reconciliation step. Without this, the catalog
    # would be empty and every assertion below would fail.
    with TestClient(app) as client:
        _run(client, check)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


def _run(client: TestClient, check) -> None:
    # ── 1. Catalog ───────────────────────────────────────────────────────
    print("\n[1] Catalog: GET /detections/packs")
    r = client.get("/detections/packs", headers=_auth(TENANT_ALPHA))
    check(
        "catalog list returns 200",
        r.status_code == 200,
        f"status={r.status_code} body={r.text[:200]}",
    )
    if r.status_code != 200:
        return  # nothing else makes sense if the catalog is broken
    catalog = r.json()["packs"]
    slugs = {p["slug"] for p in catalog}
    expected = {"finserv", "healthcare", "retail", "manufacturing", "public_sector"}
    check(
        "catalog contains all 5 vertical packs",
        expected.issubset(slugs),
        f"missing={expected - slugs}",
    )

    # Capture finserv's numeric id and rule list for later assertions.
    finserv_row = next((p for p in catalog if p["slug"] == "finserv"), None)
    check("finserv row present in catalog", finserv_row is not None)
    assert finserv_row is not None  # mypy hint; check() already recorded
    finserv_id = finserv_row["id"]

    # Detail endpoint — by slug AND by numeric id. This exercises the
    # ``GET /{pack}`` route that lives at the bottom of the routes file.
    r = client.get("/detections/packs/finserv", headers=_auth(TENANT_ALPHA))
    check(
        "GET /detections/packs/finserv returns 200",
        r.status_code == 200,
        f"status={r.status_code}",
    )
    finserv_rule_ids: list[str] = []
    if r.status_code == 200:
        body = r.json()
        check(
            "finserv detail exposes a non-empty rule list",
            isinstance(body.get("rules"), list) and len(body["rules"]) > 0,
            f"rule_count={body.get('rule_count')}",
        )
        finserv_rule_ids = [rl["id"] for rl in body["rules"]]

    r = client.get(f"/detections/packs/{finserv_id}", headers=_auth(TENANT_ALPHA))
    check(
        "GET /detections/packs/{id} (numeric) returns 200",
        r.status_code == 200,
        f"status={r.status_code}",
    )

    r = client.get("/detections/packs/nonexistent", headers=_auth(TENANT_ALPHA))
    check(
        "GET /detections/packs/{unknown} returns 404",
        r.status_code == 404,
        f"status={r.status_code}",
    )

    # Routing-order regression: a literal path defined AFTER ``/{pack}``
    # in source order would be shadowed. Verify ``/effective`` resolves
    # to the effective-engine endpoint, not the pack-detail handler
    # treating "effective" as an unknown slug → 404.
    r = client.get("/detections/packs/effective", headers=_auth(TENANT_ALPHA))
    check(
        "/effective is NOT shadowed by /{pack}",
        r.status_code == 200,
        f"status={r.status_code} body={r.text[:120]}",
    )

    # ── 2. Effective engine — baseline (no assignment) ───────────────────
    print("\n[2] Effective engine — baseline")
    r = client.get("/detections/packs/effective", headers=_auth(TENANT_ALPHA))
    check(
        "alpha /effective returns 200",
        r.status_code == 200,
        f"status={r.status_code}",
    )
    baseline_count = r.json().get("rule_count", 0) if r.status_code == 200 else 0
    check(
        "baseline rule_count > 0 (builtin pack non-empty)",
        baseline_count > 0,
        f"rule_count={baseline_count}",
    )

    # ── 3. Assignments — POST/GET/DELETE idempotency ─────────────────────
    print("\n[3] Assignments lifecycle")
    r = client.get("/detections/packs/assignments", headers=_auth(TENANT_ALPHA))
    check(
        "alpha starts with zero assignments",
        r.status_code == 200 and r.json().get("assignments") == [],
        f"status={r.status_code} body={r.text[:200]}",
    )

    r = client.post(
        "/detections/packs/assignments",
        headers=_auth(TENANT_ALPHA, subject="alice-admin"),
        json={"pack": "finserv", "enabled": True, "notes": "smoke-test"},
    )
    check(
        "POST assignment for finserv returns 201",
        r.status_code == 201,
        f"status={r.status_code} body={r.text[:200]}",
    )
    first_assignment_id: int | None = None
    if r.status_code == 201:
        body = r.json()
        first_assignment_id = body.get("id")
        check(
            "assignment carries pack_slug=finserv",
            body.get("pack_slug") == "finserv",
            f"body={body}",
        )
        check(
            "assigned_by reflects token subject (not 'system')",
            body.get("assigned_by") == "alice-admin",
            f"assigned_by={body.get('assigned_by')!r}",
        )

    # Idempotent re-post: same (tenant_id, pack) MUST upsert in place,
    # not create a duplicate row.
    r = client.post(
        "/detections/packs/assignments",
        headers=_auth(TENANT_ALPHA, subject="bob-admin"),
        json={"pack": "finserv", "enabled": True, "notes": "smoke-test (repeat)"},
    )
    check(
        "repeat POST upserts in place (still 201)",
        r.status_code == 201,
        f"status={r.status_code}",
    )
    if r.status_code == 201 and first_assignment_id is not None:
        check(
            "repeat POST keeps the same row id",
            r.json().get("id") == first_assignment_id,
            f"first={first_assignment_id} now={r.json().get('id')}",
        )

    # 404 on unknown pack slug.
    r = client.post(
        "/detections/packs/assignments",
        headers=_auth(TENANT_ALPHA),
        json={"pack": "nope-not-a-pack", "enabled": True},
    )
    check(
        "POST unknown pack returns 404",
        r.status_code == 404,
        f"status={r.status_code}",
    )

    # List shows exactly one row.
    r = client.get("/detections/packs/assignments", headers=_auth(TENANT_ALPHA))
    check(
        "list assignments shows 1 row",
        r.status_code == 200 and len(r.json().get("assignments", [])) == 1,
        f"body={r.text[:200]}",
    )

    # ── 4. Effective engine — with assignment ────────────────────────────
    print("\n[4] Effective engine grows after assignment")
    r = client.get("/detections/packs/effective", headers=_auth(TENANT_ALPHA))
    assigned_count = r.json().get("rule_count", 0) if r.status_code == 200 else 0
    check(
        "alpha /effective rule_count grew after finserv assignment",
        assigned_count > baseline_count,
        f"baseline={baseline_count} assigned={assigned_count} "
        f"(delta={assigned_count - baseline_count})",
    )

    # ── 5. Tenant isolation: beta must NOT see alpha's assignment ────────
    print("\n[5] Tenant isolation")
    r = client.get("/detections/packs/assignments", headers=_auth(TENANT_BETA))
    check(
        "beta has zero assignments (isolated from alpha)",
        r.status_code == 200 and r.json().get("assignments") == [],
        f"body={r.text[:200]}",
    )
    r = client.get("/detections/packs/effective", headers=_auth(TENANT_BETA))
    beta_count = r.json().get("rule_count", -1) if r.status_code == 200 else -1
    check(
        "beta /effective stays at baseline (no leakage from alpha)",
        beta_count == baseline_count,
        f"baseline={baseline_count} beta={beta_count}",
    )

    # ── 6. Calibrations: disable one rule → effective shrinks by 1 ───────
    print("\n[6] Calibration round-trip")
    if not finserv_rule_ids:
        check("had a finserv rule id to calibrate", False, "rules list was empty")
    else:
        target_rule = finserv_rule_ids[0]

        # No override yet → 404 with a friendly detail message.
        r = client.get(
            f"/detections/packs/calibrations/{target_rule}",
            headers=_auth(TENANT_ALPHA),
        )
        check(
            "GET calibration before upsert returns 404",
            r.status_code == 404,
            f"status={r.status_code}",
        )

        # PUT disable + severity override.
        r = client.put(
            f"/detections/packs/calibrations/{target_rule}",
            headers=_auth(TENANT_ALPHA),
            json={
                "pack": "finserv",
                "enabled": False,
                "severity_override": "critical",
                "baseline": {"threshold": 5},
                "notes": "smoke test",
            },
        )
        check(
            "PUT calibration returns 200",
            r.status_code == 200,
            f"status={r.status_code} body={r.text[:200]}",
        )
        if r.status_code == 200:
            body = r.json()
            check(
                "calibration body reflects payload",
                body.get("enabled") is False
                and body.get("severity_override") == "critical"
                and body.get("baseline") == {"threshold": 5},
                f"body={body}",
            )

        # Idempotent repeat — same payload, no duplicate row.
        r = client.put(
            f"/detections/packs/calibrations/{target_rule}",
            headers=_auth(TENANT_ALPHA),
            json={
                "pack": "finserv",
                "enabled": False,
                "severity_override": "critical",
                "baseline": {"threshold": 5},
            },
        )
        check(
            "PUT calibration is idempotent",
            r.status_code == 200,
            f"status={r.status_code}",
        )

        # GET single + list.
        r = client.get(
            f"/detections/packs/calibrations/{target_rule}",
            headers=_auth(TENANT_ALPHA),
        )
        check(
            "GET single calibration returns 200 after upsert",
            r.status_code == 200,
            f"status={r.status_code}",
        )
        r = client.get(
            "/detections/packs/calibrations?pack=finserv",
            headers=_auth(TENANT_ALPHA),
        )
        check(
            "list calibrations filtered by pack returns 1 row",
            r.status_code == 200 and len(r.json().get("calibrations", [])) == 1,
            f"body={r.text[:200]}",
        )

        # /effective should shrink by 1 because the calibration disabled
        # a rule. This is the cache-invalidation contract: PUT mutated
        # the calibration store and the engine must reflect it on the
        # next read.
        r = client.get("/detections/packs/effective", headers=_auth(TENANT_ALPHA))
        after_disable = r.json().get("rule_count", -1) if r.status_code == 200 else -1
        check(
            "disabling a rule via calibration shrinks effective rule_count by 1",
            after_disable == assigned_count - 1,
            f"assigned={assigned_count} after_disable={after_disable}",
        )

        # DELETE → effective bounces back to assigned_count.
        r = client.delete(
            f"/detections/packs/calibrations/{target_rule}",
            headers=_auth(TENANT_ALPHA),
        )
        check(
            "DELETE calibration returns 204",
            r.status_code == 204,
            f"status={r.status_code}",
        )
        # Double-delete is idempotent (204 even when nothing to remove).
        r = client.delete(
            f"/detections/packs/calibrations/{target_rule}",
            headers=_auth(TENANT_ALPHA),
        )
        check(
            "DELETE calibration is idempotent (204 again)",
            r.status_code == 204,
            f"status={r.status_code}",
        )
        r = client.get("/detections/packs/effective", headers=_auth(TENANT_ALPHA))
        restored = r.json().get("rule_count", -1) if r.status_code == 200 else -1
        check(
            "removing the calibration restores the assigned rule_count",
            restored == assigned_count,
            f"assigned={assigned_count} restored={restored}",
        )

    # ── 7. Assignment teardown ───────────────────────────────────────────
    print("\n[7] Assignment teardown")
    r = client.delete(
        "/detections/packs/assignments/finserv", headers=_auth(TENANT_ALPHA)
    )
    check(
        "DELETE assignment returns 204",
        r.status_code == 204,
        f"status={r.status_code}",
    )
    r = client.delete(
        "/detections/packs/assignments/finserv", headers=_auth(TENANT_ALPHA)
    )
    check(
        "DELETE assignment is idempotent",
        r.status_code == 204,
        f"status={r.status_code}",
    )
    # Effective collapses to baseline again.
    r = client.get("/detections/packs/effective", headers=_auth(TENANT_ALPHA))
    after_unassign = r.json().get("rule_count", -1) if r.status_code == 200 else -1
    check(
        "after unassign, /effective drops back to baseline",
        after_unassign == baseline_count,
        f"baseline={baseline_count} after_unassign={after_unassign}",
    )

    # ── 8. Auth boundaries ───────────────────────────────────────────────
    print("\n[8] Auth boundaries")
    r = client.get(
        "/detections/packs", headers={"Authorization": "Bearer not-a-token"}
    )
    check("bogus token → 401", r.status_code == 401, f"status={r.status_code}")

    # Anonymous dev mode binds to default_tenant — useful smoke that the
    # require_tenant dependency still ships in friendly default mode.
    r = client.get("/detections/packs")
    check(
        "anonymous dev mode list returns 200",
        r.status_code == 200,
        f"status={r.status_code}",
    )
    r = client.get("/detections/packs/assignments")
    check(
        "anonymous dev mode assignments returns 200",
        r.status_code == 200,
        f"status={r.status_code} body={r.text[:200]}",
    )
    if r.status_code == 200:
        # default_tenant should look bare (we never assigned to it).
        check(
            "default_tenant has zero assignments",
            r.json().get("tenant_id") == settings.default_tenant
            and r.json().get("assignments") == [],
            f"body={r.text[:200]}",
        )


if __name__ == "__main__":
    raise SystemExit(main())

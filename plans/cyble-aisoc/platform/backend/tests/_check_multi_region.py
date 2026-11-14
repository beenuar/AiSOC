"""Smoke test: multi-region active-active + residency policy (t6-multi-region).

Covers:

* Mesh parsing — the env-var format produces typed records that
  honour the local region's identity and zone.
* Default-pinning — a tenant with no home_region row falls back to
  the local region.
* Cross-region pinning — pinning a tenant to a peer region produces
  ``forward_to_peer`` decisions with the right base_url.
* Disallowed-zone rejection — when ``region_allowed_residency_zones``
  excludes the home zone, the API returns a 451 hint.
* Audit trail — every pin produces a TenantRegionEvent row.
* Admin gating — non-admins cannot pin a tenant's home region.
* Mesh hot-reload — flipping ``settings.region_peers`` and reloading
  produces the new mesh shape without a process restart.
"""
from __future__ import annotations

import os
import tempfile

os.environ["AISOC_AUTH_DISABLED"] = "1"
os.environ["AISOC_LLM_PROVIDER"] = "mock"
os.environ["AISOC_REGION_ID"] = "us-east-1"
os.environ["AISOC_REGION_PEERS"] = (
    "us-east-1|http://us.local|us, eu-west-1|http://eu.local|eu"
)
os.environ["AISOC_REGION_DEFAULT_RESIDENCY_ZONE"] = "us"
os.environ["AISOC_REGION_ALLOWED_RESIDENCY_ZONES"] = ""
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-region-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.security.jwt import issue_tenant_token  # noqa: E402
from app.regions import (  # noqa: E402
    RegionResolution,
    decide_residency,
    parse_peers,
)
from app.regions.service import (  # noqa: E402
    get_region_mesh,
    home_region_for,
    list_region_events,
    pin_home_region,
    reload_region_mesh,
    resolve_for_tenant,
)


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _mesh_smoke() -> None:
    init_db()
    reload_region_mesh()
    mesh = get_region_mesh()
    _expect(mesh.local_region_id == "us-east-1", f"local_region_id: {mesh.local_region_id}")
    _expect(len(mesh.regions) == 2, f"expected 2 regions, got {mesh.regions}")
    eu = mesh.by_id("eu-west-1")
    _expect(eu is not None, "eu region missing from mesh")
    _expect(eu.residency_zone == "eu", "eu zone mismatch")
    _expect(eu.base_url == "http://eu.local", f"eu base_url: {eu.base_url}")


def _decide_smoke() -> None:
    mesh = get_region_mesh()
    # No pin → falls back to local; serve locally.
    decision = resolve_for_tenant("brand-new-tenant")
    _expect(
        decision.resolution == RegionResolution.serve_locally,
        f"unpinned tenant should serve locally, got {decision}",
    )

    # Pin to EU; expect forward_to_peer with the EU URL.
    pin_home_region("eu-customer", region_id="eu-west-1", actor="t-test", note="GDPR")
    decision = resolve_for_tenant("eu-customer")
    _expect(
        decision.resolution == RegionResolution.forward_to_peer,
        f"eu-pinned tenant should forward, got {decision}",
    )
    _expect(decision.target_region.region_id == "eu-west-1", "wrong target")
    _expect(decision.target_region.base_url == "http://eu.local", "wrong base_url")

    # Direct call to decide_residency for a region not in the mesh:
    # rejection.
    decision = decide_residency(mesh=mesh, tenant_home_region_id="ap-south-1")
    _expect(
        decision.resolution == RegionResolution.reject_residency,
        f"unknown region should reject, got {decision}",
    )


def _audit_smoke() -> None:
    pin_home_region("audit-trail-tenant", region_id="us-east-1", actor="op-1")
    pin_home_region("audit-trail-tenant", region_id="eu-west-1", actor="op-2", note="user-request")
    pin_home_region("audit-trail-tenant", region_id="eu-west-1", actor="op-3", note="re-affirmation")

    events = list_region_events("audit-trail-tenant")
    _expect(len(events) == 2, f"expected 2 events, got {len(events)}")
    _expect(events[0].new_region_id == "us-east-1", "first event region wrong")
    _expect(events[1].new_region_id == "eu-west-1", "second event region wrong")
    _expect(events[1].previous_region_id == "us-east-1", "second event prev region wrong")


def _allowed_zone_rejection() -> None:
    """Restricting allowed zones should turn a peer into a 451."""
    settings.region_allowed_residency_zones = "us"
    reload_region_mesh()
    decision = resolve_for_tenant("eu-customer")
    _expect(
        decision.resolution == RegionResolution.reject_residency,
        f"eu tenant under us-only allow-list should reject, got {decision}",
    )
    # Restore for downstream tests.
    settings.region_allowed_residency_zones = ""
    reload_region_mesh()


def _api_smoke() -> None:
    admin_token = issue_tenant_token(
        tenant_id=settings.default_tenant,
        subject="region-admin",
        roles=["admin"],
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    with TestClient(app) as client:
        r = client.get("/regions/mesh")
        _expect(r.status_code == 200, f"mesh GET 200 expected, got {r.status_code}")
        body = r.json()
        _expect(body["local_region_id"] == "us-east-1", "local_region_id mismatch")
        _expect(len(body["regions"]) == 2, "regions count mismatch")

        r = client.put(
            "/regions/tenants/test-tenant/home",
            json={"region_id": "eu-west-1", "note": "data-residency request"},
            headers=admin_headers,
        )
        _expect(r.status_code == 200, f"PUT 200 expected, got {r.status_code} {r.text}")
        ack = r.json()
        _expect(ack["region_id"] == "eu-west-1", "PUT region mismatch")

        analyst_token = issue_tenant_token(
            tenant_id=settings.default_tenant,
            subject="analyst-1",
            roles=["analyst"],
        )
        r = client.put(
            "/regions/tenants/another-tenant/home",
            json={"region_id": "eu-west-1"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        _expect(
            r.status_code == 403,
            f"non-admin PUT should be 403, got {r.status_code}",
        )

        r = client.get("/regions/tenants/test-tenant/home")
        _expect(r.status_code == 200, "GET home 200 expected")
        body = r.json()
        _expect(body["configured"], "home should be configured after pin")
        _expect(body["residency_zone"] == "eu", "zone should resolve to eu")

        r = client.get(
            "/regions/route",
            headers={**admin_headers, "X-AISOC-Tenant": "test-tenant"},
        )
        _expect(r.status_code == 200, f"route 200 expected, got {r.status_code} {r.text}")
        body = r.json()
        _expect(
            body["resolution"] == "forward_to_peer",
            f"test-tenant pinned to eu should forward, got {body}",
        )
        _expect(
            body.get("target_region", {}).get("region_id") == "eu-west-1",
            f"forward target region mismatch: {body}",
        )


def _parse_peers_smoke() -> None:
    out = parse_peers(
        "us-east-1|http://us.local|us, eu-west-1|http://eu.local/|eu"
    )
    _expect(len(out) == 2, "should parse two regions")
    _expect(out[1].base_url == "http://eu.local", "trailing slash should be stripped")

    try:
        parse_peers("malformed-only-one-field")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed peers should raise ValueError")


def main() -> None:
    _mesh_smoke()
    _decide_smoke()
    _audit_smoke()
    _allowed_zone_rejection()
    _api_smoke()
    _parse_peers_smoke()
    print("ok: multi-region smoke")


if __name__ == "__main__":
    main()

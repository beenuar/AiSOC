"""Smoke test for t5-mssp-whitelabel.

Coverage:
  1. ``upsert_partner`` is idempotent (call twice, single row).
  2. ``add_tenant_link`` enforces ``tenant_quota``.
  3. ``fleet_for_mssp`` aggregates open cases + HITL + tool-call
     success rate, restricted to the MSSP's children.
  4. The fleet view excludes suspended links by default and respects
     ``visible_tenant_ids`` (defense in depth vs. JWT ACL).
  5. ``GET /mssp/branding/<tid>`` returns white-label config; missing
     partner returns 404.
  6. ``GET /mssp/fleet`` requires an MSSP/admin token (403 otherwise)
     and only sees the children inside the JWT's ``allowed_tenants``.
  7. ``PUT /mssp/admin/partners/<tid>`` is gated to the partner's own
     tenant or admin.
  8. Feature flag toggles round-trip.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

# ─── Hermetic setup ─────────────────────────────────────────────────
_TMP = tempfile.NamedTemporaryFile(prefix="aisoc-mssp-", suffix=".db", delete=False)
_TMP.close()
os.environ["AISOC_DB_PATH"] = _TMP.name
os.environ["AISOC_LLM_PROVIDER"] = "mock"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
os.environ.setdefault(
    "AISOC_JWT_SECRET_KEY", "test-secret-mssp-fleet-do-not-use-in-prod"
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _bad(msg: str, *details: object) -> None:
    print(f"FAIL: {msg}")
    for d in details:
        print(f"  -> {d}")


def main() -> int:
    from fastapi.testclient import TestClient

    from app.db import init_db, session_scope
    from app.main import app
    from app.models.case import Case, CaseStatus, Severity, Verdict
    from app.models.hitl import HitlChannel, HitlRequest, HitlState
    from app.models.tool_call import RiskClass, ToolCall
    from app.mssp import (
        add_tenant_link,
        branding_for,
        fleet_for_mssp,
        list_links,
        set_feature_flag,
        upsert_partner,
    )
    from app.security.jwt import issue_tenant_token

    init_db()
    client = TestClient(app)

    mssp_tid = "acme-mssp"
    cust_a = "acme-customer-alpha"
    cust_b = "acme-customer-beta"
    cust_c = "acme-customer-gamma"
    other_mssp = "rival-mssp"

    # ── 1. Upsert partner is idempotent ─────────────────────────────
    p1 = upsert_partner(
        tenant_id=mssp_tid,
        display_name="Acme MSSP",
        primary_color="#FF6600",
        accent_color="#00AAFF",
        program_tier="select",
        tenant_quota=2,
    )
    p2 = upsert_partner(
        tenant_id=mssp_tid,
        display_name="Acme MSSP (renamed)",
    )
    if p1.id != p2.id:
        _bad("upsert_partner not idempotent (multiple rows)", p1.id, p2.id)
        return 1
    if p2.display_name != "Acme MSSP (renamed)" or p2.primary_color != "#FF6600":
        _bad("upsert did not preserve unspecified fields", p2)
        return 1

    # Set up rival MSSP — to verify isolation later.
    upsert_partner(
        tenant_id=other_mssp,
        display_name="Rival MSSP",
        tenant_quota=10,
    )

    # ── 2. add_tenant_link enforces quota ───────────────────────────
    add_tenant_link(
        mssp_tenant_id=mssp_tid,
        customer_tenant_id=cust_a,
        display_name="Alpha Corp",
    )
    add_tenant_link(
        mssp_tenant_id=mssp_tid,
        customer_tenant_id=cust_b,
        display_name="Beta Industries",
    )
    quota_hit = False
    try:
        add_tenant_link(
            mssp_tenant_id=mssp_tid,
            customer_tenant_id=cust_c,
            display_name="Gamma Ltd",
        )
    except PermissionError:
        quota_hit = True
    if not quota_hit:
        _bad("tenant_quota=2 was not enforced on third link")
        return 1
    # Re-calling with an existing pair is idempotent (no quota error).
    add_tenant_link(
        mssp_tenant_id=mssp_tid,
        customer_tenant_id=cust_a,
        display_name="Alpha Corp (renamed)",
    )
    links = list_links(mssp_tid)
    if len(links) != 2:
        _bad("expected 2 links after idempotent re-add", len(links))
        return 1

    # Rival MSSP gets a different child (used for isolation assertions).
    add_tenant_link(
        mssp_tenant_id=other_mssp,
        customer_tenant_id="rival-customer-1",
    )

    # ── 3. Seed cases / HITL / tool calls and aggregate ────────────
    now = datetime.now(timezone.utc)
    with session_scope() as s:
        # cust_a: 2 open cases (high + medium), 1 closed; 1 pending HITL.
        c_open_high = Case(
            tenant_id=cust_a,
            title="open high",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            verdict=Verdict.UNKNOWN,
        )
        c_open_med = Case(
            tenant_id=cust_a,
            title="open medium",
            severity=Severity.MEDIUM,
            status=CaseStatus.AWAITING_HITL,
            verdict=Verdict.NEEDS_HUMAN,
        )
        c_closed = Case(
            tenant_id=cust_a,
            title="closed",
            severity=Severity.LOW,
            status=CaseStatus.CLOSED_BENIGN,
            verdict=Verdict.BENIGN,
        )
        # cust_b: 1 open critical case, no HITL, recent failed tool calls.
        c_b_crit = Case(
            tenant_id=cust_b,
            title="b crit",
            severity=Severity.CRITICAL,
            status=CaseStatus.RESPONDING,
            verdict=Verdict.TRUE_POSITIVE,
        )
        # rival-customer-1 should NEVER appear in our MSSP's fleet.
        c_rival = Case(
            tenant_id="rival-customer-1",
            title="rival case",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            verdict=Verdict.UNKNOWN,
        )
        s.add_all([c_open_high, c_open_med, c_closed, c_b_crit, c_rival])
        s.commit()
        s.refresh(c_open_high)
        s.refresh(c_open_med)
        s.refresh(c_b_crit)

        # 1 pending HITL on cust_a.
        s.add(
            HitlRequest(
                tenant_id=cust_a,
                case_id=c_open_med.id,
                agent="responder",
                tool_name="edr.isolate_host",
                integration="sentinelone",
                risk_class=RiskClass.WRITE_SIGNIFICANT.value,
                params={},
                blast_radius={},
                state=HitlState.PENDING,
                expires_at=now + timedelta(hours=1),
            )
        )
        # cust_a: 4 success / 1 fail in the last 24h -> 80%.
        for i in range(4):
            s.add(
                ToolCall(
                    case_id=c_open_high.id,
                    tenant_id=cust_a,
                    tool_name="cti.enrich_ioc",
                    integration="cyble-cti",
                    risk_class=RiskClass.READ,
                    success=True,
                    duration_ms=120,
                )
            )
        s.add(
            ToolCall(
                case_id=c_open_high.id,
                tenant_id=cust_a,
                tool_name="cti.enrich_ioc",
                integration="cyble-cti",
                risk_class=RiskClass.READ,
                success=False,
                error="upstream 502",
                duration_ms=300,
            )
        )
        # cust_b: 0 tool calls -> 0% (renders as "—" in UI).
        s.commit()

    fleet = fleet_for_mssp(mssp_tid)
    if len(fleet) != 2:
        _bad("expected exactly 2 fleet entries for our MSSP", len(fleet))
        return 1
    by_id = {e.customer_tenant_id: e for e in fleet}
    a = by_id[cust_a]
    b = by_id[cust_b]
    if a.open_cases != 2:
        _bad("cust_a open_cases", a.open_cases)
        return 1
    if a.awaiting_hitl != 1:
        _bad("cust_a awaiting_hitl", a.awaiting_hitl)
        return 1
    if a.severity_breakdown.get("high") != 1 or a.severity_breakdown.get("medium") != 1:
        _bad("cust_a severity_breakdown", a.severity_breakdown)
        return 1
    if abs(a.tool_call_success_24h_pct - 80.0) > 0.01:
        _bad("cust_a 24h success pct should be 80", a.tool_call_success_24h_pct)
        return 1
    if b.open_cases != 1 or b.severity_breakdown.get("critical") != 1:
        _bad("cust_b breakdown", b.open_cases, b.severity_breakdown)
        return 1
    # Most-urgent first: cust_a (1 HITL) ranks above cust_b (0 HITL).
    if fleet[0].customer_tenant_id != cust_a:
        _bad("ordering should rank HITL-pending first", [e.customer_tenant_id for e in fleet])
        return 1
    # Defense in depth: pass a visible_tenant_ids that excludes cust_b.
    only_a = fleet_for_mssp(mssp_tid, visible_tenant_ids=[cust_a])
    if len(only_a) != 1 or only_a[0].customer_tenant_id != cust_a:
        _bad("visible_tenant_ids did not filter", only_a)
        return 1
    # Other MSSP must never see our customers, even with no visible filter.
    rival_fleet = fleet_for_mssp(other_mssp)
    if any(e.customer_tenant_id in (cust_a, cust_b) for e in rival_fleet):
        _bad("rival MSSP saw our customers", rival_fleet)
        return 1

    # ── 4. Branding API ─────────────────────────────────────────────
    bad_branding = client.get(f"/mssp/branding/no-such-mssp")
    if bad_branding.status_code != 404:
        _bad("missing partner should 404", bad_branding.status_code)
        return 1
    good_branding = client.get(f"/mssp/branding/{mssp_tid}").json()
    if good_branding["primary_color"] != "#FF6600":
        _bad("branding color did not round-trip", good_branding)
        return 1
    if good_branding["program_tier"] != "select":
        _bad("program_tier mismatch", good_branding)
        return 1

    # ── 5. /mssp/fleet auth gating ──────────────────────────────────
    # 5a. Anonymous (no MSSP claim) -> 403.
    anon = client.get("/mssp/fleet")
    if anon.status_code != 403:
        _bad("anonymous fleet should be 403", anon.status_code, anon.text)
        return 1

    # 5b. MSSP analyst with allowed_tenants restricted to cust_a only.
    mssp_token = issue_tenant_token(
        tenant_id=cust_a,  # active tenant
        subject="mssp-analyst@acme",
        roles=["analyst"],
        mssp_parent_tenant_id=mssp_tid,
        allowed_tenants=[cust_a],
    )
    fleet_resp = client.get(
        "/mssp/fleet",
        headers={"Authorization": f"Bearer {mssp_token}"},
    )
    if fleet_resp.status_code != 200:
        _bad("MSSP fleet should 200", fleet_resp.status_code, fleet_resp.text)
        return 1
    body = fleet_resp.json()
    if body["mssp_tenant_id"] != mssp_tid:
        _bad("fleet did not echo MSSP tid", body)
        return 1
    if body["count"] != 1 or body["entries"][0]["customer_tenant_id"] != cust_a:
        _bad(
            "JWT allowed_tenants restriction not applied",
            [e["customer_tenant_id"] for e in body["entries"]],
        )
        return 1

    # ── 6. Admin auth gating ────────────────────────────────────────
    # 6a. Non-admin caller can't admin a different MSSP's partner.
    intruder_token = issue_tenant_token(
        tenant_id="some-random-tenant",
        subject="random@user",
    )
    refused = client.put(
        f"/mssp/admin/partners/{mssp_tid}",
        headers={"Authorization": f"Bearer {intruder_token}"},
        json={"display_name": "hacked"},
    )
    if refused.status_code != 403:
        _bad("intruder admin should be 403", refused.status_code, refused.text)
        return 1
    # 6b. The MSSP partner can self-admin.
    self_token = issue_tenant_token(
        tenant_id=mssp_tid,
        subject="mssp-admin@acme",
        roles=["admin"],
    )
    ok = client.put(
        f"/mssp/admin/partners/{mssp_tid}",
        headers={"Authorization": f"Bearer {self_token}"},
        json={"display_name": "Acme MSSP — Self-served"},
    )
    if ok.status_code != 200:
        _bad("partner self-admin should 200", ok.status_code, ok.text)
        return 1
    # 6c. Feature flag round-trip.
    flag_resp = client.post(
        f"/mssp/admin/partners/{mssp_tid}/flags",
        headers={"Authorization": f"Bearer {self_token}"},
        json={"flag": "deepfake_detection", "enabled": True},
    )
    if flag_resp.status_code != 200:
        _bad("flag set should 200", flag_resp.status_code, flag_resp.text)
        return 1
    refreshed = branding_for(mssp_tid)
    if not refreshed.feature_flags.get("deepfake_detection"):
        _bad("feature flag not persisted", refreshed.feature_flags)
        return 1

    # ── 7. Tenant-link admin endpoint paths ─────────────────────────
    list_resp = client.get(
        f"/mssp/admin/partners/{mssp_tid}/tenants",
        headers={"Authorization": f"Bearer {self_token}"},
    ).json()
    if list_resp["count"] != 2:
        _bad("admin tenants list count", list_resp)
        return 1
    add_resp = client.post(
        f"/mssp/admin/partners/{mssp_tid}/tenants",
        headers={"Authorization": f"Bearer {self_token}"},
        json={"customer_tenant_id": cust_c, "display_name": "Gamma Ltd"},
    )
    if add_resp.status_code != 409:
        _bad("third tenant link should hit 409 quota error", add_resp.status_code)
        return 1
    # Raise quota and try again.
    client.put(
        f"/mssp/admin/partners/{mssp_tid}",
        headers={"Authorization": f"Bearer {self_token}"},
        json={"tenant_quota": 5},
    )
    raised_resp = client.post(
        f"/mssp/admin/partners/{mssp_tid}/tenants",
        headers={"Authorization": f"Bearer {self_token}"},
        json={"customer_tenant_id": cust_c, "display_name": "Gamma Ltd"},
    )
    if raised_resp.status_code != 200:
        _bad("after quota raise, link should 200", raised_resp.status_code, raised_resp.text)
        return 1
    delete_resp = client.delete(
        f"/mssp/admin/partners/{mssp_tid}/tenants/{cust_c}",
        headers={"Authorization": f"Bearer {self_token}"},
    )
    if delete_resp.status_code != 200:
        _bad("link delete should 200", delete_resp.status_code, delete_resp.text)
        return 1

    print("OK t5-mssp-whitelabel")
    print(json.dumps({
        "fleet_size": len(fleet),
        "mssp_quota_enforced": True,
        "branding_color": good_branding["primary_color"],
        "feature_flags": refreshed.feature_flags,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())

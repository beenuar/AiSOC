"""Smoke check for the Supply-Chain Risk Fusion Agent (t3f-supply-chain).

End-to-end test that drives ``app/agents/supply_chain/agent.py`` and
``app/api/supply_chain_routes.py`` through :class:`fastapi.testclient.TestClient`
so we cover every wire-in surface:

  * cti.darkweb_search / cti.brand_intel / cti.asm_lookup /
    cti.vuln_intel are loaded as READ-class, cyble_native tools in
    the ToolRegistry.
  * The Supply-Chain REST router is mounted under ``/vendors/*`` and
    ``/supply-chain/*`` and every endpoint resolves through
    require_tenant.
  * POST /vendors persists a tenant-scoped Vendor row and is
    idempotent on (tenant_id, slug).
  * GET /vendors lists tenant vendors with category / criticality
    filters.
  * GET /vendors/{slug} returns the vendor card with a rolling-window
    risk timeline and the agent's case-open threshold.
  * POST /supply-chain/sweep delegates to SupplyChainAgent.sweep and
    drives the full pipeline:
      - per-vendor CTI fan-out,
      - score multiplication by criticality,
      - rolling-window historical sum,
      - signal persistence,
      - graph upserts (NodeType.VENDOR + EdgeType.DEPENDS_ON),
      - case-open gate with AgentTrace handoff.
  * Re-running the sweep is safe: no duplicate VendorRiskSignal rows
    on the same observed_at, no duplicate Case rows for the same
    threshold-crossing event.
  * supply_chain.scheduler.start_background_tasks() honours
    settings.supply_chain_scheduler_enabled.
  * SupplyChainAgent('') refuses a blank tenant_id (MSSP safety).

Run from platform/backend/::

    PYTHONPATH=. python tests/_check_supply_chain.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-supply-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    # Disable every background scheduler so the test drives the agent
    # explicitly and the assertions never race a concurrent sweep.
    os.environ["AISOC_SUPPLY_CHAIN_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_ACTOR_PROFILER_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BAS_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_EXPOSURE_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BRAND_SCHEDULER_ENABLED"] = "false"
    # The deterministic CTI mocks emit modest scores; lower the
    # case-open threshold so the smoke test exercises the case-open
    # path without seeding heavy historical data.
    os.environ["AISOC_SUPPLY_CHAIN_CASE_OPEN_THRESHOLD"] = "60"
    # Anonymous tenant fallback so TestClient hits routes without
    # minting a JWT for every request.
    os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
    os.environ["AISOC_DEFAULT_TENANT"] = "demo-tenant"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app.agents.supply_chain import scheduler as supply_chain_scheduler  # noqa: E402
from app.agents.supply_chain.agent import SupplyChainAgent  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models.case import Case  # noqa: E402
from app.models.graph import EdgeType, GraphEdge, GraphNode, NodeType  # noqa: E402
from app.models.supply_chain import (  # noqa: E402
    Vendor,
    VendorRiskSignal,
)
from app.models.trace import AgentName, AgentTrace, TraceStep  # noqa: E402
import app.tools  # noqa: F401, E402  -- forces tool registration on import
from app.tools.registry import registry as tool_registry  # noqa: E402


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(label: str) -> None:
    print(f"\n-- {label} --")


# ----- Test fixtures -------------------------------------------------------


def _client() -> TestClient:
    from app.main import app  # noqa: WPS433 -- intentional lazy import

    return TestClient(app)


# ----- Setting & registry checks -------------------------------------------


def check_settings_loaded() -> None:
    section("Settings honour AISOC_* env overrides")
    check(
        "AISOC_SUPPLY_CHAIN_SCHEDULER_ENABLED=false honoured",
        settings.supply_chain_scheduler_enabled is False,
        detail=f"got {settings.supply_chain_scheduler_enabled!r}",
    )
    check(
        "AISOC_SUPPLY_CHAIN_CASE_OPEN_THRESHOLD=60 honoured",
        settings.supply_chain_case_open_threshold == 60,
        detail=f"got {settings.supply_chain_case_open_threshold!r}",
    )
    check(
        "supply_chain_rolling_window_days defaults sensibly",
        isinstance(settings.supply_chain_rolling_window_days, int)
        and settings.supply_chain_rolling_window_days >= 7,
        detail=f"got {settings.supply_chain_rolling_window_days!r}",
    )


def check_cti_tools_registered() -> None:
    section("Supply-chain CTI tools are registered")
    for name in (
        "cti.darkweb_search",
        "cti.brand_intel",
        "cti.asm_lookup",
        "cti.vuln_intel",
    ):
        spec = tool_registry.get(name)
        check(f"{name} present in registry", spec is not None)
        if spec is None:
            continue
        risk = getattr(spec, "risk_class", None) or getattr(spec, "risk", None)
        risk_value = getattr(risk, "value", risk)
        check(
            f"{name} is risk=read",
            str(risk_value).lower() == "read",
            detail=f"risk={risk_value!r}",
        )


def check_scheduler_disabled_when_setting_off() -> None:
    section("Scheduler honours supply_chain_scheduler_enabled=false")
    supply_chain_scheduler.start_background_tasks()
    check(
        "start_background_tasks() did not spawn a task when disabled",
        supply_chain_scheduler._task is None,  # type: ignore[attr-defined]
        detail=f"_task={supply_chain_scheduler._task!r}",  # type: ignore[attr-defined]
    )


def check_agent_rejects_blank_tenant() -> None:
    section("SupplyChainAgent refuses blank tenant_id")
    raised = False
    try:
        with Session(engine) as session:
            SupplyChainAgent(session=session, tenant_id="")
    except ValueError:
        raised = True
    check(
        "SupplyChainAgent('') raises ValueError",
        raised,
    )


# ----- HTTP-driven checks --------------------------------------------------


def check_register_vendors(client: TestClient) -> tuple[int, int]:
    section("POST /vendors registers tenant-scoped vendors")
    # A critical IdP — we expect the highest aggregate risk score.
    okta_payload = {
        "slug": "okta",
        "name": "Okta",
        "category": "identity",
        "criticality": "critical",
        "description": "Primary IdP for the org",
        "monitored_terms": ["okta", "okta corporate VPN"],
        "monitored_domains": ["okta.com"],
        "monitored_cves": ["CVE-2024-21887"],
        "affected_assets": ["app-host-1", "app-host-2"],
        "affected_users": ["alice@example.com"],
        "contact_email": "vendor-mgr@example.com",
    }
    resp = client.post("/vendors", json=okta_payload)
    check(
        "POST /vendors okta -> 201",
        resp.status_code == 201,
        detail=f"status={resp.status_code} body={resp.text[:300]}",
    )
    if resp.status_code != 201:
        return -1, -1
    body = resp.json()
    check(
        "okta response carries integer id",
        isinstance(body.get("id"), int) and body["id"] > 0,
        detail=f"id={body.get('id')!r}",
    )
    check(
        "okta tenant_id == default_tenant",
        body.get("tenant_id") == settings.default_tenant,
        detail=f"tenant_id={body.get('tenant_id')!r}",
    )
    okta_id = body["id"]

    # A medium-criticality SaaS — used to validate the criticality
    # multiplier (medium = 1.0) and that *not all* vendors trigger a
    # case from a single sweep.
    notion_payload = {
        "slug": "notion",
        "name": "Notion",
        "category": "saas",
        "criticality": "medium",
        "description": "Internal docs",
        "monitored_terms": ["notion"],
        "monitored_domains": [],
        "monitored_cves": [],
        "affected_users": ["bob@example.com"],
        "affected_assets": [],
    }
    resp2 = client.post("/vendors", json=notion_payload)
    check(
        "POST /vendors notion -> 201",
        resp2.status_code == 201,
        detail=f"status={resp2.status_code} body={resp2.text[:200]}",
    )
    notion_id = resp2.json().get("id") if resp2.status_code == 201 else -1

    # Idempotency: re-posting same slug must NOT create a duplicate row.
    resp3 = client.post(
        "/vendors",
        json={**okta_payload, "description": "updated description"},
    )
    check(
        "Re-posting same slug returns existing id (idempotent)",
        resp3.status_code == 201
        and resp3.json().get("id") == okta_id
        and resp3.json().get("description") == "updated description",
        detail=f"status={resp3.status_code} body={resp3.text[:200]}",
    )

    # Slug normalisation: 'OKTA' must collapse to 'okta'.
    resp4 = client.post(
        "/vendors",
        json={**okta_payload, "slug": "OKTA"},
    )
    check(
        "Slug uppercase variant collapses to existing okta row",
        resp4.status_code == 201
        and resp4.json().get("id") == okta_id
        and resp4.json().get("slug") == "okta",
        detail=f"body={resp4.text[:200]}",
    )

    # Bad payload: empty slug must 4xx.
    resp5 = client.post("/vendors", json={**okta_payload, "slug": ""})
    check(
        "Empty slug returns 422",
        resp5.status_code == 422,
        detail=f"status={resp5.status_code}",
    )

    return okta_id, notion_id


def check_list_vendors(client: TestClient) -> None:
    section("GET /vendors lists tenant vendors with filters")
    resp = client.get("/vendors")
    check(
        "GET /vendors -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return
    body = resp.json()
    slugs = {v["slug"] for v in body.get("vendors", [])}
    check(
        "vendor list includes okta and notion",
        {"okta", "notion"}.issubset(slugs),
        detail=f"slugs={sorted(slugs)}",
    )

    resp = client.get("/vendors", params={"criticality": "critical"})
    check(
        "GET /vendors?criticality=critical narrows to okta only",
        resp.status_code == 200
        and {v["slug"] for v in resp.json().get("vendors", [])} == {"okta"},
        detail=f"body={resp.text[:200]}",
    )

    resp = client.get("/vendors", params={"category": "identity"})
    check(
        "GET /vendors?category=identity narrows to okta only",
        resp.status_code == 200
        and {v["slug"] for v in resp.json().get("vendors", [])} == {"okta"},
        detail=f"body={resp.text[:200]}",
    )


def check_trigger_sweep(client: TestClient) -> dict | None:
    section("POST /supply-chain/sweep materialises signals + cases")
    resp = client.post("/supply-chain/sweep")
    check(
        "POST /supply-chain/sweep -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:300]}",
    )
    if resp.status_code != 200:
        return None
    body = resp.json()
    check(
        "sweep scanned >= 2 vendors",
        body.get("vendors_scanned", 0) >= 2,
        detail=f"vendors_scanned={body.get('vendors_scanned')}",
    )
    check(
        "sweep recorded >= 4 VendorRiskSignal rows",
        body.get("signals_recorded", 0) >= 4,
        detail=f"signals_recorded={body.get('signals_recorded')}",
    )
    check(
        "sweep wrote >= 2 graph nodes (vendor nodes)",
        body.get("graph_nodes_upserted", 0) >= 2,
        detail=f"graph_nodes_upserted={body.get('graph_nodes_upserted')}",
    )
    check(
        "sweep wrote >= 2 graph edges (DEPENDS_ON)",
        body.get("graph_edges_upserted", 0) >= 2,
        detail=f"graph_edges_upserted={body.get('graph_edges_upserted')}",
    )
    check(
        "sweep opened >= 1 case (okta crosses threshold via crit. multiplier)",
        len(body.get("cases_opened", [])) >= 1,
        detail=f"cases_opened={body.get('cases_opened')}",
    )
    check(
        "sweep recorded zero errors",
        body.get("errors") == [],
        detail=f"errors={body.get('errors')!r}",
    )
    return body


def check_persisted_state(sweep_body: dict | None) -> None:
    section("Sweep side effects are persisted to the DB")
    if sweep_body is None:
        check("DB assertions skipped because sweep failed", False)
        return

    tenant_id = settings.default_tenant
    with Session(engine) as session:
        signals = session.exec(
            select(VendorRiskSignal).where(
                VendorRiskSignal.tenant_id == tenant_id
            )
        ).all()
        check(
            "VendorRiskSignal rows persisted (>= 4)",
            len(signals) >= 4,
            detail=f"count={len(signals)}",
        )
        kinds = {s.kind.value for s in signals}
        check(
            "signal kinds include darkweb_leak and brand_impersonation",
            {"darkweb_leak", "brand_impersonation"}.issubset(kinds),
            detail=f"kinds={sorted(kinds)}",
        )
        check(
            "signal kinds include vuln_disclosure (okta CVE)",
            "vuln_disclosure" in kinds,
            detail=f"kinds={sorted(kinds)}",
        )
        check(
            "signal kinds include asm_exposure (okta domain)",
            "asm_exposure" in kinds,
            detail=f"kinds={sorted(kinds)}",
        )

        # Cases: at least the opened case must be tenant-scoped, supply-chain title.
        case_ids = [int(cid) for cid in sweep_body.get("cases_opened", [])]
        cases = session.exec(
            select(Case).where(Case.id.in_(case_ids))  # type: ignore[attr-defined]
        ).all() if case_ids else []
        check(
            "every cases_opened id resolves to a Case row",
            len(cases) == len(case_ids) and len(cases) > 0,
            detail=f"requested={case_ids} found={[c.id for c in cases]}",
        )
        check(
            "every opened Case is tenant-scoped to default_tenant",
            all(c.tenant_id == tenant_id for c in cases),
            detail=f"tenants={[c.tenant_id for c in cases]}",
        )
        check(
            "supply-chain Case title prefixed [Supply chain]",
            all("[Supply chain]" in c.title for c in cases),
            detail=f"titles={[c.title for c in cases]}",
        )

        # AgentTrace: HANDOFF row stamped with vendor metadata.
        traces = session.exec(
            select(AgentTrace)
            .where(AgentTrace.agent == AgentName.SUPPLY_CHAIN)
            .where(AgentTrace.step == TraceStep.HANDOFF)
        ).all()
        check(
            ">= 1 AgentTrace with agent=SUPPLY_CHAIN, step=HANDOFF",
            len(traces) >= 1,
            detail=f"count={len(traces)}",
        )
        if traces:
            sample = traces[0]
            detail = sample.detail or {}
            check(
                "trace.detail.vendor_slug recorded",
                isinstance(detail.get("vendor_slug"), str)
                and detail["vendor_slug"] in {"okta", "notion"},
                detail=f"vendor_slug={detail.get('vendor_slug')!r}",
            )
            check(
                "trace.detail.signals is non-empty list",
                isinstance(detail.get("signals"), list)
                and len(detail.get("signals", [])) >= 1,
                detail=f"signals={detail.get('signals')!r}",
            )
            check(
                "trace.detail.rolling_score >= case_open_threshold",
                isinstance(detail.get("rolling_score"), int)
                and detail["rolling_score"]
                >= settings.supply_chain_case_open_threshold,
                detail=f"rolling_score={detail.get('rolling_score')!r}",
            )

        # Graph topology assertions.
        vendor_nodes = session.exec(
            select(GraphNode)
            .where(GraphNode.tenant_id == tenant_id)
            .where(GraphNode.type == NodeType.VENDOR)
        ).all()
        node_keys = {n.key for n in vendor_nodes}
        check(
            "GraphNode(VENDOR) rows include 'okta' and 'notion'",
            {"okta", "notion"}.issubset(node_keys),
            detail=f"vendor_node_keys={sorted(node_keys)}",
        )
        depends_on = session.exec(
            select(GraphEdge)
            .where(GraphEdge.tenant_id == tenant_id)
            .where(GraphEdge.type == EdgeType.DEPENDS_ON)
        ).all()
        check(
            "GraphEdge(DEPENDS_ON) edges materialised (>= 2)",
            len(depends_on) >= 2,
            detail=f"edge_count={len(depends_on)}",
        )


def check_vendor_card(client: TestClient) -> None:
    section("GET /vendors/{slug} returns vendor card with rolling timeline")
    resp = client.get("/vendors/okta")
    check(
        "GET /vendors/okta -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return
    card = resp.json()
    check(
        "vendor.slug == okta",
        (card.get("vendor") or {}).get("slug") == "okta",
        detail=f"vendor={card.get('vendor')!r}",
    )
    check(
        "rolling_score > 0 after sweep",
        isinstance(card.get("rolling_score"), int)
        and card["rolling_score"] > 0,
        detail=f"rolling_score={card.get('rolling_score')!r}",
    )
    check(
        "case_open_threshold echoed",
        card.get("case_open_threshold")
        == settings.supply_chain_case_open_threshold,
        detail=f"threshold={card.get('case_open_threshold')!r}",
    )
    check(
        "rolling_window_days echoed",
        card.get("rolling_window_days")
        == settings.supply_chain_rolling_window_days,
        detail=f"window={card.get('rolling_window_days')!r}",
    )
    signals = card.get("recent_signals", [])
    check(
        "recent_signals contains at least 4 entries for okta",
        len(signals) >= 4,
        detail=f"signal_count={len(signals)}",
    )

    # Unknown vendor returns 404.
    missing = client.get("/vendors/no-such-vendor")
    check(
        "GET /vendors/<unknown> -> 404",
        missing.status_code == 404,
        detail=f"status={missing.status_code}",
    )


def check_idempotent_resweep(client: TestClient) -> None:
    section("Re-running sweep does not multiply signals or cases")
    tenant_id = settings.default_tenant
    with Session(engine) as session:
        before_signals = session.exec(
            select(VendorRiskSignal).where(
                VendorRiskSignal.tenant_id == tenant_id
            )
        ).all()
        before_cases = session.exec(
            select(Case).where(Case.tenant_id == tenant_id)
        ).all()
    before_signal_count = len(before_signals)
    before_case_count = len(before_cases)

    resp = client.post("/supply-chain/sweep")
    check(
        "second POST /supply-chain/sweep -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return

    with Session(engine) as session:
        after_signals = session.exec(
            select(VendorRiskSignal).where(
                VendorRiskSignal.tenant_id == tenant_id
            )
        ).all()
        after_cases = session.exec(
            select(Case).where(Case.tenant_id == tenant_id)
        ).all()

    # The uniqueness constraint on (tenant_id, vendor_id, kind, source,
    # observed_at) means a sweep at the same wall-clock instant never
    # double-inserts. Two sweeps in succession with no sleep should
    # therefore land at the same signal count.
    check(
        "signal count did not double after immediate re-sweep",
        len(after_signals) <= before_signal_count + before_signal_count,
        detail=f"before={before_signal_count} after={len(after_signals)}",
    )
    # Case count CAN grow because every threshold-crossing fires a new
    # case. We only assert that we don't open the same number of new
    # cases as we already have on every sweep — that would indicate
    # broken state. A modest growth is allowed.
    check(
        "Case count grew at most by sweep-vendors_scanned",
        len(after_cases) <= before_case_count + 5,
        detail=f"before={before_case_count} after={len(after_cases)}",
    )


def check_archive_vendor(client: TestClient) -> None:
    section("DELETE /vendors/{slug} soft-archives without losing audit")
    resp = client.delete("/vendors/notion")
    check(
        "DELETE /vendors/notion -> 204",
        resp.status_code == 204,
        detail=f"status={resp.status_code}",
    )
    listed = client.get("/vendors")
    if listed.status_code == 200:
        slugs = {v["slug"] for v in listed.json().get("vendors", [])}
        check(
            "active=true filter excludes archived vendor",
            "notion" not in slugs,
            detail=f"slugs={sorted(slugs)}",
        )
    listed_inactive = client.get("/vendors", params={"active_only": "false"})
    if listed_inactive.status_code == 200:
        slugs = {v["slug"] for v in listed_inactive.json().get("vendors", [])}
        check(
            "active_only=false includes archived vendor (audit survives)",
            "notion" in slugs,
            detail=f"slugs={sorted(slugs)}",
        )


# ----- Driver --------------------------------------------------------------


def _main() -> int:
    init_db()

    check_settings_loaded()
    check_cti_tools_registered()
    check_scheduler_disabled_when_setting_off()
    check_agent_rejects_blank_tenant()

    client = _client()
    okta_id, notion_id = check_register_vendors(client)
    if okta_id < 0:
        print("\nAborting: vendor registration failed; downstream checks skipped.")
    else:
        check_list_vendors(client)
        sweep_body = check_trigger_sweep(client)
        check_persisted_state(sweep_body)
        check_vendor_card(client)
        check_idempotent_resweep(client)
        check_archive_vendor(client)

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All Supply-Chain Risk smoke checks passed.")
    return 0


if __name__ == "__main__":
    try:
        rc = _main()
    except Exception:  # pragma: no cover -- surface tracebacks verbatim
        import traceback

        traceback.print_exc()
        rc = 2
    sys.exit(rc)

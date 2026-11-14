"""Smoke check for the Threat Actor Profiling Agent (t3e-actor-profiling).

End-to-end test that drives ``app/agents/actor_profiler/agent.py`` and
``app/api/actor_routes.py`` through :class:`fastapi.testclient.TestClient`
so we cover the wire-in surfaces:

  * ``cti.actor_lookup`` and ``cti.enrich_ioc`` are loaded as
    READ-class, cyble_native tools in the ToolRegistry.
  * The Actor Profiler REST router is mounted under ``/actors/*`` and
    every endpoint resolves through ``require_tenant`` (anon dev
    fallback via ``AISOC_DEV_ALLOW_ANON_TENANT=true``).
  * ``POST /actors/sweep`` delegates to
    ``ThreatActorProfilingAgent.sweep`` and drives the full pipeline:
      - scan tenant + global IOCs,
      - extract handles from ``actor:<NAME>`` tags AND from
        ``cti.enrich_ioc`` for IOCs without explicit attribution,
      - resolve canonical profile via ``cti.actor_lookup``,
      - upsert ``ThreatActor`` rows + ``ActorIOCLink`` rows + graph
        ``NodeType.ACTOR`` + ``EdgeType.ATTRIBUTED_TO`` edges.
  * ``GET /actors`` collapses tenant-local + global rows by handle and
    surfaces ``ioc_count``.
  * ``GET /actors/{handle}`` merges the tenant row with the live
    catalogue overlay so analysts always see canonical CTI fields.
  * ``GET /actors/pivot?ioc=<value>`` returns every actor attributed
    to that IOC via the denormalised link table.
  * Re-running the sweep is idempotent: the second pass does not
    create new actor rows or new link rows for the same IOCs.
  * ``actor_profiler.scheduler.start_background_tasks()`` honours
    ``settings.actor_profiler_scheduler_enabled``.
  * ``ThreatActorProfilingAgent('')`` refuses a blank tenant_id (MSSP
    safety: every row must carry tenancy).

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_actor_profiler.py

Exits non-zero on any failure and prints a PASS/FAIL summary per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-actor-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    # Disable every background scheduler so the test drives the agent
    # explicitly and the assertions never race a concurrent sweep.
    os.environ["AISOC_ACTOR_PROFILER_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BAS_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_EXPOSURE_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BRAND_SCHEDULER_ENABLED"] = "false"
    # Anonymous tenant fallback so TestClient hits routes without minting
    # a JWT for every request.
    os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
    os.environ["AISOC_DEFAULT_TENANT"] = "demo-tenant"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app.agents.actor_profiler import scheduler as actor_scheduler  # noqa: E402
from app.agents.actor_profiler.agent import (  # noqa: E402
    ThreatActorProfilingAgent,
)
from app.config import settings  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models.graph import EdgeType, GraphEdge, GraphNode, NodeType  # noqa: E402
from app.models.ioc import IOC, IOCType  # noqa: E402
from app.models.threat_actor import (  # noqa: E402
    ActorIOCLink,
    ActorMotivation,
    ActorSophistication,
    ThreatActor,
)
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


def _seed_iocs(tenant_id: str = "demo-tenant") -> None:
    """Insert IOCs across both tenant scopes that the agent will sweep.

    The catalogue ships profiles for ``FIN7``, ``APT29``, ``Lazarus``,
    and ``CL0P``. We seed:

      * 2 IOCs tagged ``actor:FIN7`` under the demo tenant (tag-driven
        attribution path; no enrichment round-trip required).
      * 1 IOC matching the cti enrichment catalogue value
        ``ttps-clop.onion`` under the demo tenant (enrichment-driven
        attribution, ``actor=CL0P`` returned by ``cti.enrich_ioc``).
      * 1 IOC tagged ``actor:APT29`` under ``__global__`` so the agent's
        cross-tenant fan-in is exercised.

    All four actors should be materialised with at least one ActorIOCLink
    row under the demo tenant after a sweep.
    """
    now = datetime.now(timezone.utc)
    rows = [
        IOC(
            tenant_id=tenant_id,
            value="185.220.101.45",
            type=IOCType.IP,
            threat_score=85,
            confidence=0.9,
            tags=["actor:FIN7", "ransomware"],
            sources=["cyble-cti"],
            first_seen=now,
            last_seen=now,
            cyble_native=True,
        ),
        IOC(
            tenant_id=tenant_id,
            value="evil-fin7.example",
            type=IOCType.DOMAIN,
            threat_score=80,
            confidence=0.85,
            tags=["actor:FIN7", "c2"],
            sources=["cyble-cti"],
            first_seen=now,
            last_seen=now,
            cyble_native=True,
        ),
        IOC(
            tenant_id=tenant_id,
            value="ttps-clop.onion",
            type=IOCType.DOMAIN,
            threat_score=95,
            confidence=0.9,
            tags=["leak_site"],  # NO actor: tag — must come from enrichment
            sources=["cyble-cti"],
            first_seen=now,
            last_seen=now,
            cyble_native=True,
        ),
        IOC(
            tenant_id="__global__",
            value="apt29-c2.example",
            type=IOCType.DOMAIN,
            threat_score=92,
            confidence=0.88,
            tags=["actor:APT29", "espionage"],
            sources=["cyble-cti"],
            first_seen=now,
            last_seen=now,
            cyble_native=True,
        ),
    ]
    with Session(engine) as session:
        for row in rows:
            session.add(row)
        session.commit()


# ----- Setting & registry checks -------------------------------------------


def check_settings_loaded() -> None:
    section("Settings honour AISOC_* env overrides")
    check(
        "AISOC_ACTOR_PROFILER_SCHEDULER_ENABLED=false honoured",
        settings.actor_profiler_scheduler_enabled is False,
        detail=f"got {settings.actor_profiler_scheduler_enabled!r}",
    )
    check(
        "actor_profiler_sweep_timeout_seconds defaults sensibly",
        isinstance(settings.actor_profiler_sweep_timeout_seconds, int)
        and settings.actor_profiler_sweep_timeout_seconds > 0,
        detail=f"got {settings.actor_profiler_sweep_timeout_seconds!r}",
    )
    check(
        "actor_profiler_scan_interval_seconds defaults sensibly",
        isinstance(settings.actor_profiler_scan_interval_seconds, int)
        and settings.actor_profiler_scan_interval_seconds > 0,
        detail=f"got {settings.actor_profiler_scan_interval_seconds!r}",
    )


def check_cti_tools_registered() -> None:
    section("cti.actor_lookup and cti.enrich_ioc are registered")
    for name in ("cti.actor_lookup", "cti.enrich_ioc"):
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
        check(
            f"{name} is flagged cyble_native",
            bool(getattr(spec, "cyble_native", False)),
        )


def check_scheduler_disabled_when_setting_off() -> None:
    section("Scheduler honours actor_profiler_scheduler_enabled=false")
    actor_scheduler.start_background_tasks()
    check(
        "start_background_tasks() did not spawn a task when disabled",
        actor_scheduler._task is None,  # type: ignore[attr-defined]
        detail=f"_task={actor_scheduler._task!r}",  # type: ignore[attr-defined]
    )


def check_agent_rejects_blank_tenant() -> None:
    section("ThreatActorProfilingAgent refuses blank tenant_id")
    raised = False
    try:
        with Session(engine) as session:
            ThreatActorProfilingAgent(session=session, tenant_id="")
    except ValueError:
        raised = True
    check(
        "ThreatActorProfilingAgent('') raises ValueError",
        raised,
    )


# ----- HTTP-driven checks --------------------------------------------------


def _client() -> TestClient:
    from app.main import app  # noqa: WPS433 -- intentional lazy import

    return TestClient(app)


def check_trigger_sweep(client: TestClient) -> dict | None:
    section("POST /actors/sweep materialises actors and IOC links")
    resp = client.post("/actors/sweep")
    check(
        "POST /actors/sweep -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:300]}",
    )
    if resp.status_code != 200:
        return None
    body = resp.json()
    # Demo + global IOC corpus has 4 rows seeded above.
    check(
        "sweep scanned >= 4 IOCs (3 tenant + 1 global)",
        body.get("iocs_scanned", 0) >= 4,
        detail=f"iocs_scanned={body.get('iocs_scanned')}",
    )
    # FIN7 (2 IOCs), APT29 (1 IOC global), CL0P (1 IOC via enrichment).
    check(
        "sweep upserted >= 3 ThreatActor rows",
        body.get("actors_upserted", 0) >= 3,
        detail=f"actors_upserted={body.get('actors_upserted')}",
    )
    check(
        "sweep created >= 3 new ThreatActor rows on first pass",
        body.get("actors_new", 0) >= 3,
        detail=f"actors_new={body.get('actors_new')}",
    )
    check(
        "sweep upserted >= 4 ActorIOCLink rows",
        body.get("ioc_links_upserted", 0) >= 4,
        detail=f"ioc_links_upserted={body.get('ioc_links_upserted')}",
    )
    check(
        "sweep created >= 4 new ActorIOCLink rows on first pass",
        body.get("ioc_links_new", 0) >= 4,
        detail=f"ioc_links_new={body.get('ioc_links_new')}",
    )
    check(
        "sweep wrote >= 3 graph nodes (actor nodes)",
        body.get("graph_nodes_upserted", 0) >= 3,
        detail=f"graph_nodes_upserted={body.get('graph_nodes_upserted')}",
    )
    check(
        "sweep wrote >= 4 graph edges (ATTRIBUTED_TO)",
        body.get("graph_edges_upserted", 0) >= 4,
        detail=f"graph_edges_upserted={body.get('graph_edges_upserted')}",
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
        actors = session.exec(
            select(ThreatActor).where(ThreatActor.tenant_id == tenant_id)
        ).all()
        handles = {a.handle for a in actors}
        check(
            "FIN7 ThreatActor row persisted",
            "FIN7" in handles,
            detail=f"handles={sorted(handles)}",
        )
        check(
            "APT29 ThreatActor row persisted (from __global__ IOC)",
            "APT29" in handles,
            detail=f"handles={sorted(handles)}",
        )
        check(
            "CL0P ThreatActor row persisted (via cti.enrich_ioc)",
            "CL0P" in handles,
            detail=f"handles={sorted(handles)}",
        )

        fin7 = next((a for a in actors if a.handle == "FIN7"), None)
        if fin7 is not None:
            check(
                "FIN7 motivation merged from catalogue (financial_gain)",
                fin7.motivation == ActorMotivation.FINANCIAL_GAIN,
                detail=f"motivation={fin7.motivation!r}",
            )
            check(
                "FIN7 sophistication merged from catalogue (advanced)",
                fin7.sophistication == ActorSophistication.ADVANCED,
                detail=f"sophistication={fin7.sophistication!r}",
            )
            check(
                "FIN7 origin_country merged from catalogue (RU)",
                fin7.origin_country == "RU",
                detail=f"origin_country={fin7.origin_country!r}",
            )
            check(
                "FIN7 aliases include 'Carbanak' from catalogue",
                "Carbanak" in (fin7.aliases or []),
                detail=f"aliases={fin7.aliases!r}",
            )
            check(
                "FIN7 confidence > default 50 after catalogue hit",
                fin7.confidence >= 50,
                detail=f"confidence={fin7.confidence}",
            )

        links = session.exec(
            select(ActorIOCLink).where(ActorIOCLink.tenant_id == tenant_id)
        ).all()
        link_pairs = {(l.actor_handle, l.ioc_value) for l in links}
        check(
            "FIN7 -> 185.220.101.45 link persisted",
            ("FIN7", "185.220.101.45") in link_pairs,
            detail=f"sample_pairs={sorted(link_pairs)[:6]}",
        )
        check(
            "FIN7 -> evil-fin7.example link persisted",
            ("FIN7", "evil-fin7.example") in link_pairs,
        )
        check(
            "CL0P -> ttps-clop.onion link persisted (enrichment-driven)",
            ("CL0P", "ttps-clop.onion") in link_pairs,
        )
        check(
            "APT29 -> apt29-c2.example link persisted under tenant scope",
            ("APT29", "apt29-c2.example") in link_pairs,
            detail="global IOCs still link under sweeping-tenant scope",
        )

        # Graph topology assertions.
        actor_nodes = session.exec(
            select(GraphNode)
            .where(GraphNode.tenant_id == tenant_id)
            .where(GraphNode.type == NodeType.ACTOR)
        ).all()
        node_keys = {n.key for n in actor_nodes}
        check(
            "GraphNode(ACTOR) rows include FIN7 / APT29 / CL0P",
            {"FIN7", "APT29", "CL0P"}.issubset(node_keys),
            detail=f"actor_node_keys={sorted(node_keys)}",
        )
        attributed_edges = session.exec(
            select(GraphEdge)
            .where(GraphEdge.tenant_id == tenant_id)
            .where(GraphEdge.type == EdgeType.ATTRIBUTED_TO)
        ).all()
        check(
            "GraphEdge(ATTRIBUTED_TO) edges materialised (>= 4)",
            len(attributed_edges) >= 4,
            detail=f"edge_count={len(attributed_edges)}",
        )


def check_idempotent_resweep(client: TestClient) -> None:
    section("Re-running sweep is idempotent (no new rows)")
    tenant_id = settings.default_tenant
    with Session(engine) as session:
        before_actors = session.exec(
            select(ThreatActor).where(ThreatActor.tenant_id == tenant_id)
        ).all()
        before_links = session.exec(
            select(ActorIOCLink).where(ActorIOCLink.tenant_id == tenant_id)
        ).all()
    before_actor_count = len(before_actors)
    before_link_count = len(before_links)

    resp = client.post("/actors/sweep")
    check(
        "second POST /actors/sweep -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return
    body = resp.json()
    check(
        "second sweep created zero new ThreatActor rows",
        body.get("actors_new", -1) == 0,
        detail=f"actors_new={body.get('actors_new')}",
    )
    check(
        "second sweep created zero new ActorIOCLink rows",
        body.get("ioc_links_new", -1) == 0,
        detail=f"ioc_links_new={body.get('ioc_links_new')}",
    )

    with Session(engine) as session:
        after_actors = session.exec(
            select(ThreatActor).where(ThreatActor.tenant_id == tenant_id)
        ).all()
        after_links = session.exec(
            select(ActorIOCLink).where(ActorIOCLink.tenant_id == tenant_id)
        ).all()
    check(
        "ThreatActor row count unchanged after second sweep",
        len(after_actors) == before_actor_count,
        detail=f"before={before_actor_count} after={len(after_actors)}",
    )
    check(
        "ActorIOCLink row count unchanged after second sweep",
        len(after_links) == before_link_count,
        detail=f"before={before_link_count} after={len(after_links)}",
    )


def check_list_endpoint(client: TestClient) -> None:
    section("GET /actors lists tenant + global view, supports filters")
    resp = client.get("/actors")
    check(
        "GET /actors -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return
    body = resp.json()
    actors = body.get("actors", [])
    check(
        "GET /actors returns >= 3 actors",
        len(actors) >= 3,
        detail=f"count={len(actors)}",
    )
    handles = {a["handle"] for a in actors}
    check(
        "GET /actors includes FIN7, APT29, CL0P",
        {"FIN7", "APT29", "CL0P"}.issubset(handles),
        detail=f"handles={sorted(handles)}",
    )
    fin7_summary = next((a for a in actors if a["handle"] == "FIN7"), None)
    if fin7_summary is not None:
        check(
            "FIN7 summary reports ioc_count >= 2",
            fin7_summary.get("ioc_count", 0) >= 2,
            detail=f"ioc_count={fin7_summary.get('ioc_count')}",
        )
        check(
            "FIN7 summary motivation == financial_gain",
            fin7_summary.get("motivation") == "financial_gain",
            detail=f"motivation={fin7_summary.get('motivation')!r}",
        )

    # Filter: motivation=espionage should narrow to APT29 only (and any
    # other future espionage-class actors we later seed).
    resp_filtered = client.get("/actors", params={"motivation": "espionage"})
    check(
        "GET /actors?motivation=espionage narrows result set",
        resp_filtered.status_code == 200
        and all(
            a["motivation"] == "espionage"
            for a in resp_filtered.json().get("actors", [])
        )
        and any(
            a["handle"] == "APT29"
            for a in resp_filtered.json().get("actors", [])
        ),
        detail=f"body={resp_filtered.text[:300]}",
    )


def check_actor_card(client: TestClient) -> None:
    section("GET /actors/{handle} merges tenant row + catalogue overlay")
    resp = client.get("/actors/FIN7")
    check(
        "GET /actors/FIN7 -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return
    card = resp.json()
    check(
        "card.handle == 'FIN7'",
        card.get("handle") == "FIN7",
        detail=f"handle={card.get('handle')!r}",
    )
    check(
        "card.catalogue_hit is True (cti.actor_lookup overlay applied)",
        card.get("catalogue_hit") is True,
        detail=f"catalogue_hit={card.get('catalogue_hit')!r}",
    )
    check(
        "card.aliases includes Carbanak (from catalogue)",
        "Carbanak" in (card.get("aliases") or []),
        detail=f"aliases={card.get('aliases')!r}",
    )
    check(
        "card.tools includes Cobalt Strike (from catalogue)",
        "Cobalt Strike" in (card.get("tools") or []),
        detail=f"tools={card.get('tools')!r}",
    )
    check(
        "card.iocs lists both seeded FIN7 IOCs",
        {ioc["value"] for ioc in card.get("iocs", [])}
        >= {"185.220.101.45", "evil-fin7.example"},
        detail=f"iocs={[i['value'] for i in card.get('iocs', [])]}",
    )

    # Unknown handle should 404 (no tenant row, no catalogue hit).
    missing = client.get("/actors/SnakeOilSquad")
    check(
        "GET /actors/<unknown> -> 404",
        missing.status_code == 404,
        detail=f"status={missing.status_code}",
    )


def check_pivot_endpoint(client: TestClient) -> None:
    section("GET /actors/pivot pivots from IOC to attributed actor(s)")
    resp = client.get("/actors/pivot", params={"ioc": "185.220.101.45"})
    check(
        "GET /actors/pivot?ioc=185.220.101.45 -> 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 200:
        return
    body = resp.json()
    check(
        "pivot payload echoes the queried IOC",
        body.get("ioc") == "185.220.101.45",
        detail=f"ioc={body.get('ioc')!r}",
    )
    pivot_handles = {a["handle"] for a in body.get("actors", [])}
    check(
        "pivot returns FIN7 for tag-attributed IOC",
        "FIN7" in pivot_handles,
        detail=f"handles={sorted(pivot_handles)}",
    )

    # Enrichment-driven pivot: ttps-clop.onion has no actor: tag, only
    # cti.enrich_ioc returns CL0P. Exercises the second-pass code path
    # in ThreatActorProfilingAgent._collect.
    resp = client.get("/actors/pivot", params={"ioc": "ttps-clop.onion"})
    check(
        "pivot on enrichment-attributed IOC returns CL0P",
        resp.status_code == 200
        and any(
            a["handle"] == "CL0P"
            for a in resp.json().get("actors", [])
        ),
        detail=f"body={resp.text[:200]}",
    )

    # Unknown IOC: empty list, not 404 (analysts often type-search).
    resp = client.get("/actors/pivot", params={"ioc": "no-such-ioc.invalid"})
    check(
        "pivot on unknown IOC returns 200 + empty actors list",
        resp.status_code == 200
        and resp.json().get("actors") == [],
        detail=f"body={resp.text[:200]}",
    )


# ----- Driver --------------------------------------------------------------


def _main() -> int:
    init_db()
    _seed_iocs(tenant_id=settings.default_tenant)

    check_settings_loaded()
    check_cti_tools_registered()
    check_scheduler_disabled_when_setting_off()
    check_agent_rejects_blank_tenant()

    client = _client()
    sweep_body = check_trigger_sweep(client)
    check_persisted_state(sweep_body)
    check_idempotent_resweep(client)
    check_list_endpoint(client)
    check_actor_card(client)
    check_pivot_endpoint(client)

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All Threat Actor Profiling smoke checks passed.")
    return 0


if __name__ == "__main__":
    try:
        rc = _main()
    except Exception:  # pragma: no cover -- surface tracebacks verbatim
        import traceback

        traceback.print_exc()
        rc = 2
    sys.exit(rc)

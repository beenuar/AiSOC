"""Marketplace + open-eval benchmark REST API (t3g-mcp-marketplace).

Three thematic surfaces:

1. ``GET /marketplace/...``  — read-only catalog of MCP-aligned tools
   and connectors derived from the live registries. Anyone can hit
   these; they return what the platform *claims* to support, which is
   the same answer an MCP client would get if the platform exposed an
   MCP discovery endpoint. No tenancy gating — the catalog is public
   product information, not customer data.

2. ``POST /benchmark/run``    — kick off a benchmark run against the
   live agent mesh. Persists a leaderboard row.

3. ``GET /benchmark/...``    — leaderboard, scenarios, and per-run
   detail. Read-only.

Design rules:

- Read endpoints are pure-Python: they do not require a tenant context
  because the marketplace and the benchmark suite are both global.
- The benchmark write endpoint is gated behind ``require_tenant`` to
  avoid anonymous compute on the platform; the actual run still uses
  the synthetic ``benchmark-suite`` tenant for data isolation.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import select

from app.cards import agent_card_catalog
from app.db import session_scope
from app.marketplace import (
    BenchmarkOutcome,
    REDTEAM_VERSION,
    RedTeamOutcome,
    benchmark_runner,
    builtin_attacks,
    builtin_scenarios,
    catalog,
    redteam_runner,
)
from app.models.benchmark import BenchmarkRun
from app.models.tool_call import RiskClass
from app.security.tenant import TenantContext, require_tenant

logger = logging.getLogger(__name__)


router = APIRouter(tags=["marketplace"])


# ─── Marketplace ────────────────────────────────────────────────────────


@router.get("/marketplace/tools")
def list_marketplace_tools(
    category: Optional[str] = Query(default=None),
    verified_only: bool = Query(default=False),
    cyble_native_only: bool = Query(default=False),
    max_risk: Optional[str] = Query(
        default=None,
        description="Filter to tools at or below this risk class.",
    ),
) -> dict[str, Any]:
    """Return marketplace tool entries (MCP-aligned).

    The response is a snapshot of the in-process tool registry plus
    curator overlay metadata. Useful for: integration partners
    discovering what an AiSOC deployment can call, internal admin
    surfaces auditing the verified/unverified mix, and the public
    marketplace site that mirrors this JSON.
    """
    risk_filter: Optional[RiskClass] = None
    if max_risk is not None:
        # Accept any of: READ / read / Read / write-reversible /
        # WRITE_REVERSIBLE — the canonical enum values are upper-case
        # with hyphens (READ, WRITE-REVERSIBLE) but partner API consumers
        # routinely lower-case URL params and use underscores.
        normalised = max_risk.upper().replace("_", "-")
        try:
            risk_filter = RiskClass(normalised)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"max_risk must be one of: "
                    f"{', '.join(r.value for r in RiskClass)}"
                ),
            ) from exc

    entries = catalog.list_tools(
        category=category,
        verified_only=verified_only,
        cyble_native_only=cyble_native_only,
        max_risk=risk_filter,
    )
    return {
        "tools": [e.to_dict() for e in entries],
        "total": len(entries),
    }


@router.get("/marketplace/connectors")
def list_marketplace_connectors(
    category: Optional[str] = Query(default=None),
    verified_only: bool = Query(default=False),
) -> dict[str, Any]:
    entries = catalog.list_connectors(
        category=category,
        verified_only=verified_only,
    )
    return {
        "connectors": [e.to_dict() for e in entries],
        "total": len(entries),
    }


@router.get("/marketplace/categories")
def list_marketplace_categories() -> dict[str, Any]:
    return {"categories": catalog.categories()}


@router.get("/marketplace/stats")
def marketplace_stats() -> dict[str, Any]:
    return catalog.stats()


# ─── Benchmark ──────────────────────────────────────────────────────────


class BenchmarkRunRequest(BaseModel):
    """Payload for ``POST /benchmark/run``.

    Empty body = run the full suite. Pass ``scenario_ids`` to run a
    subset (useful when iterating on a single scenario in dev).
    """

    notes: str | None = None
    scenario_ids: list[str] | None = None


@router.get("/benchmark/scenarios")
def list_benchmark_scenarios() -> dict[str, Any]:
    scenarios = builtin_scenarios()
    return {
        "version": "0.1.0",
        "total": len(scenarios),
        "scenarios": [
            {
                "id": s.id,
                "title": s.title,
                "description": s.description,
                "tags": s.tags,
                "expected_keys": sorted(s.expected.keys()),
            }
            for s in scenarios
        ],
    }


@router.post("/benchmark/run")
async def run_benchmark(
    payload: BenchmarkRunRequest = BenchmarkRunRequest(),
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Run the benchmark suite end-to-end and persist a leaderboard row.

    The run executes against the synthetic ``benchmark-suite`` tenant —
    cases never appear in the caller's tenant data. We still gate the
    endpoint behind ``require_tenant`` so anonymous agents can't burn
    LLM credits on the platform.
    """
    try:
        outcome: BenchmarkOutcome = await benchmark_runner.run(
            notes=payload.notes,
            scenario_ids=payload.scenario_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return outcome.to_dict()


@router.get("/benchmark/leaderboard")
def benchmark_leaderboard(
    limit: int = Query(default=20, ge=1, le=100),
    benchmark_version: Optional[str] = Query(default=None),
) -> dict[str, Any]:
    """Top-N open-benchmark runs, ordered by aggregate score then latency.

    Red-team runs share the same :class:`BenchmarkRun` table but live
    under ``benchmark_version`` strings prefixed ``redteam-`` so the two
    surfaces stay grouped on the leaderboard. This endpoint excludes
    them by default.
    """
    with session_scope() as session:
        stmt = select(BenchmarkRun).where(
            ~BenchmarkRun.benchmark_version.startswith("redteam-")
        )
        if benchmark_version is not None:
            stmt = stmt.where(BenchmarkRun.benchmark_version == benchmark_version)
        stmt = stmt.order_by(
            BenchmarkRun.aggregate_score.desc(),
            BenchmarkRun.total_latency_ms.asc(),
        ).limit(limit)
        rows = session.exec(stmt).all()
        leaderboard = [
            {
                "run_id": row.id,
                "benchmark_version": row.benchmark_version,
                "model_provider": row.model_provider,
                "model_name": row.model_name,
                "aggregate_score": row.aggregate_score,
                "pass_rate": row.pass_rate,
                "total_latency_ms": row.total_latency_ms,
                "scenarios_run": list(row.scenarios_run or []),
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "finished_at": (
                    row.finished_at.isoformat() if row.finished_at else None
                ),
                "notes": row.notes,
            }
            for row in rows
        ]
    return {"leaderboard": leaderboard, "total": len(leaderboard)}


@router.get("/benchmark/runs/{run_id}")
def benchmark_run_detail(run_id: int) -> dict[str, Any]:
    with session_scope() as session:
        row = session.get(BenchmarkRun, run_id)
        if row is None:
            raise HTTPException(status_code=404, detail="benchmark run not found")
        snapshot = {
            "run_id": row.id,
            "benchmark_version": row.benchmark_version,
            "model_provider": row.model_provider,
            "model_name": row.model_name,
            "aggregate_score": row.aggregate_score,
            "pass_rate": row.pass_rate,
            "total_latency_ms": row.total_latency_ms,
            "scenarios_run": list(row.scenarios_run or []),
            "outcomes": list(row.outcomes or []),
            "notes": row.notes,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "finished_at": (
                row.finished_at.isoformat() if row.finished_at else None
            ),
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
    return snapshot


# ─── Adversarial / red-team ─────────────────────────────────────────────


class RedTeamRunRequest(BaseModel):
    """Payload for ``POST /redteam/run``.

    Empty body = run every attack in the catalogue.
    """

    notes: str | None = None
    attack_ids: list[str] | None = None


@router.get("/redteam/attacks")
def list_redteam_attacks() -> dict[str, Any]:
    attacks = builtin_attacks()
    return {
        "version": REDTEAM_VERSION,
        "total": len(attacks),
        "attacks": [
            {
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "surface": a.surface,
                "tags": a.tags,
                "expected_keys": sorted(a.expected.keys()),
            }
            for a in attacks
        ],
    }


@router.post("/redteam/run")
async def run_redteam(
    payload: RedTeamRunRequest = RedTeamRunRequest(),
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Drive the adversarial harness and persist a leaderboard row.

    The same :class:`BenchmarkRun` table holds open-benchmark and
    red-team rows. Red-team rows have ``benchmark_version`` prefixed
    ``redteam-`` so the public leaderboard query can split the surfaces.
    """
    try:
        outcome: RedTeamOutcome = await redteam_runner.run(
            notes=payload.notes,
            attack_ids=payload.attack_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return outcome.to_dict()


@router.get("/cards/system")
def get_system_card() -> dict[str, Any]:
    """Top-level platform/system card.

    Mirrors the Hugging Face system-card pattern: lists every agent in
    the mesh, the cross-cutting risk-governance controls, and the
    evaluation surfaces (open benchmark + red-team) used to verify
    them. Public information; no tenant gating.
    """
    return agent_card_catalog.system_card()


@router.get("/cards/agents")
def list_agent_cards() -> dict[str, Any]:
    cards = agent_card_catalog.list_cards()
    return {"total": len(cards), "agents": [c.to_dict() for c in cards]}


@router.get("/cards/agents/{agent}")
def get_agent_card(agent: str) -> dict[str, Any]:
    card = agent_card_catalog.get(agent)
    if card is None:
        raise HTTPException(status_code=404, detail=f"unknown agent: {agent}")
    return card.to_dict()


@router.get("/redteam/leaderboard")
def redteam_leaderboard(
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """Top-N red-team runs (highest block-rate first)."""
    with session_scope() as session:
        stmt = (
            select(BenchmarkRun)
            .where(BenchmarkRun.benchmark_version.startswith("redteam-"))
            .order_by(
                BenchmarkRun.aggregate_score.desc(),
                BenchmarkRun.total_latency_ms.asc(),
            )
            .limit(limit)
        )
        rows = session.exec(stmt).all()
        leaderboard = [
            {
                "run_id": row.id,
                "benchmark_version": row.benchmark_version,
                "model_provider": row.model_provider,
                "model_name": row.model_name,
                "block_rate": row.pass_rate,
                "block_score": row.aggregate_score,
                "total_latency_ms": row.total_latency_ms,
                "attacks_run": list(row.scenarios_run or []),
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "finished_at": (
                    row.finished_at.isoformat() if row.finished_at else None
                ),
                "notes": row.notes,
            }
            for row in rows
        ]
    return {"leaderboard": leaderboard, "total": len(leaderboard)}

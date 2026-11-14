"""Threat Actor Profiling Agent (t3e-actor-profiling).

Runs a three-phase sweep per tenant:

1.  **Scan**     – iterate the tenant's IOCs (plus ``__global__`` CTI
    rows), call ``cti.enrich_ioc`` for any that have actor attribution
    we haven't profiled yet, and group observations by actor handle.
2.  **Resolve**  – for every distinct actor handle, call
    ``cti.actor_lookup`` and merge the canonical profile with the
    observed IOC list into an :class:`ActorProfileFinding`.
3.  **Materialise** – upsert one :class:`ThreatActor` row per actor,
    one :class:`ActorIOCLink` row per observed IOC, and the matching
    ``NodeType.ACTOR`` nodes + ``EdgeType.ATTRIBUTED_TO`` edges in
    the threat graph.

Like :class:`ExposureAgent`, this is not a :class:`BaseAgent` subclass
— it's proactive (scheduler-driven), it owns its own tenancy, and it
never invokes a write tool. Every produced artifact is idempotent: a
second sweep over an unchanged IOC corpus is a no-op (we update
``last_observed`` timestamps but don't churn ID columns).

Tenancy model:

- ``ThreatActor`` rows are written with the agent's ``tenant_id``.
  Global catalogue rows (``tenant_id="__global__"``) are inserted by
  a separate platform sync job, not this agent; we *read* them via
  the actor-card API but never overwrite them here.
- ``ActorIOCLink`` rows are always tenant-scoped to the sweeping
  tenant — even when the underlying IOC came from the global feed
  — because the *fact that this tenant saw this IOC* is tenant data.
- Graph nodes are written under the actor's tenant scope; edges
  inherit the source/destination scope (graph_upsert_edge handles).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from app.agents.actor_profiler.models import (
    ActorProfileFinding,
    ActorProfilingResult,
)
from app.memory.graph import graph_upsert_edge, graph_upsert_node
from app.models.graph import EdgeType, NodeType
from app.models.ioc import IOC
from app.models.threat_actor import (
    ActorIOCLink,
    ActorMotivation,
    ActorSophistication,
    ThreatActor,
)
from app.tools.registry import registry

logger = logging.getLogger("aisoc.actor_profiler")

# Stamp on graph nodes / link rows so downstream consumers can attribute
# changes back to this agent (mirrors ``_SOURCE`` in exposure/agent.py).
_SOURCE = "actor-profiler"


class ThreatActorProfilingAgent:
    """One sweep per tenant; the scheduler instantiates it per-run."""

    def __init__(self, session: Session, *, tenant_id: str) -> None:
        if not tenant_id:
            # Same hard requirement as ExposureAgent / BAS — every
            # ThreatActor row and graph node carries tenant_id, and
            # MSSP deployments must not cross-contaminate.
            raise ValueError("ThreatActorProfilingAgent requires a tenant_id")
        self.session = session
        self.tenant_id = tenant_id

    # ── public entry point ────────────────────────────────────────
    async def sweep(self) -> ActorProfilingResult:
        result = ActorProfilingResult(tenant_id=self.tenant_id)

        # Phase 1: scan IOCs and collect distinct actor observations.
        observations = await self._collect(result)

        # Phase 2: resolve each actor handle against the catalogue.
        findings = await self._resolve(observations, result)
        result.findings = findings

        # Phase 3: persist actors, links, and graph topology.
        self._materialise(findings, result)

        self._log_summary(result)
        return result

    # ── phase 1: scan IOCs ────────────────────────────────────────
    async def _collect(
        self, result: ActorProfilingResult
    ) -> dict[str, list[dict[str, Any]]]:
        """Group IOC observations by canonical actor handle.

        We scan both tenant-owned IOC rows and the ``__global__`` shared
        feed (an MSSP tenant pivoting on a public ransomware IOC still
        wants the attribution). For every IOC with non-trivial signal
        we call ``cti.enrich_ioc`` once — the tool is a pure read and
        we trust the registry's caching layer to keep us cheap.

        Returns a mapping ``handle -> [observation, ...]`` where each
        observation carries the raw IOC data plus enrichment payload.
        """
        observations: dict[str, list[dict[str, Any]]] = {}

        # Pull IOCs visible to this tenant (own + shared feed). We cap
        # the per-sweep scan to avoid runaway memory on tenants with
        # 10k+ IOCs; the scheduler runs us frequently enough that a
        # rolling window is fine.
        scan_limit = 500
        stmt = (
            select(IOC)
            .where(IOC.tenant_id.in_([self.tenant_id, "__global__"]))
            .order_by(IOC.last_seen.desc())
            .limit(scan_limit)
        )
        rows = self.session.exec(stmt).all()
        result.iocs_scanned = len(rows)

        for ioc in rows:
            # First pass: trust the IOC row itself. Many of our CTI
            # ingestion paths already stamp `tags=["actor:APT29"]` on
            # the IOC so we don't have to round-trip to the tool for
            # something we already know.
            handle = _extract_actor_from_tags(ioc.tags)

            # Second pass: if the row didn't carry attribution, ask
            # cti.enrich_ioc. We only call the tool when there's a
            # decent chance of a hit (threat_score > 0) to keep
            # large feeds cheap.
            enrich: dict[str, Any] | None = None
            if not handle and ioc.threat_score and ioc.threat_score > 0:
                enrich = await self._safe_call(
                    "cti.enrich_ioc", ioc=ioc.value, ioc_type=ioc.type.value
                )
                if enrich and enrich.get("found"):
                    handle = (enrich.get("actor") or "").strip() or None

            if not handle:
                continue

            obs = {
                "value": ioc.value,
                "type": ioc.type.value,
                "threat_score": int(ioc.threat_score or 0),
                "confidence": int(round((ioc.confidence or 0.0) * 100)),
                "source": "ioc.tags" if enrich is None else "cti.enrich_ioc",
                "first_seen": ioc.first_seen,
                "last_seen": ioc.last_seen,
                "tenant_id": ioc.tenant_id,
            }
            observations.setdefault(handle, []).append(obs)

        return observations

    # ── phase 2: resolve actor handles against catalogue ─────────
    async def _resolve(
        self,
        observations: dict[str, list[dict[str, Any]]],
        result: ActorProfilingResult,
    ) -> list[ActorProfileFinding]:
        """Materialise one :class:`ActorProfileFinding` per actor handle.

        A finding is built even when ``cti.actor_lookup`` returns
        ``found=False`` — we still want the IOC pivot to work for
        novel/unattributed handles. Catalogue misses are counted so
        the scheduler can surface "your CTI catalogue is stale" in
        the sweep summary.
        """
        findings: list[ActorProfileFinding] = []

        for handle, obs_list in observations.items():
            profile = await self._safe_call("cti.actor_lookup", actor=handle)
            catalogue_hit = bool(profile and profile.get("found"))
            if not catalogue_hit:
                result.catalogue_misses += 1
                profile = {}  # normalised empty profile for downstream
            findings.append(
                ActorProfileFinding(
                    handle=handle,
                    profile=profile or {},
                    observed_iocs=obs_list,
                    catalogue_hit=catalogue_hit,
                )
            )

        return findings

    # ── phase 3: persist ──────────────────────────────────────────
    def _materialise(
        self,
        findings: list[ActorProfileFinding],
        result: ActorProfilingResult,
    ) -> None:
        """Idempotent upserts for actor rows, link rows, and graph topology."""
        now = datetime.now(timezone.utc)

        for finding in findings:
            handle = finding.handle
            try:
                # 1) ThreatActor row (tenant-scoped). _upsert_actor already
                # commits self.session so the row is visible to the
                # graph subsystem's separate session_scope.
                actor_row, created = self._upsert_actor(finding, now=now)
                result.actors_upserted += 1
                if created:
                    result.actors_new += 1

                # 2) Graph: NodeType.ACTOR.
                node_id = graph_upsert_node(
                    tenant_id=self.tenant_id,
                    type=NodeType.ACTOR,
                    key=handle,
                    label=handle,
                    props={
                        "source": _SOURCE,
                        "motivation": actor_row.motivation.value,
                        "sophistication": actor_row.sophistication.value,
                        "origin_country": actor_row.origin_country or "",
                        "aliases": list(actor_row.aliases or []),
                        "confidence": actor_row.confidence,
                    },
                    tags=["actor", _SOURCE],
                )
                if node_id:
                    result.graph_nodes_upserted += 1

                # 3) For each observed IOC: link row + IOC graph node
                # (defensive — IOC nodes usually exist already) + the
                # ATTRIBUTED_TO edge from IOC -> ACTOR.
                #
                # We commit the link write *before* the graph call so the
                # graph subsystem's separate session_scope() doesn't fight
                # this session for the SQLite write lock. SQLite holds a
                # per-DB write lock for any pending transaction; with two
                # sessions both wanting to write we deadlock without this
                # explicit handoff.
                for obs in finding.observed_iocs:
                    self._upsert_link(
                        handle=handle,
                        obs=obs,
                        now=now,
                        result=result,
                    )
                    self.session.commit()
                    self._upsert_ioc_edge(
                        handle=handle,
                        obs=obs,
                        result=result,
                    )
            except Exception as exc:  # noqa: BLE001 — survive per-actor failures
                logger.exception(
                    "actor_profiler: materialise failed tenant=%s actor=%s",
                    self.tenant_id,
                    handle,
                )
                result.errors.append(f"{handle}: {exc!s}")
                # Roll back any half-applied link insert so the next
                # actor's sweep starts on a clean transaction.
                try:
                    self.session.rollback()
                except Exception:  # noqa: BLE001
                    pass

        # Final commit is a no-op when every per-IOC iteration already
        # committed; kept for safety in case future code paths add work
        # to ``self.session`` after the loop.
        self.session.commit()

    # ── persistence helpers ───────────────────────────────────────
    def _upsert_actor(
        self, finding: ActorProfileFinding, *, now: datetime
    ) -> tuple[ThreatActor, bool]:
        """Insert-or-update the per-tenant ThreatActor row.

        Returns ``(row, created)``. We merge catalogue data on top of
        any existing tenant fields conservatively: if the catalogue
        has a value and the tenant row doesn't, we adopt it; if both
        have values we keep the tenant's (it's the local override).
        """
        row = self.session.exec(
            select(ThreatActor)
            .where(ThreatActor.tenant_id == self.tenant_id)
            .where(ThreatActor.handle == finding.handle)
        ).first()

        profile = finding.profile or {}
        created = False
        if row is None:
            row = ThreatActor(
                tenant_id=self.tenant_id,
                handle=finding.handle,
                aliases=list(profile.get("aliases") or []),
                description=str(profile.get("description") or ""),
                motivation=_coerce_motivation(profile.get("motivation")),
                sophistication=_coerce_sophistication(
                    profile.get("sophistication")
                ),
                origin_country=profile.get("origin_country") or None,
                target_sectors=list(profile.get("target_sectors") or []),
                target_regions=list(profile.get("target_regions") or []),
                techniques=list(profile.get("techniques") or []),
                tools=list(profile.get("tools") or []),
                campaigns=list(profile.get("campaigns") or []),
                references=list(profile.get("references") or []),
                confidence=_coerce_confidence(
                    profile.get("confidence"), default=40
                ),
                first_observed=now,
                last_observed=now,
                created_at=now,
                updated_at=now,
            )
            created = True
        else:
            # Conservative merge: only adopt catalogue fields the
            # tenant row left empty. Tenants intentionally override
            # the global profile in places, so we don't stomp them.
            if profile:
                if not row.aliases:
                    row.aliases = list(profile.get("aliases") or row.aliases)
                if not row.description and profile.get("description"):
                    row.description = str(profile["description"])
                if row.motivation == ActorMotivation.UNKNOWN:
                    row.motivation = _coerce_motivation(profile.get("motivation"))
                if row.sophistication == ActorSophistication.UNKNOWN:
                    row.sophistication = _coerce_sophistication(
                        profile.get("sophistication")
                    )
                if not row.origin_country:
                    row.origin_country = profile.get("origin_country") or None
                if not row.target_sectors:
                    row.target_sectors = list(profile.get("target_sectors") or [])
                if not row.target_regions:
                    row.target_regions = list(profile.get("target_regions") or [])
                if not row.techniques:
                    row.techniques = list(profile.get("techniques") or [])
                if not row.tools:
                    row.tools = list(profile.get("tools") or [])
                if not row.campaigns:
                    row.campaigns = list(profile.get("campaigns") or [])
                if not row.references:
                    row.references = list(profile.get("references") or [])
            # Every sweep that re-observes the actor bumps last_observed
            # and nudges confidence upward (capped at 95 — we never claim
            # 100% from heuristic attribution alone).
            row.last_observed = now
            row.updated_at = now
            if finding.catalogue_hit and row.confidence < 95:
                row.confidence = min(95, row.confidence + 5)

        self.session.add(row)
        self.session.commit()
        self.session.refresh(row)
        return row, created

    def _upsert_link(
        self,
        *,
        handle: str,
        obs: dict[str, Any],
        now: datetime,
        result: ActorProfilingResult,
    ) -> None:
        link = self.session.exec(
            select(ActorIOCLink)
            .where(ActorIOCLink.tenant_id == self.tenant_id)
            .where(ActorIOCLink.actor_handle == handle)
            .where(ActorIOCLink.ioc_value == obs["value"])
        ).first()

        if link is None:
            link = ActorIOCLink(
                tenant_id=self.tenant_id,
                actor_handle=handle,
                ioc_value=obs["value"],
                ioc_type=obs.get("type", "unknown"),
                confidence=int(obs.get("confidence") or 50),
                source=str(obs.get("source") or "cti.enrich_ioc"),
                first_seen=obs.get("first_seen") or now,
                last_seen=obs.get("last_seen") or now,
            )
            result.ioc_links_new += 1
        else:
            link.last_seen = obs.get("last_seen") or now
            link.ioc_type = obs.get("type", link.ioc_type)
            # Bump confidence on repeat observations, capped at 95.
            new_conf = int(obs.get("confidence") or link.confidence)
            link.confidence = min(95, max(link.confidence, new_conf))

        self.session.add(link)
        result.ioc_links_upserted += 1

    def _upsert_ioc_edge(
        self,
        *,
        handle: str,
        obs: dict[str, Any],
        result: ActorProfilingResult,
    ) -> None:
        """Ensure the IOC node + ATTRIBUTED_TO edge exist in the graph.

        We upsert the IOC node defensively — the IOC ingestion path
        usually creates it, but on a fresh DB or a backfill it might
        not yet exist. Idempotent so no harm in double-writing.
        """
        ioc_value = obs["value"]
        ioc_type = obs.get("type", "unknown")
        ioc_tenant = obs.get("tenant_id") or self.tenant_id

        # IOC node (cheap idempotent upsert).
        graph_upsert_node(
            tenant_id=ioc_tenant,
            type=NodeType.IOC,
            key=ioc_value,
            label=ioc_value,
            props={"ioc_type": ioc_type, "source": _SOURCE},
            tags=["ioc"],
        )
        # The ATTRIBUTED_TO edge always lives in the *actor's* tenant
        # scope (self.tenant_id) because that's the analyst-facing
        # relationship; cross-scope IOCs (from __global__) still resolve
        # because graph_upsert_edge accepts the (type, key) tuples by
        # value, not by id.
        edge_id = graph_upsert_edge(
            tenant_id=self.tenant_id,
            src=(NodeType.IOC, ioc_value),
            dst=(NodeType.ACTOR, handle),
            type=EdgeType.ATTRIBUTED_TO,
            weight=float(obs.get("confidence") or 50) / 100.0,
            props={
                "source": _SOURCE,
                "ioc_type": ioc_type,
                "threat_score": obs.get("threat_score") or 0,
            },
        )
        if edge_id:
            result.graph_edges_upserted += 1

    # ── infrastructure helpers ────────────────────────────────────
    async def _safe_call(
        self, tool_name: str, /, **params: Any
    ) -> dict[str, Any] | None:
        """Best-effort tool dispatch — mirrors ExposureAgent._safe_call.

        Every CTI tool we call is ``RiskClass.READ`` so there's nothing
        to gate; we run outside any case context, so we deliberately
        bypass :class:`BaseAgent.call_tool`. Failures are logged and
        return ``None`` — a single tool blip shouldn't abort the sweep.
        """
        td = registry.get(tool_name)
        if td is None:
            logger.warning("actor_profiler: missing tool %s", tool_name)
            return None
        if not registry.is_allowed_for_tenant(tool_name, self.tenant_id):
            logger.info(
                "actor_profiler: tool %s denied for tenant %s; skipping",
                tool_name,
                self.tenant_id,
            )
            return None
        try:
            result = await td.handler(**params)
        except Exception:  # noqa: BLE001 — observability + survive
            logger.exception(
                "actor_profiler: tool %s raised tenant=%s params=%s",
                tool_name,
                self.tenant_id,
                params,
            )
            return None
        if not isinstance(result, dict):
            return None
        return result

    def _log_summary(self, result: ActorProfilingResult) -> None:
        logger.info(
            "actor_profiler:sweep_complete tenant=%s iocs_scanned=%d "
            "actors=%d (new=%d) links=%d (new=%d) graph_nodes=%d "
            "graph_edges=%d catalogue_misses=%d errors=%d",
            self.tenant_id,
            result.iocs_scanned,
            result.actors_upserted,
            result.actors_new,
            result.ioc_links_upserted,
            result.ioc_links_new,
            result.graph_nodes_upserted,
            result.graph_edges_upserted,
            result.catalogue_misses,
            len(result.errors),
        )


# ── module-level helpers ──────────────────────────────────────────
def _extract_actor_from_tags(tags: list[str] | None) -> str | None:
    """Pull ``actor:<handle>`` out of an IOC tag list.

    Several ingestion paths already stamp attribution as a tag so we
    avoid an unnecessary ``cti.enrich_ioc`` round-trip.
    """
    if not tags:
        return None
    for tag in tags:
        if isinstance(tag, str) and tag.lower().startswith("actor:"):
            handle = tag.split(":", 1)[1].strip()
            if handle:
                return handle
    return None


def _coerce_motivation(value: Any) -> ActorMotivation:
    if not value:
        return ActorMotivation.UNKNOWN
    v = str(value).strip().lower()
    # Catalogue uses "financial" while the enum is FINANCIAL_GAIN —
    # accept both so we don't lose attribution to a string mismatch.
    if v in {"financial", "financial_gain", "money", "criminal"}:
        return ActorMotivation.FINANCIAL_GAIN
    if v in {"espionage", "intelligence", "state", "nation_state"}:
        return ActorMotivation.ESPIONAGE
    if v in {"hacktivism", "ideology", "ideological"}:
        return ActorMotivation.HACKTIVISM
    if v in {"sabotage", "destruction", "wiper"}:
        return ActorMotivation.SABOTAGE
    if v in {"notoriety", "ego", "reputation"}:
        return ActorMotivation.NOTORIETY
    return ActorMotivation.UNKNOWN


def _coerce_sophistication(value: Any) -> ActorSophistication:
    if not value:
        return ActorSophistication.UNKNOWN
    v = str(value).strip().lower()
    if v in {"minimal", "low", "novice"}:
        return ActorSophistication.MINIMAL
    if v in {"intermediate", "medium", "moderate"}:
        return ActorSophistication.INTERMEDIATE
    if v in {"advanced", "high"}:
        return ActorSophistication.ADVANCED
    if v in {"expert", "nation_state", "apt", "tier1"}:
        return ActorSophistication.EXPERT
    return ActorSophistication.UNKNOWN


def _coerce_confidence(value: Any, *, default: int = 50) -> int:
    if value is None:
        return default
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    # Accept both 0-1 floats and 0-100 ints.
    if 0.0 <= v <= 1.0:
        return int(round(v * 100))
    return max(0, min(100, int(round(v))))


__all__ = ["ThreatActorProfilingAgent"]

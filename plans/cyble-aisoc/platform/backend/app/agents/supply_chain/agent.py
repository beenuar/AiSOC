"""Third-party / Supply-Chain Risk Fusion Agent (t3f-supply-chain).

Per-tenant sweep that fuses Cyble's CTI surface against the tenant's
declared third-party footprint:

1.  **Collect** – iterate each active :class:`Vendor` for the tenant.
    For every vendor call the relevant CTI tools (dark-web mention
    search, brand intel, ASM lookup, vuln intel) and turn each hit
    into a :class:`SignalObservation`.
2.  **Score**   – multiply per-signal scores by the vendor's
    criticality weight to produce a per-vendor ``risk_score``. Combine
    with the rolling sum of recent signals already in the audit log
    to decide the gating ``rolling_score``.
3.  **Materialise** – idempotently insert :class:`VendorRiskSignal`
    rows for everything observed this sweep, upsert
    ``NodeType.VENDOR`` and ``EdgeType.DEPENDS_ON`` edges in the
    graph, and open a proactive :class:`Case` when ``rolling_score``
    crosses ``settings.supply_chain_case_open_threshold``.

Tenancy model:

- Every Vendor row is tenant-private. Cross-tenant signal sharing is
  Theme 3b (federated) territory — out of scope here.
- Cases inherit the sweeping tenant. The agent never invokes a
  WRITE-class tool (no remediation actions) — it only opens the
  case and records a HANDOFF trace so the Responder picks it up.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from app.agents.supply_chain.models import (
    SignalObservation,
    SupplyChainSweepResult,
    VendorFinding,
    VendorSnapshot,
)
from app.config import settings
from app.memory.graph import graph_upsert_edge, graph_upsert_node
from app.models.case import Case, CaseStatus, Severity
from app.models.graph import EdgeType, NodeType
from app.models.supply_chain import (
    SignalKind,
    Vendor,
    VendorCriticality,
    VendorRiskSignal,
)
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.realtime.case_events import publish_case_created
from app.tools.registry import registry

logger = logging.getLogger("aisoc.supply_chain")

_SOURCE = "supply-chain-agent"

# Per-criticality multiplier applied to per-signal scores. Critical
# vendors (IdP, payroll) have outsized blast radius so their breach
# signals deserve higher gravity even when the underlying CTI score
# is moderate. The multipliers are deliberately small: a critical
# vendor with one low-severity signal still shouldn't auto-open a
# case; the threshold remains the gate.
_CRITICALITY_MULTIPLIER: dict[VendorCriticality, float] = {
    VendorCriticality.LOW: 0.5,
    VendorCriticality.MEDIUM: 1.0,
    VendorCriticality.HIGH: 1.5,
    VendorCriticality.CRITICAL: 2.0,
}


class SupplyChainAgent:
    """One sweep per tenant; the scheduler instantiates it per-run."""

    def __init__(self, session: Session, *, tenant_id: str) -> None:
        if not tenant_id:
            # Same hard requirement as ExposureAgent / Actor Profiler:
            # every Vendor / VendorRiskSignal row carries tenant_id and
            # MSSP deployments must not cross-contaminate.
            raise ValueError("SupplyChainAgent requires a tenant_id")
        self.session = session
        self.tenant_id = tenant_id

    # ── public entry point ────────────────────────────────────────
    async def sweep(self) -> SupplyChainSweepResult:
        result = SupplyChainSweepResult(tenant_id=self.tenant_id)

        vendors = self._load_active_vendors()
        result.vendors_scanned = len(vendors)

        for vendor in vendors:
            try:
                finding = await self._collect_vendor(vendor)
                self._compute_rolling_score(vendor, finding)
                await self._materialise(vendor, finding, result)
                result.findings.append(finding)
            except Exception as exc:  # noqa: BLE001 — survive per-vendor
                logger.exception(
                    "supply_chain: vendor sweep failed tenant=%s slug=%s",
                    self.tenant_id,
                    vendor.slug,
                )
                result.errors.append(f"{vendor.slug}: {exc!s}")
                # Make sure a half-applied transaction doesn't poison
                # the next vendor in the loop.
                try:
                    self.session.rollback()
                except Exception:  # noqa: BLE001
                    pass

        self._log_summary(result)
        return result

    # ── phase 1: load active vendors for this tenant ──────────────
    def _load_active_vendors(self) -> list[VendorSnapshot]:
        """Load every active Vendor and freeze it as a snapshot.

        Snapshots are session-detached so subsequent commits +
        per-vendor failure rollbacks don't expire SQLAlchemy state and
        force a refresh-on-access mid-loop. The vendor row is
        re-loaded by primary key inside :meth:`_materialise` only when
        we need the live row to update something.
        """
        rows = self.session.exec(
            select(Vendor)
            .where(Vendor.tenant_id == self.tenant_id)
            .where(Vendor.active == True)  # noqa: E712 — SQLModel idiom
            .order_by(Vendor.criticality.desc(), Vendor.name.asc())
        ).all()
        snapshots: list[VendorSnapshot] = []
        for row in rows:
            snapshots.append(
                VendorSnapshot(
                    id=int(row.id) if row.id is not None else 0,
                    tenant_id=row.tenant_id,
                    slug=row.slug,
                    name=row.name,
                    category=row.category,
                    criticality=row.criticality,
                    description=row.description or "",
                    monitored_terms=list(row.monitored_terms or []),
                    monitored_domains=list(row.monitored_domains or []),
                    monitored_cves=list(row.monitored_cves or []),
                    affected_assets=list(row.affected_assets or []),
                    affected_users=list(row.affected_users or []),
                    contact_email=row.contact_email,
                    active=row.active,
                )
            )
        return snapshots

    # ── phase 1b: per-vendor CTI fan-out ──────────────────────────
    async def _collect_vendor(self, vendor: VendorSnapshot) -> VendorFinding:
        """Run the CTI fan-out and produce a :class:`VendorFinding`.

        Each CTI tool is best-effort: a single tool failure must not
        abort the per-vendor sweep. The agent never invokes anything
        WRITE-class so there's no rollback concern — a missed dark-web
        check just means the next sweep picks it up.
        """
        observations: list[SignalObservation] = []

        # Dark-web mentions: scan every monitored term for leak-site
        # chatter referencing the vendor or its products.
        for term in self._search_terms(vendor):
            payload = await self._safe_call(
                "cti.darkweb_search", query=term, days=30
            )
            for hit in (payload or {}).get("hits", []) or []:
                obs = _darkweb_to_signal(term, hit)
                if obs is not None:
                    observations.append(obs)

        # Brand intel: typosquats / fake-app campaigns against vendor
        # brand. A burst of fresh typosquats often precedes a phishing
        # campaign that *uses* the vendor's name to social-engineer
        # tenant employees.
        brand_payload = await self._safe_call(
            "cti.brand_intel", brand=vendor.name
        )
        if brand_payload:
            obs = _brand_to_signal(vendor.name, brand_payload)
            if obs is not None:
                observations.append(obs)

        # ASM exposures on the vendor's perimeter. We only run if the
        # tenant supplied vendor domains; firing ASM against an
        # arbitrary vendor name is noisy and rarely actionable.
        for domain in vendor.monitored_domains or []:
            asm_payload = await self._safe_call("cti.asm_lookup", domain=domain)
            for finding in (asm_payload or {}).get("high_risk_findings", []) or []:
                obs = _asm_to_signal(domain, finding)
                if obs is not None:
                    observations.append(obs)

        # Vuln intel: tenant-tracked CVEs against the vendor's stack.
        # Each CVE is one signal; the per-signal score reflects the
        # ``ransomware_use`` / ``exploited_in_wild`` flags from the
        # tool payload.
        for cve in vendor.monitored_cves or []:
            vuln_payload = await self._safe_call("cti.vuln_intel", cve=cve)
            obs = _vuln_to_signal(cve, vuln_payload or {})
            if obs is not None:
                observations.append(obs)

        # Apply per-criticality multiplier once at finding scope so
        # the per-signal scores stay comparable across vendors.
        multiplier = _CRITICALITY_MULTIPLIER.get(vendor.criticality, 1.0)
        risk_score = int(round(sum(o.score for o in observations) * multiplier))

        return VendorFinding(
            vendor_id=vendor.id,
            slug=vendor.slug,
            name=vendor.name,
            risk_score=risk_score,
            observations=observations,
        )

    @staticmethod
    def _search_terms(vendor: VendorSnapshot) -> list[str]:
        terms = list(vendor.monitored_terms or [])
        if vendor.name and vendor.name not in terms:
            terms.append(vendor.name)
        if vendor.slug and vendor.slug not in terms:
            terms.append(vendor.slug)
        # De-dupe while preserving order (so explicit tenant terms run
        # first; helpful when a tenant explicitly names a product line).
        seen: set[str] = set()
        out: list[str] = []
        for t in terms:
            key = t.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(t)
        return out

    # ── phase 2: combine sweep score with the rolling history ─────
    def _compute_rolling_score(
        self, vendor: VendorSnapshot, finding: VendorFinding
    ) -> None:
        """Add stale-but-still-fresh past-sweep signals to this sweep's score.

        A vendor that crosses the case-open threshold by *accumulating*
        moderate signals over a week should still trigger a case; the
        per-sweep ``risk_score`` alone wouldn't catch that. We sum the
        scores of past signals that are within the configured rolling
        window and that haven't already been attributed to a case.
        """
        window = timedelta(
            days=settings.supply_chain_rolling_window_days
        )
        cutoff = datetime.now(timezone.utc) - window
        rows = self.session.exec(
            select(VendorRiskSignal)
            .where(VendorRiskSignal.tenant_id == self.tenant_id)
            .where(VendorRiskSignal.vendor_id == vendor.id)
            .where(VendorRiskSignal.observed_at >= cutoff)
            .where(VendorRiskSignal.case_id == None)  # noqa: E711 — SQL NULL
        ).all()
        historical = sum(int(r.score) for r in rows)
        finding.rolling_score = finding.risk_score + historical

    # ── phase 3: persist + open case + write graph topology ───────
    async def _materialise(
        self,
        vendor: VendorSnapshot,
        finding: VendorFinding,
        result: SupplyChainSweepResult,
    ) -> None:
        """Write signals, graph topology, and (optionally) open a case."""
        now = datetime.now(timezone.utc)

        # 1) Append-only signal rows. Idempotent on
        # (tenant_id, vendor_id, kind, source, observed_at) — we set
        # observed_at to ``now`` for every row in this sweep so a
        # second sweep on the same wall-clock tick can't double-write
        # but the next sweep will record a fresh row (giving us the
        # "this leak has been hot for N days" signal-history surface).
        new_signal_ids: list[int] = []
        for obs in finding.observations:
            row = VendorRiskSignal(
                tenant_id=self.tenant_id,
                vendor_id=vendor.id,
                kind=obs.kind,
                source=obs.source,
                score=obs.score,
                summary=obs.summary,
                evidence=obs.evidence,
                observed_at=now,
            )
            self.session.add(row)
            try:
                self.session.commit()
                self.session.refresh(row)
                if row.id is not None:
                    new_signal_ids.append(row.id)
                    result.signals_recorded += 1
            except Exception:  # noqa: BLE001
                # Idempotent uniq violation (same source/kind at the
                # same observed_at) — roll back and continue.
                self.session.rollback()

        # 2) Graph: VENDOR node + DEPENDS_ON edges from each affected
        # asset/user. We stamp source=_SOURCE so the UI can attribute.
        node_id = graph_upsert_node(
            tenant_id=self.tenant_id,
            type=NodeType.VENDOR,
            key=vendor.slug,
            label=vendor.name,
            props={
                "source": _SOURCE,
                "category": vendor.category.value,
                "criticality": vendor.criticality.value,
                "risk_score": finding.risk_score,
                "rolling_score": finding.rolling_score,
                "last_swept_at": now.isoformat(),
            },
            tags=["vendor", vendor.category.value, _SOURCE],
        )
        if node_id:
            result.graph_nodes_upserted += 1

        for host in vendor.affected_assets or []:
            if not host:
                continue
            edge_id = graph_upsert_edge(
                tenant_id=self.tenant_id,
                src=(NodeType.ASSET, host),
                dst=(NodeType.VENDOR, vendor.slug),
                type=EdgeType.DEPENDS_ON,
                props={"source": _SOURCE},
            )
            if edge_id:
                result.graph_edges_upserted += 1

        for user in vendor.affected_users or []:
            if not user:
                continue
            edge_id = graph_upsert_edge(
                tenant_id=self.tenant_id,
                src=(NodeType.USER, user),
                dst=(NodeType.VENDOR, vendor.slug),
                type=EdgeType.DEPENDS_ON,
                props={"source": _SOURCE},
            )
            if edge_id:
                result.graph_edges_upserted += 1

        # 3) Case-open gate. Threshold compares against rolling_score
        # so accumulating moderate signals can still trigger.
        if finding.rolling_score < settings.supply_chain_case_open_threshold:
            return
        if not finding.observations:
            # Defensive: don't open a case off purely-historical
            # signals. If nothing fired this sweep, the threshold
            # crossing was already represented by an earlier case
            # (or the rolling window is misconfigured).
            return

        case_id = await self._open_case(vendor, finding, now=now)
        if case_id is not None:
            finding.case_opened = case_id
            result.cases_opened.append(case_id)
            # Backfill the link from each fresh signal row to the case
            # so the analyst sees "these are the signals that opened
            # this case" in the audit log.
            for sig_id in new_signal_ids:
                row = self.session.get(VendorRiskSignal, sig_id)
                if row is not None:
                    row.case_id = case_id
                    self.session.add(row)
            self.session.commit()
            self._log_trace(case_id, vendor, finding)

    # ── helpers ────────────────────────────────────────────────────
    async def _open_case(
        self,
        vendor: VendorSnapshot,
        finding: VendorFinding,
        *,
        now: datetime,
    ) -> int | None:
        """Open a proactive supply-chain risk case."""
        # Severity ladder: scale with rolling_score, capped at HIGH so
        # the agent never opens a CRITICAL case autonomously — that
        # decision belongs to a human.
        rolling = finding.rolling_score
        if rolling >= 150:
            severity = Severity.HIGH
        elif rolling >= 90:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        narrative_lines = [
            f"Third-party risk: {vendor.name} ({vendor.category.value}, "
            f"criticality={vendor.criticality.value}).",
            f"Rolling 30-day risk score: {finding.rolling_score} "
            f"(this sweep contributed {finding.risk_score}).",
            "",
            "Signals observed this sweep:",
        ]
        for obs in finding.observations:
            narrative_lines.append(
                f"- [{obs.kind.value}] {obs.summary} (score={obs.score}, "
                f"source={obs.source})"
            )
        narrative = "\n".join(narrative_lines)

        case = Case(
            tenant_id=self.tenant_id,
            title=f"[Supply chain] {vendor.name} risk threshold crossed",
            narrative=narrative,
            status=CaseStatus.NEW,
            severity=severity,
            affected_users=list(vendor.affected_users or []),
            affected_hosts=list(vendor.affected_assets or []),
            iocs=[],
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)
        if case.id is None:
            return None

        try:
            await publish_case_created(
                tenant_id=self.tenant_id,
                case_id=case.id,
                title=case.title,
                severity=severity.value,
                status=case.status.value,
            )
        except Exception:  # noqa: BLE001 — realtime is best-effort
            logger.exception(
                "supply_chain: realtime case publish failed case=%s", case.id
            )
        return case.id

    def _log_trace(
        self,
        case_id: int,
        vendor: VendorSnapshot,
        finding: VendorFinding,
    ) -> None:
        try:
            top_signals = sorted(
                finding.observations, key=lambda o: o.score, reverse=True
            )[:3]
            top_kinds = ", ".join(o.kind.value for o in top_signals) or "(none)"
            summary = (
                f"Supply-chain risk handoff for {vendor.name} "
                f"(rolling={finding.rolling_score}, top={top_kinds})"
            )
            trace = AgentTrace(
                tenant_id=self.tenant_id,
                case_id=case_id,
                agent=AgentName.SUPPLY_CHAIN,
                step=TraceStep.HANDOFF,
                summary=summary,
                detail={
                    "vendor_slug": vendor.slug,
                    "vendor_name": vendor.name,
                    "category": vendor.category.value,
                    "criticality": vendor.criticality.value,
                    "risk_score": finding.risk_score,
                    "rolling_score": finding.rolling_score,
                    "signals": [
                        {
                            "kind": o.kind.value,
                            "score": o.score,
                            "summary": o.summary,
                            "source": o.source,
                        }
                        for o in finding.observations
                    ],
                    "source": _SOURCE,
                },
            )
            self.session.add(trace)
            self.session.commit()
        except Exception:  # noqa: BLE001 — trace failures must not abort
            logger.exception(
                "supply_chain: trace write failed case=%s", case_id
            )

    async def _safe_call(
        self, tool_name: str, /, **params: Any
    ) -> dict[str, Any] | None:
        """Best-effort tool dispatch — mirrors ActorProfiler._safe_call."""
        td = registry.get(tool_name)
        if td is None:
            logger.warning("supply_chain: missing tool %s", tool_name)
            return None
        if not registry.is_allowed_for_tenant(tool_name, self.tenant_id):
            logger.info(
                "supply_chain: tool %s denied for tenant %s; skipping",
                tool_name,
                self.tenant_id,
            )
            return None
        try:
            result = await td.handler(**params)
        except Exception:  # noqa: BLE001 — observability + survive
            logger.exception(
                "supply_chain: tool %s raised tenant=%s params=%s",
                tool_name,
                self.tenant_id,
                params,
            )
            return None
        if not isinstance(result, dict):
            return None
        return result

    def _log_summary(self, result: SupplyChainSweepResult) -> None:
        logger.info(
            "supply_chain:sweep_complete tenant=%s vendors=%d signals=%d "
            "cases_opened=%d nodes=%d edges=%d errors=%d",
            self.tenant_id,
            result.vendors_scanned,
            result.signals_recorded,
            len(result.cases_opened),
            result.graph_nodes_upserted,
            result.graph_edges_upserted,
            len(result.errors),
        )


# ── module-level: CTI payload normalisers ─────────────────────────


def _darkweb_to_signal(
    term: str, hit: dict[str, Any]
) -> SignalObservation | None:
    """Turn a single ``cti.darkweb_search`` hit into an observation.

    The Cyble dark-web tool returns hits with ``forum`` / ``ts`` /
    ``snippet`` / ``confidence`` fields; we score by confidence band
    so a single ``high``-confidence forum post drives more risk than
    a smattering of ``low``-confidence chatter.
    """
    if not isinstance(hit, dict):
        return None
    confidence = str(hit.get("confidence") or "low").lower()
    score_table = {"high": 35, "medium": 20, "low": 8}
    score = score_table.get(confidence, 8)
    snippet = str(hit.get("snippet") or "")[:280]
    return SignalObservation(
        kind=SignalKind.DARKWEB_LEAK,
        source="cti.darkweb_search",
        score=score,
        summary=f"Dark-web mention referencing '{term}' on {hit.get('forum', 'unknown')}",
        evidence={
            "term": term,
            "forum": hit.get("forum"),
            "ts": hit.get("ts"),
            "snippet": snippet,
            "confidence": confidence,
        },
    )


def _brand_to_signal(
    name: str, payload: dict[str, Any]
) -> SignalObservation | None:
    """Turn a ``cti.brand_intel`` payload into one observation per vendor.

    We collapse the per-typosquat detail into a single signal because
    each typosquat already gets its own Brand Responder case (Theme
    3c). The supply-chain signal here is the "your vendor is being
    impersonated" *meta*-fact, not the individual squats.
    """
    if not isinstance(payload, dict):
        return None
    typosquat_count = int(payload.get("active_typosquats") or 0)
    phishing_kits = int(payload.get("phishing_kits_observed") or 0)
    if typosquat_count == 0 and phishing_kits == 0:
        return None
    score = min(typosquat_count * 5 + phishing_kits * 15, 60)
    return SignalObservation(
        kind=SignalKind.BRAND_IMPERSONATION,
        source="cti.brand_intel",
        score=score,
        summary=(
            f"{typosquat_count} active typosquat(s) and "
            f"{phishing_kits} phishing kit(s) observed against {name}"
        ),
        evidence={
            "active_typosquats": typosquat_count,
            "phishing_kits": phishing_kits,
            "examples": list(payload.get("examples") or [])[:5],
        },
    )


def _asm_to_signal(
    domain: str, finding: dict[str, Any]
) -> SignalObservation | None:
    """One ASM high-risk finding becomes one observation.

    The ASM tool already classifies severity (``critical``/``high``/
    ``medium``); we map those onto our own 0-100 scale so the
    rolling-score arithmetic stays consistent.
    """
    if not isinstance(finding, dict):
        return None
    severity = str(finding.get("severity") or "medium").lower()
    score_table = {"critical": 50, "high": 30, "medium": 15, "low": 5}
    score = score_table.get(severity, 10)
    issue = str(finding.get("issue") or "Unspecified ASM finding")
    asset = str(finding.get("asset") or domain)
    return SignalObservation(
        kind=SignalKind.ASM_EXPOSURE,
        source="cti.asm_lookup",
        score=score,
        summary=f"{severity.upper()} ASM exposure on {asset}: {issue}",
        evidence={
            "domain": domain,
            "asset": asset,
            "issue": issue,
            "severity": severity,
        },
    )


def _vuln_to_signal(
    cve: str, payload: dict[str, Any]
) -> SignalObservation | None:
    """A vendor-tracked CVE becomes one observation.

    Heaviest weight when the CVE is exploited in the wild *and* used
    by a known ransomware crew — that's the failure mode that takes
    a vendor breach all the way to "your tenant got popped".
    """
    if not isinstance(payload, dict):
        return None
    if not payload.get("exploited_in_wild"):
        # Tenant cares about CVEs that matter; non-exploited CVEs
        # surface in the patching backlog, not in proactive cases.
        return None
    ransomware_use = list(payload.get("ransomware_use") or [])
    base = 25
    if ransomware_use:
        base += 15
    if payload.get("exploit_kits"):
        base += 10
    score = min(base, 60)
    return SignalObservation(
        kind=SignalKind.VULN_DISCLOSURE,
        source="cti.vuln_intel",
        score=score,
        summary=(
            f"{cve} exploited in the wild" +
            (f" — used by {', '.join(ransomware_use[:3])}" if ransomware_use else "")
        ),
        evidence={
            "cve": cve,
            "ransomware_use": ransomware_use,
            "first_itw": payload.get("first_itw"),
            "exploit_kits": list(payload.get("exploit_kits") or [])[:5],
        },
    )


__all__ = ["SupplyChainAgent"]

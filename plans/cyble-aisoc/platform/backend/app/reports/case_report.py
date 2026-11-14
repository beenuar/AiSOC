"""Pure builder for the multi-modal case report (Theme 2k).

This module is intentionally I/O-light: it accepts an open SQLModel
``Session`` plus a ``(case_id, tenant_id)`` pair and returns a fully
structured :class:`CaseReport`. No external services, no LLMs, no
caching layer — the report is recomputed from the canonical case
tables on every call, which keeps it consistent with the audit log
(including rollbacks recorded via ``ToolCall.rollback_of_id``).

The four panels:

* **timeline** — every materially relevant event during the case
  lifetime, in chronological order, with a stable kind discriminator
  the UI can switch on.
* **attack_graph** — a node/edge representation of the adversary
  activity reconstructed from EDR process trees + Alert metadata.
* **attack_heatmap** — MITRE ATT&CK tactic → technique → occurrence
  count, aggregated across every alert and every case-level
  technique tag.
* **blast_radius** — the *concrete* set of hosts, users, and
  identifiers each containment action touched, plus a coarse score
  for "how much of the org did this case end up affecting?"

All four panels are computed from rows the caller already had
permission to read — tenant scoping is enforced at the entry point
in :func:`build_case_report`.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlmodel import Session, select

from app.models.alert import Alert
from app.models.case import Case
from app.models.hitl import HitlRequest, HitlState
from app.models.tool_call import RiskClass, ToolCall
from app.models.trace import AgentTrace, TraceStep


# ───────────────────────── data classes ──────────────────────────────


@dataclass
class TimelineEvent:
    """One row on the case timeline."""

    timestamp: str  # ISO-8601, UTC
    kind: str  # alert | trace | tool_call | hitl | response | close
    actor: str  # who/what caused the event (agent name, analyst id, source)
    summary: str  # one-line human-readable
    detail: dict[str, Any] = field(default_factory=dict)
    # Helpful linkage so the UI can deep-link back into the raw audit log
    # without joining anything itself.
    ref_id: int | None = None  # primary key of the underlying row


@dataclass
class AttackGraphNode:
    """A vertex in the attack graph.

    ``kind`` is one of ``host``, ``user``, ``process``, ``ioc``, or
    ``mitre`` so the UI can render distinct glyphs per type.
    """

    id: str  # stable, unique within this report
    kind: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackGraphEdge:
    """A directed edge in the attack graph."""

    source: str
    target: str
    kind: str  # parent_of | executed_on | observed_at | used_ioc | mapped_to
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackGraph:
    nodes: list[AttackGraphNode] = field(default_factory=list)
    edges: list[AttackGraphEdge] = field(default_factory=list)


@dataclass
class AttackHeatmapCell:
    technique: str
    tactic: str | None
    count: int
    # Where each occurrence came from — useful for the UI tooltip /
    # drill-in and for compliance evidence ("which alert proved T1059?").
    sources: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AttackHeatmap:
    """Tactic → list of (technique, count) cells.

    ``cells`` is the flat list (easier for the frontend to render as
    a matrix); ``by_tactic`` is the same data pre-grouped.
    """

    cells: list[AttackHeatmapCell] = field(default_factory=list)
    by_tactic: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class BlastRadius:
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    # What was actually done, distilled from successful ToolCall rows.
    # Each entry is a dict of {tool_name, integration, target, risk_class,
    # success, rolled_back}.
    actions: list[dict[str, Any]] = field(default_factory=list)
    # Coarse 0..3 severity score:
    #   0 = nothing touched (read-only investigation)
    #   1 = single asset
    #   2 = small set (<=5 assets) or one significant write
    #   3 = anything destructive, or >5 assets
    score: int = 0


@dataclass
class CaseReport:
    """Top-level multi-modal report for one case."""

    case_id: int
    tenant_id: str
    generated_at: str
    timeline: list[TimelineEvent] = field(default_factory=list)
    attack_graph: AttackGraph = field(default_factory=AttackGraph)
    attack_heatmap: AttackHeatmap = field(default_factory=AttackHeatmap)
    blast_radius: BlastRadius = field(default_factory=BlastRadius)
    # Lightweight rollups so the API + Reporter trace can summarize
    # without re-walking the panels.
    stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (JSON-safe)."""
        return asdict(self)


# ─────────────────────────── helpers ─────────────────────────────────


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    # Always emit a Z-suffixed UTC timestamp so the frontend can sort
    # lexicographically without a parse step.
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.isoformat()


def _dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


# Best-effort MITRE technique→tactic mapping for the small set of
# techniques the seed/demo data uses. Real deployments should pull
# this from the ATT&CK json the DetectionEngine already ships, but
# the report builder must stay pure (no I/O), so we keep a tight
# in-process fallback and otherwise leave ``tactic`` as ``None``.
_TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1566": "Initial Access",
    "T1566.001": "Initial Access",
    "T1078": "Initial Access",
    "T1110": "Credential Access",
    "T1110.003": "Credential Access",
    "T1003": "Credential Access",
    "T1486": "Impact",
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1071": "Command and Control",
    "T1105": "Command and Control",
    "T1547": "Persistence",
    "T1098": "Persistence",
    "T1546": "Privilege Escalation",
    "T1055": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1018": "Discovery",
    "T1087": "Discovery",
}


def _resolve_tactic(technique: str, hint: str | None = None) -> str | None:
    """Best-effort technique→tactic mapping.

    `hint` is the tactic the alert already declared (preferred when
    present). Falls back to a small in-process lookup and finally
    ``None`` so the UI can render the cell uncategorized.
    """
    if hint:
        return hint
    base = technique.split(".")[0]
    return _TECHNIQUE_TO_TACTIC.get(technique) or _TECHNIQUE_TO_TACTIC.get(base)


# ───────────────────────── timeline ──────────────────────────────────


def _build_timeline(
    case: Case,
    alerts: list[Alert],
    traces: list[AgentTrace],
    tool_calls: list[ToolCall],
    hitl: list[HitlRequest],
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    for a in alerts:
        events.append(
            TimelineEvent(
                timestamp=_iso(a.created_at),
                kind="alert",
                actor=a.source,
                summary=f"Alert: {a.title}",
                detail={
                    "severity": a.severity,
                    "detection_rule": a.detection_rule,
                    "src_host": a.src_host,
                    "src_user": a.src_user,
                    "src_ip": a.src_ip,
                    "mitre_techniques": list(a.mitre_techniques or []),
                },
                ref_id=a.id,
            )
        )

    # Surface only the high-signal trace steps — THINK/PLAN are noisy
    # for a stakeholder-facing timeline.
    interesting_steps = {
        TraceStep.DECISION,
        TraceStep.HANDOFF,
        TraceStep.HITL_REQUEST,
        TraceStep.ERROR,
    }
    for t in traces:
        if t.step not in interesting_steps:
            continue
        events.append(
            TimelineEvent(
                timestamp=_iso(t.created_at),
                kind="trace",
                actor=t.agent.value if hasattr(t.agent, "value") else str(t.agent),
                summary=t.summary,
                detail={
                    "step": t.step.value if hasattr(t.step, "value") else str(t.step),
                    **(t.detail or {}),
                },
                ref_id=t.id,
            )
        )

    for tc in tool_calls:
        # Forward + rollback both surface; the UI can collapse pairs.
        is_rollback = tc.rollback_of_id is not None
        events.append(
            TimelineEvent(
                timestamp=_iso(tc.created_at),
                kind="tool_call",
                actor=tc.integration,
                summary=(
                    f"Rollback of #{tc.rollback_of_id}: {tc.tool_name}"
                    if is_rollback
                    else f"Tool: {tc.tool_name}"
                ),
                detail={
                    "risk_class": (
                        tc.risk_class.value
                        if hasattr(tc.risk_class, "value")
                        else str(tc.risk_class)
                    ),
                    "success": tc.success,
                    "error": tc.error,
                    "duration_ms": tc.duration_ms,
                    "rollback_of_id": tc.rollback_of_id,
                    "rolled_back_at": _iso(tc.rolled_back_at),
                },
                ref_id=tc.id,
            )
        )

    for h in hitl:
        # We show two events per HITL: requested (created_at) and decided
        # (decided_at) when present. Pending requests show up only as
        # the request event.
        events.append(
            TimelineEvent(
                timestamp=_iso(h.created_at),
                kind="hitl",
                actor=h.agent,
                summary=f"HITL requested: {h.tool_name}",
                detail={
                    "state": h.state.value if hasattr(h.state, "value") else str(h.state),
                    "risk_class": h.risk_class,
                    "rationale": h.rationale,
                    "blast_radius": h.blast_radius or {},
                    "expires_at": _iso(h.expires_at),
                },
                ref_id=h.id,
            )
        )
        if h.decided_at is not None:
            events.append(
                TimelineEvent(
                    timestamp=_iso(h.decided_at),
                    kind="hitl",
                    actor=h.decided_by or "system",
                    summary=(
                        f"HITL {h.state.value if hasattr(h.state, 'value') else h.state}"
                        f": {h.tool_name}"
                    ),
                    detail={
                        "state": (
                            h.state.value if hasattr(h.state, "value") else str(h.state)
                        ),
                        "decided_channel": (
                            h.decided_channel.value
                            if h.decided_channel and hasattr(h.decided_channel, "value")
                            else (str(h.decided_channel) if h.decided_channel else None)
                        ),
                        "decision_reason": h.decision_reason,
                        "decided_by_mfa_method": h.decided_by_mfa_method,
                    },
                    ref_id=h.id,
                )
            )

    # Response-action summary entries (taken from the Case row itself).
    # These are *not* a duplicate of tool_calls — they're the Responder's
    # high-level summary of "what got contained" and live on the Case.
    for idx, action in enumerate(case.response_actions or []):
        action_dict = action if isinstance(action, dict) else {"action": str(action)}
        events.append(
            TimelineEvent(
                # Best-effort: response actions don't carry their own
                # timestamps in the schema, so we attach them to the
                # case's updated_at. The UI sorts on this.
                timestamp=_iso(case.updated_at),
                kind="response",
                actor=str(action_dict.get("by") or "responder"),
                summary=str(action_dict.get("action") or "response action"),
                detail=action_dict,
                ref_id=case.id,
            )
        )

    # Close event (only when the case is actually closed).
    if case.closed_at is not None:
        events.append(
            TimelineEvent(
                timestamp=_iso(case.closed_at),
                kind="close",
                actor="reporter",
                summary=f"Case closed: {case.status.value if hasattr(case.status, 'value') else case.status}",
                detail={
                    "verdict": (
                        case.verdict.value
                        if hasattr(case.verdict, "value")
                        else str(case.verdict)
                    ),
                    "confidence": case.confidence,
                },
                ref_id=case.id,
            )
        )

    events.sort(key=lambda e: e.timestamp or "")
    return events


# ─────────────────────── attack graph ────────────────────────────────


def _walk_process_tree(
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
    host_node_id: str,
    process_tree: list[dict[str, Any]],
    *,
    parent_id: str | None = None,
) -> None:
    """Depth-first walk over an EDR process-tree result.

    The EDR tool returns a forest like::

        [{"pid": 1, "name": "outlook.exe", "children": [
            {"pid": 2, "name": "winword.exe", ...}
        ]}]

    For each process we synthesise one node (id = ``host:pid``) and one
    edge from the host (top-level processes) or from its parent
    process (nested). Suspicious / signed flags are preserved as
    attributes so the UI can colour the node.
    """
    for proc in process_tree or []:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        name = proc.get("name") or "<unknown>"
        node_id = f"{host_node_id}:pid:{pid}"
        nodes.append(
            AttackGraphNode(
                id=node_id,
                kind="process",
                label=str(name),
                attrs={
                    "pid": pid,
                    "cmdline": proc.get("cmdline"),
                    "signed": proc.get("signed"),
                    "suspicious": bool(proc.get("suspicious")),
                    "user": proc.get("user"),
                },
            )
        )
        edges.append(
            AttackGraphEdge(
                source=parent_id or host_node_id,
                target=node_id,
                kind="parent_of" if parent_id else "executed_on",
            )
        )
        children = proc.get("children") or []
        if isinstance(children, list):
            _walk_process_tree(
                nodes, edges, host_node_id, children, parent_id=node_id
            )


def _build_attack_graph(
    case: Case,
    alerts: list[Alert],
    tool_calls: list[ToolCall],
) -> AttackGraph:
    nodes: list[AttackGraphNode] = []
    edges: list[AttackGraphEdge] = []
    seen_node_ids: set[str] = set()

    def add_node(node: AttackGraphNode) -> None:
        if node.id in seen_node_ids:
            return
        seen_node_ids.add(node.id)
        nodes.append(node)

    # 1. Hosts + users + IOCs from the case envelope.
    for host in case.affected_hosts or []:
        add_node(
            AttackGraphNode(id=f"host:{host}", kind="host", label=str(host))
        )
    for user in case.affected_users or []:
        add_node(
            AttackGraphNode(id=f"user:{user}", kind="user", label=str(user))
        )
    for ioc in case.iocs or []:
        add_node(
            AttackGraphNode(id=f"ioc:{ioc}", kind="ioc", label=str(ioc))
        )

    # 2. Alerts contribute observation edges (user observed on host,
    #    IOC observed at host).
    for a in alerts:
        if a.src_host:
            host_id = f"host:{a.src_host}"
            add_node(
                AttackGraphNode(id=host_id, kind="host", label=str(a.src_host))
            )
            if a.src_user:
                user_id = f"user:{a.src_user}"
                add_node(
                    AttackGraphNode(
                        id=user_id, kind="user", label=str(a.src_user)
                    )
                )
                edges.append(
                    AttackGraphEdge(
                        source=user_id,
                        target=host_id,
                        kind="observed_at",
                        attrs={"alert_id": a.id, "title": a.title},
                    )
                )
            if a.src_ip:
                ip_id = f"ioc:{a.src_ip}"
                add_node(
                    AttackGraphNode(
                        id=ip_id,
                        kind="ioc",
                        label=str(a.src_ip),
                        attrs={"ioc_kind": "ip"},
                    )
                )
                edges.append(
                    AttackGraphEdge(
                        source=ip_id,
                        target=host_id,
                        kind="used_ioc",
                        attrs={"alert_id": a.id},
                    )
                )

    # 3. EDR process trees become attached subgraphs under the host.
    for tc in tool_calls:
        if tc.tool_name != "edr.get_process_tree":
            continue
        result = tc.result or {}
        if not isinstance(result, dict):
            continue
        host = result.get("host")
        tree = result.get("tree")
        if not host or not isinstance(tree, list):
            continue
        host_id = f"host:{host}"
        add_node(AttackGraphNode(id=host_id, kind="host", label=str(host)))
        _walk_process_tree(nodes, edges, host_id, tree)

    # 4. MITRE technique nodes anchor the graph to ATT&CK.
    techniques = list(case.mitre_techniques or [])
    for a in alerts:
        techniques.extend(a.mitre_techniques or [])
    for tech in _dedupe_preserve_order(str(t) for t in techniques):
        mitre_id = f"mitre:{tech}"
        add_node(
            AttackGraphNode(
                id=mitre_id,
                kind="mitre",
                label=tech,
                attrs={"tactic": _resolve_tactic(tech)},
            )
        )
        # Tie technique to every host we observed (best-effort).
        for host in case.affected_hosts or []:
            edges.append(
                AttackGraphEdge(
                    source=f"host:{host}",
                    target=mitre_id,
                    kind="mapped_to",
                )
            )

    return AttackGraph(nodes=nodes, edges=edges)


# ────────────────────── attack heatmap ───────────────────────────────


def _build_heatmap(case: Case, alerts: list[Alert]) -> AttackHeatmap:
    counter: Counter[tuple[str, str | None]] = Counter()
    sources: dict[tuple[str, str | None], list[dict[str, Any]]] = defaultdict(list)

    # Each alert can declare both a list of tactics AND a list of techniques.
    # We attribute every technique to the alert's first tactic when present,
    # otherwise fall back to the static lookup.
    for a in alerts:
        tactic_hint = (a.mitre_tactics or [None])[0]
        for tech in a.mitre_techniques or []:
            tech_str = str(tech)
            tactic = _resolve_tactic(tech_str, hint=tactic_hint)
            key = (tech_str, tactic)
            counter[key] += 1
            sources[key].append(
                {
                    "kind": "alert",
                    "alert_id": a.id,
                    "title": a.title,
                    "source": a.source,
                }
            )

    # Case-level techniques also count (these come from Investigator
    # adding techniques the alerts didn't tag, e.g. after CTI enrichment).
    for tech in case.mitre_techniques or []:
        tech_str = str(tech)
        tactic = _resolve_tactic(tech_str)
        key = (tech_str, tactic)
        counter[key] += 1
        sources[key].append({"kind": "case", "case_id": case.id})

    cells: list[AttackHeatmapCell] = []
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for (tech, tactic), count in counter.most_common():
        cells.append(
            AttackHeatmapCell(
                technique=tech,
                tactic=tactic,
                count=count,
                sources=sources[(tech, tactic)],
            )
        )
        by_tactic[tactic or "unmapped"].append(tech)

    return AttackHeatmap(cells=cells, by_tactic=dict(by_tactic))


# ────────────────────── blast radius ─────────────────────────────────


_TARGET_KEYS = ("host", "hostname", "device", "user", "username", "principal", "url", "domain", "ioc", "file_hash", "sender", "message_id", "address")


def _extract_target(params: dict[str, Any] | None) -> str | None:
    """Best-effort: find the primary target of a tool invocation."""
    if not isinstance(params, dict):
        return None
    for key in _TARGET_KEYS:
        v = params.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def _build_blast_radius(
    case: Case, tool_calls: list[ToolCall]
) -> BlastRadius:
    hosts: set[str] = set(case.affected_hosts or [])
    users: set[str] = set(case.affected_users or [])
    iocs: set[str] = set(case.iocs or [])

    actions: list[dict[str, Any]] = []
    significant_writes = 0
    has_destructive = False

    for tc in tool_calls:
        # Only successful WRITE-* invocations count as "touched". Rolled-
        # back rows still count for audit but flag the rollback so the
        # UI can render them muted.
        risk = (
            tc.risk_class.value
            if hasattr(tc.risk_class, "value")
            else str(tc.risk_class)
        )
        if risk == RiskClass.READ.value:
            continue
        if not tc.success:
            continue
        target = _extract_target(tc.params)
        # Categorize the target into hosts/users/iocs heuristically.
        params = tc.params or {}
        if isinstance(params, dict):
            for key in ("host", "hostname", "device"):
                v = params.get(key)
                if isinstance(v, str) and v:
                    hosts.add(v)
            for key in ("user", "username", "principal", "sender"):
                v = params.get(key)
                if isinstance(v, str) and v:
                    users.add(v)
            for key in ("url", "domain", "ioc", "file_hash", "address", "message_id"):
                v = params.get(key)
                if isinstance(v, str) and v:
                    iocs.add(v)
        if risk in (
            RiskClass.WRITE_SIGNIFICANT.value,
            RiskClass.DESTRUCTIVE.value,
        ):
            significant_writes += 1
        if risk == RiskClass.DESTRUCTIVE.value:
            has_destructive = True
        actions.append(
            {
                "tool_name": tc.tool_name,
                "integration": tc.integration,
                "risk_class": risk,
                "target": target,
                "success": tc.success,
                "rolled_back": tc.rolled_back_at is not None,
                "rolled_back_at": _iso(tc.rolled_back_at),
                "rolled_back_by": tc.rolled_back_by,
                "tool_call_id": tc.id,
                "created_at": _iso(tc.created_at),
            }
        )

    assets_touched = len(hosts) + len(users)
    if has_destructive:
        score = 3
    elif assets_touched > 5:
        score = 3
    elif significant_writes >= 1 or assets_touched > 1:
        score = 2
    elif assets_touched == 1:
        score = 1
    else:
        score = 0

    return BlastRadius(
        hosts=sorted(hosts),
        users=sorted(users),
        iocs=sorted(iocs),
        actions=actions,
        score=score,
    )


# ───────────────────── entry point ───────────────────────────────────


def build_case_report(
    db: Session,
    *,
    case_id: int,
    tenant_id: str,
    case: Optional[Case] = None,
) -> CaseReport:
    """Construct a :class:`CaseReport` for ``case_id`` within ``tenant_id``.

    The caller is responsible for tenant authorization (the API
    endpoint wraps this with :func:`apply_tenant_filter` /
    :func:`ensure_row_visible`). This function defensively re-asserts
    the tenant match: if the loaded case row's ``tenant_id`` doesn't
    match the passed ``tenant_id``, we raise ``PermissionError`` rather
    than emit a cross-tenant report.

    Pass an already-loaded ``case`` to avoid a second SELECT — the
    Reporter agent does this so its trace-step and the report agree on
    the exact case state.
    """
    if case is None:
        case = db.get(Case, case_id)
    if case is None:
        raise LookupError(f"case {case_id} not found")
    if case.tenant_id != tenant_id:
        raise PermissionError(
            f"case {case_id} belongs to tenant {case.tenant_id!r}, "
            f"not {tenant_id!r}"
        )

    alerts = list(
        db.exec(
            select(Alert)
            .where(Alert.case_id == case_id)
            .where(Alert.tenant_id == tenant_id)
            .order_by(Alert.created_at.asc())
        ).all()
    )
    traces = list(
        db.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.tenant_id == tenant_id)
            .order_by(AgentTrace.created_at.asc())
        ).all()
    )
    tool_calls = list(
        db.exec(
            select(ToolCall)
            .where(ToolCall.case_id == case_id)
            .where(ToolCall.tenant_id == tenant_id)
            .order_by(ToolCall.created_at.asc())
        ).all()
    )
    hitl = list(
        db.exec(
            select(HitlRequest)
            .where(HitlRequest.case_id == case_id)
            .where(HitlRequest.tenant_id == tenant_id)
            .order_by(HitlRequest.created_at.asc())
        ).all()
    )

    timeline = _build_timeline(case, alerts, traces, tool_calls, hitl)
    attack_graph = _build_attack_graph(case, alerts, tool_calls)
    attack_heatmap = _build_heatmap(case, alerts)
    blast_radius = _build_blast_radius(case, tool_calls)

    stats = {
        "alerts": len(alerts),
        "traces": len(traces),
        "tool_calls": len(tool_calls),
        "hitl_requests": len(hitl),
        "hitl_pending": sum(1 for h in hitl if h.state == HitlState.PENDING),
        "timeline_events": len(timeline),
        "graph_nodes": len(attack_graph.nodes),
        "graph_edges": len(attack_graph.edges),
        "heatmap_techniques": len(attack_heatmap.cells),
        "blast_assets": len(blast_radius.hosts) + len(blast_radius.users),
        "blast_actions": len(blast_radius.actions),
        "blast_score": blast_radius.score,
    }

    from datetime import datetime as _dt, timezone as _tz

    return CaseReport(
        case_id=case_id,
        tenant_id=tenant_id,
        generated_at=_iso(_dt.now(_tz.utc)),
        timeline=timeline,
        attack_graph=attack_graph,
        attack_heatmap=attack_heatmap,
        blast_radius=blast_radius,
        stats=stats,
    )

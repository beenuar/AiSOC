"""Pre-action simulation / dry-run blast-radius (t4-dry-run).

Before any WRITE_REVERSIBLE / WRITE_SIGNIFICANT / DESTRUCTIVE tool runs,
the analyst gets a deterministic, evidence-grounded preview of what
the action will affect. The simulation is read-only and side-effect-free
— it walks the CMDB and Threat Graph to estimate:

  * **target**: the canonical entity the tool will modify (host, user,
    file, oauth grant), with criticality, environment, owner.
  * **dependents**: directly-related entities pulled from the Threat
    Graph (1-hop neighbours by default). For ``edr.isolate_host`` this
    is "users with a session on this host", "files modified by this
    host in the last hour", "containers / VMs running on this host".
  * **collateral_count**: a single numeric "how big" statistic so the
    HITL UI can render a traffic-light without parsing the structured
    detail.
  * **reversibility**: pulled directly from the
    :class:`app.tools.registry.ToolDef` — the source of truth for
    whether the rollback service can undo this action.
  * **counterfactual**: a one-line "if you skip this action…" so the
    analyst sees the *cost of inaction*, not just the *cost of action*
    (Theme 4: counterfactual why-not).

The output of :func:`simulate_action` is the same shape that
:class:`HitlRequest.blast_radius` already accepts, so the preview drops
straight into the HITL approval payload without UI changes.

Design rules:

- Read-only: no LLM call, no SIEM query, no graph mutation. Pure
  function over (tool_name, params, tenant_id).
- Deterministic: same inputs produce the same simulation. The HITL UI
  caches the result keyed on (tool_name, params hash) so the analyst
  never sees the prediction wobble between page refreshes.
- Cheap: every helper has a configurable depth/limit cap. The whole
  call should comfortably stay under 50 ms on the SQLite demo DB.
- Tenant-scoped: every CMDB and graph lookup is filtered by
  ``tenant_id``; there is no cross-tenant leak even when the same
  hostname appears in two tenants.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from sqlmodel import select

from app.db import session_scope
from app.memory.graph import graph_neighbors
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.graph import EdgeType, NodeType
from app.models.tool_call import RiskClass
from app.tools.registry import ToolDef, registry as tool_registry


# Cap blast-radius graph traversal so a misconfigured demo DB can't
# grind the request to a halt. 200 neighbours is plenty for HITL UI.
_NEIGHBOUR_LIMIT = 200

# Tools whose params signal which CMDB record / graph node is the
# canonical target. Keyed on tool name; value picks the params field
# that holds the entity key plus the matching node/asset type.
_TARGET_HINTS: dict[str, tuple[str, NodeType, AssetType]] = {
    "edr.isolate_host": ("host", NodeType.ASSET, AssetType.HOST),
    "edr.release_host": ("host", NodeType.ASSET, AssetType.HOST),
    "edr.kill_process": ("host", NodeType.ASSET, AssetType.HOST),
    "edr.quarantine_file": ("sha256", NodeType.IOC, AssetType.HOST),
    "edr.restore_file": ("sha256", NodeType.IOC, AssetType.HOST),
    "idp.disable_user": ("user", NodeType.USER, AssetType.USER),
    "idp.enable_user": ("user", NodeType.USER, AssetType.USER),
    "idp.revoke_sessions": ("user", NodeType.USER, AssetType.USER),
    "idp.reset_password": ("user", NodeType.USER, AssetType.USER),
    "saas.revoke_oauth_grant": ("user", NodeType.USER, AssetType.USER),
    "cloud.disable_iam_user": ("user", NodeType.USER, AssetType.USER),
    "cloud.deactivate_access_key": ("user", NodeType.USER, AssetType.USER),
}

# Edge types that count as dependent traversal for blast-radius scoring.
# We keep this conservative on purpose — we want first-order neighbours
# only (logins on a host, IOCs observed on a host, group membership and
# permissions held by a user) and not the full transitive cascade.
_DEPENDENT_EDGES_BY_TARGET: dict[NodeType, list[EdgeType]] = {
    NodeType.ASSET: [
        EdgeType.AUTHENTICATED_AS,
        EdgeType.OBSERVED_ON,
        EdgeType.COMMUNICATES_WITH,
        EdgeType.OWNED_BY,
    ],
    NodeType.USER: [
        EdgeType.AUTHENTICATED_AS,
        EdgeType.OWNED_BY,
        EdgeType.MEMBER_OF,
        EdgeType.HAS_PERMISSION,
        EdgeType.CAN_ASSUME_ROLE,
    ],
    NodeType.IOC: [
        EdgeType.OBSERVED_ON,
        EdgeType.ATTRIBUTED_TO,
        EdgeType.PART_OF,
    ],
}


# ─── DTOs ───────────────────────────────────────────────────────────────


@dataclass
class TargetSummary:
    """Concise CMDB snapshot of the entity the tool will modify."""

    asset_type: str
    key: str
    name: Optional[str]
    criticality: str
    environment: str
    owner: Optional[str]
    business_unit: Optional[str]
    compliance_scopes: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)
    found_in_cmdb: bool = False


@dataclass
class DependentSummary:
    """One-hop neighbour from the Threat Graph for the target entity."""

    node_type: str
    key: str
    edge_type: str
    direction: str  # "out" / "in"
    name: Optional[str] = None


@dataclass
class DryRunSimulation:
    """The full pre-action preview the HITL UI consumes verbatim."""

    tool_name: str
    integration: str
    risk_class: str
    reversibility: str  # "reversible" | "forward_only" | "destructive"
    reverse_tool: Optional[str]
    forward_only_reason: Optional[str]
    target: Optional[TargetSummary]
    dependents: list[DependentSummary] = field(default_factory=list)
    collateral_count: int = 0
    severity_hint: str = "low"  # "low" | "medium" | "high"
    counterfactual: str = ""
    advisory: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Helpers ────────────────────────────────────────────────────────────


def _fingerprint(tool_name: str, params: dict[str, Any]) -> str:
    """Deterministic id for ``(tool, params)`` used to memoise the UI cache."""
    blob = json.dumps(
        {"tool": tool_name, "params": params}, sort_keys=True, default=str
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _classify_reversibility(td: ToolDef) -> str:
    if td.risk_class == RiskClass.DESTRUCTIVE:
        return "destructive"
    if td.is_reversible:
        return "reversible"
    if td.is_forward_only:
        return "forward_only"
    if td.risk_class == RiskClass.READ:
        return "reversible"  # nothing to undo
    return "forward_only"


def _severity_hint(
    *,
    risk_class: RiskClass,
    target: Optional[TargetSummary],
    collateral_count: int,
) -> str:
    """Combine risk class, target criticality, and dependent count.

    Goal: the HITL UI's traffic-light always degrades to ``high`` for
    destructive actions on critical/regulated systems, and to ``low`` for
    reversible reads against unknown targets. Anything in between stays
    ``medium`` so the UI can show a yellow indicator and an analyst note.
    """
    if risk_class == RiskClass.DESTRUCTIVE:
        return "high"
    crit = target.criticality if target else AssetCriticality.UNKNOWN.value
    sensitive = bool(target and (target.compliance_scopes or target.data_classifications))
    # Map model enum strings ("crown_jewel" / "high" / "medium" / "low" /
    # "unknown") to the dry-run severity floor.
    if (
        risk_class == RiskClass.WRITE_SIGNIFICANT
        and (crit in {"crown_jewel", "high"} or sensitive or collateral_count >= 25)
    ):
        return "high"
    if risk_class in {RiskClass.WRITE_SIGNIFICANT, RiskClass.WRITE_REVERSIBLE}:
        return "medium"
    return "low"


def _counterfactual(td: ToolDef, target: Optional[TargetSummary]) -> str:
    """One-line "what happens if you skip this?" text for the UI.

    Hand-curated per *tool family* (not per individual tool) because the
    LLM-driven Reporter is wrong here just often enough to be dangerous;
    the Counterfactual Why-Not work in t4-counterfactual builds on top
    of this baseline.
    """
    name = (target.name or target.key) if target else "the target"
    if td.name in {"edr.isolate_host"}:
        return (
            f"Skipping isolation leaves {name} reachable from the corporate "
            "network; expect continued lateral-movement opportunities until "
            "the host is rebuilt or quarantined."
        )
    if td.name == "edr.release_host":
        return (
            f"Leaving {name} isolated keeps it offline. If the threat is "
            "already eradicated this is purely a productivity tax."
        )
    if td.name == "edr.kill_process":
        return (
            "Letting the process keep running gives the attacker more "
            "time to persist, exfil, or pivot. This action is "
            "DESTRUCTIVE and cannot be undone — verify the PID."
        )
    if td.name == "edr.quarantine_file":
        return (
            "If the binary is malicious, leaving it on disk lets it "
            "execute on any machine that runs it next."
        )
    if td.name in {"idp.disable_user", "saas.revoke_oauth_grant"}:
        return (
            f"Leaving {name} active continues to grant the attacker any "
            "access the account already had, including to OAuth-granted "
            "third-party apps."
        )
    if td.name == "idp.revoke_sessions":
        return (
            f"Skipping session revoke leaves any stolen cookies/tokens "
            f"for {name} valid until they expire naturally."
        )
    if td.name == "idp.reset_password":
        return (
            f"Skipping a forced reset leaves {name}'s credentials "
            "available to whoever already has them."
        )
    if td.name == "cloud.deactivate_access_key":
        return (
            "Leaving the access key live means anything that already "
            "stole it can keep authenticating."
        )
    return (
        "Skipping the action leaves the underlying condition unchanged; "
        "the next detection cycle will re-surface it."
    )


def _advisory(
    *,
    target: Optional[TargetSummary],
    risk_class: RiskClass,
    collateral_count: int,
    reversibility: str,
) -> list[str]:
    notes: list[str] = []
    if target is None:
        notes.append("Target not found in CMDB — verify the entity manually.")
    else:
        if target.criticality in {"crown_jewel", "high"}:
            label = (
                "CROWN-JEWEL"
                if target.criticality == "crown_jewel"
                else target.criticality.upper()
            )
            notes.append(
                f"Asset criticality is {label}. "
                "Coordinate with the system owner before approval."
            )
        if target.environment == AssetEnvironment.PROD.value:
            notes.append("Target is in PROD — confirm change-control window.")
        if target.compliance_scopes:
            notes.append(
                "Compliance scope(s): "
                f"{', '.join(target.compliance_scopes).upper()}. "
                "Document this action for the next audit cycle."
            )
        if target.data_classifications:
            notes.append(
                f"Data classification(s): {', '.join(target.data_classifications)}."
            )
    if reversibility == "destructive":
        notes.append("DESTRUCTIVE action — cannot be rolled back automatically.")
    if reversibility == "forward_only":
        notes.append("Forward-only action — rollback service will not undo it.")
    if collateral_count >= 25:
        notes.append(
            f"{collateral_count} dependent entities affected — high blast radius."
        )
    if risk_class == RiskClass.WRITE_SIGNIFICANT:
        notes.append("Significant write — second-set-of-eyes recommended.")
    return notes


def _resolve_target(
    *,
    tool_name: str,
    params: dict[str, Any],
    tenant_id: str,
) -> tuple[Optional[TargetSummary], Optional[NodeType], Optional[str]]:
    """Pull the canonical target entity from the CMDB / Threat Graph.

    Returns ``(target_summary, node_type, key)`` so dependent traversal
    can use the resolved ``key`` even when the asset isn't in CMDB yet.
    """
    hint = _TARGET_HINTS.get(tool_name)
    if hint is None:
        return None, None, None
    key_field, node_type, asset_type = hint
    key = params.get(key_field)
    if not isinstance(key, str) or not key:
        return None, node_type, None

    with session_scope() as session:
        stmt = (
            select(Asset)
            .where(Asset.tenant_id == tenant_id)
            .where(Asset.asset_type == asset_type)
            .where(Asset.key == key)
        )
        row = session.exec(stmt).first()
        if row is None:
            # Try alias match — the alert source may have used a different
            # canonical key (FQDN vs hostname, UPN vs sAMAccountName).
            stmt = (
                select(Asset)
                .where(Asset.tenant_id == tenant_id)
                .where(Asset.asset_type == asset_type)
            )
            for candidate in session.exec(stmt).all():
                aliases = list(candidate.aliases or [])
                if key in aliases:
                    row = candidate
                    break

        if row is None:
            return (
                TargetSummary(
                    asset_type=asset_type.value,
                    key=key,
                    name=None,
                    criticality=AssetCriticality.UNKNOWN.value,
                    environment=AssetEnvironment.UNKNOWN.value,
                    owner=None,
                    business_unit=None,
                    found_in_cmdb=False,
                ),
                node_type,
                key,
            )

        return (
            TargetSummary(
                asset_type=row.asset_type.value
                if isinstance(row.asset_type, AssetType)
                else str(row.asset_type),
                key=row.key,
                name=row.name or row.key,
                criticality=row.criticality.value
                if isinstance(row.criticality, AssetCriticality)
                else str(row.criticality),
                environment=row.environment.value
                if isinstance(row.environment, AssetEnvironment)
                else str(row.environment),
                owner=row.owner or None,
                business_unit=row.business_unit or None,
                compliance_scopes=list(row.compliance_scopes or []),
                data_classifications=list(row.data_classifications or []),
                found_in_cmdb=True,
            ),
            node_type,
            row.key,
        )


def _gather_dependents(
    *,
    tenant_id: str,
    node_type: NodeType,
    key: str,
) -> list[DependentSummary]:
    edge_types = _DEPENDENT_EDGES_BY_TARGET.get(node_type, [])
    if not edge_types:
        return []
    try:
        rows = graph_neighbors(
            tenant_id=tenant_id,
            type=node_type,
            key=key,
            edge_types=edge_types,
            depth=1,
            include_global=False,
            limit=_NEIGHBOUR_LIMIT,
        )
    except Exception:  # pragma: no cover - graph backend hiccup
        return []
    out: list[DependentSummary] = []
    for row in rows:
        node = row.get("node") or {}
        edge = row.get("edge") or {}
        out.append(
            DependentSummary(
                node_type=str(node.get("type") or ""),
                key=str(node.get("key") or ""),
                edge_type=str(edge.get("type") or ""),
                direction=str(row.get("direction") or "out"),
                name=node.get("props", {}).get("name") if isinstance(node.get("props"), dict) else None,
            )
        )
    return out


# ─── Public API ─────────────────────────────────────────────────────────


def simulate_action(
    *,
    tool_name: str,
    params: dict[str, Any],
    tenant_id: str,
) -> DryRunSimulation:
    """Predict the blast radius for ``tool_name(params)`` without running it.

    Used by:

    - The HITL gateway, which embeds the simulation in the
      ``blast_radius`` field of every approval request.
    - The ``/dry-run`` REST endpoint, so analysts can preview an action
      before they ask the agent mesh to take it (or write a runbook
      around it).
    """
    td = tool_registry.get(tool_name)
    if td is None:
        return DryRunSimulation(
            tool_name=tool_name,
            integration="unknown",
            risk_class="unknown",
            reversibility="unknown",
            reverse_tool=None,
            forward_only_reason=None,
            target=None,
            advisory=[f"Tool {tool_name!r} is not registered. Verify the name."],
            fingerprint=_fingerprint(tool_name, params),
        )

    target, node_type, resolved_key = _resolve_target(
        tool_name=tool_name, params=params, tenant_id=tenant_id
    )

    dependents: list[DependentSummary] = []
    if node_type is not None and resolved_key:
        dependents = _gather_dependents(
            tenant_id=tenant_id, node_type=node_type, key=resolved_key
        )

    reversibility = _classify_reversibility(td)
    severity = _severity_hint(
        risk_class=td.risk_class,
        target=target,
        collateral_count=len(dependents),
    )
    advisory = _advisory(
        target=target,
        risk_class=td.risk_class,
        collateral_count=len(dependents),
        reversibility=reversibility,
    )

    return DryRunSimulation(
        tool_name=td.name,
        integration=td.integration,
        risk_class=td.risk_class.value
        if isinstance(td.risk_class, RiskClass)
        else str(td.risk_class),
        reversibility=reversibility,
        reverse_tool=td.reverse_tool,
        forward_only_reason=td.forward_only_reason,
        target=target,
        dependents=dependents,
        collateral_count=len(dependents),
        severity_hint=severity,
        counterfactual=_counterfactual(td, target),
        advisory=advisory,
        fingerprint=_fingerprint(td.name, params),
    )


def simulate_runbook(
    *,
    steps: list[dict[str, Any]],
    tenant_id: str,
) -> dict[str, Any]:
    """Simulate an entire runbook (sequence of tool calls) at once.

    Each step is ``{"tool_name": ..., "params": {...}}``. The runbook
    summary aggregates blast radius across all steps so analysts can
    approve a multi-step response in a single click without losing
    transparency on what each step touches.
    """
    simulations = [
        simulate_action(
            tool_name=step.get("tool_name", ""),
            params=step.get("params", {}) or {},
            tenant_id=tenant_id,
        )
        for step in steps
    ]
    severity_order = {"low": 0, "medium": 1, "high": 2}
    overall_severity = "low"
    for sim in simulations:
        if severity_order.get(sim.severity_hint, 0) > severity_order.get(overall_severity, 0):
            overall_severity = sim.severity_hint
    affected_keys: set[tuple[str, str]] = set()
    for sim in simulations:
        if sim.target is not None:
            affected_keys.add((sim.target.asset_type, sim.target.key))
        for dep in sim.dependents:
            affected_keys.add((dep.node_type, dep.key))
    destructive_steps = [s.tool_name for s in simulations if s.reversibility == "destructive"]
    forward_only = [s.tool_name for s in simulations if s.reversibility == "forward_only"]
    return {
        "steps": [s.to_dict() for s in simulations],
        "severity_hint": overall_severity,
        "unique_entities_affected": len(affected_keys),
        "destructive_steps": destructive_steps,
        "forward_only_steps": forward_only,
        "fingerprint": hashlib.sha256(
            "|".join(s.fingerprint for s in simulations).encode("utf-8")
        ).hexdigest()[:16],
    }

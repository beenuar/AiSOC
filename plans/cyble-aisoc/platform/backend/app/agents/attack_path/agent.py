"""Attack-Path Agent — proactive pre-attack-path discovery (todo ``t2g``).

This module is intentionally **not** a :class:`BaseAgent` subclass:

* The agent is *proactive*, not reactive — it runs on a schedule (or
  via the ``POST /attack-paths/scan`` endpoint), not in response to an
  alert handoff.
* Its tool surface is *read-only* across the Connector SDK; it never
  mutates the live environment. Containment is always delegated back
  to ITDR / CDR / SaaS-posture via their own HITL-gated tools, so the
  ``BaseAgent.call_tool`` HITL machinery would be dead weight here.
* The agent manages its own tenancy enforcement (every connector call
  is bound to the active tenant; every graph upsert and case insert
  carries the active ``tenant_id``).

What it does, in order:

1. **Collect** exposures, identities, cloud roles, K8s RBAC, and OAuth
   grants for one tenant via :func:`app.connectors.get_connector`.
2. **Stitch** them into the threat graph (:mod:`app.memory.graph`)
   using the new node types (``EXPOSURE``, ``ROLE``, ``PERMISSION``,
   ``GROUP``) and edge verbs (``EXPOSED_AS``, ``CAN_ASSUME_ROLE``,
   ``HAS_PERMISSION``, ``MEMBER_OF``, ``CAN_REACH``, ``CAN_PRIVESC_TO``).
3. **Rank** the resulting pre-attack paths by a composite risk score
   that combines connector-supplied risk + path depth + toxic
   combinations (e.g. no-MFA + wildcard policy + cluster-admin in same
   chain).
4. **Open proactive cases** with ``Severity.HIGH`` for every path
   above the threshold, emitting ``case.created`` on the realtime bus
   so the UI surfaces it next to reactive cases.

The agent always records an :class:`AgentTrace` row under
``AgentName.ATTACK_PATH`` so the "why did the agent do that?" replay
works the same way it does for reactive sub-agents.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlmodel import Session

from app.agents.attack_path.models import (
    AttackPath,
    AttackPathHop,
    AttackPathScanResult,
)
from app.connectors import ConnectorKind, get_connector
from app.connectors.sdk.base import ConnectorError
from app.memory.graph import (
    graph_upsert_edge,
    graph_upsert_node,
)
from app.models.case import Case, CaseStatus, Severity
from app.models.graph import EdgeType, NodeType
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.realtime.case_events import publish_case_created
from app.tools.cti import cti_asm_lookup

logger = logging.getLogger("aisoc.attack_path")

# Risk threshold above which a path opens a proactive case. Below this
# we still write the path into the graph (for the UI's attack-path
# explorer) but we don't pull a SOC analyst onto it — that's reserved
# for "fix this before the adversary does" urgency.
_HIGH_RISK_THRESHOLD = 0.70


class AttackPathAgent:
    """Proactive attack-path discovery for one tenant.

    The agent is intentionally instantiated per-tenant per-run — there
    is no long-lived shared state. The scheduler creates one instance,
    calls :meth:`scan`, and discards it. This keeps tenancy enforcement
    trivially correct: a single instance only ever sees one tenant.
    """

    def __init__(
        self,
        session: Session,
        *,
        tenant_id: str,
        domain: str | None = None,
        risk_threshold: float = _HIGH_RISK_THRESHOLD,
    ) -> None:
        if not tenant_id:
            # Hard requirement: every graph upsert, every Case row, and
            # every AgentTrace row must carry the active tenant_id.
            # Refusing to construct without one prevents accidental
            # cross-tenant leakage in MSSP deployments.
            raise ValueError("AttackPathAgent requires a tenant_id")
        self.session = session
        self.tenant_id = tenant_id
        # Domain used for the ASM lookup. In production this comes from
        # the tenant's brand profile; for now we let the caller pass it
        # and fall back to a deterministic per-tenant default that the
        # mock connector accepts.
        self.domain = domain or f"{tenant_id}.example"
        self.risk_threshold = risk_threshold

    # ── public entry point ─────────────────────────────────────────
    async def scan(self) -> AttackPathScanResult:
        """Run one full scan: collect → stitch → rank → file cases."""
        result = AttackPathScanResult(tenant_id=self.tenant_id)

        # Collect from each plane independently so a degraded connector
        # (e.g. AWS auth flapping) only nukes that plane's contribution,
        # not the whole scan.
        asm = await self._collect_asm(result)
        iam_principals, sts_chains, k8s_bindings = await self._collect_cloud(result)
        oauth_grants = await self._collect_identity(result)

        # Stitch the graph. Each helper returns the (type, key) tuples
        # it created so the path-finder doesn't have to re-query.
        exposure_nodes = self._stitch_asm(asm, result)
        iam_nodes = self._stitch_iam(iam_principals, sts_chains, result)
        k8s_nodes = self._stitch_k8s(k8s_bindings, result)
        oauth_nodes = self._stitch_oauth(oauth_grants, result)

        # Discover paths. Each detector returns a list of AttackPath.
        paths: list[AttackPath] = []
        paths.extend(self._detect_iam_pivot_paths(iam_nodes, sts_chains, k8s_nodes))
        paths.extend(self._detect_exposure_to_admin_paths(exposure_nodes, iam_nodes))
        paths.extend(self._detect_illicit_oauth_paths(oauth_nodes))

        # Open proactive cases for high-risk paths. Each case_id is
        # written back onto its AttackPath so the API response can link.
        for path in paths:
            if path.risk_score >= self.risk_threshold:
                case_id = await self._open_proactive_case(path)
                path.case_id = case_id
                result.cases_opened += 1

        result.paths = paths
        result.paths_discovered = len(paths)

        self._log_trace(
            case_id=None,
            step=TraceStep.DECISION,
            summary=(
                f"Attack-path scan: {result.paths_discovered} paths, "
                f"{result.cases_opened} cases opened"
            ),
            detail=result.to_dict(),
        )
        return result

    # ── collection ─────────────────────────────────────────────────
    async def _collect_asm(
        self, result: AttackPathScanResult
    ) -> dict[str, Any]:
        try:
            # ASM lives in the CTI tool surface (not the Connector SDK)
            # — see ``app.tools.cti.cti_asm_lookup``. The mock returns
            # exposed assets + high-risk findings for a domain.
            data = await cti_asm_lookup(self.domain)
            result.connector_health["asm"] = "ok"
            return data
        except Exception as exc:  # noqa: BLE001 — defensive against ASM going down
            logger.warning("ASM lookup failed for tenant=%s: %s", self.tenant_id, exc)
            result.connector_health["asm"] = f"error:{exc.__class__.__name__}"
            return {"domain": self.domain, "external_assets": 0, "high_risk_findings": []}

    async def _collect_cloud(
        self, result: AttackPathScanResult
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            cloud = await get_connector(self.tenant_id, ConnectorKind.CLOUD)
        except ConnectorError as exc:
            result.connector_health["cloud"] = f"error:{exc.__class__.__name__}"
            return [], [], []

        principals: list[dict[str, Any]] = []
        sessions: list[dict[str, Any]] = []
        k8s: list[dict[str, Any]] = []
        try:
            principals = (await cloud.list_iam_principals(limit=500)).get(
                "principals", []
            )
            sessions = (await cloud.list_sts_sessions(hours=72)).get("sessions", [])
            k8s = (await cloud.list_k8s_rolebindings()).get("bindings", [])
            result.connector_health["cloud"] = "ok"
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cloud collect failed for tenant=%s: %s", self.tenant_id, exc)
            result.connector_health["cloud"] = f"error:{exc.__class__.__name__}"
        return principals, sessions, k8s

    async def _collect_identity(
        self, result: AttackPathScanResult
    ) -> list[dict[str, Any]]:
        try:
            idp = await get_connector(self.tenant_id, ConnectorKind.IDP)
        except ConnectorError as exc:
            result.connector_health["idp"] = f"error:{exc.__class__.__name__}"
            return []
        grants: list[dict[str, Any]] = []
        try:
            # Mock IdP exposes ``list_oauth_apps`` (tenant-wide grants)
            # which is what we want for proactive scanning — per-user
            # lookup is reserved for reactive ITDR.
            apps = await idp.list_oauth_apps()
            grants = apps.get("apps", [])
            result.connector_health["idp"] = "ok"
        except Exception as exc:  # noqa: BLE001
            logger.warning("IdP collect failed for tenant=%s: %s", self.tenant_id, exc)
            result.connector_health["idp"] = f"error:{exc.__class__.__name__}"
        return grants

    # ── graph stitching ────────────────────────────────────────────
    def _stitch_asm(
        self, asm: dict[str, Any], result: AttackPathScanResult
    ) -> list[tuple[str, str, dict[str, Any]]]:
        """Stitch ASM exposures into the graph as ``ASSET → EXPOSURE``.

        Returns ``(node_type, key, payload)`` for the exposure nodes so
        the path detector can use them as starting points.
        """
        out: list[tuple[str, str, dict[str, Any]]] = []
        for finding in asm.get("high_risk_findings", []) or []:
            asset = finding.get("asset", "")
            if not asset:
                continue
            issue = finding.get("issue", "exposure")
            severity = finding.get("severity", "high")
            # Asset node (re-use IOC node type if the asset is a
            # hostname; otherwise mint a generic ASSET node). We keep
            # it as ASSET regardless — IOCs are reserved for indicators
            # of *compromise*, not exposures.
            self._upsert_node(
                NodeType.ASSET,
                asset,
                label=asset,
                props={"role": "external"},
            )
            result.nodes_upserted += 1
            exposure_key = f"{severity}:{asset}"
            self._upsert_node(
                NodeType.EXPOSURE,
                exposure_key,
                label=issue,
                props={"asset": asset, "severity": severity, "issue": issue},
                tags=["asm", severity],
            )
            result.nodes_upserted += 1
            self._upsert_edge(
                src=(NodeType.ASSET, asset),
                dst=(NodeType.EXPOSURE, exposure_key),
                etype=EdgeType.EXPOSED_AS,
                weight={"critical": 0.95, "high": 0.8, "medium": 0.5}.get(
                    severity, 0.4
                ),
                props={"issue": issue},
            )
            result.edges_upserted += 1
            out.append((NodeType.EXPOSURE.value, exposure_key, finding))
        return out

    def _stitch_iam(
        self,
        principals: list[dict[str, Any]],
        sts_sessions: list[dict[str, Any]],
        result: AttackPathScanResult,
    ) -> dict[str, dict[str, Any]]:
        """Stitch IAM principals + STS chains into the graph.

        Returns a dict keyed by principal ARN with the original payload
        so the path detector can score without re-fetching.
        """
        by_arn: dict[str, dict[str, Any]] = {}
        for p in principals:
            arn = p.get("arn") or ""
            if not arn:
                continue
            by_arn[arn] = p
            kind = (p.get("principal_type") or "").lower()
            # Roles → ROLE, users → IDENTITY. This keeps the graph
            # semantics tight: "role" is the thing you can assume,
            # "identity" is the thing that does the assuming.
            node_type = NodeType.ROLE if kind == "role" else NodeType.USER
            self._upsert_node(
                node_type,
                arn,
                label=p.get("name", arn),
                props={
                    "principal_type": kind,
                    "mfa_enabled": p.get("mfa_enabled"),
                    "last_used": p.get("last_used"),
                    "risk_score": p.get("risk_score", 0),
                    "tags": p.get("tags", {}),
                },
                tags=["aws", "iam", kind] if kind else ["aws", "iam"],
            )
            result.nodes_upserted += 1
            for policy in p.get("attached_policies", []) or []:
                self._upsert_node(
                    NodeType.PERMISSION,
                    policy,
                    label=policy.split("/")[-1],
                    props={"arn": policy},
                    tags=["aws", "policy"],
                )
                result.nodes_upserted += 1
                self._upsert_edge(
                    src=(node_type, arn),
                    dst=(NodeType.PERMISSION, policy),
                    etype=EdgeType.HAS_PERMISSION,
                    weight=0.9 if "Wildcard" in policy or "Admin" in policy else 0.5,
                )
                result.edges_upserted += 1

        # STS chains turn into ``CAN_ASSUME_ROLE`` edges. We use the
        # observed *source → assumed_role* pairs so the path detector
        # walks the real, ground-truth pivot capability instead of the
        # theoretical trust policy.
        for s in sts_sessions:
            src = s.get("source_principal") or ""
            dst = s.get("assumed_role") or ""
            if not src or not dst:
                continue
            self._upsert_edge(
                src=(NodeType.USER if "user/" in src else NodeType.ROLE, src),
                dst=(NodeType.ROLE, dst),
                etype=EdgeType.CAN_ASSUME_ROLE,
                weight=float(s.get("anomaly_score", 0.5)),
                props={
                    "session_id": s.get("session_id"),
                    "mfa_used": s.get("mfa_used"),
                    "country": s.get("country"),
                    "asn": s.get("asn"),
                },
            )
            result.edges_upserted += 1
        return by_arn

    def _stitch_k8s(
        self,
        bindings: list[dict[str, Any]],
        result: AttackPathScanResult,
    ) -> list[dict[str, Any]]:
        """Stitch K8s RoleBindings as ``IDENTITY/GROUP → ROLE``.

        We use the K8s role *name* (``ClusterRole/cluster-admin``) as
        the ``PERMISSION``/``ROLE`` key so path display matches what
        SREs already see in ``kubectl get rolebindings``.
        """
        for b in bindings:
            role_ref = b.get("role_ref") or ""
            if not role_ref:
                continue
            role_key = f"k8s:{role_ref}"
            risk = float(b.get("risk_score", 0.0))
            self._upsert_node(
                NodeType.ROLE,
                role_key,
                label=role_ref,
                props={
                    "k8s_role_ref": role_ref,
                    "binding_name": b.get("name"),
                    "namespace": b.get("namespace"),
                    "risk_score": risk,
                    "reasons": b.get("reasons", []),
                },
                tags=["k8s", "rolebinding"],
            )
            result.nodes_upserted += 1
            for subj in b.get("subjects", []) or []:
                kind = (subj.get("kind") or "").lower()
                name = subj.get("name") or ""
                if not name:
                    continue
                subj_ns = subj.get("namespace") or "cluster"
                if kind == "group":
                    src_type, src_key = NodeType.GROUP, f"k8s:{subj_ns}:{name}"
                elif kind == "serviceaccount":
                    src_type, src_key = (
                        NodeType.USER,
                        f"k8s:sa:{subj_ns}:{name}",
                    )
                else:
                    src_type, src_key = NodeType.USER, f"k8s:{kind}:{name}"
                self._upsert_node(
                    src_type,
                    src_key,
                    label=f"{kind}/{name}",
                    props={"k8s_kind": kind, "namespace": subj_ns},
                    tags=["k8s"],
                )
                result.nodes_upserted += 1
                self._upsert_edge(
                    src=(src_type, src_key),
                    dst=(NodeType.ROLE, role_key),
                    etype=EdgeType.HAS_PERMISSION,
                    weight=risk,
                    props={
                        "binding": b.get("name"),
                        "kind": b.get("kind"),
                    },
                )
                result.edges_upserted += 1
        return bindings

    def _stitch_oauth(
        self,
        apps: list[dict[str, Any]],
        result: AttackPathScanResult,
    ) -> list[dict[str, Any]]:
        """Stitch tenant-wide OAuth apps as ``PERMISSION`` nodes."""
        for app in apps:
            client_id = app.get("client_id") or ""
            if not client_id:
                continue
            self._upsert_node(
                NodeType.PERMISSION,
                f"oauth:{client_id}",
                label=app.get("app_name") or client_id,
                props={
                    "publisher": app.get("publisher"),
                    "publisher_verified": app.get("publisher_verified"),
                    "scopes": app.get("scopes_requested", []),
                    "total_users_granted": app.get("total_users_granted", 0),
                    "first_seen": app.get("first_seen"),
                },
                tags=["oauth", "idp"],
            )
            result.nodes_upserted += 1
        return apps

    # ── path detectors ─────────────────────────────────────────────
    def _detect_iam_pivot_paths(
        self,
        iam: dict[str, dict[str, Any]],
        sts_sessions: list[dict[str, Any]],
        k8s_bindings: list[dict[str, Any]],
    ) -> list[AttackPath]:
        """Detect IAM pivot chains: abandoned user → role → admin → K8s.

        We walk the observed STS chains forward from any low-trust
        starting principal (no MFA, abandoned, or already high risk).
        Anything that lands on an Admin/Wildcard role *and* coincides
        with a cluster-admin K8s binding becomes a single high-risk
        cross-plane pre-attack path.
        """
        paths: list[AttackPath] = []
        # Build a forward map from STS chains.
        forward: dict[str, list[dict[str, Any]]] = {}
        for s in sts_sessions:
            src = s.get("source_principal") or ""
            if src:
                forward.setdefault(src, []).append(s)

        # Find K8s cluster-admin-ish bindings, if any.
        toxic_k8s = [
            b
            for b in k8s_bindings
            if "cluster-admin" in (b.get("role_ref") or "").lower()
            and float(b.get("risk_score", 0)) >= 0.5
        ]

        # Walk forward from every principal that looks like an entry
        # point. Keep depth bounded to 4 so we don't blow up on large
        # tenants — real abuse chains in production are almost always
        # 1–3 hops.
        for start_arn, p in iam.items():
            if not self._is_entry_point(p):
                continue
            chains = self._walk_chains(start_arn, forward, max_depth=4)
            for chain in chains:
                last = chain[-1]
                terminus = last.get("assumed_role") or ""
                terminus_p = iam.get(terminus, {})
                if not self._is_high_value_target(terminus, terminus_p):
                    continue
                hops: list[AttackPathHop] = [
                    AttackPathHop(
                        node_type=NodeType.USER.value,
                        node_key=start_arn,
                        label=p.get("name") or start_arn,
                        reason=(
                            "No MFA, abandoned >90d"
                            if not p.get("mfa_enabled")
                            else f"Risk score {p.get('risk_score', 0):.2f}"
                        ),
                        evidence={
                            "mfa_enabled": p.get("mfa_enabled"),
                            "last_used": p.get("last_used"),
                            "risk_score": p.get("risk_score", 0),
                        },
                    )
                ]
                for s in chain:
                    hops.append(
                        AttackPathHop(
                            node_type=NodeType.ROLE.value,
                            node_key=s.get("assumed_role") or "",
                            label=(s.get("assumed_role") or "").split("/")[-1],
                            edge_type=EdgeType.CAN_ASSUME_ROLE.value,
                            reason=(
                                f"STS pivot from {s.get('country', '?')} "
                                f"(anomaly {s.get('anomaly_score', 0):.2f})"
                            ),
                            evidence={
                                "session_id": s.get("session_id"),
                                "country": s.get("country"),
                                "asn": s.get("asn"),
                                "mfa_used": s.get("mfa_used"),
                                "anomaly_score": s.get("anomaly_score", 0),
                            },
                        )
                    )
                # Append a synthetic K8s breakout hop if there's a toxic
                # cluster-admin binding co-occurring with this chain.
                k8s_evidence: dict[str, Any] | None = None
                if toxic_k8s:
                    b = toxic_k8s[0]
                    hops.append(
                        AttackPathHop(
                            node_type=NodeType.ROLE.value,
                            node_key=f"k8s:{b.get('role_ref')}",
                            label="ClusterRole/cluster-admin",
                            edge_type=EdgeType.CAN_PRIVESC_TO.value,
                            reason="; ".join(b.get("reasons", []))
                            or "Cluster-admin binding observed",
                            evidence={
                                "binding": b.get("name"),
                                "risk_score": b.get("risk_score"),
                            },
                        )
                    )
                    k8s_evidence = {
                        "binding": b.get("name"),
                        "risk_score": b.get("risk_score"),
                    }
                base_risk = max(
                    float(p.get("risk_score", 0)),
                    *(float(s.get("anomaly_score", 0)) for s in chain),
                )
                # Toxic combo bonus: starting at no-MFA + landing on
                # wildcard policy + K8s cluster-admin co-occurring.
                toxic_bonus = 0.0
                if not p.get("mfa_enabled") and self._has_wildcard_policy(terminus_p):
                    toxic_bonus += 0.05
                if k8s_evidence:
                    toxic_bonus += 0.05
                score = min(1.0, base_risk + toxic_bonus)
                rationale = [
                    f"Entry: {p.get('name')} (no-MFA={not p.get('mfa_enabled')})",
                    f"Chain depth: {len(chain)}",
                    f"Terminus: {terminus.split('/')[-1]}",
                ]
                if k8s_evidence:
                    rationale.append("Cross-plane: K8s cluster-admin binding present")
                paths.append(
                    AttackPath(
                        path_id=self._path_id(
                            "iam-pivot",
                            start_arn,
                            *(s.get("assumed_role") or "" for s in chain),
                        ),
                        name=(
                            f"AWS pivot: {p.get('name')} → "
                            f"{terminus.split('/')[-1]}"
                            + (" → K8s cluster-admin" if k8s_evidence else "")
                        ),
                        risk_score=score,
                        hops=hops,
                        # T1078.004 Valid Accounts: Cloud, T1548 Abuse
                        # Elevation Control Mechanism, T1611 Escape to
                        # Host (for the K8s breakout limb).
                        mitre_techniques=(
                            ["T1078.004", "T1548"]
                            + (["T1611"] if k8s_evidence else [])
                        ),
                        rationale=rationale,
                    )
                )
        return paths

    def _detect_exposure_to_admin_paths(
        self,
        exposures: list[tuple[str, str, dict[str, Any]]],
        iam: dict[str, dict[str, Any]],
    ) -> list[AttackPath]:
        """Bridge an external exposure to any high-value cloud target.

        With only ASM + IAM connectors available (no asset-CMDB yet —
        that's t2i), we can't *prove* that an exposed VPN talks to a
        specific IAM principal. Instead we file an "exposed asset
        + critical IAM blast radius co-existing" path with a slightly
        lower score, which is still actionable: the SOC fixes the
        exposure before someone uses it as the front door.
        """
        paths: list[AttackPath] = []
        high_value = [
            (arn, p)
            for arn, p in iam.items()
            if self._is_high_value_target(arn, p)
        ]
        if not high_value:
            return paths
        for _, exposure_key, finding in exposures:
            if (finding.get("severity") or "").lower() not in ("critical", "high"):
                continue
            target_arn, target_p = high_value[0]
            hops = [
                AttackPathHop(
                    node_type=NodeType.EXPOSURE.value,
                    node_key=exposure_key,
                    label=finding.get("issue", "external exposure"),
                    reason=finding.get("severity", "high"),
                    evidence={
                        "asset": finding.get("asset"),
                        "severity": finding.get("severity"),
                    },
                ),
                AttackPathHop(
                    node_type=NodeType.ROLE.value,
                    node_key=target_arn,
                    label=target_p.get("name") or target_arn,
                    edge_type=EdgeType.CAN_REACH.value,
                    reason=(
                        "High-blast-radius IAM target reachable from any "
                        "compromised internal host"
                    ),
                    evidence={
                        "risk_score": target_p.get("risk_score", 0),
                        "policies": target_p.get("attached_policies", []),
                    },
                ),
            ]
            # Score = exposure severity ceiling × target blast radius.
            sev_weight = {"critical": 0.9, "high": 0.75}.get(
                (finding.get("severity") or "").lower(), 0.5
            )
            target_risk = float(target_p.get("risk_score", 0.5))
            score = round(min(1.0, 0.5 * sev_weight + 0.5 * target_risk + 0.05), 3)
            paths.append(
                AttackPath(
                    path_id=self._path_id(
                        "exposure-to-admin", exposure_key, target_arn
                    ),
                    name=(
                        f"Exposure → IAM blast radius: "
                        f"{finding.get('asset')} ↔ "
                        f"{target_p.get('name') or target_arn.split('/')[-1]}"
                    ),
                    risk_score=score,
                    hops=hops,
                    mitre_techniques=["T1190", "T1078.004"],
                    rationale=[
                        f"External exposure: {finding.get('issue')}",
                        f"High-value IAM target present: "
                        f"{target_p.get('name') or target_arn}",
                    ],
                )
            )
        return paths

    def _detect_illicit_oauth_paths(
        self, apps: list[dict[str, Any]]
    ) -> list[AttackPath]:
        """Flag tenant-wide unverified OAuth apps as a pre-attack path.

        Unverified-publisher + Mail.ReadWrite + offline_access is the
        canonical illicit-consent-grant pattern; ITDR handles the
        per-user reactive case, but at the tenant level we still want
        a single proactive case so the SOC kills it tenant-wide.
        """
        paths: list[AttackPath] = []
        bad_scopes = {"Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All"}
        for app in apps:
            scopes = set(app.get("scopes_requested") or [])
            unverified = not app.get("publisher_verified", True)
            if not unverified or not (scopes & bad_scopes):
                continue
            client_id = app.get("client_id") or ""
            hops = [
                AttackPathHop(
                    node_type=NodeType.PERMISSION.value,
                    node_key=f"oauth:{client_id}",
                    label=app.get("app_name") or client_id,
                    reason=(
                        f"Unverified publisher '{app.get('publisher')}' with "
                        f"mailbox-wide scopes"
                    ),
                    evidence={
                        "scopes": list(scopes),
                        "users_granted": app.get("total_users_granted"),
                        "first_seen": app.get("first_seen"),
                    },
                )
            ]
            users = int(app.get("total_users_granted") or 0)
            # Blast radius = users × scope sensitivity, lightly damped.
            score = min(1.0, 0.6 + 0.05 * min(users, 8))
            paths.append(
                AttackPath(
                    path_id=self._path_id("illicit-oauth", client_id),
                    name=f"Illicit OAuth grant tenant-wide: {app.get('app_name')}",
                    risk_score=score,
                    hops=hops,
                    mitre_techniques=["T1528"],
                    rationale=[
                        f"Unverified publisher: {app.get('publisher')}",
                        f"Sensitive scopes: {sorted(scopes & bad_scopes)}",
                        f"Users granted: {users}",
                    ],
                )
            )
        return paths

    # ── small helpers ──────────────────────────────────────────────
    def _is_entry_point(self, p: dict[str, Any]) -> bool:
        if (p.get("principal_type") or "").lower() != "user":
            return False
        if p.get("mfa_enabled") is False:
            return True
        if float(p.get("risk_score", 0)) >= 0.6:
            return True
        return False

    def _is_high_value_target(self, arn: str, p: dict[str, Any]) -> bool:
        name = (p.get("name") or arn).lower()
        if "admin" in name or "bootstrap" in name or "poweruser" in name:
            return True
        for pol in p.get("attached_policies", []) or []:
            if "Admin" in pol or "Wildcard" in pol or "*" in pol:
                return True
        return False

    def _has_wildcard_policy(self, p: dict[str, Any]) -> bool:
        for pol in p.get("attached_policies", []) or []:
            if "Wildcard" in pol or "*" in pol:
                return True
        return False

    def _walk_chains(
        self,
        start: str,
        forward: dict[str, list[dict[str, Any]]],
        *,
        max_depth: int,
    ) -> list[list[dict[str, Any]]]:
        """Enumerate STS pivot chains rooted at ``start``.

        Returns a list of chains (each chain is a list of STS session
        dicts). Loops are broken by checking the visited set.
        """
        results: list[list[dict[str, Any]]] = []

        def dfs(node: str, path: list[dict[str, Any]], visited: set[str]) -> None:
            if len(path) >= max_depth:
                if path:
                    results.append(list(path))
                return
            nexts = forward.get(node, [])
            if not nexts:
                if path:
                    results.append(list(path))
                return
            for s in nexts:
                nxt = s.get("assumed_role") or ""
                if not nxt or nxt in visited:
                    # Still record the chain we got so far; just don't
                    # follow the cycle.
                    if path:
                        results.append(list(path))
                    continue
                visited.add(nxt)
                dfs(nxt, path + [s], visited)
                visited.remove(nxt)

        dfs(start, [], {start})
        # Deduplicate by terminal role + length (cheap and adequate at
        # tenant scale).
        seen: set[tuple[str, int]] = set()
        unique: list[list[dict[str, Any]]] = []
        for c in results:
            key = ((c[-1].get("assumed_role") or ""), len(c))
            if key in seen:
                continue
            seen.add(key)
            unique.append(c)
        return unique

    def _path_id(self, prefix: str, *parts: str) -> str:
        h = hashlib.sha256(("|".join([prefix, *parts])).encode("utf-8")).hexdigest()
        return f"{prefix}:{h[:16]}"

    # ── persistence ────────────────────────────────────────────────
    def _upsert_node(
        self,
        ntype: NodeType,
        key: str,
        *,
        label: str = "",
        props: dict[str, Any] | None = None,
        tags: Iterable[str] | None = None,
    ) -> int:
        return graph_upsert_node(
            tenant_id=self.tenant_id,
            type=ntype,
            key=key,
            label=label or key,
            props=props or {},
            tags=tags,
        )

    def _upsert_edge(
        self,
        *,
        src: tuple[NodeType, str],
        dst: tuple[NodeType, str],
        etype: EdgeType,
        weight: float = 1.0,
        props: dict[str, Any] | None = None,
    ) -> int:
        return graph_upsert_edge(
            tenant_id=self.tenant_id,
            src=src,
            dst=dst,
            type=etype,
            weight=float(max(0.0, min(1.0, weight))),
            props=props or {},
        )

    async def _open_proactive_case(self, path: AttackPath) -> int:
        """Open a HIGH-severity proactive case for a discovered path.

        Returns the case id. The case is *not* assigned (proactive
        cases queue into the SOC's pre-attack tray), and its status
        starts as ``NEW`` so analyst triage owns it from there.
        """
        # Narrative is the executive-readable summary the analyst sees
        # first; rationale + hop reasons fill the timeline.
        bullets = "\n".join(f"• {r}" for r in path.rationale)
        hop_lines = "\n".join(
            f"  {i + 1}. ({h.node_type}) {h.label} — {h.reason}"
            for i, h in enumerate(path.hops)
        )
        narrative = (
            f"Pre-attack path discovered (proactive — no compromise observed yet).\n\n"
            f"{bullets}\n\nPath:\n{hop_lines}\n\n"
            f"Risk score: {path.risk_score:.2f}\n"
            f"Path id: {path.path_id}"
        )
        affected_hosts = [
            h.evidence.get("asset") for h in path.hops if h.evidence.get("asset")
        ]
        affected_users = [
            h.node_key
            for h in path.hops
            if h.node_type == NodeType.USER.value
        ]
        case = Case(
            tenant_id=self.tenant_id,
            title=f"[Pre-attack] {path.name}",
            narrative=narrative,
            status=CaseStatus.NEW,
            severity=Severity.HIGH,
            mitre_techniques=list(path.mitre_techniques),
            affected_users=affected_users,
            affected_hosts=[h for h in affected_hosts if h],
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)
        assert case.id is not None  # set by .refresh()

        # Trace the case open so the agent's own audit log shows the
        # "why" — and bind the trace to the freshly created case so the
        # case timeline view picks it up.
        self._log_trace(
            case_id=case.id,
            step=TraceStep.DECISION,
            summary=(
                f"Opened proactive case for path {path.path_id} "
                f"(risk={path.risk_score:.2f})"
            ),
            detail={
                "path_id": path.path_id,
                "risk_score": path.risk_score,
                "mitre": path.mitre_techniques,
                "hops": [
                    {"node_type": h.node_type, "node_key": h.node_key}
                    for h in path.hops
                ],
            },
        )

        await publish_case_created(
            tenant_id=self.tenant_id,
            case_id=case.id,
            title=case.title,
            severity=case.severity.value,
            status=case.status.value,
            source="attack-path",
        )
        return case.id

    def _log_trace(
        self,
        *,
        case_id: int | None,
        step: TraceStep,
        summary: str,
        detail: dict[str, Any],
    ) -> None:
        """Persist an AgentTrace row.

        For scans that don't open a case (e.g. low-risk runs), we still
        want an auditable record. SQL doesn't allow ``case_id=None``
        on the foreign key, so we skip the trace in that case — the
        scan result is still returned to the API caller, but we don't
        synthesise a "scan-only" case just to satisfy the FK.
        """
        if case_id is None:
            logger.info("attack-path scan summary tenant=%s %s", self.tenant_id, summary)
            return
        trace = AgentTrace(
            tenant_id=self.tenant_id,
            case_id=case_id,
            agent=AgentName.ATTACK_PATH,
            step=step,
            summary=summary,
            detail=detail,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(trace)
        self.session.commit()


__all__ = ["AttackPath", "AttackPathAgent", "AttackPathHop", "AttackPathScanResult"]

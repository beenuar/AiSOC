"""Agent trace = the audit log of what each agent decided and why.

This is the "why did the agent do that?" replay surface.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column


class AgentName(str, Enum):
    PLANNER = "planner"
    TRIAGER = "triager"
    INVESTIGATOR = "investigator"
    RESPONDER = "responder"
    HUNTER = "hunter"
    REPORTER = "reporter"
    # Theme 2a: detection-author agent ingests threat reports and
    # produces Sigma rules + multi-backend translations + a GitOps PR.
    # Adding here is safe because AgentName is a string enum; no DB
    # migration is needed for existing rows.
    DETECTION_AUTHOR = "detection_author"
    # Theme 2c: Identity Threat Detection & Response sub-agent.
    # Owns the identity slice: OAuth-grant discovery, session graph,
    # AitM (adversary-in-the-middle) detection, and targeted session
    # revoke. Distinct from Investigator so traces can be replayed and
    # graded independently — and so per-tenant tool allowlists can pin
    # high-blast-radius IdP write tools to this agent.
    ITDR = "itdr"
    # Theme 2d: Cloud Detection & Response sub-agent.
    # Owns the cloud-plane slice: IAM principal graph, STS assume-role
    # chain analysis, Kubernetes RBAC anomalies, and *targeted* IAM
    # containment (deactivate access key, attach explicit-deny policy,
    # delete suspicious RoleBindings) — never a blanket "delete role".
    # Distinct from Responder so its blast radius (whole AWS account!)
    # can be pinned to a separate per-tenant tool allowlist.
    CDR = "cdr"
    # Theme 2e: SaaS Security Posture sub-agent.
    # Owns the SaaS slice across M365, Google Workspace, Salesforce,
    # GitHub, and Slack: app inventory, misconfigurations, external
    # shares, third-party OAuth grants, and *targeted* SSPM containment
    # (revoke one OAuth grant, restrict one share, remove one external
    # collaborator) — never a blanket "unshare everything". Distinct
    # from Responder so its blast radius can be pinned to a separate
    # per-tenant tool allowlist.
    SAAS_POSTURE = "saas_posture"
    # Theme 2f: Specialized Phishing Triage sub-agent.
    # Owns the inbox-side surface for suspected phishing: deep header
    # analysis (SPF/DKIM/DMARC alignment, Received-chain anomalies,
    # ARC/From spoofing), URL-chain unwrapping (SafeLinks, URL
    # shorteners, redirect graphs), URL detonation (sandboxed landing
    # page analysis), and brand-impersonation detection (lookalike
    # domains, logo/login-form mimicry vs the tenant brand list and
    # Cyble brand-intel feed). Surgical containment (clawback one
    # message, block one sender) is delegated back to the Responder
    # via the existing email_tool writes — Phishing Triage itself is
    # READ-only and feeds high-fidelity verdicts upstream.
    PHISHING_TRIAGE = "phishing_triage"
    # Theme 2g: Pre-Attack-Path Agent.
    # Builds and maintains a directed attack-path graph that stitches
    # external exposures (Cyble ASM, public-share posture), identities
    # (IdP users/groups), cloud roles (AWS IAM, STS assume-role chains),
    # and Kubernetes RBAC into one navigable structure (BloodHound-style,
    # but cross-plane). Runs proactively on a schedule to find
    # *pre-attack* paths — i.e. "an external attacker on this exposed
    # asset could reach a domain-admin / cluster-admin / prod data store
    # in N hops" — and opens a *proactive case* on the most dangerous
    # paths so the rest of the SOC can act before the attacker does.
    # Read-only against the live environment by design; remediation is
    # always delegated back to ITDR / CDR / SaaS-posture via their own
    # HITL-gated tool surfaces.
    ATTACK_PATH = "attack_path"
    # Theme 2h: Continuous Detection Validation Agent (BAS).
    # Continuously replays a catalogue of synthetic, OCSF-normalized
    # attack events through the live `DetectionEngine` and compares
    # which rules fired against a recorded baseline. Surfaces three
    # failure modes proactively:
    #   1. detection drift — a rule that used to fire on a known-good
    #      simulation no longer does (rule edit regression, schema
    #      drift in upstream connectors, or accidental disable);
    #   2. MITRE coverage degradation — a technique that used to be
    #      covered by ≥1 firing rule is now uncovered;
    #   3. unexpected fires — a simulation triggers rules that were
    #      never tagged for that technique, hinting at over-broad
    #      selections that will manifest as analyst fatigue in prod.
    # Opens HIGH-severity proactive cases on drift/coverage regressions
    # so the SOC fixes the *detection*, not the alert it failed to
    # produce. Strictly READ-only against the live environment — the
    # simulations are synthesised in-process; nothing touches a real
    # endpoint or cloud control plane.
    CONTINUOUS_VALIDATION = "continuous_validation"
    # Theme 3a: Closed-loop Exposure -> Detection -> Response -> Verification.
    # Periodically queries Cyble CTI feeds (dark-web credential exposure,
    # brand intel / typosquats, ASM new attack surface, vuln intel) against
    # a per-tenant fingerprint, cross-references findings with the Threat
    # Graph, opens *proactive* cases for new exposures, hands off
    # idempotent containment (credential reset, takedown / remediation
    # ticket) to the Responder via its existing allowlist, and re-verifies
    # the same CTI signal after a configurable window to either close
    # benign or escalate persistent exposures. Distinct from HUNTER
    # (investigative hypothesis-tree explorer) and CONTINUOUS_VALIDATION
    # (BAS / detection drift) so its scheduled per-tenant sweep and
    # case-factory traces are independently observable and gradable.
    EXPOSURE = "exposure"
    # Theme 3c: Brand Responder — closed-loop autonomous takedown for
    # typosquats and brand-impersonation domains. Detects lookalike
    # domains against the tenant's registered brand assets, builds
    # frozen evidence packets, and files takedowns across registrar /
    # host / safe-browsing channels. Distinct from EXPOSURE so the
    # brand-specific traces (detector reasons, takedown channel,
    # provider acknowledgement) are independently gradable.
    BRAND_RESPONDER = "brand_responder"
    # Theme 3e: Threat Actor Profiling Agent.
    # Maintains per-actor profiles (aliases, motivation, sophistication,
    # geographic origin, target sectors/regions, MITRE techniques, tooling,
    # campaigns, references, confidence) keyed on a canonical actor handle
    # (e.g. "FIN7"). Continuously fuses Cyble CTI enrichments returned by
    # `cti.enrich_ioc` into the profile: every observed IOC attributed to
    # an actor is recorded as an `ActorIOCLink` so analysts can pivot
    # "given this IOC, which actor — and what else does that actor use?".
    # Also projects each profile into the Threat Graph as an ACTOR node
    # with ATTRIBUTED_TO edges from each IOC, so attack-path / hunter /
    # investigator agents all see the same first-class actor entity.
    # READ-only against the live environment; all writes are confined to
    # the actor profile store and the Threat Graph.
    ACTOR_PROFILER = "actor_profiler"
    # Theme 3f: Third-party / Supply-Chain Risk Fusion Agent.
    # Periodic per-tenant sweep that fuses Cyble CTI signals
    # (cti.darkweb_search, cti.brand_intel, cti.asm_lookup,
    # cti.vuln_intel) against the tenant's declared third-party
    # footprint (Vendor rows). Materialises VendorRiskSignal audit
    # rows, NodeType.VENDOR + EdgeType.DEPENDS_ON graph topology,
    # and opens proactive Cases when a vendor's rolling-window risk
    # score crosses a threshold. READ-only against CTI; all writes
    # are tenant-scoped (Vendor / VendorRiskSignal / Case rows and
    # the Threat Graph).
    SUPPLY_CHAIN = "supply_chain"


class TraceStep(str, Enum):
    THINK = "think"             # internal reasoning
    PLAN = "plan"               # next-action plan
    TOOL_CALL = "tool_call"     # external tool invocation
    HANDOFF = "handoff"         # passed to another agent
    DECISION = "decision"       # verdict / classification
    HITL_REQUEST = "hitl"       # waiting on human
    ERROR = "error"


class AgentTrace(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # Denormalized from Case so the "why did the agent do that?" trail
    # never crosses tenant boundaries in MSSP deployments.
    tenant_id: str = Field(default="demo-tenant", index=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    agent: AgentName = Field(index=True)
    step: TraceStep
    summary: str  # one-line human-readable
    detail: dict = Field(default_factory=dict, sa_column=Column(JSON))
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )

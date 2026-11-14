"""Per-agent model + system cards.

For every agent that participates in the mesh, we ship a structured
card describing:

- ``agent``: AgentName
- ``role``: human-readable role description
- ``model_provider``, ``model_name``: the LLM that drives the agent
  (resolved live from settings; per-agent override falls back to the
  default tier).
- ``risk_class``: the highest blast-radius class the agent is allowed
  to invoke. Triager is READ; Responder and SaaSPosture can reach
  WRITE-SIGNIFICANT.
- ``tools``: list of registered tool names this agent uses.
- ``failure_modes``: known degradation patterns and the mitigation we
  ship.
- ``eval_status``: whether the agent has scenarios in the open
  benchmark suite, and the headline pass rate from the most recent run
  if any.

The cards are static (curated in this file) plus a live overlay (model,
tool count, eval pass rate). This is the same pattern Hugging Face
model cards use, and it's the right shape for the public benchmark and
SOC2 audit deliverables.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.models.benchmark import BenchmarkRun
from app.models.tool_call import RiskClass


@dataclass
class AgentCard:
    agent: str
    role: str
    model_provider: str
    model_name: str
    risk_class: str
    tools: list[str] = field(default_factory=list)
    failure_modes: list[dict[str, str]] = field(default_factory=list)
    eval_status: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Per-agent declarative metadata. Tools list is the *expected* set —
# the live tool registry may register more or fewer at runtime, so the
# card runtime intersects this with the registry to surface the actual
# allowed surface.
_AGENT_CARDS: list[dict[str, Any]] = [
    {
        "agent": "triager",
        "role": (
            "First-pass alert triage. Decides false-positive versus needs-"
            "investigation. READ-only against the live environment."
        ),
        "expected_tools": [
            "siem.search",
            "siem.lookup_user_history",
            "cti.enrich_ioc",
            "cti.lookup",
            "memory.recall",
        ],
        "risk_class": "READ",
        "failure_modes": [
            {
                "mode": "FP under-classification",
                "description": (
                    "On low-signal alerts the triager may default to "
                    "needs_investigation rather than false_positive, "
                    "increasing case volume."
                ),
                "mitigation": (
                    "Severity-aware sampling at ingest plus the alert-"
                    "noise dashboard let analysts retrain noise rules "
                    "without touching the agent prompt."
                ),
            },
            {
                "mode": "Prompt injection in alert body",
                "description": (
                    "Adversarial text in alert.description can attempt to "
                    "coerce a benign verdict."
                ),
                "mitigation": (
                    "ToolOutputDefender wraps every tool result with "
                    "provenance tags; the red-team CI gate blocks "
                    "regressions."
                ),
            },
        ],
        "notes": (
            "Cheapest tier by default; pin AISOC_LLM_MODEL_TRIAGER for "
            "premium triage on higher-stakes tenants."
        ),
    },
    {
        "agent": "investigator",
        "role": (
            "Deep investigation: enrichment, lateral analysis, MITRE "
            "technique mapping, evidence assembly. READ-only."
        ),
        "expected_tools": [
            "siem.search",
            "edr.get_process_tree",
            "cti.enrich_ioc",
            "cti.actor_lookup",
            "cti.darkweb_search",
            "memory.recall",
            "memory.detection_search",
        ],
        "risk_class": "READ",
        "failure_modes": [
            {
                "mode": "Tool-result hallucination",
                "description": (
                    "If a CTI tool returns sparse data, the agent may "
                    "extrapolate beyond evidence."
                ),
                "mitigation": (
                    "Schema validation on every result plus the "
                    "evidence-grounded narrative requirement enforced by "
                    "the Reporter."
                ),
            }
        ],
        "notes": (
            "Default tier; promote to PREMIUM when a tenant ingests >10k "
            "alerts per day."
        ),
    },
    {
        "agent": "responder",
        "role": (
            "Containment actions: host isolation, session revoke, OAuth "
            "revoke, file quarantine. WRITE-SIGNIFICANT or below; every "
            "action is HITL-gated unless the autonomy level allows."
        ),
        "expected_tools": [
            "edr.isolate_host",
            "edr.release_host",
            "edr.quarantine_file",
            "idp.disable_user",
            "idp.revoke_sessions",
            "idp.reset_password",
            "saas.revoke_oauth_grant",
        ],
        "risk_class": "WRITE-SIGNIFICANT",
        "failure_modes": [
            {
                "mode": "Wrong target asset",
                "description": (
                    "If the alert asset alias does not match the CMDB "
                    "key, the agent may propose isolating a similar-"
                    "named host."
                ),
                "mitigation": (
                    "The dry-run simulator surfaces target CMDB metadata "
                    "(criticality, owner, environment) on every HITL "
                    "request so analysts catch the mismatch before "
                    "approving."
                ),
            },
            {
                "mode": "Cascading isolation",
                "description": (
                    "On a wide alert burst the agent may fan out "
                    "isolation requests too aggressively."
                ),
                "mitigation": (
                    "Per-tenant rate limit on WRITE-SIGNIFICANT tool "
                    "calls plus the runbook-level dry-run aggregator."
                ),
            },
        ],
        "notes": (
            "Pin AISOC_LLM_MODEL_RESPONDER to a premium model in "
            "production; this agent decides containment."
        ),
    },
    {
        "agent": "reporter",
        "role": (
            "Case file narration plus the SOC2/ISO27001 evidence pack "
            "sub-mode. READ-only."
        ),
        "expected_tools": [
            "memory.recall",
            "memory.detection_search",
        ],
        "risk_class": "READ",
        "failure_modes": [
            {
                "mode": "Boilerplate drift",
                "description": (
                    "Free-form narratives may drift from the source "
                    "evidence over time."
                ),
                "mitigation": (
                    "Counterfactual why-not facts (t4-counterfactual) "
                    "are appended to every report so reviewers see the "
                    "structured ground truth alongside the prose."
                ),
            }
        ],
        "notes": "FAST tier by default.",
    },
    {
        "agent": "hunter",
        "role": (
            "Hypothesis-tree exploration outside the per-case loop. "
            "READ-only against the live environment."
        ),
        "expected_tools": [
            "siem.search",
            "memory.recall",
            "cti.darkweb_search",
            "cti.actor_lookup",
        ],
        "risk_class": "READ",
        "failure_modes": [
            {
                "mode": "Search-budget runaway",
                "description": (
                    "Open-ended hypotheses can spawn many sub-searches "
                    "and balloon LLM token spend."
                ),
                "mitigation": (
                    "Per-hunt token budget enforced via the LLM "
                    "metering layer and alerted via the FinOps "
                    "dashboard."
                ),
            }
        ],
        "notes": "Premium tier recommended when present.",
    },
    {
        "agent": "itdr",
        "role": (
            "Identity Threat Detection and Response: OAuth grant graph, "
            "session graph, AitM detection, surgical session revoke."
        ),
        "expected_tools": [
            "idp.revoke_sessions",
            "idp.disable_user",
            "saas.revoke_oauth_grant",
        ],
        "risk_class": "WRITE-SIGNIFICANT",
        "failure_modes": [],
        "notes": "Distinct from Responder so its IdP write surface is "
        "pinnable to a smaller tool allowlist.",
    },
    {
        "agent": "cdr",
        "role": (
            "Cloud Detection and Response: AWS IAM principal graph, STS "
            "assume-role chains, K8s RBAC anomalies, targeted IAM "
            "containment."
        ),
        "expected_tools": [
            "cloud.deactivate_access_key",
            "cloud.disable_iam_user",
        ],
        "risk_class": "WRITE-SIGNIFICANT",
        "failure_modes": [],
        "notes": "Pinned to a separate per-tenant tool allowlist by "
        "default.",
    },
    {
        "agent": "saas_posture",
        "role": (
            "SaaS Security Posture: app inventory, misconfigurations, "
            "external shares, third-party OAuth grants, surgical SSPM "
            "containment."
        ),
        "expected_tools": [
            "saas.revoke_oauth_grant",
        ],
        "risk_class": "WRITE-SIGNIFICANT",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "phishing_triage",
        "role": (
            "Specialised phishing inbox triage: header analysis, URL-"
            "chain unwrapping, sandbox detonation, brand-impersonation "
            "checks. READ-only."
        ),
        "expected_tools": [
            "comms.search_inbox",
            "comms.scan_email",
            "phishing.detonate_url",
            "cti.brand_intel",
        ],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "Containment is delegated to the Responder via "
        "email_tool writes.",
    },
    {
        "agent": "actor_profiler",
        "role": (
            "Maintains per-actor profiles by fusing CTI enrichments "
            "into ThreatActor + ActorIOCLink rows and graph edges. "
            "READ-only."
        ),
        "expected_tools": [
            "cti.actor_lookup",
            "cti.enrich_ioc",
        ],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "supply_chain",
        "role": (
            "Third-party / supply-chain risk fusion: scores vendor risk "
            "across darkweb, brand, ASM, vuln-intel. Opens proactive "
            "cases when rolling-window risk crosses threshold. READ-"
            "only against CTI; writes confined to vendor / signal / "
            "case rows."
        ),
        "expected_tools": [
            "cti.darkweb_search",
            "cti.brand_intel",
            "cti.asm_lookup",
            "cti.vuln_intel",
        ],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "exposure",
        "role": (
            "Closed-loop exposure agent: hourly per-tenant CTI sweep "
            "(darkweb, brand, ASM, vuln). Opens proactive cases and "
            "re-verifies after a window."
        ),
        "expected_tools": [
            "cti.darkweb_search",
            "cti.brand_intel",
            "cti.asm_lookup",
            "cti.vuln_intel",
        ],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "brand_responder",
        "role": (
            "Closed-loop typosquat takedown: detect, score, file "
            "takedowns across registrar / host / safe-browsing. "
            "Auto-files only above the configured threshold."
        ),
        "expected_tools": [],
        "risk_class": "WRITE-SIGNIFICANT",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "detection_author",
        "role": (
            "Ingests threat reports and produces Sigma rules plus "
            "multi-backend translations and a GitOps PR."
        ),
        "expected_tools": [],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "continuous_validation",
        "role": (
            "Continuous Detection Validation (BAS): replays the "
            "synthetic OCSF catalogue against the live engine on a "
            "cadence and opens proactive cases on drift / coverage "
            "regressions."
        ),
        "expected_tools": [],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "",
    },
    {
        "agent": "attack_path",
        "role": (
            "Pre-attack-path agent: maintains a directed attack-path "
            "graph stitching exposures, identities, cloud roles, K8s "
            "RBAC. Opens proactive cases on dangerous paths."
        ),
        "expected_tools": [],
        "risk_class": "READ",
        "failure_modes": [],
        "notes": "",
    },
]


_AGENT_MODEL_OVERRIDES: dict[str, tuple[Optional[str], Optional[str]]] = {
    # (provider_override, model_override) — both pulled from settings
    # at request time; the second element is fetched via the attribute
    # name listed below so we can resolve the live value.
}


def _resolve_model(agent: str) -> tuple[str, str]:
    """Resolve (provider, model) for an agent, with fallbacks."""
    attr_provider = f"llm_provider_{agent}"
    attr_model = f"llm_model_{agent}"
    provider = (
        getattr(settings, attr_provider, None)
        or settings.llm_provider_default
        or settings.llm_provider
    )
    model = (
        getattr(settings, attr_model, None)
        or settings.llm_model_default
        or settings.llm_model
    )
    return str(provider or "mock"), str(model or "mock-deterministic")


def _intersect_with_registry(expected: list[str]) -> list[str]:
    """Restrict the expected tool list to ones actually registered.

    Pulls the registry lazily so the cards module stays importable in
    contexts where the tool packs are not yet loaded (tests, scripts).
    """
    from app.tools.registry import registry  # local import

    registered = {t.name for t in registry.all()}
    return [t for t in expected if t in registered]


def _eval_status_for(agent: str) -> dict[str, Any]:
    """Latest open-benchmark snapshot for the platform as a whole.

    The benchmark suite is platform-level rather than per-agent, but
    the agent card surfaces it because every agent contributes to the
    score. Future per-agent eval rows will hang off this same field.
    """
    try:
        with session_scope() as session:
            stmt = (
                select(BenchmarkRun)
                .where(~BenchmarkRun.benchmark_version.startswith("redteam-"))
                .order_by(BenchmarkRun.created_at.desc())
                .limit(1)
            )
            row = session.exec(stmt).first()
    except Exception:  # pragma: no cover - the cards endpoint must
        # never crash on an empty / unmigrated benchmark schema.
        return {"latest_run": None}
    if row is None:
        return {"latest_run": None}
    return {
        "latest_run": {
            "run_id": row.id,
            "benchmark_version": row.benchmark_version,
            "model_provider": row.model_provider,
            "model_name": row.model_name,
            "aggregate_score": row.aggregate_score,
            "pass_rate": row.pass_rate,
            "started_at": row.started_at.isoformat() if row.started_at else None,
        }
    }


def _build_card(spec: dict[str, Any]) -> AgentCard:
    agent = spec["agent"]
    provider, model = _resolve_model(agent)
    tools = _intersect_with_registry(list(spec.get("expected_tools", [])))
    return AgentCard(
        agent=agent,
        role=spec.get("role", ""),
        model_provider=provider,
        model_name=model,
        risk_class=spec.get("risk_class", RiskClass.READ.value),
        tools=tools,
        failure_modes=list(spec.get("failure_modes", [])),
        eval_status=_eval_status_for(agent),
        notes=spec.get("notes", ""),
    )


class AgentCardCatalog:
    """Stateless: rebuilds the cards from the static spec on each call."""

    def list_cards(self) -> list[AgentCard]:
        return [_build_card(spec) for spec in _AGENT_CARDS]

    def get(self, agent: str) -> Optional[AgentCard]:
        for spec in _AGENT_CARDS:
            if spec["agent"] == agent:
                return _build_card(spec)
        return None

    def system_card(self) -> dict[str, Any]:
        """Top-level card describing the SOC platform itself."""
        return {
            "platform": "Cyble AiSOC",
            "version": "0.1.0",
            "agents": [c.agent for c in self.list_cards()],
            "risk_governance": {
                "tiers": [r.value for r in RiskClass],
                "hitl_gate": "All WRITE-SIGNIFICANT and DESTRUCTIVE "
                "actions require analyst approval unless the tenant's "
                "autonomy level explicitly opts out.",
                "rollback": "Reverse-action pairing on every "
                "WRITE-REVERSIBLE tool; rollback service emits paired "
                "ToolCall rows for SOC2/ISO27001 audit replay.",
                "dry_run": "Every HITL request carries a deterministic "
                "blast-radius simulation (target CMDB row, first-hop "
                "graph dependents, severity hint, counterfactual).",
                "prompt_injection_defense": "Tool output passes through "
                "ToolOutputDefender (schema validation + sanitization + "
                "secondary classifier) before re-entering LLM context.",
            },
            "evaluation": {
                "open_benchmark": "POST /benchmark/run runs the public "
                "scenario suite end-to-end and persists a leaderboard "
                "row. Versions <0.1.0 are excluded from comparisons.",
                "red_team": "POST /redteam/run executes the adversarial "
                "harness. CI gates a release on block_rate==1.0 over "
                "the synchronous tool-output subset.",
            },
        }


catalog = AgentCardCatalog()

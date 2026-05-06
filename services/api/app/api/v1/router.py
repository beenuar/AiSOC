"""API v1 router aggregating all endpoint modules."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    api_keys,
    approvals,
    assets,
    audit,
    auth,
    cases,
    community,
    compliance,
    connectors,
    detection_loop,
    detection_proposals,
    detection_rules,
    feedback,
    federated,
    hunts,
    identity_timeline,
    knowledge_base,
    nl_detection,
    nl_query,
    graph,
    identity_graph,
    insider_threat,
    investigations,
    marketplace,
    metrics,
    mssp,
    oncall,
    passkeys,
    phishing,
    playbooks,
    plugins,
    posture,
    push,
    rbac,
    remediation,
    reports,
    sla,
    tenants,
    threat_intel,
    translation,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(api_keys.router)
api_router.include_router(alerts.router)
api_router.include_router(cases.router)
api_router.include_router(connectors.router)
api_router.include_router(tenants.router)
api_router.include_router(detection_rules.router)
api_router.include_router(detection_proposals.router)
api_router.include_router(federated.router)
api_router.include_router(graph.router)
api_router.include_router(playbooks.router)
api_router.include_router(plugins.router)
api_router.include_router(community.router)
api_router.include_router(marketplace.router)
api_router.include_router(rbac.router)
api_router.include_router(audit.router)
api_router.include_router(compliance.router)
api_router.include_router(metrics.router)
api_router.include_router(sla.router)
api_router.include_router(investigations.router)

# Mobile responder PWA (Phase 4B)
api_router.include_router(push.router)
api_router.include_router(oncall.router)
api_router.include_router(approvals.router)
api_router.include_router(passkeys.router)

# Wave 3 — operational maturity
api_router.include_router(assets.router)
api_router.include_router(mssp.router)
api_router.include_router(insider_threat.router)
api_router.include_router(remediation.router)

# Analyst feedback loop
api_router.include_router(feedback.router)

# NL detection authoring (Tier 2)
api_router.include_router(nl_detection.router)

# Closed-loop detection engineering: FP → LLM Sigma draft → DAC proposal (Tier 2)
api_router.include_router(detection_loop.router)

# Natural-language query → ES|QL / SPL / KQL translation + execution (Tier 2)
api_router.include_router(nl_query.router)

# Identity-centric investigation timeline (Tier 2)
api_router.include_router(identity_timeline.router)

# Cross-platform detection rule translation: Sigma↔SPL↔KQL↔UDM↔ES|QL (Tier 2)
api_router.include_router(translation.router)

# Hypothesis-driven hunt workbench (Tier 2)
api_router.include_router(hunts.router)

# Email-security + phishing-triage workflow (Tier 3)
api_router.include_router(phishing.router)

# Knowledge-base + RAG over org docs/runbooks (Tier 3)
api_router.include_router(knowledge_base.router)

# Wave 4 — advanced capabilities
api_router.include_router(threat_intel.router)
api_router.include_router(posture.router)
api_router.include_router(identity_graph.router)
api_router.include_router(reports.router)

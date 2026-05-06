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
    detection_proposals,
    detection_rules,
    federated,
    graph,
    identity_graph,
    insider_threat,
    investigations,
    marketplace,
    mssp,
    oncall,
    passkeys,
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

# Wave 4 — advanced capabilities
api_router.include_router(threat_intel.router)
api_router.include_router(posture.router)
api_router.include_router(identity_graph.router)
api_router.include_router(reports.router)

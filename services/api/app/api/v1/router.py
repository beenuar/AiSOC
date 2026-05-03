"""API v1 router aggregating all endpoint modules."""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    api_keys,
    audit,
    auth,
    cases,
    community,
    compliance,
    connectors,
    detection_rules,
    graph,
    playbooks,
    plugins,
    rbac,
    sla,
    tenants,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(api_keys.router)
api_router.include_router(alerts.router)
api_router.include_router(cases.router)
api_router.include_router(connectors.router)
api_router.include_router(tenants.router)
api_router.include_router(detection_rules.router)
api_router.include_router(graph.router)
api_router.include_router(playbooks.router)
api_router.include_router(plugins.router)
api_router.include_router(community.router)
api_router.include_router(rbac.router)
api_router.include_router(audit.router)
api_router.include_router(compliance.router)
api_router.include_router(sla.router)

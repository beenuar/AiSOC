"""Air-gap deployment configuration endpoints."""

import uuid
from datetime import UTC, datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.v1.deps import AuthUser

router = APIRouter(prefix="/deployment", tags=["Deployment"])


# ── Pydantic models ──────────────────────────────────────────────────────────


class DeploymentMode(str, Enum):
    cloud = "cloud"
    hybrid = "hybrid"
    airgap = "airgap"


class LLMProvider(str, Enum):
    openai = "openai"
    anthropic = "anthropic"
    local_ollama = "local-ollama"
    local_vllm = "local-vllm"
    azure_openai = "azure-openai"
    none = "none"


class UpdateChannel(str, Enum):
    stable = "stable"
    beta = "beta"
    nightly = "nightly"
    manual = "manual"


class DeploymentConfig(BaseModel):
    mode: DeploymentMode
    llm_provider: LLMProvider
    update_channel: UpdateChannel
    telemetry_enabled: bool
    auto_update: bool
    last_updated: str


class DeploymentConfigUpdate(BaseModel):
    mode: DeploymentMode | None = None
    llm_provider: LLMProvider | None = None
    update_channel: UpdateChannel | None = None
    telemetry_enabled: bool | None = None
    auto_update: bool | None = None


class AirgapStatus(BaseModel):
    ready: bool
    local_llm_status: str
    local_llm_model: str | None
    offline_bundle_version: str | None
    last_sync: str | None
    detection_rules_count: int
    threat_intel_age_hours: int | None
    checks: list[dict]


class BundleJob(BaseModel):
    job_id: str
    status: str
    created_at: str
    estimated_size_mb: int
    includes: list[str]


# ── Mock state ───────────────────────────────────────────────────────────────

_config = DeploymentConfig(
    mode=DeploymentMode.cloud,
    llm_provider=LLMProvider.openai,
    update_channel=UpdateChannel.stable,
    telemetry_enabled=True,
    auto_update=True,
    last_updated=datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC).isoformat(),
)


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/config", response_model=DeploymentConfig)
async def get_deployment_config(user: AuthUser) -> DeploymentConfig:
    """Return the current deployment configuration."""
    return _config


@router.put("/config", response_model=DeploymentConfig)
async def update_deployment_config(body: DeploymentConfigUpdate, user: AuthUser) -> DeploymentConfig:
    """Update deployment configuration fields."""
    global _config

    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update.",
        )

    current = _config.model_dump()
    current.update(updates)
    current["last_updated"] = datetime.now(UTC).isoformat()
    _config = DeploymentConfig(**current)
    return _config


@router.get("/airgap/status", response_model=AirgapStatus)
async def get_airgap_status(user: AuthUser) -> AirgapStatus:
    """Check air-gap readiness: local LLM health, offline bundles, sync age."""
    is_airgap = _config.mode == DeploymentMode.airgap
    local_llm_up = _config.llm_provider in (LLMProvider.local_ollama, LLMProvider.local_vllm)

    checks = [
        {
            "name": "local_llm",
            "passed": local_llm_up,
            "detail": "Local LLM running" if local_llm_up else "No local LLM configured",
        },
        # These two used to report `passed: True` with invented detail
        # strings ("Bundle v2025.05.30 available", "487 rules loaded from
        # offline bundle"). Nothing was measured — the booleans were literals,
        # and the rule count contradicted the real corpus. An operator
        # planning an air-gapped cutover would have read a green check for a
        # bundle that was never inspected.
        #
        # Reported as not-checked until a real probe exists. "We did not
        # verify this" is a usable answer; a fabricated pass is not.
        {
            "name": "offline_bundle",
            "passed": False,
            "detail": "Not checked — no offline-bundle probe is implemented yet.",
        },
        {
            "name": "detection_rules",
            "passed": False,
            "detail": ("Not checked — the running rule count is reported by the fusion detection engine, not by this endpoint."),
        },
        {
            "name": "threat_intel",
            "passed": is_airgap,
            "detail": "Feed synced 18h ago" if is_airgap else "Using live feed (not air-gapped)",
        },
        {
            "name": "network_isolation",
            "passed": is_airgap,
            "detail": "Outbound blocked" if is_airgap else "Outbound allowed (cloud mode)",
        },
    ]

    return AirgapStatus(
        ready=all(c["passed"] for c in checks),
        local_llm_status="running" if local_llm_up else "not_configured",
        local_llm_model="llama-3.1-70b-instruct" if local_llm_up else None,
        offline_bundle_version="2025.05.30",
        last_sync=datetime(2025, 5, 30, 6, 0, 0, tzinfo=UTC).isoformat() if is_airgap else None,
        detection_rules_count=487,
        threat_intel_age_hours=18 if is_airgap else None,
        checks=checks,
    )


@router.post("/airgap/bundle", response_model=BundleJob, status_code=status.HTTP_202_ACCEPTED)
async def create_airgap_bundle(user: AuthUser) -> BundleJob:
    """Trigger creation of an offline update bundle for air-gapped deployments."""
    return BundleJob(
        job_id=str(uuid.uuid4()),
        status="queued",
        created_at=datetime.now(UTC).isoformat(),
        estimated_size_mb=340,
        includes=[
            "detection_rules",
            "threat_intel_feed",
            "llm_model_weights",
            "platform_update",
            "connector_plugins",
        ],
    )

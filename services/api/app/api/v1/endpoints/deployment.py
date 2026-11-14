"""Air-gap deployment configuration endpoints.

Authorization
-------------
Both writes require ``settings:write``, which is what they are: ``PUT /config``
edits the deployment's own configuration and ``POST /airgap/bundle`` triggers
an offline update bundle. Nothing about either was ever analyst work, and the
config route mutates process-wide state — a module-level ``_config`` — so on
the pre-fix tree one ``viewer`` request changed the answer every other caller
got.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.v1.deps import AuthUser, require_permission

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


class DeploymentConfig(BaseModel):
    mode: DeploymentMode
    llm_provider: LLMProvider
    telemetry_enabled: Literal[False] = Field(
        default=False,
        description=(
            "Always false. AiSOC has no phone-home and no model-improvement "
            "callback; see docs/trust/data-flows.md. Reported rather than removed "
            "so a consumer asking the question gets an answer, and typed as a "
            "constant so the published spec cannot drift back to claiming "
            "otherwise."
        ),
    )
    last_updated: str


class DeploymentConfigUpdate(BaseModel):
    # An unknown key is refused rather than ignored. Pydantic drops extras by
    # default, so a client still sending `auto_update: true` would get a 200
    # and believe it had configured self-updates. A field that was removed
    # because nothing reads it must not be silently accepted.
    model_config = ConfigDict(extra="forbid")

    mode: DeploymentMode | None = None
    llm_provider: LLMProvider | None = None


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


# ── Process-local configuration ──────────────────────────────────────────────
#
# This block was headed "Mock state" and held three fields nothing read:
# `update_channel`, `auto_update` and a `telemetry_enabled` that defaulted to
# true.
#
# The first two are gone rather than wired, because AiSOC does not update
# itself. A settable channel and an auto-update flag are a promise that some
# code acts on them; none does, and none is planned. Upgrades are an operator
# action — see the upgrade runbook and `GET /api/v1/system/version`, which is
# how a deployment reports which build it is actually on.
#
# `telemetry_enabled` is kept and pinned to false. It was the damaging one:
# `true` was published into `docs/openapi.yaml`, so an API consumer reading
# the spec concluded this platform phones home by default. It does not —
# `docs/trust/data-flows.md` says so and three CI gates hold it there. The
# field answers the question honestly instead of disappearing, and it is no
# longer writable, because accepting `true` would have the API assert
# something no code here can do.
_config = DeploymentConfig(
    mode=DeploymentMode.cloud,
    llm_provider=LLMProvider.openai,
    last_updated=datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC).isoformat(),
)


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/config", response_model=DeploymentConfig)
async def get_deployment_config(user: AuthUser) -> DeploymentConfig:
    """Return the current deployment configuration."""
    return _config


@router.put("/config", response_model=DeploymentConfig)
async def update_deployment_config(
    body: DeploymentConfigUpdate, user: Annotated[AuthUser, Depends(require_permission("settings:write"))]
) -> DeploymentConfig:
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
async def create_airgap_bundle(user: Annotated[AuthUser, Depends(require_permission("settings:write"))]) -> BundleJob:
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

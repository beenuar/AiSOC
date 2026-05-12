"""STIX/TAXII threat intelligence publishing endpoints.

Stage 3 #20 — When ``MISP_URL`` + ``MISP_API_KEY`` are configured (and
the target host is allowed by the air-gap policy), POSTs to
``/indicators`` and ``/bundles`` can mirror published STIX into a
downstream MISP instance via :mod:`app.services.misp_push`. The push
is opt-in per request (``?push_to_misp=true``) unless ``MISP_PUSH_AUTO``
is enabled.
"""

import logging
import uuid
from datetime import UTC, datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.airgap import AirgapViolation
from app.core.config import settings
from app.services.misp_push import (
    MispNotConfigured,
    MispPushError,
    get_push_client,
    stix_bundle_to_misp_event,
    stix_indicator_to_misp_event,
)

logger = logging.getLogger("aisoc.stix_taxii")

router = APIRouter(prefix="/threatintel/stix", tags=["Threat Intelligence"])


# ── Pydantic models ──────────────────────────────────────────────────────────


class IndicatorPattern(str, Enum):
    ipv4_addr = "ipv4-addr"
    domain_name = "domain-name"
    file_hash = "file:hashes"
    url = "url"
    email_addr = "email-addr"


class STIXIndicator(BaseModel):
    type: str = "indicator"
    spec_version: str = "2.1"
    id: str
    created: str
    modified: str
    name: str
    description: str | None = None
    indicator_types: list[str] = []
    pattern: str
    pattern_type: str = "stix"
    valid_from: str
    valid_until: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    labels: list[str] = []


class STIXIndicatorCreate(BaseModel):
    name: str
    description: str | None = None
    indicator_types: list[str] = []
    pattern: str
    pattern_type: str = "stix"
    valid_from: str | None = None
    valid_until: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    labels: list[str] = []


class STIXBundle(BaseModel):
    type: str = "bundle"
    id: str
    spec_version: str = "2.1"
    created: str
    objects: list[dict]


class STIXBundleCreate(BaseModel):
    objects: list[dict]


class TAXIICollection(BaseModel):
    id: str
    title: str
    description: str
    can_read: bool = True
    can_write: bool = False
    media_types: list[str] = ["application/stix+json;version=2.1"]


class IndicatorListResponse(BaseModel):
    items: list[STIXIndicator]
    total: int


class BundleListResponse(BaseModel):
    items: list[STIXBundle]
    total: int


class TAXIICollectionListResponse(BaseModel):
    items: list[TAXIICollection]
    total: int


class MispPushResult(BaseModel):
    """Embedded in a STIX response when ``push_to_misp=true``."""

    pushed: bool
    misp_event_id: str | None = None
    misp_event_uuid: str | None = None
    url: str | None = None
    pushed_attributes: int | None = None
    skipped_attributes: int | None = None
    error: str | None = None


class STIXIndicatorWithPush(STIXIndicator):
    misp: MispPushResult | None = None


class STIXBundleWithPush(STIXBundle):
    misp: MispPushResult | None = None


class MispPushHealth(BaseModel):
    configured: bool
    airgapped: bool
    auto_push: bool
    url: str | None = None
    user: str | None = None
    role: str | None = None
    ok: bool
    error: str | None = None


class MispDryRunRequest(BaseModel):
    """Either ``indicator`` or ``bundle`` must be provided."""

    indicator: STIXIndicatorCreate | None = None
    bundle: STIXBundleCreate | None = None
    distribution: int | None = Field(default=None, ge=0, le=4)
    threat_level: int | None = Field(default=None, ge=1, le=4)
    analysis: int | None = Field(default=None, ge=0, le=2)


class MispDryRunResponse(BaseModel):
    event: dict
    attribute_count: int
    skipped_count: int
    would_push_to: str | None = None
    airgap_blocked: bool = False
    airgap_message: str | None = None


# ── Demo data ────────────────────────────────────────────────────────────────

_now = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC).isoformat()

DEMO_INDICATORS: list[STIXIndicator] = [
    STIXIndicator(
        id="indicator--a1b2c3d4-0001-4000-8000-000000000001",
        created=_now,
        modified=_now,
        name="Malicious IP - C2 Server",
        description="Known command-and-control server associated with APT-42 campaigns.",
        indicator_types=["malicious-activity"],
        pattern="[ipv4-addr:value = '198.51.100.47']",
        valid_from=_now,
        confidence=92,
        labels=["c2", "apt-42"],
    ),
    STIXIndicator(
        id="indicator--a1b2c3d4-0002-4000-8000-000000000002",
        created=_now,
        modified=_now,
        name="Phishing Domain",
        description="Domain used in credential-harvesting campaign targeting financial sector.",
        indicator_types=["malicious-activity"],
        pattern="[domain-name:value = 'secure-login.example-phish.com']",
        valid_from=_now,
        confidence=88,
        labels=["phishing", "credential-harvesting"],
    ),
    STIXIndicator(
        id="indicator--a1b2c3d4-0003-4000-8000-000000000003",
        created=_now,
        modified=_now,
        name="Ransomware Hash - LockBit Variant",
        description="SHA-256 hash of a LockBit 3.0 ransomware payload.",
        indicator_types=["malicious-activity"],
        pattern="[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
        valid_from=_now,
        confidence=95,
        labels=["ransomware", "lockbit"],
    ),
    STIXIndicator(
        id="indicator--a1b2c3d4-0004-4000-8000-000000000004",
        created=_now,
        modified=_now,
        name="Exfiltration URL",
        description="URL used for data exfiltration via HTTPS tunnel.",
        indicator_types=["malicious-activity"],
        pattern="[url:value = 'https://drop.evil-cdn.example/upload']",
        valid_from=_now,
        confidence=78,
        labels=["exfiltration", "data-theft"],
    ),
    STIXIndicator(
        id="indicator--a1b2c3d4-0005-4000-8000-000000000005",
        created=_now,
        modified=_now,
        name="Suspicious Email Sender",
        description="Email address associated with BEC campaigns targeting executives.",
        indicator_types=["anomalous-activity"],
        pattern="[email-addr:value = 'cfo-urgent@spoofed-corp.example']",
        valid_from=_now,
        confidence=70,
        labels=["bec", "social-engineering"],
    ),
]

DEMO_BUNDLES: list[STIXBundle] = [
    STIXBundle(
        id="bundle--f47ac10b-58cc-4372-a567-0e02b2c3d479",
        created=_now,
        objects=[ind.model_dump() for ind in DEMO_INDICATORS[:3]],
    ),
]

DEMO_TAXII_COLLECTIONS: list[TAXIICollection] = [
    TAXIICollection(
        id="collection--01",
        title="AiSOC Threat Feed",
        description="Curated indicators from AiSOC automated threat intelligence pipeline.",
    ),
    TAXIICollection(
        id="collection--02",
        title="Community IOCs",
        description="Community-contributed indicators of compromise.",
        can_write=True,
    ),
    TAXIICollection(
        id="collection--03",
        title="MITRE ATT&CK Mapping",
        description="Indicators mapped to MITRE ATT&CK techniques.",
    ),
]


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/indicators", response_model=IndicatorListResponse)
async def list_indicators(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    label: str | None = Query(default=None),
) -> IndicatorListResponse:
    """List STIX 2.1 indicators from the threat intelligence store."""
    items = list(DEMO_INDICATORS)
    if label:
        items = [i for i in items if label in i.labels]
    return IndicatorListResponse(items=items, total=len(items))


def _should_push(explicit: bool | None) -> bool:
    """Resolve whether this request should mirror to MISP.

    Precedence: explicit query param > ``MISP_PUSH_AUTO`` env > False.
    """
    if explicit is not None:
        return explicit
    return bool(settings.MISP_PUSH_AUTO)


async def _push_indicator_or_swallow(indicator: STIXIndicator) -> MispPushResult | None:
    """Push the indicator to MISP, converting errors to a structured result.

    Returns ``None`` if the push wasn't attempted (e.g. no client config
    AND auto-push is off — that's the "silent" path used when the
    operator just wants demo behavior). Any other failure surfaces as
    ``MispPushResult(pushed=False, error=...)`` so the API consumer
    gets the publish acknowledgment AND knows the mirror failed.
    """
    client = get_push_client()
    if not client.configured:
        return MispPushResult(
            pushed=False,
            error="MISP push not configured (set MISP_URL and MISP_API_KEY).",
        )
    try:
        result = await client.push_indicator(indicator.model_dump())
    except AirgapViolation as exc:
        logger.warning("misp_push.airgap_blocked", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=f"Air-gap policy blocked push: {exc}")
    except MispNotConfigured as exc:
        return MispPushResult(pushed=False, error=str(exc))
    except MispPushError as exc:
        logger.warning("misp_push.failed", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=str(exc))
    return MispPushResult(
        pushed=True,
        misp_event_id=str(result.get("misp_event_id") or "") or None,
        misp_event_uuid=str(result.get("misp_event_uuid") or "") or None,
        url=str(result.get("url") or "") or None,
    )


async def _push_bundle_or_swallow(bundle: STIXBundle) -> MispPushResult | None:
    client = get_push_client()
    if not client.configured:
        return MispPushResult(
            pushed=False,
            error="MISP push not configured (set MISP_URL and MISP_API_KEY).",
        )
    try:
        result = await client.push_bundle(bundle.model_dump())
    except AirgapViolation as exc:
        logger.warning("misp_push.airgap_blocked", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=f"Air-gap policy blocked push: {exc}")
    except MispNotConfigured as exc:
        return MispPushResult(pushed=False, error=str(exc))
    except MispPushError as exc:
        logger.warning("misp_push.failed", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=str(exc))
    return MispPushResult(
        pushed=True,
        misp_event_id=str(result.get("misp_event_id") or "") or None,
        misp_event_uuid=str(result.get("misp_event_uuid") or "") or None,
        url=str(result.get("url") or "") or None,
        pushed_attributes=int(result.get("pushed_attributes") or 0),
        skipped_attributes=int(result.get("skipped_attributes") or 0),
    )


@router.post(
    "/indicators",
    response_model=STIXIndicatorWithPush,
    status_code=status.HTTP_201_CREATED,
)
async def create_indicator(
    body: STIXIndicatorCreate,
    push_to_misp: bool | None = Query(
        default=None,
        description=("Mirror this indicator to the configured MISP instance. Defaults to the value of MISP_PUSH_AUTO."),
    ),
) -> STIXIndicatorWithPush:
    """Publish a new STIX 2.1 indicator and optionally mirror it to MISP."""
    now_iso = datetime.now(UTC).isoformat()
    indicator = STIXIndicator(
        id=f"indicator--{uuid.uuid4()}",
        created=now_iso,
        modified=now_iso,
        name=body.name,
        description=body.description,
        indicator_types=body.indicator_types,
        pattern=body.pattern,
        pattern_type=body.pattern_type,
        valid_from=body.valid_from or now_iso,
        valid_until=body.valid_until,
        confidence=body.confidence,
        labels=body.labels,
    )
    DEMO_INDICATORS.append(indicator)

    push_result: MispPushResult | None = None
    if _should_push(push_to_misp):
        push_result = await _push_indicator_or_swallow(indicator)

    return STIXIndicatorWithPush(**indicator.model_dump(), misp=push_result)


@router.get("/bundles", response_model=BundleListResponse)
async def list_bundles() -> BundleListResponse:
    """List STIX 2.1 bundles."""
    return BundleListResponse(items=DEMO_BUNDLES, total=len(DEMO_BUNDLES))


@router.post(
    "/bundles",
    response_model=STIXBundleWithPush,
    status_code=status.HTTP_201_CREATED,
)
async def create_bundle(
    body: STIXBundleCreate,
    push_to_misp: bool | None = Query(
        default=None,
        description=(
            "Mirror this bundle to the configured MISP instance as a single "
            "MISP event (one attribute per translatable indicator). Defaults "
            "to MISP_PUSH_AUTO."
        ),
    ),
) -> STIXBundleWithPush:
    """Create a new STIX 2.1 bundle and optionally mirror it to MISP."""
    if not body.objects:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bundle must contain at least one STIX object.",
        )
    bundle = STIXBundle(
        id=f"bundle--{uuid.uuid4()}",
        created=datetime.now(UTC).isoformat(),
        objects=body.objects,
    )
    DEMO_BUNDLES.append(bundle)

    push_result: MispPushResult | None = None
    if _should_push(push_to_misp):
        push_result = await _push_bundle_or_swallow(bundle)

    return STIXBundleWithPush(**bundle.model_dump(), misp=push_result)


@router.get("/taxii/collections", response_model=TAXIICollectionListResponse)
async def list_taxii_collections() -> TAXIICollectionListResponse:
    """List TAXII 2.1 collections for server compatibility."""
    return TAXIICollectionListResponse(
        items=DEMO_TAXII_COLLECTIONS,
        total=len(DEMO_TAXII_COLLECTIONS),
    )


# ── MISP push admin endpoints ───────────────────────────────────────────────


@router.get("/misp/health", response_model=MispPushHealth, tags=["MISP push"])
async def misp_push_health() -> MispPushHealth:
    """Check whether MISP push is configured and reachable.

    Surfaces enough state for an operator to debug a misconfigured
    deployment without leaking the API key. Calls ``/users/view/me``
    against MISP only when the client is configured.
    """
    client = get_push_client()
    base = MispPushHealth(
        configured=client.configured,
        airgapped=bool(settings.AISOC_AIRGAPPED),
        auto_push=bool(settings.MISP_PUSH_AUTO),
        url=settings.MISP_URL or None,
        ok=False,
    )
    if not client.configured:
        base.error = "MISP_URL and/or MISP_API_KEY not set."
        return base
    try:
        result = await client.health_check()
    except AirgapViolation as exc:
        base.error = f"Air-gap policy blocked health check: {exc}"
        return base
    except (MispNotConfigured, MispPushError) as exc:
        base.error = str(exc)
        return base
    base.ok = True
    base.user = str(result.get("user") or "") or None
    base.role = str(result.get("role") or "") or None
    return base


@router.post("/misp/dry-run", response_model=MispDryRunResponse, tags=["MISP push"])
async def misp_push_dry_run(body: MispDryRunRequest) -> MispDryRunResponse:
    """Show the MISP event payload that *would* be pushed, without sending it.

    Useful for operators tuning STIX → MISP mappings, and for proving
    that an air-gapped deployment will refuse to send. The endpoint
    runs the air-gap check against the configured MISP URL and reports
    the result, but never opens an HTTP connection.
    """
    if (body.indicator is None) == (body.bundle is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide exactly one of `indicator` or `bundle`.",
        )

    if body.indicator is not None:
        now_iso = datetime.now(UTC).isoformat()
        ind = STIXIndicator(
            id=f"indicator--dry-run-{uuid.uuid4()}",
            created=now_iso,
            modified=now_iso,
            name=body.indicator.name,
            description=body.indicator.description,
            indicator_types=body.indicator.indicator_types,
            pattern=body.indicator.pattern,
            pattern_type=body.indicator.pattern_type,
            valid_from=body.indicator.valid_from or now_iso,
            valid_until=body.indicator.valid_until,
            confidence=body.indicator.confidence,
            labels=body.indicator.labels,
        )
        event = stix_indicator_to_misp_event(
            ind.model_dump(),
            distribution=body.distribution,
            threat_level=body.threat_level,
            analysis=body.analysis,
        )
        if event is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"STIX pattern {ind.pattern!r} is not currently translatable "
                    "to a MISP attribute. Supported observable prefixes: "
                    "ipv4-addr, ipv6-addr, domain-name, url, email-addr, "
                    "file:hashes (MD5/SHA1/SHA256/SHA512), file:name."
                ),
            )
        attribute_count = len(event.get("Event", {}).get("Attribute", []))
        skipped = 0
    else:
        assert body.bundle is not None  # narrow for type checker
        bundle = STIXBundle(
            id=f"bundle--dry-run-{uuid.uuid4()}",
            created=datetime.now(UTC).isoformat(),
            objects=body.bundle.objects,
        )
        raw = stix_bundle_to_misp_event(
            bundle.model_dump(),
            distribution=body.distribution,
            threat_level=body.threat_level,
            analysis=body.analysis,
        )
        skipped = int(raw.pop("_skipped", 0))
        attribute_count = int(raw.pop("_attribute_count", 0))
        event = raw

    would_push_to: str | None = None
    airgap_blocked = False
    airgap_message: str | None = None
    misp_url = (settings.MISP_URL or "").rstrip("/")
    if misp_url:
        would_push_to = f"{misp_url}/events/add"
        try:
            from app.core.airgap import enforce_airgap_for_url  # local import keeps top tidy

            enforce_airgap_for_url(would_push_to)
        except AirgapViolation as exc:
            airgap_blocked = True
            airgap_message = str(exc)

    return MispDryRunResponse(
        event=event,
        attribute_count=attribute_count,
        skipped_count=skipped,
        would_push_to=would_push_to,
        airgap_blocked=airgap_blocked,
        airgap_message=airgap_message,
    )

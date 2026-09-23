"""
Community ecosystem endpoints — plugin publishing, reviews, and detection catalog.

POST   /community/plugins/publish           – submit plugin tarball (signed)
GET    /community/plugins                   – browse community plugins
GET    /community/plugins/{id}              – get plugin detail + versions
POST   /community/plugins/{id}/install      – install from community to instance
POST   /community/plugins/{id}/rate         – rate a community plugin
PUT    /community/plugins/{id}/review       – admin: approve/reject submission

POST   /community/detections/publish        – submit Sigma detection rule
GET    /community/detections                – paginated Sigma rule catalog
GET    /community/detections/{id}           – get rule detail
POST   /community/detections/{id}/install   – install rule to tenant detection set

POST   /community/playbooks/submit          – submit a playbook
GET    /community/playbooks                 – browse community playbooks
POST   /community/playbooks/{id}/install    – install playbook
PUT    /community/playbooks/{id}/curate     – admin: approve/reject playbook
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, CurrentUser, require_permission
from app.db.rls import TenantDBSession
from app.services.marketplace_publishers import (
    PublisherKeyError,
    active_keys,
    ensure_publisher,
    keys_for_user,
    parse_public_key,
    register_key,
    revoke_key,
    verify_against,
)

router = APIRouter(prefix="/community", tags=["community"])

# ── In-memory stores (replace with DB in production) ─────────────────────────

_community_plugins: dict[str, dict[str, Any]] = {}
_community_detections: dict[str, dict[str, Any]] = {}
_community_playbooks: dict[str, dict[str, Any]] = {}

# ── Schemas ───────────────────────────────────────────────────────────────────


class PublishStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class CommunityPluginOut(BaseModel):
    id: str
    name: str
    version: str
    plugin_type: str
    description: str
    author: str
    tags: list[str] = []
    status: PublishStatus = PublishStatus.PENDING
    install_count: int = 0
    rating: float = 0.0
    rating_count: int = 0
    verified: bool = False
    submitted_at: str
    approved_at: str | None = None


class CommunityPluginListOut(BaseModel):
    total: int
    items: list[CommunityPluginOut]


class ReviewAction(BaseModel):
    action: str = Field(..., pattern="^(approve|reject)$")
    notes: str | None = None


class RatingIn(BaseModel):
    score: int = Field(..., ge=1, le=5)
    comment: str | None = None


class CommunityDetectionOut(BaseModel):
    id: str
    title: str
    description: str
    author: str
    tags: list[str] = []
    status: PublishStatus = PublishStatus.PENDING
    install_count: int = 0
    logsource: dict[str, Any] = {}
    submitted_at: str
    content: str | None = None


class CommunityPlaybookOut(BaseModel):
    id: str
    name: str
    description: str
    author: str
    tags: list[str] = []
    status: PublishStatus = PublishStatus.PENDING
    install_count: int = 0
    submitted_at: str
    definition: dict[str, Any] | None = None


# ── Publisher identity ────────────────────────────────────────────────────────


class PublisherKeyIn(BaseModel):
    public_key_pem: str = Field(..., description="PEM-encoded Ed25519 public key.")
    label: str = Field(default="", max_length=120, description="Which machine or CI job holds the private half.")
    display_name: str = Field(default="", max_length=200)
    contact_email: str = Field(default="", max_length=320)


class PublisherKeyOut(BaseModel):
    fingerprint: str
    label: str
    publisher_id: uuid.UUID


@router.post("/publishers/keys", response_model=PublisherKeyOut, status_code=201)
async def add_publisher_key(
    body: PublisherKeyIn,
    current_user: AuthUser,
    db: TenantDBSession,
) -> PublisherKeyOut:
    """Register a public key you will sign submissions with.

    Until a key is registered, submissions are accepted and marked
    unverified. Once one is, a submission that does not match it is rejected
    — which is the difference between a signature and a decoration.
    """
    try:
        parse_public_key(body.public_key_pem)
    except PublisherKeyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    publisher_id = await ensure_publisher(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        display_name=body.display_name or (current_user.email or "Publisher"),
        contact_email=body.contact_email or (current_user.email or ""),
    )
    key = await register_key(db, publisher_id=publisher_id, public_key_pem=body.public_key_pem, label=body.label)
    return PublisherKeyOut(fingerprint=key.fingerprint, label=key.label, publisher_id=key.publisher_id)


@router.get("/publishers/keys", response_model=list[PublisherKeyOut])
async def list_publisher_keys(
    current_user: AuthUser,
    db: TenantDBSession,
) -> list[PublisherKeyOut]:
    keys = await keys_for_user(db, tenant_id=current_user.tenant_id, user_id=current_user.user_id)
    return [PublisherKeyOut(fingerprint=k.fingerprint, label=k.label, publisher_id=k.publisher_id) for k in keys]


@router.delete("/publishers/keys/{fingerprint}", status_code=204)
async def revoke_publisher_key(
    fingerprint: str,
    current_user: AuthUser,
    db: TenantDBSession,
) -> None:
    """Revoke a key.

    Recorded as a timestamp, not a delete: "signed by a key we have since
    revoked" is a more useful statement after the fact than "unknown key".
    """
    publisher_id = await ensure_publisher(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        display_name=current_user.email or "Publisher",
        contact_email=current_user.email or "",
    )
    keys = await active_keys(db, publisher_id=publisher_id)
    if not any(k.fingerprint == fingerprint for k in keys):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such active key for this publisher")
    await revoke_key(db, publisher_id=publisher_id, fingerprint=fingerprint)


# ── Plugin endpoints ──────────────────────────────────────────────────────────


@router.post("/plugins/publish", status_code=201)
async def publish_plugin(
    request: Request,
    current_user: AuthUser,
    db: TenantDBSession,
) -> dict[str, Any]:
    """Submit a signed plugin tarball for community review."""
    sig_b64 = request.headers.get("X-Plugin-Signature")
    manifest_json = request.headers.get("X-Plugin-Manifest")

    if not sig_b64 or not manifest_json:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Plugin-Signature or X-Plugin-Manifest header",
        )

    tarball = await request.body()
    if not tarball:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty body")

    try:
        manifest = json.loads(manifest_json)
        signature = base64.b64decode(sig_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid signature or manifest: {exc}") from exc

    # Signature verification against this publisher's registered keys.
    #
    # Two outcomes that used to be one. A submission from somebody with no
    # registered key is *unverified* and accepted as such; a submission whose
    # signature does not match a key they do have is *rejected*. Before the
    # publisher tables existed, `_get_registered_pub_key` returned None
    # unconditionally, so the second branch was unreachable and no plugin
    # could ever be rejected for a bad signature.
    verified = False
    signing_fingerprint: str | None = None
    keys = await keys_for_user(db, tenant_id=current_user.tenant_id, user_id=current_user.user_id)
    if keys:
        signing_fingerprint = verify_against(keys, tarball, signature)
        if signing_fingerprint is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Signature does not match any key registered to this publisher. "
                    "Register the key you signed with, or revoke the stale one."
                ),
            )
        verified = True

    plugin_id = manifest.get("id", str(uuid.uuid4()))
    entry = {
        "id": plugin_id,
        "name": manifest.get("name", plugin_id),
        "version": manifest.get("version", "0.0.1"),
        "plugin_type": manifest.get("plugin_type", "enricher"),
        "description": manifest.get("description", ""),
        "author": manifest.get("author", current_user.email),
        "tags": manifest.get("tags", []),
        "status": PublishStatus.PENDING,
        "install_count": 0,
        "rating": 0.0,
        "rating_count": 0,
        "verified": verified,
        "signing_fingerprint": signing_fingerprint,
        "submitted_by": current_user.user_id,
        "submitted_at": datetime.now(UTC).isoformat(),
        "approved_at": None,
        "tarball_sha256": hashlib.sha256(tarball).hexdigest(),
        "_tarball": tarball,
    }
    _community_plugins[plugin_id] = entry

    return {"id": plugin_id, "status": "pending", "message": "Plugin submitted for review"}


@router.get("/plugins", response_model=CommunityPluginListOut)
async def list_community_plugins(
    status_filter: str | None = Query(None, alias="status"),
    plugin_type: str | None = Query(None),
    tags: str | None = Query(None, description="Comma-separated tags"),
    sort: str = Query("install_count", pattern="^(install_count|rating|submitted_at|name)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> CommunityPluginListOut:
    """Browse approved community plugins."""
    items = list(_community_plugins.values())

    # Filter
    if status_filter:
        items = [p for p in items if p["status"] == status_filter]
    else:
        items = [p for p in items if p["status"] == PublishStatus.APPROVED]
    if plugin_type:
        items = [p for p in items if p["plugin_type"] == plugin_type]
    if tags:
        tag_list = [t.strip() for t in tags.split(",")]
        items = [p for p in items if any(t in p.get("tags", []) for t in tag_list)]

    # Sort
    reverse = order == "desc"
    items.sort(key=lambda p: p.get(sort, 0), reverse=reverse)

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return CommunityPluginListOut(
        total=total,
        items=[CommunityPluginOut(**{k: v for k, v in p.items() if k != "_tarball"}) for p in page_items],
    )


@router.get("/plugins/{plugin_id}", response_model=CommunityPluginOut)
async def get_community_plugin(plugin_id: str) -> CommunityPluginOut:
    """Get community plugin detail."""
    p = _community_plugins.get(plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return CommunityPluginOut(**{k: v for k, v in p.items() if k != "_tarball"})


@router.post("/plugins/{plugin_id}/install")
async def install_community_plugin(
    plugin_id: str,
    current_user: AuthUser,
) -> dict[str, str]:
    """Install a community plugin to the current instance."""
    p = _community_plugins.get(plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")
    if p["status"] != PublishStatus.APPROVED:
        raise HTTPException(status_code=400, detail="Plugin is not approved for installation")

    p["install_count"] += 1
    return {"message": f"Plugin {plugin_id} installed successfully", "version": p["version"]}


@router.post("/plugins/{plugin_id}/rate")
async def rate_community_plugin(
    plugin_id: str,
    rating: RatingIn,
    current_user: AuthUser,
) -> dict[str, Any]:
    """Rate a community plugin."""
    p = _community_plugins.get(plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")

    count = p["rating_count"]
    current_rating = p["rating"]
    new_rating = (current_rating * count + rating.score) / (count + 1)
    p["rating"] = round(new_rating, 2)
    p["rating_count"] = count + 1

    return {"rating": p["rating"], "rating_count": p["rating_count"]}


@router.put("/plugins/{plugin_id}/review")
async def review_community_plugin(
    plugin_id: str,
    review: ReviewAction,
    current_user: Annotated[CurrentUser, Depends(require_permission("plugins:admin"))],
) -> dict[str, str]:
    """Admin: approve or reject a plugin submission."""
    p = _community_plugins.get(plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")

    if review.action == "approve":
        p["status"] = PublishStatus.APPROVED
        p["approved_at"] = datetime.now(UTC).isoformat()
    else:
        p["status"] = PublishStatus.REJECTED
        p["review_notes"] = review.notes

    return {"id": plugin_id, "status": p["status"]}


# ── Detection endpoints ───────────────────────────────────────────────────────


@router.post("/detections/publish", status_code=201)
async def publish_detection(
    content: str = Body(..., media_type="text/plain"),
    current_user: AuthUser = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Submit a Sigma detection rule for community review."""
    import yaml as _yaml

    try:
        rule = _yaml.safe_load(content)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from exc

    required = ["title", "id", "status", "description", "logsource", "detection"]
    missing = [f for f in required if f not in rule]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required Sigma fields: {missing}")

    detection_id = rule.get("id", str(uuid.uuid4()))
    logsource = rule.get("logsource", {})
    entry = {
        "id": detection_id,
        "name": rule.get("title", detection_id),
        "description": rule.get("description", ""),
        "author": rule.get("author", ""),
        "tags": rule.get("tags", []),
        "logsource_category": logsource.get("category", ""),
        "logsource_product": logsource.get("product", ""),
        "level": rule.get("level", "medium"),
        "status": PublishStatus.APPROVED,  # auto-approve for demo; change to PENDING in prod
        "install_count": 0,
        "rating": 0.0,
        "rating_count": 0,
        "submitted_at": datetime.now(UTC).isoformat(),
        "sigma_yaml": content,
    }
    _community_detections[detection_id] = entry

    return {"id": detection_id, "status": entry["status"]}


@router.get("/detections")
async def list_community_detections(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None),
    logsource_category: str | None = Query(None),
    logsource_product: str | None = Query(None),
    level: str | None = Query(None),
    sort_by: str = Query("install_count", pattern="^(install_count|rating|name)$"),
) -> dict[str, Any]:
    """Browse community Sigma detection rules with pagination and filtering."""
    items = list(_community_detections.values())

    # filter by status — show approved + auto-approved
    items = [d for d in items if d["status"] in (PublishStatus.APPROVED, "approved")]

    if search:
        q = search.lower()
        items = [
            d
            for d in items
            if q in d.get("name", "").lower() or q in d.get("description", "").lower() or any(q in t.lower() for t in d.get("tags", []))
        ]
    if logsource_category:
        items = [d for d in items if d.get("logsource_category") == logsource_category]
    if logsource_product:
        items = [d for d in items if d.get("logsource_product") == logsource_product]
    if level:
        items = [d for d in items if d.get("level") == level]

    # Sort
    if sort_by == "name":
        items.sort(key=lambda d: d.get("name", "").lower())
    else:
        items.sort(key=lambda d: d.get(sort_by, 0), reverse=True)

    total = len(items)
    start = (page - 1) * page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items[start : start + page_size],
    }


@router.get("/detections/{detection_id}")
async def get_community_detection(detection_id: str) -> dict[str, Any]:
    """Get Sigma rule detail including full YAML content (sigma_yaml field)."""
    d = _community_detections.get(detection_id)
    if not d:
        raise HTTPException(status_code=404, detail="Detection not found")
    return d


@router.post("/detections/{detection_id}/install")
async def install_community_detection(
    detection_id: str,
    current_user: AuthUser,
) -> dict[str, str]:
    """Install a community detection rule to the tenant."""
    d = _community_detections.get(detection_id)
    if not d:
        raise HTTPException(status_code=404, detail="Detection not found")
    d["install_count"] += 1
    return {"message": f"Detection {detection_id} installed", "title": d["title"]}


# ── Playbook endpoints ────────────────────────────────────────────────────────


@router.post("/playbooks/submit", status_code=201)
async def submit_playbook(
    definition: dict[str, Any] = Body(...),
    current_user: AuthUser = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Submit a community playbook."""
    name = definition.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="Playbook must have a name")

    playbook_id = str(uuid.uuid4())
    entry = {
        "id": playbook_id,
        "name": name,
        "description": definition.get("description", ""),
        "author": definition.get("author", ""),
        "tags": definition.get("tags", []),
        "status": PublishStatus.APPROVED,  # auto-approve for demo; change to PENDING in prod
        "install_count": 0,
        "rating": 0.0,
        "rating_count": 0,
        "submitted_at": datetime.now(UTC).isoformat(),
        "definition": definition,
    }
    _community_playbooks[playbook_id] = entry

    return {"id": playbook_id, "status": entry["status"]}


@router.get("/playbooks")
async def list_community_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None),
    sort_by: str = Query("install_count", pattern="^(install_count|rating|name)$"),
) -> dict[str, Any]:
    """Browse approved community playbooks with optional search and sort."""
    items = [p for p in _community_playbooks.values() if p["status"] in (PublishStatus.APPROVED, "approved")]

    if search:
        q = search.lower()
        items = [
            p
            for p in items
            if q in p.get("name", "").lower() or q in p.get("description", "").lower() or any(q in t.lower() for t in p.get("tags", []))
        ]

    if sort_by == "name":
        items.sort(key=lambda p: p.get("name", "").lower())
    else:
        items.sort(key=lambda p: p.get(sort_by, 0), reverse=True)

    total = len(items)
    start = (page - 1) * page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items[start : start + page_size],
    }


@router.post("/playbooks/{playbook_id}/install")
async def install_community_playbook(
    playbook_id: str,
    current_user: AuthUser,
) -> dict[str, str]:
    """Install a community playbook to the tenant."""
    p = _community_playbooks.get(playbook_id)
    if not p:
        raise HTTPException(status_code=404, detail="Playbook not found")
    p["install_count"] += 1
    return {"message": f"Playbook {playbook_id} installed", "name": p["name"]}


@router.put("/playbooks/{playbook_id}/curate")
async def curate_community_playbook(
    playbook_id: str,
    review: ReviewAction,
    current_user: Annotated[CurrentUser, Depends(require_permission("playbooks:admin"))],
) -> dict[str, str]:
    """Admin: approve or reject a playbook submission."""
    p = _community_playbooks.get(playbook_id)
    if not p:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if review.action == "approve":
        p["status"] = PublishStatus.APPROVED
    else:
        p["status"] = PublishStatus.REJECTED
        p["review_notes"] = review.notes

    return {"id": playbook_id, "status": p["status"]}


# ── Helpers ───────────────────────────────────────────────────────────────────


# `_get_registered_pub_key` used to live here, returning None unconditionally
# with the comment "(stub — wire to DB)". It is gone rather than fixed in
# place, because the shape was wrong as well as the body: one key per user
# cannot express a rotation, and a publisher who cannot rotate will not.
# `app.services.marketplace_publishers` owns this now.

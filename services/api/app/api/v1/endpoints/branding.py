"""Reading and administering white-label branding.

Two audiences on one router:

* ``GET /branding`` and ``GET /branding/assets/{id}`` are read by the console
  on every page load, by any authenticated member of the tenant. Reading what
  the product is called is not a privileged act.
* Everything that writes requires ``settings:write`` and applies to the
  organisation the caller's tenant belongs to. The organisation is resolved
  from the credential, never named in the request: a body field would let an
  authenticated user of one tenant rebrand somebody else's console.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, File, HTTPException, Request, Response, UploadFile, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.branding import OrgBrandAsset, OrgBranding
from app.services.audit import emit_audit
from app.services.branding import resolver, svg_sanitizer

router = APIRouter(prefix="/branding", tags=["branding"])

#: Raster types accepted beside SVG. Deliberately short: each one is a
#: decoder that will be handed attacker-supplied bytes by a browser, and the
#: list of formats a logo needs is not long.
ALLOWED_RASTER_TYPES: dict[str, str] = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
}

#: Magic bytes, checked against the declared type. A caller controls the
#: header; announcing an SVG as `image/png` would otherwise skip the
#: sanitiser, which is the whole attack.
_MAGIC: dict[str, tuple[bytes, ...]] = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/webp": (b"RIFF",),
}


class BrandingIn(BaseModel):
    product_name: str | None = Field(None, min_length=1, max_length=80)
    primary_color: str | None = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")
    accent_color: str | None = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")
    support_email: str | None = Field(None, max_length=255)
    support_url: str | None = Field(None, max_length=500)
    sender_name: str | None = Field(None, min_length=1, max_length=80)
    footer_text: str | None = Field(None, max_length=300)

    @field_validator("support_url")
    @classmethod
    def _https_only(cls, value: str | None) -> str | None:
        """Refuse anything but https.

        This string is rendered as a link in an email and in a PDF report, so
        a `javascript:` value would be a stored script in somebody else's
        inbox. Checked here as well as by the database constraint, so the
        caller gets a 422 naming the field rather than a 500.
        """
        if value is None or not value.strip():
            return None
        candidate = value.strip()
        if not candidate.startswith("https://"):
            raise ValueError("support_url must be an https:// address")
        return candidate


async def _require_org(db: Any, tenant_id: uuid.UUID) -> uuid.UUID:
    org_id = await resolver.owning_org_id(db, tenant_id)
    if org_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This tenant does not belong to an operator organisation, so there is nothing to brand. "
                "Create an organisation and add this tenant to its portfolio first."
            ),
        )
    return org_id


@router.get("")
async def get_branding(db: DBSession, current_user: AuthUser) -> dict[str, Any]:
    """What the product looks like for the caller's tenant.

    Readable by any authenticated member. The console calls it on every page
    load, and gating it behind an administrative permission would leave an
    analyst looking at a differently-branded product from their colleague.
    """
    return (await resolver.resolve_branding(db, current_user.tenant_id)).as_dict()


@router.put("")
async def put_branding(
    body: BrandingIn,
    db: DBSession,
    request: Request,
    current_user: Annotated[Any, require_permission("settings:write")],
) -> dict[str, Any]:
    """Set branding for the organisation the caller's tenant belongs to."""
    org_id = await _require_org(db, current_user.tenant_id)

    row = (await db.execute(select(OrgBranding).where(OrgBranding.org_id == org_id))).scalar_one_or_none()
    if row is None:
        row = OrgBranding(org_id=org_id)
        db.add(row)

    for field_name, value in body.model_dump().items():
        setattr(row, field_name, value)
    row.updated_by = current_user.user_id
    row.updated_at = datetime.now(UTC)

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="branding:update",
        resource="org_branding",
        resource_id=str(org_id),
        changes=body.model_dump(),
        request=request,
    )
    await db.commit()
    return (await resolver.branding_for_org(db, org_id)).as_dict()


@router.post("/assets/{kind}", status_code=status.HTTP_201_CREATED)
async def upload_asset(
    kind: str,
    db: DBSession,
    request: Request,
    current_user: Annotated[Any, require_permission("settings:write")],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    """Upload a logo or favicon.

    An SVG goes through the sanitiser and what is stored is the sanitised
    output. Nothing re-sanitises at render time, so this handler is the only
    writer and the stored bytes are trusted thereafter.
    """
    if kind not in {"logo", "favicon"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="kind must be 'logo' or 'favicon'")

    org_id = await _require_org(db, current_user.tenant_id)

    raw = await file.read(svg_sanitizer.MAX_SVG_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="the uploaded file is empty")
    if len(raw) > svg_sanitizer.MAX_SVG_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"asset exceeds {svg_sanitizer.MAX_SVG_BYTES} bytes",
        )

    declared = (file.content_type or "").split(";")[0].strip().lower()
    was_sanitized = False

    # Decided on the bytes as well as the declared type. An SVG announced as
    # `image/png` would otherwise be stored unsanitised and served back with
    # a content type a browser may sniff past.
    if svg_sanitizer.looks_like_svg(declared, raw):
        try:
            cleaned = svg_sanitizer.sanitize_svg(raw)
        except svg_sanitizer.SvgRejected as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        content = cleaned.svg.encode("utf-8")
        content_type = "image/svg+xml"
        was_sanitized = cleaned.modified
        removed = {"elements": sorted(set(cleaned.removed_elements)), "attributes": sorted(set(cleaned.removed_attributes))}
    elif declared in ALLOWED_RASTER_TYPES:
        prefixes = _MAGIC.get(declared, ())
        if prefixes and not any(raw.startswith(prefix) for prefix in prefixes):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"the file does not begin with {declared} magic bytes",
            )
        content, content_type, removed = raw, declared, {"elements": [], "attributes": []}
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unsupported content type {declared!r}; accepted: image/svg+xml, {', '.join(sorted(ALLOWED_RASTER_TYPES))}",
        )

    existing = (
        await db.execute(select(OrgBrandAsset).where(OrgBrandAsset.org_id == org_id, OrgBrandAsset.kind == kind))
    ).scalar_one_or_none()
    digest = hashlib.sha256(content).hexdigest()

    if existing is None:
        existing = OrgBrandAsset(org_id=org_id, kind=kind)
        db.add(existing)
    existing.content_type = content_type
    existing.content = content
    existing.byte_size = len(content)
    existing.sha256 = digest
    existing.was_sanitized = was_sanitized
    existing.uploaded_by = current_user.user_id
    await db.flush()

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="branding:asset:upload",
        resource="org_brand_asset",
        resource_id=str(existing.id),
        changes={"kind": kind, "content_type": content_type, "bytes": len(content), "sanitized": was_sanitized, "removed": removed},
        request=request,
    )
    await db.commit()

    return {
        "id": str(existing.id),
        "kind": kind,
        "content_type": content_type,
        "byte_size": len(content),
        "sha256": digest,
        "was_sanitized": was_sanitized,
        "removed": removed,
        "url": f"/api/v1/branding/assets/{existing.id}",
    }


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: uuid.UUID, db: DBSession, current_user: AuthUser) -> Response:
    """Serve a brand asset from this deployment.

    Scoped to the caller's own organisation. The bytes are not secret, but
    an unscoped read would let any authenticated user enumerate every
    operator's logo, which is a customer list.
    """
    org_id = await resolver.owning_org_id(db, current_user.tenant_id)
    if org_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    asset = (
        await db.execute(select(OrgBrandAsset).where(OrgBrandAsset.id == asset_id, OrgBrandAsset.org_id == org_id))
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return Response(
        content=asset.content,
        media_type=asset.content_type,
        headers={
            # The bytes are immutable for a given id, and replacing an asset
            # writes a new sha. Caching privately rather than publicly: a
            # shared cache would serve one operator's logo from another's
            # request path.
            "Cache-Control": "private, max-age=300",
            "ETag": f'"{asset.sha256}"',
            # Belt and braces on the SVG path. The content is sanitised, and
            # a browser that sniffs past the declared type still gets no
            # script execution from a document served with these headers.
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox",
        },
    )


@router.delete("/assets/{kind}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_asset(
    kind: str,
    db: DBSession,
    request: Request,
    current_user: Annotated[Any, require_permission("settings:write")],
) -> None:
    """Remove an asset, returning that surface to the wordmark."""
    org_id = await _require_org(db, current_user.tenant_id)
    asset = (await db.execute(select(OrgBrandAsset).where(OrgBrandAsset.org_id == org_id, OrgBrandAsset.kind == kind))).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    await db.delete(asset)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="branding:asset:delete",
        resource="org_brand_asset",
        resource_id=str(asset.id),
        changes={"kind": kind},
        request=request,
    )
    await db.commit()

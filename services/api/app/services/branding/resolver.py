"""Answering "what does this tenant's product look like".

One resolver, called by every surface that renders a product name or a
colour: the console, the PDF report, the executive digest, email approvals
and ChatOps. Two resolvers would be two answers, and the one a customer
notices is whichever renders in the document they forward to their board.

Falls back field by field rather than row by row. An organisation that has
set a product name and no colours renders its name against the platform
palette, which is what a half-configured organisation should look like; the
alternative, falling back to the whole default row, would silently discard
the one field the operator had bothered to set.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, replace
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.branding import OrgBrandAsset, OrgBranding
from app.models.organization import Organization, OrganizationTenant


@dataclass(frozen=True)
class Branding:
    """The resolved appearance of the product for one tenant.

    ``logo_url`` is a path on this deployment, never a third-party address.
    It is ``None`` when no asset has been uploaded, and every renderer treats
    that as "use the wordmark", so a missing logo is a layout this project
    ships rather than a broken image.
    """

    product_name: str
    primary_color: str
    accent_color: str
    support_email: str | None
    support_url: str | None
    sender_name: str
    footer_text: str
    logo_url: str | None
    #: The logo inlined as a ``data:`` URI, populated only when a caller asks
    #: for it. A PDF is rendered server-side by WeasyPrint, so a remote
    #: ``<img src>`` there would be an outbound request made by the server to
    #: an address a customer administrator supplied. The console takes
    #: ``logo_url`` instead and fetches it as an authenticated user.
    logo_data_uri: str | None
    org_id: uuid.UUID | None
    #: False when nothing is configured, so a caller can tell "the default,
    #: because that is what was chosen" from "the default, because nobody has
    #: been here yet".
    is_white_labelled: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "product_name": self.product_name,
            "primary_color": self.primary_color,
            "accent_color": self.accent_color,
            "support_email": self.support_email,
            "support_url": self.support_url,
            "sender_name": self.sender_name,
            "footer_text": self.footer_text,
            "logo_url": self.logo_url,
            "org_id": str(self.org_id) if self.org_id else None,
            "is_white_labelled": self.is_white_labelled,
        }


#: What an unbranded deployment looks like. Referenced by name everywhere
#: rather than written out, so "the product is called AiSOC" is one fact.
DEFAULT_BRANDING: Final[Branding] = Branding(
    product_name="AiSOC",
    primary_color="#2563EB",
    accent_color="#7C3AED",
    support_email=None,
    support_url=None,
    sender_name="AiSOC",
    footer_text="AiSOC — open-source AI Security Operations Center.",
    logo_url=None,
    logo_data_uri=None,
    org_id=None,
    is_white_labelled=False,
)


def _merge(row: OrgBranding, *, logo_url: str | None, logo_data_uri: str | None) -> Branding:
    """Overlay one organisation's settings on the platform default."""
    resolved = replace(
        DEFAULT_BRANDING,
        org_id=row.org_id,
        is_white_labelled=True,
        logo_url=logo_url,
        logo_data_uri=logo_data_uri,
    )
    if row.product_name:
        resolved = replace(resolved, product_name=row.product_name)
        # The sender name defaults to the product name rather than to
        # "AiSOC". An operator who renames the product and forgets this field
        # would otherwise send mail from a brand their customer has never
        # heard of, which reads as a phishing attempt.
        resolved = replace(resolved, sender_name=row.product_name)
        resolved = replace(resolved, footer_text=row.product_name)
    if row.primary_color:
        resolved = replace(resolved, primary_color=row.primary_color)
    if row.accent_color:
        resolved = replace(resolved, accent_color=row.accent_color)
    if row.support_email:
        resolved = replace(resolved, support_email=row.support_email)
    if row.support_url:
        resolved = replace(resolved, support_url=row.support_url)
    if row.sender_name:
        resolved = replace(resolved, sender_name=row.sender_name)
    if row.footer_text:
        resolved = replace(resolved, footer_text=row.footer_text)
    return resolved


async def branding_for_org(db: AsyncSession, org_id: uuid.UUID | None, *, inline_logo: bool = False) -> Branding:
    """Resolve branding for one organisation, or the default for ``None``.

    ``inline_logo`` loads the asset bytes and returns them as a ``data:``
    URI. Off by default because the console does not need them and every
    page load would otherwise carry a logo through the JSON.
    """
    if org_id is None:
        return DEFAULT_BRANDING

    row = (await db.execute(select(OrgBranding).where(OrgBranding.org_id == org_id))).scalar_one_or_none()
    if row is None:
        return DEFAULT_BRANDING

    columns = (OrgBrandAsset.id, OrgBrandAsset.content_type, OrgBrandAsset.content) if inline_logo else (OrgBrandAsset.id,)
    asset = (await db.execute(select(*columns).where(OrgBrandAsset.org_id == org_id, OrgBrandAsset.kind == "logo"))).first()

    logo_url = f"/api/v1/branding/assets/{asset[0]}" if asset else None
    logo_data_uri = None
    if asset is not None and inline_logo:
        encoded = base64.b64encode(bytes(asset[2])).decode("ascii")
        logo_data_uri = f"data:{asset[1]};base64,{encoded}"
    return _merge(row, logo_url=logo_url, logo_data_uri=logo_data_uri)


async def owning_org_id(db: AsyncSession, tenant_id: uuid.UUID) -> uuid.UUID | None:
    """The organisation whose portfolio holds this tenant, or its home org.

    Two ways a tenant belongs to an organisation and both have to resolve:
    a managed customer is in ``organization_tenants``, and the operator's own
    staff sign in to the organisation's ``home_tenant_id``. Checking only the
    first leaves an operator's own console unbranded, which is the one
    console they look at every day.
    """
    managed = (await db.execute(select(OrganizationTenant.org_id).where(OrganizationTenant.tenant_id == tenant_id))).scalar_one_or_none()
    if managed is not None:
        return managed
    return (await db.execute(select(Organization.id).where(Organization.home_tenant_id == tenant_id))).scalar_one_or_none()


async def resolve_branding(db: AsyncSession, tenant_id: uuid.UUID, *, inline_logo: bool = False) -> Branding:
    """The appearance of the product for one tenant.

    Never raises. A branding lookup that failed would take down whatever it
    was decorating, and a report that does not render is worse than a report
    that renders in the platform palette.
    """
    try:
        return await branding_for_org(db, await owning_org_id(db, tenant_id), inline_logo=inline_logo)
    except Exception:  # noqa: BLE001 - see the docstring; appearance must not break content
        return DEFAULT_BRANDING

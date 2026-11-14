"""Which alert classes a tenant lets AiSOC ask its own people about.

Depth plan 5.4. The playbook engine refuses to send an automatic
verification prompt unless a row exists here for the alert's class, and a
tenant with no rows auto-sends nothing. Without this surface that table
would have a reader and no writer — the shape this repository keeps finding,
where the control is real, fails closed, and can never be switched on, so
the feature reads as broken rather than as governed.

Why opt-in per class rather than one switch
--------------------------------------------
"Ask the user" is reasonable for an impossible-travel sign-in and absurd for
a malware detection on a server. One boolean forces a tenant to choose
between never using it and using it everywhere, and the second choice is the
one that gets the feature turned off again after the first complaint.

Why there is no "ask on everything" value
------------------------------------------
Because the refusal that matters — never on a confirmed true positive — is
not expressible as a class, and a wildcard would invite somebody to reach
for it instead of listing what they mean. The list is short in practice:
sign-in anomalies, MFA prompts, new-device registrations.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.services.audit import emit_audit

router = APIRouter(prefix="/verification-policies", tags=["settings"])

#: Classes are compared case-insensitively against the alert's `rule_id`,
#: `category` or `alert_class`, so they are stored lower-cased and the
#: comparison has one spelling rather than two.
_MAX_CLASS_LENGTH = 200


class VerificationPolicyIn(BaseModel):
    alert_class: str = Field(
        ...,
        min_length=1,
        max_length=_MAX_CLASS_LENGTH,
        description="An alert's rule_id, category or alert_class. Matched case-insensitively.",
    )

    @field_validator("alert_class")
    @classmethod
    def _normalise(cls, value: str) -> str:
        folded = value.strip().lower()
        if not folded:
            raise ValueError("alert_class cannot be blank")
        if folded == "*":
            # Refused rather than silently stored. A wildcard here would be
            # a tenant-wide grant to message every employee on any alert,
            # entered in a text box.
            raise ValueError("a wildcard is not accepted; name the alert classes you mean")
        return folded


class VerificationPolicyOut(BaseModel):
    alert_class: str
    enabled_by: uuid.UUID | None
    enabled_at: datetime


@router.get("", response_model=list[VerificationPolicyOut])
async def list_policies(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
) -> list[VerificationPolicyOut]:
    """Every class this tenant has opted into. Empty means none."""
    rows = await db.execute(
        text(
            "SELECT alert_class, enabled_by, enabled_at FROM aisoc_verification_policies "
            "WHERE tenant_id = CAST(:tenant AS uuid) ORDER BY alert_class"
        ).bindparams(tenant=str(current_user.tenant_id))
    )
    return [VerificationPolicyOut(alert_class=r.alert_class, enabled_by=r.enabled_by, enabled_at=r.enabled_at) for r in rows]


@router.put("", response_model=VerificationPolicyOut, status_code=status.HTTP_200_OK)
async def enable_class(
    body: VerificationPolicyIn,
    db: DBSession,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> VerificationPolicyOut:
    """Allow automatic verification prompts for one alert class.

    Idempotent: re-enabling an already-enabled class re-stamps who asked for
    it and when, which is the record a review after a complaint needs.
    """
    tenant = str(current_user.tenant_id)
    await db.execute(
        text(
            "INSERT INTO aisoc_verification_policies (tenant_id, alert_class, enabled_by) "
            "VALUES (CAST(:tenant AS uuid), :alert_class, CAST(:actor AS uuid)) "
            "ON CONFLICT (tenant_id, alert_class) DO UPDATE "
            "SET enabled_by = EXCLUDED.enabled_by, enabled_at = NOW()"
        ).bindparams(tenant=tenant, alert_class=body.alert_class, actor=str(current_user.user_id))
    )
    row = (
        await db.execute(
            text(
                "SELECT alert_class, enabled_by, enabled_at FROM aisoc_verification_policies "
                "WHERE tenant_id = CAST(:tenant AS uuid) AND alert_class = :alert_class"
            ).bindparams(tenant=tenant, alert_class=body.alert_class)
        )
    ).one()
    await emit_audit(
        db=db,
        request=request,
        action="verification_policy:enable",
        resource="verification_policy",
        resource_id=body.alert_class,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        changes={"alert_class": body.alert_class},
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
    )
    await db.commit()
    return VerificationPolicyOut(alert_class=row.alert_class, enabled_by=row.enabled_by, enabled_at=row.enabled_at)


@router.delete("/{alert_class}", status_code=status.HTTP_204_NO_CONTENT)
async def disable_class(
    alert_class: str,
    db: DBSession,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> None:
    """Stop automatic prompts for one class.

    Answers 204 whether or not a row existed. A tenant revoking a grant
    wants it gone; telling them it was already gone is not useful and a 404
    here would read as "the revocation failed".
    """
    folded = alert_class.strip().lower()[:_MAX_CLASS_LENGTH]
    await db.execute(
        text("DELETE FROM aisoc_verification_policies WHERE tenant_id = CAST(:tenant AS uuid) AND alert_class = :alert_class").bindparams(
            tenant=str(current_user.tenant_id), alert_class=folded
        )
    )
    await emit_audit(
        db=db,
        request=request,
        action="verification_policy:disable",
        resource="verification_policy",
        resource_id=folded,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        changes={"alert_class": folded},
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
    )
    await db.commit()

"""Poll a customer's SIEM for analyst closures and grade the shadow decisions.

Gap-closure Phase 2.1, closing D15.

``app.services.shadow_reconcile`` matched a vendor closure to the shadow
decision it grades, had eleven tests, and had no caller. The AiSOC-side half
of reconciliation ran on every read of the agreement endpoint; this half was a
library. A tenant whose analysts close their queue in Splunk ES rather than in
this console therefore watched a scorecard that could never fill in, and the
natural reading of an empty scorecard is that the agent is not being evaluated
rather than that nobody is looking.

Why the route is here
=====================

The same reason ``POST /replay/history`` is. ``services/actions`` owns the five
closed-finding readers, the retry behaviour, the pagination loops and the
vendor quirks Phase 1.1 recorded one at a time, and it owns
``reconcile_findings``. ``services/api`` owns the vault and the tenant session.
No process can hold both, because all three services package their code as
top-level ``app`` (D8), so the API decrypts the connector's credentials and
posts them here with a window, and this route reads and then reconciles in one
hop rather than shipping a finding list back across the network to be written
by a second copy of the matcher.

The tenant comes from the credential
====================================

There is no ``tenant_id`` field on the request. ``POST /replay/history`` needs
no tenant at all, because the credentials it is handed *are* the scope: they
reach exactly one customer's SIEM and nothing is written. This route writes,
and it writes to one tenant's shadow decisions, so it resolves a tenant the
way every other tenant-scoped service in this tree does: the vendored
``app.security.tenant_scope``, where a console token carries a verified claim
and a service token must declare the tenant it acts for on
``X-AiSOC-Tenant-ID``. A service token with no tenant header resolves to an
empty scope and refuses rather than widening to every tenant.

Three answers, not two
======================

A sweep that cannot tell a condition that will never resolve from one that
might turns a misconfiguration into churn, and this repository has shipped that
defect more than once. So a vendor failure is classified before it is returned:

``422``  the credentials in this request cannot build a client, or the vendor
         rejected them. Permanent until an operator re-authorises the
         connector, and the body names that action.
``502``  the vendor was reachable and unhappy, or was not reachable at all.
         Transient; the caller retries on its own cadence.
``429``  the vendor asked us to slow down, with its ``Retry-After`` forwarded
         so the caller can honour it rather than guess.

The distinction is drawn from the vendor's own status code, which every client
here surfaces through ``raise_for_status``. Guessing from an exception type
would put a revoked API key and a five-second timeout in the same bucket, and
only one of them is worth waiting on.
"""

from __future__ import annotations

from typing import Annotated

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel

from app.api.replay_history_router import READERS, HistoryRequest
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)
from app.services.shadow_reconcile import database_configured, reconcile_findings

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/shadow", tags=["shadow"])

ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]

#: Vendor statuses that mean the credential itself is the problem. Retrying
#: these on a timer is what turns one revoked API key into a poll loop nobody
#: reads, so they are reported as permanent and name the operator action. 404
#: is included deliberately for the same reason: on these five APIs it means
#: the workspace, index or console path in the saved connector does not exist,
#: which no amount of waiting fixes.
PERMANENT_VENDOR_STATUSES = frozenset({400, 401, 403, 404})


class ReconcileRequest(HistoryRequest):
    """One vendor, one window, credentials the API already decrypted.

    Deliberately the *same* envelope as :class:`HistoryRequest` rather than a
    parallel one: the same five readers are driven with the same credential
    keys, the same vendor literal and the same two vendor-specific knobs, and a
    second shape would be a second place for one of them to drift. Subclassed
    rather than reused by name only so the OpenAPI schema names the operation a
    reader is looking at.
    """


class ReconcileResponse(BaseModel):
    """What the pass read, and what it did with it.

    ``count`` and ``matched`` are reported separately and both are needed. A
    window with a healthy ``count`` and ``matched`` at zero means the join key
    is not arriving, which is a wiring fault; a window with ``count`` at zero
    means the analysts closed nothing, which is a fact about their week. One
    number cannot say which, and the caller decides what to record on the
    difference.
    """

    vendor: str
    count: int
    labelled: int
    unlabeled: int
    considered: int
    matched: int
    unmatched: int
    already_resolved: int
    skipped_no_key: int
    #: The latest close time in this window, ISO-8601, or ``None`` when the
    #: window held nothing. The caller advances its watermark from this rather
    #: than from its own clock, so a vendor whose indexing lags does not have
    #: findings stepped over.
    latest_closed_at: str | None = None


def _permanent(vendor: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{vendor}: {detail}")


@router.post("/reconcile", response_model=ReconcileResponse, summary="Grade shadow decisions against SIEM closures")
async def reconcile(
    body: ReconcileRequest,
    principal: ScopedPrincipal,
    response: Response,
) -> ReconcileResponse:
    """Read one window of closures and attach each to the decision it grades.

    Idempotent by construction: ``reconcile_findings`` only writes decisions
    whose ``resolved_at`` is still null, so a window re-read after a transient
    failure grades nothing twice and reports the overlap as ``already_resolved``
    rather than as fresh evidence.
    """
    tenant_id = scoped_tenant_or_403(principal)

    if body.until <= body.since:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"until ({body.until.isoformat()}) must be after since ({body.since.isoformat()})",
        )

    # Checked before the vendor is called rather than after. Without a
    # database this route would spend a customer's API quota and then report a
    # window it read and graded nothing from, which reads as a broken join key
    # rather than as a missing environment variable.
    if not database_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "this service has no DATABASE_URL, so a closure read from the vendor could not be "
                "recorded against the decision it grades. Set DATABASE_URL on the actions container"
            ),
        )

    try:
        findings = await READERS[body.vendor](body)
    except HTTPException as exc:
        # The reader refused to build a client at all. That is this request's
        # credentials rather than the vendor, and it is permanent until they
        # change.
        raise _permanent(body.vendor, str(exc.detail)) from exc
    except httpx.HTTPStatusError as exc:
        raise _from_vendor_status(body.vendor, exc) from exc
    except Exception as exc:  # noqa: BLE001 - a read failure is never an empty window
        logger.exception("shadow_reconcile.read_failed", vendor=body.vendor)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"reading {body.vendor} closures failed: {type(exc).__name__}",
        ) from exc

    result = await reconcile_findings(tenant_id, findings)

    labelled = sum(1 for f in findings if f.is_labelled)
    closed_times = [f.closed_at for f in findings if f.closed_at is not None]
    logger.info(
        "shadow_reconcile.window_complete",
        tenant_id=str(tenant_id),
        vendor=body.vendor,
        count=len(findings),
        labelled=labelled,
        **result.as_dict(),
    )
    # Echoed so the caller's log line can be correlated with this one without
    # reading both sides' clocks.
    response.headers["X-AiSOC-Reconciled"] = str(result.matched)
    return ReconcileResponse(
        vendor=body.vendor,
        count=len(findings),
        labelled=labelled,
        unlabeled=len(findings) - labelled,
        latest_closed_at=max(closed_times).isoformat() if closed_times else None,
        **result.as_dict(),
    )


def _from_vendor_status(vendor: str, exc: httpx.HTTPStatusError) -> HTTPException:
    """Turn the vendor's own status into permanent, rate-limited or transient."""
    code = exc.response.status_code
    if code == status.HTTP_429_TOO_MANY_REQUESTS:
        retry_after = exc.response.headers.get("Retry-After")
        logger.warning("shadow_reconcile.rate_limited", vendor=vendor, retry_after=retry_after)
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"{vendor} asked us to slow down",
            headers={"Retry-After": retry_after} if retry_after else None,
        )
    if code in PERMANENT_VENDOR_STATUSES:
        logger.warning("shadow_reconcile.credentials_refused", vendor=vendor, vendor_status=code)
        return _permanent(
            vendor,
            f"the vendor refused the stored credentials with HTTP {code}. "
            f"Re-authorise this connector in Settings; polling will not recover on its own",
        )
    logger.warning("shadow_reconcile.vendor_error", vendor=vendor, vendor_status=code)
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"{vendor} returned HTTP {code}")

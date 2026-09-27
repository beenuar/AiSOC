"""Expose the closed-finding readers so replay evaluation can reach them.

Gap-closure Phase 1.4.

Phase 1.1 put five readers on the five SIEM clients in this service, because
this service already owns the credential path. Nothing called them. This is
the route that does.

Why the route is here and not in ``services/api``
-------------------------------------------------
The API orchestrates the replay job, but it cannot read a customer's SIEM
itself without a second copy of every client. ``services/actions`` holds the
clients, the retry behaviour, the pagination loops and the vendor quirks that
Phase 1.1 recorded one at a time. A reader in the API would be a sixth place
for "what does a closed Splunk notable look like" to be written down.

So the API decrypts ``auth_config`` from the vault and forwards it, exactly
the trust model ``POST /connectors/{id}/normalize`` already uses from Phase
1.2. Nothing is persisted here and no credential is stored: the client is
built, used for one window, and dropped.

Why the client factory is imported rather than rewritten
--------------------------------------------------------
``app.executors.siem`` already builds all five clients from a flat credential
mapping, and this repository has twice found a second factory reading keys the
first one does not. ``_splunk_client`` and friends are reused as-is, so a
credential key that works for writeback works for the read in the same
deployment. The one client ``siem.py`` builds inline rather than through a
factory is Defender, and that arm is built here from the same
``DEFENDER_CLIENT_PARAM_KEYS`` it declares.

What a vendor with no usable credentials gets
---------------------------------------------
A 422 naming the keys that would have built a client, not an empty list. An
empty list reads as "this customer closed nothing in that window", which is a
statement about their SOC rather than about their configuration, and it would
travel into a report as a sample size of zero.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.clients.defender_client import DefenderClient
from app.executors.siem import (
    DEFENDER_CLIENT_PARAM_KEYS,
    ELASTIC_CLIENT_PARAM_KEYS,
    QRADAR_CLIENT_PARAM_KEYS,
    SENTINEL_CLIENT_PARAM_KEYS,
    SPLUNK_CLIENT_PARAM_KEYS,
    _elastic_client,
    _qradar_client,
    _sentinel_client,
    _splunk_client,
)
from app.security.authz import require_service_auth
from app.services.alert_history import (
    ClosedFinding,
    parse_defender_alert,
    parse_elastic_signal,
    parse_qradar_offense,
    parse_sentinel_incident,
    parse_splunk_notable,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/replay", tags=["replay"])

#: The five vendors Phase 1.1 wrote readers for. A literal rather than a free
#: string so an unsupported vendor is a 422 from the schema with the supported
#: set in the message, rather than a 500 from a dictionary lookup.
Vendor = Literal["splunk", "sentinel", "elastic", "qradar", "defender"]

#: Hard ceiling on one window's read. Replay grades a window, and a caller who
#: asks for more than this is asking for a different job than the one the
#: report describes. Refused rather than truncated: a truncated list reads as
#: the whole window and would be reported as one.
MAX_FINDINGS = 5000

#: Which credential keys each vendor's client factory reads, so a refusal can
#: name them. Sourced from ``app.executors.siem`` rather than retyped, which
#: is the defect this repository found in the dry-run credential strip: a list
#: of key names that had drifted from what the factory actually read.
_CREDENTIAL_KEYS: dict[str, tuple[str, ...]] = {
    "splunk": SPLUNK_CLIENT_PARAM_KEYS,
    "sentinel": SENTINEL_CLIENT_PARAM_KEYS,
    "elastic": ELASTIC_CLIENT_PARAM_KEYS,
    "qradar": QRADAR_CLIENT_PARAM_KEYS,
    "defender": DEFENDER_CLIENT_PARAM_KEYS,
}


class HistoryRequest(BaseModel):
    """One vendor, one window, one set of credentials the API already decrypted.

    There is no tenant field. This service never resolves a tenant: the
    credentials it is handed *are* the scope, because they reach exactly one
    customer's SIEM. A tenant field here would be a value the caller chose
    that nothing checked.
    """

    vendor: Vendor
    #: Decrypted by ``services/api`` from the connector instance's vault
    #: record before the call. Same envelope as the connector test-connection
    #: and normalize proxies.
    credentials: dict[str, Any] = Field(default_factory=dict)
    since: datetime
    until: datetime
    limit: int = Field(default=1000, ge=1, le=MAX_FINDINGS)
    #: Splunk only: the saved search or inline SPL the deployment stores its
    #: notables under. Deployments rename it, so a hardcoded search returns
    #: nothing on a site that did.
    search_override: str | None = None
    #: Elastic only: the signals index pattern.
    index: str | None = None


class HistoryResponse(BaseModel):
    vendor: str
    #: Rows the vendor returned. Reported separately from ``labelled`` so a
    #: customer whose analysts close without a disposition sees that, rather
    #: than a small graded sample with no explanation.
    count: int
    labelled: int
    unlabeled: int
    findings: list[dict[str, Any]]


def _unusable(vendor: str) -> HTTPException:
    keys = ", ".join(_CREDENTIAL_KEYS.get(vendor, ()))
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            f"no usable {vendor} credentials in this request; the client factory reads {keys}. "
            f"Returning an empty history instead would be reported as a window in which "
            f"nobody closed anything."
        ),
    )


async def _read_splunk(body: HistoryRequest) -> list[ClosedFinding]:
    client = _splunk_client(body.credentials)
    if client is None:
        raise _unusable("splunk")
    rows = await client.list_closed_notables(
        body.since,
        body.until,
        limit=body.limit,
        search_override=body.search_override,
    )
    return [parse_splunk_notable(row) for row in rows]


async def _read_sentinel(body: HistoryRequest) -> list[ClosedFinding]:
    client = _sentinel_client(body.credentials)
    if client is None:
        raise _unusable("sentinel")
    rows = await client.list_closed_incidents(body.since, body.until, limit=body.limit)
    return [parse_sentinel_incident(row) for row in rows]


async def _read_elastic(body: HistoryRequest) -> list[ClosedFinding]:
    client = _elastic_client(body.credentials)
    if client is None:
        raise _unusable("elastic")
    kwargs: dict[str, Any] = {"limit": body.limit}
    if body.index:
        kwargs["index"] = body.index
    rows = await client.list_closed_signals(body.since, body.until, **kwargs)
    return [parse_elastic_signal(row) for row in rows]


async def _read_qradar(body: HistoryRequest) -> list[ClosedFinding]:
    client = _qradar_client(body.credentials)
    if client is None:
        raise _unusable("qradar")
    rows = await client.list_closed_offenses(body.since, body.until, limit=body.limit)
    return [parse_qradar_offense(row) for row in rows]


async def _read_defender(body: HistoryRequest) -> list[ClosedFinding]:
    creds = body.credentials
    required = (creds.get("mde_tenant_id"), creds.get("mde_client_id"), creds.get("mde_client_secret"))
    if not all(required):
        raise _unusable("defender")
    client = DefenderClient(str(required[0]), str(required[1]), str(required[2]))
    rows = await client.list_resolved_alerts(body.since, body.until, limit=body.limit)
    return [parse_defender_alert(row) for row in rows]


_READERS = {
    "splunk": _read_splunk,
    "sentinel": _read_sentinel,
    "elastic": _read_elastic,
    "qradar": _read_qradar,
    "defender": _read_defender,
}


@router.post("/history", response_model=HistoryResponse, summary="Closed findings for one window")
async def read_history(
    body: HistoryRequest,
    _auth: Annotated[None, Depends(require_service_auth)] = None,
) -> HistoryResponse:
    """Read the findings a customer's analysts closed, with the labels they chose.

    A vendor error surfaces as a 502 naming the vendor rather than an empty
    list, for the same reason a missing credential does: replay must not grade
    a window it could not read and report the result as a measurement.
    """
    if body.until <= body.since:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"until ({body.until.isoformat()}) must be after since ({body.since.isoformat()})",
        )

    try:
        findings = await _READERS[body.vendor](body)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - every vendor failure is a 502, never an empty window
        logger.exception("replay.history.read_failed", vendor=body.vendor)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"reading {body.vendor} history failed: {type(exc).__name__}",
        ) from exc

    labelled = sum(1 for f in findings if f.is_labelled)
    logger.info(
        "replay.history.read",
        vendor=body.vendor,
        count=len(findings),
        labelled=labelled,
    )
    return HistoryResponse(
        vendor=body.vendor,
        count=len(findings),
        labelled=labelled,
        unlabeled=len(findings) - labelled,
        findings=[f.as_dict() for f in findings],
    )

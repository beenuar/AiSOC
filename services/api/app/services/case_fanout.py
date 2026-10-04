"""Case → ITSM fan-out service (Workstream 8).

Responsibility
==============
Project AiSOC case lifecycle events (create, status change) onto every
external ITSM connector instance the tenant has linked to that case
class. Concretely:

* On ``POST /api/v1/cases``: optionally call ``fanout_create_case``
  for the operator-selected list of connector instances. The service
  decrypts each connector's ``auth_config`` via the credential vault,
  POSTs to ``services/connectors POST /connectors/{type}/push_case``,
  and persists the returned ``{external_id, external_url, vendor,
  external_status}`` envelope into ``case_external_refs``.
* On ``PATCH /api/v1/cases/{id}`` with a status change:
  ``fanout_status_change`` walks every existing ``case_external_refs``
  row for that case and POSTs to
  ``POST /connectors/{type}/push_status_change`` with the prior +
  current status. Connectors decide how to project that onto their
  vendor (state code, resolution code, close notes).

Design notes
------------
* The fan-out is best-effort, never blocking. A flaky Jira instance
  must not 503 a case create. We catch every exception per backend
  and surface a per-vendor ``status`` field; the caller gets a 201
  on the case + a ``ticket_refs`` array that includes failures.
* Idempotency lives in the connector. ``push_case`` SHOULD treat a
  retry on the same AiSOC ``case.id`` as a no-op or update, not a
  fresh ticket. The connectors microservice already enforces this
  for Jira (correlation_id) and ServiceNow (correlation_id). Our
  layer only has to make the external_ref upsert race-safe, which the
  ``UNIQUE (connector_instance_id, external_id)`` constraint from
  migration 035 handles.
* Auth model mirrors ``federated.py``: API service decrypts via the
  vault and forwards plaintext over the internal Docker / VPC network;
  the connectors microservice never sees ciphertext.

The module is intentionally connector-agnostic — it only knows
``connector_type`` strings ("jira", "servicenow", ...) and forwards
everything else to the connectors microservice. New ITSM connectors
that declare ``Capability.PUSH_CASE`` flow through here automatically
once the operator allow-lists the connector_type in
``ITSM_PUSH_CAPABLE_TYPES`` below.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.connectors_auth import connectors_headers
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)


# Connector types eligible for case fan-out. Mirrors the
# ``Capability.PUSH_CASE`` declaration in services/connectors but
# expressed here as a string set so the API service doesn't need to
# import the connectors-microservice-side enum just to filter.
ITSM_PUSH_CAPABLE_TYPES: frozenset[str] = frozenset(
    {
        "jira",
        "servicenow",
    }
)


# ---------------------------------------------------------------- response models


class FanoutResult(BaseModel):
    """Outcome of one ``push_case`` / ``push_status_change`` call.

    Always set so the UI can show "Jira ✓ · ServiceNow ✗ (timeout)"
    next to the case header without needing to re-read the audit log.
    """

    connector_id: uuid.UUID
    connector_type: str
    connector_name: str
    status: str = Field(description="ok | error | unsupported | skipped")
    external_id: str | None = None
    external_url: str | None = None
    external_status: str | None = None
    error: str | None = None


# --------------------------------------------------------------------- helpers


def _push_case_url(connector_type: str) -> str:
    base = settings.CONNECTORS_SERVICE_URL.rstrip("/")
    return f"{base}/api/v1/connectors/{connector_type}/push_case"


def _push_status_url(connector_type: str) -> str:
    base = settings.CONNECTORS_SERVICE_URL.rstrip("/")
    return f"{base}/api/v1/connectors/{connector_type}/push_status_change"


async def _fetch_connectors_by_id(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    connector_ids: list[uuid.UUID],
) -> list[Connector]:
    """Resolve the connector instances the caller asked us to fan out to.

    Same defense-in-depth as ``federated._fetch_target_connectors``:
    tenant-scoped, ``is_enabled=True``, type in the push-capable set.
    Connectors not in ``ITSM_PUSH_CAPABLE_TYPES`` are silently dropped
    (rather than raising) because the operator may legitimately have
    a Splunk + a Jira selected — we only push to the Jira and let the
    audit log record that Splunk was skipped.
    """
    if not connector_ids:
        return []

    stmt = select(Connector).where(
        Connector.tenant_id == tenant_id,
        Connector.is_enabled.is_(True),
        Connector.connector_type.in_(ITSM_PUSH_CAPABLE_TYPES),
        Connector.id.in_(connector_ids),
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


def _serialize_case_for_push(case_row: Any) -> dict[str, Any]:
    """Project an ``aisoc_cases`` row into the ``case`` payload.

    The connectors microservice expects a plain dict — it doesn't share
    the API service's ORM. We deliberately avoid forwarding tenant-only
    columns (``observable_graph``, ``evidence_chain``, etc.) so a
    misconfigured connector that decides to log the entire payload
    can't accidentally exfiltrate intra-tenant graph data.
    """
    # Support both SQLAlchemy ``Row``-style and dict-style inputs so
    # callers can pass either ``row._mapping`` or a hand-built dict.
    if hasattr(case_row, "_mapping"):
        case_row = dict(case_row._mapping)
    elif not isinstance(case_row, dict):
        case_row = dict(case_row)

    return {
        "id": str(case_row.get("id")) if case_row.get("id") else None,
        "case_number": case_row.get("case_number"),
        "title": case_row.get("title"),
        "description": case_row.get("description"),
        "severity": case_row.get("severity"),
        "status": case_row.get("status"),
        "assignee": case_row.get("assignee"),
        "tags": case_row.get("tags") or {},
        "mitre_techniques": case_row.get("mitre_techniques") or [],
    }


async def _post_to_connector_service(
    *,
    url: str,
    payload: dict[str, Any],
    timeout_seconds: float,
    tenant_id: Any,
) -> tuple[str, dict[str, Any] | None, str | None]:
    """POST to the connectors microservice and return (status, body, err).

    ``status`` is one of:
      * ``"ok"`` — 2xx response, ``body`` populated.
      * ``"error"`` — 4xx/5xx or transport error, ``error`` populated.
      * ``"unsupported"`` — 501 (connector lacks the capability).

    Wraps every failure path so the caller never has to catch
    ``httpx.HTTPError`` itself.
    """
    timeout = httpx.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=connectors_headers(tenant_id))
    except httpx.HTTPError as exc:
        return ("error", None, f"connectors service unreachable: {exc}")

    if resp.status_code == 501:
        return ("unsupported", None, resp.text or "capability not declared")

    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail") or resp.text
        except ValueError:
            detail = resp.text
        return ("error", None, f"backend {resp.status_code}: {detail}")

    try:
        body = resp.json() if resp.content else {}
    except ValueError:
        return ("error", None, "connectors service returned non-JSON body")

    if not isinstance(body, dict):
        return ("error", None, "connectors service returned unexpected payload shape")

    return ("ok", body, None)


# ------------------------------------------------------------------ persistence


async def _upsert_external_ref(
    db: AsyncSession,
    *,
    case_id: uuid.UUID,
    connector_instance_id: uuid.UUID,
    vendor: str,
    external_id: str,
    external_url: str | None,
    external_status: str | None,
    pushed_by: str | None,
) -> None:
    """Idempotently insert/update a ``case_external_refs`` row.

    The unique constraint ``(connector_instance_id, external_id)``
    guarantees two concurrent fan-outs collapse into one row. We use
    ``ON CONFLICT DO UPDATE`` so the second writer still gets the
    fresh ``external_status``/``last_synced_at`` instead of dropping
    the update on the floor.
    """
    q = text(
        """
        INSERT INTO case_external_refs (
            case_id, connector_instance_id, vendor, external_id,
            external_url, external_status, pushed_by, last_synced_at
        ) VALUES (
            :case_id, :connector_instance_id, :vendor, :external_id,
            :external_url, :external_status, :pushed_by, NOW()
        )
        ON CONFLICT (connector_instance_id, external_id) DO UPDATE SET
            external_url     = COALESCE(EXCLUDED.external_url,    case_external_refs.external_url),
            external_status  = COALESCE(EXCLUDED.external_status, case_external_refs.external_status),
            pushed_by        = COALESCE(EXCLUDED.pushed_by,       case_external_refs.pushed_by),
            last_synced_at   = NOW()
        """
    ).bindparams(
        case_id=case_id,
        connector_instance_id=connector_instance_id,
        vendor=vendor,
        external_id=external_id,
        external_url=external_url,
        external_status=external_status,
        pushed_by=pushed_by,
    )
    await db.execute(q)


async def _fetch_existing_refs(
    db: AsyncSession,
    case_id: uuid.UUID,
) -> list[dict[str, Any]]:
    """Return the external refs already known for this case.

    Used by the status-change path: each refrow tells us which
    connector instance + external id to PATCH. ``vendor`` is used to
    pick the right ``connector_type`` URL on the connectors service.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT id, case_id, connector_instance_id, vendor,
                       external_id, external_url, external_status
                FROM case_external_refs
                WHERE case_id = :case_id
                """
            ).bindparams(case_id=case_id)
        )
    ).fetchall()
    return [dict(r._mapping) for r in rows]


# ---------------------------------------------------------------------- public API


async def fanout_create_case(
    db: AsyncSession,
    *,
    case_row: Any,
    tenant_id: uuid.UUID,
    connector_ids: list[uuid.UUID],
    pushed_by: str | None = None,
    timeout_seconds: float | None = None,
) -> list[FanoutResult]:
    """Push the just-created case to ``connector_ids`` in parallel-ish order.

    We deliberately do NOT use ``asyncio.gather`` here: each push
    requires writing back to the same ``case_external_refs`` table,
    and the AsyncSession is not safe to share across concurrent
    tasks. Sequential per-connector loop is fast enough — fan-out is
    bounded by the operator's connector count (typically ≤ 3) and the
    httpx timeout — and avoids subtle session interleaving bugs.

    Per-backend errors are captured into ``FanoutResult`` and never
    raise; the caller (``POST /api/v1/cases``) gets a list it can
    surface in the response without changing its 201 status.
    """
    if not connector_ids:
        return []

    timeout = float(timeout_seconds or settings.CONNECTORS_SERVICE_TIMEOUT_SECONDS)
    targets = await _fetch_connectors_by_id(db, tenant_id, connector_ids)
    case_payload = _serialize_case_for_push(case_row)
    case_id = uuid.UUID(case_payload["id"]) if case_payload.get("id") else None

    results: list[FanoutResult] = []
    for connector in targets:
        result = await _push_one_case(
            db=db,
            connector=connector,
            case_payload=case_payload,
            case_id=case_id,
            pushed_by=pushed_by,
            timeout_seconds=timeout,
        )
        results.append(result)
    return results


async def _push_one_case(
    *,
    db: AsyncSession,
    connector: Connector,
    case_payload: dict[str, Any],
    case_id: uuid.UUID | None,
    pushed_by: str | None,
    timeout_seconds: float,
) -> FanoutResult:
    """Inner per-connector push for ``fanout_create_case``."""
    try:
        decrypted_auth = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        return FanoutResult(
            connector_id=connector.id,
            connector_type=connector.connector_type,
            connector_name=connector.name,
            status="error",
            error=f"credential decryption failed: {exc}",
        )

    payload = {
        "auth_config": decrypted_auth,
        "connector_config": connector.connector_config or {},
        "case": case_payload,
        "external_ref": None,
    }
    url = _push_case_url(connector.connector_type)
    push_status, body, err = await _post_to_connector_service(
        url=url,
        payload=payload,
        timeout_seconds=timeout_seconds,
        tenant_id=connector.tenant_id,
    )

    if push_status != "ok" or body is None:
        return FanoutResult(
            connector_id=connector.id,
            connector_type=connector.connector_type,
            connector_name=connector.name,
            status=push_status,
            error=err,
        )

    external_id = body.get("external_id")
    if not external_id:
        return FanoutResult(
            connector_id=connector.id,
            connector_type=connector.connector_type,
            connector_name=connector.name,
            status="error",
            error="connector did not return external_id",
        )

    if case_id is not None:
        try:
            await _upsert_external_ref(
                db,
                case_id=case_id,
                connector_instance_id=connector.id,
                vendor=str(body.get("vendor") or connector.connector_type),
                external_id=str(external_id),
                external_url=body.get("external_url"),
                external_status=body.get("external_status"),
                pushed_by=pushed_by,
            )
        except Exception:
            logger.exception(
                "case_fanout.upsert_external_ref_failed case=%s connector=%s",
                case_id,
                connector.id,
            )
            # External system already minted the ticket; failing here
            # would silently lose the linkage. We surface the persistence
            # failure but keep external_id in the response so the
            # operator can recover via the manual "link existing ticket"
            # affordance.
            return FanoutResult(
                connector_id=connector.id,
                connector_type=connector.connector_type,
                connector_name=connector.name,
                status="error",
                external_id=str(external_id),
                external_url=body.get("external_url"),
                external_status=body.get("external_status"),
                error="case_external_refs persistence failed; external ticket was created",
            )

    return FanoutResult(
        connector_id=connector.id,
        connector_type=connector.connector_type,
        connector_name=connector.name,
        status="ok",
        external_id=str(external_id),
        external_url=body.get("external_url"),
        external_status=body.get("external_status"),
    )


async def fanout_status_change(
    db: AsyncSession,
    *,
    case_row: Any,
    tenant_id: uuid.UUID,
    old_status: str,
    new_status: str,
    pushed_by: str | None = None,
    timeout_seconds: float | None = None,
) -> list[FanoutResult]:
    """Project a status change to every connector this case is linked to.

    Walks ``case_external_refs`` for the case. For each row, finds the
    matching live ``connectors`` row (so we get the latest decrypted
    creds and connector_config, not whatever was current at create
    time), builds the push payload, and POSTs.

    The connector decides whether to no-op (``new_status`` is already
    reflected on the ticket) or to PATCH. We don't try to be clever
    here; that's exactly the kind of decision that has to live next
    to the vendor mapping.
    """
    case_payload = _serialize_case_for_push(case_row)
    raw_id = case_payload.get("id")
    if not raw_id:
        return []
    case_id = uuid.UUID(raw_id)

    refs = await _fetch_existing_refs(db, case_id)
    if not refs:
        return []

    timeout = float(timeout_seconds or settings.CONNECTORS_SERVICE_TIMEOUT_SECONDS)

    instance_ids = [ref["connector_instance_id"] for ref in refs]
    stmt = select(Connector).where(
        Connector.tenant_id == tenant_id,
        Connector.id.in_(instance_ids),
    )
    rows = (await db.execute(stmt)).scalars().all()
    connectors_by_id = {row.id: row for row in rows}

    results: list[FanoutResult] = []
    for ref in refs:
        connector = connectors_by_id.get(ref["connector_instance_id"])
        if connector is None:
            # Connector was deleted but the external_ref row survived
            # (FK is on case_id, not connector_instance_id). Surface
            # this as a skipped result so operators see the orphan.
            results.append(
                FanoutResult(
                    connector_id=ref["connector_instance_id"],
                    connector_type=ref["vendor"],
                    connector_name="(deleted)",
                    status="skipped",
                    external_id=ref["external_id"],
                    external_url=ref.get("external_url"),
                    error="connector instance no longer exists",
                )
            )
            continue

        result = await _push_one_status_change(
            db=db,
            connector=connector,
            ref=ref,
            case_payload=case_payload,
            old_status=old_status,
            new_status=new_status,
            pushed_by=pushed_by,
            timeout_seconds=timeout,
        )
        results.append(result)
    return results


async def _push_one_status_change(
    *,
    db: AsyncSession,
    connector: Connector,
    ref: dict[str, Any],
    case_payload: dict[str, Any],
    old_status: str,
    new_status: str,
    pushed_by: str | None,
    timeout_seconds: float,
) -> FanoutResult:
    """Inner per-connector push for ``fanout_status_change``."""
    try:
        decrypted_auth = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        return FanoutResult(
            connector_id=connector.id,
            connector_type=connector.connector_type,
            connector_name=connector.name,
            status="error",
            external_id=ref["external_id"],
            error=f"credential decryption failed: {exc}",
        )

    external_ref_payload = {
        "external_id": ref["external_id"],
        "external_url": ref.get("external_url"),
        "external_status": ref.get("external_status"),
        "vendor": ref["vendor"],
    }
    payload = {
        "auth_config": decrypted_auth,
        "connector_config": connector.connector_config or {},
        "case": case_payload,
        "old_status": old_status,
        "new_status": new_status,
        "external_ref": external_ref_payload,
    }
    url = _push_status_url(connector.connector_type)
    push_status, body, err = await _post_to_connector_service(
        url=url,
        payload=payload,
        timeout_seconds=timeout_seconds,
        tenant_id=connector.tenant_id,
    )

    if push_status != "ok" or body is None:
        return FanoutResult(
            connector_id=connector.id,
            connector_type=connector.connector_type,
            connector_name=connector.name,
            status=push_status,
            external_id=ref["external_id"],
            error=err,
        )

    external_id = body.get("external_id") or ref["external_id"]
    new_external_status = body.get("external_status") or ref.get("external_status")

    try:
        await _upsert_external_ref(
            db,
            case_id=uuid.UUID(case_payload["id"]),
            connector_instance_id=connector.id,
            vendor=str(body.get("vendor") or connector.connector_type),
            external_id=str(external_id),
            external_url=body.get("external_url") or ref.get("external_url"),
            external_status=new_external_status,
            pushed_by=pushed_by,
        )
    except Exception:
        logger.exception(
            "case_fanout.upsert_external_ref_failed case=%s connector=%s",
            case_payload.get("id"),
            connector.id,
        )

    return FanoutResult(
        connector_id=connector.id,
        connector_type=connector.connector_type,
        connector_name=connector.name,
        status="ok",
        external_id=str(external_id),
        external_url=body.get("external_url") or ref.get("external_url"),
        external_status=new_external_status,
    )

"""FastAPI middleware that auto-emits audit log events for mutating requests.

For every POST / PUT / PATCH / DELETE request that carries a valid JWT the
middleware appends an AuditLog row **after** the response has been produced so
it never blocks the hot path.

Non-authenticated requests and GET/HEAD/OPTIONS are silently skipped.

Hardening (BATCH 7 — H-4 + M-12)
--------------------------------

* Uses :func:`app.core.trusted_proxy.resolve_client_ip` so
  ``X-Forwarded-For`` is only honoured for trusted hops. The previous
  implementation took the first XFF value unconditionally.
* Caps user-agent / request-id header sizes before writing them to the
  ``metadata`` JSONB column.
* Writes ``prev_hash`` / ``entry_hash`` so middleware-emitted rows
  participate in the same tamper-evident chain as :func:`emit_audit`.

One writer per request (migration 074)
--------------------------------------

This middleware and a handler's :func:`emit_audit` used to write two audit
rows for one request, on two sessions, both resolving the same chain head —
and the chain forked. It now writes only when the request produced no audit
row of its own, so a request has exactly one audit writer. See
:func:`app.services.audit._append_to_chain` for why serializing the two was
not an option from here.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime

from app.core.trusted_proxy import resolve_client_ip
from app.db.database import AsyncSessionLocal
from app.models.audit import AuditLog
from app.services.audit import (
    _append_to_chain,
    begin_request_audit_scope,
    end_request_audit_scope,
    request_emitted_audit,
)
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger("aisoc.audit.middleware")

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

# Header value caps — keep audit rows bounded even under malicious peers.
_MAX_UA_LEN = 512
_MAX_REQUEST_ID_LEN = 128

# Map URL patterns → (action, resource) label pairs for cleaner audit records.
_ROUTE_LABELS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^/api/v1/cases/?(.*)"), "cases", "case"),
    (re.compile(r"^/api/v1/alerts/?(.*)"), "alerts", "alert"),
    (re.compile(r"^/api/v1/playbooks/?(.*)"), "playbooks", "playbook"),
    (re.compile(r"^/api/v1/detection_rules/?(.*)"), "detections", "detection_rule"),
    (re.compile(r"^/api/v1/connectors/?(.*)"), "connectors", "connector"),
    (re.compile(r"^/api/v1/api-keys/?(.*)"), "api_keys", "api_key"),
    (re.compile(r"^/api/v1/rbac/roles/?(.*)"), "roles", "role"),
    (re.compile(r"^/api/v1/rbac/users/?(.*)"), "user_roles", "user_role"),
    (re.compile(r"^/api/v1/plugins/?(.*)"), "plugins", "plugin"),
    (re.compile(r"^/api/v1/community/?(.*)"), "community", "community_item"),
    (re.compile(r"^/api/v1/tenants/?(.*)"), "tenants", "tenant"),
    (re.compile(r"^/api/v1/auth/?(.*)"), "auth", "auth"),
    (re.compile(r"^/auth/?(.*)"), "auth", "auth"),
]


def _label_for_path(method: str, path: str) -> tuple[str, str]:
    """Return (action, resource) for a given HTTP method + path."""
    for pattern, resource_prefix, resource_type in _ROUTE_LABELS:
        if pattern.match(path):
            verb = {
                "POST": "create",
                "PUT": "update",
                "PATCH": "update",
                "DELETE": "delete",
            }.get(method, method.lower())
            return f"{resource_prefix}:{verb}", resource_type
    return f"{method.lower()}:{path}", "unknown"


def _extract_jwt_claims(request: Request) -> tuple[uuid.UUID | None, uuid.UUID | None, str | None]:
    """Return (user_id, tenant_id, email) from the Bearer JWT without re-validating."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None, None, None
    token = auth.split(" ", 1)[1]
    try:
        import jwt  # noqa: PLC0415

        payload = jwt.decode(token, options={"verify_signature": False})
        user_id = uuid.UUID(payload["sub"]) if payload.get("sub") else None
        tenant_id = uuid.UUID(payload["tenant_id"]) if payload.get("tenant_id") else None
        email = payload.get("email")
        return user_id, tenant_id, email
    except Exception:
        return None, None, None


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit]


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Opened *before* `call_next` so the downstream task inherits the
        # dict by reference and `emit_audit` can mark it. A context is copied
        # when the task is spawned, so a scope opened after this point would
        # never see the handler's mark.
        scope_token = begin_request_audit_scope()
        try:
            response = await call_next(request)
        except BaseException:
            end_request_audit_scope(scope_token)
            raise

        try:
            return await self._audit(request, response)
        finally:
            end_request_audit_scope(scope_token)

    async def _audit(self, request: Request, response: Response) -> Response:
        if request.method not in _MUTATING:
            return response

        # Only audit successful (2xx) and most 4xx responses – skip 5xx noise
        if response.status_code >= 500:
            return response

        user_id, tenant_id, email = _extract_jwt_claims(request)
        if tenant_id is None:
            return response  # unauthenticated

        # One audit writer per request.
        #
        # This row and the handler's `emit_audit` row were written on separate
        # sessions, both resolving the same chain head, and the chain forked.
        # Serializing them cannot work from here: this runs before the request
        # session's dependency teardown, so waiting on the handler's
        # transaction waits on something that cannot commit until this returns
        # — measured, and it dropped this row entirely.
        #
        # The handler's row is the better of the two anyway. It carries the
        # real `changes` payload and the action the handler meant, where this
        # one carries a label guessed from the URL. What is lost by skipping
        # is the status code, which is recoverable from the access log and is
        # not worth a forked audit chain.
        if request_emitted_audit(request):
            return response

        try:
            action, resource = _label_for_path(request.method, request.url.path)
            # Try to extract resource_id from path (last segment that looks like a UUID)
            segments = [s for s in request.url.path.split("/") if s]
            resource_id: str | None = None
            for seg in reversed(segments):
                try:
                    uuid.UUID(seg)
                    resource_id = seg
                    break
                except ValueError:
                    pass  # segment is not a UUID; try next

            async with AsyncSessionLocal() as db:
                try:
                    actor_ip = resolve_client_ip(request)
                except Exception:  # noqa: BLE001
                    logger.warning("audit-middleware: failed to resolve client IP", exc_info=True)
                    actor_ip = None

                meta: dict = {}
                ua = _truncate(request.headers.get("user-agent"), _MAX_UA_LEN)
                if ua:
                    meta["user_agent"] = ua
                rid = _truncate(request.headers.get("x-request-id"), _MAX_REQUEST_ID_LEN)
                if rid:
                    meta["request_id"] = rid
                meta["status_code"] = response.status_code

                created_at = datetime.now(UTC)
                event = AuditLog(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    actor_id=user_id,
                    actor_email=email,
                    actor_ip=actor_ip,
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    metadata_=meta or None,
                    created_at=created_at,
                )

                # Chain-link the middleware event onto the tenant's history,
                # through the same serialized appender the handlers use. This
                # session is the only audit writer for this request, so the
                # per-tenant lock it takes can only ever wait on *another*
                # request's transaction, which commits on its own.
                try:
                    await _append_to_chain(db, event)
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "audit-middleware: failed to compute hash chain",
                        exc_info=True,
                    )
                    event.prev_hash = None
                    event.entry_hash = None

                db.add(event)
                await db.commit()
        except Exception:
            pass  # Never let audit failures break the main response

        return response

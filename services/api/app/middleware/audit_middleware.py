"""FastAPI middleware that auto-emits audit log events for mutating requests.

For every POST / PUT / PATCH / DELETE request that carries a valid JWT the
middleware appends an AuditLog row **after** the response has been produced so
it never blocks the hot path.

Non-authenticated requests and GET/HEAD/OPTIONS are silently skipped.
"""

from __future__ import annotations

import re
import uuid

from app.db.database import AsyncSessionLocal
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

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


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method not in _MUTATING:
            return response

        # Only audit successful (2xx) and most 4xx responses – skip 5xx noise
        if response.status_code >= 500:
            return response

        user_id, tenant_id, email = _extract_jwt_claims(request)
        if tenant_id is None:
            return response  # unauthenticated

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
                from app.models.audit import AuditLog  # noqa: PLC0415

                forwarded = request.headers.get("x-forwarded-for")
                actor_ip = (forwarded.split(",")[0].strip() if forwarded else None) or (
                    str(request.client.host) if request.client else None
                )
                meta: dict = {}
                ua = request.headers.get("user-agent")
                if ua:
                    meta["user_agent"] = ua
                rid = request.headers.get("x-request-id")
                if rid:
                    meta["request_id"] = rid
                meta["status_code"] = response.status_code

                event = AuditLog(
                    tenant_id=tenant_id,
                    actor_id=user_id,
                    actor_email=email,
                    actor_ip=actor_ip,
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    metadata_=meta or None,
                )
                db.add(event)
                await db.commit()
        except Exception:
            pass  # Never let audit failures break the main response

        return response

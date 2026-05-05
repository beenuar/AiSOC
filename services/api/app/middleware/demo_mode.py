"""Demo-mode guard for the hosted demo at tryaisoc.com.

When `AISOC_DEMO_MODE=true`, this middleware:

1. **Surfaces a banner.** Adds `X-AiSOC-Demo: true` and
   `X-AiSOC-Demo-Banner: <message>` headers on every response so the web
   client can render the "demo data resets daily" notice.
2. **Blocks destructive writes.** Any non-safe HTTP method (POST/PUT/PATCH/DELETE)
   targeting a mutating endpoint returns 403 with a structured payload
   explaining how to self-host. We allow a small allowlist (auth, dev_auth,
   investigation kickoff against the canonical case) so the canned demo
   experience still works end-to-end.

This is *not* a substitute for proper auth/RBAC — it's a defense-in-depth
layer on top of the demo tenant's read-only RBAC role. Without it, a
visitor poking at `/api/v1/cases` could mutate the global demo state for
every other concurrent visitor.

Configured in `app.main.create_application` after CORS/GZip so the headers
land on cached error responses too.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable

from app.core.config import settings
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger(__name__)

# Always allowed (auth flows + read endpoints). Match by prefix.
_ALWAYS_ALLOWED_PREFIXES: tuple[str, ...] = (
    "/health",
    "/metrics",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth/",
    "/api/v1/dev-auth",
    "/saml/",
    "/oidc/",
)

# In demo mode these *write* endpoints still work — needed for the canned
# "click → see investigation" experience to function.
_DEMO_WRITE_ALLOWLIST: tuple[re.Pattern[str], ...] = (
    # The seed pre-warms a run, but visitors can still kick off their own.
    re.compile(r"^/api/v1/cases/INC-001/investigate$"),
    re.compile(r"^/api/v1/investigations/[^/]+/cancel$"),
    # Acknowledgement is local-state-only on the visitor's view.
    re.compile(r"^/api/v1/alerts/[^/]+/ack$"),
)

_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


class DemoModeMiddleware(BaseHTTPMiddleware):
    """Gate writes and surface banner headers when AISOC_DEMO_MODE is on."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not settings.AISOC_DEMO_MODE:
            return await call_next(request)

        path = request.url.path
        method = request.method.upper()

        # Read-only or auth flow → just decorate response.
        if method in _SAFE_METHODS or path.startswith(_ALWAYS_ALLOWED_PREFIXES):
            response = await call_next(request)
            self._stamp_demo_headers(response)
            return response

        # Allowlisted mutations (canonical demo flow) → permit.
        if any(p.match(path) for p in _DEMO_WRITE_ALLOWLIST):
            response = await call_next(request)
            self._stamp_demo_headers(response)
            return response

        # Everything else → 403 with a structured "self-host me" payload.
        log.info(
            "demo-mode blocked %s %s (origin=%s)",
            method,
            path,
            request.client.host if request.client else "?",
        )
        response = JSONResponse(
            status_code=403,
            content={
                "error": "demo_mode_read_only",
                "message": (
                    "This is the public AiSOC demo at tryaisoc.com. "
                    "Write actions are disabled here so every visitor sees "
                    "the same dataset. To run AiSOC for real, self-host it "
                    "in 5 minutes — see https://github.com/beenuar/AiSOC."
                ),
                "self_host_url": "https://github.com/beenuar/AiSOC#quickstart",
                "blocked_path": path,
                "blocked_method": method,
            },
        )
        self._stamp_demo_headers(response)
        return response

    @staticmethod
    def _stamp_demo_headers(response: Response) -> None:
        response.headers["X-AiSOC-Demo"] = "true"
        response.headers["X-AiSOC-Demo-Tenant"] = settings.AISOC_DEMO_TENANT
        # Headers can't carry newlines; banner is short by design.
        response.headers["X-AiSOC-Demo-Banner"] = settings.AISOC_DEMO_BANNER

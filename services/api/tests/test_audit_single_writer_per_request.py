"""One request must produce one audit writer.

Why this is the layer that makes serializing the chain possible at all
----------------------------------------------------------------------
A transaction-scoped advisory lock was tried here before and reverted. The two
writers were a handler's `emit_audit` on the request session and
`audit_middleware` on a session of its own, **inside one request**, and the
middleware runs before the request session's dependency teardown. So the
middleware waited on a transaction that could not commit until the middleware
returned. Its acquisition timed out and its audit row was dropped — worse than
the fork it was meant to prevent, because a missing audit row is undetectable
and a forked one is not.

Removing the second writer removes that cycle. Every other layer of the fix
(the per-tenant append lock, the unique index) depends on it, so this is
tested on its own rather than only through the concurrency proof.

These run a real Starlette app through `TestClient`, not a hand-built call of
`dispatch`. The signalling channel is a mutable dict in a `ContextVar`, and
whether it survives depends on how `BaseHTTPMiddleware` spawns the downstream
task — which is precisely the thing a hand-built call would fake. A context is
*copied* when a task is spawned, so a value the endpoint sets is invisible to
the middleware; a reference the middleware installed first, mutated
downstream, is visible to both. A test that asserted the ContextVar was
declared would pass on either.
"""

from __future__ import annotations

import pytest
from app.services.audit import (
    begin_request_audit_scope,
    end_request_audit_scope,
    request_emitted_audit,
)
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient


class _ProbeMiddleware(BaseHTTPMiddleware):
    """Stands in for `AuditMiddleware`, using the same scope helpers.

    Records what the middleware would have decided, so the assertion is about
    the signal arriving rather than about a database row.
    """

    def __init__(self, app, sink: list) -> None:
        super().__init__(app)
        self.sink = sink

    async def dispatch(self, request: Request, call_next):
        token = begin_request_audit_scope()
        try:
            response = await call_next(request)
            self.sink.append(request_emitted_audit(request))
            return response
        finally:
            end_request_audit_scope(token)


def _app(sink: list) -> FastAPI:
    app = FastAPI()

    @app.post("/emits")
    async def emits(request: Request):
        # What `emit_audit` does at the end of a successful write. Called
        # directly rather than through `emit_audit` so the test needs no
        # database — the contract under test is the signal, not the row.
        from app.services.audit import _mark_request_emitted  # noqa: PLC0415

        _mark_request_emitted(request)
        return {"ok": True}

    @app.post("/emits-without-a-request-object")
    async def emits_headless():
        """A handler that audits with no `Request` to hand.

        Several call sites do this. The ContextVar is the only channel that
        reaches them, so this is the case `request.state` alone would miss.
        """
        from app.services.audit import _mark_request_emitted  # noqa: PLC0415

        _mark_request_emitted(None)
        return {"ok": True}

    @app.post("/silent")
    async def silent():
        return {"ok": True}

    app.add_middleware(_ProbeMiddleware, sink=sink)
    return app


class TestTheMiddlewareSeesTheHandlersMark:
    def test_a_handler_that_audits_suppresses_the_second_writer(self) -> None:
        sink: list = []
        with TestClient(_app(sink)) as client:
            assert client.post("/emits").status_code == 200
        assert sink == [True], "the middleware would have written a second row for this request"

    def test_it_reaches_a_handler_with_no_request_object(self) -> None:
        sink: list = []
        with TestClient(_app(sink)) as client:
            assert client.post("/emits-without-a-request-object").status_code == 200
        assert sink == [True], (
            "the ContextVar did not survive the downstream task spawn, so handlers that "
            "audit without a Request would still produce a second writer"
        )

    def test_a_handler_that_does_not_audit_still_gets_a_row(self) -> None:
        """The other direction, and the one that matters most.

        Suppressing the middleware unconditionally would pass the two tests
        above and silently stop auditing every route that does not call
        `emit_audit` itself — which is most of them.
        """
        sink: list = []
        with TestClient(_app(sink)) as client:
            assert client.post("/silent").status_code == 200
        assert sink == [False], "the middleware must still be the writer when the handler is not"

    def test_the_mark_does_not_leak_between_requests(self) -> None:
        """A ContextVar that is set and never reset would make the first
        audited request suppress the middleware for every request after it on
        the same worker."""
        sink: list = []
        with TestClient(_app(sink)) as client:
            client.post("/emits")
            client.post("/silent")
            client.post("/emits")
            client.post("/silent")
        assert sink == [True, False, True, False]


class TestTheScopeHelpers:
    def test_no_scope_open_reads_as_not_emitted(self) -> None:
        """Outside a request — a worker, a CLI, a test — there is no second
        writer to suppress, so the answer must be False rather than an
        exception."""
        assert request_emitted_audit() is False

    def test_reset_with_a_foreign_token_does_not_raise(self) -> None:
        """`BaseHTTPMiddleware` can unwind in a different context than the one
        that opened the scope. Failing a request over bookkeeping would trade
        a duplicate audit row for a 500."""
        token = begin_request_audit_scope()
        end_request_audit_scope(token)
        end_request_audit_scope(token)  # second reset: already unwound


@pytest.mark.parametrize("value", [None, object()])
def test_end_scope_tolerates_a_nonsense_token(value) -> None:
    end_request_audit_scope(value)

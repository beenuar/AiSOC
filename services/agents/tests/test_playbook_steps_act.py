"""The `http` and `notify` steps reach a real socket, or are refused.

Parity 5.3, "steps that do something". The existing suites cover the
SSRF guard's decisions, the step models' bounds and the engine's control
flow. None of them proves a step ever leaves the process.

Why that distinction matters here specifically
------------------------------------------------
`_handle_block_ip` and `_handle_isolate_host` once returned
`{"simulated": True}` and reached no executor at all, under a comment
claiming playbooks dispatched through the actions service. A step that
returns a plausible dict is indistinguishable from one that acted, and
every test asserting on the dict passes either way.

So this drives the real handlers against a real `HTTPServer` and asks
the only question that separates the two: **did a request arrive?** A
mock answers whether a Python function was called, which is a different
question.

The guard is tested from both sides
-------------------------------------
A step that always calls out is as wrong as one that never does.
Playbook URLs are author-controlled, so the SSRF guard has to refuse
loopback, link-local and cloud-metadata destinations — and the tests
below assert the refusal *and* that nothing arrived, because a refusal
that still made the request is a refusal in name only.

The loopback case is why this suite binds `127.0.0.1` and then
explicitly allows it: without the opt-in the guard correctly refuses its
own test server, which would make every positive assertion here vacuous.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest


class _Endpoint(BaseHTTPRequestHandler):
    """Records every request that reaches it. The recording is the point."""

    received: list[dict[str, Any]] = []

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        _Endpoint.received.append({"path": self.path, "method": self.command, "body": raw.decode(errors="replace")})
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record
    do_PUT = _record

    def log_message(self, *_args: Any) -> None:
        """Quiet: the default handler prints to stderr on every request."""


@pytest.fixture(scope="module")
def endpoint():
    _Endpoint.received.clear()
    server = HTTPServer(("127.0.0.1", 0), _Endpoint)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def _clear(endpoint):  # noqa: ANN001
    """Each test asks "did a request arrive *because of me*"."""
    _Endpoint.received.clear()
    yield


@pytest.fixture
def allow_loopback(monkeypatch: pytest.MonkeyPatch):
    """Let the *positive* tests reach this suite's own server.

    The guard rejects loopback unconditionally and `AISOC_SSRF_ALLOW_PRIVATE`
    does not relax it — deliberately, because a playbook that can reach
    127.0.0.1 can reach every unauthenticated service on the host running
    the engine. (The module header claimed otherwise and contradicted the
    function's own docstring; the header was the wrong half and is now
    corrected.)

    So the loopback rule is suspended here rather than configured away,
    and only for the tests asking "does the handler reach a socket". The
    refusal tests below take no such fixture and exercise the shipped
    default.
    """
    from app.playbook import ssrf_guard

    original = ssrf_guard._is_disallowed_address

    def _permit_loopback(ip, *, allow_private):  # noqa: ANN001, ANN202
        if ip.is_loopback:
            return False, ""
        return original(ip, allow_private=allow_private)

    monkeypatch.setattr(ssrf_guard, "_is_disallowed_address", _permit_loopback)
    yield


def _step(step_type: str, **params: Any):  # noqa: ANN202
    from app.playbook.models import PlaybookStep

    return PlaybookStep(
        step_id=f"s-{step_type}",
        # 'http', not 'http_request'. The StepType enum is the source of
        # truth and the engine dispatches on it; a name taken from the
        # docs rather than the enum fails validation here, which is the
        # right place for it to fail.
        name=f"test {step_type}",
        type=step_type,
        params=params,
        timeout_seconds=5,
    )


@pytest.fixture
def http_execute(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    """Turn the http step on.

    It previews by default since depth 5.1: an `http` step in the shipped
    packs deletes sessions and resets passwords in bulk, through a path the
    capability contract cannot see. A suite that asserts a request arrived
    has to opt in, which is the same shape as `allow_loopback` above.
    """
    monkeypatch.setenv("AISOC_PLAYBOOK_HTTP_EXECUTE", "1")
    yield


@pytest.mark.asyncio
class TestTheHttpStepActs:
    async def test_it_reaches_the_endpoint(self, endpoint, allow_loopback, http_execute) -> None:  # noqa: ANN001
        """The claim: an `http_request` step makes a request."""
        import httpx
        from app.playbook.engine import _handle_http

        async with httpx.AsyncClient() as client:
            result = await _handle_http(
                _step("http", url=f"{endpoint}/hook", method="POST", body={"x": 1}),
                {},
                client,
            )

        assert _Endpoint.received, "the http step produced a result and sent no request"
        assert _Endpoint.received[0]["path"] == "/hook"
        assert result.get("status") == 200

    async def test_the_body_arrives(self, endpoint, allow_loopback, http_execute) -> None:  # noqa: ANN001
        """A request with an empty body would satisfy the test above while
        delivering nothing the recipient can act on."""
        import httpx
        from app.playbook.engine import _handle_http

        async with httpx.AsyncClient() as client:
            await _handle_http(
                _step("http", url=f"{endpoint}/hook", method="POST", body={"alert": "A-1"}),
                {},
                client,
            )

        assert json.loads(_Endpoint.received[0]["body"]).get("alert") == "A-1"


@pytest.mark.asyncio
class TestTheNotifyStepDoesNotInventADelivery:
    """`notify` no longer sends from this process, and that is the fix.

    It had one sender here — `channel == "webhook"` — which none of the 63
    notify steps in the shipped packs use, so every one of them answered
    `{"delivered": false, "reason": "no url"}`. It is now dispatched to
    `services/actions`, where the destination is a vault-held tenant
    reference rather than a URL written into shared pack content, and where
    the capability contract and the tenant's autonomy policy apply.

    The "did a request arrive" question this file exists to ask is asked of
    the arms themselves, over a mock vendor server, in
    `services/actions/tests/test_notify_and_osquery_arms.py`. What belongs
    here is the negative: the engine must not answer for them.
    """

    async def test_the_engine_has_no_notify_sender_of_its_own(self) -> None:
        from app.playbook import engine as engine_mod

        assert not hasattr(engine_mod, "_handle_notify")

    async def test_a_notify_step_is_dispatched_and_never_posted_from_here(self, endpoint, allow_loopback, monkeypatch) -> None:  # noqa: ANN001
        """Even handed a reachable URL, the step must not post it.

        The old handler would have: `channel: webhook` plus a `url` was its
        one delivering combination. A step that still sent from here would
        bypass the contract, the approval matrix and the audit record.
        """
        from app.playbook import engine as engine_mod
        from app.playbook.models import StepType

        seen: dict[str, Any] = {}

        async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
            seen.update(kwargs)
            return {"executed": True, "status": "succeeded"}

        monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _fake_dispatch)

        await engine_mod._HANDLERS[StepType.NOTIFY](
            _step("notify", channel="webhook", url=f"{endpoint}/hook", message="contained"),
            {"tenant_id": "t"},
            None,
        )

        assert seen["capability"] == "notify"
        assert not _Endpoint.received, "the notify step posted from the engine instead of dispatching"


@pytest.mark.asyncio
class TestTheGuardRefusesAndNothingArrives:
    """A step that always calls out is as wrong as one that never does."""

    async def test_loopback_is_refused_by_default(self, endpoint, http_execute) -> None:  # noqa: ANN001
        """No `allow_loopback` here: this is the shipped default.

        Playbook URLs are author-controlled, and a playbook that can
        reach 127.0.0.1 can reach every unauthenticated service on the
        host running the engine.
        """
        import httpx
        from app.playbook.engine import _handle_http
        from app.playbook.ssrf_guard import SSRFError

        async with httpx.AsyncClient() as client:
            with pytest.raises(SSRFError):
                await _handle_http(_step("http", url=f"{endpoint}/hook", method="GET"), {}, client)

        assert not _Endpoint.received, (
            "the guard refused and the request still arrived — a refusal in name only, since the side effect has already happened"
        )

    async def test_cloud_metadata_is_refused(self, http_execute) -> None:  # noqa: ANN001
        """169.254.169.254 is refused even when private IPs are allowed:
        it is the one destination whose whole purpose is handing out
        credentials."""
        import httpx
        from app.playbook.engine import _handle_http
        from app.playbook.ssrf_guard import SSRFError

        async with httpx.AsyncClient() as client:
            with pytest.raises(SSRFError):
                await _handle_http(
                    _step("http", url="http://169.254.169.254/latest/meta-data/", method="GET"),
                    {},
                    client,
                )

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


@pytest.mark.asyncio
class TestTheHttpStepActs:
    async def test_it_reaches_the_endpoint(self, endpoint, allow_loopback) -> None:  # noqa: ANN001
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

    async def test_the_body_arrives(self, endpoint, allow_loopback) -> None:  # noqa: ANN001
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
class TestTheNotifyStepActs:
    async def test_a_webhook_notify_reaches_the_endpoint(self, endpoint, allow_loopback) -> None:  # noqa: ANN001
        import httpx
        from app.playbook.engine import _handle_notify

        async with httpx.AsyncClient() as client:
            result = await _handle_notify(
                _step("notify", channel="webhook", url=f"{endpoint}/hook", message="contained"),
                {},
                client,
            )

        assert _Endpoint.received, "the notify step produced a result and sent no request"
        assert result.get("status") == 200

    async def test_a_notify_with_no_url_says_it_delivered_nothing(self, endpoint) -> None:  # noqa: ANN001
        """The honest branch.

        A notify step with nowhere to send must not report success — an
        analyst who believes a page went out and finds later that it did
        not is worse off than one told immediately.
        """
        import httpx
        from app.playbook.engine import _handle_notify

        async with httpx.AsyncClient() as client:
            result = await _handle_notify(_step("notify", channel="webhook", message="hi"), {}, client)

        assert result.get("delivered") is False
        assert result.get("reason") == "no url", result
        assert not _Endpoint.received

    async def test_a_channel_with_no_sender_says_so_rather_than_no_url(self, endpoint) -> None:  # noqa: ANN001
        """The reason has to name the real cause.

        It said "no url" whatever happened, including when a url *was*
        supplied and the channel simply had no sender — sending an
        operator to look for a missing field that was right in front of
        them.
        """
        import httpx
        from app.playbook.engine import _handle_notify

        async with httpx.AsyncClient() as client:
            result = await _handle_notify(_step("notify", channel="slack", url=f"{endpoint}/slack", message="hi"), {}, client)

        assert result.get("delivered") is False
        assert "no url" not in (result.get("reason") or ""), f"a url was supplied and the reason still blames a missing one: {result!r}"
        assert "slack" in (result.get("reason") or "")


@pytest.mark.asyncio
class TestTheGuardRefusesAndNothingArrives:
    """A step that always calls out is as wrong as one that never does."""

    async def test_loopback_is_refused_by_default(self, endpoint) -> None:  # noqa: ANN001
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

    async def test_cloud_metadata_is_refused(self) -> None:
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

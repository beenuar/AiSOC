"""The MCP client works over a real HTTP connection, not only an injected session.

Fix pass item 2.1 and 2.2. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`_CappedStream` in `app/mcp/client.py` wraps a response body so it cannot
exceed a tenant's byte cap. It was a plain class. `httpx` 0.28.1 asserts
`isinstance(response.stream, AsyncByteStream)` in `_send_single_request`
(`httpx/_client.py:1732`), so **every real `list_tools` and `call_tool` raised
`AssertionError` before a byte was read**. Its `__aiter__` was also `async def`,
which makes the object an awaitable rather than an async iterable.

Separately, `app/mcp/policy.py` names a bound tool `mcp.<server>.<tool>`.
OpenAI-compatible function names must match `^[a-zA-Z0-9_-]{1,64}$`, which
excludes `.`, so every MCP tool offered to a model was rejected by the
provider.

Why the existing suite did not catch either
-------------------------------------------
`McpClient` takes a `session_factory` so a test can drive a real MCP server
**in-process**, and every test in `test_mcp_client.py` uses it. That is a good
harness for the policy questions it asks -- which tools are bound, how a
hostile description is handled -- and it bypasses the transport entirely, so
the one thing it cannot test is the transport. The byte-cap test passes
because `_CappedStream` is exercised directly rather than through `httpx`.

And a name is only rejected by the *provider*, so no local test sees it.

What this file asserts
----------------------
A real `FastMCP` streamable-HTTP server on a loopback socket, reached with
**no `session_factory`**, so the request crosses `_CappedTransport` and the
real `httpx` client. Plus every bound name against the provider's own pattern.

Against the pre-fix tree the transport tests fail with `AssertionError` from
inside httpx, and the name test fails on the dots.
"""

from __future__ import annotations

import contextlib
import re
import socket
import threading
from typing import Any

import pytest

pytestmark = pytest.mark.anyio

#: What an OpenAI-compatible provider accepts as a function name. The dots in
#: `mcp.<server>.<tool>` are the whole defect.
FUNCTION_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def mcp_server():
    """A real MCP server over streamable HTTP, on its own loopback socket.

    Run in a thread with its own event loop rather than in-process, because
    the point is that the bytes cross a socket and a real `httpx` client.
    """
    fastmcp = pytest.importorskip("mcp.server.fastmcp", reason="mcp not installed")
    pytest.importorskip("uvicorn", reason="uvicorn not installed")
    from mcp.types import ToolAnnotations

    port = _free_port()
    server = fastmcp.FastMCP("fixpass", stateless_http=True)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    def lookup_host(hostname: str) -> dict[str, Any]:
        """Return a small record for one hostname."""
        return {"hostname": hostname, "seen": True}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    def enormous(hostname: str) -> str:
        """Return far more than any tenant would permit."""
        return "A" * 400_000

    app = server.streamable_http_app()

    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on")
    uvicorn_server = uvicorn.Server(config)

    thread = threading.Thread(target=uvicorn_server.run, daemon=True)
    thread.start()

    # Wait for the socket rather than sleeping a guessed interval.
    for _ in range(300):
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
            break
        import time

        time.sleep(0.1)
    else:  # pragma: no cover - startup guard
        pytest.fail(f"the MCP server did not bind 127.0.0.1:{port}")

    yield f"http://127.0.0.1:{port}/mcp"

    uvicorn_server.should_exit = True
    thread.join(timeout=10)


def _config(url: str, *, allowlist: tuple[str, ...], cap: int = 64_000):
    from app.mcp.config import McpServerConfig

    return McpServerConfig(
        name="fixpass",
        transport="streamable_http",
        url=url,
        tool_allowlist=list(allowlist),
        max_response_bytes=cap,
        timeout_seconds=10.0,
    )


@pytest.fixture(autouse=True)
def _permit_the_loopback_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """The SSRF guard refuses loopback unconditionally, and should.

    Measured: `validate_outbound_url` rejects `127.0.0.1` with and without
    `AISOC_SSRF_ALLOW_PRIVATE`, and rejects an RFC1918 address unless that
    variable is set. A test server has nowhere else to bind.

    This is **not** the boundary under test. The defect this file reproduces
    is in `_CappedStream` and `httpx`, two layers below the guard, and the
    guard's own behaviour is asserted in `test_mcp_client.py`. Neutralising it
    here buys access to the transport and nothing else.
    """
    from app.mcp import client as client_mod

    monkeypatch.setattr(client_mod, "validate_outbound_url", lambda url, **kw: url)


class TestTheTransportCarriesARealResponse:
    async def test_list_tools_works_over_a_real_connection(self, mcp_server) -> None:
        """No `session_factory`, so the bytes cross `_CappedTransport`.

        Pre-fix this raises `AssertionError` from `httpx/_client.py:1732`,
        because `_CappedStream` was not an `httpx.AsyncByteStream`.
        """
        from app.mcp.client import McpClient

        client = McpClient(_config(mcp_server, allowlist=("lookup_host",)))
        tools = await client.list_tools()

        names = [getattr(t, "name", None) for t in tools]
        assert "lookup_host" in names, f"the real transport returned no usable tool list: {names!r}"

    async def test_call_tool_works_over_a_real_connection(self, mcp_server) -> None:
        from app.mcp.client import McpClient

        client = McpClient(_config(mcp_server, allowlist=("lookup_host",)))
        result = await client.call_tool("lookup_host", {"hostname": "WS-42"})

        assert getattr(result, "isError", False) is not True, f"a real tool call errored: {result!r}"
        assert "WS-42" in str(result), f"the tool's own answer did not survive the transport: {result!r}"

    async def test_the_byte_cap_still_holds_over_a_real_connection(self, mcp_server) -> None:
        """The cap is the reason the wrapper exists, so it is asserted through
        the transport rather than by calling the wrapper directly.

        A fix that satisfied httpx by removing the cap would pass the two
        tests above and fail this one.
        """
        from app.mcp.client import McpClient, ResponseTooLarge

        client = McpClient(_config(mcp_server, allowlist=("enormous",), cap=4_096))

        with pytest.raises(ResponseTooLarge) as refusal:
            await client.call_tool("enormous", {"hostname": "WS-42"})

        assert "4096" in str(refusal.value), f"the refusal did not name the cap that caused it: {refusal.value}"


class TestEveryBoundNameIsCallable:
    def test_bound_tool_names_match_the_provider_pattern(self) -> None:
        """`mcp.<server>.<tool>` contains dots, which a provider rejects.

        Checked against the pattern rather than against a list of known-bad
        characters, because the pattern is what the provider actually applies.
        """
        from app.mcp import policy

        name = policy.namespaced("fixpass", "lookup_host")

        assert FUNCTION_NAME.match(name), f"{name!r} is not a callable function name; an OpenAI-compatible provider rejects it"

    def test_the_encoding_is_reversible(self) -> None:
        """A name the model calls has to resolve back to a server and a tool,
        or the loop cannot dispatch what the model asked for.

        `parse_namespaced` arrives with this fix, so against the pre-fix tree
        this fails on the missing symbol rather than on behaviour. The test
        above is the reproduction; this one pins the half the fix adds.
        """
        from app.mcp import policy

        name = policy.namespaced("fixpass", "lookup_host")
        server_id, tool = policy.parse_namespaced(name)

        assert (server_id, tool) == ("fixpass", "lookup_host")

    @pytest.mark.parametrize(
        ("server_id", "tool"),
        [
            ("with-hyphen", "lookup_host"),
            ("with_underscore", "get-thing"),
            ("a", "b"),
            ("server.with.dots", "tool.with.dots"),
        ],
    )
    def test_the_encoding_survives_awkward_identifiers(self, server_id: str, tool: str) -> None:
        """A server id is operator-supplied, so it can contain anything the
        config allows. Every one still has to produce a callable name."""
        from app.mcp import policy

        name = policy.namespaced(server_id, tool)

        assert FUNCTION_NAME.match(name), f"{name!r} is not callable"
        assert policy.parse_namespaced(name) == (server_id, tool)

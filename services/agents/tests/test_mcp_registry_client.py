"""The registry round trip, checked against the service that serves it.

Gap-closure Phase 5.2, agents half.

Two properties:

* the URL this service requests is one the API service actually serves,
  derived from the API's own source rather than restated here
* a registry that could not be asked reports "unknown", never "none"

The first is the defect D16 records. Phase 1.2 shipped a client that omitted
the ``/api/v1`` mount prefix, so every request would have 404'd, and three
green suites said nothing because the test asserted the URL the code produced
rather than the URL the service serves. The test below reads the API's router
and endpoint module with ``ast``, because this service cannot import that one:
both package their code as top-level ``app``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
from app.mcp.registry_client import API_PREFIX, fetch_servers, registry_url

REPO_ROOT = Path(__file__).resolve().parents[3]


def _router_prefix(tree: ast.Module, *, target: str) -> str:
    """The ``prefix=`` on ``<target> = APIRouter(...)``, or an empty string."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if not any(isinstance(t, ast.Name) and t.id == target for t in node.targets):
            continue
        func = node.value.func
        if not (isinstance(func, ast.Name) and func.id == "APIRouter"):
            continue
        for keyword in node.value.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                return str(keyword.value.value)
    return ""


def _mount_prefix(tree: ast.Module, *, mounted: str) -> str:
    """The ``prefix=`` on the ``include_router(<mounted>, ...)`` call."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "include_router"):
            continue
        if not (node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == mounted):
            continue
        for keyword in node.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                return str(keyword.value.value)
        return ""
    raise AssertionError(f"the API service does not mount {mounted!r} at all")


def _is_included(tree: ast.Module, *, module: str) -> bool:
    """Whether ``router.py`` actually includes ``<module>.router``."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "include_router"):
            continue
        arg = node.args[0] if node.args else None
        if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id == module and arg.attr == "router":
            return True
    return False


def _served_paths() -> set[str]:
    """Every path the API service serves from the MCP registry router.

    Composed the way the service composes it: the app mounts ``api_router``,
    ``api_router`` carries its own ``/api/v1`` prefix, and the endpoint
    module's router carries ``/mcp-servers``. Reading any one of the three and
    assuming the rest is how a URL ends up 404ing with a green test over it.
    """
    api = REPO_ROOT / "services" / "api" / "app" / "api" / "v1"

    main = ast.parse((REPO_ROOT / "services" / "api" / "app" / "main.py").read_text())
    router = ast.parse((api / "router.py").read_text())
    module = ast.parse((api / "endpoints" / "mcp_servers.py").read_text())

    assert _is_included(router, module="mcp_servers"), "the API's v1 router does not include the MCP registry router"

    app_prefix = _mount_prefix(main, mounted="api_router")
    v1_prefix = _router_prefix(router, target="api_router")
    module_prefix = _router_prefix(module, target="router")
    assert v1_prefix, "could not read the v1 router's own prefix out of the API service"

    routes: set[str] = {
        str(decorator.args[0].value)
        for node in ast.walk(module)
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr in {"get", "post", "patch", "delete"}
        and decorator.args
        and isinstance(decorator.args[0], ast.Constant)
        and isinstance(decorator.args[0].value, str)
    }
    assert routes, "could not read any route out of the MCP registry endpoint module"
    return {f"{app_prefix}{v1_prefix}{module_prefix}{route}" for route in routes}


def test_the_registry_url_matches_where_the_route_is_mounted() -> None:
    """Both directions, against the API service's own source.

    Proven against the pre-fix value: drop ``API_PREFIX`` from
    ``registry_url`` and this fails naming both the requested path and the
    served set.
    """
    served = _served_paths()
    assert f"{API_PREFIX}/mcp-servers/resolved" in served, (
        f"the agents service would request {API_PREFIX}/mcp-servers/resolved, and the API service serves {sorted(served)}"
    )

    requested = httpx.URL(registry_url("http://api:8000")).path
    assert requested in served


async def test_a_missing_service_token_is_named_and_nothing_is_requested(monkeypatch) -> None:
    """The API refuses the route without it, so a quiet zero would be a lie."""
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)

    def _explode(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request should be made without a service token")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_explode)) as client:
        fetched = await fetch_servers("tenant-a", client=client)

    assert fetched.ok is False
    assert fetched.servers == []
    assert "AISOC_AGENTS_SERVICE_TOKEN" in fetched.reason


async def test_an_unreachable_registry_is_unknown_not_empty(monkeypatch) -> None:
    """Zero servers and "could not ask" send an operator to different places."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "secret")

    def _fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_fail)) as client:
        fetched = await fetch_servers("tenant-a", client=client)

    assert fetched.ok is False
    assert fetched.servers == []
    assert "could not reach" in fetched.reason


async def test_a_refusal_carries_the_status_code(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "secret")

    def _refuse(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "nope"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_refuse)) as client:
        fetched = await fetch_servers("tenant-a", client=client)

    assert fetched.ok is False
    assert "401" in fetched.reason


async def test_the_tenant_and_token_travel_the_way_the_api_expects(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "secret")
    seen: dict[str, str] = {}

    def _ok(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["tenant"] = request.url.params.get("tenant_id", "")
        seen["token"] = request.headers.get("X-AiSOC-Service-Token", "")
        return httpx.Response(
            200,
            json={
                "tenant_id": "tenant-a",
                "servers": [
                    {
                        "name": "vendor",
                        "transport": "streamable_http",
                        "url": "https://mcp.vendor.example/mcp",
                        "auth": {"Authorization": "Bearer v"},
                        "tool_allowlist": ["get_host"],
                        "timeout_seconds": 11,
                        "max_response_bytes": 4096,
                    }
                ],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(_ok)) as client:
        fetched = await fetch_servers("tenant-a", client=client)

    assert seen["path"] == f"{API_PREFIX}/mcp-servers/resolved"
    assert seen["tenant"] == "tenant-a"
    assert seen["token"] == "secret"
    assert fetched.ok is True
    assert fetched.servers[0].name == "vendor"
    assert fetched.servers[0].tool_allowlist == ["get_host"]
    assert fetched.servers[0].timeout_seconds == 11.0
    assert fetched.servers[0].max_response_bytes == 4096
    assert fetched.servers[0].headers() == {"Authorization": "Bearer v"}


async def test_a_body_that_is_not_json_is_unknown_not_empty(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "secret")

    def _html(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>proxy error</html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_html)) as client:
        fetched = await fetch_servers("tenant-a", client=client)

    assert fetched.ok is False
    assert "not JSON" in fetched.reason


async def test_an_unavailable_registry_produces_no_tools_and_a_reason(monkeypatch) -> None:
    """The toolset says why rather than looking like a tenant with no servers."""
    from app.mcp.tools import build_mcp_toolset

    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
    toolset = await build_mcp_toolset("tenant-a")
    assert toolset.tools == []
    assert "AISOC_AGENTS_SERVICE_TOKEN" in toolset.registry_reason

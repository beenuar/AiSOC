"""Gap-closure Phase 4: the API half of the agent tool surface.

Three groups, and the third is here because of D16.

**The typed query refuses what it must.** Every indicator type is validated
against the shape it claims, and the refusal is a 422 with a reason rather
than an empty result, because a caller has to be able to tell "your query was
wrong" from "nothing matched": only one of those is evidence.

**The read door stays read-only.** Two independent checks, and both are
tested for, including the case where each alone would let something through.

**The URL the API builds is one the serving side serves.** Phase 1.2 shipped
a cross-service route whose client omitted the ``/api/v1`` prefix the
connectors service mounts under, so every request would have 404'd on every
deployment, and its unit test asserted the URL the *code* produced rather
than the URL the *service* serves, and passed. The tests at the bottom read
the other services' own source with ``ast`` and compare in the direction that
drifts.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path
from typing import Any

import pytest
from app.services.agent_tools import siem_search, vendor_reads
from app.services.agent_tools.indicators import (
    INDICATOR_TYPES,
    IndicatorTypeError,
    fields_for,
    validate_value,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


# ------------------------------------------------------- the typed vocabulary


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [
        ("ip", "203.0.113.9"),
        ("ip", "2001:db8::1"),
        ("domain", "evil.example.com"),
        ("url", "https://evil.example.com/a?b=c"),
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("hostname", "WS-42.corp.example.com"),
        ("username", "ACME\\svc_deploy"),
        ("process_name", "powershell.exe"),
    ],
)
def test_a_well_shaped_value_is_accepted(indicator_type: str, value: str) -> None:
    assert validate_value(indicator_type, value)


@pytest.mark.parametrize(
    ("indicator_type", "value", "because"),
    [
        ("ip", "203.0.113.999", "not an IP address"),
        ("ip", "not-an-ip", "not an IP address"),
        ("sha256", "a" * 63, "64 hexadecimal"),
        ("sha256", "z" * 64, "64 hexadecimal"),
        ("md5", "a" * 64, "32 hexadecimal"),
        ("domain", "not a domain", "not a DNS name"),
        ("domain", "evil", "not a DNS name"),
        ("url", "javascript:alert(1)", "must start with http"),
        ("url", "https://a/" + "x" * 3000, "payload rather than an indicator"),
        ("hostname", "WS-42 | delete", "shape of a hostname"),
        ("process_name", 'a" OR 1=1', "shape of a process_name"),
        ("username", "j.doe'; DROP TABLE", "shape of a username"),
        ("ip", "   ", "value is required"),
    ],
)
def test_a_wrongly_shaped_value_is_refused_with_a_reason(indicator_type: str, value: str, because: str) -> None:
    """Refused, never coerced.

    A coerced value produces a real query with a wrong answer, which is worse
    than a refusal: the refusal reaches the model as "could not check" and
    the wrong answer reaches it as evidence.
    """
    with pytest.raises(IndicatorTypeError) as exc:
        validate_value(indicator_type, value)
    assert because in str(exc.value)


def test_an_unknown_indicator_type_names_the_known_ones() -> None:
    with pytest.raises(IndicatorTypeError) as exc:
        validate_value("magic", "x")
    assert "not a searchable indicator type" in str(exc.value)
    assert "sha256" in str(exc.value)


def test_no_indicator_type_maps_to_a_field_name_that_is_not_an_identifier() -> None:
    """Every field token must survive the translators' own field check.

    The translators interpolate a field name unquoted, and
    ``Indicator.__post_init__`` refuses anything that is not an identifier.
    A mapping here that produced a refused token would 422 on every search
    for that indicator type, which would read to a model as the indicator
    being absent.
    """
    import re

    identifier = re.compile(r"^[A-Za-z_@][A-Za-z0-9_.@-]{0,199}$")
    for name, spec in INDICATOR_TYPES.items():
        for connector_type, tokens in spec.fields.items():
            assert tokens, f"{name} maps to no field on {connector_type}"
            assert len(tokens) <= 2, f"{name} on {connector_type} fans out to {len(tokens)} fields"
            for token in tokens:
                assert identifier.match(token), f"{name}/{connector_type} field {token!r} is not an identifier"


def test_every_indicator_type_covers_every_federated_backend() -> None:
    """A gap here is a silent coverage hole, so it is asserted rather than left.

    ``fields_for`` returning empty is handled (the source reports
    ``no_field_mapping``), but a type with no mapping anywhere would never
    search anything while looking like it searched.
    """
    from app.api.v1.endpoints.federated import FEDERATED_CAPABLE_TYPES

    for name in INDICATOR_TYPES:
        covered = {backend for backend in FEDERATED_CAPABLE_TYPES if fields_for(name, backend)}
        assert covered, f"{name} has no field mapping on any federated backend"


def test_an_unmapped_backend_yields_an_empty_tuple_rather_than_raising() -> None:
    assert fields_for("ip", "some_future_siem") == ()


# ------------------------------------------------------------ the read door


def test_the_agent_read_allowlist_holds_only_read_verbs() -> None:
    """Asserted against the contract file, not against a copy of the list.

    ``scripts/check_agent_read_tools.py`` enforces this in CI as well; this
    is here so it fails in the service's own suite too, where a contributor
    touching the allowlist is already running tests.
    """
    contracts = (REPO_ROOT / "services" / "actions" / "app" / "live_actions" / "capability_contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(contracts)
    read_only: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=True):
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str) and isinstance(value, ast.Call)):
                continue
            for keyword in value.keywords:
                if keyword.arg == "impact" and isinstance(keyword.value, ast.Attribute) and keyword.value.attr == "READ_ONLY":
                    read_only.add(key.value)
    assert read_only, "parsed no READ_ONLY contracts; the contract format has changed"
    assert vendor_reads.AGENT_READ_CAPABILITIES <= read_only


def test_every_exposed_verb_has_a_parameter_allowlist() -> None:
    assert set(vendor_reads.ALLOWED_PARAMS) == set(vendor_reads.AGENT_READ_CAPABILITIES)


def test_params_outside_the_allowlist_are_dropped_not_forwarded() -> None:
    """The credential bag is the reason this matters.

    ``params`` carries the decrypted ``auth_config`` by the time it reaches
    the actions service, so an unfiltered pass-through would let a caller
    supply ``cs_client_secret`` and have the read run against **their**
    CrowdStrike rather than the tenant's.
    """
    clean = vendor_reads._sanitise_params(
        "get_host",
        {
            "limit": 10,
            "cs_client_secret": "attacker-owned",
            "cs_base_url": "https://evil.example.com",
            "auth_config": {"okta_api_token": "t"},
            "dry_run": False,
            "tenant_id": str(uuid.uuid4()),
        },
    )
    assert clean == {"limit": 10}


def test_numeric_parameters_are_clamped_at_the_door() -> None:
    clean = vendor_reads._sanitise_params("get_user_activity", {"hours": 99_999, "limit": 10_000})
    assert clean == {"hours": 720, "limit": 50}
    clean = vendor_reads._sanitise_params("get_user_activity", {"hours": 0, "limit": -5})
    assert clean == {"hours": 1, "limit": 1}


def test_a_non_numeric_window_is_refused_rather_than_coerced() -> None:
    with pytest.raises(vendor_reads.VendorReadError):
        vendor_reads._sanitise_params("get_user_activity", {"hours": "all of them"})


@pytest.mark.asyncio
async def test_a_verb_outside_the_allowlist_never_reaches_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    async def _never(*args: Any, **kwargs: Any) -> Any:
        called.append(str(kwargs.get("capability")))
        raise AssertionError("dispatch was reached")

    monkeypatch.setattr(vendor_reads, "dispatch_step", _never)
    with pytest.raises(vendor_reads.VendorReadError) as exc:
        await vendor_reads.run_read(None, tenant_id=TENANT, capability="isolate_host", target="WS-42")  # type: ignore[arg-type]
    assert "not a read verb an investigation may call" in str(exc.value)
    assert not called


@pytest.mark.asyncio
async def test_a_verb_the_registry_stops_calling_read_only_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The second, independent check.

    The allowlist stops a new verb arriving by accident. This stops an
    existing verb whose classification changed from carrying on. Either alone
    would be a single point of failure on the one door in this product a
    model can open by emitting a sentence.
    """
    called: list[str] = []

    async def _never(*args: Any, **kwargs: Any) -> Any:
        called.append("dispatched")
        raise AssertionError("dispatch was reached")

    async def _registry() -> frozenset[str]:
        # get_host has been reclassified upstream and is no longer read-only.
        return frozenset({"get_detections"})

    monkeypatch.setattr(vendor_reads, "dispatch_step", _never)
    monkeypatch.setattr(vendor_reads.actions_client, "read_only_capabilities", _registry)

    with pytest.raises(vendor_reads.VendorReadError) as exc:
        await vendor_reads.run_read(None, tenant_id=TENANT, capability="get_host", target="WS-42")  # type: ignore[arg-type]
    assert "does not declare" in str(exc.value)
    assert "approval path" in str(exc.value)
    assert not called


@pytest.mark.asyncio
async def test_an_unreachable_registry_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusing a read is inconvenient. Allowing a containment is not."""

    async def _unreachable() -> frozenset[str]:
        raise vendor_reads.actions_client.ActionsServiceError("actions service unreachable")

    async def _never(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("dispatch was reached")

    monkeypatch.setattr(vendor_reads, "dispatch_step", _never)
    monkeypatch.setattr(vendor_reads.actions_client, "read_only_capabilities", _unreachable)

    with pytest.raises(vendor_reads.VendorReadError) as exc:
        await vendor_reads.run_read(None, tenant_id=TENANT, capability="get_host", target="WS-42")  # type: ignore[arg-type]
    assert "could not confirm" in str(exc.value)


def test_the_empty_impact_string_is_not_read_only() -> None:
    """A plugin verb with no contract publishes ``impact: ""``.

    Folding that into the read set would make an unclassified verb
    agent-reachable by omission, which is the most likely way this control
    gets bypassed: not by someone changing it, but by someone adding a verb
    and not adding a contract.
    """
    source = (REPO_ROOT / "services" / "api" / "app" / "services" / "actions_client.py").read_text(encoding="utf-8")
    # The comparison must be against the exact string, never a truthiness
    # check: `if entry.get("impact")` would admit any non-empty value.
    assert 'entry.get("impact") == "read_only"' in source


# --------------------------------------------- the caps, which bound the cost


def test_the_row_and_byte_caps_are_both_present_and_small() -> None:
    """A row cap alone is not a size cap.

    One Sentinel row carrying a base64 payload can be larger than forty
    ordinary ones, and a single tool result that fills the context window
    ends an investigation as surely as an error would.
    """
    assert siem_search.MAX_ROWS <= 50
    assert siem_search.MAX_RESULT_BYTES <= 32_000


def test_projection_keeps_signal_and_drops_bulk() -> None:
    row = {
        "_time": "2026-09-26T10:00:00Z",
        "host": "WS-42",
        "user": "svc_deploy",
        "process_name": "powershell.exe",
        "_raw": "x" * 20_000,
        "punct": "-//--",
        "linecount": "1",
        "_aisoc_source": {"connector_type": "splunk", "connector_name": "Prod"},
    }
    projected = siem_search._project(row)

    assert projected["host"] == "WS-42"
    assert projected["process_name"] == "powershell.exe"
    assert "_raw" not in projected
    assert "punct" not in projected
    # Which SIEM answered is evidence, not decoration: an indicator seen in
    # one source and not another is a different finding from one seen in both.
    assert projected["_source"] == "splunk"


def test_a_row_with_no_recognised_field_still_says_what_it_is_about() -> None:
    """An empty object would be worse than a few unrecognised keys."""
    projected = siem_search._project({"weird_vendor_col": "value", "another": "thing", "_aisoc_source": {"connector_type": "qradar"}})
    assert projected["weird_vendor_col"] == "value"
    assert projected["_source"] == "qradar"


# ------------------------------- the URLs, read off the serving side's source


def _module_router_prefix(module: Path) -> str:
    """The ``prefix=`` on the ``APIRouter(...)`` a module assigns to ``router``."""
    tree = ast.parse(module.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        if not (isinstance(func, ast.Name) and func.id == "APIRouter"):
            continue
        if "router" not in [t.id for t in node.targets if isinstance(t, ast.Name)]:
            continue
        for keyword in node.value.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                return str(keyword.value.value)
        return ""
    return ""


def _module_routes(module: Path) -> set[str]:
    """Route paths declared with ``@router.<verb>("...")`` in one module."""
    tree = ast.parse(module.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ("get", "post", "put", "patch", "delete"):
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "router":
            continue
        if not (node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            continue
        out.add(str(node.args[0].value))
    return out


def _served_paths(service: str, *, endpoint_module: str | None = None) -> set[str]:
    """Every path ``service`` serves for one endpoint module, from its own source.

    The D16 lesson. Phase 1.2's client omitted the ``/api/v1`` prefix the
    connectors service mounts under, so every request would have 404'd on
    every deployment, and the test covering it asserted the URL the *client*
    produced rather than the URL the *service* serves, and passed. This
    service cannot import the others (all of them package their code as a
    top-level ``app``), so reading the other tree's source is the only way to
    compare in the direction that drifts.

    Composes three prefixes, because the API's routes carry all three: the
    app-level mount in ``main.py``, the aggregate router's own prefix, and the
    endpoint module's ``APIRouter(prefix=...)``.
    """
    root = REPO_ROOT / "services" / service / "app"
    main = ast.parse((root / "main.py").read_text(encoding="utf-8"))

    # App-level mounts: `app.include_router(x, prefix="...")`.
    app_mounts: dict[str, str] = {}
    for node in ast.walk(main):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "include_router" or not node.args:
            continue
        target = node.args[0]
        name = target.id if isinstance(target, ast.Name) else ""
        prefix = ""
        for keyword in node.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                prefix = str(keyword.value.value)
        if name:
            app_mounts[name] = prefix

    # The aggregate router the endpoint modules are included into, and its own
    # prefix. `app.include_router(api_router)` carries no prefix of its own;
    # `api_router = APIRouter(prefix="/api/v1")` is where the segment lives,
    # which is exactly the level Phase 1.2's client skipped.
    aggregate_prefixes: set[str] = {""}
    for name, mount in app_mounts.items():
        candidate = root / "api" / "v1" / "router.py"
        if not candidate.is_file():
            continue
        for node in ast.walk(ast.parse(candidate.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            func = node.value.func
            if not (isinstance(func, ast.Name) and func.id == "APIRouter"):
                continue
            if name not in [t.id for t in node.targets if isinstance(t, ast.Name)]:
                continue
            for keyword in node.value.keywords:
                # The string check is on the constant's *value*, not just on
                # the node: `ast.Constant` also covers bytes and numbers, and
                # interpolating those would build a path nothing serves while
                # looking like it had read one.
                if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    aggregate_prefixes.add(f"{mount}{keyword.value.value}")

    served: set[str] = set()
    candidates = [root / "api" / "v1" / "endpoints" / f"{endpoint_module}.py"] if endpoint_module else sorted(root.rglob("*.py"))
    for module in candidates:
        if not module.is_file():
            continue
        module_prefix = _module_router_prefix(module)
        for route in _module_routes(module):
            for aggregate in aggregate_prefixes:
                served.add(f"{aggregate}{module_prefix}{route}")
            for mount in app_mounts.values():
                served.add(f"{mount}{module_prefix}{route}")
    if not served:
        raise AssertionError(f"parsed no routes for {service}/{endpoint_module}; this check would certify nothing")
    return served


def test_the_actions_discovery_url_this_service_builds_is_one_actions_serves() -> None:
    """``read_only_capabilities`` posts nowhere; it GETs the discovery route."""
    source = (REPO_ROOT / "services" / "api" / "app" / "services" / "actions_client.py").read_text(encoding="utf-8")
    assert '_get("/api/v1/live-actions")' in source
    served = _served_paths("actions", endpoint_module=None)
    assert "/api/v1/live-actions" in served, sorted(p for p in served if "live-actions" in p)


def test_actions_publishes_the_impact_field_this_service_reads() -> None:
    """The field has to exist on the serving side, not just be read here.

    ``read_only_capabilities`` filters on ``impact``. A descriptor without
    that field would make the filter match nothing, so every read would be
    refused as "not declared read-only" and an operator would be told their
    integration was misconfigured.
    """
    models = (REPO_ROOT / "services" / "actions" / "app" / "live_actions" / "models.py").read_text(encoding="utf-8")
    tree = ast.parse(models)
    fields: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "LiveActionDescriptor":
            for statement in node.body:
                if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    fields.add(statement.target.id)
    assert "impact" in fields, sorted(fields)

    # And it has to be *populated* from the contract, not left at its default.
    registry = (REPO_ROOT / "services" / "actions" / "app" / "live_actions" / "registry.py").read_text(encoding="utf-8")
    assert "impact=contract.impact.value" in registry


def test_the_agent_tool_routes_are_mounted_under_the_prefix_the_agent_calls() -> None:
    """The agents service builds ``/api/v1/agent-tools/...`` literals.

    Compared against what this service serves, derived from its own router
    wiring, in the direction that drifts: the client is in another repository
    tree and cannot be imported.
    """
    agent_source = (REPO_ROOT / "services" / "agents" / "app" / "tools" / "customer_tools.py").read_text(encoding="utf-8")
    requested = {
        "/api/v1/agent-tools/backends",
        "/api/v1/agent-tools/siem-search",
        "/api/v1/agent-tools/vendor-read",
    }
    for path in requested:
        assert path in agent_source, f"the agent no longer calls {path}; update this test or the route"

    served = _served_paths("api", endpoint_module="agent_tools")
    for path in requested:
        agent_tool_paths = sorted(p for p in served if "agent-tools" in p)
        assert path in served, f"the agent calls {path} and this service does not serve it. Served: {agent_tool_paths}"

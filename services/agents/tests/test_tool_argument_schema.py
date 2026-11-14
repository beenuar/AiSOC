"""Tool arguments are checked against the tool's own schema before it runs.

GHSA-4hxg-m5rw-gw3x, finding F36.

``ToolRegistry.execute`` resolved the tool, checked the agent's scope, and
then called ``tool.fn(**args)`` with whatever the model had produced. Every
tool ships a JSON schema — it is what ``bind_tools`` sends the provider, so
the schema exists and is already authoritative about what the arguments are —
and nothing compared the two.

What that costs, precisely
--------------------------
Python does not enforce annotations, so a wrong *type* reaches the body
untouched: a tool declaring ``indicator: str`` is handed a list, a dict or an
integer and runs on it. Where that value is interpolated into a query, a
vendor request or a lookup key, the tool's own reasoning about its input is
the only thing standing there — and the argument came from a model whose
context includes attacker-controlled alert text, which is the whole subject
of this advisory.

An *extra* argument did raise ``TypeError``, so the report's "the tool runs"
is half right. But it raised inside the call, after scope, and the error went
back to the model as a string — so the registry never knew the difference
between a tool that failed and a call that should never have been made.

Why the schema and not a signature check
-----------------------------------------
``inspect.signature`` would catch the extra argument and nothing else: it
cannot see that ``indicator`` must be a string, because the annotation is not
checked at runtime and half these tools take ``**kwargs``-ish shapes. The
schema is the contract already published to the model, so validating against
it closes the gap between what the model was told it may send and what the
registry accepts. Two definitions of a tool's arguments that nothing compares
is the drift this repository keeps finding.

The refusal is a structured error, not an exception, because the loop's
contract is that a tool failure reaches the model rather than aborting the
run — same shape as "unknown tool" and "outside the scope of agent".
"""

from __future__ import annotations

import time

import pytest
from app.security.agent_identity import AgentIdentity
from app.tools.registry import ToolRegistry
from app.tools.tool import Tool

ARGS_SEEN: list[dict] = []


def _record(**kwargs) -> dict:  # noqa: ANN003
    """A tool body that reports exactly what it was handed.

    The assertion that matters is not "an error came back" but "the body did
    not run", so the tool has to be able to say whether it did.
    """
    ARGS_SEEN.append(kwargs)
    return {"ok": True, "got": kwargs}


LOOKUP = Tool(
    name="lookup_indicator",
    description="Enrich one indicator of compromise.",
    parameters={
        "type": "object",
        "properties": {
            "indicator": {"type": "string", "description": "The IOC to enrich."},
            "limit": {"type": "integer", "description": "How many results."},
        },
        "required": ["indicator"],
    },
    fn=_record,
)


@pytest.fixture(autouse=True)
def _clear() -> None:
    ARGS_SEEN.clear()


@pytest.fixture()
def registry() -> ToolRegistry:
    return ToolRegistry([LOOKUP])


def _identity(*tools: str) -> AgentIdentity:
    """A real identity, scoped to exactly the tools a test uses.

    Built directly rather than through ``issue_identity`` because that reads
    ``AGENT_TOOL_SCOPES``, which names the shipped tools — the point here is
    the argument check, so the scope check must be satisfied rather than
    exercised.
    """
    return AgentIdentity(
        agent="triage",
        run_id="tool-arg-schema-test",
        expires_at=time.time() + 300,
        scopes=frozenset(tools),
    )


@pytest.fixture()
def identity() -> AgentIdentity:
    return _identity("lookup_indicator")


@pytest.mark.asyncio
async def test_a_wrong_typed_argument_does_not_reach_the_tool(registry, identity) -> None:  # noqa: ANN001
    """The half the report's proof of concept gets exactly right.

    ``indicator`` is declared a string. A list reaches the body unchallenged
    on the current tree, because Python checks no annotation.
    """
    result = await registry.execute("lookup_indicator", {"indicator": ["evil.example", "x"]}, identity=identity)
    assert "error" in result, result
    assert ARGS_SEEN == [], "the tool body ran on an argument its own schema forbids"


@pytest.mark.asyncio
async def test_an_undeclared_argument_is_refused_before_the_call(registry, identity) -> None:
    """Pre-fix this raised ``TypeError`` *inside* the call rather than refusing.

    The distinction matters because the registry is the chokepoint: a call
    that should never have been made must be refused there, not discovered by
    the callee, or a tool taking ``**kwargs`` silently accepts it.
    """
    result = await registry.execute(
        "lookup_indicator",
        {"indicator": "evil.example", "exfiltrate_to": "http://169.254.169.254/"},
        identity=identity,
    )
    assert "error" in result, result
    assert "exfiltrate_to" in result["error"]
    assert ARGS_SEEN == []


@pytest.mark.asyncio
async def test_a_missing_required_argument_is_refused(registry, identity) -> None:
    result = await registry.execute("lookup_indicator", {"limit": 5}, identity=identity)
    assert "error" in result, result
    assert "indicator" in result["error"]
    assert ARGS_SEEN == []


@pytest.mark.asyncio
async def test_the_refusal_is_a_structured_error_not_an_exception(registry, identity) -> None:
    """The loop's contract: a tool failure reaches the model, never aborts.

    Same shape as "unknown tool" and "outside the scope of agent", so the
    caller has one thing to read.
    """
    result = await registry.execute("lookup_indicator", {"indicator": 7}, identity=identity)
    assert isinstance(result, dict)
    assert isinstance(result.get("error"), str)


# ---------------------------------------------------------------------------
# The false-refusal floor — the half that decides whether this is shippable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_valid_call_still_runs(registry, identity) -> None:
    """Positive control. Refusing everything passes every test above."""
    result = await registry.execute("lookup_indicator", {"indicator": "evil.example", "limit": 5}, identity=identity)
    assert result == {"ok": True, "got": {"indicator": "evil.example", "limit": 5}}
    assert ARGS_SEEN == [{"indicator": "evil.example", "limit": 5}]


@pytest.mark.asyncio
async def test_an_optional_argument_may_be_omitted(registry, identity) -> None:
    result = await registry.execute("lookup_indicator", {"indicator": "evil.example"}, identity=identity)
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_a_tool_whose_schema_declares_no_properties_still_runs() -> None:
    """A schema that constrains nothing must not become a schema that refuses.

    Several shipped tools take no arguments at all. Reading an empty
    ``properties`` block as "nothing is permitted" would break every one of
    them, which is the shape of over-reach that gets a control switched off
    rather than fixed.
    """
    ping = Tool(name="ping", description="No arguments.", parameters={"type": "object"}, fn=_record)
    registry = ToolRegistry([ping])
    identity = _identity("ping")
    assert (await registry.execute("ping", {}, identity=identity))["ok"] is True


@pytest.mark.asyncio
async def test_every_shipped_tool_declares_a_schema_the_validator_can_read() -> None:
    """The gate's own precondition, asserted rather than assumed.

    If a shipped tool's ``parameters`` were malformed, validation would refuse
    every call to it and the only symptom would be an agent that quietly stops
    using one tool. Checked here against the real registry so adding a tool
    with a broken schema fails in this suite rather than in production.
    """
    from app.tools.registry import default_registry

    registry = default_registry(tenant_id="00000000-0000-0000-0000-000000000001")
    for name in registry.names():
        tool = registry._tools[name]
        assert isinstance(tool.parameters, dict), name
        assert tool.parameters.get("type") == "object", f"{name}: {tool.parameters!r}"
        properties = tool.parameters.get("properties", {})
        assert isinstance(properties, dict), name
        for required in tool.parameters.get("required", []):
            assert required in properties, f"{name} requires {required!r}, which it does not declare"

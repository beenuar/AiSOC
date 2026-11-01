"""Depth 2 Phase 1.1 reproduction, agents half: the model is never offered it.

``services/agents/app/tools/registry.py`` is what ``bind_tools`` ships to the
provider, so it is the list of things a model can *choose* to do. Six
effective-permission resolvers have shipped since T3.2 and none of them
appears here, which means no triage run has ever asked what an identity can
do — the same shape as ``run_with_tools``, a working ReAct loop that had no
production caller for three releases.

Fails on the pre-change tree for that reason; kept afterwards as the guard.
"""

from __future__ import annotations

from app.tools.registry import default_registry

TOOL_NAME = "identity_effective_permissions"


def test_registry_offers_the_effective_permission_tool() -> None:
    assert TOOL_NAME in default_registry(tenant_id="t1").names()


def test_the_tool_is_shipped_in_the_openai_schema_block() -> None:
    """Present in the registry but absent from the schemas is still unoffered.

    ``openai_schemas()`` is the exact payload the provider receives. Asserting
    on ``names()`` alone would pass against a tool that the binding step
    filtered out.
    """
    schemas = default_registry(tenant_id="t1").openai_schemas()
    named = {s["function"]["name"] for s in schemas}
    assert TOOL_NAME in named


def test_the_tool_takes_a_principal_and_a_point_in_time() -> None:
    """ "What can it do" and "what could it do when it acted" differ.

    An alert is triaged minutes to days after the event. A tool that cannot
    accept the event's timestamp can only answer the second question while
    appearing to answer the first, which is the failure mode the versioned
    posture table was built to prevent.
    """
    registry = default_registry(tenant_id="t1")
    schema = next(s for s in registry.openai_schemas() if s["function"]["name"] == TOOL_NAME)
    properties = schema["function"]["parameters"]["properties"]
    assert "principal_id" in properties
    assert "provider" in properties
    assert "at" in properties

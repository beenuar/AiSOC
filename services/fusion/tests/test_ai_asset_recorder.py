"""The AI-asset recorder: classification, coalescing, and the mirror.

Depth plan 6.1.

Every payload below is the shape ``services/ingest`` publishes — a
``NormalizedEvent`` envelope with ``ocsf_event`` inside — built from the field
maps in ``services/ingest/internal/normalizer/templates/ai-runtime.yaml`` and
``ai-finding.yaml`` rather than from the recorder's own expectations. A fixture
written from the thing under test proves only that it agrees with itself, and
the recurring defect here is a test double more capable than the real source.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from app.services.ai_asset_recorder import (
    ALL_KINDS,
    CODING_AGENT_PROCESSES,
    AiAssetRecorder,
    _score,
    _Sighting,
    classify,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

# The conftest's collection hook adds the asyncio marker too late for
# pytest-asyncio 1.x to see it, so the async cases below carry it explicitly.
# Explicit rather than the module-scope `pytestmark` the sibling suites use,
# because this file mixes sync and async cases and a module mark warns on
# every sync one.

TENANT = "11111111-1111-1111-1111-111111111111"


def runtime_event(**overrides: Any) -> dict[str, Any]:
    """An `ai-runtime` event as the normalizer emits it.

    Field placement follows `ai-runtime.yaml`: `agent_id` lands on
    `actor.process.name`, `on_behalf_of` on `actor.user.name`, `model` on
    `metadata.product.feature.name`, `server_name` on `resource.name`.
    """
    ocsf: dict[str, Any] = {
        "class_uid": 6003,
        "class_name": "API Activity",
        "source_type": "ai-runtime",
        "activity_name": "search_siem",
        "severity_id": 1,
        "actor": {"process": {"name": "agent-7f2", "path": "/usr/local/bin/claude"}, "user": {"name": "ada@example.com"}},
        "src_endpoint": {"hostname": "ada-mbp", "ip": "198.51.100.14"},
        "metadata": {"product": {"vendor_name": "AiSOC", "name": "AI Runtime", "feature": {"name": "claude-sonnet-4"}}},
        "cloud": {"provider": "anthropic"},
        "resource": {"name": "github-mcp"},
        "finding": {"evidence": {"prompt_tokens": 1200, "completion_tokens": 300}},
    }
    ocsf.update(overrides)
    return {"tenant_id": TENANT, "ocsf_event": ocsf}


def process_event(name: str, cmd_line: str = "", hostname: str = "ada-mbp") -> dict[str, Any]:
    """A process-activity event in the shape the endpoint connectors emit.

    `services/ingest` stores the connector's own normalized dict as a JSON
    string under `raw_data`, and the canonical OCSF field map carries almost
    nothing else — so `exe`, `process_name` and a command line live only
    here. An earlier version of this helper built a nested `process.name`
    instead, which no endpoint connector in this product produces; see
    `test_ai_endpoint_discovery.py` for the four real shapes.
    """
    payload: dict[str, Any] = {"source": "auditd", "syscall": "execve", "exe": name, "hostname": hostname, "actor": "ada@example.com"}
    if cmd_line:
        payload["cmdline"] = cmd_line
    return {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 1007,
            "class_name": "Process Activity",
            "source_type": "auditd",
            "raw_data": json.dumps(payload),
            "device": {"name": hostname},
            "actor": {"user": {"name": "ada@example.com"}},
        },
    }


def ocsf_native_process_event(name: str, hostname: str = "ada-mbp") -> dict[str, Any]:
    """The other shape: OCSF posted directly, with no connector payload.

    Kept as its own helper and its own case because both shapes reach this
    code and reading only one of them is the defect 6.2 reproduced.
    """
    return {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 1007,
            "class_name": "Process Activity",
            "process": {"name": name},
            "device": {"name": hostname},
        },
    }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def agentmetry_event(**overrides: Any) -> dict[str, Any]:
    """An ``agentmetry`` event as its inbox template emits it.

    Field placement follows ``agentmetry.yaml`` (Discussion #1577):
    ``agent.name`` lands on ``actor.process.name``, ``actor.id`` on
    ``actor.user.name``, ``host_id`` on ``src_endpoint.hostname`` and
    ``model.id`` on ``metadata.product.feature.name`` — the same slots the
    AI SDK templates use, which is what lets one recorder branch serve both.
    """
    ocsf: dict[str, Any] = {
        "class_uid": 6003,
        "class_name": "API Activity",
        "source_type": "agentmetry",
        "activity_name": "Read",
        "severity_id": 0,
        "actor": {"process": {"name": "claude"}, "user": {"name": "dev_01"}},
        "src_endpoint": {"hostname": "dev-mbp-7.local"},
        "metadata": {"product": {"vendor_name": "Agentmetry", "name": "Agentmetry", "feature": {"name": "claude"}}},
        "cloud": {"provider": "claude"},
    }
    ocsf.update(overrides)
    return {"tenant_id": TENANT, "ocsf_event": ocsf}


def test_agentmetry_event_yields_a_coding_agent_linked_to_person_and_device():
    # Discussion #1577: coding-agent telemetry pushed through the
    # agentmetry inbox template must reach the AI-estate inventory, or the
    # console stays blind to exactly the activity source the template adds.
    sightings = classify(agentmetry_event())
    agents = [s for s in sightings if s.kind == "coding_agent"]
    assert len(agents) == 1, f"want one coding agent, got {sightings}"
    agent = agents[0]
    assert agent.vendor == "Anthropic"
    assert agent.principal == "dev_01"
    assert agent.device == "dev-mbp-7.local"


def test_runtime_event_yields_a_coding_agent_linked_to_person_and_device():
    sightings = classify(runtime_event())
    agents = [s for s in sightings if s.kind == "coding_agent"]
    assert len(agents) == 1
    agent = agents[0]
    assert agent.external_id == "agent-7f2"
    assert agent.vendor == "Anthropic"
    assert agent.principal == "ada@example.com"
    assert agent.device == "ada-mbp"
    assert agent.attributes["models"] == ["claude-sonnet-4"]
    assert agent.attributes["tools"] == ["search_siem"]


def test_runtime_event_also_yields_the_mcp_server_it_called():
    kinds = {s.kind for s in classify(runtime_event())}
    assert "mcp_server" in kinds


def test_an_unrecognised_agent_binary_is_an_ai_app_not_a_coding_agent():
    """The honest answer, not the flattering one.

    An agent we cannot place is an `ai_app`. Calling it a coding agent would
    put a vendor name on a row we have no evidence for.
    """
    event = runtime_event(actor={"process": {"name": "svc-42", "path": "/opt/inhouse/summariser"}, "user": {"name": "ada@example.com"}})
    agents = [s for s in classify(event) if s.kind in ("coding_agent", "ai_app")]
    assert [s.kind for s in agents] == ["ai_app"]
    assert agents[0].vendor == "anthropic"


def test_process_activity_finds_a_coding_agent_with_a_device_and_no_model():
    """Endpoint discovery sees what runtime telemetry cannot, and vice versa.

    This is why `discovery_source` is stored: an analyst reading a row with no
    model needs to know whether it is missing or unknowable.
    """
    sightings = classify(process_event("/usr/local/bin/claude", "claude --resume"))
    assert len(sightings) == 1
    assert sightings[0].kind == "coding_agent"
    assert sightings[0].discovery_source == "endpoint"
    assert sightings[0].device == "ada-mbp"
    assert "models" not in sightings[0].attributes


def test_an_ocsf_native_process_event_is_read_too():
    sightings = classify(ocsf_native_process_event("/usr/local/bin/claude"))
    assert [s.kind for s in sightings] == ["coding_agent"]


@pytest.mark.parametrize("flag", ["--dangerously-skip-permissions", "--yolo", "--auto-approve", "--no-confirm"])
def test_permission_prompts_disabled_is_read_from_the_command_line(flag: str):
    sightings = classify(process_event("/usr/local/bin/claude", f"claude {flag} -p 'refactor'"))
    assert sightings[0].attributes["permission_prompts_disabled"] is True


def test_an_ordinary_process_is_not_an_ai_asset():
    """The negative control for the match table.

    A substring heuristic on "agent" would put every EDR sensor on the
    inventory, so the table is explicit and this asserts it stays that way.
    """
    assert classify(process_event("falcon-sensor")) == []
    assert classify(process_event("chrome")) == []


def test_a_process_name_that_is_not_class_1007_is_ignored():
    """A file event naming a binary is not evidence the binary ran."""
    event = process_event("claude")
    event["ocsf_event"]["class_uid"] = 1001
    assert classify(event) == []


def test_provider_audit_yields_a_key_with_no_device():
    event = {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 3001,
            "source_type": "llm_usage",
            "activity_name": "openai.api_key.created",
            "actor": {"user": {"name": "ada@example.com"}},
            "metadata": {"product": {"vendor_name": "OpenAI", "name": "AI / LLM Usage Audit"}},
            "finding": {"uid": "key_abc123"},
        },
    }
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["provider_key"]
    assert sightings[0].device is None
    assert sightings[0].discovery_source == "provider_audit"


def test_oauth_consent_yields_a_grant_with_its_scopes():
    event = {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 3001,
            "source_type": "llm_usage",
            "activity_name": "oauth.consent.granted",
            "actor": {"user": {"name": "ada@example.com"}},
            "metadata": {"product": {"vendor_name": "Google Workspace"}},
            "finding": {"uid": "notetaker.example", "evidence": {"scopes": ["https://mail.google.com/"]}},
        },
    }
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["oauth_grant"]
    assert sightings[0].attributes["scopes"] == ["https://mail.google.com/"]


def test_an_event_without_a_tenant_is_dropped_rather_than_guessed():
    event = runtime_event()
    event.pop("tenant_id")
    event["ocsf_event"].pop("tenant_uid", None)
    assert classify(event) == []


# ---------------------------------------------------------------------------
# Coalescing and the write
# ---------------------------------------------------------------------------


class _FakeConn:
    def __init__(self, sink: list[tuple]) -> None:
        self._sink = sink

    async def execute(self, _sql: str, *args: Any) -> None:
        self._sink.append(args)


class _FakePool:
    """A pool double that records the arguments it was asked to write.

    Deliberately records rather than answers: a double that returns a row for
    any query is how a table nobody writes passes its tests.
    """

    def __init__(self) -> None:
        self.writes: list[tuple] = []

    def acquire(self):  # noqa: ANN201
        sink = self.writes

        class _Ctx:
            async def __aenter__(self):  # noqa: ANN202
                return _FakeConn(sink)

            async def __aexit__(self, *_exc: Any) -> None:
                return None

        return _Ctx()


@pytest.mark.asyncio
async def test_chatty_agent_coalesces_into_one_row_per_flush():
    """Thirty tool calls must be one upsert, not thirty.

    Without this the recorder puts a database write on the hot path of every
    AI event in the deployment, to maintain a `last_seen_at` nobody reads at
    that resolution.
    """
    pool = _FakePool()
    recorder = AiAssetRecorder(lambda: pool)
    for i in range(30):
        await recorder.observe(runtime_event(activity_name=f"tool_{i % 3}"))
    written = await recorder.flush()

    # One coding agent + one MCP server.
    assert written == 2
    assert len(pool.writes) == 2
    counts = {row[1]: row[13] for row in pool.writes}
    assert counts["coding_agent"] == 30
    assert counts["mcp_server"] == 30


@pytest.mark.asyncio
async def test_coalescing_unions_tools_rather_than_overwriting_them():
    pool = _FakePool()
    recorder = AiAssetRecorder(lambda: pool)
    await recorder.observe(runtime_event(activity_name="search_siem"))
    await recorder.observe(runtime_event(activity_name="execute_command"))
    await recorder.flush()
    agent = next(row for row in pool.writes if row[1] == "coding_agent")
    assert '"execute_command"' in agent[8] and '"search_siem"' in agent[8]


@pytest.mark.asyncio
async def test_a_later_sighting_without_a_person_does_not_erase_one_with():
    """Merging keeps the link. The SQL keeps it too, via COALESCE."""
    pool = _FakePool()
    recorder = AiAssetRecorder(lambda: pool)
    await recorder.observe(runtime_event())
    anonymous = runtime_event(actor={"process": {"name": "agent-7f2", "path": "/usr/local/bin/claude"}})
    await recorder.observe(anonymous)
    await recorder.flush()
    agent = next(row for row in pool.writes if row[1] == "coding_agent")
    assert agent[6] == "ada@example.com"


@pytest.mark.asyncio
async def test_no_pool_drops_and_counts_rather_than_raising():
    """An inventory must never wedge alert promotion.

    The drop is counted and logged so a quiet inventory is diagnosable rather
    than mysterious — an empty page with no signal is the failure mode this
    avoids.
    """
    recorder = AiAssetRecorder(lambda: None)
    await recorder.observe(runtime_event())
    assert await recorder.flush() == 0
    assert recorder.metrics["dropped"] == 2


@pytest.mark.asyncio
async def test_a_failing_pool_is_survived():
    class _Exploding:
        def acquire(self):  # noqa: ANN201
            raise RuntimeError("connection refused")

    recorder = AiAssetRecorder(lambda: _Exploding())
    await recorder.observe(runtime_event())
    assert await recorder.flush() == 0
    assert recorder.metrics["dropped"] == 2


# ---------------------------------------------------------------------------
# The mirror
# ---------------------------------------------------------------------------


def test_recorder_kinds_match_the_api_models_vocabulary():
    """Two services, one meaning.

    `services/fusion` and `services/api` both package their code as a
    top-level `app` and cannot import each other, so the kind vocabulary is
    mirrored. A mirror nothing compares is just two copies that will drift,
    which is why this reads the other file rather than trusting the comment
    that says they match.
    """
    model = REPO_ROOT / "services/api/app/models/ai_asset.py"
    text = model.read_text(encoding="utf-8")
    for kind in ALL_KINDS:
        assert f'"{kind}"' in text, f"{kind} is in the recorder and not in the API model"


def test_risk_scoring_agrees_with_the_api_service_on_shared_cases():
    """The two risk implementations must return the same number.

    The console reads the stored score; the sanction route recomputes it.
    If they disagree, approving an asset changes its risk for a reason that
    is not the approval.
    """
    api_module = REPO_ROOT / "services/api/app/services/ai_inventory.py"
    spec = importlib.util.spec_from_file_location("_ai_inventory_mirror", api_module)
    assert spec and spec.loader
    mirror = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mirror)

    cases = [
        {"kind": "coding_agent", "principal": None, "device": None, "attributes": {}},
        {"kind": "coding_agent", "principal": "ada@example.com", "device": "mbp", "attributes": {"tools": ["execute_command"]}},
        {"kind": "provider_key", "principal": "ada@example.com", "device": None, "attributes": {}},
        {
            "kind": "oauth_grant",
            "principal": "ada@example.com",
            "device": None,
            "attributes": {"scopes": ["https://mail.google.com/"]},
        },
        {
            "kind": "coding_agent",
            "principal": "ada@example.com",
            "device": "mbp",
            "attributes": {"permission_prompts_disabled": True, "prompt_secret_kinds": ["aws_access_key"]},
        },
    ]
    for case in cases:
        sighting = _Sighting(
            tenant_id=TENANT,
            kind=case["kind"],
            external_id="x",
            device=case["device"],
            principal=case["principal"],
            attributes=dict(case["attributes"]),
        )
        fusion_score, fusion_reasons = _score(sighting)
        api_score, api_reasons = mirror.score_risk(
            kind=case["kind"],
            principal=case["principal"],
            device=case["device"],
            sanctioned=None,
            attributes=case["attributes"],
            effective_permissions=None,
        )
        assert fusion_score == api_score, case
        assert sorted(fusion_reasons) == sorted(api_reasons), case


def test_every_coding_agent_vendor_is_named():
    """A vendor of "" would render as a blank column that looks like data."""
    assert all(vendor for vendor in CODING_AGENT_PROCESSES.values())

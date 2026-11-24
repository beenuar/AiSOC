"""Session-scoped AI runtime rules, through the real ruleset and engine.

What a rule here counts as
--------------------------
Executable means: loaded from the committed `windowed_ruleset.json` by the
real loader, evaluated by the real `WindowedDetectionEngine`, over events
whose flat field names are exactly the keys the ai ingest templates map
(`ai-runtime.yaml` / `ai-finding.yaml` — `TestTemplateCoupling` pins that
by reading the YAML, so a renamed template key fails HERE rather than
silently never firing: the recorded aspirational-rule defect).

The three rules
---------------
* `wd-ai-session-untrusted-then-secret-then-egress`: inside ONE
  session, an injection/guardrail finding, then a prompt the SDK's local
  scanner flagged as secret-bearing, then an egress-capable tool call —
  ordered, one high finding. The negative fixture is the same three events
  across two sessions: it must NOT fire, because the session is the claim.
* `wd-ai-session-tool-call-flood`: per-session tool-call rate far
  above human-driven use.
* `wd-ai-identical-prompt-repetition`: the SDK hashes every prompt
  precisely so detection can ask "the same prompt fifty times?"
  (`redaction.py`'s own stated purpose) — and until now nothing consumed
  the hash. Grouped by the hash itself: cross-session repetition of one
  prompt is the signal, and the rule's name says that scoping out loud.

Session duration and token-burn-vs-baseline are deliberately NOT duplicated
here: `ai-agent-token-spend-anomaly` and the spend baselines already grade
token burn against the agent's own history, and a second rule would be a
second answer to the same question.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml
from app.services.windowed_detection import (
    WindowedDetectionEngine,
    load_sequence_rules,
    load_window_rules,
)

from tests.redis_doubles import FakeRedis

REPO = Path(__file__).resolve().parents[3]
RULESET = REPO / "services" / "fusion" / "app" / "data" / "windowed_ruleset.json"
RUNTIME_TEMPLATE = REPO / "services" / "ingest" / "internal" / "normalizer" / "templates" / "ai-runtime.yaml"
FINDING_TEMPLATE = REPO / "services" / "ingest" / "internal" / "normalizer" / "templates" / "ai-finding.yaml"

SEQ_ID = "wd-ai-session-untrusted-then-secret-then-egress"
FLOOD_ID = "wd-ai-session-tool-call-flood"
REPEAT_ID = "wd-ai-identical-prompt-repetition"


def _engine() -> WindowedDetectionEngine:
    rules = tuple(r for r in load_window_rules(RULESET) if r.id in (FLOOD_ID, REPEAT_ID))
    sequences = tuple(s for s in load_sequence_rules(RULESET) if s.id == SEQ_ID)
    assert len(rules) == 2 and len(sequences) == 1, "the committed ruleset no longer carries the AI-session rules by these ids"
    return WindowedDetectionEngine(FakeRedis(), rules=rules, sequences=sequences)


def _runtime_event(
    tenant: str,
    *,
    session: str,
    when: float,
    tool: str = "search_siem",
    prompt_sha: str | None = "a" * 64,
    secret_kinds: list[str] | None = None,
) -> dict[str, Any]:
    flat: dict[str, Any] = {
        "source_type": "ai-runtime",
        "session_id": session,
        "tool_name": tool,
        "event_time": when,
    }
    if prompt_sha is not None:
        flat["prompt_sha256"] = prompt_sha
    if secret_kinds is not None:
        flat["prompt_secret_kinds"] = secret_kinds
    return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps(flat)}}


def _finding_event(tenant: str, *, session: str, when: float, finding_type: str) -> dict[str, Any]:
    flat = {
        "source_type": "ai-finding",
        "session_id": session,
        "finding_type": finding_type,
        "event_time": when,
    }
    return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps(flat)}}


class TestTemplateCoupling:
    """Every flat field the three rules read is a key the ai templates map.

    This is the drift gate: a template rename that would orphan a rule fails
    here, by name, rather than as a rule that silently never fires again.
    """

    def test_rule_fields_are_template_keys(self) -> None:
        runtime_keys = set((yaml.safe_load(RUNTIME_TEMPLATE.read_text())["field_map"]).keys())
        finding_keys = set((yaml.safe_load(FINDING_TEMPLATE.read_text())["field_map"]).keys())
        doc = json.loads(RULESET.read_text())
        ours = [r for r in doc["rules"] if r["id"] in (SEQ_ID, FLOOD_ID, REPEAT_ID)]
        assert len(ours) == 3

        def _field(key: str) -> str:
            for suffix in ("_contains_any", "_has_any", "_neq", "_in"):
                if key.endswith(suffix):
                    return key[: -len(suffix)]
            return key

        for rule in ours:
            clauses: list[dict[str, Any]] = []
            if rule.get("match_when"):
                clauses.append(rule["match_when"])
            clauses.extend(rule.get("sequence") or [])
            for clause in clauses:
                for key in clause:
                    field = _field(key)
                    if field in ("source_type", "event_time"):
                        continue  # the normalizer's own envelope fields
                    assert field in runtime_keys | finding_keys, (
                        f"{rule['id']} reads {field!r}, which neither ai template maps — the rule can never fire on real events"
                    )
            assert rule.get("group_by") in runtime_keys | finding_keys, rule["id"]


class TestUntrustedThenSecretThenEgress:
    @pytest.mark.asyncio
    async def test_one_session_walking_the_chain_fires_once(self) -> None:
        engine = _engine()
        tenant = str(uuid4())
        session = "sess-1"
        assert not await engine.evaluate(_finding_event(tenant, session=session, when=1000.0, finding_type="prompt_injection"))
        assert not await engine.evaluate(
            _runtime_event(tenant, session=session, when=1060.0, tool="read_vault", secret_kinds=["aws_access_key"])
        )
        hits = await engine.evaluate(_runtime_event(tenant, session=session, when=1120.0, tool="http_post"))
        assert SEQ_ID in [h.rule_id for h in hits], "the chain inside one session must fire"

    @pytest.mark.asyncio
    async def test_the_same_events_across_two_sessions_do_not_fire(self) -> None:
        """The negative fixture the brief names: the session IS the claim."""
        engine = _engine()
        tenant = str(uuid4())
        assert not await engine.evaluate(_finding_event(tenant, session="sess-A", when=1000.0, finding_type="prompt_injection"))
        assert not await engine.evaluate(
            _runtime_event(tenant, session="sess-B", when=1060.0, tool="read_vault", secret_kinds=["github_token"])
        )
        hits = await engine.evaluate(_runtime_event(tenant, session="sess-B", when=1120.0, tool="send_email"))
        assert SEQ_ID not in [h.rule_id for h in hits], (
            "stage one happened in a different session; correlating across sessions would invent the chain the rule exists to prove"
        )

    @pytest.mark.asyncio
    async def test_out_of_order_does_not_fire(self) -> None:
        engine = _engine()
        tenant = str(uuid4())
        session = "sess-2"
        assert not await engine.evaluate(_runtime_event(tenant, session=session, when=1000.0, tool="http_post"))
        assert not await engine.evaluate(_runtime_event(tenant, session=session, when=1060.0, tool="read_vault", secret_kinds=["jwt"]))
        hits = await engine.evaluate(_finding_event(tenant, session=session, when=1120.0, finding_type="prompt_injection"))
        assert SEQ_ID not in [h.rule_id for h in hits], "egress before the injection is a different story"


class TestRunawaySession:
    @pytest.mark.asyncio
    async def test_the_flood_threshold_fires_per_session(self) -> None:
        engine = _engine()
        tenant = str(uuid4())
        fired: list[str] = []
        for n in range(120):
            hits = await engine.evaluate(
                _runtime_event(tenant, session="runaway", when=1000.0 + n, tool=f"tool_{n % 7}", prompt_sha=f"{n:064d}"[:64].rjust(64, "0"))
            )
            fired.extend(h.rule_id for h in hits)
        assert FLOOD_ID in fired

    @pytest.mark.asyncio
    async def test_two_calm_sessions_do_not_sum_into_a_flood(self) -> None:
        engine = _engine()
        tenant = str(uuid4())
        fired: list[str] = []
        for n in range(80):
            session = "calm-A" if n % 2 else "calm-B"
            hits = await engine.evaluate(_runtime_event(tenant, session=session, when=1000.0 + n, prompt_sha=f"{n:064x}".rjust(64, "0")))
            fired.extend(h.rule_id for h in hits)
        assert FLOOD_ID not in fired, "the rate is per session; two calm sessions are not one flood"

    @pytest.mark.asyncio
    async def test_the_same_prompt_fifty_times_fires_on_the_hash(self) -> None:
        """redaction.py hashes every prompt 'precisely so detection can ask:
        the same prompt fifty times?' — this is the asker."""
        engine = _engine()
        tenant = str(uuid4())
        sha = "f" * 64
        fired: list[str] = []
        for n in range(50):
            hits = await engine.evaluate(_runtime_event(tenant, session=f"sess-{n % 5}", when=1000.0 + n, prompt_sha=sha))
            fired.extend(h.rule_id for h in hits)
        assert REPEAT_ID in fired

    @pytest.mark.asyncio
    async def test_distinct_prompts_do_not_fire_repetition(self) -> None:
        engine = _engine()
        tenant = str(uuid4())
        fired: list[str] = []
        for n in range(60):
            hits = await engine.evaluate(
                _runtime_event(tenant, session="varied", when=1000.0 + n, prompt_sha=f"{n:064x}".rjust(64, "0")[:64])
            )
            fired.extend(h.rule_id for h in hits)
        assert REPEAT_ID not in fired

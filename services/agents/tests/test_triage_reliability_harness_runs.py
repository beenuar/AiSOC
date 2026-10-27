"""The reliability harness must actually run against the production prompt path.

`tests/test_triage_reliability_harness.py` at the repository root parses the
harness with `ast` and asserts on three configuration constants. Its reasoning
is sound and that file stays: it runs on a bare interpreter, in every
repository-level gate, and a test that skips when an import fails stops
running the day the environment changes.

What it cannot do is notice that the harness does not execute. It never
imports it, so `from app.agents.auto_triage_agent import _SYSTEM_PROMPT` — a
name that was removed when production moved to the versioned prompt registry —
raised `ImportError` on the first alert for as long as the registry has
existed, while all three parse-based assertions stayed green and the published
figures ("44 of 50", "50 of 50") stayed on the page.

So this file is the other half, and it lives here rather than beside that one
because `services/agents/tests/` is the suite CI installs the agents
`poetry.lock` for. It builds a real prompt through the real
`_build_alert_context`, the real prompt registry and the real envelope, and
classifies real model text through the real parser. No model is called: every
assertion here is about the harness reaching production code and agreeing with
it, which is the part that was broken and the part a transport failure hides.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[3]
HARNESS_PATH = REPO / "scripts" / "measure_triage_reliability.py"


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    """The harness, imported by path.

    `scripts/` is not a package and has no `__init__.py`, so this is the only
    way to reach it. Loaded once per module because executing it inserts
    `services/agents` on `sys.path`, which is idempotent but noisy.
    """
    if not HARNESS_PATH.exists():  # pragma: no cover - the file is tracked
        pytest.fail(f"the harness under test is not in this tree: {HARNESS_PATH}")
    spec = importlib.util.spec_from_file_location("measure_triage_reliability", HARNESS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def test_harness_builds_a_prompt_through_production(harness: ModuleType) -> None:
    """The failure this file exists for.

    On the pre-fix tree this raises `ImportError: cannot import name
    '_SYSTEM_PROMPT' from 'app.agents.auto_triage_agent'`, which is the whole
    of the defect: the harness could not reach its first model call.
    """
    alerts = harness._load_alerts(1)
    assert alerts, "the committed corpus yielded no alerts"

    messages = harness._build_messages(alerts[0])

    assert [m["role"] for m in messages] == ["system", "user"]
    assert messages[0]["content"].strip()
    assert messages[1]["content"].strip()


def test_system_prompt_is_the_registered_production_text(harness: ModuleType) -> None:
    """The system message must be the registry's `triage.system`, verbatim.

    A harness that restated the prompt would measure whether a copy agrees
    with itself. The registry is also where the version and hash come from, so
    a prompt edit moves the number this harness publishes *and* the provenance
    recorded beside it.
    """
    from app.llm.prompt_registry import prompt_text

    system = harness._build_messages(harness._load_alerts(1)[0])[0]["content"]

    assert system.startswith(prompt_text("triage.system"))


def test_user_message_is_the_production_alert_context(harness: ModuleType) -> None:
    """The user message must come from `_build_alert_context`, nonce included.

    The nonce is not decoration. `_build_alert_context` takes it as a
    keyword-only argument and uses it to fence retrieved runbooks, so a
    harness calling the old single-argument signature would not merely measure
    a different prompt — it would raise `TypeError`.
    """
    from app.agents.auto_triage_agent import _build_alert_context

    alert = harness._load_alerts(1)[0]
    messages = harness._build_messages(alert)
    state, nonce = harness._build_state(alert)

    assert messages[1]["content"] == _build_alert_context(state, nonce=nonce)


def test_system_prompt_carries_the_injection_fence(harness: ModuleType) -> None:
    """Production appends `system_rule(nonce)`; a harness without it is a different prompt."""
    from app.prompting.envelope import system_rule

    alert = harness._load_alerts(1)[0]
    system = harness._build_messages(alert)[0]["content"]
    _, nonce = harness._build_state(alert)

    assert system.endswith(system_rule(nonce))


def test_classify_runs_the_production_parser(harness: ModuleType) -> None:
    """Each outcome label must come from the production parser's real behaviour."""
    usable, _ = harness._classify('{"verdict": "false_positive", "confidence": 0.9, "rationale": "ok"}')
    assert usable == harness.OUTCOME_USABLE

    assert harness._classify("")[0] == harness.OUTCOME_EMPTY
    assert harness._classify("the model declined to answer")[0] == harness.OUTCOME_INVALID_JSON
    assert harness._classify('["not", "an", "object"]')[0] == harness.OUTCOME_NOT_OBJECT


def test_provenance_names_the_prompt_version_and_hash(harness: ModuleType) -> None:
    """A published number has to say which prompt produced it.

    The registry already pins `triage.system` to a version and a sha256, and a
    reliability figure that does not record them cannot be compared with the
    next one: a prompt edit is exactly the change that moves this measurement.
    """
    from app.llm.prompt_registry import _shipped

    registered = _shipped().get("triage.system")
    record = harness._prompt_provenance()

    assert record["name"] == "triage.system"
    assert record["version"] == registered.version
    assert record["sha256"] == registered.sha256

"""An analyst disposition writes a human-authored prior, under the right key.

Parity plan 2.3.

The half that shipped in v15.0.0 refuses to suppress on an AI-authored
prior. This is the half that had no implementation: nothing an analyst
could reach ever wrote a prior, so **every prior in the system was
AI-authored** and the refusal rule meant repeat suppression could not fire
on anything at all.

The key is the part worth testing hardest. A prior written under a key the
agents worker does not compute is a prior nothing ever looks up, and the
symptom is silence rather than an error. That has already shipped here
once: the fingerprint hashed the alert row id and the whole raw event, so
no two alerts ever matched and `repeat_alerts_suppressed` could only report
zero while its own test passed on a hardcoded signature.
"""

from __future__ import annotations

import inspect
import subprocess
import sys
from pathlib import Path

import pytest
from app._vendor.fingerprint import canonical_evidence, evidence_fingerprint
from app.services import human_priors

REPO_ROOT = Path(__file__).resolve().parents[3]


class _Alert:
    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestTheKeyMatchesTheAgentsWorker:
    def test_the_vendored_fingerprint_is_byte_identical_to_the_source(self) -> None:
        """Enforced here as well as in CI, because this is the property the
        whole mechanism rests on."""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/sync_vendored_fingerprint.py", "--check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_the_prefix_matches_the_agents_constant(self) -> None:
        source = (REPO_ROOT / "services/agents/app/memory/outcomes.py").read_text()
        assert 'OUTCOME_KEY_PREFIX = "outcome:"' in source, (
            "the agents service changed its key prefix and this service still writes "
            f"{human_priors.OUTCOME_KEY_PREFIX!r}, so priors would land where nothing looks"
        )
        assert human_priors.OUTCOME_KEY_PREFIX == "outcome:"

    def test_the_author_value_matches(self) -> None:
        source = (REPO_ROOT / "services/agents/app/memory/outcomes.py").read_text()
        assert 'HUMAN = "human"' in source
        assert human_priors.HUMAN == "human"


class TestTheFingerprintIsStableAcrossWhatShouldNotMatter:
    def test_two_alerts_with_the_same_evidence_share_a_key(self) -> None:
        a = _Alert(id="alert-1", rule_id="r-9", affected_host="HOST-A", severity="high")
        b = _Alert(id="alert-2", rule_id="r-9", affected_host="HOST-A", severity="high")
        assert evidence_fingerprint("t1", human_priors._alert_evidence(a)) == evidence_fingerprint("t1", human_priors._alert_evidence(b)), (
            "the alert row id leaked into the fingerprint, so no repeat can ever match"
        )

    def test_different_evidence_does_not(self) -> None:
        a = _Alert(id="x", rule_id="r-9", affected_host="HOST-A")
        b = _Alert(id="x", rule_id="r-9", affected_host="HOST-B")
        assert evidence_fingerprint("t1", human_priors._alert_evidence(a)) != evidence_fingerprint("t1", human_priors._alert_evidence(b)), (
            "two different hosts share a key, so a benign prior for one suppresses the other"
        )

    def test_tenants_do_not_share_a_key(self) -> None:
        alert = _Alert(id="x", rule_id="r-9", affected_host="HOST-A")
        evidence = human_priors._alert_evidence(alert)
        assert evidence_fingerprint("t1", evidence) != evidence_fingerprint("t2", evidence)

    def test_the_canonicaliser_is_what_decides_which_fields_count(self) -> None:
        """Not a hand-picked list here, which is how the two sides drift."""
        evidence = human_priors._alert_evidence(_Alert(id="x", rule_id="r-9", affected_host="HOST-A", created_at="now"))
        canonical = canonical_evidence(evidence)
        assert "rule_id" in canonical


class TestThePriorItWrites:
    def test_it_is_authored_human(self) -> None:
        source = inspect.getsource(human_priors.record_human_prior)
        assert '"author": HUMAN' in source
        assert '"confidence": 1.0' in source, "a human saying so is the strongest evidence this system has"

    def test_it_carries_author_source_scope_and_times(self) -> None:
        """The plan: every prior carries its author, source alert, scope and
        expiry. Expiry is enforced by the reader's TTL on `last_seen`."""
        source = inspect.getsource(human_priors.record_human_prior)
        for field in ('"author"', '"alert_id"', '"scope"', '"last_seen"', '"first_seen"'):
            assert field in source, f"the prior does not carry {field}"

    def test_a_write_failure_does_not_fail_the_analysts_request(self) -> None:
        source = inspect.getsource(human_priors.record_human_prior)
        assert "except Exception" in source
        assert "return None" in source

    def test_but_a_failure_is_logged_loudly_enough_to_notice(self) -> None:
        """A silently unwritten prior is a control that has stopped working
        and looks identical to one that is working."""
        source = inspect.getsource(human_priors.record_human_prior)
        assert "logger.warning" in source, "a swallowed failure logged at debug is invisible"


class TestTheWiring:
    def test_the_feedback_route_calls_it(self) -> None:
        """Otherwise this is another module with a passing test and no caller."""
        source = (REPO_ROOT / "services/api/app/api/v1/endpoints/feedback.py").read_text()
        assert "record_human_prior(" in source, (
            "no analyst-reachable route writes a human prior, so every prior in the system "
            "is still AI-authored and repeat suppression can never fire"
        )

    @pytest.mark.parametrize("argument", ["tenant_id=", "alert=", "disposition=", "analyst_id="])
    def test_it_is_called_with_what_it_needs(self, argument: str) -> None:
        source = (REPO_ROOT / "services/api/app/api/v1/endpoints/feedback.py").read_text()
        call = source[source.index("record_human_prior(") :][:400]
        assert argument in call

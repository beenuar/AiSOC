"""
Autonomy Guardrails — Unit Tests
=================================
Tier-1 capability 1.3 from the AiSOC capability roadmap (2026 H2): every action
the agent can take carries three confidence cutoffs (``auto``, ``review``,
``escalation``). This suite exercises the decision logic and the
defaults → YAML → DB override precedence model in
``services/agents/app/policy/guardrails.py``.

Run::

    pytest services/agents/tests/test_autonomy_guardrails.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.policy import (  # noqa: E402
    ActionResult,
    ActionThresholds,
    AutonomyDecision,
    DecisionResult,
    GuardrailPolicy,
    default_thresholds,
    reset_tenant_cache,
    reset_yaml_cache,
    yaml_thresholds,
)
from app.policy import guardrails as gmod  # noqa: E402


def _set_yaml_path(path: Path | None) -> None:
    """Set or clear the YAML override path env var, then bust the cache."""
    if path is None:
        os.environ.pop("AISOC_AUTONOMY_POLICY", None)
    else:
        os.environ["AISOC_AUTONOMY_POLICY"] = str(path)
    reset_yaml_cache()


class ActionThresholdsDecisionTest(unittest.TestCase):
    """Pure decision logic on a single ``ActionThresholds`` object."""

    def setUp(self) -> None:
        self.thresholds = ActionThresholds(auto=0.90, review=0.70, escalation=0.40)

    def test_auto_at_or_above_auto_floor(self) -> None:
        self.assertEqual(self.thresholds.decide(0.95), AutonomyDecision.AUTO)
        self.assertEqual(self.thresholds.decide(0.90), AutonomyDecision.AUTO)
        self.assertEqual(self.thresholds.decide(1.0), AutonomyDecision.AUTO)

    def test_review_band(self) -> None:
        self.assertEqual(self.thresholds.decide(0.89), AutonomyDecision.REVIEW)
        self.assertEqual(self.thresholds.decide(0.75), AutonomyDecision.REVIEW)
        self.assertEqual(self.thresholds.decide(0.70), AutonomyDecision.REVIEW)

    def test_escalate_band(self) -> None:
        self.assertEqual(self.thresholds.decide(0.69), AutonomyDecision.ESCALATE)
        self.assertEqual(self.thresholds.decide(0.55), AutonomyDecision.ESCALATE)
        self.assertEqual(self.thresholds.decide(0.40), AutonomyDecision.ESCALATE)

    def test_reject_below_escalation_floor(self) -> None:
        self.assertEqual(self.thresholds.decide(0.39), AutonomyDecision.REJECT)
        self.assertEqual(self.thresholds.decide(0.0), AutonomyDecision.REJECT)

    def test_to_dict_preserves_tiers(self) -> None:
        self.assertEqual(
            self.thresholds.to_dict(),
            {"auto": 0.90, "review": 0.70, "escalation": 0.40},
        )


class MakeThresholdsTest(unittest.TestCase):
    """``_make_thresholds`` should clamp + monotonically order tiers."""

    def test_scalar_only_derives_review_and_escalation(self) -> None:
        t = gmod._make_thresholds(0.90)
        self.assertEqual(t.auto, 0.90)
        # review = auto - 0.1, escalation = review - 0.2
        self.assertAlmostEqual(t.review, 0.80, places=6)
        self.assertAlmostEqual(t.escalation, 0.60, places=6)

    def test_scalar_at_zero_clamps_lower_tiers(self) -> None:
        t = gmod._make_thresholds(0.0)
        self.assertEqual((t.auto, t.review, t.escalation), (0.0, 0.0, 0.0))

    def test_explicit_three_tier(self) -> None:
        t = gmod._make_thresholds(0.92, 0.72, 0.45)
        self.assertEqual((t.auto, t.review, t.escalation), (0.92, 0.72, 0.45))

    def test_out_of_range_auto_clamped(self) -> None:
        t = gmod._make_thresholds(1.7, 1.5, 1.4)
        self.assertEqual(t.auto, 1.0)
        self.assertLessEqual(t.review, t.auto)
        self.assertLessEqual(t.escalation, t.review)

    def test_unordered_tiers_get_renormalised(self) -> None:
        # review > auto should get clamped down to auto
        t = gmod._make_thresholds(0.50, 0.90, 0.80)
        self.assertLessEqual(t.review, t.auto)
        self.assertLessEqual(t.escalation, t.review)

    def test_negative_values_clamped(self) -> None:
        t = gmod._make_thresholds(-0.5, -0.3, -0.2)
        self.assertEqual((t.auto, t.review, t.escalation), (0.0, 0.0, 0.0))


class DefaultPolicyTest(unittest.TestCase):
    """Hard-coded defaults match the documented blast-radius tiers."""

    def setUp(self) -> None:
        _set_yaml_path(None)

    def test_defaults_returned_as_copy(self) -> None:
        d1 = default_thresholds()
        d2 = default_thresholds()
        self.assertIsNot(d1, d2)
        self.assertEqual(d1.keys(), d2.keys())

    def test_read_actions_are_autonomous(self) -> None:
        defaults = default_thresholds()
        for action in (
            "lookup_ip",
            "lookup_domain",
            "search_logs",
            "enrich_alert",
            "mitre_lookup",
            "get_alert_context",
        ):
            with self.subTest(action=action):
                self.assertEqual(defaults[action].auto, 0.0)

    def test_containment_actions_require_high_confidence(self) -> None:
        defaults = default_thresholds()
        for action in (
            "block_ip",
            "isolate_host",
            "disable_user_account",
            "delete_object",
            "firewall_rule_add",
            "firewall_rule_remove",
        ):
            with self.subTest(action=action):
                self.assertGreaterEqual(defaults[action].auto, 0.85)
                self.assertLess(defaults[action].review, defaults[action].auto)
                self.assertLess(defaults[action].escalation, defaults[action].review)

    def test_unknown_action_rejects_by_default(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-test")
        decision = policy.decide("does_not_exist", confidence=0.99)
        self.assertEqual(decision.decision, AutonomyDecision.REJECT)
        self.assertEqual(decision.thresholds.auto, 1.0)


class YamlOverrideTest(unittest.TestCase):
    """Site-wide YAML overrides hard-coded defaults."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        _set_yaml_path(None)

    def tearDown(self) -> None:
        _set_yaml_path(None)

    def _write_policy(self, body: str) -> Path:
        path = Path(self.tmpdir.name) / "autonomy_policy.yaml"
        path.write_text(textwrap.dedent(body))
        _set_yaml_path(path)
        return path

    def test_scalar_form_sets_auto_only(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        self._write_policy(
            """
            version: 1
            thresholds:
              block_ip: 0.75
            """
        )
        loaded = yaml_thresholds()
        self.assertIn("block_ip", loaded)
        self.assertAlmostEqual(loaded["block_ip"].auto, 0.75, places=6)
        # review/escalation derived
        self.assertLess(loaded["block_ip"].review, loaded["block_ip"].auto)
        self.assertLess(loaded["block_ip"].escalation, loaded["block_ip"].review)

    def test_explicit_three_tier_form(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        self._write_policy(
            """
            version: 1
            thresholds:
              isolate_host:
                auto: 0.95
                review: 0.80
                escalation: 0.55
            """
        )
        loaded = yaml_thresholds()
        thresholds = loaded["isolate_host"]
        self.assertAlmostEqual(thresholds.auto, 0.95, places=6)
        self.assertAlmostEqual(thresholds.review, 0.80, places=6)
        self.assertAlmostEqual(thresholds.escalation, 0.55, places=6)

    def test_yaml_wins_over_defaults_in_policy(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        self._write_policy(
            """
            version: 1
            thresholds:
              block_ip:
                auto: 0.55
                review: 0.40
                escalation: 0.20
            """
        )
        policy = GuardrailPolicy.load_sync(tenant_id="t-yaml")
        ts = policy.get_thresholds("block_ip")
        self.assertAlmostEqual(ts.auto, 0.55, places=6)
        # confidence 0.60 should be AUTO under YAML override (was REVIEW under default 0.90)
        decision = policy.decide("block_ip", confidence=0.60)
        self.assertEqual(decision.decision, AutonomyDecision.AUTO)

    def test_legacy_auto_threshold_alias_accepted(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        self._write_policy(
            """
            version: 1
            thresholds:
              add_alert_tag:
                auto_threshold: 0.55
                analyst_review_threshold: 0.30
                escalation_threshold: 0.10
            """
        )
        loaded = yaml_thresholds()
        ts = loaded["add_alert_tag"]
        self.assertAlmostEqual(ts.auto, 0.55, places=6)
        self.assertAlmostEqual(ts.review, 0.30, places=6)
        self.assertAlmostEqual(ts.escalation, 0.10, places=6)

    def test_missing_yaml_file_falls_back_to_defaults(self) -> None:
        _set_yaml_path(Path(self.tmpdir.name) / "nonexistent.yaml")
        self.assertEqual(yaml_thresholds(), {})
        policy = GuardrailPolicy.load_sync(tenant_id="t-missing")
        # block_ip default auto = 0.90
        self.assertAlmostEqual(policy.get_threshold("block_ip"), 0.90, places=6)

    def test_malformed_yaml_does_not_crash(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        path = Path(self.tmpdir.name) / "broken.yaml"
        path.write_text("this is: : not :: valid yaml")
        _set_yaml_path(path)
        loaded = yaml_thresholds()
        self.assertEqual(loaded, {})

    def test_invalid_shape_logged_and_ignored(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        # ``thresholds`` not a dict — should be ignored
        self._write_policy(
            """
            version: 1
            thresholds:
              - block_ip
              - isolate_host
            """
        )
        self.assertEqual(yaml_thresholds(), {})

    def test_unknown_action_in_yaml_still_loaded(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        self._write_policy(
            """
            version: 1
            thresholds:
              custom_tenant_action: 0.42
            """
        )
        loaded = yaml_thresholds()
        self.assertIn("custom_tenant_action", loaded)
        self.assertAlmostEqual(loaded["custom_tenant_action"].auto, 0.42, places=6)


class ShippedPolicyFileTest(unittest.TestCase):
    """The actual ``services/agents/config/autonomy_policy.yaml`` shipped with
    AiSOC must parse cleanly and contain the documented action coverage."""

    def setUp(self) -> None:
        _set_yaml_path(None)
        self.policy_path = ROOT / "config" / "autonomy_policy.yaml"

    def tearDown(self) -> None:
        _set_yaml_path(None)

    def test_shipped_policy_file_exists_and_loads(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        if not self.policy_path.is_file():
            self.skipTest(f"policy file not present at {self.policy_path}")
        _set_yaml_path(self.policy_path)
        loaded = yaml_thresholds()
        self.assertGreater(len(loaded), 0, "expected actions in shipped policy")
        # Critical containment actions must be present
        for action in ("block_ip", "isolate_host", "disable_user_account"):
            self.assertIn(action, loaded, f"shipped policy missing {action}")

    def test_shipped_policy_containment_has_strict_floors(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        if not self.policy_path.is_file():
            self.skipTest(f"policy file not present at {self.policy_path}")
        _set_yaml_path(self.policy_path)
        loaded = yaml_thresholds()
        for action in ("block_ip", "isolate_host", "disable_user_account"):
            with self.subTest(action=action):
                self.assertGreaterEqual(loaded[action].auto, 0.85)


class GuardrailPolicyTest(unittest.TestCase):
    """End-to-end tests on ``GuardrailPolicy`` (sync loader, no DB)."""

    def setUp(self) -> None:
        _set_yaml_path(None)
        # bust any tenant cache the DB loader stamped on prior runs
        reset_tenant_cache()

    def test_load_sync_uses_defaults_and_yaml(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        # known default
        self.assertAlmostEqual(policy.get_threshold("block_ip"), 0.90, places=6)

    def test_decide_returns_decision_result(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        result = policy.decide("isolate_host", confidence=0.85)
        self.assertIsInstance(result, DecisionResult)
        # default isolate_host: auto 0.92 / review 0.72 / escalation 0.45 → REVIEW
        self.assertEqual(result.decision, AutonomyDecision.REVIEW)
        self.assertEqual(result.action, "isolate_host")
        self.assertEqual(result.confidence, 0.85)
        self.assertNotEqual(result.reason, "")

    def test_decide_auto_path_has_no_reason(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        result = policy.decide("isolate_host", confidence=0.99)
        self.assertEqual(result.decision, AutonomyDecision.AUTO)
        self.assertEqual(result.reason, "")

    def test_decide_escalate_band(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        # block_ip default 0.90 / 0.70 / 0.40
        result = policy.decide("block_ip", confidence=0.55)
        self.assertEqual(result.decision, AutonomyDecision.ESCALATE)
        self.assertIn("0.55", result.reason)

    def test_decide_reject_below_escalation_floor(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        result = policy.decide("block_ip", confidence=0.10)
        self.assertEqual(result.decision, AutonomyDecision.REJECT)
        self.assertIn("refusing", result.reason)

    def test_evaluate_backwards_compat_allowed_iff_auto(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")

        auto = policy.evaluate("block_ip", confidence=0.95)
        self.assertIsInstance(auto, ActionResult)
        self.assertTrue(auto.allowed)
        self.assertEqual(auto.threshold, policy.get_threshold("block_ip"))

        review = policy.evaluate("block_ip", confidence=0.75)
        self.assertFalse(review.allowed)

        escalate = policy.evaluate("block_ip", confidence=0.50)
        self.assertFalse(escalate.allowed)

        reject = policy.evaluate("block_ip", confidence=0.10)
        self.assertFalse(reject.allowed)

    def test_get_thresholds_returns_action_thresholds(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        ts = policy.get_thresholds("isolate_host")
        self.assertIsInstance(ts, ActionThresholds)
        self.assertGreaterEqual(ts.auto, ts.review)
        self.assertGreaterEqual(ts.review, ts.escalation)

    def test_all_thresholds_returns_independent_copy(self) -> None:
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        snap = policy.all_thresholds()
        snap["bogus_action"] = ActionThresholds(0.5, 0.3, 0.1)
        self.assertNotIn("bogus_action", policy.thresholds)

    def test_unknown_action_decision_is_reject(self) -> None:
        # Unknown actions get ActionThresholds(1.0, 1.0, 1.0), so anything
        # below perfect confidence rejects. We test slightly-below to confirm
        # the deny-by-default property; exactly 1.0 is a corner that, by
        # definition, only fires for perfectly calibrated outputs.
        policy = GuardrailPolicy.load_sync(tenant_id="t-1")
        result = policy.decide("totally_unknown", confidence=0.999)
        self.assertEqual(result.decision, AutonomyDecision.REJECT)
        self.assertEqual(result.thresholds.auto, 1.0)


class TenantCacheTest(unittest.TestCase):
    """Tenant override cache plumbing."""

    def test_reset_specific_tenant(self) -> None:
        gmod._TENANT_OVERRIDES["a"] = {"x": ActionThresholds(0.5, 0.3, 0.1)}
        gmod._TENANT_OVERRIDES["b"] = {}
        reset_tenant_cache("a")
        self.assertNotIn("a", gmod._TENANT_OVERRIDES)
        self.assertIn("b", gmod._TENANT_OVERRIDES)

    def test_reset_all_tenants(self) -> None:
        gmod._TENANT_OVERRIDES["a"] = {}
        gmod._TENANT_OVERRIDES["b"] = {}
        reset_tenant_cache()
        self.assertEqual(gmod._TENANT_OVERRIDES, {})


if __name__ == "__main__":
    unittest.main()

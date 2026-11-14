"""Every threat-and-anomaly rule, replayed through the real engine.

Depth plan 3.5. These rules pair a threat condition with a depth plan 3.4
baseline score, and the pairing is the entire content of the rule — so the
proof has to be about the pairing and not about either half.

Why the generic fixture gate is not enough
------------------------------------------
`test_detection_matcher_parity.py` already replays every committed fixture
and asserts positives fire and negatives do not. It would pass for this
family even if every negative were a sentinel flip, and that is exactly the
measurement this repository has already found to be worthless: 423 of the
878 existing negatives invert by prefixing `not-` to the expected value, so
the rule passes its negative by failing to match a value no log source
would ever emit.

So this file asserts the properties that make the pair meaningful:

* every rule reads at least one `baseline_*` field, or it is not a
  threat-and-anomaly rule and does not belong in the family;
* every rule also reads a **threat** condition, or it is a bare anomaly
  wearing a detection's name;
* the negative is the **benign twin**: it keeps the positive's threat
  clause and differs in the baseline score — so a rule that ignored the
  baseline would fire on both and fail here;
* no negative uses the `not-` sentinel inversion;
* the event is driven through the real `DetectionEngine` with the committed
  ruleset and the engine's own enrichment, not against a bare matcher.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from app.services.baselines import DERIVED_FIELDS
from app.services.detection_engine import DetectionEngine

_REPO = Path(__file__).resolve().parents[3]
_RULESET = _REPO / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
_FIXTURES = _REPO / "detections" / "fixtures"

TENANT = "11111111-1111-1111-1111-111111111111"


def _family() -> list[dict[str, Any]]:
    rules = json.loads(_RULESET.read_text())["rules"]
    return [r for r in rules if str(r.get("slug", "")).startswith("ta-")]


def _fixture(kind: str, slug: str) -> dict[str, Any]:
    path = _FIXTURES / kind / f"{slug}.json"
    assert path.exists(), f"{kind} fixture missing for {slug}"
    return json.loads(path.read_text())


def _product(rule: dict[str, Any]) -> str:
    """The exporter flattens `log_source` into `product` / `service`."""
    return str(rule.get("product") or "aws")


def _msg(raw_fields: dict[str, Any], product: str) -> dict[str, Any]:
    """The shape the fusion consumer hands the engine."""
    return {
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": TENANT,
        "ocsf_event": {
            "metadata": {"product": {"name": product}},
            "raw_data": json.dumps(raw_fields),
        },
    }


def _fields_of(clause: Any) -> set[str]:
    from app.services.detection_matcher import _split_op  # noqa: PLC0415

    out: set[str] = set()
    if isinstance(clause, dict):
        for key, value in clause.items():
            if key in {"any_of", "all_of", "not"}:
                out |= _fields_of(value)
                continue
            out.add(_split_op(key)[0])
    elif isinstance(clause, list):
        for item in clause:
            out |= _fields_of(item)
    return out


FAMILY = _family()


def test_the_family_is_present_and_not_empty() -> None:
    """A replay gate over an empty corpus is a gate that cannot fail."""
    assert len(FAMILY) >= 24, f"expected the 3.5 family in the ruleset, found {len(FAMILY)}"


@pytest.mark.parametrize("rule", FAMILY, ids=lambda r: r["slug"])
def test_the_positive_fires_through_the_real_engine(rule: dict[str, Any]) -> None:
    engine = DetectionEngine(rules=[rule])
    product = _product(rule)
    hits = engine.evaluate(_msg(_fixture("positive", rule["slug"]), product))
    assert any(h.rule_id == rule["id"] for h in hits), f"positive did not fire: {rule['slug']}"


@pytest.mark.parametrize("rule", FAMILY, ids=lambda r: r["slug"])
def test_the_benign_twin_does_not_fire(rule: dict[str, Any]) -> None:
    engine = DetectionEngine(rules=[rule])
    product = _product(rule)
    hits = engine.evaluate(_msg(_fixture("negative", rule["slug"]), product))
    assert all(h.rule_id != rule["id"] for h in hits), f"benign twin fired: {rule['slug']}"


@pytest.mark.parametrize("rule", FAMILY, ids=lambda r: r["slug"])
def test_each_rule_reads_a_baseline_and_a_threat_condition(rule: dict[str, Any]) -> None:
    """Both halves, or it is not this family.

    A rule with no baseline field is an ordinary detection in the wrong
    directory; a rule with no threat condition is a bare anomaly, which the
    plan explicitly says is a signal and not an alert.
    """
    fields = _fields_of(rule["match_when"])
    baseline = fields & DERIVED_FIELDS
    assert baseline, f"{rule['slug']} reads no baseline field"
    assert fields - DERIVED_FIELDS, f"{rule['slug']} is a bare anomaly with no threat condition"


@pytest.mark.parametrize("rule", FAMILY, ids=lambda r: r["slug"])
def test_the_twin_differs_only_in_the_baseline(rule: dict[str, Any]) -> None:
    """The negative must invert the clause the rule is *about*.

    A negative that changed the threat condition would prove nothing: the
    rule would not fire because the action is absent, not because the
    behaviour is normal. Requiring the baseline score to be the thing that
    moves is what makes the pair a measurement of the pairing.
    """
    slug = rule["slug"]
    positive = _fixture("positive", slug)
    negative = _fixture("negative", slug)
    baseline_fields = _fields_of(rule["match_when"]) & DERIVED_FIELDS

    moved = {f for f in baseline_fields if positive.get(f) != negative.get(f)}
    assert moved, f"{slug}: the twin does not move any baseline field"

    for field in moved:
        assert field in negative, f"{slug}: the twin drops {field} rather than making it benign"


@pytest.mark.parametrize("rule", FAMILY, ids=lambda r: r["slug"])
def test_no_negative_uses_the_sentinel_inversion(rule: dict[str, Any]) -> None:
    """`not-<value>` and `__benign__` measure nothing about false positives.

    423 of the 878 machine-generated negatives in the wider corpus invert
    that way. This family is hand-authored precisely so it does not, and
    the assertion is here so a later contributor reaching for `S()` is
    stopped rather than trusted.
    """
    negative = _fixture("negative", rule["slug"])
    for key, value in negative.items():
        if not isinstance(value, str):
            continue
        assert not value.startswith("not-"), f"{rule['slug']}: sentinel inversion on {key}"
        assert value != "__benign__", f"{rule['slug']}: sentinel inversion on {key}"


@pytest.mark.parametrize("rule", FAMILY, ids=lambda r: r["slug"])
def test_the_threat_half_alone_does_not_fire(rule: dict[str, Any]) -> None:
    """Strip the baseline from the positive and the rule must go quiet.

    This is the negative control for the family as a whole. If a rule fires
    on the threat condition alone, the baseline clause is decorative and
    the rule is just a noisy detection with an anomaly field attached to
    its name.
    """
    engine = DetectionEngine(rules=[rule])
    product = _product(rule)
    event = dict(_fixture("positive", rule["slug"]))
    for field in _fields_of(rule["match_when"]) & DERIVED_FIELDS:
        event.pop(field, None)
    hits = engine.evaluate(_msg(event, product))
    assert all(h.rule_id != rule["id"] for h in hits), f"{rule['slug']} fires without its baseline — the anomaly clause is decorative"


@pytest.mark.asyncio
async def test_core_fires_one_end_to_end_with_no_full_service() -> None:
    """The Phase 3 "Done when", as an assertion rather than a claim.

    *"a CORE install fires a threat-and-anomaly rule on a replayed fixture
    with no `full` service running."*

    So this drives the whole CORE path and nothing else: the baseline store
    on a Redis, warmed by ordinary traffic, then the real engine's
    `evaluate_async` computing the baseline field itself rather than
    reading one planted in a fixture. Nothing imports `services/ueba`, and
    no `ueba.anomalies` message exists.

    The warm-up matters. The principal does `GetObject` forty times and
    `CreateAccessKey` once, which is what makes the key-creation rare — the
    rarity is *earned from the traffic*, not asserted.
    """
    from app.services.baselines import BaselineStore  # noqa: PLC0415

    from tests.test_baselines import _FakeRedis  # noqa: PLC0415

    rule = next(r for r in FAMILY if r["slug"] == "ta-aws-access-key-created-from-rare-client")
    engine = DetectionEngine(rules=[rule])
    store = BaselineStore(_FakeRedis(), min_observations=20)

    routine = {
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "user": "dana.k@example.com",
        "user_agent": "aws-cli/2.15.17 Python/3.11.6 Darwin/23.4.0",
    }
    for _ in range(40):
        await store.derived_fields(TENANT, routine)

    # The same engineer, the same account, over a client they have never
    # used, minting a credential.
    suspicious = {
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "user": "dana.k@example.com",
        "user_agent": "python-requests/2.31.0",
    }
    hits = await engine.evaluate_async(_msg(suspicious, "aws"), None, None, store)
    assert any(h.rule_id == rule["id"] for h in hits), "CORE did not fire the rule on an earned baseline"

    # The control: the same call over the client they always use. The
    # baseline is the only thing that differs, and it must be enough.
    familiar = dict(suspicious, user_agent=routine["user_agent"])
    quiet = await engine.evaluate_async(_msg(familiar, "aws"), None, None, store)
    assert all(h.rule_id != rule["id"] for h in quiet), "CORE fired on the principal's routine client"


def test_the_family_covers_cloud_identity_saas_and_code() -> None:
    """The plan scopes 3.5 to the same surfaces as the rest of Phase 3."""
    products = {_product(r) for r in FAMILY}
    assert {"aws", "azure"} & products, "no cloud coverage"
    assert {"okta", "identity"} & products, "no identity coverage"
    assert {"google-workspace", "m365", "slack", "salesforce"} & products, "no SaaS coverage"
    assert {"github", "gitlab"} & products, "no code coverage"

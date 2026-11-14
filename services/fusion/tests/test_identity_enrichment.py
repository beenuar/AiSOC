"""The `*_priv` booleans, driven through the real engine.

18 rules read one of these and nothing computed any of them, so each read
`None` on that clause and could never fire. The assertions that matter are
not "the helper returns True"; they are:

* a rule reading `user_priv: true` **fires** when the tenant has imported
  that principal as privileged, and **does not** when it has not;
* an unknown subject produces **no key**, never `False`, because `False` is a
  confident statement that the account is ordinary and would be wrong for
  every tenant that has imported nothing;
* one tenant's administrators are not another's.

The last one is the reason this lives on the per-tenant overlay rather than
in the shared derived-field pass.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

from app.services.detection_engine import DetectionEngine
from app.services.tenant_overlay import IDENTITY_FIELDS, TenantOverlay, build_overlay, identity_fields

_REPO = Path(__file__).resolve().parents[3]


def _overlay(*, principals: tuple[str, ...] = (), roles: tuple[str, ...] = ()) -> TenantOverlay:
    rows = [{"node_type": "human_user", "external_id": p} for p in principals]
    rows += [{"node_type": "role", "external_id": r} for r in roles]
    return build_overlay("t-1", [], identities=rows, now=0.0)


def _event(**fields: Any) -> dict[str, Any]:
    return {"tenant_id": "t-1", "ocsf_event": {"tenant_uid": "t-1", "raw_data": json.dumps(fields)}}


RULE = {
    "id": "det-test-priv",
    "slug": "test-priv",
    "name": "Privileged user signed in from an anonymising VPN",
    "severity": "high",
    "category": "identity",
    "mitre": [],
    "match_when": {"event_type": "auth_success", "user_priv": True},
}


def test_the_rule_fires_only_for_a_privileged_principal() -> None:
    engine = DetectionEngine([RULE])
    privileged = _overlay(principals=("ceo@example.com",))

    hits = engine.evaluate(_event(event_type="auth_success", user="ceo@example.com"), privileged)
    assert [h.rule_id for h in hits] == ["det-test-priv"]

    assert not engine.evaluate(_event(event_type="auth_success", user="intern@example.com"), privileged)


def test_without_an_overlay_the_rule_stays_silent() -> None:
    """A tenant that has imported no directory gets no keys, not `False`.

    This is the difference between "we do not know" and "this account is
    ordinary", and the second would be asserted about every account on every
    deployment that never imported anything.
    """
    engine = DetectionEngine([RULE])
    assert not engine.evaluate(_event(event_type="auth_success", user="ceo@example.com"))
    assert not engine.evaluate(_event(event_type="auth_success", user="ceo@example.com"), _overlay())


def test_an_unknown_subject_produces_no_key() -> None:
    derived = identity_fields(frozenset({"ceo@example.com"}), frozenset(), {"user": "intern@example.com"})
    assert derived == {"user_priv": False, "actor_role_priv": False, "actor_is_admin": False}

    assert identity_fields(frozenset({"ceo@example.com"}), frozenset(), {"event_type": "auth_success"}) == {}


def test_one_tenants_administrators_are_not_anothers() -> None:
    engine = DetectionEngine([RULE])
    event = _event(event_type="auth_success", user="ceo@example.com")
    assert engine.evaluate(event, _overlay(principals=("ceo@example.com",)))
    assert not engine.evaluate(event, _overlay(principals=("someone-else@example.com",)))


def test_the_subject_is_matched_case_insensitively() -> None:
    """Directories and audit logs disagree about case on the same address."""
    derived = identity_fields(frozenset({"ceo@example.com"}), frozenset(), {"user": "CEO@Example.com"})
    assert derived["user_priv"] is True


def test_roles_and_principals_are_separate_sets() -> None:
    """A role named like a user must not make that user privileged."""
    derived = identity_fields(frozenset(), frozenset({"global-admin"}), {"user": "global-admin", "role": "global-admin"})
    assert derived["role_priv"] is True
    assert "user_priv" not in derived


def test_the_reachability_gate_mirrors_this_module() -> None:
    """The gate names these booleans; a new one must be added in both places.

    The operator list in the same gate had drifted exactly this way — `neq`
    was added to the matcher and not to the gate, so five rules the engine
    reads correctly were reported unreachable for four months. Asserting in
    both directions is the cheap half of not repeating it.
    """
    spec = importlib.util.spec_from_file_location("cdf_identity", _REPO / "scripts" / "check_detection_fields.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    assert gate._TENANT_DERIVED_FIELDS == frozenset(IDENTITY_FIELDS), (
        "scripts/check_detection_fields.py and tenant_overlay.IDENTITY_FIELDS disagree about which privilege booleans the platform computes"
    )


def test_the_gate_and_the_matcher_agree_on_every_operator() -> None:
    """Both directions. One direction is how `neq` went missing for months."""
    spec = importlib.util.spec_from_file_location("cdf_ops", _REPO / "scripts" / "check_detection_fields.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    from app.services.detection_matcher import OPERATORS  # noqa: PLC0415

    matcher_suffixes = {suffix.lstrip("_") for suffix, _name, _sql in OPERATORS}
    gate_suffixes = set(gate._OPERATOR_SUFFIXES)
    assert gate_suffixes == matcher_suffixes, (
        f"only in the gate: {sorted(gate_suffixes - matcher_suffixes)}; only in the matcher: {sorted(matcher_suffixes - gate_suffixes)}"
    )

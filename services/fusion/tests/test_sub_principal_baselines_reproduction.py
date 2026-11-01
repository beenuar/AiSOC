"""Depth 2 Phase 1.4 reproduction: only the human has a baseline of its own.

`baselines.py` keeps a rarity and volume baseline per *principal*, plus one
volume baseline per OAuth application. Everything else that acts on a
person's behalf — a personal access token, a service account, an AI agent —
is folded into the human's baseline, which is exactly backwards for the case
these baselines exist to catch: a stolen token acts *as* the user, so the
user's own numbers stay normal while the token's do not.

Four signals the plan names, none of which can be computed today:

* a token or app acting outside its **own** baseline;
* a scheduled token or bot identity suddenly interactive;
* a token used from a new ASN within minutes of its creation;
* a token idle for 60 days or more that reactivates.

Fails on the pre-change tree for those reasons. Kept afterwards as the
guard, including the cross-language fixture: the GitHub join key is produced
by Go and consumed by Python, and the two normalise differently by default.
"""

from __future__ import annotations

import pytest


def test_sub_principal_kinds_are_declared() -> None:
    from app.services.baselines import SUB_PRINCIPAL_KINDS

    assert {"oauth_app", "api_token", "service_account", "ai_agent"} <= set(SUB_PRINCIPAL_KINDS)


def test_the_four_signals_are_derived_fields() -> None:
    """A signal absent from DERIVED_FIELDS reaches no rule and no alert.

    `services/fusion/app/services/derived_fields.py` and the detection
    matcher both read that set, so a field computed and not declared is a
    number nothing can clause on.
    """
    from app.services.baselines import DERIVED_FIELDS

    required = {
        "baseline_sub_principal_rarity",
        "baseline_sub_principal_volume_z",
        "baseline_token_cadence_shift",
        "baseline_token_reactivated_after_idle",
        "baseline_token_new_asn_after_creation",
    }
    assert required <= DERIVED_FIELDS, f"missing: {sorted(required - DERIVED_FIELDS)}"


def test_a_token_is_resolved_as_its_own_subject() -> None:
    """The token, not the human it acts for, is what the baseline is held on."""
    from app.services.baselines import resolve_sub_principal

    event = {
        "connector_type": "github",
        "actor": "alice",
        # What `session.go` wrote. The consumer reads this and never the
        # vendor field it came from, so there is only ever one derivation.
        "activity": {"session": {"key": "AbC123+/xyz=", "key_kind": "vendor_credential"}},
    }
    subject = resolve_sub_principal(event)
    assert subject is not None
    assert subject.kind == "api_token"
    assert subject.id == "AbC123+/xyz="


def test_the_token_identity_comes_from_the_projection_not_the_vendor_field() -> None:
    """One producer, many consumers — the property ADR-0010 turns on.

    An earlier cut of this resolver read GitHub's `hashed_token` itself and
    pinned its normalisation against the Go side byte for byte. That passes
    and is still the wrong design: it is a *second* derivation of a session
    key, and two derivations agree until the next vendor-schema change and
    then disagree silently, leaving Postgres, the lake and the graph holding
    different answers to "which session was this".
    `scripts/check_session_projection.py` refuses it.

    So the vendor field alone resolves nothing here, and the projection is
    what the subject is keyed on.
    """
    from app.services.baselines import resolve_sub_principal

    mixed = "AbC123+/xyz="

    from_vendor_field = resolve_sub_principal({"connector_type": "github", "hashed_token": mixed})
    assert from_vendor_field is None, "the consumer must not re-derive the session key from the vendor field"

    from_projection = resolve_sub_principal(
        {"connector_type": "github", "activity": {"session": {"key": f"  {mixed}  ", "key_kind": "vendor_credential"}}}
    )
    assert from_projection is not None
    assert from_projection.id == mixed, "case must survive: the key is a digest, not a name"


def test_a_vendor_session_id_is_not_a_token_identity() -> None:
    """Keying a token baseline on a session id would merge every token used
    in that session into one subject."""
    from app.services.baselines import resolve_sub_principal

    subject = resolve_sub_principal({"connector_type": "okta", "activity": {"session": {"key": "sess-1", "key_kind": "vendor_session"}}})
    assert subject is None


@pytest.mark.parametrize(
    ("hours", "expected"),
    [
        # Even intervals around the clock with low variance: a cron job.
        ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], "scheduled"),
        # Dense bursts inside a working day: a person at a keyboard.
        ([9, 9, 9, 10, 10, 11, 14, 15, 16, 16, 17], "interactive"),
    ],
)
def test_tokens_are_classified_by_cadence(hours: list[int], expected: str) -> None:
    from app.services.baselines import classify_cadence

    assert classify_cadence(hours) == expected


def test_cadence_is_unknown_below_the_sample_floor() -> None:
    """Three calls do not establish a rhythm.

    Returning `scripted` for a token nobody has watched yet would make the
    "a scheduled token turned interactive" signal fire on the fourth call of
    every new token in the estate.
    """
    from app.services.baselines import classify_cadence

    assert classify_cadence([9, 10, 11]) == "unknown"

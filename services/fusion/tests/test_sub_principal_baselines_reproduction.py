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
        "hashed_token": "AbC123+/xyz=",
    }
    subject = resolve_sub_principal(event)
    assert subject is not None
    assert subject.kind == "api_token"
    assert subject.id == "AbC123+/xyz="


def test_the_github_join_key_is_byte_identical_to_the_go_side() -> None:
    """The cross-language contract, and the trap inside it.

    `services/ingest/internal/activity/session.go` reads `hashed_token` with
    `strings.TrimSpace` and **no case folding**, because the value is a
    base64-ish digest and case is significant. Every other field this module
    resolves goes through `_first_present`, which lowercases — so routing the
    token through the usual helper would produce a key that never joins to
    the session the Go side wrote, on every GitHub event, silently.
    """
    from app.services.baselines import resolve_sub_principal

    mixed = "AbC123+/xyz="
    subject = resolve_sub_principal({"connector_type": "github", "hashed_token": f"  {mixed}  "})
    assert subject is not None
    assert subject.id == mixed, "the token key was altered; it must match the Go session key byte for byte"


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

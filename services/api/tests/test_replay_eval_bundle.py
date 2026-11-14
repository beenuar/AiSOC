"""The replay evidence bundle: what leaves the partner's estate.

Phase 1.5. Every test here is about one of three properties, because a
bundle that fails any of them is worse than no bundle: it does not carry
the partner's data, it cannot be altered without detection, and the
numbers in it can be re-derived by whoever receives it.

The leak tests assert on the **serialised bundle**, not on the field that
was redacted. Asserting that `per_rule[0]["key"] == "RULE_1"` passes while
the same rule name sits untouched three keys away, which is how a
redaction pass ships with a hole in it. `"FIN-DB-01" not in json.dumps(...)`
cannot pass that way.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from app.services.evidence_bundle import BundleVerificationError, verify_bundle
from app.services.replay_evaluation.bundle import (
    REPLAY_BUNDLE_SCHEMA_VERSION,
    BundleRedactor,
    ReplayBundleError,
    build_replay_bundle,
    replay_bundle_filename,
)

#: A hostname in the shape real estates use, carried in three places a
#: replay result puts partner text: a rule name, an indicator example and
#: the agent's own reasoning.
HOST = "FIN-DB-01"
RULE = f"Suspicious PowerShell on {HOST}"
SIGNING_KEY = "a-deployment-signing-key"


def _score() -> dict[str, object]:
    return {
        "decisions": 40,
        "graded": 36,
        "malicious_support": 31,
        "malicious_recall": 0.8125,
        "balanced_accuracy": 0.742,
        "hallucination_rate": 0.05,
        "hallucinated_total": 2,
        "indicators_checked": 40,
        "hallucinated_examples": [HOST, "evil.example.com"],
        "per_rule": [{"key": RULE, "graded": 12, "correct": 9, "accuracy": 0.75}],
        "per_source": [{"key": "splunk", "graded": 36, "correct": 27, "accuracy": 0.75}],
        "confusion": {"true_positive": {"true_positive": 26, "benign": 5}},
    }


def _method() -> dict[str, object]:
    return {
        "tenant_id": "6f2b1f1e-0000-4000-8000-000000000001",
        "connector_id": "9c1d7a52-0000-4000-8000-000000000002",
        "history": {"vendor": "splunk", "findings_read": 40, "findings_labelled": 36},
        "split": {"train_fraction": 0.7},
    }


def _items() -> list[dict[str, object]]:
    return [
        {
            "finding_id": "NB-00177",
            "rule_id": RULE,
            "vendor": "splunk",
            "expected_disposition": "true_positive",
            "verdict": "true_positive",
            "confidence": 0.91,
            "labelled": True,
            "findings": [f"{HOST} ran an encoded command and multi-factor was not used"],
            "confidence_basis": [f"the account signed in from 10.2.3.4 to {HOST}"],
            "evidence": {"host": HOST, "command_line": "powershell -enc SQBFAFgA", "user": "ACME\\priya"},
            "error": None,
        },
        {
            "finding_id": "NB-00178",
            "rule_id": RULE,
            "vendor": "splunk",
            "expected_disposition": "false_positive",
            "verdict": "benign",
            "confidence": 0.44,
            "labelled": True,
            "findings": ["the scheduled task is signed by the vendor"],
            "confidence_basis": [],
            "evidence": {"host": "WEB-07", "command_line": "updater.exe"},
            "error": None,
        },
    ]


def _aggregate_bundle() -> dict:
    return build_replay_bundle(score=_score(), method=_method(), model={"id": "ollama_chat/llama3.2:3b"}, signing_key=SIGNING_KEY)


def _item_bundle() -> dict:
    return build_replay_bundle(
        score=_score(),
        method=_method(),
        model={"id": "ollama_chat/llama3.2:3b"},
        items=_items(),
        signing_key=SIGNING_KEY,
    )


# --------------------------------------------------------------------------
# What does not leave
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bundle_factory", [_aggregate_bundle, _item_bundle], ids=["aggregate", "with-items"])
def test_no_partner_identifier_survives_anywhere_in_the_bundle(bundle_factory) -> None:
    """Asserted over the whole serialised artefact, not per field."""
    serialised = json.dumps(bundle_factory())

    for secret in (HOST, RULE, "powershell -enc", "ACME\\priya", "10.2.3.4", "WEB-07"):
        assert secret not in serialised, f"{secret!r} survived redaction and would leave the partner's estate"


def test_the_tenant_and_connector_this_came_from_are_not_named() -> None:
    serialised = json.dumps(_item_bundle())

    assert "6f2b1f1e" not in serialised
    assert "9c1d7a52" not in serialised


def test_evidence_is_dropped_rather_than_redacted() -> None:
    """Free-form vendor JSON is not something a pattern set can be trusted over."""
    payload = _item_bundle()["payload"]

    for row in payload["items"]:
        assert "evidence" not in row
        assert row["evidence_withheld"] is True
    assert payload["privacy"]["evidence_included"] is False


def test_indicator_examples_are_withheld_from_an_aggregate_bundle() -> None:
    """They are item-level detail that leaked into the aggregate.

    The rate and its two counts carry the analytic value; the strings are
    substrings of the agent's reasoning about the partner's estate.
    """
    scores = _aggregate_bundle()["payload"]["scores"]

    assert scores["hallucinated_examples"] == []
    assert scores["hallucinated_examples_withheld"] == 2
    # The measurement itself survives — withholding the examples must not
    # turn a measured rate into a missing one.
    assert scores["hallucination_rate"] == 0.05
    assert scores["indicators_checked"] == 40


def test_exporting_items_is_what_includes_the_examples() -> None:
    scores = _item_bundle()["payload"]["scores"]

    assert scores["hallucinated_examples"], "exporting item detail should carry the examples through, redacted"
    assert HOST not in json.dumps(scores["hallucinated_examples"])


def test_a_public_indicator_is_kept_because_it_is_not_the_partners_property() -> None:
    """The deliberate half of the trade-off, asserted so a change is visible."""
    scores = _item_bundle()["payload"]["scores"]

    # Equality against each element, never `in`: both a substring test over
    # the serialised blob and a containment test spelled with `in` would
    # also pass on `evil.example.com.attacker.test`, which is a different
    # host and the opposite of what this asserts.
    assert any(example == "evil.example.com" for example in scores["hallucinated_examples"])


# --------------------------------------------------------------------------
# What survives, because a bundle nobody can read is not a deliverable
# --------------------------------------------------------------------------


def test_the_scoring_vocabulary_is_not_redacted() -> None:
    """A report whose class labels read TOKEN_4 grades nothing."""
    scores = _item_bundle()["payload"]["scores"]

    assert "true_positive" in scores["confusion"]
    assert scores["confusion"]["true_positive"]["benign"] == 5
    assert scores["balanced_accuracy"] == 0.742
    assert scores["malicious_recall"] == 0.8125


def test_ordinary_words_in_the_reasoning_survive() -> None:
    """The host pattern must not rewrite hyphenated English.

    `multi-factor` has a hyphen and no digit. A pattern that took it would
    damage the reasoning the export exists to carry.
    """
    findings = _item_bundle()["payload"]["items"][0]["findings"][0]

    assert "multi-factor was not used" in findings
    assert "ran an encoded command" in findings


def test_one_rule_is_one_token_across_the_breakdown_and_the_rows() -> None:
    """Grouping is the property that makes an export re-derivable."""
    payload = _item_bundle()["payload"]

    rule_token = payload["scores"]["per_rule"][0]["key"]
    assert rule_token.startswith("RULE_")
    assert {row["rule_id"] for row in payload["items"]} == {rule_token}


def test_two_findings_under_one_rule_keep_distinct_identities() -> None:
    payload = _item_bundle()["payload"]

    ids = [row["finding_id"] for row in payload["items"]]
    assert len(set(ids)) == 2, "distinct findings collapsed onto one token and the rows can no longer be told apart"


def test_the_confusion_matrix_can_be_recomputed_from_the_exported_rows() -> None:
    """The point of exporting items: the receiver can check the aggregate."""
    rows = _item_bundle()["payload"]["items"]

    pairs = [(row["expected_disposition"], row["verdict"]) for row in rows]
    assert pairs == [("true_positive", "true_positive"), ("false_positive", "benign")]


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------


def test_a_bundle_verifies_against_the_key_that_signed_it() -> None:
    bundle = _item_bundle()

    assert verify_bundle(bundle, signing_key=SIGNING_KEY) == bundle["payload"]


def test_an_altered_score_is_detected() -> None:
    """The negative control for the whole format."""
    bundle = json.loads(json.dumps(_item_bundle()))
    bundle["payload"]["scores"]["malicious_recall"] = 1.0

    with pytest.raises(BundleVerificationError, match="digest mismatch"):
        verify_bundle(bundle, signing_key=SIGNING_KEY)


def test_altering_the_payload_and_its_digest_together_is_still_detected() -> None:
    """A verifier that compared the two values in the file would pass here."""
    import hashlib

    from app.services.evidence_bundle import canonical_bytes

    bundle = json.loads(json.dumps(_item_bundle()))
    bundle["payload"]["scores"]["malicious_recall"] = 1.0
    bundle["integrity"]["payload_sha256"] = hashlib.sha256(canonical_bytes(bundle["payload"])).hexdigest()

    with pytest.raises(BundleVerificationError, match="signature does not match"):
        verify_bundle(bundle, signing_key=SIGNING_KEY)


def test_another_deployments_key_does_not_verify() -> None:
    with pytest.raises(BundleVerificationError, match="signature does not match"):
        verify_bundle(_item_bundle(), signing_key="a-different-deployments-key")


def test_signing_with_an_empty_key_is_refused() -> None:
    """An HMAC over the empty string verifies for anyone who tries it."""
    with pytest.raises(ValueError, match="empty key"):
        build_replay_bundle(score=_score(), method=_method(), model={}, signing_key="")


def test_a_bundle_with_no_score_is_refused() -> None:
    with pytest.raises(ReplayBundleError, match="graded nothing"):
        build_replay_bundle(score={}, method=_method(), model={}, signing_key=SIGNING_KEY)


# --------------------------------------------------------------------------
# Reproducibility
# --------------------------------------------------------------------------


def test_two_bundles_of_one_result_are_byte_identical() -> None:
    """Apart from the generation time, which is pinned here to test the rest."""
    at = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)

    # Spelled out at each call rather than splatted from one dict: a dict of
    # mixed-typed values widens to a single join type, which costs the
    # per-argument checking this file otherwise gets for free.
    def build() -> dict:
        return build_replay_bundle(
            score=_score(),
            method=_method(),
            model={"id": "m"},
            items=_items(),
            signing_key=SIGNING_KEY,
            generated_at=at,
        )

    first = build()
    second = build()

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_the_schema_version_and_kind_are_stated() -> None:
    payload = _aggregate_bundle()["payload"]

    assert payload["bundle_schema_version"] == REPLAY_BUNDLE_SCHEMA_VERSION
    assert payload["kind"] == "replay_evaluation"


def test_the_filename_is_stable_for_one_run() -> None:
    assert replay_bundle_filename("abc") == "aisoc-replay-abc.bundle.json"


# --------------------------------------------------------------------------
# The redactor's own edges
# --------------------------------------------------------------------------


def test_a_short_identifier_is_not_substituted_into_prose() -> None:
    """A rule id of `s3` would otherwise rewrite every mention of the service."""
    redactor = BundleRedactor()
    redactor.identifier("RULE", "s3")

    assert "s3 bucket" in redactor.free_text("the s3 bucket was public")


def test_the_longest_identifier_wins_when_two_overlap() -> None:
    redactor = BundleRedactor()
    outer = redactor.identifier("RULE", "FIN-DB-01 lateral movement")
    inner = redactor.identifier("HOST", "FIN-DB-01")

    assert redactor.free_text("FIN-DB-01 lateral movement fired") == f"{outer} fired"
    assert redactor.free_text("traffic from FIN-DB-01 only") == f"traffic from {inner} only"


def test_the_privacy_block_states_what_the_pass_does_not_catch() -> None:
    """A note read by someone deciding what to send must not overstate."""
    privacy = _item_bundle()["payload"]["privacy"]

    assert privacy["mapping_exported"] is False
    assert privacy["free_text_does_not_catch"], "the limits of a pattern-based pass must be stated, not implied"
    assert any("single-word machine name" in limit for limit in privacy["free_text_does_not_catch"])


def test_bare_host_in_agent_prose_is_redacted() -> None:
    """A machine named only in the agent's reasoning must not survive.

    This is the leak the first live run against a real reader produced: the
    recon step writes ``Extracted 2 IOCs: ['198.51.100.7', 'WS-040']`` and
    ``WS-040`` appears in no identifier field, so nothing registered it.
    """
    redactor = BundleRedactor()

    out = redactor.free_text("Extracted 2 IOCs for enrichment: ['198.51.100.7', 'WS-040']")

    assert "WS-040" not in out
    assert "198.51.100.7" not in out


def test_public_taxonomy_survives_host_redaction() -> None:
    """The agent reasons in CVE and ATT&CK terms; those are not machines.

    Every term below matches the host shape. Rewriting them would make the
    reasoning unreadable while protecting nothing, which is the failure mode
    that makes a redactor get switched off.
    """
    redactor = BundleRedactor()
    text = "SHA-256 matched, CVE-2026-1234 applies, technique T1059.001, RFC-1918 space, AES-256 key, x86-64 binary"

    out = redactor.free_text(text)

    assert out == text


def test_one_host_gets_one_token_whichever_pass_sees_it_first() -> None:
    """The identifier pass and the prose pass must share a namespace.

    They are separate code paths naming the same machine. If they disagree,
    two rows about one host read as two hosts and the bundle stops being
    joinable against itself -- which is most of what it is for.
    """
    from_identifier = BundleRedactor()
    from_identifier.identifier("rule", "Lateral movement on FIN-DB-01")
    identifier_first = from_identifier.free_text("the host FIN-DB-01 was contacted")

    from_prose = BundleRedactor()
    prose_first = from_prose.free_text("the host FIN-DB-01 was contacted")

    assert "FIN-DB-01" not in identifier_first
    assert identifier_first == prose_first, "the same host named by two passes must produce one token"

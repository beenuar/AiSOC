"""Evidence bundles: deterministic, tamper-evident, and honest about both.

Parity 3.7. The spec's done-when clause is *"an evidence bundle
round-trips through replay byte for byte"*, which is the first class
below. The rest exist because the other three properties a bundle claims
are each easy to get wrong in a way no happy-path test would notice.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from app.services.evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    OCSF_VERSION,
    BundleVerificationError,
    build_bundle,
    canonical_bytes,
    serialize_bundle,
    verify_bundle,
)

KEY = "test-signing-key-at-least-32-characters-long"
RUN_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
TENANT = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
WHEN = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)


def _run(**overrides):
    base = {
        "id": RUN_ID,
        "tenant_id": TENANT,
        "case_id": "CASE-1",
        "alert_summary": "Encoded PowerShell from Office on WIN-FIN-02",
        "raw_alert": {"host": "WIN-FIN-02", "user": "j.doe"},
        "model_used": "llama3.2:3b-instruct-q4_K_M",
        "status": "completed",
        "error": None,
        "total_tokens": 4096,
        "total_cost_usd": 0.0012,
        "iterations": 3,
        "started_at": WHEN,
        "completed_at": WHEN,
    }
    base.update(overrides)
    return base


def _events():
    """Returned out of order on purpose: the bundle must sort them."""
    return [
        {
            "id": uuid.UUID("00000000-0000-0000-0000-000000000002"),
            "seq": 2,
            "kind": "llm_response",
            "agent": "aisoc-investigation",
            "summary": "verdict",
            "ts": WHEN,
            "duration_ms": 900,
            "input_hash": "in-2",
            "output_hash": "out-2",
            "payload": {"verdict": "true_positive", "prompt": "SYSTEM: you are...\nUSER: WIN-FIN-02"},
        },
        {
            "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
            "seq": 1,
            "kind": "tool_call",
            "agent": "aisoc-recon",
            "summary": "lake query",
            "ts": WHEN,
            "duration_ms": 120,
            "input_hash": "in-1",
            "output_hash": "out-1",
            "payload": {"tool": "lake_query", "rows": 4},
        },
    ]


def _bundle(**run_overrides):
    return build_bundle(
        run=_run(**run_overrides),
        events=_events(),
        artifacts=[{"id": uuid.UUID(int=7), "kind": "report", "label": "summary.md", "sha256": "abc"}],
        approvals=[{"id": uuid.UUID(int=9), "action": "isolate_host", "status": "approved", "approver": "alice", "decided_at": WHEN}],
        signing_key=KEY,
    )


class TestItRoundTripsByteForByte:
    """The spec's done-when clause."""

    def test_two_exports_of_one_run_are_identical(self) -> None:
        assert serialize_bundle(_bundle()) == serialize_bundle(_bundle())

    def test_it_survives_a_json_round_trip_unchanged(self) -> None:
        """Written to disk, read back, re-serialised: still the same bytes.

        This is what "replayable" has to mean for anyone who did not
        produce the bundle — they parse it with an ordinary JSON reader
        and must be able to recompute what was signed.
        """
        first = serialize_bundle(_bundle())
        reparsed = json.loads(first.decode("utf-8"))
        assert serialize_bundle(reparsed) == first

    def test_event_order_does_not_depend_on_input_order(self) -> None:
        """A ledger read that returns rows in a different order must not
        change the digest, or the signature becomes a property of the
        query plan."""
        forward = build_bundle(run=_run(), events=_events(), signing_key=KEY)
        backward = build_bundle(run=_run(), events=list(reversed(_events())), signing_key=KEY)
        assert serialize_bundle(forward) == serialize_bundle(backward)

    def test_the_canonical_form_has_no_inserted_whitespace(self) -> None:
        raw = canonical_bytes({"b": 1, "a": 2})
        assert raw == b'{"a":2,"b":1}'


class TestTamperEvidence:
    def test_an_untouched_bundle_verifies(self) -> None:
        """The negative control for every tampering test below: without
        it they would all pass against a verifier that rejects
        everything."""
        bundle = _bundle()
        assert verify_bundle(bundle, signing_key=KEY)["run"]["case_id"] == "CASE-1"

    def test_editing_the_verdict_is_caught(self) -> None:
        bundle = _bundle()
        bundle["payload"]["steps"][1]["payload"]["verdict"] = "false_positive"
        with pytest.raises(BundleVerificationError, match="digest mismatch"):
            verify_bundle(bundle, signing_key=KEY)

    def test_editing_the_payload_and_its_digest_together_is_caught(self) -> None:
        """The attack a verifier that compares two fields in the file
        would miss. Both values are recomputed from the payload."""
        from app.services.evidence_bundle import _digest  # noqa: PLC0415

        bundle = _bundle()
        bundle["payload"]["alert"]["summary"] = "nothing happened"
        bundle["integrity"]["payload_sha256"] = _digest(bundle["payload"])
        with pytest.raises(BundleVerificationError, match="signature does not match"):
            verify_bundle(bundle, signing_key=KEY)

    def test_another_deployments_key_does_not_verify(self) -> None:
        with pytest.raises(BundleVerificationError, match="signature does not match"):
            verify_bundle(_bundle(), signing_key="a-different-key-at-least-32-characters")

    def test_a_bundle_with_no_payload_is_refused(self) -> None:
        with pytest.raises(BundleVerificationError, match="no payload"):
            verify_bundle({"integrity": {}}, signing_key=KEY)


class TestPromptsTravelAsHashes:
    """A bundle is the artefact most likely to leave the customer's
    control, so it must not carry their estate in clear text."""

    def test_prompt_text_is_not_in_the_bundle(self) -> None:
        raw = serialize_bundle(_bundle()).decode("utf-8")
        assert "SYSTEM: you are" not in raw
        assert "USER: WIN-FIN-02" not in raw

    def test_the_hash_is_there_instead(self) -> None:
        """Still enough to prove *which* prompt ran: re-hash and compare."""
        step = next(s for s in _bundle()["payload"]["steps"] if s["kind"] == "llm_response")
        assert step["payload"]["prompt_sha256"].startswith("sha256:")
        assert "prompt" not in step["payload"]

    def test_a_step_with_no_prompt_gains_no_hash_field(self) -> None:
        """A hash of nothing would read as a prompt that existed."""
        step = next(s for s in _bundle()["payload"]["steps"] if s["kind"] == "tool_call")
        assert "prompt_sha256" not in step["payload"]


class TestAbsentIsNotZero:
    def test_a_run_with_no_cost_exports_null(self) -> None:
        """`0.0` says the run was free; `null` says nobody measured. This
        repository has published the first while meaning the second."""
        model = _bundle(total_cost_usd=None, total_tokens=None)["payload"]["model"]
        assert model["total_cost_usd"] is None
        assert model["total_tokens"] is None
        assert "not measured" in model["cost_provenance"]

    def test_a_measured_cost_says_measured(self) -> None:
        model = _bundle()["payload"]["model"]
        assert model["total_cost_usd"] == pytest.approx(0.0012)
        assert model["cost_provenance"] == "measured"


class TestTheOcsfMapping:
    """Every field here was checked against schema.ocsf.io before use."""

    def test_it_declares_the_version_that_actually_has_these_objects(self) -> None:
        """`ai_agent` exists only from 1.9.0 and `ai_operation` from
        1.8.0. The ingest spine emits 1.1.0, where neither exists —
        declaring that here while emitting an `ai_agent` would be a false
        claim about a public standard."""
        assert _bundle()["payload"]["ocsf"]["metadata"]["version"] == OCSF_VERSION == "1.9.0"

    def test_it_names_both_profiles_it_uses(self) -> None:
        profiles = _bundle()["payload"]["ocsf"]["metadata"]["profiles"]
        assert "ai_operation" in profiles
        assert "record_integrity" in profiles

    def test_the_agent_carries_the_model_nested_as_the_schema_has_it(self) -> None:
        agent = _bundle()["payload"]["ocsf"]["ai_operation"]["ai_agent"]
        assert agent["ai_model"]["name"] == "llama3.2:3b-instruct-q4_K_M"
        assert set(agent) <= {"name", "uid", "type", "type_id", "instance_uid", "ai_model", "version", "charter", "uid_numeric"}

    def test_a_run_with_no_model_carries_null_not_a_placeholder(self) -> None:
        agent = _bundle(model_used=None)["payload"]["ocsf"]["ai_operation"]["ai_agent"]
        assert agent["ai_model"] is None

    def test_the_attestation_matches_the_computed_digest(self) -> None:
        bundle = _bundle()
        attestation = bundle["integrity"]["attestation_list"][0]
        assert attestation["fingerprint"]["value"] == bundle["integrity"]["payload_sha256"]


class TestItSaysWhatTheSignatureIsWorth:
    def test_the_bundle_states_it_is_not_non_repudiation(self) -> None:
        """An auditor who assumes a public-key signature from the word
        "signed" has been misled by us rather than by the format."""
        note = _bundle()["integrity"]["algorithm_note"]
        assert "not non-repudiation" in note.lower()
        assert "tamper-evidence" in note.lower()

    def test_the_schema_version_is_published(self) -> None:
        assert _bundle()["payload"]["bundle_schema_version"] == BUNDLE_SCHEMA_VERSION

"""The unsupported-claim detector, measured against hand-annotated cases.

What this is
------------
`score_claim_support` gates auto-closure in production, and until now its
quality was asserted case by case rather than *measured*: there was no
unsupported-claim rate anywhere in the tree, so "the detector works" rested
on the examples its own tests happened to contain. This file is the
measurement: a fixed annotated corpus of (rationale, evidence, human label)
triples, a confusion matrix over it, and the detector's precision and recall
pinned exactly — in both directions, so an improvement has to announce
itself in the same commit as a regression would.

What the annotation is, and is not
----------------------------------
Each case was labelled by reading the rationale against the evidence and
answering one question: *does this rationale rest on at least one decisive
claim — authorization, maintenance, a change record, sanctioned tooling,
prior review — that the evidence shown does not support?* The label is about
the text pair, not about the detector.

The annotation is **not independent in the strong sense**: the annotator had
read the detector's code, and authored the cases. That makes this a
regression-grade measurement of the detector on a fixed corpus — the same
standing as the injection guard's tuned-corpus rate — and NOT an audit-grade
unsupported-claim rate, which needs cases authored and labelled by someone
who has not read the patterns (the held-out discipline the behavioural
corpus already follows). That limit is stated here because the number below
will otherwise be quoted without it.

The published numbers
---------------------
Pinned exactly rather than floored: a floor hides drift in the direction
nobody checks, and these are small-denominator counts where every single
case moving is worth a look.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.confidence.claim_support import score_claim_support

#: Detector performance on the annotated corpus, pinned exactly. The
#: denominators travel with the rates (the repository rule: a mean without
#: its count is a different fact), and `tests/` is the publication venue —
#: quoting these anywhere else without the annotation caveat above is wrong.
EXPECTED_TRUE_POSITIVES = 7
EXPECTED_FALSE_POSITIVES = 0
EXPECTED_FALSE_NEGATIVES = 1
EXPECTED_TRUE_NEGATIVES = 8


@dataclass(frozen=True)
class AnnotatedCase:
    case_id: str
    rationale: str
    evidence: dict[str, Any]
    #: The human label: the rationale rests on >= 1 unsupported decisive claim.
    unsupported_claim: bool
    #: Why the label is what it is — the annotation's working, kept beside it.
    annotation_note: str
    supporting_context: str | None = None


CASES: tuple[AnnotatedCase, ...] = (
    # ── Unsupported decisive claims (the detector should flag) ────────────
    AnnotatedCase(
        case_id="CS-01",
        rationale="198.51.100.14 is our approved scanner under change CHG0049112, so the port sweep is expected.",
        evidence={"src_ip": "198.51.100.14", "ports_contacted": 1024},
        unsupported_claim=True,
        annotation_note="Approval and a change record asserted; evidence carries neither.",
    ),
    AnnotatedCase(
        case_id="CS-02",
        rationale="This window is scheduled maintenance for the cluster, and the reboots match the change window.",
        evidence={"hostname": "db-07", "event": "unexpected_reboot", "count": 4},
        unsupported_claim=True,
        annotation_note="Maintenance window asserted; nothing in the evidence records one.",
    ),
    AnnotatedCase(
        case_id="CS-03",
        rationale="The activity was previously reviewed and closed as a known false-positive by the SOC.",
        evidence={"rule_id": "edr-lolbin-exec", "process": "regsvr32.exe"},
        unsupported_claim=True,
        annotation_note="Prior review asserted; no disposition history is in the evidence or context.",
    ),
    AnnotatedCase(
        case_id="CS-04",
        rationale="This source is the internal vulnerability scanner, so the authentication failures are benign.",
        evidence={"src_ip": "203.0.113.9", "failed_logins": 212},
        unsupported_claim=True,
        annotation_note="Sanctioned tooling asserted; the evidence names no scanner.",
    ),
    AnnotatedCase(
        case_id="CS-05",
        rationale="Ticket INC-77421 covers this activity; the engineer was permitted to export the bucket.",
        evidence={"user": "j.doe", "action": "s3:GetObject", "object_count": 90210},
        unsupported_claim=True,
        annotation_note="A change/ticket record and a permission asserted; evidence has neither.",
    ),
    AnnotatedCase(
        case_id="CS-06",
        rationale="This is a red-team exercise; the beaconing is part of the engagement.",
        evidence={"domain": "cdn-metrics.example", "beacon_interval_s": 60},
        unsupported_claim=True,
        annotation_note="Engagement asserted with no engagement record anywhere.",
    ),
    AnnotatedCase(
        case_id="CS-07",
        rationale="The transfer was pre-approved; data movement of this size is sanctioned for this team each quarter.",
        evidence={"user": "a.smith", "bytes_out": 92_000_000_000},
        unsupported_claim=True,
        annotation_note="Approval asserted twice; evidence is a byte count and a username.",
    ),
    # ── Supported or claim-free rationales (the detector must not flag) ───
    AnnotatedCase(
        case_id="CS-08",
        rationale="The rule counts distinct destination ports and this source contacted 1024 of them, which is the condition it was written for.",
        evidence={"src_ip": "198.51.100.14", "ports_contacted": 1024},
        unsupported_claim=False,
        annotation_note="Reasons from the telemetry; asserts no decisive claim.",
    ),
    AnnotatedCase(
        case_id="CS-09",
        rationale="The export was approved: the change record is in the evidence and names this user.",
        evidence={"user": "j.doe", "action": "s3:GetObject", "approval_id": "CHG0031177", "approved_by": "it-change-board"},
        unsupported_claim=False,
        annotation_note="Approval asserted and the evidence carries approval_id/approved_by.",
    ),
    AnnotatedCase(
        case_id="CS-10",
        rationale="Organisation memory records that this scanner subnet is sanctioned, which covers this source.",
        evidence={"src_ip": "192.0.2.33", "ports_contacted": 400},
        unsupported_claim=False,
        annotation_note="Sanctioned-tooling claim supported by first-party context, not the payload.",
        supporting_context="Analysts have repeatedly confirmed: 192.0.2.0/24 is the sanctioned internal scanner subnet (authorized scanner).",
    ),
    AnnotatedCase(
        case_id="CS-11",
        rationale="Nothing in the telemetry indicates this traffic was approved or part of any maintenance window, so it escalates.",
        evidence={"hostname": "ws-4", "event": "service_install"},
        unsupported_claim=False,
        annotation_note="Mentions the vocabulary under negation; asserts the opposite of the claim.",
    ),
    AnnotatedCase(
        case_id="CS-12",
        rationale="High-entropy domain, first seen today, resolved by one host only: consistent with command and control.",
        evidence={"domain": "qx7zt.example", "first_seen": "today", "resolver_count": 1},
        unsupported_claim=False,
        annotation_note="Escalating conclusion drawn from evidence; no decisive benign claim.",
    ),
    AnnotatedCase(
        case_id="CS-13",
        rationale="The sender claims to be from the IT helpdesk, which the evidence does not corroborate; treating as phishing.",
        evidence={"email_subject": "Password reset required", "sender": "helpdesk@example.net"},
        unsupported_claim=False,
        annotation_note="Reports a third party's claim without adopting it; 'claims to be' is not an assertion.",
    ),
    AnnotatedCase(
        case_id="CS-14",
        rationale="The binary is signed and the signature chain validates to the vendor, so execution from Program Files is expected.",
        evidence={"process": "updater.exe", "signature_valid": True, "signer": "Example Corp"},
        unsupported_claim=False,
        annotation_note="A code-signing fact read off the evidence; not a decisive-claim family.",
    ),
    AnnotatedCase(
        case_id="CS-15",
        rationale="The login burst matches the scheduled scan the evidence records for this window.",
        evidence={"src_ip": "192.0.2.7", "scheduled_scan": "weekly-authenticated-scan", "window": "02:00-03:00"},
        unsupported_claim=False,
        annotation_note="Maintenance-family claim supported by the scheduled_scan key in evidence.",
    ),
    # ── The known miss, kept as a miss ─────────────────────────────────────
    AnnotatedCase(
        case_id="CS-16",
        rationale="IT said this rollout is fine and the activity matches what the desktop team normally pushes.",
        evidence={"process": "deploy.ps1", "host_count": 240},
        unsupported_claim=True,
        annotation_note=(
            "A verbal-authority claim ('IT said this is fine') with no record. No pattern family covers "
            "informal authority that avoids the approval vocabulary — the known miss, recorded rather than "
            "patched, because tuning the detector against the corpus that measures it manufactures a rate."
        ),
    ),
)


def _confusion() -> tuple[int, int, int, int]:
    tp = fp = fn = tn = 0
    for case in CASES:
        result = score_claim_support(case.rationale, case.evidence, supporting_context=case.supporting_context)
        flagged = result.blocks_auto_close
        if case.unsupported_claim and flagged:
            tp += 1
        elif case.unsupported_claim and not flagged:
            fn += 1
        elif not case.unsupported_claim and flagged:
            fp += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def test_corpus_is_balanced_enough_to_measure() -> None:
    """Half the corpus must be claim-free or supported, or the measurement
    rewards a detector that flags everything."""
    positives = sum(1 for case in CASES if case.unsupported_claim)
    assert 6 <= positives <= len(CASES) - 6


def test_detector_confusion_matrix_is_pinned_exactly() -> None:
    """The measurement. Pinned in both directions: a new miss and a new catch
    both fail until the constants — and anything quoting them — move in the
    same commit."""
    tp, fp, fn, tn = _confusion()
    print(
        f"\n[eval] claim-support on {len(CASES)} annotated cases: "
        f"TP={tp} FP={fp} FN={fn} TN={tn} "
        f"precision={tp / (tp + fp) if tp + fp else float('nan'):.3f} "
        f"recall={tp / (tp + fn) if tp + fn else float('nan'):.3f}"
    )
    assert (tp, fp, fn, tn) == (
        EXPECTED_TRUE_POSITIVES,
        EXPECTED_FALSE_POSITIVES,
        EXPECTED_FALSE_NEGATIVES,
        EXPECTED_TRUE_NEGATIVES,
    ), f"detector moved on the annotated corpus: TP={tp} FP={fp} FN={fn} TN={tn}"


def test_the_known_miss_is_the_one_annotated_as_missed() -> None:
    """CS-16 is the recorded blind spot. If the detector starts catching it,
    this fails too — the miss list must not decay into a description of a
    tree nobody re-measured (the injection ratchet's rule, applied here)."""
    case = next(c for c in CASES if c.case_id == "CS-16")
    result = score_claim_support(case.rationale, case.evidence)
    assert not result.blocks_auto_close, "the recorded miss is now caught: move it out of the miss list and update the pinned matrix"


def test_zero_false_positives_holds_on_negated_and_supported_claims() -> None:
    """The cases production cannot afford to flag: negation, evidence-anchored
    approval, and first-party context support. A detector that flags these
    demotes ordinary analyst language and gets switched off within a week."""
    for case_id in ("CS-09", "CS-10", "CS-11", "CS-13", "CS-15"):
        case = next(c for c in CASES if c.case_id == case_id)
        result = score_claim_support(case.rationale, case.evidence, supporting_context=case.supporting_context)
        assert not result.blocks_auto_close, f"{case_id} flagged: {result.reason}"

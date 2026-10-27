"""The seven things people mean by "the AI was right", named once.

Every one of these has at some point been reported in this repository as
though it were one of the others, and each conflation has a specific cost.
They are enumerated here rather than described in a document because a
vocabulary that lives only in prose drifts: a scorecard key, a gate's
docstring and a README sentence end up using one word for three measurements
and a reader cannot tell which was taken.

A module that produces one of these states which, by name. A surface that
renders one states which, by name. Nothing may report a value under a kind it
did not measure, and :data:`UNMEASURED` is a first-class answer — the house
rule that an unmeasured rate reads "not measured" and never ``0.000`` applies
to every kind below.

Stdlib only and no ``app.`` import: repository-level gates load this to check
that a published key names a kind that exists.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["UNMEASURED", "SignalKind", "describe"]

#: What a surface prints for a kind that was not measured. Never a number.
UNMEASURED = "not measured"


class SignalKind(str, Enum):
    """What a given number is actually about."""

    #: The reply parsed into the verdict object production reads. Says
    #: nothing about whether the verdict is right — a model can emit
    #: impeccable JSON asserting nonsense. Measured by
    #: `scripts/measure_triage_reliability.py`.
    STRUCTURED_OUTPUT = "structured_output"

    #: The fraction of concrete indicators the output asserts — IPs, hashes,
    #: CVEs, techniques, domains — that appear in the evidence given.
    #: Measured by `app.confidence.groundedness`. Blind to whether the
    #: *conclusion* drawn from those indicators follows from anything.
    INDICATOR_GROUNDING = "indicator_grounding"

    #: Whether the claims that license a decision — authorized, approved,
    #: scheduled maintenance, previously reviewed — trace to something in the
    #: evidence or in the tenant's own recorded context. Measured by
    #: `app.confidence.claim_support`. Independent of
    #: :attr:`INDICATOR_GROUNDING`: a rationale can score 1.0 on that and
    #: have no support at all for the sentence that closes the alert.
    CLAIM_SUPPORT = "claim_support"

    #: Whether the verdict matches the label, over a corpus with a known
    #: answer. Measured by `scripts/run_verdict_eval.py` against the balanced
    #: verdict corpus. Requires held-out labels and an opaque alert id.
    DISPOSITION_ACCURACY = "disposition_accuracy"

    #: The number the model put in its own `confidence` field. An input to
    #: the closure gate and **not** evidence of anything: it is the model's
    #: report about itself, coerced and clamped by `_coerce_confidence`.
    MODEL_REPORTED_CONFIDENCE = "model_reported_confidence"

    #: How well that number tracks being right, measured over outcomes —
    #: Brier score, reliability curve, expected calibration error. Measured
    #: by `app.confidence.calibration`. This is the only sense in which a
    #: confidence figure is a claim about correctness.
    CALIBRATED_CONFIDENCE = "calibrated_confidence"

    #: Of the alerts this configuration would have closed without a human,
    #: the fraction it was right to close — measured separately per model,
    #: prompt version, tenant context and alert class, with a minimum sample.
    #: The input `app.confidence.eligibility` reads. Not derivable from any
    #: of the above: a model can be accurate overall and wrong exactly on the
    #: alerts it is most confident about.
    AUTO_CLOSURE_SAFETY = "auto_closure_safety"


_DESCRIPTIONS: dict[SignalKind, str] = {
    SignalKind.STRUCTURED_OUTPUT: "the reply parsed into a verdict object; not a statement about the verdict",
    SignalKind.INDICATOR_GROUNDING: "fraction of asserted indicators present in the evidence",
    SignalKind.CLAIM_SUPPORT: "whether the claims that license the decision trace to evidence",
    SignalKind.DISPOSITION_ACCURACY: "verdict against a known label on a held-out corpus",
    SignalKind.MODEL_REPORTED_CONFIDENCE: "the model's own confidence field; self-reported, not demonstrated",
    SignalKind.CALIBRATED_CONFIDENCE: "how well reported confidence tracks being right, measured over outcomes",
    SignalKind.AUTO_CLOSURE_SAFETY: "precision of the closures this configuration would have made unattended",
}


def describe(kind: SignalKind) -> str:
    """One sentence a report can print beside a number so its meaning travels with it."""
    return _DESCRIPTIONS[kind]

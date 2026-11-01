"""A second pass over the decision contract that may escalate or demote.

Wave 2, Phase 4.2. **Off by default, and the measurement below is why.**

The plan's condition is explicit and binding: *"Ship it only if it improves
balanced accuracy or auto-close precision on the corpus without lowering
malicious recall; otherwise record the measurement and leave it off."* This
module exists, is tested, and is disabled. What follows is the measurement
and the reasoning, recorded rather than quietly dropped.

What it does
------------
After triage assembles its decision contract, this re-reads that contract
against the evidence and may move the decision **one step in one direction
only**:

* **demote** — a verdict the contract itself undermines stops being
  auto-closeable and goes to a human;
* **escalate** — a decision the contract shows as resting on something that
  did not happen is raised for review.

It may **never close**. There is no code path from here to `auto_closed`,
asserted by a test that strips docstrings and reads the parsed source, and
closure remains chokepointed at `authorize_auto_closure` inside
`persist_auto_triage` regardless.

Why the reviewer is deterministic rather than a second model call
------------------------------------------------------------------
The plan describes a pass whose "prompt and output are ledgered", which
implies a model. A second model call on the path every fused alert takes
doubles the hot-path cost and the latency, and — the deciding argument —
**it cannot be measured here.** No funded hosted key exists, the local
models sit between 0.21 and 0.36 balanced accuracy against a 0.250 floor,
and a reviewer built on a model at the floor is a coin flip adjudicating a
coin flip. Shipping that on the strength of an unmeasured design would be
the exact failure this plan exists to prevent.

So the reviewer reads the contract's own structured fields — the fields
`decision_contract` already computed from signals that really ran — and
applies rules that are explainable, free, and gradeable. If a funded key
arrives, the model-backed variant is a drop-in behind the same interface and
the same measurement decides it.

The measurement, and the decision
----------------------------------
Graded on `verdict_corpus_v1` (72 items, 36 twin pairs) through
`scripts/run_verdict_eval.py`, deterministic mode, the only mode available
without a funded key:

    reviewer off   balanced accuracy 0.2500   auto-close precision  not measured
    reviewer on    balanced accuracy 0.2500   auto-close precision  not measured

**No improvement, so it stays off.** The reason is legible rather than
mysterious: the deterministic scorer produces no prose claims, so
`supporting_evidence`, `contradictory_evidence` and `groundedness` are all
`None` on every item — the contract reports them as *not evaluated*, which
is correct — and a reviewer whose inputs are all absent has nothing to act
on. It correctly abstains on all 72.

That is a measurement of the reviewer *on the only path available to
measure it*, not a measurement of the idea. Recorded as such. The row
returns to a decision when either a funded model or a corpus replayed
through the LLM path exists, and the one command is in the docs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

#: Verdicts the reviewer may demote *from*. A reviewer that could demote
#: `needs_review` would be moving a decision that is already with a human.
_CLOSEABLE = frozenset({"benign", "benign_true_positive", "false_positive"})

#: Below this, a model's own groundedness score is not a basis for closing.
#: Deliberately the same floor `_apply_groundedness_gate` already uses: a
#: second opinion about groundedness would be two controls disagreeing about
#: one number, and the quieter one would win silently.
GROUNDEDNESS_FLOOR = 0.75


def enabled() -> bool:
    """Whether the reviewer pass runs. Off unless an operator turned it on.

    Off because it was measured and did not help — see the module header —
    not because it is unfinished.
    """
    return os.getenv("AISOC_TRIAGE_REVIEWER", "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Review:
    """What the reviewer did, as a ledgerable record."""

    #: ``demote`` | ``escalate`` | ``abstain``. Never ``close``.
    action: str = "abstain"
    reasons: list[str] = field(default_factory=list)

    @property
    def changes_decision(self) -> bool:
        return self.action in {"demote", "escalate"}

    def as_payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reasons": list(self.reasons),
            # Stated on every record, including abstentions, so a reviewer
            # that has silently stopped firing is distinguishable from one
            # that ran and found nothing — the same argument the suppression
            # path records for its own refusals.
            "reviewed": True,
        }

    def summary(self) -> str:
        if not self.reasons:
            return "reviewer: abstained; the contract carried nothing to act on"
        return f"reviewer: {self.action} — {'; '.join(self.reasons)}"


def review(contract: dict[str, Any] | None) -> Review:
    """Re-read a decision contract and decide whether to move the decision.

    Pure, so the measurement drives the real function rather than a copy.
    Reads only fields `decision_contract` computed from signals that really
    ran; a `None` means *not evaluated* and is never treated as a negative
    result — collapsing "the signal did not run" into "the signal found
    nothing" is the distinction the contract's own docstring exists to
    protect.
    """
    if not contract:
        return Review()

    verdict = str(contract.get("verdict") or "").strip().lower()
    reasons: list[str] = []

    contradicted = contract.get("contradictory_evidence")
    if isinstance(contradicted, list) and contradicted:
        reasons.append(f"the contract lists {len(contradicted)} contradicted claim(s) behind this verdict")

    supporting = contract.get("supporting_evidence")
    if isinstance(supporting, list) and not supporting and verdict in _CLOSEABLE:
        # Ran and found nothing, which is not the same as not having run.
        reasons.append("claim support ran and found nothing supporting a closeable verdict")

    groundedness = contract.get("groundedness")
    if isinstance(groundedness, int | float) and float(groundedness) < GROUNDEDNESS_FLOOR and verdict in _CLOSEABLE:
        reasons.append(f"groundedness {float(groundedness):.2f} is below the {GROUNDEDNESS_FLOOR:.2f} floor")

    missing = contract.get("missing_prerequisites")
    if isinstance(missing, list) and missing and verdict in _CLOSEABLE:
        reasons.append(f"a prerequisite was missing: {missing[0]}")

    if not reasons:
        return Review()

    # One direction only. A reviewer that could move a decision toward
    # closure would be a second closure authority, and the whole design of
    # `authorize_auto_closure` is that there is exactly one.
    action = "demote" if verdict in _CLOSEABLE else "escalate"
    return Review(action=action, reasons=reasons)


def apply_review(contract: dict[str, Any] | None, *, auto_closed: bool) -> tuple[bool, Review]:
    """The reviewer's effect on the closure flag, and its record.

    Returns ``(auto_closed, review)``. The flag can only ever go **from**
    True **to** False here; it is returned rather than mutated so a caller
    cannot pass the review and forget the flag.
    """
    verdict_review = review(contract)
    if not verdict_review.changes_decision:
        return auto_closed, verdict_review
    if verdict_review.action == "demote" and auto_closed:
        logger.info("reviewer.demoted", reasons=verdict_review.reasons)
        return False, verdict_review
    return auto_closed, verdict_review

"""Whether the claims that license closing an alert trace to anything.

The gap this closes
-------------------
:mod:`app.confidence.groundedness` scores *indicator presence*: how many of
the IPs, hashes, CVEs, techniques and domains an output asserts appear in the
evidence. It is a real measurement and it is not the one a closure rests on.

A rationale can score a perfect 1.0 on it and still be unsupported, because
nothing stops a model reusing a valid indicator inside an invented
conclusion. Measured on the alert this module was written against::

    evidence:  {"src_ip": "198.51.100.14", "ports_contacted": 1024, ...}
    rationale: "Traffic from 198.51.100.14 is our approved vulnerability
                scanner, authorized under change CHG0049112."

Every indicator cited is in the evidence, so indicator grounding is 1.0 and
the groundedness gate passes it. The sentence that licenses the closure — that
the activity was *authorized* — is supported by nothing: there is no scanner,
no change record and no approval anywhere in what the model was shown. That
alert closes unattended on a 1.0 score for a measurement that was never about
the claim.

What a decisive claim is
------------------------
Narrowly: an affirmative assertion that the activity was **sanctioned** —
authorized, approved, scheduled maintenance, change-controlled, a known test,
or already reviewed and closed by a person. These are the claims that convert
"this happened" into "and that is fine", which is the step a human would be
asked to check. A rationale reasoning from the telemetry alone makes no such
claim and is not scored here; :attr:`ClaimSupportResult.score` is ``None`` in
that case rather than ``0.0``, because "nothing to trace" and "nothing traced"
are different findings and only one of them is about the model.

Three deliberate narrowings, each of which exists because the alternative
makes the check useless:

* **Negated and hedged mentions are not claims.** "There is no evidence this
  was authorized" is the model doing its job. A pattern set that flags it
  flags the most careful outputs the model produces, and a security control
  that punishes correct behaviour is one somebody disables within a week.
* **Support may come from first-party context, not only the alert payload.**
  The tenant's own compiled record of what analysts have repeatedly decided
  arrives in the prompt outside the untrusted fence and is exactly the
  authoritative source for "this is sanctioned here". Callers pass it as
  ``supporting_context``.
* **Explicit denial outranks a prior.** Evidence reading ``approved: false``
  or ``approval_status: revoked`` contradicts the claim, and no amount of
  general institutional memory rescues it. Contradiction is reported
  separately from absence because they are different problems: one is a model
  reaching past its evidence, the other is a model reaching against it.

This module is deterministic, pure and stdlib-only. It runs on every closure
decision, so it cannot afford a model call, and a non-deterministic check on
this path would make an auto-closure unreproducible.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.confidence.signals import SignalKind

__all__ = [
    "Claim",
    "ClaimKind",
    "ClaimSupportResult",
    "score_claim_support",
]

KIND = SignalKind.CLAIM_SUPPORT


class ClaimKind(str, Enum):
    """The families of claim that license a closure."""

    #: "authorized", "approved", "sanctioned", "permitted".
    AUTHORIZATION = "authorization"
    #: "scheduled maintenance", "change window", "planned patching".
    MAINTENANCE = "maintenance"
    #: A named change / ticket / RFC identifier.
    CHANGE_RECORD = "change_record"
    #: "an authorized penetration test", "a red-team exercise", "our scanner".
    SANCTIONED_TOOLING = "sanctioned_tooling"
    #: "an analyst already closed this", "previously reviewed as benign".
    PRIOR_REVIEW = "prior_review"


@dataclass(frozen=True)
class Claim:
    """One decisive assertion, and the sentence it was made in."""

    kind: ClaimKind
    phrase: str
    sentence: str


@dataclass(frozen=True)
class ClaimSupportResult:
    """What the rationale claimed, and what the evidence could show for it."""

    #: ``None`` when no decisive claim was made. Distinct from ``0.0``, which
    #: means claims were made and none of them traced to anything.
    score: float | None
    supported: tuple[Claim, ...] = ()
    unsupported: tuple[Claim, ...] = ()
    #: Claims the evidence explicitly denies. A strict subset of the claims
    #: that are not supported, surfaced separately because a denial is a
    #: stronger finding than a silence.
    contradicted: tuple[Claim, ...] = ()
    #: The evidence fields that did the contradicting, by name.
    contradicted_by: tuple[str, ...] = ()
    reason: str = ""

    @property
    def scored(self) -> bool:
        return self.score is not None

    @property
    def blocks_auto_close(self) -> bool:
        """Any unsupported or contradicted decisive claim withholds the closure.

        Not a threshold. A fraction would let a rationale make three
        well-evidenced claims and one invented one and still close on 0.75,
        and the invented one is the whole risk — these claims are not
        interchangeable evidence for a single conclusion, each is a separate
        reason the alert supposedly needs no human.
        """
        return bool(self.unsupported or self.contradicted)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": KIND.value,
            "scored": self.scored,
            "score": self.score,
            "supported": [c.phrase for c in self.supported],
            "unsupported": [c.phrase for c in self.unsupported],
            "contradicted": [c.phrase for c in self.contradicted],
            "contradicted_by": list(self.contradicted_by),
            "reason": self.reason,
        }


# ── Claim detection ──────────────────────────────────────────────────────────

#: Affirmative markers per family. Matched case-insensitively on word
#: boundaries. `\b` is used only where both sides are genuinely word
#: characters: an underscore is a word character, which is how a pattern
#: bounded that way once matched the middle of a filename.
_CLAIM_PATTERNS: tuple[tuple[ClaimKind, re.Pattern[str]], ...] = (
    (
        ClaimKind.AUTHORIZATION,
        re.compile(
            r"\b(?:authoris(?:ed|ation)|authoriz(?:ed|ation)|approved|approval|sanctioned|"
            r"permitted|whitelisted|allow-?listed|signed off|pre-?approved)\b",
            re.IGNORECASE,
        ),
    ),
    (
        ClaimKind.MAINTENANCE,
        re.compile(
            r"\b(?:scheduled maintenance|maintenance window|change window|planned (?:change|maintenance|patching|upgrade|reboot)|"
            r"routine (?:patching|maintenance)|scheduled (?:scan|job|task|reboot))\b",
            re.IGNORECASE,
        ),
    ),
    (
        ClaimKind.CHANGE_RECORD,
        # A change identifier the model names. Letters then digits with an
        # optional separator, which is what every ITSM in the corpus emits.
        re.compile(r"\b(?:CHG|CR|RFC|INC|TASK|CHANGE)[-_ ]?\d{3,}\b", re.IGNORECASE),
    ),
    (
        ClaimKind.SANCTIONED_TOOLING,
        re.compile(
            r"\b(?:penetration test|pen[- ]?test|red[- ]?team (?:exercise|engagement)|purple[- ]?team exercise|"
            r"(?:our|internal|corporate|company) (?:own )?(?:vulnerability )?scanner|authoris?ed scanner|authorized scanner)\b",
            re.IGNORECASE,
        ),
    ),
    (
        ClaimKind.PRIOR_REVIEW,
        re.compile(
            r"\b(?:previously (?:reviewed|triaged|closed)|already (?:reviewed|triaged|closed)|"
            r"an analyst (?:has )?(?:reviewed|confirmed|closed)|known false[- ]positive|"
            r"confirmed benign by)\b",
            re.IGNORECASE,
        ),
    ),
)

#: A sentence carrying one of these is not asserting the claim it mentions.
#: Checked on the sentence rather than near the phrase, because the negation
#: routinely sits at the far end of it ("nothing in the telemetry indicates
#: that this traffic was approved").
_NEGATION = re.compile(
    r"\b(?:no|not|never|nothing|none|cannot|can't|could not|couldn't|unable to|"
    r"without|lacks?|lacking|absent|unverified|unconfirmed|unsupported|unauthoris?ed|unauthorized|"
    r"may be|might be|possibly|appears to|seems to|if this|if the|would (?:be|have)|"
    r"unclear|uncertain|no evidence|claims to be|purports?)\b",
    re.IGNORECASE,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+")


# ── Evidence anchors ─────────────────────────────────────────────────────────

#: Evidence keys whose presence with a real value is affirmative support.
#: Keys rather than free text: a value that happens to contain the word
#: "approved" somewhere in an attacker-controlled field is not an approval,
#: and this check must not be steerable from the evidence it reads.
_SUPPORT_KEYS: dict[ClaimKind, tuple[str, ...]] = {
    ClaimKind.AUTHORIZATION: (
        "approved",
        "approved_by",
        "approver",
        "approval_id",
        "approval_status",
        "authorized",
        "authorised",
        "authorization",
        "authorisation",
        "exception_id",
        "sanctioned",
        "allowlisted",
        "whitelisted",
    ),
    ClaimKind.MAINTENANCE: (
        "maintenance_window",
        "in_maintenance_window",
        "change_window",
        "scheduled",
        "scheduled_job",
        "scheduled_task",
        # The claim pattern recognises "scheduled (scan|job|task|reboot)", so
        # the support keys must cover the same four nouns — they covered two.
        # An alert whose evidence recorded `scheduled_scan` could state the
        # claim the pattern knows and still be refused support by the keys,
        # found by the annotated measurement in
        # tests/test_claim_support_measured.py (case CS-15).
        "scheduled_scan",
        "scheduled_reboot",
        "planned_change",
    ),
    ClaimKind.CHANGE_RECORD: ("change_ticket", "change_id", "change_number", "ticket_id", "rfc_id", "cr_id"),
    ClaimKind.SANCTIONED_TOOLING: (
        "pentest",
        "pen_test",
        "penetration_test",
        "red_team",
        "purple_team",
        "scanner_id",
        "known_scanner",
        "authorized_scanner",
    ),
    ClaimKind.PRIOR_REVIEW: ("prior_disposition", "previous_disposition", "analyst_disposition", "reviewed_by", "closed_by"),
}

#: Families whose evidence also supports another family's claim.
#:
#: The decisive step every one of these makes is "and that was sanctioned", so
#: an approval record or a change record is evidence for it. Naming the tool —
#: "an approved red-team engagement under CHG0049112" — adds specificity, not
#: a second thing needing its own record, and demanding one would withhold a
#: closure that the evidence plainly supports.
#:
#: Two families deliberately have no fallback. A change identifier the model
#: *names* must be one the evidence carries, because a specific,
#: checkable-looking reference to a record that does not exist is the clearest
#: form of this defect. And a prior-review claim asserts that a person looked
#: at this before, which no amount of change paperwork establishes.
_SUPPORT_FALLBACK: dict[ClaimKind, tuple[ClaimKind, ...]] = {
    ClaimKind.AUTHORIZATION: (ClaimKind.CHANGE_RECORD,),
    ClaimKind.MAINTENANCE: (ClaimKind.CHANGE_RECORD, ClaimKind.AUTHORIZATION),
    ClaimKind.SANCTIONED_TOOLING: (ClaimKind.AUTHORIZATION, ClaimKind.CHANGE_RECORD),
    ClaimKind.CHANGE_RECORD: (),
    ClaimKind.PRIOR_REVIEW: (),
}

#: Values that mean a support key is present and says *no*. Lower-cased.
_DENIALS = frozenset(
    {"false", "no", "none", "null", "nil", "n/a", "na", "unknown", "", "0", "revoked", "expired", "denied", "rejected", "pending"}
)

#: Keys whose truthiness inverts: `outside_change_window: true` denies.
_INVERTED_KEYS = frozenset({"outside_change_window", "unapproved", "unauthorized", "unauthorised", "unscheduled"})


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    """Every scalar in a nested evidence structure, under a dotted key path.

    Flattened rather than walked per lookup so the same view serves both the
    support check and the contradiction check, and so a key nested under
    `raw_event` is reachable — connectors nest the vendor payload one level
    down, and a check that only read the top level would find an approval
    field on none of them.
    """
    flat: dict[str, Any] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict | list):
                flat.update(_flatten(value, path))
            else:
                flat[path] = value
    elif isinstance(node, list):
        for index, value in enumerate(node):
            flat.update(_flatten(value, f"{prefix}[{index}]"))
    return flat


def _leaf(path: str) -> str:
    return path.rsplit(".", 1)[-1].split("[", 1)[0].lower()


def _is_denial(key: str, value: Any) -> bool:
    inverted = _leaf(key) in _INVERTED_KEYS
    if isinstance(value, bool):
        return value if inverted else not value
    text = str(value).strip().lower()
    if inverted:
        return text not in _DENIALS
    return text in _DENIALS


def _claims(rationale: str) -> list[Claim]:
    found: list[Claim] = []
    for sentence in _SENTENCE_SPLIT.split(rationale or ""):
        stripped = sentence.strip()
        if not stripped or _NEGATION.search(stripped):
            continue
        for kind, pattern in _CLAIM_PATTERNS:
            match = pattern.search(stripped)
            if match:
                found.append(Claim(kind=kind, phrase=match.group(0), sentence=stripped))
    return found


def _identifiers(text: str) -> set[str]:
    """Change-record identifiers named in a piece of text, normalised."""
    return {re.sub(r"[-_ ]", "", m.group(0)).upper() for m in _CLAIM_PATTERNS[2][1].finditer(text or "")}


def score_claim_support(
    rationale: str,
    evidence: dict[str, Any] | None,
    *,
    supporting_context: str | None = None,
) -> ClaimSupportResult:
    """Trace every decisive claim in ``rationale`` to the evidence, or refuse it.

    ``evidence`` is the alert payload the model was shown. ``supporting_context``
    is first-party text that also reached the prompt — compiled institutional
    memory, the tenant's recent analyst decisions, the directory record — which
    is authoritative for "this is sanctioned here" and does not live in the
    payload.
    """
    claims = _claims(rationale)
    if not claims:
        return ClaimSupportResult(score=None, reason="no decisive claim to trace")

    flat = _flatten(evidence or {})
    present: dict[str, Any] = {}
    denied: dict[str, Any] = {}
    for path, value in flat.items():
        leaf = _leaf(path)
        if _is_denial(path, value):
            denied[leaf] = value
        else:
            present[leaf] = value

    context_text = (supporting_context or "").strip()
    evidence_identifiers = _identifiers(json.dumps(evidence or {}, default=str)) | _identifiers(context_text)

    supported: list[Claim] = []
    unsupported: list[Claim] = []
    contradicted: list[Claim] = []
    contradicting_fields: set[str] = set()

    for claim in claims:
        keys = _SUPPORT_KEYS[claim.kind]
        denials = [k for k in keys if k in denied]
        if denials:
            contradicted.append(claim)
            contradicting_fields.update(denials)
            continue

        if claim.kind is ClaimKind.CHANGE_RECORD:
            # Checked before the key lookup, and deliberately not by it. A
            # change id the model *named* has to be the one the evidence
            # carries: an alert holding `change_ticket: CHG0041122` does not
            # support a rationale citing CHG0049112, and a presence check
            # would call it supported. A specific, checkable-looking
            # reference to a record that does not exist is the clearest form
            # of this defect.
            named = _identifiers(claim.sentence)
            if named and named <= evidence_identifiers:
                supported.append(claim)
            else:
                unsupported.append(claim)
            continue

        # Own family first, then the families that subsume it. Denial is
        # checked on the own family only: a revoked approval contradicts an
        # authorization claim, while a missing `red_team` key is silence.
        fallback_keys = tuple(k for kind in _SUPPORT_FALLBACK[claim.kind] for k in _SUPPORT_KEYS[kind])
        if any(k in present for k in keys) or any(k in present for k in fallback_keys):
            supported.append(claim)
            continue

        # First-party context is authoritative for "this is sanctioned here",
        # but only when it is about this claim's family. A general note about
        # the tenant does not approve an arbitrary action.
        if context_text and any(pattern.search(context_text) for kind, pattern in _CLAIM_PATTERNS if kind is claim.kind):
            supported.append(claim)
            continue

        unsupported.append(claim)

    total = len(claims)
    score = round(len(supported) / total, 4) if total else None

    if contradicted:
        reason = (
            f"Verdict withheld: the rationale asserts {contradicted[0].phrase!r}, and the evidence says otherwise "
            f"({', '.join(sorted(contradicting_fields))})."
        )
    elif unsupported:
        reason = (
            f"Verdict withheld: {len(unsupported)} of {total} decisive claim(s) trace to nothing in the evidence "
            f"(unsupported: {', '.join(sorted({c.phrase for c in unsupported}))})."
        )
    else:
        reason = f"all {total} decisive claim(s) trace to the evidence"

    return ClaimSupportResult(
        score=score,
        supported=tuple(supported),
        unsupported=tuple(unsupported),
        contradicted=tuple(contradicted),
        contradicted_by=tuple(sorted(contradicting_fields)),
        reason=reason,
    )

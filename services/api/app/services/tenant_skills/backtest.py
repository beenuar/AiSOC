"""Read a skill's two backtest runs and compare them over the alerts it matches.

Fix-pass 3.8.

Activation used to read two UUIDs and a version number. Nothing opened the
runs those ids name, so a skill activated identically whether the backtest had
completed, crashed, or was still queued, and whether the window it graded
contained a single alert the skill applies to.

Why the subset is the whole point
---------------------------------
Both runs cover the same window, so a headline difference between them is an
average over every alert in it. A skill matches a shape of alert, usually a
handful out of hundreds. Suppose four matched alerts out of twenty: a skill
that corrects every one of them moves the headline by 0.20, and a skill that
breaks every one of them moves it by -0.20, and both figures sit inside the
noise of any real queue. Averaged over a few hundred findings neither is
visible at all. The comparison that describes the *skill* is over the alerts
the skill selects, and it is the one activation is allowed to rest on.

So the gate is: both runs completed, and the matched subset is not empty. The
gate is deliberately **not** on the value of the delta. A threshold would be a
target to tune a skill against, and an organisational fact that happens not to
move last quarter's verdicts is still true about the estate.

How "the alerts the skill matches" is decided, and what that is not
--------------------------------------------------------------------
From the skill's own ``match`` block, evaluated against the evidence each
replay decision recorded: the rule id, the ATT&CK techniques, the connector
the alert came from, and the title the agent was handed as its summary. Those
are the four conditions :func:`app.context.tenant_skills.select_skill` scores
on in the agents service, read from the same places.

It is **not** a record of which alerts triage actually applied the skill to. A
replay decision does not carry the skill that steered it, so that record does
not exist to read. The difference is that agents-side selection also arbitrates
between competing skills, and a tenant whose more specific skill wins on the
same alert would have had that one applied. This subset is therefore the
skill's declared scope, which can be wider than the set production steered,
never narrower. Widening dilutes the delta toward the whole-window figure; it
cannot manufacture a match for a skill that selects nothing.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.aisoc_benchmark.replay import ABSTENTION_VERDICTS
from app.services.tenant_skills.models import SkillMatch

__all__ = [
    "COMPLETED",
    "MatchedDelta",
    "match_from_body",
    "matched_delta",
    "selects",
]

#: The terminal status a run reaches when it produced a report.
#: ``app.services.replay_evaluation.store`` writes it; this module only reads.
COMPLETED = "completed"

#: Nothing useful comes of comparing more than this, and a window larger than
#: it was truncated when the decisions were stored: ``list_decisions`` caps at
#: the same figure. Stated here so the two cannot drift into disagreeing about
#: how much of a long window the comparison saw.
MAX_DECISIONS = 2000


@dataclass(frozen=True)
class MatchedDelta:
    """What the two runs say about the alerts one skill selects.

    Every mean carries the count it was computed over, and an accuracy with no
    labelled alert behind it is ``None`` rather than ``0.0``: a zero in an
    accuracy column says the agent got every one of these wrong, which is a
    different fact from no analyst having said.
    """

    #: Decisions the two runs have in common, matched or not. The denominator
    #: the old whole-window reading used. Not "graded": it counts unlabelled
    #: findings too, and an accuracy denominator that quietly includes them
    #: is how a rate comes to describe more rows than anybody scored.
    window_compared: int
    #: Of those, the ones this skill's match block selects.
    matched: int
    #: Of those, the ones an analyst labelled and *both* runs answered.
    matched_graded: int
    #: Matched findings the two runs disagree about. Computable with no
    #: labels at all, and the only figure that is zero exactly when the skill
    #: changed nothing on the alerts it applies to.
    verdicts_changed: int

    baseline_accuracy: float | None
    candidate_accuracy: float | None
    accuracy_delta: float | None

    #: The same comparison over the whole window, kept beside the matched one
    #: rather than dropped. The gap between the two is what this module exists
    #: to make visible.
    window_accuracy_delta: float | None

    #: Set when activation must refuse, and phrased for the operator. ``None``
    #: means the comparison stands.
    blocked_reason: str | None = None

    def as_log_fields(self) -> dict[str, Any]:
        return {
            "window_compared": self.window_compared,
            "matched": self.matched,
            "matched_graded": self.matched_graded,
            "verdicts_changed": self.verdicts_changed,
            "baseline_accuracy": self.baseline_accuracy,
            "candidate_accuracy": self.candidate_accuracy,
            "accuracy_delta": self.accuracy_delta,
            "window_accuracy_delta": self.window_accuracy_delta,
        }


def _blocked(reason: str) -> MatchedDelta:
    return MatchedDelta(
        window_compared=0,
        matched=0,
        matched_graded=0,
        verdicts_changed=0,
        baseline_accuracy=None,
        candidate_accuracy=None,
        accuracy_delta=None,
        window_accuracy_delta=None,
        blocked_reason=reason,
    )


def match_from_body(body: Mapping[str, Any]) -> SkillMatch:
    """Just the match block out of a stored skill, with its parse-time casing.

    Narrower than :func:`app.services.tenant_skills.models.skill_from_body` on
    purpose. That one rebuilds the whole document and raises on a body with no
    expiry; this runs on the activation path, where a parse error would reach
    the route as a 500 rather than as the 409 every other refusal produces,
    and nothing here reads a field outside ``match``.
    """
    raw = body.get("match")
    raw = raw if isinstance(raw, Mapping) else {}

    def _strings(key: str, *, upper: bool = False, lower: bool = False) -> tuple[str, ...]:
        values = raw.get(key)
        if not isinstance(values, list):
            return ()
        out = []
        for item in values:
            if not isinstance(item, str) or not item.strip():
                continue
            text_value = item.strip()
            out.append(text_value.upper() if upper else text_value.lower() if lower else text_value)
        return tuple(out)

    return SkillMatch(
        techniques=_strings("techniques", upper=True),
        rule_ids=_strings("rule_ids"),
        sources=_strings("sources", lower=True),
        keywords=_strings("keywords", lower=True),
    )


def selects(match: SkillMatch, decision: Mapping[str, Any]) -> bool:
    """Whether this skill's match block applies to one replayed decision.

    The four conditions are read the way the agents-side selector reads them,
    including the casing each is normalised to at parse time and the rule that
    a skill written against a parent technique matches a sub-technique alert.
    Scoring is absent on purpose: the selector ranks several skills against one
    alert, and the question here is whether this one skill applies at all.
    """
    evidence = decision.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}

    rule_id = str(decision.get("rule_id") or evidence.get("rule_id") or "").strip()
    if rule_id and rule_id in match.rule_ids:
        return True

    mapped = {str(t).upper() for t in (evidence.get("mitre_techniques") or []) if str(t).strip()}
    for technique in match.techniques:
        if any(m == technique or m.startswith(technique + ".") for m in mapped):
            return True

    source = str(evidence.get("connector_type") or evidence.get("source") or decision.get("vendor") or "").strip().lower()
    if source and source in match.sources:
        return True

    # The title is what ``build_state`` puts in ``alert_summary``, which is the
    # string the selector searches, so a keyword that would hit in production
    # hits here.
    title = str(evidence.get("title") or "").lower()
    return bool(title) and any(keyword in title for keyword in match.keywords)


def _answered(decision: Mapping[str, Any]) -> bool:
    """A graded answer: labelled, not an abstention, and not a refusal.

    ``ABSTENTION_VERDICTS`` comes from the replay scorer rather than from a
    second list here, so an alert excluded from the published accuracy is
    excluded from this one.
    """
    if not decision.get("labelled") or decision.get("error"):
        return False
    return str(decision.get("verdict") or "") not in ABSTENTION_VERDICTS


def _accuracy(decisions: list[Mapping[str, Any]]) -> tuple[int, float | None]:
    answered = [d for d in decisions if _answered(d)]
    if not answered:
        return 0, None
    correct = sum(1 for d in answered if d.get("verdict") == d.get("expected_disposition"))
    return len(answered), correct / len(answered)


def compare(
    match: SkillMatch,
    baseline: list[Mapping[str, Any]],
    candidate: list[Mapping[str, Any]],
) -> MatchedDelta:
    """Pair two runs' decisions by finding and compare the matched ones.

    Pairing by ``finding_id`` rather than by position: the two runs grade the
    same window, but a normalisation failure on one side drops a decision, and
    comparing two lists of different lengths by index would silently compare
    different alerts.
    """
    by_finding = {str(d.get("finding_id") or ""): d for d in baseline}
    pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for row in candidate:
        other = by_finding.get(str(row.get("finding_id") or ""))
        if other is not None:
            pairs.append((other, row))

    matched = [(b, c) for b, c in pairs if selects(match, c)]

    # Each side scored over its own answered rows, because this figure exists
    # to reproduce the gap between the two published headlines, and those are
    # computed independently, one per report.
    _, window_baseline_accuracy = _accuracy([b for b, _ in pairs])
    _, window_candidate_accuracy = _accuracy([c for _, c in pairs])
    window_delta = (
        window_candidate_accuracy - window_baseline_accuracy
        if window_baseline_accuracy is not None and window_candidate_accuracy is not None
        else None
    )

    # One denominator for both sides of the matched comparison, unlike the
    # window figure above: over a handful of alerts a finding only one run
    # answered would move the delta without either agent having changed its
    # mind about anything.
    gradable = [(b, c) for b, c in matched if _answered(b) and _answered(c)]
    _, baseline_accuracy = _accuracy([b for b, _ in gradable])
    _, candidate_accuracy = _accuracy([c for _, c in gradable])
    accuracy_delta = candidate_accuracy - baseline_accuracy if baseline_accuracy is not None and candidate_accuracy is not None else None

    return MatchedDelta(
        window_compared=len(pairs),
        matched=len(matched),
        matched_graded=len(gradable),
        verdicts_changed=sum(1 for b, c in matched if b.get("verdict") != c.get("verdict")),
        baseline_accuracy=baseline_accuracy,
        candidate_accuracy=candidate_accuracy,
        accuracy_delta=accuracy_delta,
        window_accuracy_delta=window_delta,
        blocked_reason=None,
    )


async def matched_delta(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    match: SkillMatch,
    baseline_evaluation_id: uuid.UUID | None,
    candidate_evaluation_id: uuid.UUID | None,
) -> MatchedDelta:
    """The comparison, or the reason there is none to make."""
    if baseline_evaluation_id is None or candidate_evaluation_id is None:  # pragma: no cover - the caller checks first
        return _blocked("this skill has no backtest attached")

    for label, evaluation_id in (("baseline", baseline_evaluation_id), ("candidate", candidate_evaluation_id)):
        status, error = await _evaluation_state(db, tenant_id=tenant_id, evaluation_id=evaluation_id)
        if status is None:
            return _blocked(
                f"the attached {label} backtest names replay run {evaluation_id} and this tenant has no such "
                f"replay run. Re-run the backtest: activation reads both reports, and an id pointing at "
                f"nothing cannot be read."
            )
        if status != COMPLETED:
            if status == "failed":
                return _blocked(
                    f"the {label} backtest run failed and graded nothing: {error or 'no reason was recorded'}. "
                    f"Fix that and re-run the backtest. Activating on a failed run would put this skill in "
                    f"front of every matching alert on the strength of a measurement that never happened."
                )
            return _blocked(
                f"the {label} backtest run has not finished; it is {status}. Wait for both runs to complete, "
                f"then activate. Nothing is wrong with the skill."
            )

    baseline = await _decisions(db, tenant_id=tenant_id, evaluation_id=baseline_evaluation_id)
    candidate = await _decisions(db, tenant_id=tenant_id, evaluation_id=candidate_evaluation_id)
    delta = compare(match, baseline, candidate)

    if delta.matched == 0:
        if delta.window_compared == 0:
            return _blocked(
                "both backtest runs completed and recorded no decisions in common, so there is nothing to "
                "compare. Re-run the backtest over a window that holds closed findings."
            )
        return _blocked(
            f"the backtest compared {delta.window_compared} alerts across the two runs and this skill's "
            f"match block selects none of them, so the difference between the two reports is entirely over "
            f"alerts this skill never touches. Re-run the backtest over a window containing alerts this "
            f"skill matches, or widen the match block to the alerts you meant."
        )
    return delta


async def _evaluation_state(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    evaluation_id: uuid.UUID,
) -> tuple[str | None, str | None]:
    """One run's status and failure reason, or ``(None, None)`` when it is gone.

    Tenant-scoped in the predicate rather than by RLS alone, the same way every
    other read of this table is: another tenant's run must read as absent.
    """
    row = (
        await db.execute(
            text("SELECT status, error FROM aisoc_replay_evaluations WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=evaluation_id, tenant_id=tenant_id
            )
        )
    ).fetchone()
    if row is None:
        return None, None
    return str(row.status), (str(row.error)[:400] if row.error else None)


async def _decisions(db: AsyncSession, *, tenant_id: uuid.UUID, evaluation_id: uuid.UUID) -> list[Mapping[str, Any]]:
    """Every decision one run recorded, as the dicts the runner wrote.

    Ordered by ``finding_id`` so a truncated read takes the same prefix from
    both runs: comparing the first two thousand of one against a differently
    ordered first two thousand of the other would pair alerts that are not the
    same alert.
    """
    rows = (
        await db.execute(
            text(
                "SELECT decision FROM aisoc_replay_decisions "
                "WHERE evaluation_id = :evaluation_id AND tenant_id = :tenant_id "
                "ORDER BY finding_id LIMIT :limit"
            ).bindparams(evaluation_id=evaluation_id, tenant_id=tenant_id, limit=MAX_DECISIONS)
        )
    ).fetchall()
    return [parsed for row in rows if (parsed := _as_mapping(row.decision)) is not None]


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    """Read a JSONB column back, whatever the driver handed over.

    Same reader as ``replay_evaluation.store``: these statements go through
    ``text()``, so the value arrives parsed on one driver and as a string on
    another, and a row that is neither is skipped rather than guessed at.
    """
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return value if isinstance(value, Mapping) else None

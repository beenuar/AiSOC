"""Tie every factual claim in a copilot answer to the record behind it.

Parity 3.6, the half that decides whether the rest is worth having.

The copilot answers questions about a customer's own estate. An answer
that names a host, an IP or a CVE is making a claim about their network,
and the analyst reading it has no way to tell a claim drawn from the
evidence from one the model produced because it sounded right. So every
checkable claim either cites the record it came from, or the answer says
plainly that it does not.

What counts as a checkable claim
----------------------------------
Exactly what `app.confidence.groundedness` already counts: IPs, hashes,
CVEs, MITRE techniques and domains. Deliberately the same extractor,
imported rather than re-implemented, for the reason
`aisoc_benchmark.replay` records about its own reuse — a second
definition of "checkable" would eventually disagree with the first, and
the two numbers would stop being comparable while still looking like
they were.

Prose is not a claim. "This looks like credential access" cites nothing
and needs no citation; "198.51.100.4 contacted the domain controller"
does.

What a citation points at
---------------------------
A ledger entry — a run and a sequence number — or an alert id. Both are
things an analyst can open. A citation that pointed at a paragraph of
context the console happened to send would be unfalsifiable: there would
be nothing to go and look at.

Why "uncited" is a first-class outcome
----------------------------------------
The tempting design is to suppress uncited claims, or to quietly drop
them from the answer. Both are worse than saying so. An analyst who sees
*"this part is not supported by anything I was given"* can go and check;
one who sees a confident sentence with the unsupported half silently
removed has been handed a different answer than the model gave, by
something that cannot reliably tell which half was wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.confidence.groundedness import _extract

__all__ = [
    "Citation",
    "GroundedAnswer",
    "EvidenceSource",
    "ground_answer",
]


@dataclass(frozen=True)
class EvidenceSource:
    """One record the copilot was given, and how to open it.

    `ref` is what the console turns into a link. `kind` says which store
    it came from so a reader knows whether they are looking at an
    immutable ledger row or a mutable alert.
    """

    #: `ledger:<run_id>#<seq>`, `alert:<uuid>`, or `case:<uuid>`.
    ref: str
    kind: str
    #: Everything the source said, flattened. Indicators are matched
    #: against this.
    text: str
    label: str | None = None


@dataclass(frozen=True)
class Citation:
    """One checkable claim, and the sources that actually contain it."""

    claim: str
    refs: tuple[str, ...]


@dataclass(frozen=True)
class GroundedAnswer:
    """A copilot reply, graded against what it was given."""

    #: Claims found in at least one source.
    citations: tuple[Citation, ...] = field(default_factory=tuple)
    #: Claims found in none of them. The reason this type exists.
    uncited: tuple[str, ...] = field(default_factory=tuple)
    #: True when the answer made no checkable claim at all. Distinct from
    #: "every claim was cited": an answer that asserts nothing concrete
    #: is not grounded, it is simply not checkable, and reporting it as
    #: grounded would make the label meaningless on exactly the prose
    #: answers where it should be silent.
    no_claims: bool = False

    @property
    def fully_cited(self) -> bool:
        """Every checkable claim cites something. False when any did not."""
        return not self.uncited and not self.no_claims

    @property
    def label(self) -> str:
        """What the console shows beside the answer.

        Three outcomes, not two, because "asserted nothing" and "asserted
        things and supported all of them" deserve different words.
        """
        if self.no_claims:
            return "no checkable claims"
        if self.uncited:
            return "partially uncited" if self.citations else "uncited"
        return "cited"

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "fully_cited": self.fully_cited,
            "no_claims": self.no_claims,
            "citations": [{"claim": c.claim, "refs": list(c.refs)} for c in self.citations],
            "uncited": list(self.uncited),
        }


def ground_answer(answer: str, sources: list[EvidenceSource]) -> GroundedAnswer:
    """Grade one answer against the records it was given.

    Returns rather than raises on an ungrounded answer: refusing to show
    it would hide the model's actual output from the person best placed
    to judge it. The label is what carries the warning.
    """
    claims = _extract(answer or "")
    if not claims:
        return GroundedAnswer(no_claims=True)

    # Each source's indicators, extracted once rather than per claim.
    by_source = [(source.ref, _extract(source.text or "")) for source in sources]

    citations: list[Citation] = []
    uncited: list[str] = []
    for claim in sorted(claims):
        refs = tuple(ref for ref, found in by_source if claim in found)
        if refs:
            citations.append(Citation(claim=claim, refs=refs))
        else:
            uncited.append(claim)

    return GroundedAnswer(citations=tuple(citations), uncited=tuple(uncited))


def sources_from_ledger(rows: list[dict[str, Any]]) -> list[EvidenceSource]:
    """Turn ledger event rows into citable sources.

    `ledger:<run>#<seq>` rather than the event's own uuid, because that
    is the coordinate `aisoc_explain_step` and the console's replay view
    both address a step by. A citation an analyst cannot paste somewhere
    is not much of a citation.
    """
    sources: list[EvidenceSource] = []
    for row in rows:
        run_id = row.get("run_id")
        seq = row.get("seq")
        if run_id is None or seq is None:
            continue
        sources.append(
            EvidenceSource(
                ref=f"ledger:{run_id}#{seq}",
                kind="ledger",
                label=str(row.get("summary") or row.get("kind") or ""),
                # Summary and payload both: an indicator can appear in
                # either, and a citation that missed the payload would
                # call a supported claim uncited.
                text=f"{row.get('summary') or ''} {row.get('payload') or ''}",
            )
        )
    return sources


def sources_from_context(context: dict[str, Any] | None) -> list[EvidenceSource]:
    """Turn the page context the console sends into citable sources.

    Only the parts that carry an identifier. A free-text page title is
    context for the model and is deliberately *not* citable: pointing a
    citation at it would give the analyst nothing to open.
    """
    if not isinstance(context, dict):
        return []
    sources: list[EvidenceSource] = []
    for key, prefix in (("alert", "alert"), ("case", "case"), ("alerts", "alert")):
        value = context.get(key)
        items = value if isinstance(value, list) else [value] if value else []
        for item in items:
            if not isinstance(item, dict):
                continue
            identifier = item.get("id")
            if not identifier:
                continue
            sources.append(
                EvidenceSource(
                    ref=f"{prefix}:{identifier}",
                    kind=prefix,
                    label=str(item.get("title") or ""),
                    text=repr(item),
                )
            )
    return sources

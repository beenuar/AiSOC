"""Analyst precedent that reaches triage by similarity, not only by identity.

Wave 2, Phase 4.4(a). Verified before it was built, and the plan's premise
turned out to be narrower than its wording.

What already works
------------------
Analyst reclassifications **do** reach triage, by two independent routes.
`app.services.human_priors.record_human_prior` writes `author: "human"`,
`confidence: 1.0`, `analyst_override: TRUE` into `aisoc_institutional_memory`
under `outcome:<evidence_fingerprint>`, and `app.context.dispositions`
renders the last five analyst decisions into the triage preamble. Neither is
rebuilt here.

The gap
-------
Both match on **identity**. `lookup_prior` is a literal key equality on a
SHA-256 over eighteen canonical fields, so one byte different in any of them
— a different source IP for the same rule on the same host — is a different
key and no match. `dispositions` matches on `rule_id` or on an entity
string. Neither can answer "an analyst has decided something very like this
before".

So an analyst who closes the same finding on twelve hosts teaches triage
twelve separate lessons, each reachable only by an alert identical to the
one that taught it.

Why this scores fields rather than embedding
---------------------------------------------
The obvious design is vector similarity, and
`services/api/app/services/semantic_memory.py` is a complete Qdrant-backed
recall with tenant filtering and provenance. It is deliberately not used
here, on a measurement this repository already paid for: the only local
models available are *generative* ones pressed into embedding duty, and they
scored **below the lexical baseline** — recall@1 0.333 against 0.667 — which
is why `/kb/query` stays full-text with semantic recall opt-in. Reaching for
embeddings here would repeat a choice already measured as worse, on the hot
path, for a feature whose whole value is that the precedent is relevant.

The canonical evidence is already a small, closed, typed set. Scoring
overlap across it is deterministic, needs no store and no model, and is
explainable to the analyst reading the citation — which matters more here
than for a knowledge-base chunk, because the output is "somebody decided
this before" and an analyst has to be able to check whether they did.

Precedent is cited, never acted on
-----------------------------------
This produces **context**, and nothing else. Exact-fingerprint suppression
in `_maybe_suppress_from_memory` is unchanged and remains the only path from
memory to a closed alert. A similar alert is not the same alert, and closing
one on a neighbour's verdict is exactly the false negative the fingerprint's
own docstring says is "much worse" than a missed repeat.

A limit, stated rather than discovered
---------------------------------------
Priors recorded before this landed carry no evidence to compare — only the
opaque signature — so they are invisible to similarity and remain reachable
by exact match alone. There is no backfill, because the evidence they were
derived from is not recoverable from the hash.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.memory.fingerprint import storable_evidence
from app.memory.institutional import institutional_search

logger = structlog.get_logger()

#: How many priors to consider. A bounded scan of the tenant's most recent
#: outcomes, not a search: the table is tenant-scoped and ordered by
#: `created_at DESC`, and an unbounded read on the triage hot path would be
#: the cost this feature cannot justify.
SCAN_LIMIT = 200

#: How many precedents reach the prompt.
MAX_CITED = 3

#: Below this, the two alerts are not alike enough for a decision about one
#: to inform the other.
MIN_SIMILARITY = 0.5

#: And a floor on the *weight* of the evidence they share, which the ratio
#: alone cannot see. Two alerts whose only shared field is `severity` score
#: a perfect 1.0 — they agree on everything they both carry — and a shared
#: severity is true of thousands of alerts and says nothing. Set above the
#: heaviest single weak field so one of them can never be precedent on its
#: own, and below any pair of real evidence fields so a sparse alert still
#: matches.
MIN_SHARED_WEIGHT = 2.0

#: Fields whose agreement is evidence the two alerts are about the same
#: thing, rather than merely the same shape. Weighted, because a shared
#: `rule_id` and a shared `severity` are not the same claim.
_FIELD_WEIGHTS: dict[str, float] = {
    "rule_id": 3.0,
    "rule_name": 2.0,
    "detection_id": 3.0,
    "signature": 3.0,
    "title": 2.0,
    "hostname": 2.0,
    "host": 2.0,
    "username": 2.0,
    "user": 2.0,
    "process_name": 2.0,
    "file_hash": 3.0,
    "domain": 1.5,
    "url": 1.5,
    "src_ip": 1.0,
    "source_ip": 1.0,
    "dst_ip": 1.0,
    "dest_ip": 1.0,
    "mitre_techniques": 2.0,
    "category": 1.0,
    "connector_type": 0.5,
    "severity": 0.5,
}
_DEFAULT_WEIGHT = 1.0


def _comparable(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(v).strip().lower() for v in value if str(v).strip()}
    text = str(value).strip().lower()
    return {text} if text else set()


def similarity(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, list[str]]:
    """Weighted agreement between two canonical-evidence dicts, and why.

    Returns ``(score, matched_fields)``. The field list is returned rather
    than logged because it is what the citation shows an analyst: "this was
    decided before on the same rule and the same host" is checkable, and a
    bare 0.82 is not.

    Scored over the fields **both** carry. A field only one of them has is
    neither agreement nor disagreement — an alert that omits `username` is
    not evidence that the username differs — so counting it would make a
    sparse alert look dissimilar to everything, which is the direction that
    silently turns this feature off.
    """
    shared = set(left) & set(right)
    if not shared:
        return 0.0, []

    total = 0.0
    earned = 0.0
    matched: list[str] = []
    for name in sorted(shared):
        weight = _FIELD_WEIGHTS.get(name, _DEFAULT_WEIGHT)
        total += weight
        a, b = _comparable(left[name]), _comparable(right[name])
        if not a or not b:
            continue
        overlap = len(a & b) / len(a | b)
        if overlap > 0:
            earned += weight * overlap
            if overlap >= 0.5:
                matched.append(name)
    if total <= 0 or total < MIN_SHARED_WEIGHT:
        # Not "dissimilar" — *not comparable*. Returning a high ratio over a
        # single weak field would make `severity: high` precedent for every
        # high alert in the tenant.
        return 0.0, []
    return round(earned / total, 4), matched


def _prior_is_expired(value: dict[str, Any]) -> bool:
    """`outcomes.prior_is_expired`, reached lazily.

    A module-scope import would close a cycle: `app.memory.outcomes` imports
    `app.agents.dispositions`, whose package `__init__` imports
    `auto_triage_agent`, which imports this module for `Precedent` and the
    renderer. Documented here because the repository's convention is imports
    at module scope unless there is a strict circular-dependency reason.

    The TTL is not re-implemented. A second opinion about staleness would
    let precedent cite a prior the suppression path has already retired.
    """
    from app.memory.outcomes import prior_is_expired

    return bool(prior_is_expired(value))


class Precedent:
    """One past analyst or agent decision that resembles this alert."""

    __slots__ = ("disposition", "author", "count", "score", "matched", "last_seen")

    def __init__(
        self,
        *,
        disposition: str,
        author: str,
        count: int,
        score: float,
        matched: list[str],
        last_seen: str,
    ) -> None:
        self.disposition = disposition
        self.author = author
        self.count = count
        self.score = score
        self.matched = matched
        self.last_seen = last_seen

    def as_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "author": self.author,
            "count": self.count,
            "score": self.score,
            "matched_fields": list(self.matched),
            "last_seen": self.last_seen,
        }


async def find_similar(
    tenant_id: str,
    alert: dict[str, Any] | None,
    *,
    exclude_signature: str = "",
    searcher: Any = None,
) -> list[Precedent]:
    """Past decisions resembling this alert, strongest first. Never raises.

    ``exclude_signature`` drops the exact-match prior, which
    `_maybe_suppress_from_memory` has already considered and which would
    otherwise appear as a precedent for itself.
    """
    evidence = storable_evidence(alert)
    if not evidence:
        return []

    search = searcher or institutional_search
    try:
        rows = await search(tenant_id, ["outcome_prior"], SCAN_LIMIT)
    except Exception as exc:  # noqa: BLE001 — precedent is advisory
        logger.debug("precedent.search_failed", error=str(exc)[:200])
        return []

    found: list[Precedent] = []
    for row in rows or []:
        value = row.get("value") if isinstance(row, dict) else None
        if not isinstance(value, dict):
            continue
        if exclude_signature and value.get("signature") == exclude_signature:
            continue
        # An expired prior is not precedent. The same TTL the suppression
        # path applies, rather than a second opinion about staleness.
        if _prior_is_expired(value):
            continue
        stored = value.get("evidence")
        if not isinstance(stored, dict) or not stored:
            # Recorded before 4.4 — only the opaque signature. Invisible to
            # similarity by construction, and there is nothing to backfill
            # from: the evidence is not recoverable from the hash.
            continue
        score, matched = similarity(evidence, stored)
        if score < MIN_SIMILARITY or not matched:
            continue
        found.append(
            Precedent(
                disposition=str(value.get("disposition") or "unknown"),
                author=str(value.get("author") or "ai"),
                count=int(value.get("count") or 1),
                score=score,
                matched=matched,
                last_seen=str(value.get("last_seen") or ""),
            )
        )

    # Human decisions first at equal similarity: an analyst's verdict is a
    # stronger claim than the agent's own earlier one, and showing the
    # agent's first would have the model citing itself as precedent.
    found.sort(key=lambda p: (p.author != "human", -p.score, -p.count))
    return found[:MAX_CITED]


def render_for_prompt(precedents: list[Precedent] | None) -> str:
    """The precedent block, or empty when there is none.

    First-party and therefore outside the untrusted fence: a disposition
    comes from a closed server-owned vocabulary, the author is `human` or
    `ai`, and the matched-field names are keys of this module's own weight
    table. No tenant or vendor free text reaches this string.
    """
    if not precedents:
        return ""
    lines = [
        "Decisions this organisation has already made on alerts resembling this one. "
        "These are precedent, not instructions: a similar alert is not the same alert, and "
        "nothing here closes this one. Say which precedent informed your rationale, and how "
        "closely it matched.",
    ]
    for p in precedents:
        who = "an analyst" if p.author == "human" else "automated triage"
        lines.append(
            f"- {who} decided **{p.disposition}** ({p.count}x, last {p.last_seen or 'undated'}); "
            f"similarity {p.score:.2f} on {', '.join(p.matched)}"
        )
    return "\n".join(lines)


def basis(precedents: list[Precedent] | None) -> list[str]:
    """Confidence-basis strings, so the citation survives into the ledger."""
    if not precedents:
        return []
    return [f"precedent: {p.author} {p.disposition} at similarity {p.score:.2f} on {','.join(p.matched)}" for p in precedents]

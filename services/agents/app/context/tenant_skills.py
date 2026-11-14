"""Read the tenant's active skills and turn the matching one into a plan.

Gap-closure Phase 6.1 and 6.2, agents half.

A skill is the customer's own investigation approach, authored in the console.
This module is what makes it steer anything: it reads the active set over the
same round trip organisation memory already uses, picks the one that matches
an alert, and renders it two ways.

* :meth:`ResolvedSkill.strategy` produces a real
  :class:`~app.investigator.strategies.Strategy`, so the deep-investigation
  loop, the depth record and ``check_investigation_depth.py`` all work on a
  tenant skill exactly as they work on a built-in. Nothing downstream needs to
  know a skill is involved.
* :meth:`ResolvedSkill.triage_guidance` produces the prompt block for
  auto-triage, which is the path a replay measures.

Both, because a skill that only changed the pivot plan could not be
backtested: the replay grades triage verdicts, and a plan that never reaches
the verdict would show a delta of zero on every run and look like a skill that
does nothing.

Why a skill outranks a built-in strategy
----------------------------------------
The plan says so, and the reason is that the two are different kinds of claim.
A built-in strategy encodes how an attack behaves in general. A skill encodes
what is true in *this* estate, which is knowledge the built-in cannot have and
cannot be argued out of. When both match, the specific one wins. When no skill
matches, selection is untouched, which is the property the existing strategy
tests assert.

How the text is contained
-------------------------
Skill text is first-party: it is typed into the console by a user holding
``settings:write``, the same trust class as organisation-memory statements and
business-context rules, and unlike a knowledge-base document or an MCP reply
it is not something an attacker can write by planting a log line. So it is
sanitised and capped rather than nonce-fenced, and it is worded as guidance
rather than as instruction: a skill is a reason to consider a verdict, never a
reason to stop looking. The cap matters independently of trust, because the
prompt budget is shared with the evidence the verdict is supposed to rest on.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.investigator.prompt_sanitizer import sanitize_text
from app.investigator.strategies import Strategy

logger = structlog.get_logger()

__all__ = [
    "MAX_SKILLS_IN_PROMPT",
    "ResolvedSkill",
    "clear_cache",
    "enabled",
    "fetch_skills",
    "select_skill",
    "skills_from_payload",
]

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT_S = float(os.getenv("AISOC_TENANT_SKILLS_TIMEOUT_S", "5"))

#: Skills change at human speed: authoring, a backtest and an explicit
#: activation. This sits on the path of every fused alert, so it is cached for
#: the same reason organisation memory is.
_CACHE_TTL_S = float(os.getenv("AISOC_TENANT_SKILLS_TTL_S", "120"))

#: How many skills may be resolved for one tenant at all. A cap exists because
#: the resolver runs per alert and a tenant with three hundred active skills
#: would pay for all of them on every one.
MAX_SKILLS_IN_PROMPT = 50

#: Per-field caps applied at render time. The API caps these at authoring
#: time too; this is the floor under a body written before those caps existed.
_MAX_BLOCK_CHARS = 1200
_MAX_ITEM_CHARS = 400

_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def enabled() -> bool:
    return os.getenv("AISOC_TENANT_SKILLS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def clear_cache() -> None:
    """Drop cached skills. Tests, and the activation path."""
    _cache.clear()


@dataclass(frozen=True)
class ResolvedSkill:
    """One active skill, as the agent uses it."""

    skill_id: str
    version: int
    name: str
    owner: str
    plan: tuple[str, ...]
    expected_pivots: tuple[str, ...]
    min_pivots: int = 2
    applies_when: str = ""
    guidance: str = ""
    verdict_guidance: str = ""
    required_evidence: tuple[str, ...] = ()
    escalate_when: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    activated_at: str | None = None
    expires_at: str | None = None

    @property
    def ref(self) -> str:
        """The pair recorded on an investigation, and the one the history table resolves."""
        return f"{self.skill_id}@v{self.version}"

    @property
    def strategy_id(self) -> str:
        """Namespaced so a tenant skill can never collide with a built-in id.

        Without the prefix a skill called ``generic-triage`` would occupy the
        fallback's identity in the depth cache and in every log line, and a
        reader could not tell which of the two produced a run.
        """
        return f"tenant:{self.skill_id}"

    def strategy(self) -> Strategy:
        """The skill as a :class:`Strategy`, so the loop needs no special case."""
        return Strategy(
            id=self.strategy_id,
            name=self.name,
            applies_when=self.applies_when or "This tenant authored a skill matching this alert.",
            rationale=self._rationale(),
            plan=self.plan,
            expected_pivots=self.expected_pivots,
            min_pivots=self.min_pivots,
            techniques=self.techniques,
            keywords=self.keywords,
        )

    def _rationale(self) -> str:
        parts = [
            f"Tenant skill {self.ref}, authored by {sanitize_text(self.owner)[:200]}. "
            f"This is what this organisation knows about alerts of this shape."
        ]
        if self.guidance:
            parts.append(sanitize_text(self.guidance)[:_MAX_BLOCK_CHARS])
        return " ".join(parts)

    def system_guidance(self) -> str:
        """Investigation guidance: the strategy block plus what the skill adds."""
        blocks = [self.strategy().system_guidance()]
        extra = self._organisation_block(include_verdict=False)
        if extra:
            blocks.append(extra)
        return "\n\n".join(blocks)

    def triage_guidance(self) -> str:
        """The triage-prompt block. Empty when the skill says nothing a verdict uses."""
        return self._organisation_block(include_verdict=True)

    def _organisation_block(self, *, include_verdict: bool) -> str:
        lines: list[str] = []
        if self.guidance:
            lines.append(sanitize_text(self.guidance)[:_MAX_BLOCK_CHARS])
        if include_verdict and self.verdict_guidance:
            lines.append(f"Verdict guidance: {sanitize_text(self.verdict_guidance)[:_MAX_BLOCK_CHARS]}")
        if self.required_evidence:
            rendered = "\n".join(f"  - {sanitize_text(item)[:_MAX_ITEM_CHARS]}" for item in self.required_evidence)
            lines.append(
                "Evidence this organisation requires before that verdict is safe. If you could not "
                "establish one of these, say which, and do not close on the guidance alone:\n" + rendered
            )
        if self.escalate_when:
            rendered = "\n".join(f"  - {sanitize_text(item)[:_MAX_ITEM_CHARS]}" for item in self.escalate_when)
            lines.append("Escalate to a human regardless of the guidance above if any of these hold:\n" + rendered)

        if not lines:
            return ""
        return (
            f"Organisation skill {self.ref} applies to this alert. It is what this tenant's analysts "
            f"have written down about alerts of this shape, and it is advisory: it is a reason to "
            f"consider a verdict, never a reason to stop looking, and it never overrides direct "
            f"evidence of compromise in the telemetry.\n" + "\n".join(lines)
        )

    def as_provenance(self) -> dict[str, Any]:
        """What the ledger and the investigation record carry.

        The owner travels with the reference because the first question after
        a disputed verdict is who to ask, and resolving that from the id
        requires a database the reader of a ledger row may not have.
        """
        return {
            "skill_id": self.skill_id,
            "version": self.version,
            "ref": self.ref,
            "owner": self.owner,
            "activated_at": self.activated_at,
            "expires_at": self.expires_at,
        }


@dataclass
class _Candidate:
    skill: ResolvedSkill
    score: int = 0
    reasons: list[str] = field(default_factory=list)


def skills_from_payload(payload: Any) -> list[dict[str, Any]]:
    """Pull the skill rows out of an API response, tolerating a bad shape."""
    if not isinstance(payload, dict):
        return []
    rows = payload.get("skills")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)][:MAX_SKILLS_IN_PROMPT]


def _resolve_one(row: dict[str, Any]) -> ResolvedSkill | None:
    body = row.get("body")
    if not isinstance(body, dict):
        return None
    skill_id = str(row.get("skill_id") or body.get("id") or "").strip()
    if not skill_id:
        return None
    raw_match = body.get("match")
    match: dict[str, Any] = raw_match if isinstance(raw_match, dict) else {}

    def _tuple(value: Any, *, upper: bool = False, lower: bool = False) -> tuple[str, ...]:
        if not isinstance(value, list):
            return ()
        out = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                continue
            text = item.strip()
            out.append(text.upper() if upper else text.lower() if lower else text)
        return tuple(out)

    plan = _tuple(body.get("plan"))
    pivots = _tuple(body.get("expected_pivots"))
    if not plan or not pivots:
        # Both are required at authoring time. A body missing either was not
        # written by the parser, and a skill with no plan cannot steer.
        logger.warning("tenant_skills.malformed_body", skill_id=skill_id, hint="missing plan or expected_pivots")
        return None

    try:
        version = int(row.get("version") or 0)
    except (TypeError, ValueError):
        version = 0
    if version < 1:
        # A version of zero is not a version. The pair recorded on the
        # investigation would resolve to nothing in the history table, which
        # is provenance that looks real and is not.
        logger.warning("tenant_skills.unversioned", skill_id=skill_id)
        return None

    return ResolvedSkill(
        skill_id=skill_id,
        version=version,
        name=str(body.get("name") or skill_id),
        owner=str(body.get("owner") or ""),
        plan=plan,
        expected_pivots=pivots,
        min_pivots=max(1, min(int(body.get("min_pivots") or 2), len(pivots))),
        applies_when=str(body.get("applies_when") or ""),
        guidance=str(body.get("guidance") or ""),
        verdict_guidance=str(body.get("verdict_guidance") or ""),
        required_evidence=_tuple(body.get("required_evidence")),
        escalate_when=_tuple(body.get("escalate_when")),
        techniques=_tuple(match.get("techniques"), upper=True),
        rule_ids=_tuple(match.get("rule_ids")),
        sources=_tuple(match.get("sources"), lower=True),
        keywords=_tuple(match.get("keywords"), lower=True),
        activated_at=str(row.get("activated_at")) if row.get("activated_at") else None,
        expires_at=str(row.get("expires_at")) if row.get("expires_at") else None,
    )


def select_skill(
    rows: list[dict[str, Any]],
    *,
    summary: str = "",
    techniques: list[str] | None = None,
    rule_id: str | None = None,
    source: str | None = None,
) -> ResolvedSkill | None:
    """Pick the skill that best matches an alert, or ``None``.

    Scoring mirrors :func:`app.investigator.strategies.select_strategy` so an
    author who understands one understands the other: a deliberate
    classification outranks a keyword. A rule id is the most specific claim an
    author can make, so it outranks a technique; a technique outranks a
    source, which is a whole product's worth of alerts; keywords are last.

    Ties break on skill id, not on list order. A tenant with two skills
    scoring equally must get the same one on every alert, or the same alert
    triaged twice produces two different plans for no reason a reader can see.
    """
    mapped = {str(t).upper() for t in (techniques or [])}
    text = (summary or "").lower()
    rule = (rule_id or "").strip()
    src = (source or "").strip().lower()

    best: _Candidate | None = None
    for row in rows[:MAX_SKILLS_IN_PROMPT]:
        skill = _resolve_one(row)
        if skill is None:
            continue
        candidate = _Candidate(skill=skill)

        if rule and rule in skill.rule_ids:
            candidate.score += 20
            candidate.reasons.append(f"rule_id={rule}")
        for technique in skill.techniques:
            # A sub-technique alert matches a skill written against the
            # parent, the same reading select_strategy uses.
            if any(m == technique or m.startswith(technique + ".") for m in mapped):
                candidate.score += 10
                candidate.reasons.append(f"technique={technique}")
                break
        if src and src in skill.sources:
            candidate.score += 5
            candidate.reasons.append(f"source={src}")
        matched_keywords = [k for k in skill.keywords if k in text]
        if matched_keywords:
            candidate.score += 2 * len(matched_keywords)
            candidate.reasons.append("keywords=" + ",".join(matched_keywords[:4]))

        if candidate.score == 0:
            continue
        if best is None or candidate.score > best.score or (candidate.score == best.score and skill.skill_id < best.skill.skill_id):
            best = candidate

    if best is None:
        return None
    logger.info(
        "tenant_skills.selected",
        skill=best.skill.ref,
        score=best.score,
        matched_on=",".join(best.reasons),
    )
    return best.skill


async def fetch_skills(tenant_id: str | None) -> list[dict[str, Any]]:
    """Active, unexpired skills for a tenant, or ``[]``. Never raises.

    Fail-soft for the same reason organisation memory is: an investigation
    without the tenant's skill is degraded, and one that dies because a skill
    lookup failed is worse than the gap it was closing. A cached set is served
    through a brief outage rather than dropping the tenant's guidance.
    """
    if not enabled() or not tenant_id:
        return []

    cached = _cache.get(tenant_id)
    now = time.monotonic()
    if cached is not None and now - cached[0] < _CACHE_TTL_S:
        return cached[1]

    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        # Loud, like the organisation-memory and MCP-registry equivalents:
        # without the shared secret the API refuses the service path, so every
        # investigation would silently run without the guidance an operator
        # authored, backtested and activated.
        logger.warning(
            "tenant_skills.no_service_token",
            reason="AISOC_AGENTS_SERVICE_TOKEN is unset, so active tenant skills cannot be read",
        )
        return []

    # Two path segments rather than one. A single `/resolved` would be matched
    # by `GET /tenant-skills/{skill_id}` on any deployment where the route
    # order changed, and the symptom would be a 404 for a tenant whose skill
    # happened not to be called "resolved".
    url = f"{_API_URL.rstrip('/')}/api/v1/tenant-skills/resolved/active"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.get(
                url,
                params={"tenant_id": tenant_id},
                headers={"X-AiSOC-Service-Token": token},
            )
    except httpx.HTTPError as exc:
        logger.warning("tenant_skills.unreachable", error=str(exc)[:300])
        return cached[1] if cached else []

    if response.status_code >= 400:
        logger.warning("tenant_skills.refused", status_code=response.status_code)
        return cached[1] if cached else []

    try:
        payload = response.json()
    except ValueError:
        logger.warning("tenant_skills.bad_response")
        return cached[1] if cached else []

    rows = skills_from_payload(payload)
    _cache[tenant_id] = (now, rows)
    return rows

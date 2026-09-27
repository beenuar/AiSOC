"""Tenant-authored investigation skills: the YAML the console edits, parsed.

Gap-closure Phase 6.1.

A skill is a customer's own investigation approach, written down. It carries
the same shape as a built-in ``Strategy`` in ``services/agents`` (a plan, the
pivots it expects, a rationale) plus the four things a built-in cannot have,
because they are statements about one organisation rather than about attacker
behaviour: what is normal here, what verdict that normality implies, what
evidence has to be in hand before the verdict is allowed, and what pulls the
alert back to a human anyway.

Why this is shaped like a detection rule and not like a settings page
---------------------------------------------------------------------
A skill steers an agent's verdict. Six months after a disputed auto-close,
"why did it decide that" has to be answerable, and the answer is partly this
text. So a skill has an **owner** (who to ask), a **version** (which text was
in force), and an **expiry** (organisational facts rot, and a skill nobody
renews should stop steering rather than steer forever on last year's estate).
The version is assigned here and never by the author: ``version:`` is refused
as a top-level key precisely so there is one authority for what version 3 is.

Why YAML, and why the parse is strict
-------------------------------------
Same reasoning as ``app.services.business_context.models``: the console
exposes an editor and analysts author rules in YAML. Strictness is the part
that differs. Unknown top-level keys are **refused** rather than ignored,
because a skill whose ``verdict_guidance`` was typed as ``verdict_guidence``
is a skill that silently does half of what its author believes it does, and
the author has no way to find out short of reading a prompt.

Every free-text field is capped. The text reaches a prompt, and the prompt
has a budget shared with the evidence the verdict is supposed to rest on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

import yaml

__all__ = [
    "MAX_ESCALATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_KEYWORDS",
    "MAX_PIVOTS",
    "MAX_PLAN_STEPS",
    "SkillMatch",
    "SkillParseError",
    "TenantSkill",
    "parse_skill_yaml",
]


class SkillParseError(ValueError):
    """A skill failed structural validation.

    ``ValueError`` for the same reason ``RuleParseError`` is one: the API layer
    catches this single class and returns the message verbatim in a 422, so
    every message here is written for the analyst who typed the YAML rather
    than for a log.
    """


# --------------------------------------------------------------------------
# Bounds
#
# Each cap is the point past which the field stops being guidance and starts
# being a document. They are module constants so the console can show them and
# the gate can assert the docs quote the same numbers.
# --------------------------------------------------------------------------

MAX_PLAN_STEPS = 12
MAX_PIVOTS = 12
MAX_EVIDENCE_ITEMS = 10
MAX_ESCALATIONS = 10
MAX_KEYWORDS = 24
MAX_TECHNIQUES = 24
MAX_RULE_IDS = 32
MAX_SOURCES = 16

#: Per-item and per-block character caps. ``guidance`` and ``verdict_guidance``
#: are prose blocks and get more room than a plan step, which is one sentence.
MAX_ITEM_CHARS = 400
MAX_BLOCK_CHARS = 1200
MAX_NAME_CHARS = 120
MAX_OWNER_CHARS = 200

#: Kebab-case slug, 3 to 63 characters. Same shape as a business-context rule
#: id and a playbook id, so an analyst who knows one knows this one.
_SKILL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")

#: ATT&CK technique or sub-technique. Parent matching is done at selection
#: time, so ``T1078`` here matches an alert mapped to ``T1078.004``.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

_ALLOWED_TOP_LEVEL = frozenset(
    {
        "id",
        "name",
        "owner",
        "expires_at",
        "applies_when",
        "match",
        "guidance",
        "verdict_guidance",
        "required_evidence",
        "escalate_when",
        "plan",
        "expected_pivots",
        "min_pivots",
    }
)

_ALLOWED_MATCH_KEYS = frozenset({"techniques", "rule_ids", "sources", "keywords"})

#: Keys an author might reasonably type that the server owns instead. Named
#: individually so the refusal explains rather than just rejects.
_SERVER_OWNED = {
    "version": "version is assigned by the server on every content change, so it cannot be set in YAML",
    "status": "status moves through draft, backtested and active via the lifecycle routes, not the document",
    "enabled": "a skill is active or it is not; use the activate and retire routes",
    "tenant_id": "the tenant comes from your credential, never from the document",
}


@dataclass(frozen=True)
class SkillMatch:
    """When a skill applies.

    At least one condition must be present. A skill with an empty match block
    would apply to every alert in the tenant, which is a way to replace the
    whole strategy library by accident.
    """

    techniques: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (self.techniques or self.rule_ids or self.sources or self.keywords)

    def as_dict(self) -> dict[str, Any]:
        return {
            "techniques": list(self.techniques),
            "rule_ids": list(self.rule_ids),
            "sources": list(self.sources),
            "keywords": list(self.keywords),
        }


@dataclass(frozen=True)
class TenantSkill:
    """A parsed skill, before it is given a version or a status.

    Frozen, because the store hands the same object to the validator, the
    serialiser and the backtest, and a mutable one would let any of them edit
    what the others are about to read.
    """

    id: str
    name: str
    owner: str
    expires_at: datetime
    match: SkillMatch
    plan: tuple[str, ...]
    expected_pivots: tuple[str, ...]
    applies_when: str = ""
    guidance: str = ""
    verdict_guidance: str = ""
    required_evidence: tuple[str, ...] = ()
    escalate_when: tuple[str, ...] = ()
    min_pivots: int = 2
    raw_yaml: str = ""

    def as_dict(self) -> dict[str, Any]:
        """The JSONB body. Field names match the YAML so a round trip is obvious."""
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner,
            "expires_at": self.expires_at.isoformat(),
            "applies_when": self.applies_when,
            "match": self.match.as_dict(),
            "guidance": self.guidance,
            "verdict_guidance": self.verdict_guidance,
            "required_evidence": list(self.required_evidence),
            "escalate_when": list(self.escalate_when),
            "plan": list(self.plan),
            "expected_pivots": list(self.expected_pivots),
            "min_pivots": self.min_pivots,
        }

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return self.expires_at <= (now or datetime.now(UTC))


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def _string_list(
    raw: Any,
    *,
    field_name: str,
    limit: int,
    lower: bool = False,
) -> tuple[str, ...]:
    """Read a list of non-empty strings, or a bare string as a one-item list."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise SkillParseError(f"{field_name!r}: expected a list of strings, got {type(raw).__name__}")
    if len(raw) > limit:
        raise SkillParseError(f"{field_name!r}: at most {limit} entries, got {len(raw)}")

    out: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise SkillParseError(f"{field_name}[{index}]: must be a non-empty string")
        text = item.strip()
        if len(text) > MAX_ITEM_CHARS:
            raise SkillParseError(f"{field_name}[{index}]: at most {MAX_ITEM_CHARS} characters, got {len(text)}")
        if lower:
            text = text.lower()
        if text in seen:
            raise SkillParseError(f"{field_name}[{index}]: duplicate entry {text!r}")
        seen.add(text)
        out.append(text)
    return tuple(out)


def _block(raw: Any, *, field_name: str) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise SkillParseError(f"{field_name!r}: must be a string")
    text = raw.strip()
    if len(text) > MAX_BLOCK_CHARS:
        raise SkillParseError(f"{field_name!r}: at most {MAX_BLOCK_CHARS} characters, got {len(text)}")
    return text


def _expiry(raw: Any) -> datetime:
    """Read the expiry, which is required and has no default.

    No default on purpose. Every plausible default is a policy decision
    disguised as a convenience: a year silently renews a fact about an estate
    that may have been rebuilt, and no expiry at all is what the field exists
    to prevent. The author states when this stops being true about their
    organisation, or the skill does not parse.

    A bare date means end of that day in UTC. ``expires_at: 2027-01-31``
    reading as midnight would expire the skill the evening before the day its
    author wrote down.
    """
    if raw is None:
        raise SkillParseError(
            "'expires_at' is required: a skill states what is normal in one organisation, and an "
            "organisational fact with no review date goes on steering verdicts after it stops being true"
        )
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, date):
        return datetime(raw.year, raw.month, raw.day, 23, 59, 59, tzinfo=UTC)
    if isinstance(raw, str) and raw.strip():
        text = raw.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise SkillParseError(f"'expires_at': {raw!r} is not an ISO-8601 date or timestamp") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise SkillParseError(f"'expires_at': expected an ISO-8601 date or timestamp, got {type(raw).__name__}")


def _match(raw: Any) -> SkillMatch:
    if raw is None:
        raise SkillParseError(
            "'match' is required: a skill with no match conditions applies to every alert in the "
            "tenant, which replaces the whole strategy library rather than adding to it"
        )
    if not isinstance(raw, dict):
        raise SkillParseError(f"'match': expected a mapping, got {type(raw).__name__}")

    unknown = sorted(set(raw) - _ALLOWED_MATCH_KEYS)
    if unknown:
        raise SkillParseError(f"'match': unknown key(s) {unknown}; allowed keys are {sorted(_ALLOWED_MATCH_KEYS)}")

    techniques = _string_list(raw.get("techniques"), field_name="match.techniques", limit=MAX_TECHNIQUES)
    for index, technique in enumerate(techniques):
        if not _TECHNIQUE_RE.match(technique):
            raise SkillParseError(f"match.techniques[{index}]: {technique!r} is not an ATT&CK technique id (e.g. T1059 or T1059.001)")

    match = SkillMatch(
        techniques=tuple(t.upper() for t in techniques),
        rule_ids=_string_list(raw.get("rule_ids"), field_name="match.rule_ids", limit=MAX_RULE_IDS),
        sources=_string_list(raw.get("sources"), field_name="match.sources", limit=MAX_SOURCES, lower=True),
        keywords=_string_list(raw.get("keywords"), field_name="match.keywords", limit=MAX_KEYWORDS, lower=True),
    )
    if match.is_empty():
        raise SkillParseError(
            "'match': at least one of techniques, rule_ids, sources or keywords must be present, or the "
            "skill applies to every alert in the tenant"
        )
    return match


def parse_skill_yaml(source: str) -> TenantSkill:
    """Parse one skill document.

    One skill per document, unlike business-context rules. A skill is a named,
    owned, separately versioned and separately backtested artefact, and a file
    holding four of them would have one version number across four independent
    decisions.
    """
    if not isinstance(source, str):
        raise SkillParseError("YAML source must be a string")
    text = source.strip()
    if not text:
        raise SkillParseError("the skill document is empty")

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SkillParseError(f"YAML parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise SkillParseError(f"a skill document must be a single mapping, got {type(data).__name__}")

    for key, reason in _SERVER_OWNED.items():
        if key in data:
            raise SkillParseError(f"{key!r} cannot be set in the document: {reason}")
    unknown = sorted(set(data) - _ALLOWED_TOP_LEVEL)
    if unknown:
        raise SkillParseError(f"unknown key(s) {unknown}; allowed keys are {sorted(_ALLOWED_TOP_LEVEL)}")

    skill_id = data.get("id")
    if not isinstance(skill_id, str) or not _SKILL_ID_RE.match(skill_id):
        raise SkillParseError("'id' must be a kebab-case slug of 3 to 63 characters, for example 'finance-batch-powershell'")

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SkillParseError("'name' is required and must be a non-empty string")
    name = name.strip()
    if len(name) > MAX_NAME_CHARS:
        raise SkillParseError(f"'name': at most {MAX_NAME_CHARS} characters, got {len(name)}")

    owner = data.get("owner")
    if not isinstance(owner, str) or not owner.strip():
        raise SkillParseError(
            "'owner' is required: a skill that steers a verdict needs someone to ask when the verdict "
            "is disputed, and an unowned one has nobody to ask six months later"
        )
    owner = owner.strip()
    if len(owner) > MAX_OWNER_CHARS:
        raise SkillParseError(f"'owner': at most {MAX_OWNER_CHARS} characters, got {len(owner)}")

    plan = _string_list(data.get("plan"), field_name="plan", limit=MAX_PLAN_STEPS)
    if not plan:
        raise SkillParseError("'plan' is required and must list at least one step; a skill with no plan cannot steer an investigation")

    expected_pivots = _string_list(data.get("expected_pivots"), field_name="expected_pivots", limit=MAX_PIVOTS)
    if not expected_pivots:
        raise SkillParseError(
            "'expected_pivots' is required and must name at least one tool; without it the skill's depth "
            "cannot be graded and the investigation cannot be told apart from a summary"
        )

    min_pivots = data.get("min_pivots", 2)
    if isinstance(min_pivots, bool) or not isinstance(min_pivots, int):
        raise SkillParseError("'min_pivots' must be an integer")
    if not 1 <= min_pivots <= len(expected_pivots):
        raise SkillParseError(
            f"'min_pivots' must be between 1 and the number of expected_pivots ({len(expected_pivots)}), got {min_pivots}"
        )

    return TenantSkill(
        id=skill_id,
        name=name,
        owner=owner,
        expires_at=_expiry(data.get("expires_at")),
        match=_match(data.get("match")),
        plan=plan,
        expected_pivots=expected_pivots,
        applies_when=_block(data.get("applies_when"), field_name="applies_when"),
        guidance=_block(data.get("guidance"), field_name="guidance"),
        verdict_guidance=_block(data.get("verdict_guidance"), field_name="verdict_guidance"),
        required_evidence=_string_list(data.get("required_evidence"), field_name="required_evidence", limit=MAX_EVIDENCE_ITEMS),
        escalate_when=_string_list(data.get("escalate_when"), field_name="escalate_when", limit=MAX_ESCALATIONS),
        min_pivots=min_pivots,
        raw_yaml=text,
    )


def skill_from_body(body: dict[str, Any], *, raw_yaml: str = "") -> TenantSkill:
    """Rebuild a skill from the stored JSONB body.

    The agents service is served from this shape rather than from the YAML,
    so a stored skill is never re-parsed on the read path: a parser change
    that tightened a rule would otherwise make an already-active skill
    unreadable at triage time, which is a production outage caused by a
    validation improvement.
    """
    match_raw = body.get("match") or {}
    return TenantSkill(
        id=str(body.get("id") or ""),
        name=str(body.get("name") or ""),
        owner=str(body.get("owner") or ""),
        expires_at=_expiry(body.get("expires_at")),
        match=SkillMatch(
            techniques=tuple(str(t) for t in (match_raw.get("techniques") or [])),
            rule_ids=tuple(str(r) for r in (match_raw.get("rule_ids") or [])),
            sources=tuple(str(s) for s in (match_raw.get("sources") or [])),
            keywords=tuple(str(k) for k in (match_raw.get("keywords") or [])),
        ),
        plan=tuple(str(p) for p in (body.get("plan") or [])),
        expected_pivots=tuple(str(p) for p in (body.get("expected_pivots") or [])),
        applies_when=str(body.get("applies_when") or ""),
        guidance=str(body.get("guidance") or ""),
        verdict_guidance=str(body.get("verdict_guidance") or ""),
        required_evidence=tuple(str(e) for e in (body.get("required_evidence") or [])),
        escalate_when=tuple(str(e) for e in (body.get("escalate_when") or [])),
        min_pivots=int(body.get("min_pivots") or 2),
        raw_yaml=raw_yaml,
    )

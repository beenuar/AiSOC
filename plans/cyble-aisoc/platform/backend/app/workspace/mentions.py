"""@agent mention parsing (Theme 2l).

We deliberately split the parser from the dispatcher so the API layer
can:

* parse mentions at write time (analyst types ``@investigator``),
* persist a ``mention`` workspace op with the canonical agent name,
* and then hand the op off to the dispatcher in a separate task.

This split also means the parser is trivially unit-testable without
spinning up a session or an event loop — it's pure text → list of
structs.

Aliases
-------

Operators don't always type the full enum name. ``@phishing`` should
resolve to :attr:`AgentName.PHISHING_TRIAGE`, ``@saas`` to
:attr:`AgentName.SAAS_POSTURE`, etc. The alias table is intentionally
small and human-curated; we'd rather refuse to dispatch an ambiguous
mention than guess wrong and run a destructive agent.

Mentions inside code fences or inline code spans are *not* extracted.
A triple-backtick block like::

    ```bash
    grep '@investigator' file.log
    ```

is an analyst pasting a log line, not a request to run the investigator.
We honor the common-sense Markdown boundary so this is safe.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.models.trace import AgentName


# ── Dispatchable agents ────────────────────────────────────────────────
# These are the agents that can be dispatched from a workspace mention.
# Mirror the orchestrator's AGENT_MAP — we exclude PLANNER (it's the
# orchestrator itself) and HUNTER (out-of-band, runs without a case
# context). Adding a new agent here requires it to be registered in
# :data:`app.workspace.dispatcher.DISPATCHABLE_AGENTS` so the runtime
# can actually instantiate it.
_DISPATCHABLE: frozenset[AgentName] = frozenset({
    AgentName.TRIAGER,
    AgentName.INVESTIGATOR,
    AgentName.ITDR,
    AgentName.CDR,
    AgentName.SAAS_POSTURE,
    AgentName.PHISHING_TRIAGE,
    AgentName.RESPONDER,
    AgentName.REPORTER,
    AgentName.DETECTION_AUTHOR,
})


# Map of canonical alias → :class:`AgentName`. Keys are lowercase and
# only contain ``[a-z0-9_]`` so they survive the regex below.
_ALIASES: dict[str, AgentName] = {
    # canonical names (exact match against AgentName values)
    **{a.value: a for a in _DISPATCHABLE},
    # common short forms operators actually type
    "phishing": AgentName.PHISHING_TRIAGE,
    "phish": AgentName.PHISHING_TRIAGE,
    "saas": AgentName.SAAS_POSTURE,
    "sspm": AgentName.SAAS_POSTURE,
    "detection": AgentName.DETECTION_AUTHOR,
    "detect": AgentName.DETECTION_AUTHOR,
    "report": AgentName.REPORTER,
    "respond": AgentName.RESPONDER,
    "investigate": AgentName.INVESTIGATOR,
    "triage": AgentName.TRIAGER,
}


# Regex: an @ token starts on a non-word boundary, then 2-32 chars from
# ``[A-Za-z0-9_]``. We deliberately reject 1-char mentions because they
# are almost always typos and never match a real agent alias.
_MENTION_RE = re.compile(r"(?:^|(?<=[^\w]))@([A-Za-z][A-Za-z0-9_]{1,31})")


@dataclass(frozen=True)
class Mention:
    """A single parsed @agent mention.

    ``raw`` is the literal text the analyst typed (e.g. ``@phishing``);
    ``agent`` is the resolved canonical agent. We keep both so the
    persisted op records exactly what the human wrote *and* what the
    dispatcher will execute.
    """

    agent: AgentName
    raw: str
    start: int
    end: int


def parse_mentions(text: str) -> list[Mention]:
    """Extract dispatchable @agent mentions from ``text``.

    Returns mentions in left-to-right order. Unknown handles
    (``@charlie``, ``@nope``) are silently ignored — the analyst just
    typed the wrong thing, and refusing the whole note would be hostile.

    Mentions inside fenced code blocks or inline code spans are
    skipped. We strip those regions before scanning. This is a
    heuristic (we don't parse Markdown fully), but it handles the
    pasted-log-line case which is the only failure mode that matters
    in practice.
    """
    if not text:
        return []
    cleaned = _strip_code_regions(text)
    mentions: list[Mention] = []
    seen: set[tuple[AgentName, int]] = set()
    for match in _MENTION_RE.finditer(cleaned):
        handle = match.group(1).lower()
        agent = _ALIASES.get(handle)
        if agent is None or agent not in _DISPATCHABLE:
            continue
        key = (agent, match.start())
        if key in seen:
            continue
        seen.add(key)
        mentions.append(
            Mention(
                agent=agent,
                raw=match.group(0),
                start=match.start(),
                end=match.end(),
            )
        )
    return mentions


def unique_agents(mentions: Iterable[Mention]) -> list[AgentName]:
    """Return the deduplicated list of agents mentioned, in first-seen order.

    The dispatcher uses this to fan out one run per agent even when the
    analyst typed the same handle twice (``@investigator pls. cc
    @investigator``). Order matters because the timeline should show
    agents starting in the order the human requested them.
    """
    out: list[AgentName] = []
    seen: set[AgentName] = set()
    for m in mentions:
        if m.agent in seen:
            continue
        seen.add(m.agent)
        out.append(m.agent)
    return out


# ── helpers ────────────────────────────────────────────────────────────

_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`]+`")


def _strip_code_regions(text: str) -> str:
    """Replace fenced/inline code spans with spaces of equal length.

    Equal length matters because :func:`parse_mentions` reports the
    ``start``/``end`` offsets back to the API layer — collapsing code
    regions to ``""`` would shift every subsequent mention by an
    arbitrary amount and the persisted op would point at the wrong
    place in the original note.
    """
    def blank(m: re.Match[str]) -> str:
        return " " * (m.end() - m.start())

    # Order matters: strip fenced blocks first so we don't double-strip
    # backticks nested inside them.
    without_fences = _FENCE_RE.sub(blank, text)
    return _INLINE_CODE_RE.sub(blank, without_fences)

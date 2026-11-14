"""The severity vocabularies, declared once, and the matcher that reads them.

Why this module exists
----------------------
Two things were wrong with the way alert text was keyword-matched, and they
were wrong in the same place twice.

**The match was a substring test.** ``"c2" in text`` over
``alert_summary + str(raw_alert)`` fires on every AWS private hostname
(``ip-10-0-1-7.ec2.internal``), on every EC2 instance id (``i-0ab2c2d3e4f5``),
and on any hex digest or base64 blob carrying the pair — base64 of a string
beginning "s" starts ``c2``. An alert with nothing critical about it was
scored ``("critical", 0.9)``, proposed ``isolate_host`` against the hostname,
and took a +0.35 confidence boost. The quiet part was the routing: the model
cascade uses the deterministic scorer as tier 1, and 0.9 clears the
escalation floor, so those alerts were never sent to the ML or LLM tier at
all. A false critical is visible; an alert that silently skips analysis is
not. Reported as #1607 by Rudy Mizrahi Celekli.

**The vocabulary was declared twice and had already drifted.** The triage
agent's critical set carried 13 entries and the confidence scorer's carried
11: ``beacon`` and ``domain admin`` were in one and not the other, so an
alert could be *scored* critical by triage while the confidence scorer
declined to credit the same evidence, with nothing reporting the
disagreement. One list, one matcher, one gate
(``scripts/check_keyword_matching.py``).

The matching rule
-----------------
A keyword matches where it begins at a token boundary, and — unless it is a
deliberate stem — ends at one too. "Token" is a run of ASCII alphanumerics,
so a boundary is only asserted on an edge whose own character is
alphanumeric; ``.lockbit`` keeps matching ``report.docx.lockbit``.

The left boundary is what fixes the bug: it is the edge that stops a keyword
matching inside an identifier. The right boundary is what stops ``c2``
matching the leading pair of a hash or a base64 blob, and it is safe for
every keyword that is a whole word. It is *not* safe for the ones that are
deliberately prefixes — ``credential dump`` has to reach "credential
dumping", the canonical phrasing and the actual name of T1003 — so **a
trailing ``*`` marks a stem**, matched at the left boundary only.

The mode is written into the keyword rather than kept in a parallel set of
"these ones are stems", because a second collection that has to agree with
the first is the exact drift this module exists to end. Giving up the
right-hand boundary is only sound for a keyword long enough that it cannot
begin a run inside an identifier, and ``scripts/check_keyword_matching.py``
proves that against a corpus of real cloud identifiers rather than leaving
it as an assertion in a docstring.

A boundary rule alone is not quite enough, which the gate found rather than
a reviewer: a MAC address octet is delimited by colons, so ``c2`` in
``00:1a:c2:3b:4c:5d`` sits between two token boundaries and matches under
*any* boundary rule — about one MAC address in forty carries a ``c2`` octet.
The same goes for the ``c2`` group of a dotted hex digest. So
:func:`normalise` strikes opaque identifiers out of the haystack before
matching: a hash, a UUID and a MAC address are not natural language and
cannot contain a keyword, only coincide with one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache

__all__ = [
    "CRITICAL_KEYWORDS",
    "HIGH_KEYWORDS",
    "STEM_SUFFIX",
    "alert_text",
    "any_matched",
    "display",
    "matched",
    "matches",
    "normalise",
]

#: A keyword ending in this is matched as a prefix — left boundary only.
STEM_SUFFIX = "*"

#: Behaviour and tooling that make an alert critical on sight. Read by the
#: triage agent's severity scorer and by the confidence scorer's critical
#: bonus; the same evidence has to mean the same thing to both.
#:
#: ``beacon*`` and ``credential dump*`` are stems because "C2 beaconing" and
#: "credential dumping" are the ordinary way those behaviours are written.
CRITICAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "beacon*",
        "c2",
        "cobalt strike",
        "credential dump*",
        "data breach",
        "exfiltration",
        "lateral movement",
        "mimikatz",
        "ransomware",
        "rootkit",
        "supply chain",
        "zero-day",
    }
)

#: Serious, but not critical on sight.
#:
#: ``domain admin`` sits here rather than in the critical set. Every other
#: critical entry names a *behaviour or a tool*; this one names an *account
#: tier*, and it turns up in entirely routine text — a group-membership
#: audit, a least-privilege review, an AD sync listing the ``Domain Admins``
#: group. Treating the mention of a privileged group as critical conflates
#: "a privileged account is named" with "a privileged account is
#: compromised". ``privilege escalation``, the behavioural form of the same
#: concern, was already high.
HIGH_KEYWORDS: frozenset[str] = frozenset(
    {
        "anomaly",
        "backdoor",
        "brute force*",
        "domain admin",
        "exploit*",
        "malware",
        "phishing",
        "privilege escalation",
        "suspicious login",
    }
)


#: Values that are opaque by construction: whatever letters they contain are
#: an accident of encoding, so a keyword found inside one has coincided with
#: it rather than occurred in it. Struck out before matching.
#:
#: Ordered longest-shape-first so a MAC address is consumed as a MAC address
#: rather than leaving fragments behind.
_OPAQUE = re.compile(
    r"""
      (?:[0-9a-f]{2}:){5}[0-9a-f]{2}                     # MAC address
    | [0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}        # UUID
    | (?<![0-9a-z])[0-9a-f]{12,}(?![0-9a-z])             # hash / git revision
    """,
    re.VERBOSE,
)


def normalise(text: str) -> str:
    """Lowercase, and blank out opaque identifiers.

    A hash, a UUID and a MAC address carry no words. Leaving them in the
    haystack means a keyword can match a run of hex that happens to spell
    it — which no boundary rule can prevent, because the delimiters of a
    MAC address *are* token boundaries.
    """

    return _OPAQUE.sub(" ", text.lower())


def alert_text(alert_summary: str, raw_alert: object) -> str:
    """The haystack every keyword check reads.

    Built in one place because three call sites had each written their own
    copy of ``(summary + " " + str(raw)).lower()``, which is how two of them
    would eventually disagree about whether the raw payload is searched.
    """

    return normalise(f"{alert_summary} {raw_alert}")


def display(keyword: str) -> str:
    """The keyword as a human reads it, with any stem marker removed."""

    return keyword[: -len(STEM_SUFFIX)] if keyword.endswith(STEM_SUFFIX) else keyword


@lru_cache(maxsize=1024)
def _pattern(keyword: str) -> re.Pattern[str]:
    """Compile one keyword into its boundary-aware pattern.

    A boundary is asserted only on an edge whose own character is
    alphanumeric: ``.lockbit`` is meant to match a file extension, and
    demanding a boundary before its leading dot would stop it matching the
    very thing it is for.
    """

    stem = keyword.endswith(STEM_SUFFIX)
    body = display(keyword)
    left = r"(?<![a-z0-9])" if body[:1].isalnum() else ""
    right = "" if stem else (r"(?![a-z0-9])" if body[-1:].isalnum() else "")
    return re.compile(f"{left}{re.escape(body)}{right}")


def matches(text: str, keyword: str) -> bool:
    """True when ``keyword`` occurs in ``text`` at a token boundary.

    ``text`` is expected lowercased — :func:`alert_text` does that.
    """

    return _pattern(keyword).search(text) is not None


def matched(text: str, keywords: Iterable[str]) -> list[str]:
    """Display forms of every keyword that matches, sorted for stable output."""

    return sorted(display(kw) for kw in keywords if matches(text, kw))


def any_matched(text: str, keywords: Iterable[str]) -> bool:
    return any(matches(text, kw) for kw in keywords)

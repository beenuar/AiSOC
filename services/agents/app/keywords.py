"""Keyword vocabularies and boundary-aware matching for alert triage."""

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

STEM_SUFFIX = "*"

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


_OPAQUE = re.compile(
    r"""
      (?:[0-9a-f]{2}:){5}[0-9a-f]{2}
    | [0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}
    | (?<![0-9a-z])[0-9a-f]{12,}(?![0-9a-z])
    """,
    re.VERBOSE,
)


def normalise(text: str) -> str:
    """Lowercase and blank out opaque identifiers."""

    return _OPAQUE.sub(" ", text.lower())


def alert_text(alert_summary: str, raw_alert: object) -> str:
    """The haystack every keyword check reads."""

    return normalise(f"{alert_summary} {raw_alert}")


def display(keyword: str) -> str:
    """The keyword as a human reads it, with any stem marker removed."""

    return keyword[: -len(STEM_SUFFIX)] if keyword.endswith(STEM_SUFFIX) else keyword


@lru_cache(maxsize=1024)
def _pattern(keyword: str) -> re.Pattern[str]:
    """Compile one keyword into its boundary-aware pattern."""

    stem = keyword.endswith(STEM_SUFFIX)
    body = display(keyword)
    left = r"(?<![a-z0-9])" if body[:1].isalnum() else ""
    right = "" if stem else (r"(?![a-z0-9])" if body[-1:].isalnum() else "")
    return re.compile(f"{left}{re.escape(body)}{right}")


def matches(text: str, keyword: str) -> bool:
    """True when keyword occurs in text at a token boundary."""

    return _pattern(keyword).search(text) is not None


def matched(text: str, keywords: Iterable[str]) -> list[str]:
    """Display forms of every keyword that matches, sorted for stable output."""

    return sorted(display(kw) for kw in keywords if matches(text, kw))


def any_matched(text: str, keywords: Iterable[str]) -> bool:
    return any(matches(text, kw) for kw in keywords)

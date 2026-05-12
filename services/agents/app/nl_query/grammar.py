"""Lightweight grammar validators for ES|QL, KQL, and SPL.

These validators are intentionally pragmatic rather than exhaustive: they
reject queries that are obviously malformed (unbalanced quotes, unknown
processing commands, dangling pipes) so that the API layer can refuse to
execute output the LLM produced incorrectly.

We deliberately avoid pulling in a heavy parser dependency — security teams
running AiSOC in an air-gapped environment should not have to wait for a
PyPI mirror sync just to validate that a query is well-formed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass


class GrammarError(ValueError):
    """Raised when a translated query fails grammar validation."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_QUOTE_PAIRS = (('"', '"'), ("'", "'"))


def _balanced_quotes(query: str) -> bool:
    """Return True if single and double quotes are balanced in *query*.

    We do not try to handle escape sequences exhaustively; the goal is to
    catch the common LLM failure mode where a string literal is left open.
    """

    for opener, closer in _QUOTE_PAIRS:
        # Drop escaped quotes so they don't unbalance the count.
        cleaned = query.replace(f"\\{opener}", "")
        if cleaned.count(opener) % 2 != 0 and opener == closer:
            return False
    return True


def _balanced_parens(query: str) -> bool:
    depth = 0
    for ch in query:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# ---------------------------------------------------------------------------
# ES|QL
# ---------------------------------------------------------------------------


# These mirror the ES|QL processing commands documented in the Elastic stack
# reference. We don't enforce ordering rules, just that every command is a
# recognised verb so we can reject typos like ``WHEER`` or ``STATSS``.
_ESQL_PROCESSING_COMMANDS = {
    "WHERE",
    "STATS",
    "EVAL",
    "KEEP",
    "DROP",
    "RENAME",
    "LIMIT",
    "SORT",
    "GROK",
    "DISSECT",
    "ENRICH",
    "MV_EXPAND",
    "DEDUP",
    "INLINESTATS",
    "LOOKUP",
    "TOP",
    "FORK",
    "JOIN",
}

# Valid source commands that may appear in the first segment of an ES|QL pipe.
_ESQL_SOURCE_COMMANDS = {"FROM", "ROW", "SHOW", "META"}


@dataclass(frozen=True)
class _Segment:
    head: str
    body: str


def _split_pipes(query: str) -> list[_Segment]:
    """Split *query* on top-level ``|`` characters, ignoring those in strings."""

    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    for ch in query:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if ch == "|" and not in_single and not in_double:
            segments.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    segments.append("".join(current).strip())

    out: list[_Segment] = []
    for seg in segments:
        if not seg:
            continue
        head, _, body = seg.partition(" ")
        out.append(_Segment(head=head.upper(), body=body.strip()))
    return out


def validate_esql(query: str) -> None:
    """Validate an ES|QL query, raising :class:`GrammarError` on failure."""

    if not query or not query.strip():
        raise GrammarError("query is empty")
    if not _balanced_quotes(query):
        raise GrammarError("unbalanced quotes")
    if not _balanced_parens(query):
        raise GrammarError("unbalanced parentheses")

    # Strip line comments — ES|QL allows ``// ...`` to end-of-line.
    cleaned = "\n".join(re.sub(r"//.*$", "", line) for line in query.splitlines())
    cleaned = cleaned.strip()
    if not cleaned:
        raise GrammarError("query is only comments")
    if cleaned.endswith("|"):
        raise GrammarError("query ends with a dangling pipe")

    segments = _split_pipes(cleaned)
    if not segments:
        raise GrammarError("no statements found")

    first = segments[0]
    if first.head not in _ESQL_SOURCE_COMMANDS:
        raise GrammarError(f"first command must be one of {_ESQL_SOURCE_COMMANDS}, got {first.head!r}")

    if first.head == "FROM" and not first.body:
        raise GrammarError("FROM requires an index pattern")

    for seg in segments[1:]:
        if seg.head not in _ESQL_PROCESSING_COMMANDS:
            raise GrammarError(f"unknown processing command {seg.head!r}")
        if seg.head in {"STATS", "EVAL", "WHERE", "SORT", "GROK", "DISSECT"} and not seg.body:
            raise GrammarError(f"{seg.head} requires arguments")
        if seg.head == "LIMIT":
            try:
                limit_val = int(seg.body.strip())
            except (TypeError, ValueError) as exc:
                raise GrammarError("LIMIT must be a positive integer") from exc
            if limit_val <= 0:
                raise GrammarError("LIMIT must be a positive integer")
        if seg.head == "STATS" and " BY " not in seg.body.upper() and "=" not in seg.body:
            # Allow STATS without BY only if at least one named aggregation is present.
            raise GrammarError("STATS requires either BY or a named aggregation")


# ---------------------------------------------------------------------------
# KQL (Microsoft Sentinel / Kusto)
# ---------------------------------------------------------------------------


_KQL_OPERATORS = {
    "where",
    "summarize",
    "extend",
    "project",
    "project-away",
    "project-keep",
    "sort",
    "order",
    "top",
    "take",
    "limit",
    "distinct",
    "count",
    "join",
    "union",
    "render",
    "evaluate",
    "make-series",
    "mv-expand",
    "parse",
    "search",
    "lookup",
    "let",
    "as",
}


def _kql_first_token(line: str) -> str:
    line = line.strip().lstrip("|").lstrip()
    return line.split(" ", 1)[0].lower() if line else ""


def validate_kql(query: str) -> None:
    """Validate a KQL query."""

    if not query or not query.strip():
        raise GrammarError("query is empty")
    if not _balanced_quotes(query):
        raise GrammarError("unbalanced quotes")
    if not _balanced_parens(query):
        raise GrammarError("unbalanced parentheses")

    # Drop blank lines and comments (// to end-of-line).
    lines = [re.sub(r"//.*$", "", line).rstrip() for line in query.splitlines()]
    lines = [line for line in lines if line.strip()]
    if not lines:
        raise GrammarError("query is only comments")
    if lines[-1].rstrip().endswith("|"):
        raise GrammarError("query ends with a dangling pipe")

    # First non-empty line must reference a table OR begin with a let/declare.
    first = lines[0].lstrip()
    first_token = _kql_first_token(first)
    if first.startswith("|"):
        raise GrammarError("KQL query must start with a table name, not a pipe")
    if first_token in {"where", "summarize", "extend", "project"}:
        raise GrammarError("KQL query must start with a table reference before applying operators")

    # For each line that begins with `|`, the next token must be a known KQL operator.
    for line in lines[1:]:
        stripped = line.lstrip()
        if not stripped.startswith("|"):
            # Continuation lines are fine.
            continue
        token = _kql_first_token(stripped)
        if token not in _KQL_OPERATORS:
            raise GrammarError(f"unknown KQL operator {token!r}")


# ---------------------------------------------------------------------------
# SPL (Splunk)
# ---------------------------------------------------------------------------


_SPL_COMMANDS = {
    "search",
    "stats",
    "eval",
    "where",
    "rex",
    "table",
    "sort",
    "head",
    "tail",
    "dedup",
    "fields",
    "rename",
    "lookup",
    "join",
    "append",
    "appendcols",
    "transaction",
    "timechart",
    "chart",
    "top",
    "rare",
    "bin",
    "bucket",
    "iplocation",
    "geostats",
    "tstats",
    "spath",
}


def validate_spl(query: str) -> None:
    """Validate a SPL query."""

    if not query or not query.strip():
        raise GrammarError("query is empty")
    if not _balanced_quotes(query):
        raise GrammarError("unbalanced quotes")
    if not _balanced_parens(query):
        raise GrammarError("unbalanced parentheses")

    cleaned = " ".join(query.split())
    if cleaned.endswith("|"):
        raise GrammarError("query ends with a dangling pipe")

    parts: Iterable[str] = (p.strip() for p in cleaned.split("|"))
    parts_list = [p for p in parts if p]
    if not parts_list:
        raise GrammarError("query has no segments")

    # Splunk's implicit search command means the first segment may either start
    # with ``search ...`` or with a search expression like ``index=... ...``.
    first = parts_list[0]
    first_token = first.split(" ", 1)[0].lower()
    if first_token not in _SPL_COMMANDS and "=" not in first:
        raise GrammarError(f"unknown SPL command {first_token!r} and no search expression")

    for seg in parts_list[1:]:
        token = seg.split(" ", 1)[0].lower()
        if token not in _SPL_COMMANDS:
            raise GrammarError(f"unknown SPL command {token!r}")


# Public re-exports for convenience.
__all__ = [
    "GrammarError",
    "validate_esql",
    "validate_kql",
    "validate_spl",
]

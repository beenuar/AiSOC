"""Evaluate a Lucene query against one in-memory event, with real boolean semantics.

Why this exists
---------------
``rule_engine._run_sigma`` converts a Sigma rule with pySigma's OpenSearch
backend and then has to decide, in this process, whether an event matches the
resulting query. It used to do that with::

    return query.lower() in " ".join(f"{k}:{v}" for k, v in flat.items()).lower()

A Lucene boolean expression is never a contiguous substring of a
``key:value key:value`` join, so the moment a rule had two clauses —
``Image:*\\powershell.exe AND CommandLine:*Mimikatz*``, which is what the
backend emits for a two-field ``selection`` — it matched **nothing**, and
returned ``False`` without an error. A rule that cannot fire and a rule that
found nothing are indistinguishable to every caller: the backtest reported
``would_fire: 0`` with a straight face, the candidate-rule eval gate failed
every Sigma proposal on its own positive fixtures, and scheduled Sigma hunts
returned zero hits.

Substring containment cannot represent a boolean. Nothing short of parsing
the query fixes it, so this module parses the query.

Scope
-----
The subset pySigma's OpenSearch backend actually emits, which is what this
has to evaluate correctly:

===============================  ==========================================
``EventID:4625``                 term equality
``Image:*\\powershell.exe``      wildcards (``*`` any run, ``?`` one char)
``TargetUserName:(a OR b)``      grouped alternatives on one field
``CommandLine:/foo.*bar/``       regular expression
``NOT _exists_:User``            field-absence, from a Sigma ``null``
``*whoami*``                     a bare term, from Sigma keywords
``A AND B``, ``A OR B``, ``(…)`` boolean composition
``Name:Remote\\ Desktop``        backslash escaping of any metacharacter
===============================  ==========================================

Matching is case-insensitive, which is Sigma's default.

Anything outside that subset raises :class:`LuceneQueryError` rather than
evaluating to ``False``. That direction is the whole point: a query this
module cannot read must surface as an error the caller reports, never as a
quiet "no match" that reads exactly like a clean event.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = ["LuceneQueryError", "lucene_matches", "parse_lucene"]


class LuceneQueryError(ValueError):
    """The query uses something this evaluator cannot faithfully represent."""


# ─── Tokeniser ───────────────────────────────────────────────────────────────

# A run of query text that is one token: either a bare word (with backslash
# escapes, so `Remote\ Desktop` stays a single token) or a /regex/ literal.
_TOKEN_RE = re.compile(
    r"""
      /(?P<regex>(?:\\.|[^/\\])*)/    # /.../ with escapes
    | (?P<term>(?:\\.|[^\s():])+)     # bare term; ( ) : and space end it unless escaped
    """,
    re.VERBOSE,
)

_KEYWORDS = {"AND", "OR", "NOT", "&&", "||", "!"}


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # "lparen" | "rparen" | "colon" | "kw" | "term" | "regex"
    value: str


def _tokenise(query: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append(_Token("lparen", "("))
            i += 1
            continue
        if ch == ")":
            tokens.append(_Token("rparen", ")"))
            i += 1
            continue
        if ch == ":":
            tokens.append(_Token("colon", ":"))
            i += 1
            continue
        match = _TOKEN_RE.match(query, i)
        if match is None:
            raise LuceneQueryError(f"cannot tokenise at offset {i}: {query[i : i + 30]!r}")
        if match.lastgroup == "regex" or match.group("regex") is not None:
            tokens.append(_Token("regex", match.group("regex")))
        else:
            text = match.group("term")
            tokens.append(_Token("kw", text.upper()) if text.upper() in _KEYWORDS else _Token("term", text))
        i = match.end()
    return tokens


# ─── AST ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Term:
    field: str | None  # None => match against every field's value
    pattern: str
    is_regex: bool


@dataclass(frozen=True, slots=True)
class _Exists:
    field: str


@dataclass(frozen=True, slots=True)
class _Not:
    operand: Any


@dataclass(frozen=True, slots=True)
class _BoolOp:
    op: str  # "AND" | "OR"
    operands: tuple[Any, ...]


# ─── Parser ──────────────────────────────────────────────────────────────────


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self, offset: int = 0) -> _Token | None:
        index = self._pos + offset
        return self._tokens[index] if index < len(self._tokens) else None

    def _take(self) -> _Token:
        token = self._peek()
        if token is None:
            raise LuceneQueryError("query ended where a term was expected")
        self._pos += 1
        return token

    def parse(self) -> Any:
        if not self._tokens:
            raise LuceneQueryError("empty query")
        node = self._or()
        if self._peek() is not None:
            raise LuceneQueryError(f"unconsumed input at token {self._pos}: {self._tokens[self._pos].value!r}")
        return node

    def _or(self) -> Any:
        operands = [self._and()]
        while (token := self._peek()) is not None and token.kind == "kw" and token.value in ("OR", "||"):
            self._take()
            operands.append(self._and())
        return operands[0] if len(operands) == 1 else _BoolOp("OR", tuple(operands))

    def _and(self) -> Any:
        operands = [self._not()]
        while (token := self._peek()) is not None:
            if token.kind == "kw" and token.value in ("AND", "&&"):
                self._take()
                operands.append(self._not())
                continue
            # Lucene's implicit operator. The backend always emits an explicit
            # one, so an adjacency here means the query is not the shape this
            # evaluator was written against: refuse rather than guess whether
            # the default is AND or OR.
            if token.kind in ("term", "regex", "lparen"):
                raise LuceneQueryError(f"implicit operator before {token.value!r}; only explicit AND/OR are supported")
            break
        return operands[0] if len(operands) == 1 else _BoolOp("AND", tuple(operands))

    def _not(self) -> Any:
        token = self._peek()
        if token is not None and token.kind == "kw" and token.value in ("NOT", "!"):
            self._take()
            return _Not(self._not())
        return self._primary()

    def _primary(self) -> Any:
        token = self._take()
        if token.kind == "lparen":
            node = self._or()
            closing = self._take()
            if closing.kind != "rparen":
                raise LuceneQueryError(f"expected ')' , got {closing.value!r}")
            return node
        if token.kind == "regex":
            return _Term(None, token.value, is_regex=True)
        if token.kind != "term":
            raise LuceneQueryError(f"expected a term, got {token.value!r}")

        following = self._peek()
        if following is None or following.kind != "colon":
            return _Term(None, token.value, is_regex=False)

        self._take()  # consume ':'
        field = token.value
        value = self._take()
        if value.kind == "regex":
            return _Term(field, value.value, is_regex=True)
        if value.kind == "lparen":
            # `field:(a OR b)` — the alternatives all bind to this field.
            group = self._field_group(field)
            closing = self._take()
            if closing.kind != "rparen":
                raise LuceneQueryError(f"expected ')' closing {field}:(...), got {closing.value!r}")
            return group
        if value.kind != "term":
            raise LuceneQueryError(f"expected a value after {field}:, got {value.value!r}")
        if field == "_exists_":
            return _Exists(_unescape(value.value))
        return _Term(field, value.value, is_regex=False)

    def _field_group(self, field: str) -> Any:
        operands: list[Any] = []
        op = "OR"
        while True:
            token = self._take()
            if token.kind == "regex":
                operands.append(_Term(field, token.value, is_regex=True))
            elif token.kind == "term":
                operands.append(_Term(field, token.value, is_regex=False))
            else:
                raise LuceneQueryError(f"expected a value inside {field}:(...), got {token.value!r}")
            nxt = self._peek()
            if nxt is not None and nxt.kind == "kw" and nxt.value in ("OR", "AND", "||", "&&"):
                self._take()
                op = "AND" if nxt.value in ("AND", "&&") else "OR"
                continue
            break
        return operands[0] if len(operands) == 1 else _BoolOp(op, tuple(operands))


def parse_lucene(query: str) -> Any:
    """Parse ``query`` into an evaluable tree, or raise :class:`LuceneQueryError`."""
    return _Parser(_tokenise(query)).parse()


# ─── Evaluation ──────────────────────────────────────────────────────────────


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def _to_matcher(pattern: str, *, is_regex: bool) -> re.Pattern[str]:
    if is_regex:
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise LuceneQueryError(f"bad regular expression {pattern!r}: {exc}") from exc
    # Build the expression from escaped literals so a value carrying regex
    # metacharacters -- a Windows path, a command line -- cannot become one.
    # Only `*` and `?` survive as wildcards, which is what Lucene means.
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile(f"^{''.join(out)}$", re.IGNORECASE | re.DOTALL)


def _values_for(event: dict[str, Any], field: str) -> list[Any]:
    key = _unescape(field).lower()
    if key in event:
        value = event[key]
        return list(value) if isinstance(value, list | tuple) else [value]
    return []


def _evaluate(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, _BoolOp):
        results = (_evaluate(operand, event) for operand in node.operands)
        return all(results) if node.op == "AND" else any(results)
    if isinstance(node, _Not):
        return not _evaluate(node.operand, event)
    if isinstance(node, _Exists):
        return event.get(node.field.lower()) is not None
    if isinstance(node, _Term):
        matcher = _to_matcher(node.pattern, is_regex=node.is_regex)
        check = matcher.search if node.is_regex else matcher.match
        if node.field is None:
            # A bare term. Sigma keywords search the whole record, so this
            # matches anywhere in any value rather than the whole of one.
            loose = matcher if node.is_regex else _to_matcher(f"*{node.pattern}*", is_regex=False)
            return any(loose.match(str(value)) for value in event.values() if value is not None)
        return any(check(str(value)) for value in _values_for(event, node.field) if value is not None)
    raise LuceneQueryError(f"unsupported node {node!r}")


def lucene_matches(query: str, flat_event: dict[str, Any]) -> bool:
    """Whether ``flat_event`` satisfies ``query``.

    ``flat_event`` is a flattened, lower-cased-key mapping as produced by
    ``rule_engine._flatten_dict``.

    Raises:
        LuceneQueryError: the query is outside the supported subset. Callers
            must surface this rather than treating it as a non-match.
    """
    return _evaluate(parse_lucene(query), flat_event)

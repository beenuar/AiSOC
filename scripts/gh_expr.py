#!/usr/bin/env python3
"""A three-valued evaluator for the GitHub Actions expressions used in ``if:``.

Why this exists
---------------
``scripts/check_required_check_substance.py`` has to answer one question about
every step of every required check: *would this step run on a push to a
protected branch?* Three answers are possible and they must stay distinct,
because collapsing any two of them is how a gate starts lying:

``TRUE``
    The step always runs on such a push. If the API says it was skipped,
    something is wrong.

``FALSE``
    The step can never run on such a push — ``if: failure()``,
    ``if: github.event_name == 'pull_request'``. It being skipped is correct
    and must not be reported. This is the "genuinely not applicable" half of
    the distinction the gate exists to draw.

``UNKNOWN``
    The condition depends on something only the run knows: a job output, a
    previous step's output, a secret. These are the steps a change filter can
    switch off, so on a protected-branch push they are exactly the ones that
    must be observed to have run.

The alternative — a hand-maintained list of "substantive" step names — is the
thing this deliberately avoids. A list goes stale the moment someone renames a
step, and it goes stale silently, which is the defect being fixed rather than
a new way of fixing it.

Scope
-----
The subset of the expression language this repository's ``if:`` conditions
actually use: ``&&``, ``||``, ``!``, comparison, parentheses, string and
number literals, property paths, and the handful of functions below. Anything
the parser does not recognise evaluates to ``UNKNOWN`` rather than raising, so
a future expression shape makes the gate more cautious rather than broken —
``UNKNOWN`` means "this step must be observed to have run", which errs toward
demanding evidence.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "UNKNOWN",
    "Unknown",
    "evaluate",
    "truthy",
    "PUSH_TO_PROTECTED_BRANCH",
    "unresolved_references",
    "string_literals",
]


class Unknown:
    """A value the static evaluator cannot resolve.

    A singleton rather than ``None``: ``None`` is a real Actions value (an
    absent property) and it is falsy, so reusing it would silently turn
    "I cannot tell" into "definitely false" — which would classify every
    change-filtered step as correctly skipped and make the whole gate vacuous.
    """

    _instance: Unknown | None = None

    def __new__(cls) -> Unknown:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNKNOWN"

    def __bool__(self) -> bool:
        raise TypeError("UNKNOWN has no truth value; use truthy() which returns a tri-state")


UNKNOWN = Unknown()


#: The context this gate asks about: a push that has landed on a protected
#: branch, in a job that has succeeded up to the step being classified.
#:
#: Everything a change filter could produce is deliberately absent, so it
#: resolves to UNKNOWN. That is the point: a step gated on a filter output is
#: one whose execution has to be *observed*, not predicted.
PUSH_TO_PROTECTED_BRANCH: dict[str, Any] = {
    "github.event_name": "push",
    "github.ref": "refs/heads/main",
    "github.ref_name": "main",
    "github.ref_type": "branch",
    "github.ref_protected": True,
    "github.base_ref": "",
    "github.head_ref": "",
    "github.repository": "beenuar/AiSOC",
    "github.repository_owner": "beenuar",
    "github.workflow": UNKNOWN,
    "github.actor": UNKNOWN,
    "github.sha": UNKNOWN,
    "github.run_attempt": "1",
    "job.status": "success",
    "runner.os": "Linux",
    "runner.arch": "X64",
}

#: A job that succeeded implies every step it ran reported `success`, and
#: every job it needed resolved `success`. Matched structurally so no list of
#: step ids has to be maintained.
_STATUS_PATH = re.compile(r"^steps\.[A-Za-z0-9_\-]+\.(outcome|conclusion)$|^needs\.[A-Za-z0-9_\-]+\.result$")

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<string>'(?:[^']|'')*')
    | (?P<number>-?\d+(?:\.\d+)?)
    | (?P<op>==|!=|<=|>=|&&|\|\||[<>!()\[\],*])
    | (?P<ident>[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_][A-Za-z0-9_\-]*)*)
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> list[tuple[str, str]] | None:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            return None
        pos = match.end()
        kind = match.lastgroup or ""
        if kind == "ws":
            continue
        tokens.append((kind, match.group()))
    return tokens


def truthy(value: Any) -> bool | Unknown:
    """Actions truthiness, preserving UNKNOWN.

    Empty string, 0 and null are false; everything else is true.
    """
    if isinstance(value, Unknown):
        return UNKNOWN
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, (int, float)):
        return value != 0
    return True


class _Parser:
    """Recursive descent over the token list.

    Returns ``UNKNOWN`` for anything it does not understand rather than
    raising, so an unfamiliar expression makes the caller demand evidence
    instead of crashing the gate.
    """

    def __init__(self, tokens: list[tuple[str, str]], context: dict[str, Any]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.context = context
        self.ok = True

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> tuple[str, str] | None:
        token = self.peek()
        if token is not None:
            self.pos += 1
        return token

    def expect_op(self, op: str) -> bool:
        token = self.peek()
        if token and token[0] == "op" and token[1] == op:
            self.pos += 1
            return True
        return False

    # or := and ('||' and)*
    def parse_or(self) -> Any:
        value = self.parse_and()
        while self.expect_op("||"):
            right = self.parse_and()
            left_t, right_t = truthy(value), truthy(right)
            if left_t is True or right_t is True:
                value = True
            elif isinstance(left_t, Unknown) or isinstance(right_t, Unknown):
                value = UNKNOWN
            else:
                value = False
        return value

    # and := not ('&&' not)*
    def parse_and(self) -> Any:
        value = self.parse_not()
        while self.expect_op("&&"):
            right = self.parse_not()
            left_t, right_t = truthy(value), truthy(right)
            if left_t is False or right_t is False:
                value = False
            elif isinstance(left_t, Unknown) or isinstance(right_t, Unknown):
                value = UNKNOWN
            else:
                value = True
        return value

    def parse_not(self) -> Any:
        if self.expect_op("!"):
            inner = truthy(self.parse_not())
            return UNKNOWN if isinstance(inner, Unknown) else (not inner)
        return self.parse_comparison()

    def parse_comparison(self) -> Any:
        left = self.parse_primary()
        token = self.peek()
        if token and token[0] == "op" and token[1] in {"==", "!=", "<", "<=", ">", ">="}:
            self.take()
            right = self.parse_primary()
            if isinstance(left, Unknown) or isinstance(right, Unknown):
                return UNKNOWN
            return _compare(token[1], left, right)
        return left

    def parse_primary(self) -> Any:
        token = self.take()
        if token is None:
            self.ok = False
            return UNKNOWN
        kind, text = token
        if kind == "op" and text == "(":
            value = self.parse_or()
            if not self.expect_op(")"):
                self.ok = False
            return value
        if kind == "string":
            return text[1:-1].replace("''", "'")
        if kind == "number":
            return float(text) if "." in text else int(text)
        if kind == "ident":
            lowered = text.lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
            if lowered == "null":
                return None
            nxt = self.peek()
            if nxt and nxt[0] == "op" and nxt[1] == "(":
                return self.parse_call(text)
            return self.lookup(text)
        self.ok = False
        return UNKNOWN

    def parse_call(self, name: str) -> Any:
        self.expect_op("(")
        args: list[Any] = []
        if not self.expect_op(")"):
            while True:
                args.append(self.parse_or())
                if self.expect_op(")"):
                    break
                if not self.expect_op(","):
                    self.ok = False
                    break
        return _call(name.lower(), args)

    def lookup(self, path: str) -> Any:
        if path in self.context:
            return self.context[path]
        status = _STATUS_PATH.match(path)
        if status:
            # `steps.x.outcome`, `steps.x.conclusion`, `needs.y.result`. In a
            # job that *succeeded* these read `success`, which makes a step
            # gated on an earlier one having failed classify as correctly-not-
            # run rather than as a change filter that skipped.
            #
            # `continue-on-error` is the one way a green job can hold a failed
            # step, and it does not escape through here: the caller flags any
            # step whose own reported conclusion is `failure` inside a green
            # required check, independently of this condition.
            return "success"
        # Indexing (`needs.x.outputs['y']`) and every unlisted property are
        # runtime facts. UNKNOWN, never False.
        return UNKNOWN


def _compare(op: str, left: Any, right: Any) -> bool:
    if op in {"==", "!="}:
        # Actions coerces across types for loose equality. Comparing the
        # string forms covers every shape these conditions use.
        equal = left == right or (_coerce(left) == _coerce(right))
        return equal if op == "==" else not equal
    try:
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        return left >= right
    except TypeError:
        return False


def _coerce(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _call(name: str, args: list[Any]) -> Any:
    # The four job-status functions, resolved for "this job has succeeded so
    # far". `failure()` and `cancelled()` are what make forensics and teardown
    # steps classify as correctly-not-run rather than as findings.
    if name == "success":
        return True
    if name == "always":
        return True
    if name in {"failure", "cancelled"}:
        return False
    if any(isinstance(a, Unknown) for a in args):
        return UNKNOWN
    if name == "contains" and len(args) == 2:
        haystack, needle = args
        if isinstance(haystack, (list, tuple)):
            return needle in haystack
        return _coerce(needle) in _coerce(haystack)
    if name == "startswith" and len(args) == 2:
        return _coerce(args[0]).startswith(_coerce(args[1]))
    if name == "endswith" and len(args) == 2:
        return _coerce(args[0]).endswith(_coerce(args[1]))
    if name == "format" and args:
        template = _coerce(args[0])
        for index, extra in enumerate(args[1:]):
            template = template.replace("{" + str(index) + "}", _coerce(extra))
        return template
    return UNKNOWN


_WRAPPER_RE = re.compile(r"^\s*\$\{\{(?P<body>.*)\}\}\s*$", re.DOTALL)


def evaluate(condition: Any, context: dict[str, Any] | None = None) -> Any:
    """Evaluate an ``if:`` value. Returns ``True``, ``False`` or ``UNKNOWN``.

    ``None`` (no condition) is ``True``: an unconditional step always runs.
    """
    if condition is None:
        return True
    if isinstance(condition, bool):
        return condition
    text = str(condition).strip()
    if not text:
        return True
    # `if: ${{ ... }}` and bare `if: ...` are the same expression. A partially
    # interpolated string ("a-${{ b }}-c") is not an expression at all, so it
    # falls through to UNKNOWN below.
    wrapper = _WRAPPER_RE.match(text)
    if wrapper:
        text = wrapper.group("body").strip()
    elif "${{" in text:
        return UNKNOWN

    tokens = _tokenize(text)
    if tokens is None or not tokens:
        return UNKNOWN
    parser = _Parser(tokens, {**PUSH_TO_PROTECTED_BRANCH, **(context or {})})
    value = parser.parse_or()
    if not parser.ok or parser.pos != len(parser.tokens):
        return UNKNOWN
    return truthy(value)


def _expression_body(condition: Any) -> str | None:
    if condition is None or isinstance(condition, bool):
        return None
    text = str(condition).strip()
    if not text:
        return None
    wrapper = _WRAPPER_RE.match(text)
    if wrapper:
        return wrapper.group("body").strip()
    return None if "${{" in text else text


def unresolved_references(condition: Any, context: dict[str, Any] | None = None) -> set[str]:
    """The property paths in ``condition`` whose value the evaluator cannot fix.

    These are the run-time facts a step's execution can turn on — a change
    filter's output, another step's output. The caller enumerates values for
    them to work out which paths through a job are reachable at all, so this
    has to be derived from the expression rather than from a list of names
    someone remembered to update.
    """
    body = _expression_body(condition)
    if body is None:
        return set()
    tokens = _tokenize(body)
    if not tokens:
        return set()
    resolved = {**PUSH_TO_PROTECTED_BRANCH, **(context or {})}
    found: set[str] = set()
    for index, (kind, text) in enumerate(tokens):
        if kind != "ident" or text.lower() in {"true", "false", "null"}:
            continue
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        if nxt and nxt[0] == "op" and nxt[1] == "(":
            continue  # a function call, not a property path
        if text in resolved or _STATUS_PATH.match(text):
            continue
        found.add(text)
    return found


def string_literals(condition: Any) -> set[str]:
    """Every quoted string in ``condition``.

    The candidate values a reference is compared against, so an enumeration
    over them covers every branch the author actually wrote.
    """
    body = _expression_body(condition)
    if body is None:
        return set()
    tokens = _tokenize(body) or []
    return {text[1:-1].replace("''", "'") for kind, text in tokens if kind == "string"}

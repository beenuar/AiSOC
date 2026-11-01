"""Plain-language business-context rules, compiled to the existing schema.

Wave 2, Phase 4.3.

What this is, and what it deliberately is not
--------------------------------------------
An analyst writes "if user.department is finance and severity is critical then
route to tier3" and gets back a :class:`~.models.BusinessContextRule` — the
*same* structured rule the YAML editor produces and the *same* one both
engines evaluate. There is no second rule format and no second evaluator.

**No model is involved at any point.** That is the whole design, not an
optimisation. The plan's hard constraint for this item is that a tenant's free
text never becomes an instruction, and the strongest way to honour it is to
leave no channel through which it could: this compiler is a deterministic
lexer and parser, so the sentence an analyst types is parsed, not interpreted.
A string that does not parse is refused with the position and the reason; it
is never "best effort" turned into a rule that means something else.

Why a closed phrase table rather than a closed field list
---------------------------------------------------------
Operators are a closed set — the thirteen in :data:`~.models.ALLOWED_OPS`,
which both engines implement and which `scripts/check_business_context_grammar.py`
holds level. Every phrase below maps to one of them, and the gate asserts the
mapping's range is a subset, so a phrase can never introduce a comparator the
evaluators do not have. That is the `neq` failure one level up: `neq` is not an
operator, and a rule using it parses, saves, and silently never matches.

Fields are *not* a closed set, because they are dotted paths into a fused
alert whose shape depends on which connectors a tenant runs; a hardcoded list
would refuse legitimate fields and would go stale with every new connector.
The same failure mode is closed a different way — the compiler reports which
fields a rule references, and the preview route measures how many of the
tenant's recent alerts actually carry each one. An operator sees "this field
appeared in 0 of 50 of your alerts" *before* saving, which is the warning the
`neq` case never got.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from .models import ALLOWED_OPS, ALLOWED_ROUTES, ALLOWED_SEVERITIES


class PlainLanguageError(ValueError):
    """A sentence that could not be compiled, with where and why.

    ``ValueError`` for the same reason :class:`~.models.RuleParseError` is:
    the API layer catches one class and returns the message verbatim, and the
    message is already written for the person who typed the sentence.
    """

    def __init__(self, message: str, *, near: str | None = None) -> None:
        super().__init__(f"{message} (near {near!r})" if near else message)
        self.near = near


#: Operator phrases, longest first so "is not one of" wins over "is not",
#: which wins over "is". Order is load-bearing and asserted by the self-test.
#:
#: Every target is in ``ALLOWED_OPS``. The gate re-derives that rather than
#: trusting this comment, because a phrase pointing at a comparator no
#: evaluator implements is a rule that saves and never fires.
_OPERATOR_PHRASES: tuple[tuple[str, str], ...] = (
    ("is not one of", "not_in"),
    ("is none of", "not_in"),
    ("is not any of", "not_in"),
    ("is not in", "not_in"),
    ("not one of", "not_in"),
    ("does not exist", "not_exists"),
    ("does not equal", "ne"),
    ("does not contain", "not_contains_unsupported"),
    ("is no more than", "lte"),
    ("is no less than", "lte_or_gte_ambiguous"),
    ("is greater than or equal to", "gte"),
    ("is less than or equal to", "lte"),
    ("is not present", "not_exists"),
    ("is not set", "not_exists"),
    ("is greater than", "gt"),
    ("is more than", "gt"),
    ("is less than", "lt"),
    ("is at least", "gte"),
    ("is at most", "lte"),
    ("is one of", "in"),
    ("is any of", "in"),
    ("is missing", "not_exists"),
    ("is absent", "not_exists"),
    ("is present", "exists"),
    ("starts with", "startswith"),
    ("begins with", "startswith"),
    ("ends with", "endswith"),
    ("is not", "ne"),
    ("is set", "exists"),
    ("contains", "contains"),
    ("includes", "contains"),
    ("equals", "eq"),
    ("exists", "exists"),
    ("is in", "in"),
    ("is", "eq"),
)

#: Phrases that parse as English but have no comparator behind them. Listed
#: so the refusal can name the gap instead of saying "not understood", which
#: would send an author looking for a typo that is not there.
_UNSUPPORTED: dict[str, str] = {
    "not_contains_unsupported": (
        "there is no 'does not contain' comparator — the evaluators implement "
        "'contains' only. Write the positive form and wrap it: "
        '"if not (field contains value) then ..."'
    ),
    "lte_or_gte_ambiguous": (
        "'is no less than' is ambiguous in this grammar; write 'is at least' for a lower bound or 'is at most' for an upper one"
    ),
}

#: Unary comparators, which take no value.
_UNARY = {"exists", "not_exists"}

#: Action phrases, longest first for the same reason as the operators.
_SEVERITY_PHRASES = ("set severity to", "set the severity to", "set severity")
_ROUTE_PHRASES = ("route to", "send to", "assign to")
_TAG_PHRASES = ("tag it", "tag as", "add tag", "tag")
_SUPPRESS_PHRASES = ("suppress it", "suppress", "drop it", "drop")

#: A dotted path into the fused alert. Deliberately strict: an operator
#: phrase embedded in a field name would make the split ambiguous, and a
#: field carrying quotes or brackets is not something either engine reads.
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

_OPENERS = ("if ", "when ", "whenever ")


@dataclass(frozen=True)
class CompiledRule:
    """What the preview shows and what saving would write.

    ``rule`` is the structured mapping in exactly the shape
    :func:`~.models.load_rules_from_yaml` accepts, so the preview and the save
    cannot drift: the same dict is what gets written.
    """

    rule: dict[str, Any]
    fields_referenced: tuple[str, ...]
    #: Non-fatal observations worth showing beside the preview.
    warnings: tuple[str, ...] = dc_field(default_factory=tuple)


def _strip_opener(text: str) -> str:
    lowered = text.lstrip()
    for opener in _OPENERS:
        if lowered.lower().startswith(opener):
            return lowered[len(opener) :]
    raise PlainLanguageError(
        "a rule has to start with 'if', 'when' or 'whenever' — for example \"if severity is critical then route to tier3\"",
        near=lowered[:40] or None,
    )


def _split_then(text: str) -> tuple[str, str]:
    """Split on the last top-level ' then ', so a value containing it survives."""
    matches = list(re.finditer(r"\bthen\b", text, re.IGNORECASE))
    if not matches:
        raise PlainLanguageError(
            "a rule needs a 'then' clause saying what to do — for example \"... then set severity to high\"",
            near=text[:40] or None,
        )
    last = matches[-1]
    return text[: last.start()].strip(), text[last.end() :].strip()


def _parse_value(raw: str, op: str) -> Any:
    """Turn the right-hand side into a value the schema accepts."""
    text = raw.strip().rstrip(".")
    if not text:
        raise PlainLanguageError(f"'{op}' needs a value on the right-hand side")

    if op in {"in", "not_in"}:
        # Commas only. "or" is reserved as the boolean joiner, because
        # "a is one of x or y" and "a is one of x, or b is y" are the same
        # string with two meanings — see `_split_conditions`, which refuses
        # it by name rather than picking a reading.
        values = [_scalar(p) for p in text.split(",") if p.strip()]
        if not values:
            raise PlainLanguageError(f"'{op}' needs at least one value", near=raw[:40])
        return values
    return _scalar(text)


def _scalar(text: str) -> Any:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        # Quoted wins: it is how an author says "treat this literally",
        # including a value that looks like a number or a boolean.
        return text[1:-1]
    lowered = text.lower()
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d*\.\d+", text):
        return float(text)
    return text


def _parse_condition(clause: str) -> dict[str, Any]:
    text = clause.strip()
    if not text:
        raise PlainLanguageError("empty condition")

    negated = False
    if re.match(r"^not\s+\(", text, re.IGNORECASE) and text.endswith(")"):
        negated = True
        text = text[text.index("(") + 1 : -1].strip()

    # Longest-phrase-first scan. The first phrase that appears wins at the
    # earliest position it appears, so "is not one of" beats the "is" inside it.
    best = _match_operator(text)
    if best is None:
        raise PlainLanguageError(
            "no comparison found in this condition. Supported comparisons are: " + ", ".join(sorted({p for p, _ in _OPERATOR_PHRASES})),
            near=text[:40],
        )

    start, phrase, op = best
    if op in _UNSUPPORTED:
        raise PlainLanguageError(_UNSUPPORTED[op], near=text[:60])

    field_name = text[:start].strip()
    # "the host is ..." reads better than "host is ..."; strip the article
    # rather than refusing, because an author will write it.
    field_name = re.sub(r"^(?:the|a|an)\s+", "", field_name, flags=re.IGNORECASE).strip()
    if not _FIELD_RE.match(field_name):
        raise PlainLanguageError(
            f"{field_name!r} is not a field path. A field is a dotted name such as 'severity', 'user.department' or 'host.name'",
            near=field_name[:40] or None,
        )

    remainder = text[start + 1 + len(phrase) :].strip()
    if op in _UNARY:
        if remainder:
            raise PlainLanguageError(
                f"'{phrase}' takes no value, but {remainder!r} follows it",
                near=remainder[:40],
            )
        leaf: dict[str, Any] = {"field": field_name, "op": op}
    else:
        leaf = {"field": field_name, "op": op, "value": _parse_value(remainder, op)}

    return {"not": leaf} if negated else leaf


def _split_conditions(text: str) -> tuple[str, list[str]]:
    """Split a condition clause on ``and`` / ``or``, refusing a mix.

    Mixing them in one flat sentence is genuinely ambiguous — "a and b or c"
    has two readings and silently picking one is how a rule comes to mean
    something its author did not write. The structured schema can express
    either; the sentence has to say which, so this refuses and says so.
    """
    parts = re.split(r"\b(and|or)\b", text, flags=re.IGNORECASE)
    clauses = [parts[0]]
    joiners: list[str] = []
    for i in range(1, len(parts), 2):
        joiners.append(parts[i].lower())
        clauses.append(parts[i + 1])

    distinct = set(joiners)
    if len(distinct) > 1:
        raise PlainLanguageError(
            "mixing 'and' with 'or' in one sentence is ambiguous. Write the rule in the YAML editor, where 'all' and 'any' nest explicitly",
            near=text[:60],
        )

    cleaned = [c.strip() for c in clauses if c.strip()]
    # "is one of finance or legal" splits here into a condition and a bare
    # word, because `or` is the boolean joiner. Say that, rather than letting
    # the fragment fail downstream with "no comparison found" — which is true
    # and tells the author nothing about what they actually wrote.
    for index, clause in enumerate(cleaned):
        if _has_comparison(clause):
            continue
        previous = cleaned[index - 1] if index else ""
        if _uses_list_operator(previous):
            raise PlainLanguageError(
                "separate the values of a list comparison with commas — 'or' joins "
                'conditions, so "is one of a or b" reads as two conditions. Write '
                '"is one of a, b"',
                near=f"{previous} or {clause}"[:80],
            )

    logical = "any" if distinct == {"or"} else "all"
    return logical, cleaned


#: Comparators that take a list, and so collide with `or` as a separator.
_LIST_OPS = {"in", "not_in"}


def _match_operator(text: str) -> tuple[int, str, str] | None:
    """The earliest, longest operator phrase in ``text``, or None."""
    best: tuple[int, str, str] | None = None
    for phrase, op in _OPERATOR_PHRASES:
        match = re.search(rf"\s{re.escape(phrase)}(?=\s|$)", text, re.IGNORECASE)
        if match is None:
            continue
        if best is None or match.start() < best[0] or (match.start() == best[0] and len(phrase) > len(best[1])):
            best = (match.start(), phrase, op)
    return best


def _has_comparison(clause: str) -> bool:
    return _match_operator(clause.strip()) is not None


def _uses_list_operator(clause: str) -> bool:
    found = _match_operator(clause.strip())
    return found is not None and found[2] in _LIST_OPS


def _parse_actions(text: str) -> dict[str, Any]:
    action: dict[str, Any] = {}
    for raw in re.split(r"\band\b", text, flags=re.IGNORECASE):
        clause = raw.strip().rstrip(".")
        if not clause:
            continue
        lowered = clause.lower()

        matched = False
        for phrase in _SEVERITY_PHRASES:
            if lowered.startswith(phrase):
                value = clause[len(phrase) :].strip().strip("\"'")
                if value.lower() not in ALLOWED_SEVERITIES:
                    raise PlainLanguageError(
                        f"{value!r} is not a severity. Use one of: {', '.join(ALLOWED_SEVERITIES)}",
                        near=clause[:40],
                    )
                action["set_severity"] = value.lower()
                matched = True
                break
        if matched:
            continue

        for phrase in _ROUTE_PHRASES:
            if lowered.startswith(phrase):
                value = clause[len(phrase) :].strip().strip("\"'")
                if value not in ALLOWED_ROUTES:
                    raise PlainLanguageError(
                        f"{value!r} is not a routing destination. Use one of: {', '.join(sorted(ALLOWED_ROUTES))}",
                        near=clause[:40],
                    )
                action["route_to"] = value
                matched = True
                break
        if matched:
            continue

        # Exact match only: "suppress" is the whole action, and a trailing
        # object ("suppress the mailbox") means something this schema cannot
        # express, so it belongs in the refusal rather than silently dropped.
        if lowered in _SUPPRESS_PHRASES:
            action["suppress"] = True
            continue

        for phrase in _TAG_PHRASES:
            if lowered.startswith(f"{phrase} "):
                action["tag"] = clause[len(phrase) :].strip().strip("\"'")
                matched = True
                break
        if matched:
            continue

        raise PlainLanguageError(
            "this action is not one the schema can express. Supported actions are: "
            "'set severity to <level>', 'route to <destination>', 'tag <name>', 'suppress'",
            near=clause[:60],
        )

    if not action:
        raise PlainLanguageError("the 'then' clause does not say what to do")
    return action


def _fields_of(condition: dict[str, Any]) -> list[str]:
    if "field" in condition:
        return [str(condition["field"])]
    out: list[str] = []
    for key in ("all", "any"):
        for child in condition.get(key, []):
            out.extend(_fields_of(child))
    if "not" in condition:
        out.extend(_fields_of(condition["not"]))
    return out


def compile_plain_language(text: str, *, rule_id: str, description: str = "") -> CompiledRule:
    """Compile one plain-language sentence into the structured rule schema.

    Raises :class:`PlainLanguageError` with a reason an author can act on.
    Never returns a partially-understood rule: this is the surface where
    "best effort" would produce a rule that quietly means something else.
    """
    if not isinstance(text, str) or not text.strip():
        raise PlainLanguageError('write the rule as a sentence, for example "if severity is critical then route to tier3"')
    if len(text) > 2000:
        raise PlainLanguageError("that sentence is too long to be one rule; split it, or use the YAML editor")

    body = _strip_opener(text)
    condition_text, action_text = _split_then(body)
    logical, clauses = _split_conditions(condition_text)

    leaves = [_parse_condition(c) for c in clauses]
    when: dict[str, Any] = leaves[0] if len(leaves) == 1 else {logical: leaves}
    then = _parse_actions(action_text)

    warnings: list[str] = []
    if then.get("suppress") and len(then) > 1:
        warnings.append(
            "this rule suppresses the alert as well as modifying it; the alert is dropped "
            "before triage, so the other effects are not observable"
        )

    fields = tuple(dict.fromkeys(_fields_of(when)))
    return CompiledRule(
        rule={
            "id": rule_id,
            "description": description or text.strip(),
            "when": when,
            "then": then,
            "enabled": True,
            "priority": 100,
        },
        fields_referenced=fields,
        warnings=tuple(warnings),
    )


def operator_phrase_targets() -> set[str]:
    """Every comparator this grammar can produce. Read by the lockstep gate."""
    return {op for _, op in _OPERATOR_PHRASES if op not in _UNSUPPORTED}


def unsupported_phrase_targets() -> set[str]:
    """Phrases that parse but are refused, so the gate can tell them apart."""
    return set(_UNSUPPORTED)


__all__ = [
    "ALLOWED_OPS",
    "CompiledRule",
    "PlainLanguageError",
    "compile_plain_language",
    "operator_phrase_targets",
    "unsupported_phrase_targets",
]
